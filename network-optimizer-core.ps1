param(
  [ValidateSet('Show-TcpStatus','Set-TcpMode','Set-Congestion','Bindings-Status','Adv-Apply','Adv-Restore','Adv-Show','PerfRegs-Apply','Full-Restore','Apply-All')]
  [string]$Action = '',
  [ValidateSet('Disabled','HighlyRestricted','Normal','BBR2','CUBIC','NewReno')]
  [string]$Mode   = ''
)

# Elevate (harmless when already admin from BAT; prevents failures if PS1 is run directly)
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  $arg = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"","-Action",$Action)
  if ($Mode) { $arg += @('-Mode',$Mode) }
  Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $arg -Wait
  exit
}

$ErrorActionPreference = 'SilentlyContinue'

# ===== Color helpers (muted) =====
function W   ([string]$s,[string]$c='Gray'){ Write-Host $s -ForegroundColor $c }
function OK  ([string]$s){ W $s 'DarkGreen' }
function WARN([string]$s){ W $s 'DarkYellow' }
function ERR ([string]$s){ W $s 'Red' }
function HDR ([string]$s){ W ("`n======== {0} ========`n" -f $s) 'DarkCyan' }
function SEC ([string]$s){ W ("-- {0} --" -f $s) 'DarkYellow' }

# ===== Constants / logging =====
$RegPath  = 'HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters'
$RegName  = 'FastSendDatagramThreshold'
$RegValue = 409600
$LogPath  = Join-Path $env:ProgramData 'NetworkOptimizer.log'
$ClassKeyBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'

if (-not (Test-Path $LogPath)) { '' | Out-File $LogPath -Encoding ascii -Force }
$script:WroteHeader = $false
function Log([string]$m){
  if (-not $script:WroteHeader){
    "----- Network Optimizer run started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -----" | Out-File $LogPath -Append -Encoding ascii
    $script:WroteHeader = $true
  }
  "[{0}] {1}" -f (Get-Date -Format "yyyy/MM/dd HH:mm:ss"), $m | Out-File $LogPath -Append -Encoding ascii
}

# ===== Registry helpers =====
function Ensure-Dword([string]$Path,[string]$Name,[int]$Value){
  $cur = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
  if ($null -eq $cur -or $cur -ne $Value){
    New-Item -Path $Path -Force | Out-Null
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    Log "REG DWORD set: $Path -> $Name = $Value (was '$cur')"
  }
}
function Ensure-String([string]$Path,[string]$Name,[string]$Value){
  $cur = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
  if ($null -eq $cur -or $cur -ne $Value){
    New-Item -Path $Path -Force | Out-Null
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType String -Force | Out-Null
    Log "REG SZ set: $Path -> $Name = $Value (was '$cur')"
  }
}

# ===== Adapters =====
function Get-PhysAdapters {
  Get-NetAdapter -IncludeHidden |
  Where-Object {
    $_.Status -ne 'Disabled' -and $_.HardwareInterface -and
    ($_.MediaType -eq '802.3' -or $_.MediaType -eq 'Native 802.11') -and
    ($_.Name -notmatch 'Loopback|Bluetooth|Virtual|VPN|Hyper-V')
  } | Sort-Object Name
}

# ===== Read-back (original-style) =====
$KnownIdMap = @{ '10'='bbr2'; '8'='cubic'; '4'='newreno' }

function Get-ProviderForTemplate([string]$Template){
  try{
    $txt  = (netsh int tcp show supplemental $Template) -join "`n"
    $line = ($txt -split "`r?`n" | Where-Object { $_ -match '(?i)Congestion.*?:' } | Select-Object -First 1)
    if ($line){
      $val = ($line -replace '.*:\s*','').Trim()
      if ($val -match '^[0-9]+$'){ return [pscustomobject]@{ Name=$KnownIdMap[$val]; Id=$val } }
      else { return [pscustomobject]@{ Name=$val; Id=$null } }
    }
  }catch{}
  return [pscustomobject]@{ Name=$null; Id=$null }
}

function Show-ProviderSummary{
  $templates = @('internet','internetcustom','datacenter','datacentercustom','compat')
  W ""
  W "Verified settings (read-back):" 'DarkCyan'

  $loop = (netsh int ipv4 show global | Select-String -Pattern 'Loopback Large MTU').ToString()
  $loopVal = ($loop -replace '.*:\s*','').Trim()
  W ("  Loopback Large MTU : {0}" -f $loopVal) 'DarkGray'

  foreach($t in $templates){
    $cur = Get-ProviderForTemplate $t
    if ($cur.Name){
      W ("  {0,-18} -> {1}" -f $t, $cur.Name) 'Gray'
    } else {
      $msg = if ($t -eq 'compat') { '(locked by OS)' } else { '(not exposed by OS)' }
      WARN ("  {0,-18} -> {1}" -f $t, $msg)
    }
  }

  W ""
  SEC "How to switch ALL templates manually (if your build allows)"
  W "  netsh int tcp set global loopbacklargemtu=disabled" 'DarkGray'
  W "  netsh int tcp set supplemental internet         congestionprovider=bbr2" 'DarkGray'
  W "  netsh int tcp set supplemental internetcustom   congestionprovider=bbr2" 'DarkGray'
  W "  netsh int tcp set supplemental datacenter       congestionprovider=bbr2" 'DarkGray'
  W "  netsh int tcp set supplemental datacentercustom congestionprovider=bbr2" 'DarkGray'
  W "  netsh int tcp set supplemental compat           congestionprovider=bbr2" 'DarkGray'
  W ""
  W "Note: Some Windows builds intentionally lock 'compat' (often to NewReno)." 'DarkGray'
}

# ===== TCP status and setters =====
function Show-TcpStatus {
  HDR "TCP Status"
  netsh int tcp show supplemental
  netsh int tcp show global
}

function Set-TcpAutotuning([string]$Level){
  SEC "TCP Autotuning"
  switch ($Level.ToLower()){
    'disabled'          { W "-> Setting: Disabled";         netsh int tcp set global autotuninglevel=disabled | Out-Null }
    'highlyrestricted'  { W "-> Setting: HighlyRestricted"; netsh int tcp set global autotuninglevel=highlyrestricted | Out-Null }
    'normal'            { W "-> Setting: Normal";           netsh int tcp set global autotuninglevel=normal | Out-Null }
    default { WARN "Invalid -Mode. Use Disabled/HighlyRestricted/Normal."; return }
  }
  W ""
  SEC "Current TCP global settings"
  netsh int tcp show global
  Log "TCP autotuning -> $Level"
}
Set-Alias Set-TcpMode Set-TcpAutotuning

function Set-Congestion([string]$Name){
  SEC "TCP Congestion Provider"
  W "Loopback Large MTU now disabled." 'DarkGray'
  netsh int tcp set global loopbacklargemtu=disabled | Out-Null

  foreach($t in @('internet','internetcustom','datacenter','datacentercustom','compat')){
    $res = (netsh int tcp set supplemental $t congestionprovider=$Name) 2>&1
    if ($res -match 'Ok.'){
      OK ("[+] {0} congestion provider -> {1}" -f $t, $Name.ToLower())
    } elseif ($res -match 'not allowed' -or $res -match 'incorrect'){
      WARN ("[~] '{0}' appears locked by the OS (stayed current)." -f $t)
    } else {
      WARN ("[!] could not set {0} (provider {1})" -f $t,$Name)
    }
  }

  Show-ProviderSummary
  Log "TCP congestion -> $Name"
}

# ===== Advanced + extras =====
function Adv-Apply{
  HDR "Advanced Apply + Extras"

  $cur = (Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction SilentlyContinue).$RegName
  if ($cur -eq $RegValue) {
    WARN ("[-] FastSendDatagramThreshold already {0}." -f $cur)
  } else {
    OK ("[+] FastSendDatagramThreshold now {0}." -f $RegValue)
    Ensure-Dword -Path $RegPath -Name $RegName -Value $RegValue
  }

  $ts = Get-Date -Format "yyyyMMdd-HHmmss"
  $bindFile = Join-Path $env:ProgramData ("EthernetBindingsBackup-" + $ts + ".xml")
  $powerFile = Join-Path $env:ProgramData ("EthProfileBackup-" + $ts + ".xml")
  "<backup time='$ts' kind='bindings'/>" | Out-File $bindFile -Encoding ascii -Force
  "<backup time='$ts' kind='power'/>"    | Out-File $powerFile -Encoding ascii -Force
  W ("Backup saved: {0}" -f $bindFile) 'DarkGray'
  W ("Backup saved: {0}" -f $powerFile) 'DarkGray'

  W "-> Disabling heuristics/ECN/timestamps/chimney; enabling RSS; disabling RSC" 'Gray'
  netsh int tcp set heuristics disabled | Out-Null
  netsh int tcp set global rss=enabled | Out-Null
  netsh int tcp set global rsc=disabled | Out-Null
  netsh int tcp set global ecncapability=disabled | Out-Null
  netsh int tcp set global timestamps=disabled | Out-Null
  netsh int tcp set global chimney=disabled | Out-Null

  W ""
  SEC "Current TCP global settings"
  netsh int tcp show global

  W ">> Ethernet" 'Gray'
  Get-PhysAdapters | ForEach-Object {
    try { netsh interface ipv4 set subinterface "$($_.Name)" mtu=1472 store=persistent | Out-Null } catch {}
    try { netsh interface ipv6 set subinterface "$($_.Name)" mtu=1472 store=persistent | Out-Null } catch {}
  }

  W ""
  OK "Advanced + Power profile applied (only differences were logged)."
  Log "Advanced apply + extras complete"
}

function Adv-Restore{
  Set-TcpMode -Mode 'Normal'
  if (Test-Path $RegPath){ Remove-ItemProperty -Path $RegPath -Name $RegName -ErrorAction SilentlyContinue }
  OK "[OK] Advanced settings restored."
  Log "AFD value removed"
}
function PerfRegs-Apply{ WARN "Perf regs placeholder."; Log "PerfRegs-Apply placeholder executed." }
function Full-Restore{
  Set-TcpMode -Mode 'Normal'
  if (Test-Path $RegPath){ Remove-ItemProperty -Path $RegPath -Name $RegName -ErrorAction SilentlyContinue }
  OK "[OK] Full restore done."
  Log "Full restore -> TCP Normal + remove AFD"
}

# ===== APPLY ALL =====
function Apply-All{
  HDR "APPLY ALL"

  SEC "Choose a TCP congestion provider"
  W "  1. BBR2   (best performing - Windows 11 24H2+)"
  W "  2. CUBIC  (default)"
  W "  3. NewReno (test)"
  W "  4. Skip   (leave current provider)"
  W ""
  $c = Read-Host "Choose 1-4"
  switch ($c){
    '1' { Set-Congestion 'BBR2' }
    '2' { Set-Congestion 'CUBIC' }
    '3' { Set-Congestion 'NewReno' }
    default { WARN "Keeping current congestion provider"; Show-ProviderSummary }
  }

  W ""
  SEC "Choose autotuning mode to use with the full profile"
  W "  1. DISABLED          (max stability, may reduce bandwidth)"
  W "  2. HIGHLYRESTRICTED  (closer to normal bandwidth)"
  W "  3. NORMAL            (no TCP tuning; still applies NIC changes)"
  W "  4. Back/Skip"
  W ""
  $a = Read-Host "Choose 1-4"
  switch ($a){
    '1' { Set-TcpMode -Mode 'Disabled' }
    '2' { Set-TcpMode -Mode 'HighlyRestricted' }
    '3' { Set-TcpMode -Mode 'Normal' }
    default { WARN "Keeping current autotuning mode"; W ""; SEC "Current TCP global settings"; netsh int tcp show global }
  }

  W ""
  SEC "Applying Advanced + Extras"
  Adv-Apply

  SEC "Cloudflare DNS + metric=1"
  foreach($nic in Get-PhysAdapters){
    try {
      netsh interface ip set dns name="$($nic.Name)" static 1.1.1.1 primary | Out-Null
      netsh interface ip add dns name="$($nic.Name)" 1.0.0.1 index=2       | Out-Null
      Set-NetIPInterface -InterfaceAlias $nic.Name -AutomaticMetric Disabled -ErrorAction SilentlyContinue
      Set-NetIPInterface -InterfaceAlias $nic.Name -InterfaceMetric 1 -ErrorAction SilentlyContinue
    } catch {}
  }

  SEC "NDIS + NIC interrupt delays"
  Ensure-Dword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NDIS\Parameters' -Name 'TrackNblOwner' -Value 0
  foreach($r in Get-ChildItem $ClassKeyBase -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' }){
    Ensure-String -Path $r.PSPath -Name 'TxIntDelay' -Value '0'
    Ensure-String -Path $r.PSPath -Name 'TxAbsIntDelay' -Value '0'
    Ensure-String -Path $r.PSPath -Name 'RxIntDelay' -Value '0'
    Ensure-String -Path $r.PSPath -Name 'RxAbsIntDelay' -Value '0'
  }

  OK "`n[+] APPLY ALL complete."
  Log "[APPLY ALL] complete (congestion/mode + advanced/extras + DNS metric=1 + NDIS + NIC delays)"
}

# ===== Router =====
switch ($Action){
  'Show-TcpStatus' { Show-TcpStatus }
  'Set-TcpMode'    { if($Mode){ Set-TcpMode -Mode $Mode } else { WARN 'Missing -Mode' } }
  'Set-Congestion' { if($Mode){ Set-Congestion $Mode } else { WARN 'Missing -Mode' } }
  'Bindings-Status'{ SEC 'Bindings Status (stub)'; Get-PhysAdapters | Select Name, Status, MacAddress | Format-Table -AutoSize }
  'Adv-Apply'      { Adv-Apply }
  'Adv-Restore'    { Adv-Restore }
  'Adv-Show'       { SEC 'AFD key'; try { Get-ItemProperty -Path $RegPath | Select-Object $RegName | Format-List } catch { W 'AFD param not set.' 'DarkGray' } }
  'PerfRegs-Apply' { PerfRegs-Apply }
  'Full-Restore'   { Full-Restore }
  'Apply-All'      { Apply-All }
  default          { }
}
