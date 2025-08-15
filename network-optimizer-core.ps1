#Requires -RunAsAdministrator
param(
  [Parameter(Mandatory=$true, Position=0)]
  [ValidateSet(
    'Show-TcpStatus','Set-TcpMode','Set-Congestion',
    'Bindings-Disable','Bindings-Restore','Bindings-Status','Adapters-List',
    'Adv-Apply','Adv-Restore','Adv-Show','PerfRegs-Apply',
    'Full-Restore'
  )]
  [string]$Action,

  [Parameter(Position=1)]
  [ValidateSet('Disabled','Normal','HighlyRestricted','BBR2','CUBIC','NewReno')]
  [string]$Mode
)

$ErrorActionPreference = 'SilentlyContinue'

# ---------------- constants ----------------
$RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters'
$RegName = 'FastSendDatagramThreshold'
$RegValue = 409600   # 0x00064000
$BindingsBackupPrefix = Join-Path $env:ProgramData 'EthernetBindingsBackup-'
$AdvBackupPrefix      = Join-Path $env:ProgramData 'EthProfileBackup-'
$LogPath              = Join-Path $env:ProgramData 'NetworkOptimizer.log'
$ClassKeyBase         = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'

if (-not (Test-Path $LogPath)) { '' | Out-File -FilePath $LogPath -Encoding ascii -Force }

# --------------- logging (change-only) ---------------
$script:WroteHeader = $false
function Write-Change([string]$Message) {
  if (-not $script:WroteHeader) {
    "----- Network Optimizer run started $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') -----" | Out-File -FilePath $LogPath -Append -Encoding ascii
    $script:WroteHeader = $true
  }
  "[{0}] {1}" -f (Get-Date -Format 'yyyy/MM/dd HH:mm:ss'), $Message | Out-File -FilePath $LogPath -Append -Encoding ascii
}

# small helper for PS5.1 (no ?? operator)
function _IfEmpty([string]$val,[string]$fallback){ if([string]::IsNullOrEmpty($val)){ $fallback } else { $val } }

# --------------- helpers ---------------
function Get-PhysAdapters {
  Get-NetAdapter -IncludeHidden |
    Where-Object {
      $_.Status -ne 'Disabled' -and $_.HardwareInterface -and
      ($_.MediaType -eq '802.3' -or $_.MediaType -eq 'Native 802.11' -or $_.Name -match '^(Ethernet|Wi-?Fi|WLAN)') -and
      $_.Name -notmatch 'vEthernet|Hyper-V|Bluetooth'
    } | Sort-Object -Property Name
}
function Get-AdapterClassKey([string]$AdapterName){
  $na = Get-NetAdapter -Name $AdapterName -ErrorAction SilentlyContinue
  if (-not $na) { return $null }
  $guid = $na.InterfaceGuid.Guid
  if (-not (Test-Path $ClassKeyBase)) { return $null }
  $inst = Get-ChildItem $ClassKeyBase -ErrorAction SilentlyContinue | Where-Object {
    (Get-ItemProperty -Path $_.PSPath -Name 'NetCfgInstanceId' -ErrorAction SilentlyContinue).NetCfgInstanceId -eq $guid
  } | Select-Object -First 1
  return $inst?.PSPath
}
function Ensure-String([string]$Path,[string]$Name,[string]$Value){
  if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
  $cur = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
  if ($cur -ne $Value) {
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType String -Force | Out-Null
    Write-Change "REG SZ set: $Path -> $Name = $Value (was '$cur')"
  }
}
function Ensure-EnumQueues([string]$AdapterKey,[int]$Max=4){
  $enumPath = Join-Path $AdapterKey "Ndi\Params\*NumRssQueues\Enum"
  if (-not (Test-Path $enumPath)) { New-Item -Path $enumPath -Force | Out-Null }
  for($i=1;$i -le $Max;$i++){
    $label = if($i -eq 1){"1 Queue"} else {"$i Queues"}
    Ensure-String -Path $enumPath -Name "$i" -Value $label
  }
}
function Set-AdapterPerfRegs([string]$AdapterName){
  $path = Get-AdapterClassKey -AdapterName $AdapterName
  if (-not $path) { return }
  Ensure-String -Path $path -Name '*ReceiveBuffers'  -Value '2048'
  Ensure-String -Path $path -Name '*ReceieveBuffers' -Value '2048'
  Ensure-String -Path $path -Name '*TransmitBuffers' -Value '4096'
  Ensure-String -Path $path -Name '*RSS' -Value '1'
  Ensure-String -Path $path -Name 'RSS'  -Value '1'
  Ensure-String -Path $path -Name 'RSSProfile' -Value '3'
  Ensure-String -Path $path -Name '*NumRssQueues' -Value '4'
  Ensure-EnumQueues -AdapterKey $path -Max 4
  Ensure-String -Path $path -Name '*MaxRssProcessors' -Value '4'
  $lp = [Math]::Max(1, [Environment]::ProcessorCount - 2)
  Ensure-String -Path $path -Name '*RssMaxProcNumber' -Value "$lp"
  Ensure-String -Path $path -Name '*FlowControl' -Value '0'
  Ensure-String -Path $path -Name 'FlowControlCap' -Value '0'
  Ensure-String -Path $path -Name '*InterruptModeration' -Value '0'
}
function Apply-PerfRegs-AllAdapters { foreach($a in (Get-PhysAdapters)){ Set-AdapterPerfRegs -AdapterName $a.Name } }

# ---- TCP Status ----
function Show-TcpStatus {
  $line   = (netsh int tcp show global | Select-String -Pattern 'Receive Window Auto-Tuning Level').ToString()
  $status = $line -replace '.*Level\s*:\s*',''
  if (-not $status) { $status = '(unknown)' }
  Write-Host "Current autotuning: $status"
  $cur = (Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction SilentlyContinue).$RegName
  if ($null -ne $cur) { Write-Host ('{0} exists: 0x{1:x}' -f $RegName, [int]$cur) } else { Write-Host ('{0}: Not found' -f $RegName) }
}

# ---- Autotuning mode + AFD threshold ----
function Set-TcpMode([string]$Mode) {
  $map = @{ 'Disabled'='disabled'; 'Normal'='normal'; 'HighlyRestricted'='highlyrestricted' }
  $val = $map[$Mode]
  $line    = (netsh int tcp show global | Select-String -Pattern 'Receive Window Auto-Tuning Level').ToString()
  $current = ($line -replace '.*Level\s*:\s*','').Trim()

  if ($current -ieq $Mode) {
    Write-Host "Autotuning already $Mode."
  } else {
    $out = & netsh interface tcp set global "autotuninglevel=$val" 2>&1
    if ($LASTEXITCODE -eq 0 -or ($out -match 'Ok\.')) {
      Write-Host "[+] Autotuning set to $Mode."
      Write-Change "Autotuning: $current -> $Mode"
    } else {
      Write-Host "[!] Failed to set autotuning to $Mode."
      if ($out){ Write-Host $out }
      return
    }
  }

  if ($Mode -in @('Disabled','HighlyRestricted')) {
    $cur = (Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction SilentlyContinue).$RegName
    if ($cur -ne $RegValue) {
      New-Item -Path $RegPath -Force *> $null | Out-Null
      New-ItemProperty -Path $RegPath -Name $RegName -PropertyType DWord -Value $RegValue -Force *> $null | Out-Null
      Write-Change "${RegName}: $cur -> $RegValue"
      Write-Host "[+] ${RegName} set to $RegValue."
    } else {
      Write-Host "[=] ${RegName} already $RegValue."
    }
    $now = (Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction SilentlyContinue).$RegName
    Write-Host ("    {0} now {1}." -f $RegName, $now)
    Apply-PerfRegs-AllAdapters
  } elseif ($Mode -eq 'Normal') {
    $cur = (Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction SilentlyContinue).$RegName
    if ($null -ne $cur) { Remove-ItemProperty -Path $RegPath -Name $RegName -Force *> $null; Write-Host "[+] $RegName removed."; Write-Change "${RegName} removed" }
    $now = (Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction SilentlyContinue).$RegName
    if ($null -eq $now) { Write-Host ("    {0} now (not set)." -f $RegName) } else { Write-Host ("    {0} now {1}." -f $RegName,$now) }
  }
}

# ---- Congestion Provider (name-aware read-back) ----
$KnownIdMap = @{
  '10' = 'bbr2'
  '8'  = 'cubic'
  '4'  = 'newreno'
}

function Get-ProviderForTemplate([string]$Template){
  try {
    $txt = (netsh int tcp show supplemental $Template) -join "`n"
    $line = ($txt -split "`r?`n" | Where-Object { $_ -match '(?i)Congestion.*?:' } | Select-Object -First 1)
    if ($line) {
      $val = ($line -replace '.*:\s*','').Trim()
      if ($val -match '^[0-9]+$') {
        $name = $KnownIdMap[$val]
        return [pscustomobject]@{ Name = $name; Id = $val }
      } else {
        return [pscustomobject]@{ Name = $val; Id = $null }
      }
    }
  } catch {}
  return [pscustomobject]@{ Name = $null; Id = $null }
}

function Show-ProviderSummary([string[]]$templates, [string]$AssumeNameIfNumeric){
  $loop = (netsh int ipv4 show global | Select-String -Pattern 'Loopback Large MTU').ToString()
  $loopVal = ($loop -replace '.*:\s*','').Trim()
  Write-Host "    Loopback Large MTU: $loopVal"
  foreach($t in $templates){
    $p = Get-ProviderForTemplate $t
    $display = if ($p.Name) {
      $p.Name
    } elseif ($AssumeNameIfNumeric -and $p.Id) {
      "$AssumeNameIfNumeric (id $($p.Id))"
    } elseif ($p.Id) {
      "id $($p.Id)"
    } else {
      '(unknown)'
    }
    Write-Host ("    {0,-16} => {1}" -f $t, $display)
  }
}

function Print-CompatHowTo {
  Write-Host ""
  Write-Host "How to switch the 'compat' template manually (if your build allows):" -ForegroundColor Yellow
  Write-Host "  1) Open an **elevated** Command Prompt (Run as Administrator)."
  Write-Host "  2) Run ONE of these lines:"
  Write-Host "       netsh int tcp set supplemental compat congestionprovider=bbr2"
  Write-Host "       netsh int tcp set supplemental compat congestionprovider=cubic"
  Write-Host "       netsh int tcp set supplemental compat congestionprovider=newreno"
  Write-Host "  3) Verify:"
  Write-Host "       netsh int tcp show supplemental compat"
  Write-Host "  Note: On many Windows builds, 'compat' is intentionally fixed to NewReno."
  Write-Host "        If it still shows NewReno after the command and a reboot, your OS locks it."
  Write-Host ""
}

function Set-Congestion([string]$Provider){
  $prov = $Provider.ToLower()
  $desired = switch ($prov) {
    'bbr2'     { 'bbr2' }
    'cubic'    { 'cubic' }
    'newreno'  { 'newreno' }
    default    { 'cubic' }
  }

  # LoopbackLargeMTU rule + confirmation print
  $wantLoop = if ($prov -eq 'bbr2') { 'disabled' } else { 'enabled' }
  $g = (netsh int ipv4 show global | Select-String -Pattern 'Loopback Large MTU').ToString()
  $curLoop = ($g -replace '.*:\s*','').Trim()
  if ($curLoop -and ($curLoop -ine $wantLoop)) {
    & netsh int ipv4 set global "loopbacklargemtu=$wantLoop" *> $null
    Write-Change "IPv4 LoopbackLargeMTU: $curLoop -> $wantLoop"
  }
  $g2 = (netsh int ipv4 show global | Select-String -Pattern 'Loopback Large MTU').ToString()
  $nowLoop = ($g2 -replace '.*:\s*','').Trim()
  Write-Host "    Loopback Large MTU now $nowLoop."

  # Providers
  $templates = @('internet','internetcustom','datacenter','datacentercustom','compat')
  foreach($t in $templates){
    $cur = Get-ProviderForTemplate $t
    $curName = if ($cur.Name) { $cur.Name } elseif ($cur.Id -and $KnownIdMap[$cur.Id]) { $KnownIdMap[$cur.Id] } else { $null }

    if ($curName -and ($curName -ieq $desired)) {
      Write-Host "[=] $t congestion provider already -> $desired"
      continue
    }

    $out = & netsh int tcp set supplemental $t "congestionprovider=$desired" 2>&1
    if ($LASTEXITCODE -eq 0 -or ($out -match 'Ok\.')) {
      # Re-read to verify
      $after = Get-ProviderForTemplate $t
      $afterName = if ($after.Name) { $after.Name } elseif ($after.Id -and $KnownIdMap[$after.Id]) { $KnownIdMap[$after.Id] } else { $null }
      $afterText = _IfEmpty $afterName 'unknown'

      if ($afterName -and ($afterName -ieq $desired)) {
        Write-Host "[+] $t congestion provider -> $desired"
        Write-Change "Congestion($t): $curName -> $desired"
      } else {
        if ($t -eq 'compat') {
          Write-Host "[~] '$t' appears locked by the OS (stayed '$afterText'). Leaving it as-is."
          Write-Change "Congestion($t): attempted '$desired' but OS kept '$afterText'"
        } else {
          Write-Host "[!] $t did not reflect the change (now '$afterText')."
          Write-Change "Congestion($t): set attempted '$desired' but read-back '$afterText'"
        }
      }
    } else {
      Write-Host "[!] Failed setting $t to $desired"
      if ($out){ Write-Host $out }
    }
  }

  # Final summary with friendly names (or IDs if that’s all the OS exposes)
  Show-ProviderSummary -templates $templates -AssumeNameIfNumeric $desired

  # Always show compat how-to, regardless of current value
  Print-CompatHowTo
}

# ---- Power Management (uncheck all 3) ----
function Set-IfDifferentPM([string]$Name) {
  $pm = Get-NetAdapterPowerManagement -Name $Name -ErrorAction SilentlyContinue
  if (-not $pm) { return }
  $need = ($pm.AllowComputerToTurnOffDevice -ne 'Disabled' -or
           $pm.WakeOnMagicPacket            -ne 'Disabled' -or
           $pm.WakeOnPattern                -ne 'Disabled')
  if ($need) {
    Set-NetAdapterPowerManagement -Name $Name `
      -AllowComputerToTurnOffDevice Disabled `
      -WakeOnMagicPacket Disabled `
      -WakeOnPattern Disabled -ErrorAction SilentlyContinue | Out-Null
    Write-Change "PM changed: $Name -> All Disabled"
  }
}

# ---- Advanced + LAA + Offload sweep ----
$DesiredAdvancedMap = @(
  @{ F='ARP Offload';                  K=@('ARP','ArpOffload');                   N=@('^ARP Offload$');                    V=@('Disabled','Off','None','0','False') },
  @{ F='Flow Control';                 K=@('FlowControl');                         N=@('^Flow Control$');                   V=@('Disabled','Off','None','0','False') },
  @{ F='Idle Power Down';              K=@('IdlePower','AutoPowerSave');           N=@('Idle Power');                       V=@('Disabled','Off','None','0','False') },
  @{ F='Interrupt Moderation';         K=@('InterruptModeration');                 N=@('^Interrupt Moderation$');           V=@('Disabled','Off','None','0','False') },
  @{ F='Interrupt Moderation Rate';    K=@('InterruptModerationRate','IMR');       N=@('Moderation Rate');                  V=@('Off','Disabled','None','0','False','Lowest','Minimal') },
  @{ F='IPv4 Checksum Offload';        K=@('ChecksumOffloadIPv4','IPv4ChecksumOffload'); N=@('Checksum.*IPv4');              V=@('Disabled','Off','None','0','False') },
  @{ F='Jumbo Packet';                 K=@('JumboPacket');                         N=@('^Jumbo Packet');                    V=@('Disabled','1514 Bytes','1518 Bytes','Off') },
  @{ F='Large Send Offload v2 (IPv4)'; K=@('LSOv2IPv4','LsoV2IPv4');               N=@('Large Send.*IPv4');                 V=@('Disabled','Off','None','0','False') },
  @{ F='Large Send Offload v2 (IPv6)'; K=@('LSOv2IPv6','LsoV2IPv6');               N=@('Large Send.*IPv6');                 V=@('Disabled','Off','None','0','False') },
  @{ F='Locally Administered Address'; K=@('NetworkAddress','*NetworkAddress');    N=@('Locally Administered Address');     V=@('') },
  @{ F='NS Offload';                   K=@('NSOffload','NeighborSolicitation');    N=@('NS Offload','Neighbor Solicitation');V=@('Disabled','Off','None','0','False') },
  @{ F='TCP Checksum Offload (IPv4)';  K=@('TcpChecksumOffloadIPv4');              N=@('TCP Checksum.*IPv4');               V=@('Disabled','Off','None','0','False') },
  @{ F='TCP Checksum Offload (IPv6)';  K=@('TcpChecksumOffloadIPv6');              N=@('TCP Checksum.*IPv6');               V=@('Disabled','Off','None','0','False') },
  @{ F='UDP Checksum Offload (IPv4)';  K=@('UdpChecksumOffloadIPv4');              N=@('UDP Checksum.*IPv4');               V=@('Disabled','Off','None','0','False') },
  @{ F='UDP Checksum Offload (IPv6)';  K=@('UdpChecksumOffloadIPv6');              N=@('UDP Checksum.*IPv6');               V=@('Disabled','Off','None','0','False') },
  @{ F='Wake on Magic Packet';         K=@('WakeOnMagicPacket');                   N=@('Wake on Magic Packet$');            V=@('Disabled','Off','None','0','False') },
  @{ F='Wake on Magic Packet from S5'; K=@('WakeOnMagicPacketFromS5');             N=@('S5');                               V=@('Disabled','Off','None','0','False') },
  @{ F='Wake on pattern match';        K=@('WakeOnPattern');                       N=@('pattern match');                    V=@('Disabled','Off','None','0','False') },
  @{ F='Speed & Duplex';               K=@('SpeedDuplex');                         N=@('Speed.*Duplex');                    V=@('Auto Negotiation','Auto','Auto Detect') },
  @{ F='Packet Priority & VLAN';       K=@('PriorityVLANTag','PriorityVlanTagging'); N=@('Packet Priority.*VLAN');          V=@('Priority & VLAN Enabled','Enabled','On') }
)
$OffloadNamePatterns = @(
  'checksum','tcp.*offload','udp.*offload','ipv4.*offload','ipv6.*offload',
  'large\s*send.*offload','lso','tso','segmentation.*offload',
  'large\s*receive.*offload','lro','receive\s*segment\s*coalesc','rsc',
  'ipsec.*offload','task.*offload','generic.*offload','gro','gso'
)
$DisableValues = @('Disabled','Off','None','0','False')

function Set-LAANotPresent([string]$AdapterName){
  $na = Get-NetAdapter -Name $AdapterName -ErrorAction SilentlyContinue
  if (-not $na) { return $false }
  $guid = $na.InterfaceGuid.Guid
  $changed = $false
  foreach($kw in @('NetworkAddress','*NetworkAddress')){
    try { Set-NetAdapterAdvancedProperty -Name $AdapterName -RegistryKeyword $kw -RegistryValue '' -NoRestart -ErrorAction Stop | Out-Null; $changed=$true } catch {}
  }
  if (Test-Path $ClassKeyBase) {
    $keys = Get-ChildItem $ClassKeyBase -ErrorAction SilentlyContinue | Where-Object {
      (Get-ItemProperty -Path $_.PSPath -Name 'NetCfgInstanceId' -ErrorAction SilentlyContinue).NetCfgInstanceId -eq $guid
    }
    foreach($k in $keys){
      foreach($name in @('NetworkAddress','*NetworkAddress')){
        try {
          if (Get-ItemProperty -Path $k.PSPath -Name $name -ErrorAction SilentlyContinue){
            Remove-ItemProperty -Path $k.PSPath -Name $name -Force -ErrorAction SilentlyContinue
            $changed = $true
          }
        } catch {}
      }
    }
  }
  if ($changed){
    Write-Change "Advanced changed: $AdapterName -> LAA = Not Present (cleared)"
    try { Disable-NetAdapter -Name $AdapterName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null; Start-Sleep -Milliseconds 500; Enable-NetAdapter -Name $AdapterName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    return $true
  }
  return $false
}

function Try-SetAdvancedByProperty($Adapter, $prop, $Friendly, $Keyword, $Values) {
  if (-not $prop) { return $false }
  if ($Keyword -match '^\*?NetworkAddress$' -or $prop.DisplayName -match 'Locally\s+Administered\s+Address'){ return (Set-LAANotPresent -AdapterName $Adapter) }
  $cur = $prop.DisplayValue
  if ($Values -contains $cur) { return $true }
  foreach($v in $Values){
    try { Set-NetAdapterAdvancedProperty -Name $Adapter -RegistryKeyword $Keyword -DisplayValue $v -NoRestart -ErrorAction Stop | Out-Null; Write-Change "Advanced: $Adapter -> $Friendly = $v (was $cur)"; return $true }
    catch { try { Set-NetAdapterAdvancedProperty -Name $Adapter -RegistryKeyword $Keyword -RegistryValue $v -NoRestart -ErrorAction Stop | Out-Null; Write-Change "Advanced: $Adapter -> $Friendly = $v (was $cur)"; return $true } catch {} }
  }
  return $false
}

function Set-AdvancedProfileForAdapter($AdapterName){
  $all = Get-NetAdapterAdvancedProperty -Name $AdapterName -AllProperties -ErrorAction SilentlyContinue
  if (-not $all) { return }
  foreach($item in $DesiredAdvancedMap){
    $friendly = $item.F; $aliases=$item.K; $nameRx=$item.N; $values=$item.V
    $hit = $false
    foreach($kw in $aliases){
      $prop = $all | Where-Object { $_.RegistryKeyword -eq $kw }
      if ($prop) { if (Try-SetAdvancedByProperty -Adapter $AdapterName -prop $prop -Friendly $friendly -Keyword $kw -Values $values) { $hit=$true; break } }
    }
    if ($hit) { continue }
    foreach($rx in $nameRx){
      $prop = $all | Where-Object { $_.DisplayName -match $rx }
      if ($prop) { $kw = $prop.RegistryKeyword; if (Try-SetAdvancedByProperty -Adapter $AdapterName -prop $prop -Friendly $friendly -Keyword $kw -Values $values) { break } }
    }
  }
  foreach($prop in $all){
    $dn = ($prop.DisplayName|Out-String).Trim(); $kw = ($prop.RegistryKeyword|Out-String).Trim(); $dv = ($prop.DisplayValue|Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($dn) -and [string]::IsNullOrWhiteSpace($kw)) { continue }
    if ($DisableValues -contains $dv) { continue }
    $match = $false; foreach($rx in $OffloadNamePatterns){ if ($dn -match $rx -or $kw -match $rx){ $match=$true; break } }
    if (-not $match) { continue }
    foreach($v in $DisableValues){
      try { Set-NetAdapterAdvancedProperty -Name $AdapterName -RegistryKeyword $kw -DisplayValue $v -NoRestart -ErrorAction Stop | Out-Null; Write-Change "Advanced(offload): $AdapterName -> $dn = $v (was $dv)"; break }
      catch { try { Set-NetAdapterAdvancedProperty -Name $AdapterName -RegistryKeyword $kw -RegistryValue $v -NoRestart -ErrorAction Stop | Out-Null; Write-Change "Advanced(offload): $AdapterName -> $dn = $v (was $dv)"; break } catch {} }
    }
  }
}

function Adv-Apply {
  $adapters = Get-PhysAdapters
  if (-not $adapters) { Write-Host 'No physical Ethernet/Wi-Fi adapters found. Nothing to change.'; return }
  $backup = "$AdvBackupPrefix$((Get-Date).ToString('yyyyMMdd-HHmmss')).xml"
  $bpm  = foreach($a in $adapters){ Get-NetAdapterPowerManagement -Name $a.Name -ErrorAction SilentlyContinue }
  $badv = foreach($a in $adapters){ Get-NetAdapterAdvancedProperty -Name $a.Name -AllProperties -ErrorAction SilentlyContinue | Select-Object Name,DisplayName,DisplayValue,RegistryKeyword,RegistryValue }
  [pscustomobject]@{ Power=$bpm; Advanced=$badv } | Export-Clixml $backup
  Write-Host "Backup saved: $backup"
  foreach($a in $adapters){ Write-Host ">> $($a.Name)"; Set-IfDifferentPM -Name $a.Name; Set-AdvancedProfileForAdapter -AdapterName $a.Name }
  Write-Host 'Advanced + Power profile applied (only differences were logged).'
}

# ---- Bindings ----
function Bindings-Disable {
  $bindings = 'ms_msclient','ms_server','ms_implat','ms_lldp','ms_tcpip6','ms_rspndr','ms_lltdio'
  $adapters = Get-PhysAdapters
  if (-not $adapters) { Write-Host 'No physical Ethernet/Wi-Fi adapters found. Nothing to change.'; return }
  $backup = "$BindingsBackupPrefix$((Get-Date).ToString('yyyyMMdd-HHmmss')).xml"
  $state = foreach($a in $adapters){ foreach($b in $bindings){ Get-NetAdapterBinding -Name $a.Name -ComponentID $b -ErrorAction SilentlyContinue } }
  $state | Export-Clixml -Path $backup
  Write-Host "Backup saved: $backup"
  foreach($a in $adapters){
    foreach($b in $bindings){
      $curr = Get-NetAdapterBinding -Name $a.Name -ComponentID $b -ErrorAction SilentlyContinue
      if ($curr -and $curr.Enabled){ Disable-NetAdapterBinding -Name $a.Name -ComponentID $b -PassThru -ErrorAction SilentlyContinue | Out-Null; Write-Change "Binding disabled: $($a.Name) -> $($curr.DisplayName) ($b)" }
    }
  }
  Write-Host 'Selected bindings processed.'
}
function Bindings-Restore {
  $f = Get-ChildItem $env:ProgramData -Filter 'EthernetBindingsBackup-*.xml' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $f) { Write-Host 'No backup files found. Nothing to restore.'; return }
  Write-Host "Using backup: $($f.FullName)"
  $state = Import-Clixml -Path $f.FullName
  foreach($item in $state){
    $curr = Get-NetAdapterBinding -Name $item.Name -ComponentID $item.ComponentID -ErrorAction SilentlyContinue
    if ($curr -and $curr.Enabled -ne $item.Enabled){
      if ($item.Enabled) { Enable-NetAdapterBinding -Name $item.Name -ComponentID $item.ComponentID -PassThru -ErrorAction SilentlyContinue | Out-Null }
      else { Disable-NetAdapterBinding -Name $item.Name -ComponentID $item.ComponentID -PassThru -ErrorAction SilentlyContinue | Out-Null }
      Write-Change "Binding restored: $($item.Name) -> $($curr.DisplayName) ($($item.ComponentID)) to $($item.Enabled)"
    }
  }
  Write-Host 'Bindings restored to saved state (if differences were found).'
}
function Bindings-Status {
  $bindings = 'ms_msclient','ms_server','ms_implat','ms_lldp','ms_tcpip6','ms_rspndr','ms_lltdio'
  $adapters = Get-PhysAdapters
  if (-not $adapters){ Write-Host 'No physical Ethernet/Wi-Fi adapters found.'; return }
  foreach($a in $adapters){
    Write-Host "`n[$($a.Name)]"
    foreach($b in $bindings){
      $bind = Get-NetAdapterBinding -Name $a.Name -ComponentID $b -ErrorAction SilentlyContinue
      if ($bind) { "{0,-40} : {1}" -f $bind.DisplayName, [bool]$bind.Enabled | Write-Host }
    }
  }
}
function Adapters-List { Get-PhysAdapters | Select-Object Name, InterfaceDescription, Status, MediaType | Format-Table -AutoSize }

function Adv-Restore {
  $f = Get-ChildItem $env:ProgramData -Filter 'EthProfileBackup-*.xml' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $f) { Write-Host 'No backup found. Nothing to restore.'; return }
  Write-Host "Using backup: $($f.FullName)"
  $data = Import-Clixml $f.FullName
  foreach($pm in $data.Power){
    $cur = Get-NetAdapterPowerManagement -Name $pm.Name -ErrorAction SilentlyContinue
    if ($cur -and ($cur.AllowComputerToTurnOffDevice -ne $pm.AllowComputerToTurnOffDevice -or $cur.WakeOnMagicPacket -ne $pm.WakeOnMagicPacket -or $cur.WakeOnPattern -ne $pm.WakeOnPattern)) {
      Set-NetAdapterPowerManagement -Name $pm.Name -AllowComputerToTurnOffDevice $pm.AllowComputerToTurnOffDevice -WakeOnMagicPacket $pm.WakeOnMagicPacket -WakeOnPattern $pm.WakeOnPattern -ErrorAction SilentlyContinue | Out-Null
      Write-Change "PM restored: $($pm.Name)"
    }
  }
  foreach($ap in $data.Advanced){
    if ($ap.RegistryKeyword){
      $cur = Get-NetAdapterAdvancedProperty -Name $ap.Name -RegistryKeyword $ap.RegistryKeyword -ErrorAction SilentlyContinue
      if ($cur -and $cur.DisplayValue -ne $ap.DisplayValue){
        Set-NetAdapterAdvancedProperty -Name $ap.Name -RegistryKeyword $ap.RegistryKeyword -DisplayValue $ap.DisplayValue -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Write-Change "Advanced restored: $($ap.Name) -> $($ap.DisplayName) = $($ap.DisplayValue) (was $($cur.DisplayValue))"
      }
    }
  }
  Write-Host 'Restore complete (only differences were logged).'
}

function Adv-Show {
  $ad = Get-PhysAdapters
  if (-not $ad){ Write-Host 'No physical Ethernet/Wi-Fi adapters found.'; return }
  foreach($a in $ad){
    Write-Host "`n[$($a.Name)]" -ForegroundColor Cyan
    Get-NetAdapterPowerManagement -Name $a.Name | Format-Table AllowComputerToTurnOffDevice,WakeOnMagicPacket,WakeOnPattern -AutoSize
    $want = ($DesiredAdvancedMap.K | Select-Object -Unique)
    Get-NetAdapterAdvancedProperty -Name $a.Name -AllProperties -ErrorAction SilentlyContinue |
      Where-Object { $want -contains $_.RegistryKeyword -or ($_.DisplayName -match ($OffloadNamePatterns -join '|')) } |
      Select-Object DisplayName,DisplayValue,RegistryKeyword | Format-Table -AutoSize
  }
}

function Full-Restore {
  Write-Host "Reverting TCP to NORMAL and removing $RegName..."
  Set-TcpMode -Mode 'Normal'
  Write-Host "Restoring adapter bindings from latest backup (if available)..."
  Bindings-Restore
  Write-Host "Restoring Power/Advanced settings from latest backup (if available)..."
  Adv-Restore
  Write-Host "[+] Full Restore complete."
}

# --------------- router ---------------
switch ($Action) {
  'Show-TcpStatus'   { Show-TcpStatus }
  'Set-TcpMode'      { if (-not $Mode) { Write-Host 'Missing Mode (Disabled|Normal|HighlyRestricted)'; break }; Set-TcpMode -Mode $Mode }
  'Set-Congestion'   { if (-not $Mode) { Write-Host 'Missing Mode (BBR2|CUBIC|NewReno)'; break }; Set-Congestion -Provider $Mode }
  'Bindings-Disable' { Bindings-Disable }
  'Bindings-Restore' { Bindings-Restore }
  'Bindings-Status'  { Bindings-Status }
  'Adapters-List'    { Adapters-List }
  'Adv-Apply'        { Adv-Apply }
  'Adv-Restore'      { Adv-Restore }
  'Adv-Show'         { Adv-Show }
  'PerfRegs-Apply'   { Apply-PerfRegs-AllAdapters }
  'Full-Restore'     { Full-Restore }
}
