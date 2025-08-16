#Requires -RunAsAdministrator
param(
  [string]$Action = "",
  [string]$Mode   = ""
)

$ErrorActionPreference = "SilentlyContinue"

function WTitle([string]$t){ Write-Host ""; Write-Host $t -ForegroundColor Cyan }
function WInfo ([string]$t){ Write-Host $t -ForegroundColor Gray }
function WOK   ([string]$t){ Write-Host $t -ForegroundColor Green }
function WWarn ([string]$t){ Write-Host $t -ForegroundColor Yellow }
function WErr  ([string]$t){ Write-Host $t -ForegroundColor Red }

$Stamp      = (Get-Date).ToString("yyyyMMdd-HHmmss")
$BackupRoot = "C:\ProgramData\NetOpt\Backups"
New-Item -ItemType Directory -Force -Path $BackupRoot | Out-Null

# ---------------- TCP helpers ----------------
function Show-TcpGlobal {
  Write-Host ""
  Write-Host "-- Current TCP global settings --" -ForegroundColor Yellow
  Write-Host "Querying active state..."
  Write-Host ""
  $out = cmd /c "netsh int tcp show global"
  foreach($ln in $out -split "`r?`n"){ if($ln -ne $null){ Write-Host $ln -ForegroundColor DarkGray } }
}

function Set-Autotuning([string]$level){
  if ($level) { cmd /c "netsh int tcp set global autotuninglevel=$level" | Out-Null }
}

function Apply-CoreSafe {
  Write-Host ""
  Write-Host "------- Advanced Apply + Extras -------" -ForegroundColor Yellow

  $afdKey = "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"
  New-Item -Path $afdKey -Force | Out-Null
  $cur = (Get-ItemProperty -Path $afdKey -Name FastSendDatagramThreshold -ErrorAction SilentlyContinue).FastSendDatagramThreshold
  if ($cur -ne 409600) {
    New-ItemProperty -Path $afdKey -Name FastSendDatagramThreshold -Value 409600 -PropertyType DWord -Force | Out-Null
  } else {
    Write-Host "Afd FastSendDatagramThreshold already 409600." -ForegroundColor DarkYellow
  }

  Write-Host "- Disabling heuristics/ECN/timestamps/chimney; enabling RSS; disabling RSC" -ForegroundColor DarkGray
  cmd /c "netsh int tcp set global ecncapability=disabled"        | Out-Null
  cmd /c "netsh int tcp set global timestamps=disabled"           | Out-Null
  cmd /c "netsh int tcp set global chimney=disabled"              | Out-Null 2>nul
  cmd /c "netsh int tcp set global rsc=disabled"                  | Out-Null
  cmd /c "netsh int tcp set global rss=enabled"                   | Out-Null
  cmd /c "netsh int tcp set global nonsackrttresiliency=disabled" | Out-Null
  cmd /c "netsh int tcp set global fastopen=enabled"              | Out-Null
  cmd /c "netsh int tcp set global hystart=enabled"               | Out-Null
  cmd /c "netsh int tcp set global prr=enabled"                   | Out-Null

  Show-TcpGlobal
  Write-Host ""
  WOK "Advanced + Power profile applied (only differences were logged)."
}

# -------- Congestion helpers --------
function Get-NetshValue([string]$cmd, [string]$label){
  $out = cmd /c $cmd
  ($out -split "`r?`n" | Where-Object { $_ -match $label } | Select-Object -First 1) -replace '.*:\s*',''
}
function Get-TemplateProvider([string]$tpl){
  Get-NetshValue ("netsh int tcp show supplemental template=$tpl") 'Congestion Provider'
}
function Set-AllTemplates([string]$provider){
  $tpls = @('internet','internetcustom','datacenter','datacentercustom','compat')
  foreach($t in $tpls){
    try{
      cmd /c "netsh int tcp set supplemental template=$t congestionprovider=$provider" | Out-Null
      $p = Get-TemplateProvider $t
      if (-not $p) { $p = $provider }
      Write-Host ("[+] {0} congestion provider -> {1}" -f $t, $p.ToLower()) -ForegroundColor Green
    }catch{
      Write-Host ("[i] {0} unchanged (build may lock provider)" -f $t) -ForegroundColor DarkGray
    }
  }
}

function Run-ApplyAllInteractive {
  Write-Host ""
  Write-Host "[INFO] Running SAFE Apply-All (TCP/registry)..." -ForegroundColor Cyan
  Write-Host ""
  Write-Host "======= APPLY ALL =======" -ForegroundColor Yellow
  Write-Host ""

  # 1) Congestion provider FIRST
  Write-Host "-- Choose a TCP congestion provider --" -ForegroundColor Yellow
  Write-Host "  1. BBR2  (best performing - Windows 11 24H2+)"
  Write-Host "  2. CUBIC (default)"
  Write-Host "  3. NewReno (test)"
  Write-Host "  4. Skip   (leave current provider)"
  $cp = Read-Host "Choose 1-4"
  $chosen = $null
  switch ($cp) {
    '1' { Write-Host "-- TCP Congestion Provider --" -ForegroundColor Yellow
          Write-Host "Loopback Large MTU now disabled."
          cmd /c "netsh int tcp set global loopbacklargemtu=disabled" | Out-Null
          $chosen = 'bbr2';  Set-AllTemplates $chosen }
    '2' { Write-Host "-- TCP Congestion Provider --" -ForegroundColor Yellow
          $chosen = 'cubic'; Set-AllTemplates $chosen }
    '3' { Write-Host "-- TCP Congestion Provider --" -ForegroundColor Yellow
          $chosen = 'newreno'; Set-AllTemplates $chosen }
    default { Write-Host "-- TCP Congestion Provider --" -ForegroundColor Yellow
             Write-Host "[i] leaving current provider(s)" -ForegroundColor DarkGray }
  }

  # 2) Verified settings (read-back) in DarkGray
  Write-Host ""
  Write-Host "Verified settings (read-back):" -ForegroundColor Gray
  $lb = Get-NetshValue "netsh int tcp show global" 'Loopback Large MTU'
  if (-not $lb) { $lb = 'unknown' }
  Write-Host ("Loopback Large MTU  -> {0}" -f ($lb.ToLower())) -ForegroundColor DarkGray
  foreach($t in 'internet','internetcustom','datacenter','datacentercustom','compat'){
    $p = Get-TemplateProvider $t
    if (-not $p -and $chosen) { $p = $chosen }
    $val = $(if($p){$p.ToLower()}else{'default'})
    Write-Host ("{0,-16} -> {1}" -f $t,$val) -ForegroundColor DarkGray
  }

  # 3) Manual block
  Write-Host ""
  Write-Host "-- How to switch ALL templates manually (if your build allows) --" -ForegroundColor Yellow
  Write-Host "netsh int tcp set global loopbacklargemtu=disabled"
  Write-Host "netsh int tcp set supplemental internet          congestionprovider=bbr2"
  Write-Host "netsh int tcp set supplemental internetcustom    congestionprovider=bbr2"
  Write-Host "netsh int tcp set supplemental datacenter        congestionprovider=bbr2"
  Write-Host "netsh int tcp set supplemental datacentercustom  congestionprovider=bbr2"
  Write-Host "netsh int tcp set supplemental compat            congestionprovider=bbr2"
  Write-Host "Note: Some Windows builds intentionally lock 'compat' (often to NewReno)." -ForegroundColor DarkGray

  # 4) Auto-tuning menu
  Write-Host ""
  Write-Host "-- Choose autotuning mode to use with the full profile --" -ForegroundColor Yellow
  Write-Host "  1. DISABLED        (max stability, may reduce bandwidth)"
  Write-Host "  2. HIGHLYRESTRICTED (closer to normal bandwidth)"
  Write-Host "  3. NORMAL          (no TCP tuning; still applies NIC changes)"
  Write-Host "  4. Back/Skip"
  $at = Read-Host "Choose 1-4"
  switch ($at) {
    '1' { Set-Autotuning 'disabled' }
    '2' { Set-Autotuning 'highlyrestricted' }
    '3' { Set-Autotuning 'normal' }
    default { Write-Host "Invalid -Mode. Use Disabled/HighlyRestricted/Normal." -ForegroundColor DarkYellow }
  }

  # 5) SAFE core + table
  Write-Host ""
  Write-Host "-- Applying Advanced + Extras --" -ForegroundColor Yellow
  Apply-CoreSafe

  Write-Host ""
  WOK "[+] APPLY ALL complete."
}

# ---------------- NIC backup/restore ----------------
function Backup-Nic([string]$nicName){
  $leaf = $nicName -replace "[\\/:*?""<>|]","_"
  $path = Join-Path $BackupRoot ("NIC-{0}-{1}.json" -f $leaf, $Stamp)
  $props = Get-NetAdapterAdvancedProperty -Name $nicName -ErrorAction SilentlyContinue |
           Select-Object Name,DisplayName,DisplayValue,RegistryKeyword,RegistryValue
  $props | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 $path
  $path
}
function Nic-Backup-All {
  $rows = @()
  Get-NetAdapter -Physical | ForEach-Object {
    $n = $_.Name
    $p = Backup-Nic $n
    Write-Host ("Saved NIC backup: {0}" -f $p) -ForegroundColor DarkGray
    $rows += [PSCustomObject]@{ Name=$n; Backup=$p }
  }
  $combo = Join-Path $BackupRoot ("NIC-ALL-{0}.json" -f $Stamp)
  $rows | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 $combo
  Write-Host ("Combined backup saved: {0}" -f $combo) -ForegroundColor DarkGray
  $combo
}
function Restore-Nic-FromFile([string]$file){
  if (-not (Test-Path $file)) { WErr "Backup not found: $file"; return }
  $data = Get-Content $file -Raw | ConvertFrom-Json
  if ($data -is [array]) {
    foreach($row in $data){ if ($row.Name -and $row.Backup){ Restore-Nic-FromFile $row.Backup } }
    return
  }
  $nicName = (Split-Path $file -Leaf) -replace "^NIC-(.+?)-\d+.*$","`$1"
  foreach($p in $data){
    try{
      if ($p.RegistryKeyword) {
        Set-NetAdapterAdvancedProperty -Name $nicName -RegistryKeyword $p.RegistryKeyword -RegistryValue $p.RegistryValue -NoRestart -ErrorAction Stop
      } elseif ($p.DisplayName) {
        Set-NetAdapterAdvancedProperty -Name $nicName -DisplayName $p.DisplayName -DisplayValue $p.DisplayValue -NoRestart -ErrorAction Stop
      }
    }catch{}
  }
  WOK ("Restored advanced properties for '{0}'" -f $nicName)
}

# -------- Buffer detection + setting --------
function Find-NicBufferProps {
  param([string]$Name)
  $props = Get-NetAdapterAdvancedProperty -Name $Name -ErrorAction SilentlyContinue
  if (-not $props) { return @{ RX=$null; TX=$null } }
  $rx = $props | Where-Object {
    $_.RegistryKeyword -match "receive.*buffers?|receive.*descriptors?|rx.*buffer" -or
    $_.DisplayName     -match "receive.*buffers?|receive.*descriptors?|rx.*buffer" -or
    $_.Name            -match "receive.*buffers?|receive.*descriptors?|rx.*buffer"
  } | Select-Object -First 1
  $tx = $props | Where-Object {
    $_.RegistryKeyword -match "transmit.*buffers?|transmit.*descriptors?|tx.*buffer" -or
    $_.DisplayName     -match "transmit.*buffers?|transmit.*descriptors?|tx.*buffer" -or
    $_.Name            -match "transmit.*buffers?|transmit.*descriptors?|tx.*buffer"
  } | Select-Object -First 1
  @{ RX=$rx; TX=$tx }
}
function Set-NicBufferMax {
  param([string]$Name,[ValidateSet("RX","TX")][string]$Which,[object]$Prop)
  if (-not $Prop) { return @{Changed=$false;Value=$null} }
  $candidates = 4096,2048,1024,512,256,128
  $kw=$Prop.RegistryKeyword; $disp=$Prop.DisplayName
  foreach($v in $candidates){
    try{
      if ($kw)   { Set-NetAdapterAdvancedProperty -Name $Name -RegistryKeyword $kw -RegistryValue $v -NoRestart -ErrorAction Stop }
      elseif($disp){ Set-NetAdapterAdvancedProperty -Name $Name -DisplayName $disp -DisplayValue $v -NoRestart -ErrorAction Stop }
      $now = (Get-NetAdapterAdvancedProperty -Name $Name -ErrorAction SilentlyContinue |
              Where-Object { $_.RegistryKeyword -eq $kw -or $_.DisplayName -eq $disp }) | Select-Object -First 1
      $ok=$false
      if ($now){
        if ($now.DisplayValue -match "^\d+$") { $ok = ([int]$now.DisplayValue -eq $v) }
        elseif ($now.RegistryValue -is [array]) { $ok = ($now.RegistryValue[0] -eq $v) }
      }
      if ($ok){ return @{Changed=$true;Value=$v} }
    }catch{}
  }
  @{Changed=$false;Value=$null}
}

# -------- NIC tweak sets (Option A: keep non-buffer tweaks) --------
function Apply-CrossVendorTweaks([string]$nic){
  Write-Host "-- Applying cross-vendor tweaks (MTU, DNS, metrics, TrackNblOwner) --" -ForegroundColor Yellow
  try { Set-NetIPInterface -InterfaceAlias $nic -AutomaticMetric Disabled -InterfaceMetric 1 -ErrorAction SilentlyContinue } catch {}
  New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" -Force | Out-Null
  New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" -Name "TrackNblOwner" -PropertyType DWord -Value 0 -Force | Out-Null
}
function Apply-IntelTweaks([string]$nic){
  Write-Host ("-- Intel advanced tweaks for '{0}' --" -f $nic) -ForegroundColor Yellow
  $map=@(
    @{Key="*FlowControl";Val=0}, @{Key="*InterruptModeration";Val=0},
    @{Key="*IPChecksumOffloadIPv4";Val=0}, @{Key="*TCPChecksumOffloadIPv4";Val=0}, @{Key="*UDPChecksumOffloadIPv4";Val=0},
    @{Key="*IPChecksumOffloadIPv6";Val=0}, @{Key="*TCPChecksumOffloadIPv6";Val=0}, @{Key="*UDPChecksumOffloadIPv6";Val=0},
    @{Key="*LsoV2IPv4";Val=0}, @{Key="*LsoV2IPv6";Val=0},
    @{Key="*RSS";Val=1}, @{Key="*SpeedDuplex";Val=0}, @{Key="*JumboPacket";Val=1514}
  )
  foreach($m in $map){ try{ Set-NetAdapterAdvancedProperty -Name $nic -RegistryKeyword $m.Key -RegistryValue $m.Val -NoRestart -ErrorAction Stop }catch{} }
}
function Apply-RealtekTweaks([string]$nic){
  Write-Host ("-- Realtek advanced tweaks for '{0}' --" -f $nic) -ForegroundColor Yellow
  $map=@(
    @{Key="*FlowControl";Val=0}, @{Key="*InterruptModeration";Val=0},
    @{Key="*IPChecksumOffloadIPv4";Val=0}, @{Key="*TCPChecksumOffloadIPv4";Val=0}, @{Key="*UDPChecksumOffloadIPv4";Val=0},
    @{Key="*IPChecksumOffloadIPv6";Val=0}, @{Key="*TCPChecksumOffloadIPv6";Val=0}, @{Key="*UDPChecksumOffloadIPv6";Val=0},
    @{Key="*LsoV2IPv4";Val=0}, @{Key="*LsoV2IPv6";Val=0},
    @{Key="*RSS";Val=1}, @{Key="*SpeedDuplex";Val=0}, @{Key="*JumboPacket";Val=1514}
  )
  foreach($m in $map){ try{ Set-NetAdapterAdvancedProperty -Name $nic -RegistryKeyword $m.Key -RegistryValue $m.Val -NoRestart -ErrorAction Stop }catch{} }
}

function Apply-NicTweaks-Interactive {
  Write-Host ""
  Write-Host "======== NIC Tweaks (AGGRESSIVE / OPT-IN) ========" -ForegroundColor Yellow
  Nic-Backup-All | Out-Null

  Write-Host ""
  Write-Host "Vendor selection:" -ForegroundColor Gray
  Write-Host "  1. Auto-detect per adapter (recommended)"
  Write-Host "  2. Force Intel tweaks for all adapters"
  Write-Host "  3. Force Realtek tweaks for all adapters"
  Write-Host "  4. Skip vendor-specific advanced tweaks"
  $sel = Read-Host "Choose 1-4 (default 1)"; if(-not $sel){$sel='1'}

  Get-NetAdapter -Physical | ForEach-Object {
    $nic=$_.Name
    Write-Host ""
    Write-Host "-- Backing up adapter advanced properties --"
    Backup-Nic $nic | Out-Null

    # Detect buffer knobs once up front
    $buf = Find-NicBufferProps -Name $nic
    $hasBuf = [bool]($buf.RX -or $buf.TX)
    if (-not $hasBuf) { Write-Host "[Buffers not exposed by this driver - applying non-buffer tweaks only]" -ForegroundColor DarkGray }

    # Cross-vendor tweaks
    Apply-CrossVendorTweaks $nic

    # Vendor-specific selection
    $vendor = switch($sel){ '2'{'Intel'} '3'{'Realtek'} '4'{'Skip'} default{
      $pnp=(Get-NetAdapter -Name $nic -ErrorAction SilentlyContinue).PnPDeviceID
      if($pnp -match "VEN_8086"){'Intel'} elseif($pnp -match "VEN_10EC"){'Realtek'} else {'Unknown'}
    } }

    switch($vendor){
      'Intel'   { Apply-IntelTweaks   $nic }
      'Realtek' { Apply-RealtekTweaks $nic }
      'Skip'    { WInfo "Skipping vendor-specific advanced tweaks" }
      default   { WInfo "Unknown vendor; applying cross-vendor only" }
    }

    # Buffers last (only if present)
    Write-Host ""
    Write-Host ("-- Maximizing buffers for '{0}' --" -f $nic) -ForegroundColor Yellow
    if ($hasBuf) {
      Set-NicBufferMax -Name $nic -Which RX -Prop $buf.RX | Out-Null
      Set-NicBufferMax -Name $nic -Which TX -Prop $buf.TX | Out-Null
    } else {
      Write-Host "[Buffers not exposed by this driver - skipping buffer step]" -ForegroundColor DarkGray
    }
    Write-Host ""
  }

  WOK "NIC tweaks applied."
  WInfo "If a link drops or an adapter disappears, run:  Restore-NicTweaks"
}

# ---------------- Public actions ----------------
switch ($Action) {
  "Show-TcpStatus"   { Show-TcpGlobal; break }
  "Adv-Apply"        { Apply-CoreSafe; break }
  "Apply-All"        { Run-ApplyAllInteractive; break }

  "Nic-Backup"       { Nic-Backup-All | Out-Null; break }
  "Apply-NicTweaks"  { Apply-NicTweaks-Interactive; break }
  "Restore-NicTweaks"{
      $latest = Get-ChildItem $BackupRoot -Filter "NIC-ALL-*.json" |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
      if ($latest) { Restore-Nic-FromFile $latest.FullName } else { WErr "No combined NIC-ALL backup found." }
      break
  }

  "Bindings-Status" {
      Get-NetAdapter -Physical | ForEach-Object {
        $n = $_.Name
        WTitle ("Bindings for '{0}'" -f $n)
        Get-NetAdapterBinding -Name $n |
          Select-Object Name,DisplayName,ComponentID,Enabled |
          Format-Table -AutoSize
      }
      break
  }

  "Full-Restore" {
      Set-Autotuning "normal"
      cmd /c "netsh int tcp set supplemental template=internet congestionprovider=default"  | Out-Null
      cmd /c "netsh int tcp set supplemental template=internetcustom congestionprovider=default" | Out-Null
      cmd /c "netsh int tcp set supplemental template=datacenter congestionprovider=default" | Out-Null
      cmd /c "netsh int tcp set supplemental template=datacentercustom congestionprovider=default" | Out-Null
      cmd /c "netsh int tcp set supplemental template=compat congestionprovider=default" | Out-Null
      Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" -Name "FastSendDatagramThreshold" -ErrorAction SilentlyContinue
      Show-TcpGlobal
      WOK "Full restore complete."
      break
  }

  Default { WInfo "Known actions: Show-TcpStatus, Adv-Apply, Apply-All, Nic-Backup, Apply-NicTweaks, Restore-NicTweaks, Full-Restore, Bindings-Status" }
}
