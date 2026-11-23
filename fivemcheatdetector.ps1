<#
.SYNOPSIS
    FiveM-Sentinel v3.1 - fast, clean, read-only PC-check scanner for FiveM cheat evidence.

.DESCRIPTION
    Shows one progress line per check, then a short plain-English summary:
        SERIOUS = very likely cheat related
        CHECK   = suspicious, look at it manually
        NOTE    = good to know (not a problem by itself)
    Nothing is modified, deleted or uploaded. A full report (HTML/TXT/CSV) is saved to the Desktop.

.PARAMETER Deep                Scan ALL drives completely (very slow). Default is the quick key-folder scan.
.PARAMETER MaxFileScanSeconds  Time limit for the file scan in quick mode (default 40).
.PARAMETER ShowAll             Show every finding on screen (default: top ones only).
.PARAMETER NoOpen              Do not open the HTML report at the end.
.PARAMETER Days                How many days back to read event logs (default 60).
.PARAMETER ExtraKeywords       Extra cheat names to treat as serious, e.g. -ExtraKeywords 'newcheat','other'.

.NOTE
    Run as Administrator. A scanner finds INDICATORS, not proof. Always review findings manually.
#>
[CmdletBinding()]
param(
    [switch]$Deep,
    [switch]$ShowAll,
    [switch]$NoOpen,
    [int]$MaxFileScanSeconds = 40,
    [int]$Days = 60,
    [string[]]$ExtraKeywords = @(),
    [string]$OutDir
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$Version = '3.1'
$Start   = Get-Date

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host ''
    Write-Host '  [!] Please run this as Administrator (right-click PowerShell / Terminal > Run as administrator).' -ForegroundColor Red
    Write-Host ''
    return
}

if (-not $OutDir) { $OutDir = Join-Path ([Environment]::GetFolderPath('Desktop')) ('FiveM_Scan_' + $Start.ToString('yyyyMMdd_HHmmss')) }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# ----------------------------------------------------------------------------------------------
#  KEYWORDS  (edit freely)
# ----------------------------------------------------------------------------------------------
$Brand = @(
 'eulen','red\s?engine','skript\.?gg','hx[\s_\-]?software','kiddion','cherax','2take1','desudo','susano',
 'cheat[\s_\-]?engine','extreme[\s_\-]?injector','xenos[\s_\-]?inject','kdmapper','lynx[\s_\-]?(menu|cheat|mod)',
 'tzx[\s_\-]?(menu|cheat)','phantom[\s_\-]?x','ro[\s_\-]?x[\s_\-]?(menu|cheat)','hammafia','aio[\s_\-]?cheats',
 '(anti[\s_\-]?cheat|ac)[\s_\-]?bypass','txadmin[\s_\-]?bypass','blacklist[\s_\-]?bypass'
) + $ExtraKeywords
$Phrase = @(
 'aimbot','trigger[\s_\-]?bot','wall[\s_\-]?hack','silent[\s_\-]?aim','spoofer','hwid[\s_\-]?spoof','lua[\s_\-]?executor',
 'mod[\s_\-]?menu','fivem[\s_\-]?(hack|cheat|menu|executor|spoof|bypass)','dll[\s_\-]?inject','manual[\s_\-]?map',
 'no[\s_\-]?recoil','no[\s_\-]?spread','magic[\s_\-]?bullet','cheats?[\s_\-]?(menu|loader)','loader[\s_\-]?(cheat|hack)'
)
$Medium = @(
 'process[\s_\-]?hacker','systeminformer','x64dbg','x32dbg','ollydbg','\bida(64)?\b','reclass','scyllahide','injector',
 '(?<!anti[\s_\-]?)\bcheats?\b','\bhack(s|er|ing)?\b','executor','unban','vmprotect','themida','\.ct$'
)
$Weak = @('no[\s_\-]?clip','god[\s_\-]?mode','free[\s_\-]?cam','\besp\b','keygen','\bcrack(ed)?\b','autohotkey','\.ahk$')
$Allow = @(
 'anti[\s_\-]?cheat','easyanticheat','battleye','ocean[\s_\-]?(anti|ac)','overwolf','medal','downloader','uploader',
 'detector','scanner','sentinel','checker','screenshare','bypasscsp'
)

$RxBrand   = '(?i)(' + ($Brand  -join '|') + ')'
$RxPhrase  = '(?i)(' + ($Phrase -join '|') + ')'
$RxStrong  = '(?i)(' + (($Brand + $Phrase) -join '|') + ')'
$RxMedium  = '(?i)(' + ($Medium -join '|') + ')'
$RxWeak    = '(?i)(' + ($Weak   -join '|') + ')'
$RxAllow   = '(?i)(' + ($Allow  -join '|') + ')'
$RxBin     = '(?i)(eulen|redengine|skript\.gg|kiddion|cherax|2take1|desudo|susano|aimbot|triggerbot|silent\s?aim|hwid\s?spoof|lua\s?executor|kdmapper|mod\s?menu)'
$RxVulnDrv = '(?i)^(capcom|iqvw64e?|gdrv\d?|rtcore(32|64)|dbutil_2_3|asrdrv\d*|asio[23]?|cpuz\d*|winring0(x64)?|inpoutx?64?|physmem|phymem|kprocesshacker|mhyprot\d?|atillk64|eneio(64)?|msio(32|64)|wnbios|piddrv|directio(32|64)?|dbk(32|64)|glckio2|hwrwdrv|ntiolib(_x64)?|zam64|amifldrv64|rwdrv|winio(32|64)?|bs_def|kdmapper|asmmap(64)?|asupio|lnvmsrio|rzpnk|alsysio64|mtcbsv64)$'
$RxSkipDir = '(?i)\\(Windows\\(WinSxS|assembly|servicing|SoftwareDistribution|Installer|System32|SysWOW64|Fonts)|Program Files( \(x86\))?\\(WindowsApps|Common Files|Microsoft|Windows[^\\]*|Google|Mozilla)|FiveM\\FiveM\.app\\(citizen|crashes|logs|data\\(cache|server-cache|server-cache-priv|game-storage))|node_modules|\.git|Cache|Code Cache|GPUCache|Service Worker|ShaderCache|DawnCache|\$WinREAgent|Packages)(\\|$)'
$RxRemote  = '(?i)(anydesk|teamviewer|parsec|rustdesk|ultraviewer|supremo|ammyy|splashtop|radmin|chromoting|screenconnect|aeroadmin)'
$RxUserDir = '(?i)\\(Users|ProgramData|Temp|Downloads|Desktop)\\'

$CatInfo = @{
 'Process'       = @('Suspicious program running', 'A running program has the name of a known cheat or hacking tool.')
 'WindowTitle'   = @('Suspicious window open', 'An open window title matches a cheat or hacking tool.')
 'RemoteTool'    = @('Remote-control program running', 'Someone else can control or help on this PC remotely. Ask the player why it is open.')
 'FiveM'         = @('FiveM status', '')
 'Module'        = @('Suspicious DLL inside FiveM/GTA', 'DLLs loaded from user folders or the plugins folder are how most cheats get injected into the game.')
 'FiveM-plugins' = @('File in FiveM plugins folder', 'This folder is normally empty. Cheat DLL/ASI files are often placed here.')
 'FiveM-mods'    = @('File in FiveM mods folder', 'Modified game files can be used to cheat.')
 'FiveM-Files'   = @('Unexpected plugin file in FiveM', '.asi/.sys files do not belong inside FiveM.app.')
 'CitizenFX.ini' = @('Suspicious line in FiveM settings', 'The FiveM config mentions a cheat-related word.')
 'FiveM-Log'     = @('Cheat word in FiveM log', 'FiveM logs record loaded modules and errors; a cheat name there is a strong clue.')
 'GTA-Folder'    = @('Mod/loader file in GTA V folder', 'ASI loaders, ScriptHook and proxy DLLs (dinput8, d3d11...) are used by mods and cheats.')
 'Folder'        = @('Folder with cheat-like name', 'The folder name matches a known cheat.')
 'File'          = @('File with cheat-like name', 'The file name matches a known cheat or cheat tool.')
 'FileContent'   = @('Cheat words inside a file', 'The text inside this file mentions cheat names or features.')
 'BinaryString'  = @('Program contains cheat name', 'The program file itself contains the name of a known cheat.')
 'RecycleBin'    = @('Deleted cheat-like file', 'The player deleted a file that matches a cheat name.')
 'Prefetch'      = @('Windows remembers running it', 'Prefetch proves a program with this name was executed, even if the file is now deleted.')
 'UserAssist'    = @('Windows remembers running it', 'UserAssist proves this program was started from the desktop, even if it was deleted.')
 'MuiCache'      = @('Windows remembers running it', 'This program was run on this PC (kept in the MuiCache history).')
 'AppCompat'     = @('Windows remembers running it', 'This program was run on this PC (kept in the compatibility history).')
 'RunMRU'        = @('Typed in the Run box', 'The player typed this into the Windows Run dialog.')
 'BAM'           = @('Windows remembers running it', 'The Background Activity Monitor recorded this program being executed.')
 'RecentLnk'     = @('Recently opened file', 'This file/shortcut was recently opened.')
 'Driver'        = @('Suspicious driver', 'Cheats and HWID spoofers load kernel drivers (often vulnerable ones) to hide from anti-cheat.')
 'DriverTrace'   = @('Leftover trace of a cheat-style driver', 'The service entry of a vulnerable/abused driver still exists in the registry.')
 'DriverFile'    = @('Abused driver file on disk', 'This driver is commonly used by kernel mappers and spoofers.')
 'Kernel'        = @('Windows security setting changed', 'Test-signing / disabled integrity checks let unsigned cheat drivers load.')
 'Service'       = @('Suspicious service', 'A Windows service matches a cheat name or runs from a user folder.')
 'Task'          = @('Suspicious scheduled task', 'A scheduled task matches a cheat name or runs from a user folder.')
 'Startup'       = @('Suspicious startup entry', 'This program starts automatically with Windows.')
 'EventLog'      = @('Windows log was cleared', 'Clearing the event log is a common way to hide activity.')
 'ServiceInstall'= @('Driver/service installed recently', 'A kernel driver was installed from an unusual location.')
 'Defender'      = @('Windows Defender event', 'Defender detected or was changed around the time something suspicious ran.')
 'DefenderExcl'  = @('Defender exclusion', 'Cheats are often added to the Defender exclusion list so they are not removed.')
 'USN'           = @('File-activity journal deleted', 'The NTFS journal is often wiped to hide deleted files.')
 'SystemTime'    = @('System clock was changed', 'Changing the clock can fake file and execution timestamps.')
 'DNS'           = @('Visited a cheat website', 'The DNS cache shows this PC contacted a cheat-related domain.')
 'Hosts'         = @('Custom hosts-file entry', 'The hosts file redirects websites; sometimes used to block anti-cheat servers.')
 'Browser'       = @('Cheat words in browser history', 'The browser history contains cheat-related searches or websites.')
 'MAC'           = @('Network address was changed', 'A custom MAC address is a typical sign of an HWID spoofer.')
 'HWID'          = @('Hardware ID information', 'Blank or placeholder hardware IDs can mean the IDs were spoofed.')
 'VM'            = @('Running in a virtual machine', '')
 'Hardware'      = @('Suspicious hardware device', 'DMA cards and Arduino-type devices are used for hardware cheating.')
 'Scanner'       = @('Scanner note', '')
}

# ----------------------------------------------------------------------------------------------
#  HELPERS
# ----------------------------------------------------------------------------------------------
$Findings = New-Object System.Collections.Generic.List[object]
$Seen     = New-Object 'System.Collections.Generic.HashSet[string]'
$SevOrder = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
$SigCache = @{}

$SelfPids = New-Object 'System.Collections.Generic.HashSet[int]'
$cur = [int]$PID
while ($cur -gt 0 -and $SelfPids.Add($cur)) {
    $pp = Get-CimInstance Win32_Process -Filter "ProcessId=$cur"
    if (-not $pp -or $pp.Name -eq 'explorer.exe') { break }
    $cur = [int]$pp.ParentProcessId
}

function Leaf([string]$s) { try { [IO.Path]::GetFileName($s.TrimEnd('\')) } catch { $s } }
function Cut([string]$s, [int]$n = 120) { if ($s.Length -gt $n) { $s.Substring(0, $n - 3) + '...' } else { $s } }

function Get-Sev([string]$short, [string]$full = '') {
    $all = "$short $full"
    if ($all -match $RxBrand)   { return 'High' }
    if ($all -match $RxAllow)   { return $null }
    if ($all -match $RxPhrase)  { return 'High' }
    if ($short -match $RxMedium){ return 'Medium' }
    if ($short -match $RxWeak)  { return 'Low' }
    return $null
}
function Test-Signed([string]$p) {
    if (-not $p) { return $false }
    if ($SigCache.ContainsKey($p)) { return $SigCache[$p] }
    $ok = $false
    try { $ok = ((Get-AuthenticodeSignature -LiteralPath $p).Status -eq 'Valid') } catch {}
    $SigCache[$p] = $ok
    return $ok
}
function Add-Finding([string]$Category, [string]$Severity, [string]$Item, [string]$Detail = '') {
    if ($OutDir -and $Item -like "$OutDir*") { return }
    if (-not $Seen.Add("$Category|$Item")) { return }
    $Findings.Add([pscustomobject]@{ Severity = $Severity; Category = $Category; Item = $Item; Detail = $Detail })
}

$script:SecIdx = 0
$TotalSec = 12
function Invoke-Section([string]$Name, [scriptblock]$Block) {
    $script:SecIdx++
    $label = ('[{0,2}/{1}] {2} ' -f $script:SecIdx, $TotalSec, $Name)
    Write-Host ('  ' + $label.PadRight(50, '.') + ' ') -NoNewline
    $before = $Findings.Count
    try { & $Block } catch { Add-Finding 'Scanner' 'Info' "Section failed: $Name" $_.Exception.Message }
    $new = @(); if ($Findings.Count -gt $before) { $new = $Findings.GetRange($before, $Findings.Count - $before) }
    $h = @($new | Where-Object { $_.Severity -eq 'High' }).Count
    $m = @($new | Where-Object { $_.Severity -eq 'Medium' }).Count
    if ($h -gt 0)     { Write-Host ("[XX] {0} serious, {1} to check" -f $h, $m) -ForegroundColor Red }
    elseif ($m -gt 0) { Write-Host ("[!!] {0} to check" -f $m) -ForegroundColor Yellow }
    else              { Write-Host '[OK]' -ForegroundColor Green }
}

function Get-UserProfiles { Get-ChildItem "$env:SystemDrive\Users" -Directory -Force | Where-Object { $_.Name -notin 'Public','Default','Default User','All Users' } }
function Get-UserHives    { Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.Name -match '\\S-1-5-21-[\d-]+$' } | ForEach-Object { $_.PSPath } }
function ROT13([string]$s) {
    -join ($s.ToCharArray() | ForEach-Object {
        $c = [int]$_
        if ($c -ge 65 -and $c -le 90)      { [char]((($c - 65 + 13) % 26) + 65) }
        elseif ($c -ge 97 -and $c -le 122) { [char]((($c - 97 + 13) % 26) + 97) }
        else { $_ }
    })
}
function Get-Hash([string]$p) { try { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash } catch { '' } }
function Read-SharedBytes([string]$p) {
    $fs = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite,Delete')
    try { $ms = New-Object IO.MemoryStream; $fs.CopyTo($ms); $ms.ToArray() } finally { $fs.Dispose() }
}
function Scan-RegNames([string]$Path, [string]$Cat) {
    $k = Get-Item -LiteralPath $Path
    if (-not $k) { return }
    foreach ($n in $k.GetValueNames()) { $s = Get-Sev (Leaf $n) $n; if ($s) { Add-Finding $Cat $s $n '' } }
}
function Get-Ev($log, $ids) { Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $ids; StartTime = $Start.AddDays(-$Days) } -ErrorAction SilentlyContinue }
function Get-FiveMPaths {
    $r = @()
    foreach ($p in Get-UserProfiles) { $a = Join-Path $p.FullName 'AppData\Local\FiveM'; if (Test-Path $a) { $r += $a } }
    $r | Select-Object -Unique
}
function Get-GtaDirs {
    $d = @()
    foreach ($fm in Get-FiveMPaths) {
        foreach ($ini in @("$fm\FiveM.app\CitizenFX.ini", "$fm\CitizenFX.ini")) {
            if (Test-Path $ini) { $m = Select-String -Path $ini -Pattern '^\s*IVPath\s*=\s*(.+)$'; if ($m) { $d += $m.Matches[0].Groups[1].Value.Trim() } }
        }
    }
    foreach ($rk in 'HKLM:\SOFTWARE\WOW6432Node\Rockstar Games\Grand Theft Auto V','HKLM:\SOFTWARE\Rockstar Games\Grand Theft Auto V','HKLM:\SOFTWARE\WOW6432Node\Rockstar Games\GTAV') {
        $v = (Get-ItemProperty $rk).InstallFolder; if ($v) { $d += $v }
    }
    $d | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
}
# Directory walker with depth limit + time limit
function Walk([string]$Root, [int]$MaxDepth = 64, $SW = $null, [int]$Limit = 0) {
    $stack = New-Object 'System.Collections.Generic.Stack[object]'
    $stack.Push(@($Root, 0))
    while ($stack.Count -gt 0) {
        if ($SW -and $SW.Elapsed.TotalSeconds -gt $Limit) { break }
        $it = $stack.Pop(); $d = $it[0]; $depth = $it[1]
        if ($d -match $RxSkipDir) { continue }
        $leaf = Leaf $d
        if ($leaf) { $sv = Get-Sev $leaf; if ($sv -eq 'High') { Add-Finding 'Folder' 'High' $d '' } }
        try { foreach ($f in [IO.Directory]::EnumerateFiles($d)) { $f } } catch {}
        if ($depth -lt $MaxDepth) {
            try {
                foreach ($s in [IO.Directory]::EnumerateDirectories($d)) {
                    if ([IO.File]::GetAttributes($s) -band [IO.FileAttributes]::ReparsePoint) { continue }
                    $stack.Push(@($s, ($depth + 1)))
                }
            } catch {}
        }
    }
}

# ----------------------------------------------------------------------------------------------
#  HEADER
# ----------------------------------------------------------------------------------------------
Clear-Host
$line = '=' * 72
Write-Host ''
Write-Host $line -ForegroundColor Magenta
Write-Host "   FiveM-Sentinel v$Version  -  PC CHECK" -ForegroundColor White
Write-Host ("   PC: {0}    Date: {1}    Mode: {2}" -f $env:COMPUTERNAME, $Start.ToString('yyyy-MM-dd HH:mm'), $(if ($Deep) { 'DEEP (all drives, slow)' } else { 'QUICK (key folders)' })) -ForegroundColor Gray
Write-Host '   Read-only: nothing is changed, deleted or uploaded.' -ForegroundColor DarkGray
Write-Host $line -ForegroundColor Magenta
Write-Host ''
Write-Host '  Scanning, please wait...' -ForegroundColor Gray
Write-Host ''

# ----------------------------------------------------------------------------------------------
#  1. PROCESSES
# ----------------------------------------------------------------------------------------------
Invoke-Section 'Running programs' {
    foreach ($p in Get-CimInstance Win32_Process) {
        if ($SelfPids.Contains([int]$p.ProcessId)) { continue }
        $path = $p.ExecutablePath
        $sev = Get-Sev $p.Name $path
        if ($sev -and $sev -ne 'High' -and (Test-Signed $path)) { $sev = $null }
        if ($sev) { Add-Finding 'Process' $sev $p.Name ("PID {0}  {1}" -f $p.ProcessId, $path) }
        if ($p.Name -match $RxRemote) { Add-Finding 'RemoteTool' 'Low' $p.Name "Running now (PID $($p.ProcessId))" }
        if ($path -and -not (Test-Path -LiteralPath $path)) { Add-Finding 'Process' 'Medium' $p.Name "Program is running but its file was deleted: $path" }
    }
    foreach ($w in Get-Process | Where-Object { $_.MainWindowTitle -and -not $SelfPids.Contains($_.Id) }) {
        $s = Get-Sev $w.MainWindowTitle
        if ($s) { Add-Finding 'WindowTitle' $s $w.MainWindowTitle "Program: $($w.ProcessName)" }
    }
}

# ----------------------------------------------------------------------------------------------
#  2. FIVEM / GTA MODULES
# ----------------------------------------------------------------------------------------------
Invoke-Section 'FiveM / GTA game (injected DLLs)' {
    $procs = Get-Process | Where-Object { $_.ProcessName -match '(?i)^FiveM|GTAProcess|^GTA5' }
    if (-not $procs) { Add-Finding 'FiveM' 'Info' 'FiveM is not running' 'Start FiveM, join a server, then scan again to check for injected DLLs.'; return }
    foreach ($p in $procs) {
        $mods = $null; try { $mods = $p.Modules } catch {}
        if (-not $mods) { Add-Finding 'Module' 'Medium' $p.ProcessName "Cannot read the modules of this game process (PID $($p.Id))"; continue }
        foreach ($m in $mods) {
            $path = $m.FileName
            if (-not $path -or $path -match '(?i)\\Windows\\(System32|SysWOW64|WinSxS)\\') { continue }
            $sev = Get-Sev $m.ModuleName $path
            if ($sev -eq 'High') { Add-Finding 'Module' 'High' $path "Loaded in $($p.ProcessName)"; continue }
            if (-not (Test-Path -LiteralPath $path)) { Add-Finding 'Module' 'Medium' $m.ModuleName "DLL is loaded but its file was deleted: $path"; continue }
            if ($path -match '(?i)\\FiveM\.app\\plugins\\') { Add-Finding 'Module' 'High' $path 'Loaded from the FiveM plugins folder'; continue }
            if ($path -match '(?i)\\(Temp|Downloads|Desktop|AppData\\Roaming)\\') { Add-Finding 'Module' 'High' $path "Loaded into $($p.ProcessName) from a user folder"; continue }
            if ($path -notmatch '(?i)\\FiveM\\FiveM\.app\\|\\Program Files' -and -not (Test-Signed $path)) { Add-Finding 'Module' 'Medium' $path "Unsigned DLL inside $($p.ProcessName)" }
        }
    }
}

# ----------------------------------------------------------------------------------------------
#  3. FIVEM + GTA FOLDERS
# ----------------------------------------------------------------------------------------------
Invoke-Section 'FiveM and GTA V folders' {
    foreach ($fm in Get-FiveMPaths) {
        $app = Join-Path $fm 'FiveM.app'
        foreach ($sub in 'plugins','mods') {
            foreach ($f in Get-ChildItem (Join-Path $app $sub) -Recurse -File -Force) {
                Add-Finding "FiveM-$sub" 'High' $f.FullName "Created $($f.CreationTime.ToString('yyyy-MM-dd')) | SHA256 $(Get-Hash $f.FullName)"
            }
        }
        foreach ($f in Get-ChildItem $app -Recurse -Depth 2 -File -Force | Where-Object { $_.Extension -in '.asi','.sys' }) {
            Add-Finding 'FiveM-Files' 'Medium' $f.FullName "SHA256 $(Get-Hash $f.FullName)"
        }
        $ini = Join-Path $app 'CitizenFX.ini'
        if (Test-Path $ini) { foreach ($l in Get-Content $ini) { if ((Get-Sev $l) -eq 'High') { Add-Finding 'CitizenFX.ini' 'High' $l.Trim() $ini } } }
        foreach ($lg in (Get-ChildItem (Join-Path $app 'logs') -Filter *.log -File | Sort-Object LastWriteTime -Descending | Select-Object -First 10)) {
            foreach ($h in (Select-String -Path $lg.FullName -Pattern $RxStrong | Select-Object -First 3)) {
                Add-Finding 'FiveM-Log' 'High' $h.Line.Trim() $lg.Name
            }
        }
    }
    foreach ($g in Get-GtaDirs) {
        foreach ($f in Get-ChildItem $g -Force -File) {
            if ($f.Name -match '(?i)\.asi$|^dinput8\.dll$|scripthookv|openiv|asiloader|^d3d11\.dll$|^dxgi\.dll$|^d3d9\.dll$|reshade|^version\.dll$|^winmm\.dll$|dsound\.dll') {
                Add-Finding 'GTA-Folder' 'Medium' $f.FullName "SHA256 $(Get-Hash $f.FullName)"
            }
        }
        foreach ($d in 'scripts','plugins','mods') {
            foreach ($f in Get-ChildItem (Join-Path $g $d) -Recurse -File -Force) { Add-Finding 'GTA-Folder' 'Low' $f.FullName "File inside GTA '$d' folder" }
        }
    }
}

# ----------------------------------------------------------------------------------------------
#  4. KEY FOLDERS (time-limited)
# ----------------------------------------------------------------------------------------------
Invoke-Section ('Key folders' + $(if ($Deep) { ' (deep - slow)' } else { " (max ${MaxFileScanSeconds}s)" })) {
    # Recycle Bin first (fast + important)
    foreach ($i in Get-ChildItem "$env:SystemDrive\`$Recycle.Bin" -Recurse -Force -File | Where-Object { $_.Name -like '$I*' }) {
        $b = [IO.File]::ReadAllBytes($i.FullName)
        if ($b.Length -lt 30) { continue }
        $off = if ([BitConverter]::ToInt64($b, 0) -eq 2) { 28 } else { 24 }
        $orig = [Text.Encoding]::Unicode.GetString($b, $off, $b.Length - $off).Trim([char]0)
        $when = [DateTime]::FromFileTime([BitConverter]::ToInt64($b, 16))
        $s = Get-Sev (Leaf $orig) $orig
        if ($s -eq 'High' -or $s -eq 'Medium') { Add-Finding 'RecycleBin' $s $orig "Deleted on $($when.ToString('yyyy-MM-dd HH:mm'))" }
    }

    $sw    = [Diagnostics.Stopwatch]::StartNew()
    $limit = if ($Deep) { 86400 } else { $MaxFileScanSeconds }
    $roots = @()   # most important first
    if ($Deep) {
        foreach ($d in Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -in 2,3 }) { $roots += ,@(($d.DeviceID + '\'), 64) }
    } else {
        foreach ($p in Get-UserProfiles) {
            $roots += ,@((Join-Path $p.FullName 'Downloads'), 4)
            $roots += ,@((Join-Path $p.FullName 'Desktop'), 4)
            $roots += ,@((Join-Path $p.FullName 'AppData\Local\Temp'), 3)
            $roots += ,@((Join-Path $p.FullName 'AppData\Local\FiveM'), 4)
            $roots += ,@((Join-Path $p.FullName 'Documents'), 3)
        }
        $roots += ,@("$env:SystemRoot\Temp", 2)
        foreach ($p in Get-UserProfiles) {
            $roots += ,@((Join-Path $p.FullName 'AppData\Roaming'), 2)
            $roots += ,@((Join-Path $p.FullName 'AppData\Local'), 1)
            $roots += ,@($p.FullName, 1)
        }
        $roots += ,@("$env:ProgramData", 2)
        $roots += ,@("$env:SystemDrive\", 1)
        foreach ($d in Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -in 2,3 -and $_.DeviceID -ne $env:SystemDrive }) { $roots += ,@(($d.DeviceID + '\'), 3) }
    }

    $nameExt = '.exe','.dll','.sys','.asi','.lua','.zip','.rar','.7z','.bat','.cmd','.ps1','.vbs','.js','.ct','.cetrainer','.msi','.iso'
    $binExt  = '.exe','.dll','.sys','.asi'
    $textExt = '.lua','.bat','.cmd','.ps1','.vbs','.cfg','.ini','.json','.txt'
    $recent  = (Get-Date).AddDays(-30)
    $textN = 0; $binN = 0

    foreach ($r in $roots) {
        if ($sw.Elapsed.TotalSeconds -gt $limit) { break }
        if (-not (Test-Path -LiteralPath $r[0])) { continue }
        Walk $r[0] $r[1] $sw $limit | ForEach-Object {
            $f = $_
            if ($f -like "$OutDir*") { return }
            $name = [IO.Path]::GetFileName($f)
            $ext  = [IO.Path]::GetExtension($f).ToLower()

            # 1) name check (fast)
            if ($ext -in $nameExt) {
                $sev = Get-Sev $name
                if ($sev -and $sev -ne 'High' -and $ext -in $binExt -and (Test-Signed $f)) { $sev = $null }
                if ($sev) {
                    $fi = Get-Item -LiteralPath $f -Force
                    $hash = if ($ext -in $binExt + '.zip','.rar','.7z') { ' | SHA256 ' + (Get-Hash $f) } else { '' }
                    Add-Finding 'File' $sev $f ("Created $($fi.CreationTime.ToString('yyyy-MM-dd'))$hash")
                }
            }
            if ($ext -eq '.sys' -and $f -match $RxUserDir -and $f -notmatch '(?i)\\(Windows|Program Files)') { Add-Finding 'File' 'Medium' $f ('Driver file in a user folder | SHA256 ' + (Get-Hash $f)) }
            if ($ext -eq '.asi' -and $f -notmatch '(?i)Grand Theft Auto') { Add-Finding 'File' 'Medium' $f '.asi plugin outside the GTA folder' }

            # 2) small text files in the most important folders only (capped)
            if ($textN -lt 300 -and $ext -in $textExt -and $f -match '(?i)\\Users\\[^\\]+\\(Desktop|Downloads|Documents)\\|\\Temp\\') {
                $fi = New-Object IO.FileInfo $f
                if ($fi.Length -gt 0 -and $fi.Length -lt 256KB) {
                    $textN++
                    $txt = [IO.File]::ReadAllText($f)
                    if ($txt -match $RxStrong -and $txt -notmatch 'FiveM-Sentinel') { Add-Finding 'FileContent' 'Medium' $f ('Contains: ' + $Matches[0]) }
                }
            }
            # 3) inside RECENT programs in Downloads/Desktop/Temp only (capped)
            if ($binN -lt 80 -and $ext -in $binExt -and $f -match '(?i)\\Users\\[^\\]+\\(Downloads|Desktop)\\|\\Temp\\') {
                $fi = New-Object IO.FileInfo $f
                if ($fi.Length -gt 1KB -and $fi.Length -lt 20MB -and $fi.LastWriteTime -gt $recent) {
                    $binN++
                    $b = [IO.File]::ReadAllBytes($f)
                    $hit = $null
                    $a = [Text.Encoding]::GetEncoding(28591).GetString($b)
                    if ($a -match $RxBin) { $hit = $Matches[1] }
                    else { $u = [Text.Encoding]::Unicode.GetString($b); if ($u -match $RxBin) { $hit = $Matches[1] } }
                    if ($hit) { Add-Finding 'BinaryString' 'High' $f ("Contains the text '$hit' | SHA256 " + (Get-Hash $f)) }
                }
            }
        }
    }
    if (-not $Deep -and $sw.Elapsed.TotalSeconds -gt $limit) {
        Add-Finding 'Scanner' 'Info' "File scan stopped after ${MaxFileScanSeconds}s (time limit)" 'Run with -Deep or a higher -MaxFileScanSeconds for a longer scan.'
    }
}

# ----------------------------------------------------------------------------------------------
#  5-7. EXECUTION HISTORY
# ----------------------------------------------------------------------------------------------
Invoke-Section 'Prefetch (programs that were run)' {
    $en = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters').EnablePrefetcher
    if ($en -eq 0) { Add-Finding 'Prefetch' 'Medium' 'Prefetch is turned OFF' 'Hides which programs were run.' }
    $sm = Get-Service SysMain
    if ($sm -and $sm.Status -ne 'Running') { Add-Finding 'Prefetch' 'Low' 'SysMain service is not running' "Status: $($sm.Status)" }
    $files = Get-ChildItem "$env:SystemRoot\Prefetch" -Filter *.pf -Force
    if (-not $files) { Add-Finding 'Prefetch' 'Medium' 'Prefetch folder is empty or missing' 'It may have been cleaned.' }
    else {
        $oldest = ($files | Sort-Object CreationTime | Select-Object -First 1).CreationTime
        if ($oldest -gt (Get-Date).AddDays(-2)) { Add-Finding 'Prefetch' 'Low' 'Prefetch history only goes back a day or two' "Oldest entry: $oldest (it may have been cleaned recently)" }
        foreach ($f in $files) {
            $n = $f.Name -replace '-[0-9A-Fa-f]{8}\.pf$', ''
            $s = Get-Sev $n
            if ($s) { Add-Finding 'Prefetch' $s $n "Last run about $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))" }
        }
    }
}

Invoke-Section 'Windows history (UserAssist, BAM, ...)' {
    foreach ($h in Get-UserHives) {
        foreach ($g in Get-ChildItem "$h\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist") {
            $k = Get-Item ($g.PSPath + '\Count'); if (-not $k) { continue }
            foreach ($vn in $k.GetValueNames()) {
                $dec = ROT13 $vn
                $s = Get-Sev (Leaf $dec) $dec
                if ($s) {
                    $b = $k.GetValue($vn); $runs = ''; $when = ''
                    if ($b -is [byte[]] -and $b.Length -ge 68) {
                        $runs = [BitConverter]::ToUInt32($b, 4); $ft = [BitConverter]::ToInt64($b, 60)
                        if ($ft -gt 0) { $when = [DateTime]::FromFileTime($ft).ToString('yyyy-MM-dd HH:mm') }
                    }
                    Add-Finding 'UserAssist' $s $dec "Run $runs time(s), last: $when"
                }
            }
        }
        Scan-RegNames "$h\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" 'MuiCache'
        Scan-RegNames "$h\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store" 'AppCompat'
        Scan-RegNames "$h\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted" 'AppCompat'
        Scan-RegNames "$h\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" 'AppCompat'
        $rm = Get-Item "$h\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        if ($rm) { foreach ($vn in $rm.GetValueNames()) { $v = [string]$rm.GetValue($vn); $s = Get-Sev $v; if ($s -eq 'High') { Add-Finding 'RunMRU' 'High' $v '' } } }
    }
    Scan-RegNames 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store' 'AppCompat'
    $bam = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
    if (-not (Test-Path $bam)) { $bam = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings' }
    foreach ($u in Get-ChildItem $bam) {
        foreach ($vn in $u.GetValueNames()) {
            $s = Get-Sev (Leaf $vn) $vn
            if ($s) {
                $b = $u.GetValue($vn); $when = ''
                if ($b -is [byte[]] -and $b.Length -ge 8) { $when = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($b, 0)).ToLocalTime().ToString('yyyy-MM-dd HH:mm') }
                Add-Finding 'BAM' $s $vn "Last run: $when"
            }
        }
    }
}

Invoke-Section 'Recently opened files' {
    $sh = New-Object -ComObject WScript.Shell
    foreach ($p in Get-UserProfiles) {
        foreach ($l in Get-ChildItem (Join-Path $p.FullName 'AppData\Roaming\Microsoft\Windows\Recent') -Filter *.lnk -Force) {
            $target = ''; try { $target = $sh.CreateShortcut($l.FullName).TargetPath } catch {}
            $s = Get-Sev $l.BaseName $target
            if ($s -eq 'High' -or $s -eq 'Medium') { Add-Finding 'RecentLnk' $s $l.BaseName "Target: $target | opened $($l.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))" }
        }
    }
}

# ----------------------------------------------------------------------------------------------
#  8. DRIVERS
# ----------------------------------------------------------------------------------------------
Invoke-Section 'Drivers and Windows security settings' {
    foreach ($d in Get-CimInstance Win32_SystemDriver) {
        $path = ($d.PathName -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:SystemRoot).Trim('"')
        $base = [IO.Path]::GetFileNameWithoutExtension($path)
        $sev = Get-Sev "$($d.Name) $($d.DisplayName)" $path
        if ($sev -eq 'High') { Add-Finding 'Driver' 'High' $d.Name "$path | $($d.State)" }
        if ($base -match $RxVulnDrv -or $d.Name -match $RxVulnDrv) { Add-Finding 'Driver' 'High' $d.Name "Known abused driver | $path | $($d.State)" }
        if ($d.State -eq 'Running' -and $path -and (Test-Path -LiteralPath $path) -and $path -notmatch '(?i)\\Windows\\System32\\(drivers|DriverStore)') {
            if (-not (Test-Signed $path)) { Add-Finding 'Driver' 'Medium' $d.Name "Running driver is not validly signed: $path" }
            elseif ($path -match $RxUserDir) { Add-Finding 'Driver' 'Medium' $d.Name "Driver runs from a user folder: $path" }
        }
    }
    foreach ($k in Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services') { if ($k.PSChildName -match $RxVulnDrv) { Add-Finding 'DriverTrace' 'Medium' $k.PSChildName '' } }
    foreach ($f in Get-ChildItem "$env:SystemRoot\System32\drivers" -Filter *.sys -File) {
        if ([IO.Path]::GetFileNameWithoutExtension($f.Name) -match $RxVulnDrv) { Add-Finding 'DriverFile' 'Medium' $f.FullName "Created $($f.CreationTime.ToString('yyyy-MM-dd'))" }
    }
    $bcd = (bcdedit /enum '{current}' 2>$null) -join "`n"
    if ($bcd -match '(?i)testsigning\s+Yes')       { Add-Finding 'Kernel' 'High'   'Test-signing is ON' 'Allows unsigned kernel cheats/spoofers to load.' }
    if ($bcd -match '(?i)nointegritychecks\s+Yes') { Add-Finding 'Kernel' 'High'   'Driver integrity checks are OFF' '' }
    if ($bcd -match '(?i)debug\s+Yes')             { Add-Finding 'Kernel' 'Medium' 'Kernel debugging is ON' '' }
    if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config').VulnerableDriverBlocklistEnable -eq 0) { Add-Finding 'Kernel' 'Medium' 'Microsoft vulnerable-driver blocklist is OFF' '' }
}

Invoke-Section 'Services, tasks, startup' {
    foreach ($s in Get-CimInstance Win32_Service) {
        $sev = Get-Sev "$($s.Name) $($s.DisplayName)" $s.PathName
        if ($sev -eq 'High') { Add-Finding 'Service' 'High' $s.Name $s.PathName }
        elseif ($s.PathName -match '(?i)\\(Temp|Downloads|Desktop)\\') { Add-Finding 'Service' 'Medium' $s.Name $s.PathName }
    }
    foreach ($t in Get-ScheduledTask) {
        foreach ($a in $t.Actions) {
            $cmd = "$($a.Execute) $($a.Arguments)"
            $sev = Get-Sev "$($t.TaskName) $(Leaf $a.Execute)" $cmd
            if ($sev -eq 'High') { Add-Finding 'Task' 'High' $t.TaskName $cmd }
            elseif ($cmd -match '(?i)\\(Temp|Downloads|Desktop)\\') { Add-Finding 'Task' 'Medium' $t.TaskName $cmd }
        }
    }
    $runKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
    foreach ($h in Get-UserHives) { $runKeys += "$h\Software\Microsoft\Windows\CurrentVersion\Run"; $runKeys += "$h\Software\Microsoft\Windows\CurrentVersion\RunOnce" }
    foreach ($rk in $runKeys) {
        $k = Get-Item -LiteralPath $rk; if (-not $k) { continue }
        foreach ($n in $k.GetValueNames()) {
            $v = [string]$k.GetValue($n)
            $s = Get-Sev $n $v
            if ($s -eq 'High') { Add-Finding 'Startup' 'High' $n $v }
            elseif ($v -match '(?i)\\(Temp|Downloads|Desktop)\\') { Add-Finding 'Startup' 'Medium' $n $v }
        }
    }
}

# ----------------------------------------------------------------------------------------------
#  10. EVENT LOGS + DEFENDER
# ----------------------------------------------------------------------------------------------
Invoke-Section 'Event logs and Windows Defender' {
    foreach ($e in Get-Ev 'Security' 1102) { Add-Finding 'EventLog' 'Medium' "Security log cleared on $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm'))" '' }
    foreach ($e in Get-Ev 'System' 104)    { Add-Finding 'EventLog' 'Medium' "System log cleared on $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm'))" '' }
    foreach ($e in Get-Ev 'System' 7045) {
        $svc = [string]$e.Properties[0].Value; $img = [string]$e.Properties[1].Value; $typ = [string]$e.Properties[2].Value
        $s = Get-Sev $svc $img
        if ($s -eq 'High') { Add-Finding 'ServiceInstall' 'High' $svc "$img | $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm'))" }
        elseif ($typ -match '(?i)kernel' -and $img -notmatch '(?i)\\Windows\\System32\\drivers|DriverStore') {
            Add-Finding 'ServiceInstall' 'Medium' $svc "Kernel driver installed from: $img | $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm'))"
        }
    }
    $seenT = @{}
    foreach ($e in Get-Ev 'Microsoft-Windows-Windows Defender/Operational' @(1116, 1117)) {
        $msg = $e.Message
        $name = if ($msg -match 'Name:\s*(.+)') { $Matches[1].Trim() } else { 'Unknown' }
        $path = if ($msg -match 'Path:\s*(.+)') { $Matches[1].Trim() } else { '' }
        if ($seenT["$name|$path"]) { continue }; $seenT["$name|$path"] = 1
        $sev = if ((Get-Sev (Leaf $path) $path) -eq 'High') { 'High' } elseif ($name -match '(?i)HackTool|Cheat|Inject|Spoof|Exploit|Wacatac|Trojan') { 'Medium' } else { 'Low' }
        Add-Finding 'Defender' $sev "Defender found: $name" "$path | $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm'))"
    }
    $mp = Get-MpPreference
    if ($mp) {
        foreach ($x in @($mp.ExclusionPath) + @($mp.ExclusionProcess) + @($mp.ExclusionExtension)) {
            if (-not $x) { continue }
            $s = Get-Sev (Leaf $x) $x
            if (-not $s) { $s = if ($x -match '(?i)Downloads|Desktop|Temp|AppData|Users') { 'Medium' } else { 'Low' } }
            Add-Finding 'DefenderExcl' $s $x ''
        }
        if ($mp.DisableRealtimeMonitoring) { Add-Finding 'Defender' 'Medium' 'Defender real-time protection is OFF' '' }
    }
    $null = fsutil usn queryjournal "$env:SystemDrive" 2>&1
    if ($LASTEXITCODE -ne 0) { Add-Finding 'USN' 'Medium' 'NTFS USN journal is missing' '' }
    $tc = @(Get-Ev 'System' 1 | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Kernel-General' })
    if ($tc.Count -gt 0) { Add-Finding 'SystemTime' 'Low' "System clock changed $($tc.Count) time(s) in the last $Days days" '' }
}

# ----------------------------------------------------------------------------------------------
#  11. NETWORK + BROWSERS
# ----------------------------------------------------------------------------------------------
Invoke-Section 'DNS cache, hosts file, browser history' {
    foreach ($d in Get-DnsClientCache) { $s = Get-Sev $d.Entry; if ($s -eq 'High') { Add-Finding 'DNS' 'High' $d.Entry '' } }
    foreach ($l in Get-Content "$env:SystemRoot\System32\drivers\etc\hosts") {
        if ($l -match '^\s*#' -or $l -match '^\s*$') { continue }
        Add-Finding 'Hosts' $(if ((Get-Sev $l) -eq 'High') { 'High' } else { 'Low' }) $l.Trim() ''
    }
    $rx = '(?i)[\x20-\x7e]{0,50}(' + (($Brand + $Phrase) -join '|') + ')[\x20-\x7e]{0,50}'
    $dbs = @()
    foreach ($p in Get-UserProfiles) {
        $L = Join-Path $p.FullName 'AppData\Local'; $R = Join-Path $p.FullName 'AppData\Roaming'
        foreach ($b in "$L\Google\Chrome\User Data", "$L\Microsoft\Edge\User Data", "$L\BraveSoftware\Brave-Browser\User Data", "$L\Vivaldi\User Data", "$R\Opera Software\Opera Stable", "$R\Opera Software\Opera GX Stable") {
            foreach ($f in Get-ChildItem $b -Recurse -Depth 2 -Filter History -File -Force) { $dbs += $f.FullName }
        }
        foreach ($f in Get-ChildItem "$R\Mozilla\Firefox\Profiles" -Recurse -Depth 2 -Filter places.sqlite -File -Force) { $dbs += $f.FullName }
    }
    $total = 0
    foreach ($db in $dbs) {
        $bytes = Read-SharedBytes $db
        if (-not $bytes) { continue }
        $txt = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
        foreach ($m in [regex]::Matches($txt, $rx)) {
            $v = $m.Value.Trim()
            if ($v.Length -lt 6) { continue }
            Add-Finding 'Browser' 'Medium' $v ([IO.Path]::GetFileName([IO.Path]::GetDirectoryName($db)) + ' browser history')
            if (++$total -ge 12) { break }
        }
        if ($total -ge 12) { break }
    }
}

# ----------------------------------------------------------------------------------------------
#  12. HARDWARE
# ----------------------------------------------------------------------------------------------
Invoke-Section 'Hardware, HWID/MAC spoofing, DMA devices' {
    $netClass = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
    foreach ($k in Get-ChildItem $netClass | Where-Object { $_.PSChildName -match '^\d{4}$' }) {
        $pr = Get-ItemProperty $k.PSPath
        if ($pr.NetworkAddress) { Add-Finding 'MAC' 'Medium' "Custom MAC address set: $($pr.NetworkAddress)" "Adapter: $($pr.DriverDesc)" }
    }
    $odd = '(?i)to be filled|default string|^none$|not applicable|system serial|123456789|^0+$|^f+$|o\.e\.m|^(.)\1{5,}$'
    $ids = @(
        @('BIOS serial', (Get-CimInstance Win32_BIOS).SerialNumber),
        @('Motherboard serial', (Get-CimInstance Win32_BaseBoard).SerialNumber),
        @('System UUID', (Get-CimInstance Win32_ComputerSystemProduct).UUID)
    )
    foreach ($dk in Get-CimInstance Win32_DiskDrive) { $ids += ,@("Disk serial ($($dk.Model))", ($dk.SerialNumber -as [string])) }
    foreach ($i in $ids) { if ($i[1] -and ($i[1].Trim() -match $odd)) { Add-Finding 'HWID' 'Low' "$($i[0]) looks blank/placeholder: $($i[1])" 'Normal on some cheap boards, but also seen after spoofing.' } }
    $mg = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
    Add-Finding 'HWID' 'Info' "MachineGuid: $mg" 'Write this down to compare with earlier checks or bans.'
    $os = Get-CimInstance Win32_OperatingSystem
    if ($os.InstallDate -gt (Get-Date).AddDays(-14)) { Add-Finding 'HWID' 'Low' "Windows was installed recently ($($os.InstallDate.ToString('yyyy-MM-dd')))" 'Fresh installs are sometimes used to evade bans.' }
    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.Model -match '(?i)vmware|virtualbox|virtual machine|kvm|qemu|hyper-v') { Add-Finding 'VM' 'Low' "This is a virtual machine: $($cs.Model)" '' }

    $dma = '(?i)pcileech|screamer|squirrel|ft60[1-9]|ft245|leetdma|dma[\s_-]?card|lambdaconcept|pciescreamer|xilinx|artix'
    $hid = '(?i)arduino|teensy|leonardo|pro[\s_-]?micro|kmbox|makcu|rp2040|raspberry pi pico|digispark|atmega32u4|titan[\s_-]?two|cronus|xim[\s_-]?(apex|matrix)|strike[\s_-]?pack|reasnow'
    foreach ($d in Get-PnpDevice) {
        $t = "$($d.FriendlyName) $($d.InstanceId) $($d.Manufacturer)"
        $state = if ($d.Present) { 'connected now' } else { 'was connected before' }
        if ($t -match $dma)     { Add-Finding 'Hardware' 'High' "Possible DMA cheat device: $($d.FriendlyName)" "$($d.InstanceId) ($state)" }
        elseif ($t -match $hid) { Add-Finding 'Hardware' $(if ($d.Present) { 'Medium' } else { 'Low' }) "Possible aim/input-spoofing device: $($d.FriendlyName)" "$($d.InstanceId) ($state)" }
    }
}

# ----------------------------------------------------------------------------------------------
#  RESULTS (screen)
# ----------------------------------------------------------------------------------------------
$sortKey = { $SevOrder[$_.Severity] }
$all  = @($Findings | Sort-Object @{ Expression = $sortKey }, Category, Item)
$high = @($all | Where-Object { $_.Severity -eq 'High' })
$med  = @($all | Where-Object { $_.Severity -eq 'Medium' })
$low  = @($all | Where-Object { $_.Severity -eq 'Low' })
$info = @($all | Where-Object { $_.Severity -eq 'Info' })

if ($high.Count -gt 0)    { $verdict = 'CHEAT EVIDENCE FOUND';             $vTag = '[XX]'; $vColor = 'Red';    $vClass = 'bad';  $vText = 'Serious items were found. Review them below before making a decision.' }
elseif ($med.Count -gt 0) { $verdict = 'SOME THINGS NEED A MANUAL LOOK';   $vTag = '[!!]'; $vColor = 'Yellow'; $vClass = 'warn'; $vText = 'Nothing certain, but a few items are suspicious. Check them below.' }
else                      { $verdict = 'NOTHING SUSPICIOUS FOUND';         $vTag = '[OK]'; $vColor = 'Green';  $vClass = 'ok';   $vText = 'No known cheat traces were found. This does NOT guarantee the PC is clean (private cheats and hardware can evade scanners).' }

Write-Host ''
Write-Host $line -ForegroundColor $vColor
Write-Host ("   {0}  {1}" -f $vTag, $verdict) -ForegroundColor $vColor
Write-Host ("   {0}" -f $vText) -ForegroundColor Gray
Write-Host ''
Write-Host ("   SERIOUS: {0}     CHECK: {1}     NOTES: {2}" -f $high.Count, $med.Count, $low.Count) -ForegroundColor White
Write-Host $line -ForegroundColor $vColor
Write-Host ''

$whyShown = @{}
function Show-List($items, [int]$max, [string]$color) {
    $i = 0
    foreach ($f in $items) {
        $i++
        if (-not $ShowAll -and $i -gt $max) { Write-Host ("   ... and {0} more (see the full report)." -f ($items.Count - $max)) -ForegroundColor DarkGray; Write-Host ''; break }
        $ci = $CatInfo[$f.Category]; $title = if ($ci) { $ci[0] } else { $f.Category }
        Write-Host ("  {0,2}) {1}" -f $i, $title) -ForegroundColor $color
        Write-Host ("      {0}" -f (Cut $f.Item 140)) -ForegroundColor White
        if ($f.Detail) { Write-Host ("      {0}" -f (Cut $f.Detail 140)) -ForegroundColor DarkGray }
        if ($ci -and $ci[1] -and -not $whyShown.ContainsKey($f.Category)) { $whyShown[$f.Category] = 1; Write-Host ("      Why it matters: {0}" -f $ci[1]) -ForegroundColor DarkYellow }
        Write-Host ''
    }
}
if ($high.Count -gt 0) { Write-Host '  SERIOUS - very likely cheat related' -ForegroundColor Red;    Write-Host ''; Show-List $high 20 'Red' }
if ($med.Count  -gt 0) { Write-Host '  CHECK - suspicious, verify manually' -ForegroundColor Yellow; Write-Host ''; Show-List $med 15 'Yellow' }
if ($low.Count  -gt 0) {
    Write-Host '  NOTES - good to know (not a problem by itself)' -ForegroundColor Cyan
    $n = 0
    foreach ($f in $low) {
        $n++
        if (-not $ShowAll -and $n -gt 8) { Write-Host ("    ... and {0} more (see the full report)." -f ($low.Count - 8)) -ForegroundColor DarkGray; break }
        $ci = $CatInfo[$f.Category]; $title = if ($ci) { $ci[0] } else { $f.Category }
        Write-Host ("    - {0}: {1}" -f $title, (Cut $f.Item 100)) -ForegroundColor Gray
    }
    Write-Host ''
}
if ($info | Where-Object { $_.Category -eq 'FiveM' }) {
    Write-Host '  TIP: FiveM was not running. Start FiveM, join a server and scan again for the most accurate result.' -ForegroundColor DarkYellow
    Write-Host ''
}

# ----------------------------------------------------------------------------------------------
#  REPORT FILES
# ----------------------------------------------------------------------------------------------
function H([string]$s) { [Net.WebUtility]::HtmlEncode($s) }
$lbl  = @{ High = 'SERIOUS'; Medium = 'CHECK'; Low = 'NOTE'; Info = 'INFO' }
$dur  = [int]((Get-Date) - $Start).TotalSeconds
$mode = if ($Deep) { 'DEEP' } else { 'QUICK' }

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("FiveM-Sentinel v$Version report")
[void]$sb.AppendLine("PC: $env:COMPUTERNAME   User: $env:USERNAME   Date: $($Start.ToString('yyyy-MM-dd HH:mm'))   Duration: ${dur}s   Mode: $mode")
[void]$sb.AppendLine("RESULT: $verdict   (SERIOUS $($high.Count) / CHECK $($med.Count) / NOTES $($low.Count))")
[void]$sb.AppendLine(('-' * 90))
foreach ($f in $all) {
    $ci = $CatInfo[$f.Category]; $title = if ($ci) { $ci[0] } else { $f.Category }
    [void]$sb.AppendLine(("[{0}] {1}" -f $lbl[$f.Severity], $title))
    [void]$sb.AppendLine("    $($f.Item)")
    if ($f.Detail) { [void]$sb.AppendLine("    $($f.Detail)") }
}
$txtPath = Join-Path $OutDir 'report.txt'
$sb.ToString() | Out-File -FilePath $txtPath -Encoding UTF8
$all | Export-Csv -Path (Join-Path $OutDir 'report.csv') -NoTypeInformation -Encoding UTF8
(Get-FileHash $txtPath -Algorithm SHA256).Hash | Out-File (Join-Path $OutDir 'report.txt.sha256') -Encoding ASCII

$rows = New-Object System.Text.StringBuilder
foreach ($f in $all | Where-Object { $_.Severity -ne 'Info' }) {
    $ci = $CatInfo[$f.Category]; $title = if ($ci) { $ci[0] } else { $f.Category }; $why = if ($ci) { $ci[1] } else { '' }
    [void]$rows.AppendLine("<tr><td><span class='b $($f.Severity)'>$($lbl[$f.Severity])</span></td><td><b>$(H $title)</b><div class='w'>$(H $why)</div></td><td class='m'>$(H $f.Item)<div class='d'>$(H $f.Detail)</div></td></tr>")
}
$infoRows = New-Object System.Text.StringBuilder
foreach ($f in $info) { [void]$infoRows.AppendLine("<li>$(H $f.Item) <span class='d'>$(H $f.Detail)</span></li>") }
$css = 'body{font-family:Segoe UI,Arial,sans-serif;background:#111418;color:#e8eaed;margin:0;padding:24px}.wrap{max-width:1100px;margin:auto}h1{margin:0 0 4px;font-size:22px}.sub{color:#9aa0a6;font-size:13px;margin-bottom:18px}.v{padding:18px 22px;border-radius:10px;margin-bottom:18px}.v h2{margin:0 0 6px}.v.bad{background:#3b1717;border:1px solid #e5484d}.v.warn{background:#3a3115;border:1px solid #f5a623}.v.ok{background:#14301f;border:1px solid #3fb950}.cnt span{display:inline-block;margin-right:18px;font-weight:600}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #2a2f36;padding:9px 10px;vertical-align:top;font-size:13px;text-align:left}th{color:#9aa0a6}.b{padding:2px 8px;border-radius:5px;font-size:11px;font-weight:700}.b.High{background:#e5484d;color:#fff}.b.Medium{background:#f5a623;color:#111}.b.Low{background:#2d9cdb;color:#fff}.m{font-family:Consolas,monospace;word-break:break-all}.d{color:#9aa0a6;font-family:Segoe UI,Arial;font-size:12px;margin-top:3px}.w{color:#9aa0a6;font-size:12px;margin-top:3px}li{margin:4px 0}'
$html = "<!doctype html><html><head><meta charset='utf-8'><title>FiveM-Sentinel report</title><style>$css</style></head><body><div class='wrap'>" +
        "<h1>FiveM-Sentinel report</h1><div class='sub'>PC: $(H $env:COMPUTERNAME) &nbsp;|&nbsp; $(H $Start.ToString('yyyy-MM-dd HH:mm')) &nbsp;|&nbsp; Mode: $mode &nbsp;|&nbsp; ${dur}s</div>" +
        "<div class='v $vClass'><h2>$(H $verdict)</h2><div>$(H $vText)</div><div class='cnt' style='margin-top:10px'><span>SERIOUS: $($high.Count)</span><span>CHECK: $($med.Count)</span><span>NOTES: $($low.Count)</span></div></div>" +
        "<table><tr><th style='width:90px'>Level</th><th style='width:300px'>What</th><th>Details</th></tr>$($rows.ToString())</table>" +
        "<h3>System info</h3><ul>$($infoRows.ToString())</ul>" +
        "<p class='d'>Indicators are not proof. Verify each item manually (file origin, hash lookup, context).</p></div></body></html>"
$htmlPath = Join-Path $OutDir 'report.html'
$html | Out-File -FilePath $htmlPath -Encoding UTF8

Write-Host ('  Full report saved to: ' + $OutDir) -ForegroundColor White
Write-Host '  (report.html = easy to read, report.txt, report.csv)' -ForegroundColor DarkGray
Write-Host ''
if (-not $NoOpen) { Start-Process $htmlPath }
