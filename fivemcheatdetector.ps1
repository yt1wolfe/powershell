<#
.SYNOPSIS
    FiveM-Sentinel - read-only Windows PC-check scanner that collects evidence of FiveM cheats.

.DESCRIPTION
    Scans (read-only, nothing is deleted, nothing is sent over the network):
      * Running processes, window titles, FiveM/GTA process modules (injected DLLs)
      * FiveM folders (plugins, mods, logs, CitizenFX.ini) and the GTA V folder (.asi, ScriptHook, ReShade)
      * File system (names, extensions, text content, binary strings, unsigned binaries)
      * Execution history: Prefetch, UserAssist, BAM, MuiCache, AppCompat, RunMRU, Recent .lnk
      * Drivers (vulnerable / unsigned / manual-mapped traces), test-signing, driver blocklist
      * Services, scheduled tasks, startup entries
      * Event logs (cleared logs, service installs, Defender detections / exclusions)
      * DNS cache, hosts file, browser history (Chrome/Edge/Brave/Opera/Firefox)
      * Recycle Bin, USN journal, MAC/HWID spoof traces, DMA-card and Arduino/HID devices
    Produces TXT + CSV + HTML reports with a risk score.

.PARAMETER Deep
    Full recursive scan of ALL fixed/removable drives (slow). Default = fast targeted scan.
.PARAMETER Days
    How many days back to look in event logs. Default 60.
.PARAMETER ExtraKeywords
    Extra keywords (regex fragments) to treat as high-confidence cheat names.
.PARAMETER OutDir
    Output folder (default: Desktop\FiveM_Scan_<timestamp>).

.EXAMPLE
    Right-click PowerShell -> Run as Administrator, then:
    powershell -ExecutionPolicy Bypass -File .\FiveM-Sentinel.ps1
    powershell -ExecutionPolicy Bypass -File .\FiveM-Sentinel.ps1 -Deep -ExtraKeywords 'mycheatname','otherone'

.NOTE
    A scanner finds INDICATORS, not proof. Keyword/signature detection can be evaded (renamed files,
    private cheats, DMA hardware) and can produce false positives. Always review findings manually.
#>
[CmdletBinding()]
param(
    [switch]$Deep,
    [int]$Days = 60,
    [string[]]$ExtraKeywords = @(),
    [string]$OutDir
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$Version = '2.0'
$Start   = Get-Date

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host '[!] Run this script as Administrator.' -ForegroundColor Red; exit 1 }

if (-not $OutDir) { $OutDir = Join-Path ([Environment]::GetFolderPath('Desktop')) ('FiveM_Scan_' + $Start.ToString('yyyyMMdd_HHmmss')) }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# ----------------------------------------------------------------------------------------------
#  KEYWORD DATABASE  (edit / extend freely)
# ----------------------------------------------------------------------------------------------
$Strong = @(
 'eulen','red\s?engine','skript\.?gg','hx[\s_\-]?software','kiddion','cherax','2take1','desudo','susano',
 'cheat[\s_\-]?engine','extreme[\s_\-]?injector','xenos[\s_\-]?inject','kdmapper','aimbot','trigger[\s_\-]?bot',
 'wall[\s_\-]?hack','silent[\s_\-]?aim','spoofer','hwid[\s_\-]?spoof','lua[\s_\-]?executor','mod[\s_\-]?menu',
 'fivem[\s_\-]?(hack|cheat|menu|executor|spoof|bypass)','dll[\s_\-]?inject','manual[\s_\-]?map','no[\s_\-]?recoil',
 'no[\s_\-]?spread','magic[\s_\-]?bullet','lynx[\s_\-]?(menu|cheat|mod)','tzx[\s_\-]?(menu|cheat)',
 'phantom[\s_\-]?x','ro[\s_\-]?x[\s_\-]?(menu|cheat)','hammafia','aio[\s_\-]?cheats','cheats?[\s_\-]?(menu|loader)',
 'loader[\s_\-]?(cheat|hack)','(anti[\s_\-]?cheat|ac)[\s_\-]?bypass','txadmin[\s_\-]?bypass','blacklist[\s_\-]?bypass'
) + $ExtraKeywords
$Medium = @(
 'process[\s_\-]?hacker','x64dbg','x32dbg','ollydbg','\bida(64)?\b','reclass','scyllahide','injector','dumper',
 '\bcheats?\b','\bhack(s|er|ing)?\b','exploit','\bbypass','executor','unban','vmprotect','themida','kernel[\s_\-]?driver[\s_\-]?mapper',
 'processhacker','systeminformer','recoil[\s_\-]?script','\.ct$','\.dd64$'
)
$Weak = @('no[\s_\-]?clip','god[\s_\-]?mode','free[\s_\-]?cam','\besp\b','keygen','crack(ed)?\b','autohotkey','\.ahk$','loader')

$RxStrong = '(?i)(' + ($Strong -join '|') + ')'
$RxMedium = '(?i)(' + ($Medium -join '|') + ')'
$RxWeak   = '(?i)(' + ($Weak   -join '|') + ')'
$RxBin    = '(?i)(eulen|redengine|skript\.gg|kiddion|cherax|2take1|desudo|susano|aimbot|triggerbot|silent\s?aim|hwid\s?spoof|lua\s?executor|kdmapper|mod\s?menu)'
$RxVulnDrv = '(?i)^(capcom|iqvw64e?|gdrv\d?|rtcore(32|64)|dbutil_2_3|asrdrv\d*|asio[23]?|cpuz\d*|winring0(x64)?|inpoutx?64?|physmem|phymem|kprocesshacker|mhyprot\d?|atillk64|eneio(64)?|ene|msio(32|64)|wnbios|piddrv|directio(32|64)?|dbk(32|64)|glckio2|hwrwdrv|ntiolib(_x64)?|speedfan|zam64|amifldrv64|rwdrv|nal|winio(32|64)?|gpuz|lha|bs_def|kdmapper|vboxdrv|throttlestop|asmmap(64)?|asupio|corsairllaccess64|lnvmsrio|rzpnk|alsysio64|mtcbsv64)$'
$RxSkipDir = '(?i)\\(Windows\\(WinSxS|assembly|servicing|SoftwareDistribution|Installer|System32|SysWOW64|Fonts)|Program Files( \(x86\))?\\(WindowsApps|Common Files|Microsoft|Windows[^\\]*|Google|Mozilla)|node_modules|\.git|Cache|Code Cache|GPUCache|Service Worker|ShaderCache|DawnCache|\$WinREAgent|Packages)(\\|$)'
$RxRemote  = '(?i)(anydesk|teamviewer|parsec|rustdesk|ultraviewer|supremo|ammyy|splashtop|radmin|chromoting|screenconnect|aeroadmin)'
$RxUserDir = '(?i)\\(Users|ProgramData|Temp|Downloads|Desktop)\\'

# ----------------------------------------------------------------------------------------------
#  HELPERS
# ----------------------------------------------------------------------------------------------
$Findings = New-Object System.Collections.Generic.List[object]
$Seen     = New-Object 'System.Collections.Generic.HashSet[string]'
$SevOrder = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
$SevScore = @{ High = 10; Medium = 4; Low = 1; Info = 0 }
$SevColor = @{ High = 'Red'; Medium = 'Yellow'; Low = 'Cyan'; Info = 'DarkGray' }

function Get-Sev([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    if ($s -match $RxStrong) { return 'High' }
    if ($s -match $RxMedium) { return 'Medium' }
    if ($s -match $RxWeak)   { return 'Low' }
    return $null
}

function Add-Finding([string]$Category, [string]$Severity, [string]$Item, [string]$Detail = '') {
    if ($Item -eq $PSCommandPath) { return }
    if ($Item -like "$OutDir*")   { return }
    if (-not $Seen.Add("$Category|$Item")) { return }
    $Findings.Add([pscustomobject]@{ Severity = $Severity; Category = $Category; Item = $Item; Detail = $Detail })
    Write-Host ("  [{0,-6}] {1,-12} {2}" -f $Severity, $Category, $Item) -ForegroundColor $SevColor[$Severity]
    if ($Detail) { Write-Host ("           {0}" -f $Detail) -ForegroundColor DarkGray }
}

function Write-Section([string]$t) { Write-Host ''; Write-Host ('=== ' + $t + ' ===') -ForegroundColor Green }

function Invoke-Section([string]$Name, [scriptblock]$Block) {
    Write-Section $Name
    try { & $Block } catch { Add-Finding 'Scanner' 'Info' "Section failed: $Name" $_.Exception.Message }
}

function Get-UserProfiles {
    Get-ChildItem "$env:SystemDrive\Users" -Directory -Force | Where-Object { $_.Name -notin 'Public','Default','Default User','All Users' }
}
function Get-UserHives {
    Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.Name -match '\\S-1-5-21-[\d-]+$' } | ForEach-Object { $_.PSPath }
}
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
    foreach ($n in $k.GetValueNames()) {
        $s = Get-Sev $n
        if ($s) { Add-Finding $Cat $s $n $Path }
    }
}
function Get-Ev($log, $ids) {
    Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $ids; StartTime = $Start.AddDays(-$Days) } -ErrorAction SilentlyContinue
}
function Get-FiveMPaths {
    $r = @()
    foreach ($p in Get-UserProfiles) {
        $a = Join-Path $p.FullName 'AppData\Local\FiveM'
        if (Test-Path $a) { $r += $a }
    }
    $r | Select-Object -Unique
}
function Get-GtaDirs {
    $d = @()
    foreach ($fm in Get-FiveMPaths) {
        foreach ($ini in @("$fm\FiveM.app\CitizenFX.ini", "$fm\CitizenFX.ini")) {
            if (Test-Path $ini) {
                $m = Select-String -Path $ini -Pattern '^\s*IVPath\s*=\s*(.+)$'
                if ($m) { $d += $m.Matches[0].Groups[1].Value.Trim() }
            }
        }
    }
    foreach ($rk in 'HKLM:\SOFTWARE\WOW6432Node\Rockstar Games\Grand Theft Auto V','HKLM:\SOFTWARE\Rockstar Games\Grand Theft Auto V','HKLM:\SOFTWARE\WOW6432Node\Rockstar Games\GTAV') {
        $v = (Get-ItemProperty $rk).InstallFolder
        if ($v) { $d += $v }
    }
    $d | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
}

# Streaming directory walker (prunes noisy dirs, skips reparse points, depth limited)
function Walk([string]$Root, [int]$MaxDepth = 64) {
    $stack = New-Object 'System.Collections.Generic.Stack[object]'
    $stack.Push(@($Root, 0))
    while ($stack.Count -gt 0) {
        $it = $stack.Pop(); $d = $it[0]; $depth = $it[1]
        if ($d -match $RxSkipDir) { continue }
        $leaf = [IO.Path]::GetFileName($d.TrimEnd('\'))
        if ($leaf) {
            $sv = Get-Sev $leaf
            if ($sv -in 'High','Medium') { Add-Finding 'Folder' $sv $d 'Folder name matches cheat keyword' }
        }
        try { foreach ($f in [IO.Directory]::EnumerateFiles($d)) { $f } } catch {}
        if ($depth -lt $MaxDepth) {
            try {
                foreach ($s in [IO.Directory]::EnumerateDirectories($d)) {
                    $a = [IO.File]::GetAttributes($s)
                    if ($a -band [IO.FileAttributes]::ReparsePoint) { continue }
                    $stack.Push(@($s, ($depth + 1)))
                }
            } catch {}
        }
    }
}

# ----------------------------------------------------------------------------------------------
#  BANNER
# ----------------------------------------------------------------------------------------------
Clear-Host
Write-Host "FiveM-Sentinel v$Version  |  $env:COMPUTERNAME  |  $($Start)  |  Mode: $(if($Deep){'DEEP'}else{'FAST'})" -ForegroundColor Magenta
Write-Host 'Read-only scan. Nothing is modified or uploaded.' -ForegroundColor DarkGray

# ----------------------------------------------------------------------------------------------
#  1. PROCESSES
# ----------------------------------------------------------------------------------------------
Invoke-Section '1. Running processes' {
    foreach ($p in Get-CimInstance Win32_Process) {
        $txt = "$($p.Name) $($p.ExecutablePath) $($p.CommandLine)"
        $sev = Get-Sev $txt
        if ($sev) { Add-Finding 'Process' $sev $p.Name "PID $($p.ProcessId) | $($p.ExecutablePath) | $($p.CommandLine)" }
        if ($txt -match $RxRemote) { Add-Finding 'RemoteTool' 'Low' $p.Name "Remote-control software running (possible external cheating) PID $($p.ProcessId)" }
        if ($p.ExecutablePath) {
            if (-not (Test-Path -LiteralPath $p.ExecutablePath)) {
                Add-Finding 'Process' 'Medium' $p.Name "Running but file no longer on disk (deleted after launch): $($p.ExecutablePath)"
            } elseif ($p.ExecutablePath -match '(?i)\\(Temp|Downloads|Desktop)\\') {
                $sig = Get-AuthenticodeSignature -LiteralPath $p.ExecutablePath
                if ($sig.Status -ne 'Valid') { Add-Finding 'Process' 'Low' $p.ExecutablePath "Unsigned process in user folder, PID $($p.ProcessId)" }
            }
        }
    }
    foreach ($w in Get-Process | Where-Object { $_.MainWindowTitle }) {
        $s = Get-Sev $w.MainWindowTitle
        if ($s) { Add-Finding 'WindowTitle' $s $w.MainWindowTitle "Process: $($w.ProcessName) PID $($w.Id)" }
    }
}

# ----------------------------------------------------------------------------------------------
#  2. FIVEM / GTA PROCESS MODULES (injection detection)
# ----------------------------------------------------------------------------------------------
Invoke-Section '2. FiveM / GTA process modules' {
    $procs = Get-Process | Where-Object { $_.ProcessName -match '(?i)^FiveM|GTAProcess|^GTA5' }
    if (-not $procs) {
        Add-Finding 'FiveM' 'Info' 'FiveM is not running' 'For the best result start FiveM, join a server, then re-run so loaded modules can be inspected.'
        return
    }
    foreach ($p in $procs) {
        $mods = $null
        try { $mods = $p.Modules } catch {}
        if (-not $mods) { Add-Finding 'FiveM' 'Medium' $p.ProcessName "Cannot enumerate modules of PID $($p.Id) (protected/tampered process?)"; continue }
        foreach ($m in $mods) {
            $path = $m.FileName
            if (-not $path) { continue }
            if ($path -match '(?i)\\Windows\\(System32|SysWOW64|WinSxS)\\') { continue }
            $sev = Get-Sev "$($m.ModuleName) $path"
            if ($sev) { Add-Finding 'Module' $sev $path "Loaded in $($p.ProcessName) PID $($p.Id)"; continue }
            if (-not (Test-Path -LiteralPath $path)) { Add-Finding 'Module' 'Medium' $m.ModuleName "Module loaded but file deleted: $path"; continue }
            if ($path -match '(?i)\\(Temp|Downloads|Desktop|AppData\\Roaming)\\') {
                Add-Finding 'Module' 'High' $path "DLL loaded into $($p.ProcessName) from a user-writable folder (typical injection)"; continue
            }
            $inFivem = $path -match '(?i)\\FiveM\\FiveM\.app\\'
            if ($path -match '(?i)\\FiveM\.app\\plugins\\') { Add-Finding 'Module' 'High' $path 'Loaded from FiveM plugins folder'; continue }
            if (-not $inFivem -and $path -notmatch '(?i)\\Program Files') {
                $sig = Get-AuthenticodeSignature -LiteralPath $path
                if ($sig.Status -ne 'Valid') { Add-Finding 'Module' 'Medium' $path "Unsigned module in $($p.ProcessName) ($($sig.Status))" }
            }
        }
    }
}

# ----------------------------------------------------------------------------------------------
#  3. FIVEM + GTA FOLDERS
# ----------------------------------------------------------------------------------------------
Invoke-Section '3. FiveM and GTA V folders' {
    foreach ($fm in Get-FiveMPaths) {
        $app = Join-Path $fm 'FiveM.app'
        foreach ($sub in 'plugins','mods') {
            foreach ($f in Get-ChildItem (Join-Path $app $sub) -Recurse -File -Force) {
                Add-Finding "FiveM-$sub" 'High' $f.FullName "Size $($f.Length) | Created $($f.CreationTime) | SHA256 $(Get-Hash $f.FullName)"
            }
        }
        foreach ($f in Get-ChildItem $app -Recurse -File -Force -Include *.asi,*.sys,*.exe -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '(?i)\\(crashes|data\\cache)\\' -and $_.Name -notmatch '(?i)^(FiveM|CitizenFX|CefSharp|FiveM_.*|subprocess).*\.exe$|crashpad|Cfx' }) {
            Add-Finding 'FiveM-Files' 'Medium' $f.FullName "Unexpected binary inside FiveM.app | SHA256 $(Get-Hash $f.FullName)"
        }
        $ini = Join-Path $app 'CitizenFX.ini'
        if (Test-Path $ini) {
            foreach ($l in Get-Content $ini) { $s = Get-Sev $l; if ($s) { Add-Finding 'CitizenFX.ini' $s $l $ini } }
        }
        # FiveM logs
        $logs = Get-ChildItem (Join-Path $app 'logs') -Filter *.log -File | Sort-Object LastWriteTime -Descending | Select-Object -First 25
        foreach ($lg in $logs) {
            $hits = Select-String -Path $lg.FullName -Pattern $RxStrong -ErrorAction SilentlyContinue | Select-Object -First 5
            foreach ($h in $hits) { Add-Finding 'FiveM-Log' 'High' ($lg.Name + ': ' + $h.Line.Trim()) $lg.FullName }
        }
    }
    foreach ($g in Get-GtaDirs) {
        Write-Host "  GTA V folder: $g" -ForegroundColor DarkGray
        foreach ($f in Get-ChildItem $g -Force -File -ErrorAction SilentlyContinue) {
            if ($f.Name -match '(?i)\.asi$|^dinput8\.dll$|scripthookv|scripthookvdotnet|openiv|asiloader|^d3d11\.dll$|^dxgi\.dll$|^d3d9\.dll$|reshade|^version\.dll$|^winmm\.dll$|dsound\.dll') {
                Add-Finding 'GTA-Folder' 'Medium' $f.FullName "Mod/loader file (proxy DLL or ASI) | SHA256 $(Get-Hash $f.FullName)"
            }
        }
        foreach ($d in 'scripts','plugins','mods') {
            foreach ($f in Get-ChildItem (Join-Path $g $d) -Recurse -File -Force) { Add-Finding 'GTA-Folder' 'Low' $f.FullName "File in GTA $d folder" }
        }
    }
}

# ----------------------------------------------------------------------------------------------
#  4. FILE SYSTEM
# ----------------------------------------------------------------------------------------------
Invoke-Section ('4. File system scan (' + $(if ($Deep) { 'DEEP - all drives' } else { 'FAST - targeted' }) + ')') {
    $roots = @()   # @(path, depth)
    if ($Deep) {
        foreach ($d in Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -in 2,3 }) { $roots += ,@(($d.DeviceID + '\'), 64) }
    } else {
        foreach ($p in Get-UserProfiles) {
            foreach ($s in 'Desktop','Downloads','Documents','Videos','Pictures','Music','AppData\Roaming','AppData\Local','AppData\LocalLow','OneDrive','Dropbox','Google Drive') {
                $roots += ,@((Join-Path $p.FullName $s), 64)
            }
            $roots += ,@($p.FullName, 1)
        }
        $roots += ,@("$env:ProgramData", 6)
        $roots += ,@("$env:SystemRoot\Temp", 6)
        $roots += ,@("$env:SystemDrive\", 1)
        foreach ($d in Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -in 2,3 -and $_.DeviceID -ne $env:SystemDrive }) { $roots += ,@(($d.DeviceID + '\'), 5) }
    }
    $textExt = '.lua','.txt','.cfg','.ini','.json','.bat','.cmd','.ps1','.js','.log','.xml','.vbs','.md'
    $binExt  = '.exe','.dll','.sys','.asi'
    $unsignedCount = 0
    $scanned = 0
    foreach ($r in $roots) {
        if (-not (Test-Path -LiteralPath $r[0])) { continue }
        Walk $r[0] $r[1] | ForEach-Object {
            $f = $_
            $scanned++
            if ($f -eq $PSCommandPath -or $f -like "$OutDir*") { return }
            $name = [IO.Path]::GetFileName($f)
            $ext  = [IO.Path]::GetExtension($f).ToLower()
            $inUser = $f -match $RxUserDir

            $sev = Get-Sev $name
            if ($sev -and -not ($ext -in '.lnk' -and $sev -eq 'Low')) {
                $d = ''
                if ($ext -in $binExt + '.zip','.rar','.7z') { $d = 'SHA256 ' + (Get-Hash $f) }
                $fi = Get-Item -LiteralPath $f -Force
                Add-Finding 'File' $sev $f ("Created $($fi.CreationTime) | Modified $($fi.LastWriteTime) | $d")
            }
            if ($ext -eq '.sys' -and $inUser -and $f -notmatch '(?i)\\(Windows|Program Files)') { Add-Finding 'File' 'Medium' $f ('Driver file in user-writable location | SHA256 ' + (Get-Hash $f)) }
            if ($ext -eq '.asi'  -and $f -notmatch '(?i)Grand Theft Auto') { Add-Finding 'File' 'Medium' $f '.asi plugin outside GTA folder' }

            if ($inUser -and $ext -in $textExt) {
                $fi = New-Object IO.FileInfo $f
                if ($fi.Length -gt 0 -and $fi.Length -lt 2MB) {
                    $txt = [IO.File]::ReadAllText($f)
                    if ($txt -match $RxStrong) { Add-Finding 'FileContent' 'Medium' $f ('Content matched: ' + $Matches[0]) }
                }
            }
            if ($ext -in $binExt -and $f -match '(?i)\\Users\\[^\\]+\\(Downloads|Desktop|Documents)\\|\\Temp\\|\\FiveM\\|\\ProgramData\\') {
                $fi = New-Object IO.FileInfo $f
                if ($fi.Length -gt 1KB -and $fi.Length -lt 60MB) {
                    $b = [IO.File]::ReadAllBytes($f)
                    $hit = $null
                    $a = [Text.Encoding]::GetEncoding(28591).GetString($b)
                    if ($a -match $RxBin) { $hit = $Matches[1] }
                    else { $u = [Text.Encoding]::Unicode.GetString($b); if ($u -match $RxBin) { $hit = $Matches[1] } }
                    if ($hit) { Add-Finding 'BinaryString' 'High' $f ("Binary contains cheat string '$hit' | SHA256 " + (Get-Hash $f)) }
                    elseif ($unsignedCount -lt 150 -and $fi.CreationTime -gt $Start.AddDays(-$Days)) {
                        $sig = Get-AuthenticodeSignature -LiteralPath $f
                        if ($sig.Status -eq 'NotSigned') { $unsignedCount++; Add-Finding 'Unsigned' 'Low' $f "Recent unsigned binary, created $($fi.CreationTime)" }
                    }
                }
            }
        }
    }
    Write-Host "  Files examined: $scanned" -ForegroundColor DarkGray

    # Recycle Bin
    foreach ($i in Get-ChildItem "$env:SystemDrive\`$Recycle.Bin" -Recurse -Force -File | Where-Object { $_.Name -like '$I*' }) {
        $b = [IO.File]::ReadAllBytes($i.FullName)
        if ($b.Length -lt 30) { continue }
        $ver = [BitConverter]::ToInt64($b, 0)
        $off = if ($ver -eq 2) { 28 } else { 24 }
        $orig = [Text.Encoding]::Unicode.GetString($b, $off, $b.Length - $off).Trim([char]0)
        $when = [DateTime]::FromFileTime([BitConverter]::ToInt64($b, 16))
        $s = Get-Sev ([IO.Path]::GetFileName($orig))
        if ($s) { Add-Finding 'RecycleBin' $s $orig "Deleted at $when" }
    }
}

# ----------------------------------------------------------------------------------------------
#  5. EXECUTION HISTORY ARTIFACTS
# ----------------------------------------------------------------------------------------------
Invoke-Section '5. Prefetch' {
    $pf = "$env:SystemRoot\Prefetch"
    $en = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters').EnablePrefetcher
    if ($en -eq 0) { Add-Finding 'Prefetch' 'Medium' 'Prefetch is DISABLED' 'EnablePrefetcher = 0 (hides executed programs)' }
    $sm = Get-Service SysMain
    if ($sm -and $sm.Status -ne 'Running') { Add-Finding 'Prefetch' 'Low' 'SysMain service not running' "Status: $($sm.Status)" }
    $files = Get-ChildItem $pf -Filter *.pf -Force
    if (-not $files) { Add-Finding 'Prefetch' 'Medium' 'Prefetch folder is empty or missing' 'Possible cleanup' }
    else {
        $oldest = ($files | Sort-Object CreationTime | Select-Object -First 1).CreationTime
        if ($oldest -gt (Get-Date).AddDays(-2)) { Add-Finding 'Prefetch' 'Low' 'Prefetch history is very recent' "Oldest entry: $oldest (possible recent cleaning)" }
        foreach ($f in $files) {
            $n = $f.Name -replace '-[0-9A-Fa-f]{8}\.pf$', ''
            $s = Get-Sev $n
            if ($s) { Add-Finding 'Prefetch' $s $n "Last run ~ $($f.LastWriteTime) | First run ~ $($f.CreationTime)" }
        }
    }
}

Invoke-Section '6. Registry execution traces (UserAssist, BAM, MuiCache, AppCompat, RunMRU)' {
    foreach ($h in Get-UserHives) {
        # UserAssist (ROT13)
        foreach ($g in Get-ChildItem "$h\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist") {
            $k = Get-Item ($g.PSPath + '\Count')
            if (-not $k) { continue }
            foreach ($vn in $k.GetValueNames()) {
                $dec = ROT13 $vn
                $s = Get-Sev $dec
                if ($s) {
                    $b = $k.GetValue($vn); $runs = ''; $when = ''
                    if ($b -is [byte[]] -and $b.Length -ge 68) {
                        $runs = [BitConverter]::ToUInt32($b, 4)
                        $ft = [BitConverter]::ToInt64($b, 60)
                        if ($ft -gt 0) { $when = [DateTime]::FromFileTime($ft) }
                    }
                    Add-Finding 'UserAssist' $s $dec "Runs: $runs | Last: $when"
                }
            }
        }
        Scan-RegNames "$h\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" 'MuiCache'
        Scan-RegNames "$h\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store" 'AppCompat'
        Scan-RegNames "$h\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted" 'AppCompat'
        Scan-RegNames "$h\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" 'AppCompat'
        $rm = Get-Item "$h\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        if ($rm) { foreach ($vn in $rm.GetValueNames()) { $v = [string]$rm.GetValue($vn); $s = Get-Sev $v; if ($s) { Add-Finding 'RunMRU' $s $v 'Run dialog history' } } }
    }
    Scan-RegNames 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store' 'AppCompat'
    # BAM
    $bam = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
    if (-not (Test-Path $bam)) { $bam = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings' }
    foreach ($u in Get-ChildItem $bam) {
        foreach ($vn in $u.GetValueNames()) {
            $s = Get-Sev $vn
            if ($s) {
                $b = $u.GetValue($vn); $when = ''
                if ($b -is [byte[]] -and $b.Length -ge 8) { $when = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($b, 0)).ToLocalTime() }
                Add-Finding 'BAM' $s $vn "Last execution: $when"
            }
        }
    }
}

Invoke-Section '7. Recent files (.lnk)' {
    $sh = New-Object -ComObject WScript.Shell
    foreach ($p in Get-UserProfiles) {
        foreach ($l in Get-ChildItem (Join-Path $p.FullName 'AppData\Roaming\Microsoft\Windows\Recent') -Filter *.lnk -Force) {
            $target = ''
            try { $target = $sh.CreateShortcut($l.FullName).TargetPath } catch {}
            $s = Get-Sev "$($l.BaseName) $target"
            if ($s) { Add-Finding 'RecentLnk' $s $l.BaseName "Target: $target | Last opened: $($l.LastWriteTime)" }
        }
    }
}

# ----------------------------------------------------------------------------------------------
#  8. DRIVERS / KERNEL
# ----------------------------------------------------------------------------------------------
Invoke-Section '8. Drivers and kernel integrity' {
    foreach ($d in Get-CimInstance Win32_SystemDriver) {
        $path = ($d.PathName -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:SystemRoot).Trim('"')
        $base = [IO.Path]::GetFileNameWithoutExtension($path)
        $txt  = "$($d.Name) $($d.DisplayName) $path"
        $sev = Get-Sev $txt
        if ($sev) { Add-Finding 'Driver' $sev $d.Name "$path | State $($d.State)" }
        if ($base -match $RxVulnDrv -or $d.Name -match $RxVulnDrv) { Add-Finding 'Driver' 'High' $d.Name "Known vulnerable/abused driver (BYOVD / mapper / spoofer) | $path | State $($d.State)" }
        if ($d.State -eq 'Running' -and $path -and (Test-Path -LiteralPath $path) -and $path -notmatch '(?i)\\Windows\\System32\\(drivers|DriverStore)') {
            $sig = Get-AuthenticodeSignature -LiteralPath $path
            if ($sig.Status -ne 'Valid') { Add-Finding 'Driver' 'Medium' $d.Name "Running driver outside System32\drivers is not validly signed ($($sig.Status)): $path" }
            elseif ($path -match $RxUserDir) { Add-Finding 'Driver' 'Medium' $d.Name "Driver running from user-writable path: $path" }
        }
    }
    foreach ($k in Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services') {
        if ($k.PSChildName -match $RxVulnDrv) { Add-Finding 'DriverTrace' 'Medium' $k.PSChildName 'Leftover service key of a vulnerable/abused driver' }
    }
    foreach ($f in Get-ChildItem "$env:SystemRoot\System32\drivers" -Filter *.sys -File) {
        if ([IO.Path]::GetFileNameWithoutExtension($f.Name) -match $RxVulnDrv) { Add-Finding 'DriverFile' 'Medium' $f.FullName "Abused driver file present (created $($f.CreationTime))" }
    }
    $bcd = (bcdedit /enum '{current}' 2>$null) -join "`n"
    if ($bcd -match '(?i)testsigning\s+Yes')        { Add-Finding 'Kernel' 'High'   'Test-signing is ENABLED' 'Allows loading unsigned kernel cheats/spoofers' }
    if ($bcd -match '(?i)nointegritychecks\s+Yes')  { Add-Finding 'Kernel' 'High'   'Driver integrity checks DISABLED' 'bcdedit nointegritychecks' }
    if ($bcd -match '(?i)debug\s+Yes')              { Add-Finding 'Kernel' 'Medium' 'Kernel debugging enabled' '' }
    $bl = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config').VulnerableDriverBlocklistEnable
    if ($bl -eq 0) { Add-Finding 'Kernel' 'Medium' 'Microsoft vulnerable driver blocklist is disabled' '' }
    $hv = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity').Enabled
    Add-Finding 'Kernel' 'Info' "HVCI (Memory integrity): $(if($hv -eq 1){'ON'}else{'OFF/unknown'})" ''
}

# ----------------------------------------------------------------------------------------------
#  9. SERVICES / TASKS / STARTUP
# ----------------------------------------------------------------------------------------------
Invoke-Section '9. Services, scheduled tasks, startup' {
    foreach ($s in Get-CimInstance Win32_Service) {
        $sev = Get-Sev "$($s.Name) $($s.DisplayName) $($s.PathName)"
        if ($sev) { Add-Finding 'Service' $sev $s.Name $s.PathName }
        elseif ($s.PathName -match '(?i)\\(Temp|Downloads|Desktop)\\') { Add-Finding 'Service' 'Medium' $s.Name "Service binary in user folder: $($s.PathName)" }
    }
    foreach ($t in Get-ScheduledTask) {
        foreach ($a in $t.Actions) {
            $cmd = "$($a.Execute) $($a.Arguments)"
            $sev = Get-Sev "$($t.TaskName) $cmd"
            if ($sev) { Add-Finding 'Task' $sev $t.TaskName $cmd }
            elseif ($cmd -match '(?i)\\(Temp|Downloads|Desktop)\\') { Add-Finding 'Task' 'Low' $t.TaskName $cmd }
        }
    }
    $runKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
    foreach ($h in Get-UserHives) { $runKeys += "$h\Software\Microsoft\Windows\CurrentVersion\Run"; $runKeys += "$h\Software\Microsoft\Windows\CurrentVersion\RunOnce" }
    foreach ($rk in $runKeys) {
        $k = Get-Item -LiteralPath $rk
        if (-not $k) { continue }
        foreach ($n in $k.GetValueNames()) {
            $v = [string]$k.GetValue($n); $s = Get-Sev "$n $v"
            if ($s) { Add-Finding 'Startup' $s $n $v }
            elseif ($v -match '(?i)\\(Temp|Downloads|Desktop)\\') { Add-Finding 'Startup' 'Low' $n $v }
        }
    }
}

# ----------------------------------------------------------------------------------------------
#  10. EVENT LOGS + DEFENDER
# ----------------------------------------------------------------------------------------------
Invoke-Section '10. Event logs and Windows Defender' {
    foreach ($e in Get-Ev 'Security' 1102) { Add-Finding 'EventLog' 'Medium' "Security log CLEARED at $($e.TimeCreated)" 'Event 1102' }
    foreach ($e in Get-Ev 'System' 104)    { Add-Finding 'EventLog' 'Medium' "Event log CLEARED at $($e.TimeCreated)" 'Event 104' }
    foreach ($e in Get-Ev 'System' 7045) {
        $svc = [string]$e.Properties[0].Value; $img = [string]$e.Properties[1].Value; $typ = [string]$e.Properties[2].Value
        $s = Get-Sev "$svc $img"
        if ($s) { Add-Finding 'ServiceInstall' $s $svc "$img | $typ | $($e.TimeCreated)" }
        elseif ($typ -match '(?i)kernel' -and $img -notmatch '(?i)\\Windows\\System32\\drivers|DriverStore') {
            Add-Finding 'ServiceInstall' 'Medium' $svc "Kernel driver service installed from unusual path: $img | $($e.TimeCreated)"
        }
    }
    $seenThreat = @{}
    foreach ($e in Get-Ev 'Microsoft-Windows-Windows Defender/Operational' @(1116, 1117)) {
        $msg = $e.Message
        $name = if ($msg -match 'Name:\s*(.+)') { $Matches[1].Trim() } else { 'Unknown' }
        $path = if ($msg -match 'Path:\s*(.+)') { $Matches[1].Trim() } else { '' }
        if ($seenThreat["$name|$path"]) { continue }; $seenThreat["$name|$path"] = 1
        $sev = if ((Get-Sev "$name $path") -eq 'High') { 'High' } elseif ($name -match '(?i)HackTool|Cheat|Inject|Spoof|Exploit|Wacatac|Behavior|Trojan|Gen') { 'Medium' } else { 'Low' }
        Add-Finding 'Defender' $sev "Detection: $name" "$path | $($e.TimeCreated)"
    }
    foreach ($e in Get-Ev 'Microsoft-Windows-Windows Defender/Operational' @(5001, 5004, 5007, 5008)) {
        if ($e.Message -match '(?i)exclusion|disabled|DisableRealtime|Exclusions') { Add-Finding 'Defender' 'Low' "Defender config change at $($e.TimeCreated)" (($e.Message -split "`n")[0..4] -join ' ') }
    }
    $mp = Get-MpPreference
    if ($mp) {
        foreach ($x in @($mp.ExclusionPath) + @($mp.ExclusionProcess) + @($mp.ExclusionExtension)) {
            if (-not $x) { continue }
            $s = Get-Sev $x
            if (-not $s) { $s = if ($x -match '(?i)Downloads|Desktop|Temp|AppData|Users') { 'Medium' } else { 'Low' } }
            Add-Finding 'DefenderExcl' $s $x 'Defender exclusion (cheats are often whitelisted)'
        }
        if ($mp.DisableRealtimeMonitoring) { Add-Finding 'Defender' 'Medium' 'Real-time protection is OFF' '' }
    }
    $null = fsutil usn queryjournal "$env:SystemDrive" 2>&1
    if ($LASTEXITCODE -ne 0) { Add-Finding 'USN' 'Medium' 'NTFS USN journal missing or deleted' 'Often wiped to hide file activity' }
    $tc = @(Get-Ev 'System' 1 | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Kernel-General' })
    if ($tc.Count -gt 0) { Add-Finding 'SystemTime' 'Low' "System clock changed $($tc.Count) time(s) in last $Days days" 'Can be used to fake file/execution timestamps' }
}

# ----------------------------------------------------------------------------------------------
#  11. NETWORK TRACES + BROWSERS
# ----------------------------------------------------------------------------------------------
Invoke-Section '11. DNS cache, hosts file, browser history' {
    foreach ($d in Get-DnsClientCache) {
        $s = Get-Sev $d.Entry
        if ($s) { Add-Finding 'DNS' $s $d.Entry 'Seen in DNS cache' }
    }
    foreach ($l in Get-Content "$env:SystemRoot\System32\drivers\etc\hosts") {
        if ($l -match '^\s*#' -or $l -match '^\s*$') { continue }
        $s = Get-Sev $l
        Add-Finding 'Hosts' $(if ($s) { $s } else { 'Low' }) $l.Trim() 'Non-default hosts entry'
    }
    $rx = '(?i)[\x20-\x7e]{0,60}(' + ($Strong -join '|') + ')[\x20-\x7e]{0,60}'
    $dbs = @()
    foreach ($p in Get-UserProfiles) {
        $L = Join-Path $p.FullName 'AppData\Local'; $R = Join-Path $p.FullName 'AppData\Roaming'
        foreach ($b in "$L\Google\Chrome\User Data", "$L\Microsoft\Edge\User Data", "$L\BraveSoftware\Brave-Browser\User Data", "$L\Vivaldi\User Data", "$R\Opera Software\Opera Stable", "$R\Opera Software\Opera GX Stable") {
            foreach ($f in Get-ChildItem $b -Recurse -Depth 2 -Filter History -File -Force) { $dbs += $f.FullName }
        }
        foreach ($f in Get-ChildItem "$R\Mozilla\Firefox\Profiles" -Recurse -Depth 2 -Filter places.sqlite -File -Force) { $dbs += $f.FullName }
    }
    foreach ($db in $dbs) {
        $bytes = Read-SharedBytes $db
        if (-not $bytes) { continue }
        $txt = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
        $n = 0
        foreach ($m in [regex]::Matches($txt, $rx)) {
            Add-Finding 'Browser' 'Medium' $m.Value.Trim() $db
            if (++$n -ge 20) { break }
        }
    }
}

# ----------------------------------------------------------------------------------------------
#  12. HARDWARE / SPOOFER TRACES
# ----------------------------------------------------------------------------------------------
Invoke-Section '12. Hardware, HWID/MAC spoof traces, DMA and HID devices' {
    $netClass = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
    foreach ($k in Get-ChildItem $netClass | Where-Object { $_.PSChildName -match '^\d{4}$' }) {
        $na = (Get-ItemProperty $k.PSPath).NetworkAddress
        if ($na) { Add-Finding 'MAC' 'Medium' "Custom MAC address override ($na)" "Adapter: $((Get-ItemProperty $k.PSPath).DriverDesc) - typical of HWID spoofing" }
    }
    $odd = '(?i)to be filled|default string|^none$|not applicable|system serial|123456789|^0+$|^f+$|o\.e\.m|^(.)\1{5,}$|unknown'
    $ids = @(
        @('BIOS serial',      (Get-CimInstance Win32_BIOS).SerialNumber),
        @('Baseboard serial', (Get-CimInstance Win32_BaseBoard).SerialNumber),
        @('System UUID',      (Get-CimInstance Win32_ComputerSystemProduct).UUID)
    )
    foreach ($dk in Get-CimInstance Win32_DiskDrive) { $ids += ,@("Disk serial ($($dk.Model))", ($dk.SerialNumber -as [string])) }
    foreach ($i in $ids) {
        if ($i[1] -and ($i[1].Trim() -match $odd)) { Add-Finding 'HWID' 'Low' "$($i[0]) looks blank/placeholder: $($i[1])" 'Common on cheap boards, but also seen after SMBIOS spoofing' }
    }
    $mg = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
    Add-Finding 'HWID' 'Info' "MachineGuid: $mg" 'Record this - compare with the player''s previous checks/bans'
    $os = Get-CimInstance Win32_OperatingSystem
    if ($os.InstallDate -gt (Get-Date).AddDays(-14)) { Add-Finding 'HWID' 'Low' "Windows installed recently ($($os.InstallDate))" 'Fresh installs are used for ban evasion' }
    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.Model -match '(?i)vmware|virtualbox|virtual machine|kvm|qemu|hyper-v') { Add-Finding 'VM' 'Low' "Running inside a VM: $($cs.Model)" '' }

    $dma = '(?i)xilinx|artix|pcileech|screamer|squirrel|ft60[1-9]|ft245|enigma|neptune|lambdaconcept|leetdma|dma[\s_-]?card|thunderbolt.*(fpga)|sp605|ac701|pciescreamer'
    $hid = '(?i)arduino|teensy|leonardo|pro[\s_-]?micro|kmbox|makcu|rp2040|raspberry pi pico|ch340|ch9102|cp210|digispark|atmega32u4|titan[\s_-]?two|cronus|xim[\s_-]?(apex|matrix)|strike[\s_-]?pack|reasnow'
    foreach ($d in Get-PnpDevice) {
        $t = "$($d.FriendlyName) $($d.InstanceId) $($d.Manufacturer)"
        $present = if ($d.Present) { 'currently connected' } else { 'previously connected' }
        if ($t -match $dma) { Add-Finding 'Hardware' 'High'   "Possible DMA cheat device: $($d.FriendlyName)" "$($d.InstanceId) ($present)" }
        elseif ($t -match $hid) { Add-Finding 'Hardware' 'Medium' "Possible aim/input-spoof device: $($d.FriendlyName)" "$($d.InstanceId) ($present)" }
    }
}

# ----------------------------------------------------------------------------------------------
#  REPORT
# ----------------------------------------------------------------------------------------------
$sorted = $Findings | Sort-Object @{ Expression = { $SevOrder[$_.Severity] } }, Category, Item
$score  = 0; foreach ($f in $Findings) { $score += $SevScore[$f.Severity] }
$cH = @($Findings | Where-Object Severity -eq 'High').Count
$cM = @($Findings | Where-Object Severity -eq 'Medium').Count
$cL = @($Findings | Where-Object Severity -eq 'Low').Count
$verdict = if ($cH -ge 1 -or $score -ge 20) { 'SUSPICIOUS - strong indicators found, manual review required' }
           elseif ($score -ge 6)            { 'REVIEW - some indicators, verify manually' }
           else                             { 'CLEAN (no strong indicators) - this does NOT guarantee the PC is clean' }
$verdictColor = if ($verdict -like 'SUSPICIOUS*') { 'Red' } elseif ($verdict -like 'REVIEW*') { 'Yellow' } else { 'Green' }

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("FiveM-Sentinel v$Version report")
[void]$sb.AppendLine("Computer : $env:COMPUTERNAME   User: $env:USERNAME")
[void]$sb.AppendLine("Started  : $Start   Duration: $([int]((Get-Date) - $Start).TotalSeconds)s   Mode: $(if($Deep){'DEEP'}else{'FAST'})")
[void]$sb.AppendLine("Score    : $score   (High=$cH  Medium=$cM  Low=$cL)")
[void]$sb.AppendLine("Verdict  : $verdict")
[void]$sb.AppendLine(('-' * 100))
foreach ($f in $sorted) {
    [void]$sb.AppendLine(("[{0}] {1} :: {2}" -f $f.Severity.ToUpper(), $f.Category, $f.Item))
    if ($f.Detail) { [void]$sb.AppendLine("        $($f.Detail)") }
}
[void]$sb.AppendLine(('-' * 100))
[void]$sb.AppendLine('Indicators are not proof. Verify each finding manually (hash lookup, file origin, context).')

$txt = Join-Path $OutDir 'report.txt'
$sb.ToString() | Out-File -FilePath $txt -Encoding UTF8
$sorted | Export-Csv -Path (Join-Path $OutDir 'report.csv') -NoTypeInformation -Encoding UTF8
$css = '<style>body{font-family:Segoe UI,Arial;background:#111;color:#eee}table{border-collapse:collapse;width:100%}th,td{border:1px solid #333;padding:4px 8px;font-size:13px;text-align:left;word-break:break-all}th{background:#222}tr:nth-child(even){background:#181818}</style>'
$pre = "<h2>FiveM-Sentinel report - $env:COMPUTERNAME</h2><p>Score: $score (High $cH / Medium $cM / Low $cL)<br>Verdict: $verdict</p>"
$sorted | ConvertTo-Html -Head $css -PreContent $pre -Title 'FiveM-Sentinel' | Out-File (Join-Path $OutDir 'report.html') -Encoding UTF8
(Get-FileHash $txt -Algorithm SHA256).Hash | Out-File (Join-Path $OutDir 'report.txt.sha256') -Encoding ASCII

Write-Host ''
Write-Host ('=' * 70) -ForegroundColor Magenta
Write-Host " SCORE: $score   High: $cH   Medium: $cM   Low: $cL" -ForegroundColor White
Write-Host " VERDICT: $verdict" -ForegroundColor $verdictColor
Write-Host " Reports saved to: $OutDir" -ForegroundColor White
Write-Host ('=' * 70) -ForegroundColor Magenta
Invoke-Item $OutDir
