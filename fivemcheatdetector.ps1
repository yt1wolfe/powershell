# ==================================
# Argus - PC Integrity & Cheat Check (Silent FiveM Mode)
# Updated & Fixed Version
# Author: SeraphV2
# ==================================

Add-Type -AssemblyName System.IO.Compression.FileSystem

$OrgName = "Argus"
$SubTitle = "Integrity && PC Check"
$FooterText = "Authorized integrity scan - user consent required"

# ---------------- HELPERS ----------------
$Whitelist = @("nvidia","amd","microsoft","windows","steam","obs","logitech","razer","corsair","epic","battlenet","riot")
$High = @("dma","pcileech","leechcore","fpga","kdmapper","mapper","spoof","ring0")
$Medium = @("cheat","aimbot","esp","wallhack","inject","loader","overlay","trigger")
$Low = @("menu","cfg","lua","script")

function IsWhite($t){
    if([string]::IsNullOrWhiteSpace($t)){ return $false }
    $lower = ([string]$t).ToLower()
    foreach($w in $Whitelist){ if($lower -like "*$w*"){ return $true } }
    return $false
}

function GetSev($t){
    if([string]::IsNullOrWhiteSpace($t)){ return $null }
    $lower = ([string]$t).ToLower()
    foreach($h in $High){ if($lower -like "*$h*"){ return "HIGH" } }
    foreach($m in $Medium){ if($lower -like "*$m*"){ return "MEDIUM" } }
    foreach($l in $Low){ if($lower -like "*$l*"){ return "LOW" } }
    return $null
}

function LogArtifact($OutFile,$type,$path,$ts){
    if([string]::IsNullOrWhiteSpace($path)){ return $null }
    if(IsWhite $path){ return $null }
    $sev = GetSev $path
    if($sev){
        "[$sev] $type : $path" | Out-File $OutFile -Append
        return [PSCustomObject]@{Type=$type; Path=$path; Severity=$sev; Timestamp=$ts}
    }
    return $null
}

function GetFileHashAndSignature($file){
    try{
        $hash = (Get-FileHash $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        $sig = (Get-AuthenticodeSignature $file.FullName -ErrorAction Stop).Status
        return @{Hash=$hash; Signature=$sig; Path=$file.FullName; Created=$file.CreationTime; Modified=$file.LastWriteTime}
    }catch{
        return @{Hash="N/A"; Signature="Error"; Path=$file.FullName; Created=$file.CreationTime; Modified=$file.LastWriteTime}
    }
}

# ---------------- SCAN FUNCTIONS ----------------
function ScanRegistry($OutFile){
    $Timeline = @()
    "---- REGISTRY ----" | Out-File $OutFile -Append
    $paths = @(
        "HKCU:\Software",
        "HKLM:\Software",
        "HKLM:\SYSTEM\CurrentControlSet\Services",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach($p in $paths){
        if(Test-Path $p){
            Get-ChildItem $p -Recurse -ErrorAction SilentlyContinue | ForEach-Object{
                $ts = $_.LastWriteTime
                $obj = LogArtifact $OutFile "REGKEY" $_.Name $ts
                if($obj){ $Timeline += $obj }
                try{
                    $vals = Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue
                    if($vals){
                        foreach($x in $vals.PSObject.Properties){
                            $v = "$($x.Name) $($x.Value)"
                            $obj2 = LogArtifact $OutFile "REGVAL" $v $ts
                            if($obj2){ $Timeline += $obj2 }
                        }
                    }
                }catch{}
            }
        }
    }
    return $Timeline
}

function ScanStartup($OutFile){
    $Timeline = @()
    "---- STARTUP & SCHEDULED TASKS ----" | Out-File $OutFile -Append
    $StartupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach($f in $StartupFolders){
        if(Test-Path $f){
            Get-ChildItem $f -Recurse -ErrorAction SilentlyContinue | ForEach-Object{
                $ts = $_.CreationTime
                $obj = LogArtifact $OutFile "STARTUP_FILE" $_.FullName $ts
                if($obj){ $Timeline += $obj }
            }
        }
    }
    try{
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach($t in $tasks){
            $ts = Get-Date
            $obj = LogArtifact $OutFile "SCHEDULED_TASK" $t.TaskName $ts
            if($obj){ $Timeline += $obj }
        }
    }catch{}
    return $Timeline
}

function ScanServicesAndDrivers($OutFile){
    $Timeline = @()
    "---- SERVICES & DRIVERS ----" | Out-File $OutFile -Append
    try{
        $services = Get-Service -ErrorAction SilentlyContinue
        foreach($s in $services){
            $ts = Get-Date
            $obj = LogArtifact $OutFile "SERVICE" $s.Name $ts
            if($obj){ $Timeline += $obj }
        }
    }catch{}
    try{
        $drivers = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue
        foreach($d in $drivers){
            $ts = Get-Date
            $path = $d.PathName
            if(-not [string]::IsNullOrWhiteSpace($path)){
                $obj = LogArtifact $OutFile "DRIVER" $path $ts
                if($obj){ $Timeline += $obj }
            }
        }
    }catch{}
    return $Timeline
}

# ---------------- USB HISTORY ----------------
function Get-USBHistory($OutFolder){
    $usbFile = Join-Path $OutFolder "USBHistory.csv"
    $usbHistory = @()
    $usbPaths = @("HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR")

    foreach($p in $usbPaths){
        if(Test-Path $p){
            Get-ChildItem $p -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue
                if($props -and $props.DeviceDesc){
                    $usbHistory += [PSCustomObject]@{
                        DeviceID = $_.PSChildName
                        Description = $props.DeviceDesc
                        SerialNumber = $props.SerialNumber
                        FirstSeen = $props.InstallDate
                        LastConnected = $_.LastWriteTime
                    }
                }
            }
        }
    }
    $usbHistory | Export-Csv -Path $usbFile -NoTypeInformation -Force
    return $usbFile
}

# ---------------- EVENT LOGS ----------------
function Get-EventLogs($OutFolder){
    $logFile = Join-Path $OutFolder "EventLogs.csv"
    $Keywords = @("dma","inject","cheat","fpga","kdmapper","overlay","aimbot","wallhack")
    $pattern = ($Keywords -join "|")
    $events = @()

    foreach($logName in @("System","Application","Security")){
        try{
            $matched = Get-WinEvent -LogName $logName -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object {
                $_.Message -and ($_.Message -match $pattern)
            }
            foreach($e in $matched){
                $events += [PSCustomObject]@{
                    Timestamp = $e.TimeCreated
                    LogName = $e.LogName
                    Source = $e.ProviderName
                    EventID = $e.Id
                    Message = $e.Message
                }
            }
        }catch{}
    }

    $events | Sort-Object Timestamp -Descending | Export-Csv -Path $logFile -NoTypeInformation -Force
    return $logFile
}

# ---------------- MAIN SCAN FUNCTION ----------------
function RunScan($Game,$Keys,$Operator,$Player){
    $Time = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $PC = $env:COMPUTERNAME
    $SafeGame = ($Game -replace '[^a-zA-Z0-9_-]', '_')
    $OutFile = "$env:USERPROFILE\Desktop\PC_Check_${PC}_${SafeGame}_$Time.txt"
    $Timeline = @()

    "=== PC INTEGRITY CHECK ===" | Out-File $OutFile
    "Server: Argus" | Out-File $OutFile -Append
    "Game Profile: $Game" | Out-File $OutFile -Append
    "PC: $PC" | Out-File $OutFile -Append
    "Operator: $Operator" | Out-File $OutFile -Append
    "Player: $Player" | Out-File $OutFile -Append
    "Date: $(Get-Date)" | Out-File $OutFile -Append
    "" | Out-File $OutFile -Append

    $Timeline += ScanRegistry $OutFile
    $Timeline += ScanStartup $OutFile
    $Timeline += ScanServicesAndDrivers $OutFile

    $TempFolder = "$env:TEMP\PC_EVIDENCE_$Time"
    New-Item -ItemType Directory -Path $TempFolder -Force | Out-Null

    Get-USBHistory $TempFolder | Out-Null
    Get-EventLogs $TempFolder | Out-Null

    $Timeline | Export-Csv -Path "$TempFolder\Timeline.csv" -NoTypeInformation -Force
    Copy-Item -Path $OutFile -Destination "$TempFolder\" -Force -ErrorAction SilentlyContinue
    $ZipFile = "$env:USERPROFILE\Desktop\PC_EVIDENCE_${PC}_$Time.zip"
    Compress-Archive -Path "$TempFolder\*" -DestinationPath $ZipFile -Force
    Remove-Item $TempFolder -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------------- SILENT FIVEM EXECUTION ----------------
$Operator = if ($env:ARGUS_OPERATOR) { $env:ARGUS_OPERATOR } else { $env:USERNAME }
$Player = if ($env:ARGUS_PLAYER) { $env:ARGUS_PLAYER } else { $env:USERNAME }
RunScan "FiveM / GTA" @("fivem","gta","rage","lua","menu","inject") $Operator $Player | Out-Null
