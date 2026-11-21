# ==================================
# Argus - PC Integrity & Cheat Check
# Updated & Fixed Version
# Author: SeraphV2
# ==================================

Add-Type -AssemblyName PresentationFramework
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
    $StartTime = Get-Date
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

    # --- PROGRESS WINDOW (WPF) ---
    $ProgressForm = New-Object System.Windows.Window
    $ProgressForm.Title = "Scanning $Game..."
    $ProgressForm.Width = 400
    $ProgressForm.Height = 160
    $ProgressForm.WindowStartupLocation = "CenterScreen"

    $grid = New-Object System.Windows.Controls.Grid
    $ProgressForm.Content = $grid

    $Label = New-Object System.Windows.Controls.TextBlock
    $Label.Text = "Starting scan..."
    $Label.Margin = "10"
    $grid.Children.Add($Label)

    $ProgressBar = New-Object System.Windows.Controls.ProgressBar
    $ProgressBar.Height = 20
    $ProgressBar.Margin = "10,40,10,0"
    $ProgressBar.Minimum = 0
    $ProgressBar.Maximum = 100
    $grid.Children.Add($ProgressBar)

    $TimerLabel = New-Object System.Windows.Controls.TextBlock
    $TimerLabel.Margin = "10,70,10,0"
    $grid.Children.Add($TimerLabel)

    $ProgressForm.Show()

    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromSeconds(1)
    $timer.Add_Tick({
        $elapsed = (Get-Date) - $StartTime
        $TimerLabel.Text = "Elapsed Time: {0}h {1}m {2}s" -f $elapsed.Hours,$elapsed.Minutes,$elapsed.Seconds
    })
    $timer.Start()

    # --- SCAN OPERATIONS ---
    $ProgressBar.Value = 20
    $Label.Text = "Scanning registry..."
    $Timeline += ScanRegistry $OutFile

    $ProgressBar.Value = 40
    $Label.Text = "Scanning startup and scheduled tasks..."
    $Timeline += ScanStartup $OutFile

    $ProgressBar.Value = 60
    $Label.Text = "Scanning services and drivers..."
    $Timeline += ScanServicesAndDrivers $OutFile

    $TempFolder = "$env:TEMP\PC_EVIDENCE_$Time"
    New-Item -ItemType Directory -Path $TempFolder -Force | Out-Null

    $ProgressBar.Value = 80
    $Label.Text = "Collecting USB history and event logs..."
    Get-USBHistory $TempFolder | Out-Null
    Get-EventLogs $TempFolder | Out-Null

    $ProgressBar.Value = 100
    $timer.Stop()
    $ProgressForm.Close()

    # --- FINALIZE REPORT & ZIP ---
    $Timeline | Export-Csv -Path "$TempFolder\Timeline.csv" -NoTypeInformation -Force
    Copy-Item -Path $OutFile -Destination "$TempFolder\" -Force -ErrorAction SilentlyContinue
    $ZipFile = "$env:USERPROFILE\Desktop\PC_EVIDENCE_${PC}_$Time.zip"
    Compress-Archive -Path "$TempFolder\*" -DestinationPath $ZipFile -Force
    Remove-Item $TempFolder -Recurse -Force -ErrorAction SilentlyContinue

    [System.Windows.MessageBox]::Show("Scan complete.`nReport saved to Desktop.`nZIP evidence: $ZipFile","Done")
}

# ---------------- GUI ----------------
$w = New-Object System.Windows.Window
$w.Title = "Argus - PC Integrity"
$w.Width = 520
$w.Height = 620
$w.WindowStartupLocation = "CenterScreen"
$w.Background = "#1E1E1E"

$Main = New-Object System.Windows.Controls.DockPanel

# Header
$Header = New-Object System.Windows.Controls.StackPanel
$Header.Orientation = "Horizontal"
$Header.Margin = "10"
$TitleStack = New-Object System.Windows.Controls.StackPanel
$TitleStack.Margin = "10,0,0,0"
$TitleText = New-Object System.Windows.Controls.TextBlock
$TitleText.Text = "Argus"
$TitleText.FontSize = 22
$TitleText.FontWeight = "Bold"
$TitleText.Foreground = "White"
$SubText = New-Object System.Windows.Controls.TextBlock
$SubText.Text = "Integrity && PC Check"
$SubText.FontSize = 14
$SubText.Foreground = "LightGray"
$TitleStack.AddChild($TitleText)
$TitleStack.AddChild($SubText)
$Header.AddChild($TitleStack)
[System.Windows.Controls.DockPanel]::SetDock($Header,"Top")
$Main.AddChild($Header)

# Operator / Player
$FieldsPanel = New-Object System.Windows.Controls.StackPanel
$FieldsPanel.Orientation = "Horizontal"
$FieldsPanel.Margin = "10"
$OpLabel = New-Object System.Windows.Controls.TextBlock
$OpLabel.Text = "Operator:"
$OpLabel.Width = 70
$OpLabel.Foreground = "White"
$OpBox = New-Object System.Windows.Controls.TextBox
$OpBox.Width = 120
$OpBox.Margin = "5,0,10,0"
$PlLabel = New-Object System.Windows.Controls.TextBlock
$PlLabel.Text = "Player:"
$PlLabel.Width = 50
$PlLabel.Foreground = "White"
$PlBox = New-Object System.Windows.Controls.TextBox
$PlBox.Width = 120
$PlBox.Margin = "5,0,0,0"
$FieldsPanel.AddChild($OpLabel)
$FieldsPanel.AddChild($OpBox)
$FieldsPanel.AddChild($PlLabel)
$FieldsPanel.AddChild($PlBox)
[System.Windows.Controls.DockPanel]::SetDock($FieldsPanel,"Top")
$Main.AddChild($FieldsPanel)

# Buttons
$p = New-Object System.Windows.Controls.StackPanel
$p.Margin = "20"
$p.HorizontalAlignment = "Center"
[System.Windows.Controls.DockPanel]::SetDock($p,"Top")
$Main.AddChild($p)

function Btn($n,$k){
    $b = New-Object System.Windows.Controls.Button
    $b.Content = $n
    $b.Width = 200
    $b.Height = 40
    $b.Margin = "0,5,0,5"
    $b.Background = "#3C3C3C"
    $b.Foreground = "White"
    $b.Add_Click({
        if([string]::IsNullOrWhiteSpace($OpBox.Text) -or [string]::IsNullOrWhiteSpace($PlBox.Text)){
            [System.Windows.MessageBox]::Show("Please enter Operator and Player names.","Input required")
            return
        }
        RunScan $n $k $OpBox.Text $PlBox.Text
    })
    $p.AddChild($b)
}

Btn "FiveM / GTA" @("fivem","gta","rage","lua","menu","inject")
Btn "Call of Duty" @("cod","warzone","unlock","aim","esp")
Btn "Rainbow Six Siege" @("r6","siege","recoil","wall")
Btn "Valorant" @("valorant","vanguard","overlay","trigger")
Btn "ALL GAMES" ($High+$Medium+$Low)

# Footer
$Footer = New-Object System.Windows.Controls.TextBlock
$Footer.Text = $FooterText
$Footer.Margin = "10"
$Footer.HorizontalAlignment = "Center"
$Footer.Foreground = "LightGray"
[System.Windows.Controls.DockPanel]::SetDock($Footer,"Bottom")
$Main.AddChild($Footer)

$w.Content = $Main
$w.ShowDialog() | Out-Null
