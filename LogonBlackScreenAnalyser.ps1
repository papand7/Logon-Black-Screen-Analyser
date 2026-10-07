<#
.SYNOPSIS
    Logon Black Screen Analyser - finds why users get a long black screen at sign-in on Azure Virtual Desktop /
    RDS session hosts and Windows 10/11 (multi-session), explains each fix and its impact, and can apply the
    safe fixes with one click (with backup and undo).

.DESCRIPTION
    One self-contained file. Run it (right-click > Run with PowerShell, or from a PowerShell prompt) and the GUI
    starts. Run it as administrator for full results; per-user checks reflect the account that runs it.

    GUI tabs: Findings, Logon timeline, Trends, User reports, Compare hosts, Fleet, Azure, Fix history, Tools.

    Command-line modes:
      -NoGui                          Scan and print the results (read-only). Add -ReportPath / -JsonPath to save them.
      -Gate [-GateLevel Problem|Warning] [-JsonPath f]
                                      Golden image gate: image-related checks only. Exit code 0 = pass, 1 = fail, 2 = error.
      -ComputerName a,b,c [-Credential c] [-ReportPath f]
                                      Fleet scan over PowerShell remoting (WinRM, admin rights on the hosts).
      -SaveBaseline <file> / -CompareBaseline <file>
                                      Snapshot a fast host, then compare a slow host with it.
      -SupportBundle <folder>         Zip with report, event logs, FSLogix logs, gpresult and system information.
      -ExportIntune <folder>          Intune remediation script pairs for the safe machine-level fixes.
      -InstallProbe [-SharePath \\srv\share] [-ReportShortcut] / -UninstallProbe
                                      Logon probe (measures sign-in to taskbar for every logon) and the
                                      "Report slow sign-in" desktop shortcut. Elevated.
      -InstallModules                 Install the missing PowerShell modules for the Azure features from the
                                      PowerShell Gallery (all users when elevated, otherwise current user).

    Scanning only reads the system. Changes are made only by one-click fixes in the GUI (after a confirmation that
    shows what changes and the impact), by -InstallProbe / -UninstallProbe, or by the exported Intune scripts.
    Registry fixes are backed up first and can be undone in the Fix history tab.

    Settings: LogonBlackScreenAnalyser.settings.json next to this script (share path, webhook, workspace, host pool).
    Data: C:\ProgramData\LogonBlackScreenAnalyzer (history, fix log, backups, probe data, reports; config.json there
    is the copy of the share path / webhook used by the probe and report scripts on that host).

    Azure and Microsoft Graph features run in a separate PowerShell window, where you sign in when asked; the
    analyser window stays responsive.
    Known Windows update issues are built in; a KnownIssues.json next to this file overrides them
    (Tools > Settings > Open / create KnownIssues.json).

    Central share for probe data and reports (optional): create subfolders Probe and Reports, give the users of the
    session hosts "Create files / write data" (not Modify) and IT read access. The records contain user names, host
    names and sign-in times. Teams notification for reports: Tools > Settings > Webhook (Teams Workflows URL).

    Azure tab: AVD Insights needs Az.Accounts + Az.OperationalInsights and Log Analytics Reader on the workspace of
    the host pool diagnostics; release health needs Microsoft.Graph.Authentication and WindowsUpdates.ReadWrite.All.

    Windows PowerShell 5.1 is used (the script restarts itself in Windows PowerShell when started from PowerShell 7).

.EXAMPLE
    .\LogonBlackScreenAnalyser.ps1

.EXAMPLE
    .\LogonBlackScreenAnalyser.ps1 -NoGui -ReportPath C:\Temp\blackscreen.html

.EXAMPLE
    .\LogonBlackScreenAnalyser.ps1 -Gate -GateLevel Problem -JsonPath C:\Windows\Temp\image-gate.json
    Azure Image Builder / Packer: run as the last elevated PowerShell step and fail the build when the exit code is not 0.

.EXAMPLE
    .\LogonBlackScreenAnalyser.ps1 -ComputerName avd-0,avd-1,avd-2 -ReportPath C:\Temp\fleet.html

.EXAMPLE
    .\LogonBlackScreenAnalyser.ps1 -InstallProbe -SharePath \\server\LogonData$ -ReportShortcut
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 90)]
    [int]$LookbackDays = 7,
    [switch]$NoGui,
    [string]$ReportPath,
    [string]$JsonPath,
    [switch]$Gate,
    [ValidateSet('Problem', 'Warning')]
    [string]$GateLevel = 'Problem',
    [string[]]$ComputerName,
    [pscredential]$Credential,
    [string]$SaveBaseline,
    [string]$CompareBaseline,
    [string]$SupportBundle,
    [string]$ExportIntune,
    [switch]$InstallProbe,
    [switch]$UninstallProbe,
    [switch]$InstallModules,
    [string]$SharePath,
    [switch]$ReportShortcut,
    [string]$KnownIssuesPath
)

$cliMode = $NoGui -or $Gate -or $ComputerName -or $SaveBaseline -or $CompareBaseline -or $SupportBundle -or $ExportIntune -or $InstallProbe -or $UninstallProbe -or $InstallModules

#region Relaunch in Windows PowerShell 5.1 / STA when needed
$needsRelaunch = ($PSVersionTable.PSEdition -eq 'Core') -or (-not $cliMode -and [System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA')
if ($needsRelaunch) {
    if ($Credential) { Write-Error 'Start the script from Windows PowerShell 5.1 when you use -Credential.'; exit 2 }
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$PSCommandPath`"")
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) { if ($v.IsPresent) { $argList += "-$k" } }
        elseif ($v -is [array]) { $argList += "-$k"; $argList += "`"$($v -join ',')`"" }
        else { $argList += "-$k"; $argList += "`"$v`"" }
    }
    $ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if ($cliMode) { & $ps51 @argList; exit $LASTEXITCODE }
    Start-Process -FilePath $ps51 -ArgumentList $argList
    return
}
#endregion

# ======================================================================================================
# Embedded components. Each block is dot-sourced below and its text is also handed to background jobs,
# remote hosts (fleet scan), generated Intune scripts and the probe installer.
# ======================================================================================================
#region EngineBlock
# Checks engine
$EngineBlock = {
# Engine: host detection, checks, runner, HTML report, scan history. Also sent as text to background jobs,
# remote fleet scans and generated Intune scripts, so it must stay self-contained.
$ToolVersion = '2.0'
if (-not $LookbackDays) { $LookbackDays = 7 }

# ----------------------------------------------------------------------------------------
# Known-issue data. Defaults below; KnownIssues.json (next to the main script) overrides them.
# ----------------------------------------------------------------------------------------
$KnownIssues = @{
    Sep2026Explorer = @{
        Title          = 'Windows 11: explorer.exe fails to start after sign-in (black screen)'
        TriggerKBs     = @('KB5120998', 'KB5124008', 'KB5124010')
        FixKBs         = @()
        FirstAffectedUBR = @{}
        FixedUBR       = @{}
        KirFeatureIds  = @()
        ReleaseDate    = '2026-08-27'
        Reference      = 'Microsoft Windows release health - Windows 11 24H2/25H2/26H1 known issues (KIR available)'
    }
    Sep2026Rds = @{
        Title          = 'Remote Desktop Services hangs at "Connecting" / SessionEnv delay'
        TriggerKBs     = @('KB5123099', 'KB5122876', 'KB5122882', 'KB5122871', 'KB5124008', 'KB5120998')
        FixKBs         = @('KB5129195')
        FixKBRange     = @(5129194, 5129244)
        Reference      = 'Microsoft Windows release health - September 2026 Remote Desktop Services known issue'
    }
    Kb5072911 = @{
        Title          = 'XAML shell packages not registered in time on non-persistent VDI'
        Packages       = @(
            @{ Name = 'MicrosoftWindows.Client.CBS';  Folder = 'MicrosoftWindows.Client.CBS_cw5n1h2txyewy' }
            @{ Name = 'Microsoft.UI.Xaml.CBS';        Folder = 'Microsoft.UI.Xaml.CBS_8wekyb3d8bbwe' }
            @{ Name = 'MicrosoftWindows.Client.Core'; Folder = 'MicrosoftWindows.Client.Core_cw5n1h2txyewy' }
        )
        Reference      = 'https://support.microsoft.com/kb/5072911'
    }
}
$KnownIssuesSource = 'built-in defaults'
$kiText = $null
if ($KnownIssuesJson) { $kiText = $KnownIssuesJson; $KnownIssuesSource = 'supplied JSON' }
elseif ($KnownIssuesPath -and (Test-Path -LiteralPath $KnownIssuesPath)) { $kiText = [System.IO.File]::ReadAllText($KnownIssuesPath); $KnownIssuesSource = $KnownIssuesPath }
if ($kiText) {
    try {
        $kiObj = $kiText | ConvertFrom-Json
        foreach ($p in $kiObj.PSObject.Properties) { if ($p.Name -notlike '_*') { $KnownIssues[$p.Name] = $p.Value } }
    } catch { $KnownIssuesSource = "built-in defaults (KnownIssues.json could not be read: $($_.Exception.Message))" }
}

$BloatAppPatterns = @(
    'Microsoft.Xbox*', 'Microsoft.GamingApp', 'Microsoft.ZuneMusic', 'Microsoft.ZuneVideo',
    'Microsoft.BingNews', 'Microsoft.BingWeather', 'Microsoft.BingSearch', 'Microsoft.MicrosoftSolitaireCollection',
    'Microsoft.People', 'Microsoft.WindowsMaps', 'Microsoft.GetHelp', 'Microsoft.Getstarted',
    'Microsoft.MicrosoftOfficeHub', 'Microsoft.YourPhone', 'Microsoft.WindowsFeedbackHub', 'Clipchamp.Clipchamp',
    'Microsoft.Todos', 'Microsoft.PowerAutomateDesktop', 'Microsoft.549981C3F5F10', 'Microsoft.MixedReality.Portal',
    'Microsoft.SkypeApp', 'Microsoft.Copilot', 'Microsoft.Windows.DevHome', 'MicrosoftCorporationII.MicrosoftFamily',
    'Microsoft.WindowsCommunicationsApps', 'Microsoft.Microsoft3DViewer', 'Microsoft.Wallet', 'Microsoft.OneConnect',
    'Microsoft.MicrosoftStickyNotes', 'Microsoft.WindowsSoundRecorder', 'Microsoft.WindowsAlarms', 'Microsoft.WindowsCamera',
    'MicrosoftCorporationII.QuickAssist', 'Microsoft.OutlookForWindows', 'MicrosoftWindows.CrossDevice', 'Microsoft.Windows.Ai.Copilot.Provider'
)

$script:Checks = New-Object System.Collections.Generic.List[object]

# ----------------------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------------------
function Register-Check {
    param(
        [Parameter(Mandatory)] [string]$Id,
        [Parameter(Mandatory)] [string]$Category,
        [Parameter(Mandatory)] [string]$Name,
        [int]$Weight = 1,
        [scriptblock]$AppliesTo,
        [string]$NotApplicableReason = 'Not relevant for this Windows version / configuration.',
        [string[]]$Tags = @(),
        [Parameter(Mandatory)] [scriptblock]$Test
    )
    $script:Checks.Add([pscustomobject]@{
        Id = $Id; Category = $Category; Name = $Name; Weight = $Weight; Tags = $Tags
        AppliesTo = $AppliesTo; NotApplicableReason = $NotApplicableReason; Test = $Test
    })
}

function New-Result {
    param(
        [ValidateSet('OK', 'Warning', 'Problem', 'Info', 'N/A', 'Error')]
        [string]$Status,
        [string]$Summary,
        [string]$Detail = '',
        [string]$Fix = '',
        [string]$FixCommand = '',
        [string]$Reference = '',
        [string]$Impact = '',
        [hashtable]$AutoFix = $null,
        [hashtable]$Metrics = $null
    )
    [pscustomobject]@{
        Status = $Status; Summary = $Summary; Detail = $Detail; Fix = $Fix; Impact = $Impact
        FixCommand = $FixCommand; Reference = $Reference; AutoFix = $AutoFix; Metrics = $Metrics
    }
}

# One-click fix descriptor. The script that runs is the result's FixCommand.
function New-AutoFix {
    param(
        [Parameter(Mandatory)] [string]$Label,
        [Parameter(Mandatory)] [string]$Changes,
        [switch]$NoAdmin,
        [ValidateSet('', 'Required', 'Recommended')] [string]$Reboot = '',
        [switch]$UserScope,
        [switch]$Backup
    )
    @{ Label = $Label; Changes = $Changes; Admin = (-not $NoAdmin); Reboot = $Reboot; UserScope = [bool]$UserScope; Backup = [bool]$Backup }
}

function Format-Steps   { param([object[]]$Steps) $i = 0; (@($Steps) | Where-Object { $_ } | ForEach-Object { $i++; "$i. $_" }) -join "`r`n" }
function Format-Bullets { param([object[]]$Items) (@($Items) | Where-Object { $_ } | ForEach-Object { "- $_" }) -join "`r`n" }
function Join-Lines {
    # Flattens nested lists (e.g. "@('Header', ($items | ForEach-Object { ... }))") so they print as lines, not "System.Object[]"
    param([object[]]$Lines)
    $flat = New-Object System.Collections.Generic.List[string]
    $stack = New-Object System.Collections.Stack
    for ($i = @($Lines).Count - 1; $i -ge 0; $i--) { $stack.Push(@($Lines)[$i]) }
    while ($stack.Count -gt 0) {
        $item = $stack.Pop()
        if ($null -eq $item) { continue }
        if ($item -is [System.Collections.IEnumerable] -and $item -isnot [string] -and $item -isnot [System.Collections.IDictionary]) {
            $arr = @($item); for ($i = $arr.Count - 1; $i -ge 0; $i--) { $stack.Push($arr[$i]) }
            continue
        }
        if ("$item" -ne '') { $flat.Add([string]$item) }
    }
    $flat -join "`r`n"
}

# PowerShell snippet (as text) that backs up a registry key before a change. Keys that do not exist
# yet get a marker file, so an undo knows to delete the key again.
function New-RegBackupCmd {
    param([string]$Key, [string]$Name)
    $full = $Key -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\' -replace '^HKCU\\', 'HKEY_CURRENT_USER\'
@"
`$bk = Join-Path `$env:ProgramData 'LogonBlackScreenAnalyzer\Backups'
New-Item -ItemType Directory -Force `$bk | Out-Null
`$file = Join-Path `$bk "$Name-`$(Get-Date -Format yyyyMMdd-HHmmss).reg"
if (Test-Path -LiteralPath 'Registry::$full') {
    reg.exe export "$Key" `$file /y | Out-Null
    if (`$LASTEXITCODE -ne 0) { throw 'Registry backup failed - nothing was changed.' }
    "Backup written to `$file"
} else {
    `$file = `$file -replace '\.reg`$', '.absent.txt'
    Set-Content -Path `$file -Value '$full'
    "Backup written to `$file (the key did not exist before)"
}
"@
}

function Get-ToolDataDir {
    foreach ($d in (Join-Path $env:ProgramData 'LogonBlackScreenAnalyzer'), (Join-Path $env:LOCALAPPDATA 'LogonBlackScreenAnalyzer')) {
        try {
            New-Item -ItemType Directory -Force $d -ErrorAction Stop | Out-Null
            $t = Join-Path $d '.write-test'
            [System.IO.File]::WriteAllText($t, 'x'); Remove-Item $t -Force
            return $d
        } catch { }
    }
    $env:TEMP
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function Get-HklmValueCount {
    param([string]$SubKey)
    $k = $null
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKey)
        if ($k) { return $k.ValueCount }
    } catch { } finally { if ($k) { $k.Close() } }
    $null
}

function Get-Events {
    param(
        [Parameter(Mandatory)] [string]$LogName,
        [int[]]$Id,
        [string]$ProviderName,
        [int]$Level,
        [int]$Days = $LookbackDays,
        [int]$Max = 1000
    )
    $f = @{ LogName = $LogName; StartTime = (Get-Date).AddDays(-$Days) }
    if ($Id)           { $f.Id = $Id }
    if ($ProviderName) { $f.ProviderName = $ProviderName }
    if ($Level)        { $f.Level = $Level }
    try { @(Get-WinEvent -FilterHashtable $f -MaxEvents $Max -ErrorAction Stop) } catch { @() }
}

# Event data by name (language independent), falls back to positional P0..Pn
function Get-EventDataMap {
    param($EventRecord)
    $map = [ordered]@{}
    try {
        $x = [xml]$EventRecord.ToXml()
        $i = 0
        foreach ($d in @($x.Event.EventData.Data)) {
            if ($null -eq $d) { continue }
            if ($d -is [string]) { $map["P$i"] = $d }
            else {
                $n = $d.GetAttribute('Name')
                if (-not $n) { $n = "P$i" }
                $map[$n] = $d.InnerText
            }
            $i++
        }
    } catch { }
    if ($map.Count -eq 0) {
        $i = 0
        foreach ($p in $EventRecord.Properties) { $map["P$i"] = [string]$p.Value; $i++ }
    }
    $map
}

function Find-MapValue {
    param($Map, [string[]]$Pattern)
    foreach ($k in $Map.Keys) { foreach ($p in $Pattern) { if ($k -like $p) { return $Map[$k] } } }
    $null
}

function ConvertTo-Version {
    param([string]$Text)
    if (-not $Text) { return $null }
    $parts = @(($Text -replace ',', '.').Split('.') | Where-Object { $_ -match '^\d+$' } | Select-Object -First 4)
    if ($parts.Count -eq 0) { return $null }
    while ($parts.Count -lt 2) { $parts += '0' }
    try { [version]($parts -join '.') } catch { $null }
}

function Get-UninstallEntry {
    param([string[]]$NamePattern)
    $roots = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
             'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    foreach ($r in $roots) {
        foreach ($e in @(Get-ItemProperty $r -ErrorAction SilentlyContinue)) {
            foreach ($p in $NamePattern) { if ($e.DisplayName -like $p) { $e; break } }
        }
    }
}

function Get-FsLogixSetting {
    param([string]$Name)
    $v = Get-RegValue 'HKLM:\SOFTWARE\Policies\FSLogix\Profiles' $Name
    if ($null -eq $v) { $v = Get-RegValue 'HKLM:\SOFTWARE\FSLogix\Profiles' $Name }
    $v
}

# Reads a value from a hashtable or a PSCustomObject (KnownIssues.json) by key
function Get-IssueValue {
    param($Object, $Key)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { return $Object["$Key"] }
    $p = $Object.PSObject.Properties["$Key"]
    if ($p) { $p.Value } else { $null }
}

function Get-OsFamily {
    param([int]$Build, [bool]$IsServer, [string]$Display)
    if ($IsServer) {
        switch ($Build) {
            9200    { 'Windows Server 2012' }
            9600    { 'Windows Server 2012 R2' }
            14393   { 'Windows Server 2016' }
            17763   { 'Windows Server 2019' }
            20348   { 'Windows Server 2022' }
            26100   { 'Windows Server 2025' }
            default { "Windows Server (build $Build)" }
        }
    }
    elseif ($Build -ge 22000) { "Windows 11 $Display" }
    elseif ($Build -ge 10240) { "Windows 10 $Display" }
    elseif ($Build -eq 9600)  { 'Windows 8.1' }
    else                      { "Windows (build $Build)" }
}

function Get-ShellCrashes {
    param([int]$Days = $LookbackDays)
    $shellApps = 'explorer.exe', 'sihost.exe', 'ShellExperienceHost.exe', 'StartMenuExperienceHost.exe',
                 'SearchHost.exe', 'SearchUI.exe', 'SearchApp.exe', 'userinit.exe', 'TextInputHost.exe', 'ctfmon.exe'
    foreach ($e in (Get-Events -LogName 'Application' -Id 1000, 1002 -Days $Days -Max 3000)) {
        if ($e.ProviderName -ne 'Application Error' -and $e.ProviderName -ne 'Application Hang') { continue }
        $app = [string]$e.Properties[0].Value
        if ($shellApps -contains $app) {
            $type = 'Hang'; $module = ''
            if ($e.Id -eq 1000) { $type = 'Crash'; $module = [string]$e.Properties[3].Value }
            [pscustomobject]@{ App = $app.ToLower(); Time = $e.TimeCreated; Type = $type; Module = $module }
        }
    }
}

function Get-KirOverrides {
    foreach ($p in 'HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides',
                   'HKLM:\SOFTWARE\Policies\Microsoft\FeatureManagement\Overrides') {
        if (-not (Test-Path $p)) { continue }
        $item = Get-Item $p
        foreach ($n in $item.GetValueNames()) { "$p : $n = $($item.GetValue($n))" }
        foreach ($sk in @(Get-ChildItem $p -ErrorAction SilentlyContinue)) {
            foreach ($n in $sk.GetValueNames()) { "$p\$($sk.PSChildName) : $n = $($sk.GetValue($n))" }
        }
    }
}

function Test-TcpPort {
    param([string]$HostName, [int]$Port = 445, [int]$TimeoutMs = 1500)
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($HostName, $Port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne($TimeoutMs) -and $c.Connected
        if ($ok) { $c.EndConnect($iar) }
        $ok
    } catch { $false } finally { $c.Close() }
}

# Tests a UNC path without hanging: port 445 first, then Test-Path with a timeout
function Test-UncPath {
    param([string]$Path, [int]$TimeoutMs = 5000)
    $server = ($Path -replace '^\\\\', '').Split('\')[0]
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not (Test-TcpPort -HostName $server -Port 445 -TimeoutMs 1500)) {
        return [pscustomobject]@{ Path = $Path; Server = $server; Reachable = $false; Ms = $sw.ElapsedMilliseconds; Note = "$server does not answer on port 445 (SMB)" }
    }
    $ps = [powershell]::Create()
    [void]$ps.AddScript('param($p) Test-Path -LiteralPath $p').AddArgument($Path)
    $h = $ps.BeginInvoke()
    if ($h.AsyncWaitHandle.WaitOne($TimeoutMs)) {
        $ok = [bool]($ps.EndInvoke($h) | Select-Object -First 1)
        $ps.Dispose()
        $note = 'OK'; if (-not $ok) { $note = 'Path not found or access denied' }
        return [pscustomobject]@{ Path = $Path; Server = $server; Reachable = $ok; Ms = $sw.ElapsedMilliseconds; Note = $note }
    }
    [void]$ps.BeginStop($null, $null)
    [pscustomobject]@{ Path = $Path; Server = $server; Reachable = $false; Ms = $sw.ElapsedMilliseconds; Note = "No answer within $([int]($TimeoutMs / 1000)) s" }
}

function Get-HostEnvironment {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $build = [int]$cv.CurrentBuildNumber
    $ubr = 0; if ($cv.UBR) { $ubr = [int]$cv.UBR }
    $isMulti = ($cv.EditionID -eq 'ServerRdsh')
    # Windows 10/11 multi-session can report a server product type - treat it as client
    $isServer = ($os.ProductType -ne 1) -and -not $isMulti
    $display = $cv.DisplayVersion; if (-not $display) { $display = $cv.ReleaseId }

    $ident = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal $ident).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    $isRdsh = $false
    try {
        $ts = Get-CimInstance -Namespace 'root\cimv2\TerminalServices' -ClassName Win32_TerminalServiceSetting -ErrorAction Stop
        if ($ts.TerminalServerMode -eq 1) { $isRdsh = $true }
    } catch { }

    # Join state
    $dsreg = @{}
    try {
        foreach ($l in @(& dsregcmd.exe /status 2>$null)) { if ($l -match '^\s*([A-Za-z]+)\s*:\s*(.*)$') { $dsreg[$Matches[1]] = $Matches[2].Trim() } }
    } catch { }
    $entra = $dsreg['AzureAdJoined'] -eq 'YES'
    $domainJoined = [bool]$cs.PartOfDomain

    # FSLogix
    $fsVersion = $null
    $fsInstall = Get-RegValue 'HKLM:\SOFTWARE\FSLogix\Apps' 'InstallPath'
    if (-not $fsInstall) { $fsInstall = Join-Path $env:ProgramFiles 'FSLogix\Apps' }
    $frx = Join-Path $fsInstall 'frxsvc.exe'
    if (Test-Path $frx) {
        $vi = (Get-Item $frx).VersionInfo
        $fsVersion = New-Object Version $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart
    }
    $hasFs = [bool]$fsVersion -or [bool](Get-Service frxsvc -ErrorAction SilentlyContinue)
    $fsProfiles = $hasFs -and ((Get-FsLogixSetting 'Enabled') -eq 1)

    # AVD
    $isAvd = [bool](Get-Service RDAgentBootLoader -ErrorAction SilentlyContinue) -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\RDInfraAgent')
    $avdAgent = $null
    if ($isAvd) {
        $a = @(Get-UninstallEntry 'Remote Desktop Services Infrastructure Agent*') | Sort-Object DisplayVersion -Descending | Select-Object -First 1
        if ($a) { $avdAgent = $a.DisplayVersion }
    }

    # Updates
    $hotfixes = @(Get-HotFix -ErrorAction SilentlyContinue)
    $hfIds = @($hotfixes | ForEach-Object { ([string]$_.HotFixID).ToUpper() })
    $latest = $hotfixes | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
    $hfList = @($hotfixes | Where-Object { $_.InstalledOn } | ForEach-Object { [pscustomobject]@{ Id = ([string]$_.HotFixID).ToUpper(); InstalledOn = $_.InstalledOn; Description = $_.Description } })

    # Defender
    $mp = $null
    try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { }

    $roles = @()
    if ($isRdsh)  { $roles += 'RDS Session Host' }
    if ($isMulti) { $roles += 'Multi-session' }
    if ($isAvd)   { $roles += "AVD agent $avdAgent".Trim() }
    if ($hasFs)   { $roles += "FSLogix $fsVersion".Trim() + $(if ($fsProfiles) { ' (profiles on)' } else { ' (profiles off)' }) }
    if ($entra -and $domainJoined) { $roles += 'Hybrid joined' } elseif ($entra) { $roles += 'Entra joined' } elseif ($domainJoined) { $roles += 'Domain joined' }

    [pscustomobject]@{
        ToolVersion      = $ToolVersion
        ComputerName     = $env:COMPUTERNAME
        Caption          = $os.Caption
        Family           = Get-OsFamily -Build $build -IsServer $isServer -Display $display
        DisplayVersion   = $display
        Build            = $build
        UBR              = $ubr
        BuildString      = "$build.$ubr"
        EditionID        = $cv.EditionID
        IsServer         = $isServer
        IsClient         = -not $isServer
        IsMultiSession   = $isMulti
        IsRdsh           = $isRdsh
        IsAvd            = $isAvd
        AvdAgentVersion  = $avdAgent
        DomainJoined     = $domainJoined
        DomainName       = $cs.Domain
        EntraJoined      = $entra
        TenantId         = $dsreg['TenantId']
        HasFSLogix       = $hasFs
        FSLogixVersion   = $fsVersion
        FSLogixPath      = $fsInstall
        FSLogixProfiles  = $fsProfiles
        IsSessionHost    = ($isRdsh -or $isMulti -or $isAvd)
        IsAdmin          = $isAdmin
        UserName         = "$env:USERDOMAIN\$env:USERNAME"
        HotFixIds        = $hfIds
        HotFixList       = $hfList
        LatestHotFix     = $(if ($latest) { $latest.HotFixID } else { $null })
        LatestHotFixDate = $(if ($latest) { $latest.InstalledOn } else { $null })
        LastBoot         = $os.LastBootUpTime
        Defender         = $mp
        Roles            = $(if ($roles) { $roles -join ', ' } else { 'Standalone (no session host role detected)' })
        LookbackDays     = $LookbackDays
        KnownIssuesSource = $KnownIssuesSource
        ScanTime         = Get-Date
    }
}

# Common text
$NoChangeImpact = 'This is a measurement - it changes nothing by itself. The impact depends on which of the steps above you carry out (see the impact described in the related checks).'
$OtherSessionsGuard = @'
$others = @(& { $ErrorActionPreference = 'Continue'; quser.exe 2>$null } | Select-Object -Skip 1 | Where-Object { $_ -and $_ -notmatch '^>' })
if ($others.Count) { throw "There are $($others.Count) other user session(s) on this host. Put the host in drain mode and wait until all users have signed out, then try again." }
'@

# ----------------------------------------------------------------------------------------
# CHECKS
# ----------------------------------------------------------------------------------------

#region Known Windows update issues
Register-Check -Id 'UPD-01' -Category 'Windows update (known issue)' -Weight 3 `
    -Name 'Sep 2026 update: explorer.exe fails to start after sign-in' `
    -AppliesTo { param($E) $E.IsClient -and $E.Build -ge 26100 } `
    -NotApplicableReason 'Only affects Windows 11 24H2 / 25H2 / 26H1 (build 26100+).' `
    -Test {
        param($E)
        $d = $KnownIssues.Sep2026Explorer
        $trigger = @($d.TriggerKBs | Where-Object { $E.HotFixIds -contains $_ })
        $fixed   = @($d.FixKBs | Where-Object { $E.HotFixIds -contains $_ })
        $ubrFrom = Get-IssueValue $d.FirstAffectedUBR $E.Build
        $ubrFix  = Get-IssueValue $d.FixedUBR $E.Build
        if ($ubrFix -and $E.UBR -ge [int]$ubrFix) { $fixed += "build $($E.Build).$ubrFix or later" }
        $byUbr = [bool]($ubrFrom -and $E.UBR -ge [int]$ubrFrom)
        $later = [bool]($E.LatestHotFixDate -and $E.LatestHotFixDate -ge [datetime]$d.ReleaseDate)
        $kirAll = @(Get-KirOverrides)
        $kirIds = @($d.KirFeatureIds | Where-Object { $_ })
        $kirExact = @()
        if ($kirIds) { $kirExact = @($kirAll | Where-Object { $line = $_; @($kirIds | Where-Object { $line -match "\b$_\b" }).Count -gt 0 }) }
        $crashes = @(Get-ShellCrashes | Where-Object { $_.App -eq 'explorer.exe' })

        $fsNote = $null
        if ($E.FSLogixVersion -and $E.FSLogixVersion -ge [version]'2.9.8884.27471') {
            $fsNote = "FSLogix $($E.FSLogixVersion) is 2210 HF4 or later - the combination reported most often with this issue."
        }
        $detail = Join-Lines @(
            "Host build                : $($E.BuildString)"
            "Trigger updates installed : $(if ($trigger) { $trigger -join ', ' } else { 'none of ' + ($d.TriggerKBs -join ', ') })"
            "Affected by build number  : $(if ($ubrFrom) { "$byUbr (affected from UBR $ubrFrom)" } else { 'unknown - no UBR data in KnownIssues.json' })"
            "Newest update             : $($E.LatestHotFix) installed $($E.LatestHotFixDate)"
            "Explorer crashes/hangs    : $($crashes.Count) in the last $LookbackDays days"
            $(if ($crashes) { '  Last: ' + (($crashes | Select-Object -First 5 | ForEach-Object { "$($_.Time) $($_.Type) $($_.Module)" }) -join '; ') })
            "KIR feature IDs to verify : $(if ($kirIds) { $kirIds -join ', ' } else { 'none configured in KnownIssues.json' })"
            "Feature overrides found   : $(if ($kirAll) { "`r`n    " + ($kirAll -join "`r`n    ") } else { 'none' })"
            "Known-issue data          : $($E.KnownIssuesSource)"
            $fsNote
        )
        $fix = Format-Steps @(
            'Open Microsoft Windows release health for your Windows 11 version and download the Known Issue Rollback (KIR) MSI listed for this issue.'
            'Install the MSI where you manage Group Policy (it adds an ADMX template), or import the ADMX into Intune.'
            'Create a GPO / Intune profile for the session hosts and set the KIR policy to "Disabled" (for KIR policies, Disabled means: roll the change back).'
            'Put the session hosts in drain mode and reboot them.'
            'Until the KIR is active, the logon script below can be used as a stop-gap (deploy as a user logon script).'
            'When Microsoft ships the permanent fix, install it, remove the KIR policy and add the KB to FixKBs in KnownIssues.json.'
        )
        $impact = Format-Bullets @(
            'KIR only switches off the single non-security change that causes the crash - all security fixes in the cumulative update stay installed.'
            'The policy needs a reboot of every session host. Users on a host are signed out, so drain hosts first and reboot outside business hours.'
            'Users notice no difference except that the desktop loads normally again.'
            'The KIR policy becomes obsolete once the permanent fix is installed - remove it then (leaving it is harmless).'
            'Interim logon script: checks 15 seconds after logon and starts Explorer if it is missing. If Explorer is just slow (not crashed) the user may get one extra File Explorer window.'
        )
        $cmd = @'
# Interim workaround - deploy as a USER logon script (GPO / Intune), not elevated
Start-Sleep -Seconds 15
$sid = (Get-Process -Id $PID).SessionId
$running = Get-Process explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $sid }
if (-not $running) { Start-Process explorer.exe }
'@
        if ($fixed) { return New-Result OK "Fix installed ($($fixed -join ', '))." $detail -Reference $d.Reference }
        if ($trigger -or $byUbr) {
            if ($kirExact) {
                if ($crashes) { return New-Result Warning 'The KIR policy is active, but explorer.exe is still crashing - the crash may have another cause (see SHL-01).' $detail $fix $cmd $d.Reference -Impact $impact }
                return New-Result OK 'Affected update installed and the KIR policy is active (mitigated).' $detail -Reference $d.Reference
            }
            if ($kirAll -and -not $kirIds) {
                if ($crashes) { return New-Result Warning 'Affected update installed and a feature override exists, but explorer.exe still crashes. Add the KIR feature ID to KnownIssues.json to verify the right rollback is applied.' $detail $fix $cmd $d.Reference -Impact $impact }
                return New-Result Info 'Affected update installed; a feature override policy exists (probably the KIR). Add KirFeatureIds to KnownIssues.json to verify it.' $detail -Reference $d.Reference
            }
            if ($crashes) { return New-Result Problem "Affected update installed and explorer.exe crashed $($crashes.Count) time(s) - this is very likely your black screen." $detail $fix $cmd $d.Reference -Impact $impact }
            return New-Result Warning 'Affected update installed and no KIR policy found. No explorer crashes logged yet.' $detail $fix $cmd $d.Reference -Impact $impact
        }
        if ($later) {
            if ($crashes) { return New-Result Warning "A cumulative update newer than the affected release is installed and explorer.exe crashed $($crashes.Count) time(s) - this may be the Sep 2026 issue. Add the affected UBR to KnownIssues.json to confirm." $detail $fix $cmd $d.Reference -Impact $impact }
            return New-Result Info 'A newer cumulative update is installed, so the KB list cannot confirm or rule out the issue. Add FirstAffectedUBR / FixedUBR to KnownIssues.json for an exact answer.' $detail -Reference $d.Reference
        }
        New-Result OK 'The affected updates are not installed.' $detail -Reference $d.Reference
    }

Register-Check -Id 'UPD-02' -Category 'Windows update (known issue)' -Weight 3 `
    -Name 'Sep 2026 update: RDS hangs at "Connecting" / SessionEnv delay' `
    -AppliesTo { param($E) $E.Build -ge 9600 -and ($E.IsSessionHost -or $E.IsServer) } `
    -NotApplicableReason 'Only relevant for AVD / RDS / multi-session hosts.' `
    -Test {
        param($E)
        $d = $KnownIssues.Sep2026Rds
        $range = @($d.FixKBRange)
        $trigger = @($d.TriggerKBs | Where-Object { $E.HotFixIds -contains $_ })
        $fixed = @($E.HotFixIds | Where-Object {
            ($d.FixKBs -contains $_) -or
            ($range.Count -eq 2 -and $_ -match '^KB(\d+)$' -and [int]$Matches[1] -ge [int]$range[0] -and [int]$Matches[1] -le [int]$range[1])
        })
        $ev20498 = @(Get-Events -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin' -Id 20498) +
                   @(Get-Events -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -Id 20498)
        $ev6005 = @(Get-Events -LogName 'Application' -Id 6005 -ProviderName 'Microsoft-Windows-Winlogon' |
                    Where-Object { $_.Message -match 'SessionEnv' -or ((Get-EventDataMap $_).Values -contains 'SessionEnv') })
        $svc = Get-Service TermService -ErrorAction SilentlyContinue
        $stuck = $svc -and $svc.Status -eq 'StopPending'

        $detail = Join-Lines @(
            "Trigger updates installed       : $(if ($trigger) { $trigger -join ', ' } else { 'none' })"
            "Out-of-band fix installed       : $(if ($fixed) { $fixed -join ', ' } else { 'no' })"
            "Event 20498 (RCM timeout)       : $($ev20498.Count)"
            "Winlogon 6005 for SessionEnv    : $($ev6005.Count)"
            "TermService status              : $(if ($svc) { $svc.Status } else { 'not found' })"
        )
        $fix = Format-Steps @(
            'Get the September 2026 out-of-band update for this Windows version (KB5129194-KB5129244 range, e.g. KB5129195 for Windows 11) from the Microsoft Update Catalog, or install any later cumulative update that contains it.'
            'Put the host in drain mode (AVD: Host pool > Session hosts > Drain mode On) and wait until users have signed out.'
            'Install the update and reboot.'
            'Turn drain mode off and re-run this tool - event 20498 and Winlogon 6005 (SessionEnv) should no longer appear.'
            'If symptoms continue after the fix (reported on some FSLogix hosts), open a Microsoft support case.'
        )
        $impact = Format-Bullets @(
            'Requires a reboot - users still on the host are signed out, so use drain mode.'
            'The out-of-band update is cumulative. Test it on one host or a validation host pool before rolling it out.'
            'No functional change for users - connections stop hanging at "Connecting".'
        )
        $symptoms = ($ev20498.Count + $ev6005.Count) -gt 0 -or $stuck
        if ($symptoms -and -not $fixed) { return New-Result Problem 'RDS connection-hang symptoms found and the out-of-band fix is not installed.' $detail $fix -Reference $d.Reference -Impact $impact }
        if ($symptoms -and $fixed)      { return New-Result Warning 'Out-of-band fix installed, but RDS hang symptoms are still logged.' $detail $fix -Reference $d.Reference -Impact $impact }
        if ($trigger -and -not $fixed)  { return New-Result Warning 'Affected update installed without the out-of-band fix (no symptoms logged yet).' $detail $fix -Reference $d.Reference -Impact $impact }
        New-Result OK 'No signs of the Sep 2026 RDS hang issue.' $detail -Reference $d.Reference
    }

Register-Check -Id 'UPD-03' -Category 'Windows update (known issue)' -Weight 3 `
    -Name 'KB5072911: XAML shell packages not registered at logon (Start/Explorer/Taskbar fail)' `
    -AppliesTo { param($E) $E.Build -ge 26100 -and (Test-Path (Join-Path $env:SystemRoot 'SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy')) } `
    -NotApplicableReason 'Only Windows 11 24H2 / 25H2 (build 26100+) with the XAML CBS packages.' `
    -Test {
        param($E)
        $d = $KnownIssues.Kb5072911
        $lines = @(); $missingMe = @(); $othersBad = 0
        foreach ($p in @($d.Packages)) {
            $mine = @(Get-AppxPackage -Name $p.Name -ErrorAction SilentlyContinue)
            $state = 'registered'
            if (-not $mine) { $state = 'NOT registered'; $missingMe += $p.Name }
            elseif ($mine[0].Status -and "$($mine[0].Status)" -ne 'Ok') { $state = "status $($mine[0].Status)"; $missingMe += $p.Name }
            $lines += "{0,-30} current user: {1}" -f $p.Name, $state
            if ($E.IsAdmin) {
                foreach ($pk in @(Get-AppxPackage -AllUsers -Name $p.Name -ErrorAction SilentlyContinue)) {
                    foreach ($u in @($pk.PackageUserInformation)) {
                        if ("$($u.InstallState)" -ne 'Installed') {
                            $othersBad++
                            $lines += "    $($u.UserSecurityId.Username) : $($u.InstallState)"
                        }
                    }
                }
            }
        }
        $appxErr = @(Get-Events -LogName 'Microsoft-Windows-AppXDeploymentServer/Operational' -Level 2 -Max 2000 |
                     Where-Object { $_.Message -match 'Client\.CBS|UI\.Xaml\.CBS|Client\.Core' })
        $lines += "AppX deployment errors for these packages: $($appxErr.Count) in $LookbackDays days"
        $detail = Join-Lines $lines
        $fix = Format-Steps @(
            'Run the registration INSIDE the affected user session and NOT elevated - it is per user (one-click fix, or the commands below).'
            'If the shell in that session is already broken: restart SiHost (commented command) or sign out and in again.'
            'For pooled / non-persistent hosts: deploy the same commands as a user logon script (GPO: User Configuration > Policies > Windows Settings > Scripts > Logon) and enable "Run logon scripts synchronously" for the hosts so it completes before Explorer starts.'
            'Remove the logon script again once a cumulative update with the permanent fix is installed.'
        )
        $impact = Format-Bullets @(
            'Registering the packages takes a few seconds, needs no reboot and does not affect other users.'
            'As a logon script it adds a few seconds to every logon.'
            'Synchronous logon scripts make Explorer wait for ALL logon scripts - keep other logon scripts fast (see CFG-03).'
            'Restarting SiHost in a live session briefly redraws the taskbar and notifications; open applications keep running.'
        )
        $cmd = @'
# KB5072911 workaround - run in the user's session (not elevated)
$base = Join-Path $env:SystemRoot 'SystemApps'
'MicrosoftWindows.Client.CBS_cw5n1h2txyewy','Microsoft.UI.Xaml.CBS_8wekyb3d8bbwe','MicrosoftWindows.Client.Core_cw5n1h2txyewy' | ForEach-Object {
    Add-AppxPackage -Register -Path (Join-Path $base "$_\appxmanifest.xml") -DisableDevelopmentMode
    "Registered $_"
}
# Only if the shell is already broken in this session:
# Stop-Process -Name sihost -Force
'@
        $auto = New-AutoFix -Label 'Register shell packages for this user' -NoAdmin -UserScope `
            -Changes "Runs Add-AppxPackage -Register for the three XAML shell packages for the account running this tool ($($E.UserName)). Does not restart SiHost and does not touch other users."
        if ($missingMe) { return New-Result Problem "Shell XAML package(s) not registered for $($E.UserName): $($missingMe -join ', ')" $detail $fix $cmd $d.Reference -Impact $impact -AutoFix $auto }
        if ($othersBad -gt 0 -or $appxErr.Count -gt 0) { return New-Result Warning 'Some users have the XAML shell packages in a non-installed state or deployment errors were logged.' $detail $fix $cmd $d.Reference -Impact $impact }
        $note = ''; if (-not $E.IsAdmin) { $note = ' (other users not checked - run elevated)' }
        New-Result OK "XAML shell packages are registered$note." $detail -Reference $d.Reference
    }

Register-Check -Id 'UPD-04' -Category 'Windows update (known issue)' -Weight 1 -Tags 'Image' `
    -Name 'Pending reboot / half-installed update' `
    -Test {
        param($E)
        $cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        $wu  = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        $pfr = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations'
        $detail = Join-Lines @(
            "CBS RebootPending          : $cbs"
            "Windows Update RebootReq.  : $wu"
            "PendingFileRenameOperations: $(@($pfr).Count) entries"
            "Newest update              : $($E.LatestHotFix) ($($E.LatestHotFixDate))"
            "Last boot                  : $($E.LastBoot)"
        )
        $fix = Format-Steps @(
            'Put the host in drain mode so no new sessions land on it.'
            'Notify users and wait until they have signed out.'
            'Reboot the host and confirm the update finished (Settings > Windows Update, or re-run this tool).'
            'Turn drain mode off.'
        )
        $impact = Format-Bullets @(
            'Users still signed in are disconnected and lose unsaved work - drain the host first.'
            'The host is unavailable for roughly 5-15 minutes while the update finishes.'
            'No configuration change - it only completes the update that is already installed.'
        )
        if ($cbs -or $wu) { return New-Result Warning 'A reboot is pending to finish installing updates. Half-installed cumulative updates often break AppX/shell registration at logon.' $detail $fix 'Restart-Computer' -Impact $impact }
        New-Result OK 'No pending update reboot.' $detail
    }
#endregion

#region Logon configuration
Register-Check -Id 'CFG-01' -Category 'Logon configuration' -Weight 2 -Tags 'Image', 'Intune' `
    -Name 'DelayedDesktopSwitchTimeout (logon screen disappears too early)' `
    -Test {
        param($E)
        $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $v = Get-RegValue $key 'DelayedDesktopSwitchTimeout'
        $detail = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DelayedDesktopSwitchTimeout = $(if ($null -eq $v) { '(not set, default 30s)' } else { $v })"
        if ($null -eq $v) { return New-Result OK 'Not set (default). The logon screen stays until Explorer is ready.' $detail }
        if ([int]$v -le 5) {
            $fix = Format-Steps @(
                'Find what sets the value: run "gpresult /h C:\Temp\gp.html" and search for DelayedDesktopSwitchTimeout; also check Intune profiles and image optimisation scripts.'
                'Remove it from that source, otherwise it comes back.'
                'Delete the value on this host (one-click fix). It takes effect at the next logon.'
            )
            $impact = Format-Bullets @(
                'Users see the normal "Welcome" / "Preparing Windows" screen instead of a black screen while logon finishes.'
                'Logon is not faster or slower - the same wait just becomes visible again, which also makes it easier to see what is slow.'
                'No reboot, no functional risk. If a GPO or Intune profile sets the value it is re-applied at the next policy refresh.'
            )
            $cmd = (New-RegBackupCmd -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PoliciesSystem') + "`r`n" +
                   "Remove-ItemProperty -Path '$key' -Name DelayedDesktopSwitchTimeout`r`n'DelayedDesktopSwitchTimeout removed.'"
            $auto = New-AutoFix -Label 'Delete DelayedDesktopSwitchTimeout' -Backup `
                -Changes 'Backs up HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, then deletes the DelayedDesktopSwitchTimeout value.'
            return New-Result Problem "Set to $v second(s): the logon screen is removed before Explorer has drawn the desktop, so the wait shows as a black screen." $detail $fix $cmd -Impact $impact -AutoFix $auto
        }
        New-Result Info "Set to $v seconds." $detail
    }

Register-Check -Id 'CFG-02' -Category 'Logon configuration' -Weight 2 -Tags 'Image' `
    -Name 'Always wait for the network at computer startup and logon' `
    -Test {
        param($E)
        $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $v = Get-RegValue $key 'SyncForegroundPolicy'
        $detail = "SyncForegroundPolicy = $(if ($null -eq $v) { '(not set)' } else { $v })"
        if ($v -eq 1) {
            $fix = Format-Steps @(
                'Run "gpresult /h C:\Temp\gp.html" and find the GPO that sets "Always wait for the network at computer startup and logon" (Computer Configuration > Administrative Templates > System > Logon).'
                'Set it to Not Configured (or Disabled) for the session host OU.'
                'Check first whether anything relies on it: Folder Redirection, GPO Software Installation, or GPP drive maps with the Replace action.'
                'The one-click fix only clears the value on this host (useful to test) - the GPO re-applies it at the next refresh.'
            )
            $impact = Format-Bullets @(
                'The desktop appears without waiting for all foreground Group Policy processing - shorter logon.'
                'Changes to Folder Redirection or GPO software installation can need one extra logon before they apply for a user (Windows switches to synchronous processing for that logon by itself).'
                'GPP drive maps / printers may appear a few seconds after the desktop.'
                'No reboot needed for user logons; computer startup processing changes after the next restart.'
            )
            $cmd = (New-RegBackupCmd -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'WinlogonPolicy') + "`r`n" +
                   "Remove-ItemProperty -Path '$key' -Name SyncForegroundPolicy`r`n'SyncForegroundPolicy removed locally - also change the GPO.'"
            $auto = New-AutoFix -Label 'Clear the setting on this host (test)' -Backup `
                -Changes 'Backs up the Winlogon policy key and deletes SyncForegroundPolicy. A GPO that sets it re-applies it at the next policy refresh.'
            return New-Result Warning 'Enabled: every logon processes Group Policy synchronously before the desktop appears.' $detail $fix $cmd -Impact $impact -AutoFix $auto
        }
        New-Result OK 'Not enforced.' $detail
    }

Register-Check -Id 'CFG-03' -Category 'Logon configuration' -Weight 2 `
    -Name 'Run logon scripts synchronously' `
    -Test {
        param($E)
        $hits = @()
        foreach ($p in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System',
                       'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\System') {
            $v = Get-RegValue $p 'RunLogonScriptSync'
            if ($null -ne $v) { $hits += "$p\RunLogonScriptSync = $v" }
        }
        $detail = Join-Lines $(if ($hits) { $hits } else { 'RunLogonScriptSync not set' })
        if (@($hits | Where-Object { $_ -match '= 1$' })) {
            $fix = Format-Steps @(
                'List the logon scripts that apply (gpresult /h; User Configuration > Scripts and Computer Configuration > Logon scripts).'
                'Make each script fast: remove drive/printer mappings to servers that no longer exist, add timeouts, avoid waiting on network resources.'
                'If no script has to finish before the desktop appears, set "Run logon scripts synchronously" to Not Configured in the GPO.'
                'Keep it enabled if you use the KB5072911 AppX workaround or another script that must finish before Explorer starts.'
            )
            $impact = Format-Bullets @(
                'Disabling it: the desktop appears while scripts are still running, so users may see drive letters / printers appear a few seconds later.'
                'Scripts that customise the shell may finish after Explorer has started and only take effect at the next logon.'
                'Keeping it: every second a logon script runs is added to the black screen.'
                'No reboot; takes effect at the next logon.'
            )
            return New-Result Warning 'Logon scripts run synchronously - Explorer waits for every logon script to finish.' $detail $fix -Impact $impact
        }
        New-Result OK 'Logon scripts run asynchronously.' $detail
    }

Register-Check -Id 'CFG-04' -Category 'Logon configuration' -Weight 1 -Tags 'Image', 'Intune' `
    -Name 'First sign-in animation' `
    -AppliesTo { param($E) $E.Build -ge 9200 } `
    -Test {
        param($E)
        $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $pol = Get-RegValue $key 'EnableFirstLogonAnimation'
        $wl  = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'EnableFirstLogonAnimation'
        $detail = "Policy value: $(if ($null -eq $pol) { '(not set)' } else { $pol }); Winlogon value: $(if ($null -eq $wl) { '(not set)' } else { $wl })"
        if ($pol -eq 0 -or (($null -eq $pol) -and $wl -eq 0)) { return New-Result OK 'Disabled.' $detail }
        $fix = Format-Steps @(
            'Set "Computer Configuration > Administrative Templates > System > Logon > Show first sign-in animation" to Disabled (GPO), or Intune Settings catalog > Windows Logon > Enable First Logon Animation = Disabled.'
            'Or use the one-click fix to set it on this host / in the golden image.'
        )
        $impact = Format-Bullets @(
            'New users see the normal "Welcome" / "Preparing Windows" text instead of the full-screen "Hi / We are getting things ready" animation.'
            'The first-logon work itself (AppX registration, Active Setup) still runs; the animation overhead goes away and the wait is no longer shown as black.'
            'Existing users are not affected. No reboot, no functional risk.'
        )
        $cmd = (New-RegBackupCmd -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PoliciesSystem') + "`r`n" +
               "New-ItemProperty -Path '$key' -Name EnableFirstLogonAnimation -PropertyType DWord -Value 0 -Force | Out-Null`r`n'EnableFirstLogonAnimation set to 0.'"
        $auto = New-AutoFix -Label 'Disable first sign-in animation' -Backup `
            -Changes 'Backs up HKLM\...\Policies\System and sets EnableFirstLogonAnimation = 0 (DWORD).'
        New-Result Warning 'Enabled: new / non-persistent profiles get the "Hi / Getting things ready" animation, which on session hosts is often shown as black.' $detail $fix $cmd -Impact $impact -AutoFix $auto
    }

Register-Check -Id 'CFG-05' -Category 'Logon configuration' -Weight 2 -Tags 'Image' `
    -Name 'Winlogon Userinit / Shell modified' `
    -Test {
        param($E)
        $wlPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $userinit = [string](Get-RegValue $wlPath 'Userinit')
        $shell    = [string](Get-RegValue $wlPath 'Shell')
        $polShell = @((Get-RegValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'Shell'),
                      (Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'Shell')) | Where-Object { $_ }
        $uiParts = @($userinit.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $issues = @()
        if ($uiParts.Count -ne 1 -or $uiParts[0] -notlike '*\userinit.exe') { $issues += "Userinit has extra/non-default entries: $userinit" }
        if ($shell.Trim() -ne 'explorer.exe') { $issues += "Shell is '$shell' (default explorer.exe)" }
        if ($polShell) { $issues += "Custom shell policy: $($polShell -join '; ')" }
        $detail = Join-Lines @("Userinit = $userinit", "Shell    = $shell", $(if ($polShell) { "Policy Shell = $($polShell -join '; ')" }))
        if ($issues) {
            $fix = Format-Steps @(
                'Look at each extra entry in Userinit / Shell (see evidence) and identify the product that added it.'
                'If the product is still used: update it to the current version and check the vendor guidance on logon performance.'
                'If it is a leftover from an uninstalled product: back up the Winlogon key and restore the default value (commands below - deliberately commented out).'
                'Test a logon while you keep an administrator session open, so you can roll back if logon fails.'
            )
            $impact = Format-Bullets @(
                'Removing an entry stops that product from running at logon - its settings and policies are no longer applied for users.'
                'A wrong Userinit value prevents ALL users from signing in (they are signed out immediately). Always back up and test with an admin session open.'
                'Takes effect at the next logon; no reboot.'
                'No one-click fix is offered because a mistake here locks every user out.'
            )
            $cmd = (New-RegBackupCmd -Key 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'Winlogon') + "`r`n" + @'
# Only after confirming the extra entries are leftovers:
# Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Userinit -Value "$env:SystemRoot\system32\userinit.exe,"
# Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Shell -Value 'explorer.exe'
'@
            return New-Result Warning 'Logon chain is modified - everything in Userinit/Shell runs before (or instead of) Explorer.' (Join-Lines @($detail, '', $issues)) $fix $cmd -Impact $impact
        }
        New-Result OK 'Default Userinit and Shell.' $detail
    }

Register-Check -Id 'CFG-06' -Category 'Logon configuration' -Weight 1 -Tags 'Image' `
    -Name 'Machine Run / RunOnce entries' `
    -Test {
        param($E)
        $runOnce = @(); $run = @()
        foreach ($p in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce') {
            if (Test-Path $p) { $k = Get-Item $p; foreach ($n in $k.GetValueNames()) { $runOnce += "$n = $($k.GetValue($n))" } }
        }
        foreach ($p in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') {
            if (Test-Path $p) { $k = Get-Item $p; foreach ($n in $k.GetValueNames()) { $run += "$n = $($k.GetValue($n))" } }
        }
        $teams = @($run | Where-Object { $_ -match 'TeamsMachineInstaller' })
        $detail = Join-Lines @("HKLM RunOnce ($($runOnce.Count)):", ($runOnce | ForEach-Object { "  $_" }), '', "HKLM Run ($($run.Count)):", ($run | ForEach-Object { "  $_" }))
        if ($teams) {
            $fix = Format-Steps @(
                'Provision new Teams for all users first: download teamsbootstrapper.exe from Microsoft and run "teamsbootstrapper.exe -p" in the image or on the host.'
                'Uninstall "Teams Machine-Wide Installer" (one-click fix does this silently).'
                'Per-user classic Teams installs are cleaned up by new Teams / the Microsoft classic Teams removal script.'
                'On AVD, install/update the Teams media optimisation components (WebRTC / SlimCore) for new Teams.'
            )
            $impact = Format-Bullets @(
                'Classic Teams is no longer installed into every new profile - faster first logon and smaller profiles.'
                'Users use new Teams (classic Teams is out of support). The Outlook meeting add-in comes from new Teams.'
                'If new Teams is not provisioned yet, users have no Teams after the uninstall - do step 1 first.'
                'No reboot; users see the change at their next logon.'
            )
            $cmd = @'
$u = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
     Where-Object DisplayName -eq 'Teams Machine-Wide Installer' | Select-Object -First 1
if (-not $u) { 'Teams Machine-Wide Installer is not installed.'; return }
$p = Start-Process msiexec.exe -ArgumentList "/x $($u.PSChildName) /qn /norestart" -Wait -PassThru
if ($p.ExitCode -notin 0, 3010) { throw "msiexec returned exit code $($p.ExitCode)" }
"Teams Machine-Wide Installer removed (exit code $($p.ExitCode))."
'@
            $auto = New-AutoFix -Label 'Uninstall Teams Machine-Wide Installer' `
                -Changes 'Runs msiexec /x <product code> /qn for "Teams Machine-Wide Installer". New Teams and per-user installs are not touched.'
            return New-Result Warning 'Classic "Teams Machine-Wide Installer" runs at every logon and installs Teams per user (very slow on non-persistent profiles).' $detail $fix $cmd -Impact $impact -AutoFix $auto
        }
        if ($runOnce) {
            $fix = Format-Steps @(
                'Review each RunOnce entry in the evidence.'
                'If it belongs to an installer or update that has not finished: sign in once as an administrator (console/RDP) so it completes, or run the command manually elevated.'
                'If it is a leftover: export the RunOnce key and delete the value.'
            )
            $impact = Format-Bullets @(
                'Deleting an entry for an unfinished installation can leave that product half-configured - check what the command does first.'
                'No reboot and no visible change for users.'
            )
            return New-Result Warning "$($runOnce.Count) HKLM RunOnce entr(y/ies) present - they run during logon and are only cleared by an administrator logon, so they can linger." $detail $fix -Impact $impact
        }
        New-Result Info "$($run.Count) HKLM Run entries, no RunOnce entries." $detail `
            'Only if a Run entry is slow (see TIM-04): remove it, or start it delayed through a scheduled task.' `
            -Impact 'Removing a Run entry means the application no longer starts automatically for any user (tray agents, sync clients) - users must start it themselves.'
    }

Register-Check -Id 'CFG-07' -Category 'Logon configuration' -Weight 0 `
    -Name 'Verbose logon status messages (diagnostic aid)' `
    -Test {
        param($E)
        $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $vs = Get-RegValue $p 'VerboseStatus'; $ds = Get-RegValue $p 'DisableStatusMessages'
        $detail = "VerboseStatus = $vs ; DisableStatusMessages = $ds"
        $backup = New-RegBackupCmd -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PoliciesSystem'
        if ($ds -eq 1) {
            $fix = Format-Steps @(
                'Find the GPO "Remove Boot / Shutdown / Logon / Logoff status messages" (Computer > Administrative Templates > System) and set it to Not Configured.'
                'Or remove the value on this host with the one-click fix.'
            )
            $impact = Format-Bullets @(
                'Users see status text during logon instead of a blank (often black) screen - cosmetic only, logon time is unchanged.'
                'No reboot. A GPO that sets it re-applies it at the next refresh.'
            )
            $cmd = $backup + "`r`nRemove-ItemProperty -Path '$p' -Name DisableStatusMessages`r`n'DisableStatusMessages removed.'"
            $auto = New-AutoFix -Label 'Re-enable logon status messages' -Backup -Changes 'Backs up Policies\System and deletes DisableStatusMessages.'
            return New-Result Info 'Status messages are disabled - users see nothing (often black) while logon waits.' $detail $fix $cmd -Impact $impact -AutoFix $auto
        }
        if ($vs -eq 1) { return New-Result OK 'Verbose status is enabled.' $detail }
        $fix = Format-Steps @(
            'Enable "Display highly detailed status messages" (GPO: Computer > Administrative Templates > System) or use the one-click fix.'
            'Reproduce a slow logon and note which step the screen shows while it waits.'
            'Optionally switch it off again when troubleshooting is done.'
        )
        $impact = Format-Bullets @(
            'Users see more technical status text during logon (e.g. "Applying Group Policy...") - no performance impact.'
            'No reboot; can stay on permanently.'
        )
        $cmd = $backup + "`r`nNew-ItemProperty -Path '$p' -Name VerboseStatus -PropertyType DWord -Value 1 -Force | Out-Null`r`n'VerboseStatus enabled.'"
        $auto = New-AutoFix -Label 'Enable verbose logon status' -Backup -Changes 'Backs up Policies\System and sets VerboseStatus = 1 (DWORD).'
        New-Result Info 'Tip: enable verbose status while troubleshooting - the logon screen then shows which step it waits on.' $detail $fix $cmd -Impact $impact -AutoFix $auto
    }

Register-Check -Id 'CFG-08' -Category 'Logon configuration' -Weight 1 `
    -Name 'Non-Microsoft scheduled tasks triggered at logon' `
    -Test {
        param($E)
        $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' -and $_.TaskPath -notlike '\LogonBlackScreenAnalyzer\*' -and
            @($_.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' }).Count -gt 0
        })
        $detail = Join-Lines ($tasks | ForEach-Object { "$($_.TaskPath)$($_.TaskName)  ->  $(@($_.Actions | ForEach-Object { $_.Execute }) -join ', ')" })
        if (-not $tasks) { return New-Result OK 'No non-Microsoft logon-triggered tasks.' 'None' }
        $fix = Format-Steps @(
            'Review the tasks in the evidence.'
            'Disable tasks that are not needed on session hosts, or add a delay to the logon trigger (Task Scheduler > Trigger > Delay task for 1 minute).'
        )
        $impact = Format-Bullets @(
            'Disabling a task stops whatever it does at logon (updates, agents, sync).'
            'Delaying keeps the function but moves the load away from the logon peak.'
            'No reboot.'
        )
        New-Result Info "$($tasks.Count) non-Microsoft logon-triggered task(s) compete with the shell at logon." $detail $fix -Impact $impact
    }

Register-Check -Id 'CFG-09' -Category 'Logon configuration' -Weight 1 `
    -Name 'Third-party credential providers' `
    -Test {
        param($E)
        $third = @()
        foreach ($root in 'Credential Providers', 'Credential Provider Filters') {
            $p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\$root"
            foreach ($k in @(Get-ChildItem $p -ErrorAction SilentlyContinue)) {
                $dll = Get-RegValue "HKLM:\SOFTWARE\Classes\CLSID\$($k.PSChildName)\InprocServer32" '(default)'
                $name = $k.GetValue('')
                if ($dll) {
                    $exp = [Environment]::ExpandEnvironmentVariables($dll)
                    if ($exp -notlike "$env:SystemRoot\*") { $third += "[$root] $name  ->  $exp" }
                }
            }
        }
        if ($third) {
            $fix = Format-Steps @(
                'Update each third-party credential provider to the current version.'
                'Check the vendor known issues for slow logon / black screen.'
                'To measure its effect, test on a separate test host with the provider temporarily disabled.'
            )
            $impact = Format-Bullets @(
                'Updating a credential provider usually requires a reboot.'
                'Disabling one removes that sign-in method (e.g. MFA) - only on a test host and only with agreement from the security team.'
            )
            return New-Result Info "$($third.Count) non-Windows credential provider(s)/filter(s) - they can delay the hand-off from the logon screen to the desktop." (Join-Lines $third) $fix -Impact $impact
        }
        New-Result OK 'Only Windows credential providers.' 'None outside the Windows directory.'
    }
#endregion

#region Measured logon timing
Register-Check -Id 'TIM-01' -Category 'Measured logon timing' -Weight 3 `
    -Name 'Group Policy user logon processing time' `
    -Test {
        param($E)
        $ev = @(Get-Events -LogName 'Microsoft-Windows-GroupPolicy/Operational' -Id 8001 -Max 100)
        $secs = @(foreach ($e in $ev) {
            $m = Get-EventDataMap $e
            $s = Find-MapValue $m '*Elasped*', '*Elapsed*'
            if ($null -eq $s) { $s = $e.Properties[0].Value }
            [pscustomobject]@{ Time = $e.TimeCreated; Seconds = [int]$s; User = (Find-MapValue $m '*SamName*') }
        })
        $cse = @(foreach ($e in (Get-Events -LogName 'Microsoft-Windows-GroupPolicy/Operational' -Id 5016 -Max 2000)) {
            $m = Get-EventDataMap $e
            [pscustomobject]@{ Name = (Find-MapValue $m '*ExtensionName*'); Ms = [int](Find-MapValue $m '*Elasped*', '*Elapsed*') }
        })
        if (-not $secs) { return New-Result Info "No user logon policy events (8001) in the last $LookbackDays days." 'Microsoft-Windows-GroupPolicy/Operational has no event 8001 in the window (no logons, Entra-only joined, or log disabled/too small).' }
        $max = ($secs | Measure-Object Seconds -Maximum).Maximum
        $avg = [math]::Round(($secs | Measure-Object Seconds -Average).Average, 1)
        $topCse = $cse | Where-Object { $_.Name } | Group-Object Name | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; MaxMs = ($_.Group | Measure-Object Ms -Maximum).Maximum; AvgMs = [math]::Round(($_.Group | Measure-Object Ms -Average).Average) }
        } | Sort-Object MaxMs -Descending | Select-Object -First 8
        $detail = Join-Lines @(
            "User logon GP: $($secs.Count) logons, avg $avg s, max $max s"
            ($secs | Sort-Object Seconds -Descending | Select-Object -First 5 | ForEach-Object { "  $($_.Time)  $($_.Seconds)s  $($_.User)" })
            ''
            'Slowest client-side extensions (max / avg ms):'
            ($topCse | ForEach-Object { "  {0,-40} {1,8} / {2,8}" -f $_.Name, $_.MaxMs, $_.AvgMs })
        )
        $fix = Format-Steps @(
            'Use the slowest client-side extensions in the evidence to find the culprit.'
            'Drive Maps / Printers: remove targets that no longer exist, simplify item-level targeting, use the Update action instead of Replace.'
            'Remove or simplify slow WMI filters.'
            'Folder Redirection: consider OneDrive Known Folder Move instead.'
            'Scripts: make them asynchronous and fast (see CFG-03). Check DC latency (NET-03).'
        )
        $impact = Format-Bullets @(
            'GPO changes affect every user / computer in scope - test in a pilot OU first.'
            'Changing how drives or printers are mapped can change drive letters or printer names users are used to.'
            'Removing a WMI filter can widen the scope of a GPO - check the scope before removing it.'
            'Applies at the next logon / gpupdate; no reboot.'
        )
        $metrics = @{ GroupPolicyMaxSec = $max; GroupPolicyAvgSec = $avg }
        if ($max -ge 30) { return New-Result Problem "User Group Policy took up to $max s (avg $avg s)." $detail $fix -Impact $impact -Metrics $metrics }
        if ($max -ge 10) { return New-Result Warning "User Group Policy took up to $max s (avg $avg s)." $detail $fix -Impact $impact -Metrics $metrics }
        New-Result OK "User Group Policy is fast (max $max s, avg $avg s)." $detail -Metrics $metrics
    }

Register-Check -Id 'TIM-02' -Category 'Measured logon timing' -Weight 3 `
    -Name 'Slow Winlogon notification subscribers' `
    -Test {
        param($E)
        $slow = @(foreach ($e in (Get-Events -LogName 'Application' -Id 6006 -ProviderName 'Microsoft-Windows-Winlogon' -Max 500)) {
            $m = Get-EventDataMap $e
            $sub = Find-MapValue $m '*Subscriber*'; $sec = Find-MapValue $m '*Duration*', '*Second*', '*Time*'
            foreach ($v in $m.Values) {
                if (-not $sub -and "$v" -notmatch '^\d+$') { $sub = $v }
                if (-not $sec -and "$v" -match '^\d+$') { $sec = $v }
            }
            [pscustomobject]@{ Time = $e.TimeCreated; Subscriber = $sub; Seconds = [int]$sec }
        })
        $long = @(foreach ($e in (Get-Events -LogName 'Application' -Id 6005 -ProviderName 'Microsoft-Windows-Winlogon' -Max 500)) {
            $m = Get-EventDataMap $e
            $sub = Find-MapValue $m '*Subscriber*'
            if (-not $sub) { $sub = @($m.Values)[0] }
            $sub
        })
        # Winlogon/Operational 811 (start) / 812 (end). Paired per logon by ActivityId so that concurrent
        # logons on multi-session hosts do not get mixed up; falls back to the last open start.
        $byAct = @{}; $byPlain = @{}; $dur = @()
        foreach ($e in (Get-Events -LogName 'Microsoft-Windows-Winlogon/Operational' -Id 811, 812 -Max 5000 | Sort-Object TimeCreated)) {
            $m = Get-EventDataMap $e
            $sub = Find-MapValue $m '*Subscriber*'; $evt = Find-MapValue $m 'Event'
            if (-not $sub) { continue }
            $plain = "$sub|$evt"; $act = "$plain|$($e.ActivityId)"
            if ($e.Id -eq 811) {
                if ($e.ActivityId) { $byAct[$act] = $e.TimeCreated }
                $byPlain[$plain] = $e.TimeCreated
                continue
            }
            $start = $null
            if ($e.ActivityId -and $byAct.ContainsKey($act)) { $start = $byAct[$act]; $byAct.Remove($act) }
            elseif ($byPlain.ContainsKey($plain)) { $start = $byPlain[$plain] }
            if ($start) {
                $dur += [pscustomobject]@{ Subscriber = $sub; Event = $evt; Seconds = [math]::Round(($e.TimeCreated - $start).TotalSeconds, 1) }
                $byPlain.Remove($plain)
            }
        }
        $topDur = $dur | Group-Object Subscriber | ForEach-Object {
            $w = $_.Group | Sort-Object Seconds -Descending | Select-Object -First 1
            [pscustomobject]@{ Subscriber = $_.Name; Max = $w.Seconds; Event = $w.Event }
        } | Sort-Object Max -Descending | Select-Object -First 8
        # Subscribers that work when the host restarts / shuts down (servicing), not during a user sign-in
        $notLogon = @('TrustedInstaller')
        $meaning = @{
            'Profiles' = 'User Profile Service / FSLogix container attach'; 'GPClient' = 'Group Policy'
            'SessionEnv' = 'RDS session environment (see Sep 2026 RDS issue)'; 'TermSrv' = 'Remote Desktop Services'
            'Sens' = 'System Event Notification'; 'TrustedInstaller' = 'Servicing / updates'; 'Dhcp' = 'Network'
            'CscService' = 'Offline Files'; 'Wlansvc' = 'WLAN'; 'SessionEnvironment' = 'RDS session environment'
        }
        $explain = { param($s) if ($meaning.ContainsKey("$s")) { " ($($meaning["$s"]))" } else { '' } }
        $detail = Join-Lines @(
            "Event 6006 (subscriber took long): $($slow.Count)"
            ($slow | Sort-Object Seconds -Descending | Select-Object -First 8 | ForEach-Object { "  $($_.Time)  $($_.Subscriber)$(& $explain $_.Subscriber): $($_.Seconds)s" })
            "Event 6005 (subscriber is taking long): $($long.Count)  $(($long | Group-Object | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', ')"
            ''
            'Slowest subscribers from Winlogon/Operational (811/812):'
            ($topDur | ForEach-Object { "  {0,-22} max {1}s (event {2}){3}{4}" -f $_.Subscriber, $_.Max, $_.Event, (& $explain $_.Subscriber), $(if ($notLogon -contains $_.Subscriber) { ' - not counted: works at restart / shutdown after updates, not during sign-in' } else { '' }) })
        )
        $logonSlow = @($slow | Where-Object { $notLogon -notcontains $_.Subscriber })
        $logonLong = @($long | Where-Object { $notLogon -notcontains $_ })
        $logonDur = @($topDur | Where-Object { $notLogon -notcontains $_.Subscriber })
        $worst = $logonSlow | Sort-Object Seconds -Descending | Select-Object -First 1
        $worstOp = $logonDur | Select-Object -First 1
        $fix = Format-Steps @(
            'Read the slowest subscriber in the evidence - it tells you which logon phase blocks the desktop.'
            'Profiles = profile load: see TIM-03, PRF-01, PRF-02, PRF-04.'
            'GPClient = Group Policy: see TIM-01, CFG-02, CFG-03, NET-03.'
            'SessionEnv / TermSrv = Remote Desktop Services: see UPD-02.'
            'Use the Logon timeline tab for a per-logon breakdown.'
        )
        if (($worst -and $worst.Seconds -ge 30) -or ($worstOp -and $worstOp.Max -ge 30)) {
            $n = if ($worst) { "$($worst.Subscriber) $($worst.Seconds)s" } else { "$($worstOp.Subscriber) $($worstOp.Max)s" }
            return New-Result Problem "Winlogon waited a long time on a subscriber during sign-in (worst: $n)." $detail $fix -Impact $NoChangeImpact
        }
        if ($logonSlow -or $logonLong -or ($worstOp -and $worstOp.Max -ge 10)) { return New-Result Warning 'Some Winlogon subscribers are slow during sign-in.' $detail $fix -Impact $NoChangeImpact }
        if (-not $dur) { return New-Result Info 'No Winlogon timing events found in the window.' $detail }
        $fastest = if ($worstOp) { "slowest sign-in step: $($worstOp.Subscriber) $($worstOp.Max) s" } else { 'no slow sign-in steps' }
        New-Result OK "Winlogon finishes quickly ($fastest). If users still wait, the time is spent after the hand-over to the desktop - first sign-in screens (ENT-03, ENT-01, ENT-02), shell start and Run keys (TIM-04); see the Logon timeline." $detail
    }

Register-Check -Id 'TIM-03' -Category 'Measured logon timing' -Weight 3 `
    -Name 'User profile load time (User Profile Service, incl. FSLogix attach)' `
    -Test {
        param($E)
        $ev = @(Get-Events -LogName 'Microsoft-Windows-User Profile Service/Operational' -Id 1, 2 -Max 3000 | Sort-Object TimeCreated)
        # Paired per user SID + session so concurrent logons are not mixed up
        $open = @{}; $durations = @()
        foreach ($e in $ev) {
            $m = Get-EventDataMap $e
            $sess = Find-MapValue $m '*Session*'
            $sid = ''; if ($e.UserId) { $sid = $e.UserId.Value }
            $key = "$sid|$sess"
            if ($e.Id -eq 1) { $open[$key] = $e.TimeCreated }
            elseif ($open.ContainsKey($key)) {
                $durations += [pscustomobject]@{ Time = $open[$key]; Seconds = [math]::Round(($e.TimeCreated - $open[$key]).TotalSeconds, 1) }
                $open.Remove($key)
            }
        }
        if (-not $durations) { return New-Result Info "No profile load events in the last $LookbackDays days." 'User Profile Service/Operational events 1/2 not found.' }
        $max = ($durations | Measure-Object Seconds -Maximum).Maximum
        $avg = [math]::Round(($durations | Measure-Object Seconds -Average).Average, 1)
        $detail = Join-Lines @("$($durations.Count) logons, avg $avg s, max $max s", ($durations | Sort-Object Seconds -Descending | Select-Object -First 8 | ForEach-Object { "  $($_.Time)  $($_.Seconds)s" }))
        $fix = Format-Steps @(
            'Check FSLogix load time and errors (PRF-01) and the antivirus exclusions (PRF-02).'
            'Check storage latency for the profile share (Azure Files: Premium tier, same region as the hosts, check throttling metrics).'
            'Keep containers small: FSLogix compaction, exclude caches/temp via redirections.xml.'
            'Remove stale local profiles (PRF-04).'
        )
        $impact = Format-Bullets @(
            'A faster storage tier costs more but needs no user downtime; moving containers to new storage requires users to be signed out.'
            'Antivirus exclusions stop scanning of the container files (contents are still scanned when opened).'
            'Redirecting caches out of the container means users lose those caches at every logon - slightly slower first start of some apps.'
        )
        $metrics = @{ ProfileLoadMaxSec = $max; ProfileLoadAvgSec = $avg }
        if ($max -ge 30) { return New-Result Problem "Profile load took up to $max s (avg $avg s)." $detail $fix -Impact $impact -Metrics $metrics }
        if ($max -ge 10) { return New-Result Warning "Profile load took up to $max s (avg $avg s)." $detail $fix -Impact $impact -Metrics $metrics }
        New-Result OK "Profile load is fast (max $max s, avg $avg s)." $detail -Metrics $metrics
    }

Register-Check -Id 'TIM-04' -Category 'Measured logon timing' -Weight 1 `
    -Name 'Run-key processing by the shell' `
    -AppliesTo { param($E) $E.Build -ge 9600 } `
    -Test {
        param($E)
        $ev = @(Get-Events -LogName 'Microsoft-Windows-Shell-Core/Operational' -Id 9707, 9708 -Max 5000 | Sort-Object TimeCreated)
        $open = @{}; $cmds = @()
        foreach ($e in $ev) {
            $m = Get-EventDataMap $e
            $c = Find-MapValue $m '*Command*'
            if (-not $c) { $c = @($m.Values)[0] }
            $sid = ''; if ($e.UserId) { $sid = $e.UserId.Value }
            $key = "$sid|$c"
            if ($e.Id -eq 9707) { $open[$key] = $e.TimeCreated }
            elseif ($open.ContainsKey($key)) { $cmds += [pscustomobject]@{ Command = $c; Seconds = [math]::Round(($e.TimeCreated - $open[$key]).TotalSeconds, 1) }; $open.Remove($key) }
        }
        if (-not $cmds) { return New-Result Info 'No Run-key timing events found.' 'Shell-Core/Operational 9707/9708 not present in the window.' }
        $all = @($cmds | Group-Object Command | ForEach-Object { [pscustomobject]@{ Command = $_.Name; Max = ($_.Group | Measure-Object Seconds -Maximum).Maximum; Runs = $_.Count } } | Sort-Object Max -Descending)
        # Explorer stops tracking a started program after about 30 s, so ~30 s just means "still running" (tray apps)
        $isCapped = { param($s) $s -ge 29.5 -and $s -le 32 }
        $slow = @($all | Where-Object { $_.Max -gt 45 })
        $edgeCleanup = @($all | Where-Object { $_.Command -match 'delete-old-versions' })
        $detail = Join-Lines @(
            "$($all.Count) different program(s) are started from the Run keys at logon (every user starts them on a multi-session host)."
            ''
            ($all | Select-Object -First 15 | ForEach-Object {
                $note = ''
                if ($_.Command -match 'delete-old-versions') { $note = '   <- Edge/WebView2 update cleanup' }
                elseif (& $isCapped $_.Max) { $note = '   (still running at the ~30 s tracking limit - normal for apps that stay open)' }
                elseif ($_.Max -gt 45) { $note = '   <- slow' }
                "  {0,6}s  {1}  [{2} logon(s)]{3}" -f $_.Max, $_.Command, $_.Runs, $note
            })
        )
        $fix = Format-Steps @(
            $(if ($edgeCleanup) { 'Edge / WebView2 "setup.exe ... --delete-old-versions ... --on-logon" is an update cleanup that runs when old versions were still in use. Reboot the host after Edge / WebView2 updates so it can finish. If it keeps appearing, find it with the command below, run it once elevated or remove the stale entry, and keep WebView2 current in the golden image.' })
            'Remove Run entries for programs users do not need on the session hosts (vendor helpers, licence or sync agents), or start them later through a scheduled task with a delay.'
            'Entries at about 30 s are programs that keep running (tray apps) - remove them only if they are not needed.'
        )
        $impact = Format-Bullets @(
            'Removing a Run entry: that program no longer starts automatically for any user - users start it themselves if they need it.'
            $(if ($edgeCleanup) { 'Letting the WebView2 cleanup finish (reboot or one elevated run) only removes old WebView2 versions - no user-visible change. Drain the host before a reboot.' })
            'Changing Run entries needs no reboot; it applies from the next logon.'
        )
        $cmd = @'
# Lists all Run / RunOnce entries (read-only)
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
               'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
               'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce') {
    $i = Get-Item $k -ErrorAction SilentlyContinue
    if ($i) { foreach ($n in $i.GetValueNames()) { "$k  ->  $n = $($i.GetValue($n))" } }
}
'@
        $metrics = @{ RunKeyPrograms = $all.Count; RunKeySlowestSec = ($all | Select-Object -First 1).Max }
        if ($edgeCleanup) { return New-Result Warning "The Edge / WebView2 update cleanup runs at logon and took up to $(($edgeCleanup | Select-Object -First 1).Max) s - it competes with the logon and can repeat at every sign-in until it completes." $detail $fix $cmd -Impact $impact -Metrics $metrics }
        if ($slow) { return New-Result Warning "$($slow.Count) Run-key program(s) take longer than 45 s at logon (they compete with the shell)." $detail $fix $cmd -Impact $impact -Metrics $metrics }
        New-Result Info "$($all.Count) program(s) start from the Run keys at logon; none is unusually slow (about 30 s means the program keeps running, which is normal)." $detail $fix $cmd -Impact $impact -Metrics $metrics
    }
#endregion

#region Firewall
Register-Check -Id 'FW-01' -Category 'Windows Firewall' -Weight 3 -Tags 'Image', 'Intune' `
    -Name 'DeleteUserAppContainersOnLogoff (firewall rule growth)' `
    -AppliesTo { param($E) $E.Build -ge 14393 -and ($E.IsSessionHost -or $E.IsServer) } `
    -NotApplicableReason 'Only relevant for Windows Server 2016+ / Windows 10/11 multi-session hosts.' `
    -Test {
        param($E)
        $fw = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
        $v = Get-RegValue $fw 'DeleteUserAppContainersOnLogoff'
        $detail = "$fw\DeleteUserAppContainersOnLogoff = $(if ($null -eq $v) { '(not set)' } else { $v })"
        if ($v -eq 1) { return New-Result OK 'Enabled - per-user AppContainer firewall rules are removed at logoff.' $detail }
        $fix = Format-Steps @(
            'Set DeleteUserAppContainersOnLogoff = 1 - one-click fix on this host, and for all hosts via the golden image, a GPO Preferences registry item or Intune.'
            'Windows Server 2016 needs the November 2018 cumulative update or later for the setting to work.'
            'Purge the rules that have already accumulated (FW-02).'
            'Reboot when convenient so the firewall service picks up the setting.'
        )
        $impact = Format-Bullets @(
            'Per-user app firewall rules are deleted when a user signs out and recreated automatically at the next logon - no functional change for users.'
            'Very low risk; this is a supported Microsoft setting.'
            'It does not remove rules that already exist - use FW-02 for that.'
            'A reboot is recommended; until then it may only partly take effect.'
        )
        $cmd = (New-RegBackupCmd -Key 'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy' -Name 'FirewallPolicy') + "`r`n" +
               "New-ItemProperty -Path '$fw' -Name DeleteUserAppContainersOnLogoff -PropertyType DWord -Value 1 -Force | Out-Null`r`n'DeleteUserAppContainersOnLogoff set to 1.'"
        $auto = New-AutoFix -Label 'Enable DeleteUserAppContainersOnLogoff' -Backup -Reboot Recommended `
            -Changes 'Backs up the FirewallPolicy registry key and sets DeleteUserAppContainersOnLogoff = 1 (DWORD).'
        New-Result Problem 'Not enabled: every logon adds per-user firewall rules that are never removed. Logons get slower week by week until the rules are purged.' $detail $fix $cmd -Impact $impact -AutoFix $auto
    }

Register-Check -Id 'FW-02' -Category 'Windows Firewall' -Weight 3 `
    -Name 'Firewall rule bloat' `
    -AppliesTo { param($E) $E.Build -ge 14393 } `
    -NotApplicableReason 'Firewall AppContainer rule bloat applies to Windows Server 2016 / Windows 10 and later.' `
    -Test {
        param($E)
        $base = 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
        $main   = Get-HklmValueCount "$base\FirewallRules"
        $appIso = Get-HklmValueCount "$base\RestrictedServices\AppIso\FirewallRules"
        $conf   = Get-HklmValueCount "$base\RestrictedServices\Configurable\System"
        $userOwned = 0
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$base\FirewallRules")
        if ($k) { try { foreach ($n in $k.GetValueNames()) { if ([string]$k.GetValue($n) -match 'LUOwn=S-1-(5-21|12-1)-') { $userOwned++ } } } finally { $k.Close() } }
        $total = [int]$main + [int]$appIso + [int]$conf
        $detail = Join-Lines @(
            "FirewallRules                          : $main  (user-owned: $userOwned)"
            "RestrictedServices\AppIso\FirewallRules: $appIso"
            "RestrictedServices\Configurable\System : $conf"
            "Total                                  : $total"
            "Host uptime                            : $([math]::Round(((Get-Date) - $E.LastBoot).TotalDays, 1)) days"
        )
        if ($null -eq $main) { return New-Result Info 'Could not read the firewall rule store.' $detail }
        $metrics = @{ FirewallRules = $total; FirewallUserRules = $userOwned }
        $fix = Format-Steps @(
            'Fix FW-01 first, otherwise the rules grow back.'
            'Put the host in drain mode and wait until NO other users are signed in (the one-click fix refuses to run while other sessions exist).'
            'Apply the fix - it backs up the registry key first, then removes the per-user rules.'
            'Reboot the host and re-run this tool to confirm the rule count dropped.'
            'Repeat on every session host, or rebuild the hosts from an image that has FW-01 set.'
        )
        $impact = Format-Bullets @(
            'Per-user app firewall rules (Store apps, Teams etc.) are removed and recreated automatically when each user signs in again - users do not need to do anything.'
            'Firewall rules a user created themselves (rare on session hosts) are removed as well.'
            'With tens of thousands of rules the cleanup can take several minutes; no user may be signed in meanwhile.'
            'A reboot is required afterwards so the firewall service reloads its rules.'
            'Can be undone from the Fix history tab (restores the registry backup; reboot again afterwards).'
        )
        $cmd = "# Run elevated with no other users signed in. Reboot afterwards.`r`n" + $OtherSessionsGuard + "`r`n" +
               (New-RegBackupCmd -Key 'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy' -Name 'FirewallPolicy') + "`r`n" + @'
$fwKey = 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
New-ItemProperty -Path "HKLM:\$fwKey" -Name DeleteUserAppContainersOnLogoff -PropertyType DWord -Value 1 -Force | Out-Null
# Per-user AppContainer rules (recreated for each user at the next logon)
$appIso = "HKLM:\$fwKey\RestrictedServices\AppIso\FirewallRules"
if (Test-Path $appIso) {
    $n = (Get-Item $appIso).ValueCount
    Remove-Item $appIso -Force; New-Item $appIso -Force | Out-Null
    "AppIso\FirewallRules: removed $n"
}
# User-owned rules in the main store and Configurable\System
foreach ($sub in 'FirewallRules', 'RestrictedServices\Configurable\System') {
    $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$fwKey\$sub", $true)
    if (-not $k) { continue }
    $removed = 0
    foreach ($n in $k.GetValueNames()) { if ([string]$k.GetValue($n) -match 'LUOwn=S-1-(5-21|12-1)-') { $k.DeleteValue($n); $removed++ } }
    $k.Close(); "$sub : removed $removed"
}
'Done - reboot the host now.'
'@
        $auto = New-AutoFix -Label 'Purge per-user firewall rules' -Backup -Reboot Required `
            -Changes 'Checks that no other users are signed in, backs up the FirewallPolicy key, enables DeleteUserAppContainersOnLogoff, empties AppIso\FirewallRules and deletes user-owned (LUOwn = an AD or Entra ID user SID) rules. Does not reboot.'
        if ($total -ge 20000 -or $userOwned -ge 5000) { return New-Result Problem "$total firewall rules ($userOwned user-owned) - firewall rule bloat is a well-known cause of long black screens." $detail $fix $cmd -Impact $impact -AutoFix $auto -Metrics $metrics }
        if ($total -ge 5000 -or $userOwned -ge 1000) { return New-Result Warning "$total firewall rules ($userOwned user-owned) - growing; will slow logons over time." $detail $fix $cmd -Impact $impact -AutoFix $auto -Metrics $metrics }
        New-Result OK "$total firewall rules - normal." $detail -Metrics $metrics
    }
#endregion

#region AppX / Active Setup
Register-Check -Id 'APX-01' -Category 'AppX / Active Setup' -Weight 2 -Tags 'Image' `
    -Name 'Provisioned (inbox) apps registered at first logon' `
    -AppliesTo { param($E) $E.Build -ge 14393 } `
    -NotApplicableReason 'Per-user provisioned AppX registration matters on Windows Server 2016 / Windows 10 and later.' `
    -Test {
        param($E)
        if (-not $E.IsAdmin) { return New-Result Info 'Requires elevation (Get-AppxProvisionedPackage).' 'Run the analyser as administrator.' }
        $prov = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue)
        $bloat = @($prov | Where-Object { $n = $_.DisplayName; @($BloatAppPatterns | Where-Object { $n -like $_ }).Count -gt 0 })
        $detail = Join-Lines @("Provisioned packages: $($prov.Count)", "Removable consumer apps ($($bloat.Count)):", ($bloat | ForEach-Object { "  $($_.DisplayName)" }), '', 'All:', ($prov | Sort-Object DisplayName | ForEach-Object { "  $($_.DisplayName)" }))
        $metrics = @{ ProvisionedApps = $prov.Count; RemovableApps = $bloat.Count }
        if ($bloat.Count -lt 3) { return New-Result OK "$($prov.Count) provisioned apps, $($bloat.Count) removable consumer apps." $detail -Metrics $metrics }
        $names = @($bloat | ForEach-Object { $_.DisplayName })
        $cmd = "# Removes the provisioned copies (new profiles will not get them). Edit the list first if users need some of these apps.`r`n" +
               '$remove = @(' + (($names | ForEach-Object { "'$_'" }) -join ', ') + ")`r`n" +
               'Get-AppxProvisionedPackage -Online | Where-Object { $remove -contains $_.DisplayName } | ForEach-Object {' + "`r`n" +
               '    Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName | Out-Null' + "`r`n" +
               '    "Removed $($_.DisplayName)"' + "`r`n" + '}'
        $fix = Format-Steps @(
            'Review the list of removable apps in the evidence - keep apps your users actually use.'
            'Best: remove them in the golden image and redeploy the session hosts.'
            'Or use the one-click fix to remove the provisioned copies on this host.'
            'Optional: also remove copies already installed for existing users (Remove-AppxPackage -AllUsers).'
        )
        $impact = Format-Bullets @(
            'New user profiles no longer get these apps, so their first logon is faster.'
            'Users who already have the apps keep them until they are removed for them.'
            'If someone needs one of the apps later it must be installed from the Store / Company Portal (which may be blocked on session hosts).'
            'Monthly cumulative updates do not bring removed apps back; a Windows feature upgrade can.'
            'No reboot. Cannot be undone by this tool (the apps would have to be re-provisioned).'
        )
        $auto = New-AutoFix -Label "Remove $($names.Count) provisioned consumer apps" -Changes "Runs Remove-AppxProvisionedPackage for: $($names -join ', ')."
        $maybeNonPersistent = $E.IsSessionHost -and -not $E.FSLogixProfiles
        if ($bloat.Count -ge 5 -and $maybeNonPersistent) { return New-Result Problem "$($bloat.Count) removable consumer apps are provisioned on a session host without FSLogix profiles - with non-persistent profiles they register at every logon." $detail $fix $cmd -Impact $impact -AutoFix $auto -Metrics $metrics }
        New-Result Warning "$($bloat.Count) removable consumer apps are provisioned." $detail $fix $cmd -Impact $impact -AutoFix $auto -Metrics $metrics
    }

Register-Check -Id 'APX-02' -Category 'AppX / Active Setup' -Weight 2 `
    -Name 'AppX deployment / AppReadiness errors' `
    -AppliesTo { param($E) $E.Build -ge 9600 } `
    -Test {
        param($E)
        $appx = @(Get-Events -LogName 'Microsoft-Windows-AppXDeploymentServer/Operational' -Level 2 -Max 3000)
        $ready = @(Get-Events -LogName 'Microsoft-Windows-AppReadiness/Admin' -Level 2 -Max 1000)
        $top = $appx + $ready | Group-Object { ($_.Message -split "`n")[0].Trim() -replace '\{[0-9A-Fa-f-]{36}\}', '{guid}' -replace 'S-1-(5-21|12-1)[-\d]+', '<user SID>' } |
               Sort-Object Count -Descending | Select-Object -First 8
        $detail = Join-Lines @("AppXDeploymentServer errors: $($appx.Count)", "AppReadiness errors: $($ready.Count)", '', 'Most frequent:', ($top | ForEach-Object { "  [$($_.Count)x] " + $(if ($_.Name.Length -gt 220) { $_.Name.Substring(0, 220) + '...' } else { $_.Name }) }))
        $fix = Format-Steps @(
            'Look at the most frequent errors in the evidence and note the package names.'
            'If a provisioned app keeps failing: remove it (APX-01).'
            'Clean orphaned user registrations (APX-04) and keep the StateRepository healthy (APX-03).'
            'Install the latest cumulative update; on Windows 11 24H2+ also see UPD-03.'
        )
        $n = $appx.Count + $ready.Count
        $metrics = @{ AppxErrors = $n }
        if ($n -ge 200) { return New-Result Problem "$n AppX/AppReadiness errors in $LookbackDays days." $detail $fix -Impact $NoChangeImpact -Metrics $metrics }
        if ($n -ge 20)  { return New-Result Warning "$n AppX/AppReadiness errors in $LookbackDays days." $detail $fix -Impact $NoChangeImpact -Metrics $metrics }
        New-Result OK "$n AppX/AppReadiness errors in $LookbackDays days." $detail -Metrics $metrics
    }

Register-Check -Id 'APX-03' -Category 'AppX / Active Setup' -Weight 2 `
    -Name 'AppX StateRepository database size' `
    -AppliesTo { param($E) $E.Build -ge 14393 } `
    -Test {
        param($E)
        $dir = Join-Path $env:ProgramData 'Microsoft\Windows\AppRepository'
        $files = @(Get-ChildItem $dir -Filter 'StateRepository-Machine*' -File -ErrorAction SilentlyContinue)
        $mb = [math]::Round((($files | Measure-Object Length -Sum).Sum) / 1MB)
        $detail = Join-Lines ($files | ForEach-Object { "{0,-45} {1,8:N0} MB" -f $_.Name, ($_.Length / 1MB) })
        if (-not $files) { return New-Result Info 'StateRepository not found / not accessible.' 'Run elevated.' }
        $fix = Format-Steps @(
            'Clean orphaned AppX user registrations (APX-04) and stale local profiles (PRF-04).'
            'Install the latest cumulative update.'
            'If the database stays very large, replace the session host with a fresh one from the image.'
            'Do NOT delete or edit the StateRepository files manually - that breaks all AppX apps on the host.'
        )
        $impact = Format-Bullets @(
            'Steps 1-2 have no impact on current users.'
            'Replacing the host: the VM is deleted and recreated - anything stored only locally on it is lost; FSLogix profiles are not affected. Use drain mode for the swap.'
        )
        $metrics = @{ StateRepositoryMB = $mb }
        if ($mb -ge 1024) { return New-Result Problem "StateRepository is $mb MB - every AppX operation at logon gets slower." $detail $fix -Impact $impact -Metrics $metrics }
        if ($mb -ge 300)  { return New-Result Warning "StateRepository is $mb MB." $detail $fix -Impact $impact -Metrics $metrics }
        New-Result OK "StateRepository is $mb MB." $detail -Metrics $metrics
    }

Register-Check -Id 'APX-04' -Category 'AppX / Active Setup' -Weight 2 -Tags 'Intune' `
    -Name 'Orphaned users in AppxAllUserStore' `
    -AppliesTo { param($E) $E.Build -ge 14393 } `
    -Test {
        param($E)
        $store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
        $profiles = @((Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue).PSChildName)
        $sids = @((Get-ChildItem $store -ErrorAction SilentlyContinue).PSChildName | Where-Object { $_ -match '^S-1-(5-21|12-1)-' })
        $orphans = @($sids | Where-Object { $profiles -notcontains $_ })
        $detail = "User SIDs in AppxAllUserStore: $($sids.Count); without a local profile: $($orphans.Count)"
        $metrics = @{ OrphanedAppxUsers = $orphans.Count }
        if ($orphans.Count -lt 50) { return New-Result OK "$($orphans.Count) orphaned user registrations." $detail -Metrics $metrics }
        $fix = Format-Steps @(
            'Use the one-click fix (it backs up the registry key first) or run the commands below.'
            'Optionally reboot the host afterwards.'
            'Prevent regrowth: make sure local profiles are removed consistently (FSLogix DeleteLocalProfileWhenVHDShouldApply, PRF-04).'
        )
        $impact = Format-Bullets @(
            'Only entries for users who no longer have a local profile on this host are removed - signed-in users and existing profiles are not touched.'
            'If one of those users signs in to this host again, Windows registers their apps like for a new user, so that one logon is slightly slower.'
            'No reboot required. Can be undone from the Fix history tab.'
        )
        $cmd = (New-RegBackupCmd -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore' -Name 'AppxAllUserStore') + "`r`n" + @'
$store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
$profiles = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList').PSChildName
$orphans = @(Get-ChildItem $store | Where-Object { $_.PSChildName -match '^S-1-(5-21|12-1)-' -and $profiles -notcontains $_.PSChildName })
$orphans | Remove-Item -Recurse -Force
"Removed $($orphans.Count) orphaned user registration(s)."
'@
        $auto = New-AutoFix -Label "Remove $($orphans.Count) orphaned registrations" -Backup `
            -Changes 'Backs up AppxAllUserStore and deletes the subkeys of user SIDs that have no entry in ProfileList.'
        if ($orphans.Count -ge 500) { return New-Result Problem "$($orphans.Count) orphaned user registrations in AppxAllUserStore." $detail $fix $cmd -Impact $impact -AutoFix $auto -Metrics $metrics }
        New-Result Warning "$($orphans.Count) orphaned user registrations in AppxAllUserStore." $detail $fix $cmd -Impact $impact -AutoFix $auto -Metrics $metrics
    }

Register-Check -Id 'APX-05' -Category 'AppX / Active Setup' -Weight 2 -Tags 'Image' `
    -Name 'Active Setup components (run before Explorer starts)' `
    -Test {
        param($E)
        $items = @()
        $roots = @(
            @{ M = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components';             U = 'HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components' }
            @{ M = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components'; U = 'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components' }
        )
        foreach ($r in $roots) {
            foreach ($k in @(Get-ChildItem $r.M -ErrorAction SilentlyContinue)) {
                $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
                if (-not $p -or -not $p.StubPath) { continue }
                if ($p.PSObject.Properties['IsInstalled'] -and "$($p.IsInstalled)" -eq '0') { continue }
                $name = $p.'(default)'; if (-not $name) { $name = $p.ComponentID }; if (-not $name) { $name = $k.PSChildName }
                $uPath = Join-Path $r.U $k.PSChildName
                $uVer = Get-RegValue $uPath 'Version'
                $mv = ConvertTo-Version $p.Version; $uv = ConvertTo-Version $uVer
                $pending = -not (Test-Path $uPath) -or ($mv -and (-not $uv -or $mv -gt $uv))
                $items += [pscustomobject]@{ Guid = $k.PSChildName; Name = $name; Version = $p.Version; Pending = $pending; Stub = $p.StubPath }
            }
        }
        $edge = @($items | Where-Object { $_.Guid -eq '{9459C573-B17A-45AE-9F64-1857B5D58CEE}' })
        $pending = @($items | Where-Object { $_.Pending })
        $detail = Join-Lines @(
            "Components with StubPath: $($items.Count); would run again for $($E.UserName): $($pending.Count)"
            ''
            ($items | Sort-Object Pending -Descending | ForEach-Object { "{0} {1}  v{2}`r`n      {3}" -f $(if ($_.Pending) { '[PENDING]' } else { '[done]   ' }), $_.Name, $_.Version, $_.Stub })
        )
        $metrics = @{ ActiveSetupComponents = $items.Count }
        $maybeNonPersistent = $E.IsSessionHost -and -not $E.FSLogixProfiles
        $fix = Format-Steps @(
            'Review the components in the evidence. Each one runs one after another before the desktop appears - for every NEW profile, and again whenever its HKLM version is raised (Edge raises it with its updates).'
            'Disable components that are not needed on session hosts in the golden image (rename StubPath to StubPath_disabled), after testing.'
            'Or pre-stamp HKCU\Software\Microsoft\Active Setup\Installed Components\<GUID>\Version (GPP registry item or default profile) so they are skipped.'
            'Keep profiles persistent (FSLogix) so each component only runs once per user.'
        )
        $impact = Format-Bullets @(
            'A skipped or disabled component no longer does its per-user setup: missing shortcuts, default settings or first-run configuration for that application.'
            'Test each component on a test host before disabling it; some (e.g. Edge) are needed for a correct user experience.'
            'Changes in the golden image apply to newly deployed hosts; no reboot needed.'
            'No one-click fix is offered because each component needs an individual decision.'
        )
        $cmd = @'
# List Active Setup components and their StubPaths
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components' |
    Get-ItemProperty | Where-Object StubPath | Select-Object PSChildName, '(default)', Version, StubPath | Format-List
'@
        $edgeNote = ''; if ($edge) { $edgeNote = ' Includes Microsoft Edge (re-runs after Edge updates).' }
        if ($maybeNonPersistent -and $items.Count -ge 10) { return New-Result Problem "$($items.Count) Active Setup components on a session host without FSLogix profiles - with non-persistent profiles they all run at every logon.$edgeNote" $detail $fix $cmd -Impact $impact -Metrics $metrics }
        if ($items.Count -ge 20 -or $pending.Count -ge 5) { return New-Result Warning "$($items.Count) Active Setup components ($($pending.Count) pending for current user).$edgeNote" $detail $fix $cmd -Impact $impact -Metrics $metrics }
        New-Result OK "$($items.Count) Active Setup components ($($pending.Count) pending for current user).$edgeNote" $detail -Metrics $metrics
    }

Register-Check -Id 'APX-06' -Category 'AppX / Active Setup' -Weight 1 -Tags 'Image' `
    -Name 'OneDrive per-user install at first logon' `
    -AppliesTo { param($E) $E.IsClient } `
    -NotApplicableReason 'OneDrive is not part of Windows Server.' `
    -Test {
        param($E)
        $machine = Test-Path (Join-Path ${env:ProgramFiles} 'Microsoft OneDrive\OneDrive.exe')
        $machine86 = Test-Path (Join-Path ${env:ProgramFiles(x86)} 'Microsoft OneDrive\OneDrive.exe')
        $setup = (Test-Path "$env:SystemRoot\System32\OneDriveSetup.exe") -or (Test-Path "$env:SystemRoot\SysWOW64\OneDriveSetup.exe")
        $detail = "Per-machine OneDrive: $($machine -or $machine86); inbox OneDriveSetup.exe present: $setup"
        if ($machine -or $machine86) { return New-Result OK 'OneDrive is installed per machine.' $detail }
        if ($setup) {
            $fix = Format-Steps @(
                'Download the latest OneDriveSetup.exe from Microsoft.'
                'Run "OneDriveSetup.exe /allusers" elevated in the golden image (or on the host).'
                'Redeploy the hosts from the image.'
            )
            $impact = Format-Bullets @(
                'OneDrive is installed once in Program Files and updated per machine - users no longer get a per-user install at first logon.'
                'Existing per-user installs are migrated automatically when OneDrive starts.'
                'No reboot; no functional difference for users.'
            )
            return New-Result Warning 'OneDrive is not installed per machine - OneDriveSetup.exe installs it into every new profile at first logon.' $detail $fix 'OneDriveSetup.exe /allusers' -Impact $impact
        }
        New-Result OK 'OneDrive not present.' $detail
    }
#endregion

#region Entra ID / Intune first logon
Register-Check -Id 'ENT-01' -Category 'Entra ID / Intune first logon' -Weight 2 -Tags 'Image', 'Intune' `
    -Name 'Windows Hello for Business provisioning at first sign-in' `
    -AppliesTo { param($E) $E.IsClient -and $E.IsSessionHost -and $E.EntraJoined } `
    -NotApplicableReason 'Only Entra-joined / hybrid-joined Windows 10/11 session hosts.' `
    -Test {
        param($E)
        $gpo = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'
        $gEnabled = Get-RegValue $gpo 'Enabled'; $gPost = Get-RegValue $gpo 'DisablePostLogonProvisioning'
        $mdm = @(); $mdmOn = $false; $mdmOff = $false
        foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork' -Recurse -ErrorAction SilentlyContinue)) {
            $v = $k.GetValue('UsePassportForWork')
            if ($null -ne $v) { $mdm += "$($k.Name) : UsePassportForWork = $v"; if ($v -eq 0) { $mdmOff = $true } else { $mdmOn = $true } }
        }
        $ev358 = @(Get-Events -LogName 'Microsoft-Windows-User Device Registration/Admin' -Id 358 -Max 500).Count
        $detail = Join-Lines @(
            "GPO Enabled                     : $(if ($null -eq $gEnabled) { '(not set)' } else { $gEnabled })"
            "GPO DisablePostLogonProvisioning: $(if ($null -eq $gPost) { '(not set)' } else { $gPost })"
            "Intune (MDM) policy             : $(if ($mdm) { "`r`n    " + ($mdm -join "`r`n    ") } else { '(none)' })"
            "Provisioning launched (event 358): $ev358 in $LookbackDays days"
        )
        if ($gEnabled -eq 0 -or $gPost -eq 1 -or ($mdmOff -and -not $mdmOn)) { return New-Result OK 'Windows Hello for Business provisioning is disabled for this host.' $detail }
        $fix = Format-Steps @(
            'Intune: Settings catalog > Windows Hello For Business > "Use Windows Hello For Business" = false, assigned to the session host device group (recommended).'
            'Or GPO: Computer > Administrative Templates > Windows Components > Windows Hello for Business > "Use Windows Hello for Business" = Disabled.'
            'Or use the one-click fix to set the policy locally on this host / in the golden image.'
        )
        $impact = Format-Bullets @(
            'New users are no longer taken through "Set up Windows Hello / PIN" at their first sign-in on the session hosts.'
            'Users cannot use Windows Hello (PIN / biometrics) inside the session - AVD sign-in uses the credentials / SSO from the client device, so normally nothing changes for them.'
            'Existing Windows Hello containers on the host are not removed. No reboot.'
            'If Intune configures Windows Hello the other way, set it in Intune as well so the policies do not conflict.'
        )
        $cmd = (New-RegBackupCmd -Key 'HKLM\SOFTWARE\Policies\Microsoft\PassportForWork' -Name 'PassportForWork') + "`r`n" + @'
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'
New-Item -Path $k -Force | Out-Null
New-ItemProperty -Path $k -Name Enabled -PropertyType DWord -Value 0 -Force | Out-Null
New-ItemProperty -Path $k -Name DisablePostLogonProvisioning -PropertyType DWord -Value 1 -Force | Out-Null
'Windows Hello for Business provisioning disabled.'
'@
        $auto = New-AutoFix -Label 'Disable Windows Hello provisioning' -Backup `
            -Changes 'Backs up HKLM\SOFTWARE\Policies\Microsoft\PassportForWork and sets Enabled = 0 and DisablePostLogonProvisioning = 1.'
        if ($ev358 -gt 0) { return New-Result Problem "Windows Hello for Business provisioning was launched $ev358 time(s) at sign-in - users wait on the Hello setup before the desktop." $detail $fix $cmd -Impact $impact -AutoFix $auto }
        New-Result Warning 'Windows Hello for Business is not disabled on this Entra-joined session host - new users can be held at the Hello setup on first sign-in.' $detail $fix $cmd -Impact $impact -AutoFix $auto
    }

Register-Check -Id 'ENT-02' -Category 'Entra ID / Intune first logon' -Weight 2 -Tags 'Image', 'Intune' `
    -Name 'Intune Enrollment Status Page - user phase ("Account setup")' `
    -AppliesTo { param($E) $E.IsSessionHost -and $E.EntraJoined } `
    -NotApplicableReason 'Only Entra-joined / hybrid-joined session hosts.' `
    -Test {
        param($E)
        $enr = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue | Where-Object { $_.GetValue('ProviderID') -eq 'MS DM Server' })
        if (-not $enr) { return New-Result OK 'Not enrolled in Intune (no MDM enrollment found).' 'HKLM\SOFTWARE\Microsoft\Enrollments has no "MS DM Server" enrollment.' }
        $rows = foreach ($e in $enr) {
            $fsKey = "HKLM:\SOFTWARE\Microsoft\Enrollments\$($e.PSChildName)\FirstSync"
            [pscustomobject]@{ Guid = $e.PSChildName; Key = $fsKey; Value = (Get-RegValue $fsKey 'SkipUserStatusPage') }
        }
        $detail = Join-Lines ($rows | ForEach-Object { "Enrollment $($_.Guid): SkipUserStatusPage = $(if ($null -eq $_.Value) { '(not set)' } else { $_.Value })" })
        if (@($rows | Where-Object { $_.Value -eq -1 -or $_.Value -eq 4294967295 })) { return New-Result OK 'The user phase of the Enrollment Status Page is skipped.' $detail }
        $fix = Format-Steps @(
            'Intune (recommended): custom OMA-URI ./Vendor/MSFT/DMClient/Provider/MS DM Server/FirstSyncStatus/SkipUserStatusPage = Boolean True, assigned to the session host device group.'
            'Or make sure no Enrollment Status Page profile with the user phase targets the session hosts.'
            'Or use the one-click fix on this host / in the golden image.'
        )
        $impact = Format-Bullets @(
            'New users are no longer held on the "Account setup" screen at their first sign-in.'
            'User-targeted Intune apps and policies install in the background after the desktop appears, so during the first minutes some apps or settings may still be missing.'
            'No reboot. Intune can set the value back if the CSP is configured differently - set it in Intune too.'
        )
        $lines = foreach ($r in $rows) {
            (New-RegBackupCmd -Key ("HKLM\SOFTWARE\Microsoft\Enrollments\$($r.Guid)\FirstSync") -Name "FirstSync-$($r.Guid.Substring(0, 8))")
            "New-Item -Path '$($r.Key)' -Force | Out-Null"
            "New-ItemProperty -Path '$($r.Key)' -Name SkipUserStatusPage -PropertyType DWord -Value -1 -Force | Out-Null"
        }
        $cmd = ($lines -join "`r`n") + "`r`n'Enrollment Status Page user phase will be skipped.'"
        $auto = New-AutoFix -Label 'Skip the ESP user phase' -Backup -Changes 'Backs up the FirstSync key of each Intune enrollment and sets SkipUserStatusPage = 0xFFFFFFFF.'
        New-Result Warning 'The Enrollment Status Page user phase is not skipped - each new user can be held on "Account setup" before the desktop appears.' $detail $fix $cmd -Impact $impact -AutoFix $auto
    }

Register-Check -Id 'ENT-03' -Category 'Entra ID / Intune first logon' -Weight 3 -Tags 'Image', 'Intune' `
    -Name 'Privacy settings screen at first sign-in' `
    -AppliesTo { param($E) $E.IsClient -and $E.Build -ge 17134 } `
    -NotApplicableReason 'Only Windows 10 1803+ / Windows 11 (incl. multi-session).' `
    -Test {
        param($E)
        $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE'
        $v = Get-RegValue $key 'DisablePrivacyExperience'
        $detail = "HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE\DisablePrivacyExperience = $(if ($null -eq $v) { '(not set)' } else { $v })"
        if ($v -eq 1) { return New-Result OK 'The privacy settings screen is disabled.' $detail }
        $fix = Format-Steps @(
            'GPO: Computer > Administrative Templates > Windows Components > OOBE > "Do not launch privacy settings experience on user logon" = Enabled, or Intune Settings catalog > Privacy > Disable Privacy Experience.'
            'Or use the one-click fix on this host / in the golden image.'
        )
        $impact = Format-Bullets @(
            'New users are no longer shown "Choose privacy settings for your device" at first sign-in.'
            'Privacy settings (diagnostic data, location, tailored experiences, advertising ID) then follow Windows defaults and your policies instead of the user choice - set "Turn off tailored experiences" / "Turn off the advertising ID" by policy if you want them off.'
            'No reboot; takes effect at the next sign-in.'
        )
        $cmd = (New-RegBackupCmd -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE' -Name 'OOBE') + "`r`n" +
               "New-Item -Path '$key' -Force | Out-Null`r`nNew-ItemProperty -Path '$key' -Name DisablePrivacyExperience -PropertyType DWord -Value 1 -Force | Out-Null`r`n'DisablePrivacyExperience set to 1.'"
        $auto = New-AutoFix -Label 'Disable the privacy settings screen' -Backup -Changes 'Backs up the OOBE policy key and sets DisablePrivacyExperience = 1.'
        if ($E.IsSessionHost) { return New-Result Problem 'The "Choose privacy settings" screen is not disabled. It opens before the desktop for every new (or non-persisted) profile - through the AVD client it typically shows as a black screen, while a plain RDP connection to the host shows the privacy pages.' $detail $fix $cmd -Impact $impact -AutoFix $auto }
        New-Result Info 'The privacy settings screen can appear at first sign-in of new users.' $detail $fix $cmd -Impact $impact -AutoFix $auto
    }
#endregion

#region Network paths and domain
Register-Check -Id 'NET-01' -Category 'Network paths and domain' -Weight 3 `
    -Name 'Redirected folders and mapped drives reachable (current user)' `
    -Test {
        param($E)
        $targets = @()
        $usf = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
        if (Test-Path $usf) {
            $k = Get-Item $usf
            foreach ($n in $k.GetValueNames()) {
                $v = [Environment]::ExpandEnvironmentVariables([string]$k.GetValue($n, $null, 'DoNotExpandEnvironmentNames'))
                if ($v -like '\\*') { $targets += [pscustomobject]@{ Kind = 'Redirected folder'; Name = $n; Path = $v } }
            }
        }
        foreach ($d in @(Get-ChildItem 'HKCU:\Network' -ErrorAction SilentlyContinue)) {
            $rp = $d.GetValue('RemotePath')
            if ($rp) { $targets += [pscustomobject]@{ Kind = 'Mapped drive'; Name = "$($d.PSChildName):"; Path = $rp } }
        }
        if (-not $targets) { return New-Result OK "No redirected folders or persistent mapped drives for $($E.UserName)." 'Checked HKCU User Shell Folders and HKCU\Network.' }
        $cache = @{}
        $tests = foreach ($t in $targets) {
            if (-not $cache.ContainsKey($t.Path)) { $cache[$t.Path] = Test-UncPath -Path $t.Path }
            $r = $cache[$t.Path]
            [pscustomobject]@{ Kind = $t.Kind; Name = $t.Name; Path = $t.Path; Reachable = $r.Reachable; Ms = $r.Ms; Note = $r.Note }
        }
        $dead = @($tests | Where-Object { -not $_.Reachable })
        $slow = @($tests | Where-Object { $_.Reachable -and $_.Ms -ge 1000 })
        $detail = Join-Lines @("Tested as $($E.UserName):", ($tests | ForEach-Object { "  {0,-18} {1,-12} {2}  ->  {3} ({4} ms)" -f $_.Kind, $_.Name, $_.Path, $(if ($_.Reachable) { 'OK' } else { "UNREACHABLE: $($_.Note)" }), $_.Ms }))
        $fix = Format-Steps @(
            'Dead mapped drives: remove them (one-click fix for the current user) and fix the GPP drive map / logon script that creates them (do not use "Reconnect" for drives to servers that can be offline).'
            'Redirected folders on an unreachable or slow server: correct the Folder Redirection target in the GPO, or move to OneDrive Known Folder Move.'
            'Run this tool inside an affected user session - these settings are per user.'
        )
        $impact = Format-Bullets @(
            'Removing a dead drive mapping: the drive letter disappears for this user until a logon script / GPO maps it again (to a working server).'
            'Changing Folder Redirection targets moves user data - plan the migration; users must sign out and in again.'
            'No reboot.'
        )
        $deadDrives = @($dead | Where-Object { $_.Kind -eq 'Mapped drive' })
        $cmd = ''; $auto = $null
        if ($deadDrives) {
            $cmd = ($deadDrives | ForEach-Object {
                $letter = $_.Name.TrimEnd(':')
                "& { `$ErrorActionPreference = 'Continue'; net.exe use $($_.Name) /delete /y 2>`$null | Out-Null }`r`nif (Test-Path 'HKCU:\Network\$letter') { Remove-Item 'HKCU:\Network\$letter' -Recurse -Force }`r`n'Removed $($_.Name) ($($_.Path))'"
            }) -join "`r`n"
            $auto = New-AutoFix -Label "Remove $($deadDrives.Count) dead drive mapping(s)" -NoAdmin -UserScope `
                -Changes "Deletes the persistent drive mapping(s) $(($deadDrives | ForEach-Object { $_.Name }) -join ', ') for $($E.UserName). The shares themselves are not touched."
        }
        if ($dead) { return New-Result Problem "$($dead.Count) network path(s) for $($E.UserName) do not respond - Explorer waits for these at startup, which shows as a black screen." $detail $fix $cmd -Impact $impact -AutoFix $auto }
        if ($slow) { return New-Result Warning "$($slow.Count) network path(s) for $($E.UserName) respond slowly (1 s or more)." $detail $fix -Impact $impact }
        New-Result OK "All $($tests.Count) network path(s) for $($E.UserName) respond quickly." $detail
    }

Register-Check -Id 'NET-02' -Category 'Network paths and domain' -Weight 2 -Tags 'Image' `
    -Name 'Wallpaper, lock screen or Start layout loaded from the network' `
    -Test {
        param($E)
        $sources = @(
            @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System', 'Wallpaper', 'Wallpaper policy (user)')
            @('HKCU:\Control Panel\Desktop', 'Wallpaper', 'Current wallpaper (user)')
            @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization', 'LockScreenImage', 'Lock screen image policy')
            @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP', 'DesktopImagePath', 'Intune desktop image')
            @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP', 'LockScreenImagePath', 'Intune lock screen image')
            @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer', 'StartLayoutFile', 'Start layout (machine)')
            @('HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer', 'StartLayoutFile', 'Start layout (user)')
        )
        $found = foreach ($s in $sources) {
            $v = [string](Get-RegValue $s[0] $s[1])
            if ($v) { $v = [Environment]::ExpandEnvironmentVariables($v) }
            if ($v -like '\\*') { $r = Test-UncPath -Path $v; [pscustomobject]@{ What = $s[2]; Path = $v; Reachable = $r.Reachable; Ms = $r.Ms; Note = $r.Note } }
        }
        if (-not $found) { return New-Result OK 'Wallpaper, lock screen and Start layout are not loaded from network paths.' 'No UNC paths found in the wallpaper / lock screen / Start layout settings.' }
        $detail = Join-Lines ($found | ForEach-Object { "{0,-26} {1}  ->  {2} ({3} ms)" -f $_.What, $_.Path, $(if ($_.Reachable) { 'OK' } else { "UNREACHABLE: $($_.Note)" }), $_.Ms })
        $fix = Format-Steps @(
            'Copy the image / layout file into the golden image (e.g. C:\Windows\Web\...) or deploy it with Intune / GPP files.'
            'Point the policy at the local path instead of the UNC path.'
        )
        $impact = Format-Bullets @(
            'Changing the wallpaper or Start layout later requires redeploying the file to the hosts (image, Intune or GPP).'
            'No reboot; applies at the next logon.'
        )
        $dead = @($found | Where-Object { -not $_.Reachable })
        $slow = @($found | Where-Object { $_.Reachable -and $_.Ms -ge 500 })
        if ($dead) { return New-Result Problem "$($dead.Count) desktop / Start layout file(s) are on an unreachable network path - the shell waits for them during logon." $detail $fix -Impact $impact }
        if ($slow) { return New-Result Warning "$($slow.Count) desktop / Start layout file(s) load slowly from the network." $detail $fix -Impact $impact }
        New-Result Info "$(@($found).Count) desktop / Start layout file(s) are loaded from the network at every logon (currently fast)." $detail $fix -Impact $impact
    }

Register-Check -Id 'NET-03' -Category 'Network paths and domain' -Weight 2 `
    -Name 'Domain controller discovery and latency' `
    -AppliesTo { param($E) $E.DomainJoined } `
    -NotApplicableReason 'Not joined to an Active Directory domain (Entra-only joined or workgroup).' `
    -Test {
        param($E)
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $out = (& { $ErrorActionPreference = 'Continue'; nltest.exe "/dsgetdc:$($E.DomainName)" 2>&1 }) | Out-String
        $discoveryMs = $sw.ElapsedMilliseconds
        $dc = $null; $dcSite = $null; $mySite = $null
        if ($out -match 'DC:\s*\\\\(\S+)') { $dc = $Matches[1] }
        if ($out -match 'Dc Site Name:\s*(\S+)') { $dcSite = $Matches[1] }
        if ($out -match 'Our Site Name:\s*(\S+)') { $mySite = $Matches[1] }
        if (-not $dc) { return New-Result Problem "No domain controller found for $($E.DomainName) - logon, Group Policy and Kerberos will be slow or fail." $out.Trim() (Format-Steps @('Check DNS settings of the host / vnet (must point to domain DNS servers).', 'Check network connectivity to the domain controllers (ports 53, 88, 135, 389, 445, dynamic RPC).')) -Impact 'Fixing DNS / network connectivity has no negative impact on users.' }
        $lat = @(foreach ($i in 1..3) { $s = [System.Diagnostics.Stopwatch]::StartNew(); if (Test-TcpPort -HostName $dc -Port 389 -TimeoutMs 2000) { $s.ElapsedMilliseconds } })
        $latMs = if ($lat) { ($lat | Measure-Object -Minimum).Minimum } else { $null }
        $detail = Join-Lines @(
            "Domain            : $($E.DomainName)"
            "Domain controller : $dc"
            "DC site / our site: $dcSite / $mySite"
            "Discovery time    : $discoveryMs ms"
            "LDAP TCP latency  : $(if ($null -ne $latMs) { "$latMs ms" } else { 'port 389 not reachable' })"
        )
        $fix = Format-Steps @(
            'In AD Sites and Services, add the AVD / host subnet(s) to the site that has domain controllers close to the hosts (or place DCs in the same Azure region).'
            'Point the vnet / host DNS to the nearest domain controllers.'
            'Verify with "nltest /dsgetdc:<domain> /force" that a DC in the right site is chosen.'
        )
        $impact = Format-Bullets @(
            'Changing the subnet-to-site mapping changes which DC every machine in that subnet uses (also DFS / file share referrals by site).'
            'No reboot; the DC locator picks up the change within its cache time, or immediately with nltest /force.'
        )
        $metrics = @{ DcDiscoveryMs = $discoveryMs; DcLatencyMs = $latMs }
        if ($null -eq $latMs) { return New-Result Problem "Domain controller $dc does not answer on LDAP (389)." $detail $fix -Impact $impact -Metrics $metrics }
        if ($dcSite -and $mySite -and $dcSite -ne $mySite) { return New-Result Warning "The host uses DC $dc in site $dcSite, but the host is in site $mySite - logon traffic crosses sites." $detail $fix -Impact $impact -Metrics $metrics }
        if ($latMs -ge 30 -or $discoveryMs -ge 2000) { return New-Result Warning "Domain controller is slow to find or reach (discovery $discoveryMs ms, latency $latMs ms)." $detail $fix -Impact $impact -Metrics $metrics }
        New-Result OK "DC $dc in site $dcSite answers in $latMs ms." $detail -Metrics $metrics
    }
#endregion

#region Profiles
Register-Check -Id 'PRF-01' -Category 'Profiles / FSLogix' -Weight 2 -Tags 'Intune' `
    -Name 'FSLogix configuration, version and load time' `
    -AppliesTo { param($E) $E.HasFSLogix } -NotApplicableReason 'FSLogix is not installed.' `
    -Test {
        param($E)
        $svc = Get-Service frxsvc -ErrorAction SilentlyContinue
        $vhd = Get-FsLogixSetting 'VHDLocations'; $ccd = Get-FsLogixSetting 'CCDLocations'
        $settings = foreach ($n in 'Enabled', 'VolumeType', 'SizeInMBs', 'IsDynamic', 'DeleteLocalProfileWhenVHDShouldApply', 'PreventLoginWithFailure', 'PreventLoginWithTempProfile', 'ProfileType', 'LockedRetryCount', 'LockedRetryInterval', 'ReAttachRetryCount', 'ReAttachIntervalSeconds') {
            $v = Get-FsLogixSetting $n; if ($null -ne $v) { "  $n = $v" }
        }
        # LoadProfile timing from FSLogix logs (several known line formats)
        $logDir = Join-Path $env:ProgramData 'FSLogix\Logs\Profile'
        $times = @(); $errors = 0
        foreach ($f in @(Get-ChildItem $logDir -Filter '*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 5)) {
            foreach ($l in (Get-Content $f.FullName -ErrorAction SilentlyContinue)) {
                if ($l -match 'LoadProfile time:\s*(\d+)\s*milli') { $times += [int]$Matches[1] }
                elseif ($l -match '(?i)load\s*profile.{0,40}?(\d{3,})\s*(ms|milliseconds)\b') { $times += [int]$Matches[1] }
                elseif ($l -match '\[ERROR') { $errors++ }
            }
        }
        $maxS = 0; $avgS = 0
        if ($times) { $maxS = [math]::Round(($times | Measure-Object -Maximum).Maximum / 1000, 1); $avgS = [math]::Round(($times | Measure-Object -Average).Average / 1000, 1) }
        $detail = Join-Lines @(
            "Version        : $($E.FSLogixVersion)"
            "Service frxsvc : $(if ($svc) { "$($svc.Status) / $($svc.StartType)" } else { 'missing' })"
            "VHDLocations   : $vhd"
            "CCDLocations   : $ccd"
            'Settings:'; $settings
            "LoadProfile    : $(if ($times) { "$($times.Count) samples, avg $avgS s, max $maxS s" } else { 'no timing lines found in recent logs (use the Logon timeline tab instead)' })"
            "Log errors     : $errors (last 5 log files)"
        )
        $ref = 'https://learn.microsoft.com/fslogix/overview-release-notes'
        $metrics = @{ FSLogixLoadMaxSec = $maxS; FSLogixLogErrors = $errors }
        if (-not $svc -or $svc.Status -ne 'Running') {
            if (-not $svc) { return New-Result Problem 'FSLogix service is missing.' $detail 'Reinstall FSLogix (aka.ms/fslogix-latest).' -Reference $ref -Impact 'Reinstalling FSLogix requires a reboot - drain the host first.' }
            $fix = Format-Steps @(
                'Use the one-click fix: sets the FSLogix service to Automatic and starts it.'
                'If it does not start, check the FSLogix logs and the System event log; reinstall FSLogix if needed.'
                'Users who signed in while it was stopped must sign out and in again to get their container.'
            )
            $impact = Format-Bullets @(
                'While frxsvc is stopped users get a local or temporary profile without their FSLogix data - fix immediately.'
                'Starting the service does not affect sessions that are already running.'
            )
            $cmd = "Set-Service frxsvc -StartupType Automatic`r`nStart-Service frxsvc`r`n'FSLogix service started.'"
            $auto = New-AutoFix -Label 'Start the FSLogix service' -Changes 'Sets frxsvc to Automatic and starts it.'
            return New-Result Problem 'FSLogix service is not running.' $detail $fix $cmd $ref -Impact $impact -AutoFix $auto -Metrics $metrics
        }
        if ($E.FSLogixVersion -and $E.FSLogixVersion -lt [version]'2.9.8361.52326') {
            $fix = Format-Steps @(
                'Download the latest FSLogix release (aka.ms/fslogix-latest) and read the release notes for changed defaults.'
                'Drain the host, install the update and reboot (it updates a driver).'
                'Update the golden image as well.'
            )
            $impact = Format-Bullets @(
                'Requires a reboot - users are signed out, so drain the host first.'
                'Newer versions can change default behaviour - test on one host / a validation host pool first.'
                'Profile containers are not changed by the upgrade.'
            )
            return New-Result Warning "FSLogix $($E.FSLogixVersion) is older than 2210 - update to the current release." $detail $fix -Reference $ref -Impact $impact -Metrics $metrics
        }
        $fix = Format-Steps @(
            'Check storage latency / IOPS for the profile share (Azure Files Premium, SMB multichannel, same region as the hosts).'
            'Check the antivirus exclusions (PRF-02).'
            'Keep containers small (compaction, redirections.xml for caches).'
            'Use Cloud Cache only when you need it - it adds logon time.'
        )
        $impact = Format-Bullets @(
            'A faster storage tier costs more but needs no user downtime; moving containers requires users to be signed out.'
            'Excluding caches from the container means those caches are rebuilt at each logon (slightly slower first app start).'
            'Container compaction runs at logoff, so logoff can take a little longer.'
        )
        if ($maxS -ge 60) { return New-Result Problem "FSLogix profile load took up to $maxS s." $detail $fix -Reference $ref -Impact $impact -Metrics $metrics }
        if ($maxS -ge 20) { return New-Result Warning "FSLogix profile load took up to $maxS s." $detail $fix -Reference $ref -Impact $impact -Metrics $metrics }
        $note = ''; if ($ccd) { $note = ' Cloud Cache is in use (adds logon time).' }
        New-Result OK "FSLogix running, load time max $maxS s.$note" $detail -Reference $ref -Metrics $metrics
    }

Register-Check -Id 'PRF-02' -Category 'Profiles / FSLogix' -Weight 3 -Tags 'Image', 'Intune' `
    -Name 'Antivirus exclusions for FSLogix (Defender)' `
    -AppliesTo { param($E) $E.HasFSLogix } -NotApplicableReason 'FSLogix is not installed.' `
    -Test {
        param($E)
        $ref = 'https://learn.microsoft.com/fslogix/overview-prerequisites#configure-antivirus-file-and-folder-exclusions'
        $impact = Format-Bullets @(
            'The antivirus no longer scans the container files (VHD/VHDX) and FSLogix processes in real time. Files INSIDE the mounted container are still scanned when users open them, so user files stay protected.'
            'Takes effect immediately; no reboot.'
            'Agree the exclusions with your security team - they follow the Microsoft FSLogix guidance.'
        )
        if (-not $E.Defender -or -not $E.Defender.RealTimeProtectionEnabled -or "$($E.Defender.AMRunningMode)" -match 'Passive|EDR') {
            $fix = Format-Steps @(
                'Open your antivirus / EDR management console.'
                'Exclude *.VHD and *.VHDX in %TEMP%, %WINDIR%\TEMP and on the profile share.'
                'Exclude %ProgramData%\FSLogix\Cache and %ProgramData%\FSLogix\Proxy (Cloud Cache).'
                'Exclude the processes frxsvc.exe, frxccd.exe and frxccds.exe.'
            )
            return New-Result Info 'Defender real-time protection is not the active AV. Verify the FSLogix exclusions in your AV/EDR product.' '' $fix -Reference $ref -Impact $impact
        }
        $mp = $null
        try { $mp = Get-MpPreference -ErrorAction Stop } catch { }
        if (-not $mp -or "$($mp.ExclusionPath)" -match 'Must be an administrator') { return New-Result Info 'Cannot read Defender exclusions - run elevated.' '' -Reference $ref }
        $all = @($mp.ExclusionPath) + @($mp.ExclusionExtension) | Where-Object { $_ }
        $procs = @($mp.ExclusionProcess) | Where-Object { $_ }
        $ccd = Get-FsLogixSetting 'CCDLocations'
        $missing = @()
        if (-not @($all | Where-Object { $_ -match 'vhdx' })) { $missing += '*.VHDX (local temp and the profile share)' }
        if (-not @($all | Where-Object { $_ -match '(^|\\|\.)vhd($|\W)' -or $_ -match '\*\.vhd$' })) { $missing += '*.VHD' }
        foreach ($p in 'frxsvc.exe', 'frxccd.exe', 'frxccds.exe') { if (-not @($procs | Where-Object { $_ -like "*$p" })) { $missing += "process $p" } }
        if ($ccd) {
            if (-not @($all | Where-Object { $_ -like '*FSLogix\Cache*' })) { $missing += '%ProgramData%\FSLogix\Cache' }
            if (-not @($all | Where-Object { $_ -like '*FSLogix\Proxy*' })) { $missing += '%ProgramData%\FSLogix\Proxy' }
        }
        $detail = Join-Lines @('Exclusion paths/extensions:', ($all | ForEach-Object { "  $_" }), 'Exclusion processes:', ($procs | ForEach-Object { "  $_" }), '', 'Missing:', ($missing | ForEach-Object { "  $_" }), "DisableLocalAdminMerge: $($mp.DisableLocalAdminMerge)")
        if (-not $missing) { return New-Result OK 'FSLogix Defender exclusions are in place.' $detail -Reference $ref }
        $share = (@(Get-FsLogixSetting 'VHDLocations') -split ';' | Where-Object { $_ } | Select-Object -First 1)
        $paths = @("`$env:TEMP\*\*.VHD", "`$env:TEMP\*\*.VHDX", "`$env:SystemRoot\TEMP\*\*.VHD", "`$env:SystemRoot\TEMP\*\*.VHDX")
        if ($share) { $paths += @("$share\*\*.VHD", "$share\*\*.VHDX") }
        $cmd = "`$fs = Join-Path `$env:ProgramFiles 'FSLogix\Apps'`r`n" +
               "Add-MpPreference -ExclusionProcess `"`$fs\frxsvc.exe`",`"`$fs\frxccd.exe`",`"`$fs\frxccds.exe`"`r`n" +
               'Add-MpPreference -ExclusionPath ' + (($paths | ForEach-Object { "`"$_`"" }) -join ',') + "`r`n" +
               $(if ($ccd) { "Add-MpPreference -ExclusionPath `"`$env:ProgramData\FSLogix\Cache`",`"`$env:ProgramData\FSLogix\Proxy`"`r`n" } else { '' }) +
               "'FSLogix exclusions added to Defender.'"
        $fix = Format-Steps @(
            'Preferred: add the exclusions centrally (Intune: Endpoint security > Antivirus, or GPO) so every host gets them.'
            'Or use the one-click fix to add them on this host.'
            $(if (-not $share) { 'Also add the profile share path (\\server\share\*\*.VHDX) - VHDLocations could not be read here.' })
        )
        $auto = $null
        $mergeNote = ''
        if ($mp.DisableLocalAdminMerge) {
            $mergeNote = ' Local exclusions are ignored on this host (DisableLocalAdminMerge) - add them in Intune/GPO.'
        } else {
            $auto = New-AutoFix -Label 'Add FSLogix exclusions to Defender' `
                -Changes "Runs Add-MpPreference for the FSLogix processes (frxsvc, frxccd, frxccds) and the VHD/VHDX paths$(if ($share) { " incl. $share" })$(if ($ccd) { ' and the Cloud Cache folders' })."
        }
        if (@($missing | Where-Object { $_ -match 'VHDX' })) { return New-Result Problem "VHDX files are not excluded from Defender - scanning the container during attach slows profile load.$mergeNote" $detail $fix $cmd $ref -Impact $impact -AutoFix $auto }
        New-Result Warning "Some FSLogix exclusions are missing: $($missing -join ', ').$mergeNote" $detail $fix $cmd $ref -Impact $impact -AutoFix $auto
    }

Register-Check -Id 'PRF-04' -Category 'Profiles / FSLogix' -Weight 2 `
    -Name 'Local profiles: count, temp and .bak profiles' `
    -Test {
        param($E)
        $pl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        $keys = @(Get-ChildItem $pl -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-(5-21|12-1)-' })
        $bak = @($keys | Where-Object { $_.PSChildName -like '*.bak' })
        $temp = @($keys | Where-Object { "$($_.GetValue('ProfileImagePath'))" -match '\\TEMP(\.\d+)?$' })
        $detail = Join-Lines @("Domain/local user profiles: $($keys.Count)", "'.bak' entries: $($bak.Count)", ($bak | ForEach-Object { "  $($_.PSChildName)  $($_.GetValue('ProfileImagePath'))" }), "Temp profiles: $($temp.Count)")
        $metrics = @{ LocalProfiles = $keys.Count }
        if ($bak -or $temp) {
            $fix = Format-Steps @(
                'Ask the affected user to sign out.'
                'Back up the ProfileList key, then delete the SID key that points to a TEMP folder and the duplicate .bak key (keep the one that points to the correct profile folder).'
                'Find the root cause with PRF-05 / the FSLogix logs (locked container, storage outage, antivirus).'
            )
            $impact = Format-Bullets @(
                'The user gets their proper profile again at the next logon.'
                'A wrong deletion in ProfileList can disconnect a user from their local profile; with FSLogix the real profile is in the container, so the risk is low. Always back up the key first.'
                'No reboot. No one-click fix because the right key to keep must be chosen by hand.'
            )
            $cmd = New-RegBackupCmd -Key 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name 'ProfileList'
            return New-Result Problem "$($bak.Count) '.bak' and $($temp.Count) TEMP profile entries - users are getting temporary/duplicate profiles." $detail $fix $cmd -Impact $impact -Metrics $metrics
        }
        $limit = 100; if ($E.FSLogixProfiles) { $limit = 25 }
        if ($keys.Count -lt $limit) { return New-Result OK "$($keys.Count) local user profiles." $detail -Metrics $metrics }
        $fix = Format-Steps @(
            $(if ($E.FSLogixProfiles) { 'Set FSLogix DeleteLocalProfileWhenVHDShouldApply = 1 so leftover local profiles are removed automatically.' } else { 'Set the GPO "Delete user profiles older than a specified number of days on system restart".' })
            $(if ($E.FSLogixProfiles) { 'Use the one-click fix to remove local profiles not used for 30+ days.' } else { 'Remove stale profiles with the command below (preview with -WhatIf first).' })
        )
        $impact = Format-Bullets @(
            $(if ($E.FSLogixProfiles) { 'Only the leftover local copy is removed - user data stays in the FSLogix container.' } else { 'Data stored only in a deleted local profile is lost, and the next logon of that user is a first logon (slower).' })
            'Profiles of signed-in users are never touched.'
            'No reboot. Cannot be undone by this tool.'
        )
        if ($E.FSLogixProfiles) {
            $cmd = @'
$stale = @(Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and -not $_.Loaded -and $_.SID -match '^S-1-(5-21|12-1)-' -and $_.LastUseTime -and $_.LastUseTime -lt (Get-Date).AddDays(-30) })
foreach ($p in $stale) { Remove-CimInstance -InputObject $p; "Removed $($p.LocalPath)" }
"Removed $($stale.Count) stale local profile(s)."
'@
            $auto = New-AutoFix -Label 'Remove local profiles unused for 30+ days' `
                -Changes 'Deletes local user profiles (folder + ProfileList entry) that are not loaded and were last used more than 30 days ago. FSLogix containers are not touched.'
            return New-Result Warning "$($keys.Count) local user profiles on this host - with FSLogix there should be very few." $detail $fix $cmd -Impact $impact -AutoFix $auto -Metrics $metrics
        }
        $cmd = @'
# Preview stale local profiles (not loaded, unused 30+ days). Remove -WhatIf to delete.
Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and -not $_.Loaded -and $_.LastUseTime -lt (Get-Date).AddDays(-30) } |
    Remove-CimInstance -WhatIf
'@
        New-Result Warning "$($keys.Count) local user profiles on this host - many profiles slow down the Profile Service and AppX." $detail $fix $cmd -Impact $impact -Metrics $metrics
    }

Register-Check -Id 'PRF-05' -Category 'Profiles / FSLogix' -Weight 2 `
    -Name 'User Profile Service errors' `
    -Test {
        param($E)
        $ev = @(Get-Events -LogName 'Application' -ProviderName 'Microsoft-Windows-User Profiles Service' -Id 1500, 1502, 1508, 1511, 1515, 1530, 1533 -Max 2000)
        $g = $ev | Group-Object Id | Sort-Object Name
        $names = @{ '1500' = 'cannot load profile'; '1502' = 'cannot load registry'; '1508' = 'cannot load hive'; '1511' = 'temp profile'; '1515' = 'backup profile used'; '1530' = 'registry handles leaked at logoff'; '1533' = 'cannot delete profile folder' }
        $detail = Join-Lines ($g | ForEach-Object { "Event $($_.Name) ($($names[$_.Name])): $($_.Count)" })
        if (-not $detail) { $detail = 'No profile service errors.' }
        $bad = @($ev | Where-Object { $_.Id -in 1500, 1502, 1508, 1511, 1515 })
        if ($bad) {
            $fix = Format-Steps @(
                'Note the times of the events in the evidence (Event Viewer > Application, source User Profiles Service).'
                'Check the FSLogix Profile log for the same time: locked container, user signed in on another host, storage not reachable.'
                'Fix the root cause (storage availability, concurrent-session settings, antivirus exclusions - PRF-02).'
            )
            return New-Result Problem "$($bad.Count) profile load failures / temp profiles in $LookbackDays days." $detail $fix -Impact $NoChangeImpact
        }
        $c1530 = @($ev | Where-Object { $_.Id -eq 1530 }).Count
        if ($c1530 -ge 50) {
            $fix = Format-Steps @(
                'Open an event 1530 and note the process / registry key that keeps the user hive open.'
                'Update or reconfigure that software (often antivirus, printer drivers or management agents).'
            )
            $impact = Format-Bullets @(
                'Updating agents or drivers may require a reboot.'
                'Event 1530 is often harmless - only act if logoffs or the next logons of the same users are slow.'
            )
            return New-Result Warning "$c1530 x event 1530: processes keep user hives open at logoff, which can delay the next logon/logoff of that user." $detail $fix -Impact $impact
        }
        New-Result OK 'No significant profile service errors.' $detail
    }

Register-Check -Id 'PRF-06' -Category 'Profiles / FSLogix' -Weight 1 `
    -Name 'User Profile Disks (RDS)' `
    -AppliesTo { param($E) $E.IsServer -and $E.IsRdsh } -NotApplicableReason 'Only RDS session hosts on Windows Server.' `
    -Test {
        param($E)
        $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\ClusterSettings' 'UvhdEnabled'
        if ($v -eq 1) {
            $fix = Format-Steps @(
                'Plan a migration from User Profile Disks to FSLogix profile containers.'
                'Never run UPD and FSLogix together on the same host.'
            )
            $impact = Format-Bullets @(
                'This is a project: user profiles must be migrated and users signed out during their migration.'
                'After migration, logon no longer waits for the UPD attach.'
            )
            return New-Result Info 'User Profile Disks are enabled - UPD attach adds logon time and is superseded by FSLogix.' 'UvhdEnabled = 1' $fix -Impact $impact
        }
        New-Result OK 'User Profile Disks are not in use.' "UvhdEnabled = $v"
    }
#endregion

#region Shell
Register-Check -Id 'SHL-01' -Category 'Shell' -Weight 3 `
    -Name 'Shell process crashes / hangs' `
    -Test {
        param($E)
        $c = @(Get-ShellCrashes)
        $g = $c | Group-Object App | Sort-Object Count -Descending
        $detail = Join-Lines @(
            ($g | ForEach-Object { "$($_.Name): $($_.Count)  (last $(($_.Group | Sort-Object Time -Descending | Select-Object -First 1).Time))" })
            ''
            'Faulting modules:'
            ($c | Where-Object { $_.Module } | Group-Object { "$($_.App) -> $($_.Module)" } | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { "  [$($_.Count)x] $($_.Name)" })
        )
        $metrics = @{ ShellCrashes = $c.Count }
        if (-not $c) { return New-Result OK "No shell crashes/hangs in $LookbackDays days." 'None.' -Metrics $metrics }
        $exp = @($c | Where-Object { $_.App -eq 'explorer.exe' }).Count
        $fix = Format-Steps @(
            'Look at the faulting module in the evidence.'
            'Third-party DLL (shell extension, context-menu handler, antivirus hook): update or remove that software; ShellExView can disable single shell extensions for testing.'
            'Windows module (e.g. twinui, Windows.UI.Xaml): check UPD-01 / UPD-03 and install the latest cumulative update.'
        )
        $impact = Format-Bullets @(
            'Removing or disabling a shell extension removes its features for all users (context-menu entries, sync icons, archive tools).'
            'Updates for third-party software or Windows usually require a reboot.'
        )
        if ($exp -ge 3) { return New-Result Problem "explorer.exe crashed/hung $exp times in $LookbackDays days - a crashing Explorer leaves users on a black desktop." $detail $fix -Impact $impact -Metrics $metrics }
        New-Result Warning "$($c.Count) shell component crash(es)/hang(s) in $LookbackDays days." $detail $fix -Impact $impact -Metrics $metrics
    }

Register-Check -Id 'SHL-02' -Category 'Shell' -Weight 2 `
    -Name 'Windows Search (per-user index on session hosts)' `
    -AppliesTo { param($E) $E.Build -ge 17763 -and $E.IsSessionHost } `
    -NotApplicableReason 'Per-user search index behaviour applies to Server 2019+ / multi-session session hosts.' `
    -Test {
        param($E)
        $svc = Get-Service WSearch -ErrorAction SilentlyContinue
        $perUser = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows Search' 'EnablePerUserCatalog'
        $dbDir = Join-Path $env:ProgramData 'Microsoft\Search\Data\Applications\Windows'
        $db = @(Get-ChildItem $dbDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^Windows\.(edb|db)$' })
        $gb = [math]::Round((($db | Measure-Object Length -Sum).Sum) / 1GB, 2)
        $err = @(Get-Events -LogName 'Application' -ProviderName 'Microsoft-Windows-Search' -Level 2 -Max 500).Count
        $detail = Join-Lines @("WSearch: $(if ($svc) { "$($svc.Status) / $($svc.StartType)" } else { 'not installed' })", "EnablePerUserCatalog: $perUser", "Index DB size: $gb GB", "Search errors: $err")
        $metrics = @{ SearchIndexGB = $gb }
        if (-not $svc) { return New-Result Info 'Windows Search is not installed.' $detail }
        if ($gb -ge 5 -or $err -ge 50) {
            $fix = Format-Steps @(
                'Drain the host or do it outside business hours.'
                'Use the one-click fix: it marks the index for reset and restarts Windows Search, which rebuilds the index.'
                'With FSLogix the per-user search data lives in the profile container - no extra setting needed on Server 2019+ / multi-session.'
            )
            $impact = Format-Bullets @(
                'Search results (Start menu, File Explorer, Outlook) are incomplete until the index is rebuilt, which can take hours.'
                'Higher CPU and disk use while the index rebuilds.'
                'Outlook can show "search results may be incomplete" until it is done.'
                'No reboot.'
            )
            $cmd = @'
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Search' -Name SetupCompletedSuccessfully -Value 0 -Type DWord
Restart-Service WSearch -Force
'Windows Search restarted - the index is being rebuilt.'
'@
            $auto = New-AutoFix -Label 'Reset and rebuild the search index' -Changes 'Sets HKLM\SOFTWARE\Microsoft\Windows Search\SetupCompletedSuccessfully = 0 and restarts the Windows Search service.'
            return New-Result Warning "Search index is $gb GB / $err errors - a bloated or corrupt index slows logon and Start/Search." $detail $fix $cmd -Impact $impact -AutoFix $auto -Metrics $metrics
        }
        New-Result OK "Windows Search OK ($gb GB, $err errors)." $detail -Metrics $metrics
    }

Register-Check -Id 'SHL-03' -Category 'Shell' -Weight 2 `
    -Name 'Start menu tile database (TileDataLayer)' `
    -AppliesTo { param($E) $E.Build -eq 14393 } `
    -NotApplicableReason 'TileDataLayer issues only apply to Windows Server 2016 / Windows 10 1607.' `
    -Test {
        param($E)
        $svc = Get-Service tiledatamodelsvc -ErrorAction SilentlyContinue
        $esent = @(Get-Events -LogName 'Application' -ProviderName 'ESENT' -Level 2 -Max 1000 | Where-Object { $_.Message -match 'TileDataLayer' })
        $detail = "tiledatamodelsvc: $(if ($svc) { "$($svc.Status) / $($svc.StartType)" } else { 'missing' }); ESENT errors referencing TileDataLayer: $($esent.Count)"
        if (-not $svc -or $svc.Status -ne 'Running' -or $esent) {
            $fix = Format-Steps @(
                'Use the one-click fix: sets the Tile Data model service to Automatic and starts it.'
                'Install the latest cumulative update for Windows Server 2016.'
                'For a user whose Start menu is broken: while the user is signed out, rename %LOCALAPPDATA%\TileDataLayer in their profile.'
            )
            $impact = Format-Bullets @(
                'Starting the service has no user impact.'
                'Resetting TileDataLayer resets the Start menu tile layout of that user (pinned tiles are lost unless a Start layout is enforced by policy).'
                'The cumulative update requires a reboot.'
            )
            $cmd = "Set-Service tiledatamodelsvc -StartupType Automatic`r`nStart-Service tiledatamodelsvc`r`n'Tile Data model service started.'"
            $auto = $null
            if ($svc) { $auto = New-AutoFix -Label 'Start the Tile Data model service' -Changes 'Sets tiledatamodelsvc to Automatic and starts it.' }
            return New-Result Problem 'Tile Data model service not running or TileDataLayer database errors - classic Server 2016 cause of a black screen / dead Start menu.' $detail $fix $cmd -Impact $impact -AutoFix $auto
        }
        New-Result OK 'Tile data model service running, no database errors.' $detail
    }

Register-Check -Id 'SHL-04' -Category 'Shell' -Weight 1 -Tags 'Image' `
    -Name 'WDDM graphics driver for Remote Desktop' `
    -AppliesTo { param($E) ($E.Build -eq 14393 -or $E.Build -eq 17763) -and ($E.IsRdsh -or $E.IsMultiSession -or $E.IsAvd) } `
    -NotApplicableReason 'Only Windows Server 2016/2019 and Windows 10 1809 multi-session session hosts.' `
    -Test {
        param($E)
        $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        $v = Get-RegValue $p 'fEnableWddmDriver'
        $gpu = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'NVIDIA|AMD|Radeon' })
        $detail = Join-Lines @("fEnableWddmDriver = $(if ($null -eq $v) { '(not set, WDDM enabled)' } else { $v })", "GPU adapters: $(if ($gpu) { ($gpu.Name) -join ', ' } else { 'none' })")
        if ($v -eq 0) { return New-Result OK 'WDDM driver disabled (XDDM in use).' $detail }
        if ($gpu) { return New-Result OK 'WDDM driver enabled - correct for this GPU-enabled host.' $detail }
        $fix = Format-Steps @(
            'Set "Use WDDM graphics display driver for Remote Desktop Connections" to Disabled (Computer > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Remote Session Environment), or use the one-click fix.'
            'Reboot the host (drain first).'
        )
        $impact = Format-Bullets @(
            'Sessions use the older XDDM display driver: no GPU acceleration and some DirectX-heavy applications render slower. Normal office work is unaffected.'
            'Requires a reboot - users are signed out, so drain the host first.'
            'A GPO that sets the opposite value overrides the local change.'
        )
        $cmd = (New-RegBackupCmd -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'TerminalServicesPolicy') + "`r`n" +
               "New-Item -Path '$p' -Force | Out-Null`r`nNew-ItemProperty -Path '$p' -Name fEnableWddmDriver -PropertyType DWord -Value 0 -Force | Out-Null`r`n'WDDM driver disabled - reboot the host.'"
        $auto = New-AutoFix -Label 'Disable the WDDM remote display driver' -Backup -Reboot Required `
            -Changes 'Backs up the Terminal Services policy key and sets fEnableWddmDriver = 0 (DWORD). Does not reboot.'
        New-Result Warning 'The RDP WDDM display driver is enabled (default). On 2016/2019 it is a known cause of black screens at logon/reconnect.' $detail $fix $cmd -Impact $impact -AutoFix $auto
    }

Register-Check -Id 'SHL-05' -Category 'Shell' -Weight 1 `
    -Name 'Printer drivers / Print Spooler' `
    -Test {
        param($E)
        $sp = Get-Service Spooler -ErrorAction SilentlyContinue
        $drivers = @(Get-CimInstance Win32_PrinterDriver -ErrorAction SilentlyContinue)
        $printers = @(Get-CimInstance Win32_Printer -ErrorAction SilentlyContinue)
        $err = @(Get-Events -LogName 'Microsoft-Windows-PrintService/Admin' -Level 2 -Max 1000).Count
        $detail = Join-Lines @("Spooler: $(if ($sp) { $sp.Status } else { 'missing' })", "Printer drivers: $($drivers.Count)", "Printers (all sessions): $($printers.Count)", "PrintService errors: $err", '', ($drivers | ForEach-Object { "  $($_.Name)" }))
        $metrics = @{ PrinterDrivers = $drivers.Count }
        if ($drivers.Count -ge 40 -or $err -ge 50) {
            $fix = Format-Steps @(
                'Remove printer drivers that are no longer used (Print Management > Drivers).'
                'Use Universal Print or the Remote Desktop Easy Print driver instead of many vendor drivers.'
                'If users do not need their local printers in AVD, set the host pool RDP property redirectprinters:i:0.'
                'Map network printers asynchronously (GPP printers with the Update action, not Replace).'
            )
            $impact = Format-Bullets @(
                'Removing a driver removes the printers that use it - check first.'
                'Disabling printer redirection removes the local printers of users from their sessions.'
                'Switching to Universal Print changes how users find and add printers.'
                'No reboot normally; the spooler restarts when drivers are removed.'
            )
            return New-Result Warning "$($drivers.Count) printer drivers / $err spooler errors - printer mapping at logon waits for the spooler." $detail $fix -Impact $impact -Metrics $metrics
        }
        New-Result OK "$($drivers.Count) printer drivers, $err spooler errors." $detail -Metrics $metrics
    }
#endregion

#region Security / System
Register-Check -Id 'SYS-01' -Category 'Security / System' -Weight 2 `
    -Name 'Antivirus / EDR products' `
    -Test {
        param($E)
        $known = [ordered]@{
            'CSFalconService' = 'CrowdStrike Falcon'; 'SentinelAgent' = 'SentinelOne'; 'Sense' = 'Defender for Endpoint (EDR)'
            'cyserver' = 'Palo Alto Cortex XDR'; 'CbDefense' = 'VMware Carbon Black'; 'ds_agent' = 'Trend Micro Deep Security'
            'Sophos MCS Agent' = 'Sophos'; 'SAVService' = 'Sophos AV'; 'ekrn' = 'ESET'; 'McShield' = 'McAfee/Trellix'
            'mfemms' = 'McAfee/Trellix'; 'SepMasterService' = 'Symantec'; 'WRSVC' = 'Webroot'; 'CylanceSvc' = 'Cylance'
            'BDAuxSrv' = 'Bitdefender'; 'EPSecurityService' = 'Bitdefender GravityZone'; 'HarfangLab' = 'HarfangLab'; 'elastic-agent' = 'Elastic'
        }
        $found = @(foreach ($k in $known.Keys) { $s = Get-Service $k -ErrorAction SilentlyContinue; if ($s -and $s.Status -eq 'Running') { $known[$k] } }) | Select-Object -Unique
        $defMode = if ($E.Defender) { "$($E.Defender.AMRunningMode), real-time: $($E.Defender.RealTimeProtectionEnabled)" } else { 'not available' }
        $detail = Join-Lines @("Defender: $defMode", "Other security agents running: $(if ($found) { $found -join ', ' } else { 'none detected' })")
        $thirdAv = @($found | Where-Object { $_ -notmatch 'Defender for Endpoint|CrowdStrike|SentinelOne|Cortex|Carbon Black|Elastic|HarfangLab' })
        if ($E.Defender -and "$($E.Defender.AMRunningMode)" -eq 'Normal' -and $E.Defender.RealTimeProtectionEnabled -and $thirdAv) {
            $fix = Format-Steps @(
                'Decide which product is the primary antivirus.'
                'Put Defender in passive mode (onboarded to Defender for Endpoint: ForceDefenderPassiveMode) or uninstall the second antivirus.'
                'Make sure the remaining product has the FSLogix and AVD exclusions.'
            )
            $impact = Format-Bullets @(
                'Only one engine scans files - less CPU and disk load during logon.'
                'Protection then depends entirely on the remaining product - make sure it is licensed, updated and monitored.'
                'Changing the Defender mode or uninstalling an antivirus may require a reboot.'
            )
            return New-Result Warning "Defender is in active mode alongside $($thirdAv -join ', ') - double real-time scanning at logon." $detail $fix -Impact $impact
        }
        $fix = Format-Steps @(
            'Verify that profile containers (VHDX), FSLogix processes and the AVD agent paths are excluded per vendor guidance.'
            'To prove whether the EDR is the cause, test a logon on a test host with the agent in audit / monitor mode.'
        )
        $impact = Format-Bullets @(
            'Exclusions reduce scanning on those paths - agree them with the security team.'
            'Audit mode lowers protection - only on an isolated test host and for a short time.'
        )
        New-Result Info "Defender: $defMode. Others: $(if ($found) { $found -join ', ' } else { 'none' })." $detail $fix -Impact $impact
    }

Register-Check -Id 'SYS-02' -Category 'Security / System' -Weight 1 `
    -Name 'Uptime' `
    -Test {
        param($E)
        $days = [math]::Round(((Get-Date) - $E.LastBoot).TotalDays, 1)
        $detail = "Last boot: $($E.LastBoot) ($days days)"
        $metrics = @{ UptimeDays = $days }
        if ($days -ge 30 -and $E.IsSessionHost) {
            $fix = Format-Steps @(
                'Schedule regular reboots of the session hosts (nightly or weekly) using drain mode plus a scheduled task, an Azure Automation runbook or your AVD management tool.'
                'Send users a warning message before the reboot.'
            )
            $impact = Format-Bullets @(
                'Users still signed in at reboot time are disconnected and lose unsaved work - choose a time outside business hours and use drain mode.'
                'Regular reboots also finish updates and clear accumulated state (firewall rules, leaked handles, per-user registrations).'
            )
            return New-Result Warning "Up for $days days - leaked handles, firewall rules and per-user registrations accumulate between reboots." $detail $fix -Impact $impact -Metrics $metrics
        }
        New-Result OK "Up for $days days." $detail -Metrics $metrics
    }

Register-Check -Id 'SYS-03' -Category 'Security / System' -Weight 1 `
    -Name 'System drive free space' `
    -Test {
        param($E)
        $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
        $pct = [math]::Round($d.FreeSpace / $d.Size * 100, 1)
        $detail = "{0}: {1:N1} GB free of {2:N1} GB ({3}%)" -f $env:SystemDrive, ($d.FreeSpace / 1GB), ($d.Size / 1GB), $pct
        $fix = Format-Steps @(
            'Remove stale local profiles (PRF-04).'
            'Run Disk Cleanup, or "Dism /Online /Cleanup-Image /StartComponentCleanup".'
            'Clear C:\Windows\Temp and old log files.'
            'Or enlarge the OS disk in Azure.'
        )
        $impact = Format-Bullets @(
            'StartComponentCleanup removes the ability to uninstall superseded updates.'
            'Enlarging the OS disk requires the VM to be stopped (deallocated) - downtime for users on the host.'
            'Deleting profiles: see the impact in PRF-04.'
        )
        $metrics = @{ SystemDriveFreePct = $pct }
        if ($pct -lt 5)  { return New-Result Problem "Only $pct% free on the system drive." $detail $fix -Impact $impact -Metrics $metrics }
        if ($pct -lt 10) { return New-Result Warning "Only $pct% free on the system drive." $detail $fix -Impact $impact -Metrics $metrics }
        New-Result OK "$pct% free." $detail -Metrics $metrics
    }

Register-Check -Id 'AUD-01' -Category 'Security / System' -Weight 0 `
    -Name 'Process auditing for the logon timeline (diagnostic aid)' `
    -Test {
        param($E)
        if (-not $E.IsAdmin) { return New-Result Info 'Run elevated to check process auditing.' 'Reading the Security log requires administrator rights.' }
        $has4688 = @(try { Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = (Get-Date).AddDays(-1) } -MaxEvents 1 -ErrorAction Stop } catch { }).Count -gt 0
        $has4689 = @(try { Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4689; StartTime = (Get-Date).AddDays(-1) } -MaxEvents 1 -ErrorAction Stop } catch { }).Count -gt 0
        $size = $null; try { $size = [math]::Round((Get-WinEvent -ListLog Security -ErrorAction Stop).MaximumSizeInBytes / 1MB) } catch { }
        $detail = Join-Lines @("Process creation events (4688) in the last 24 h: $has4688", "Process termination events (4689) in the last 24 h: $has4689", "Security log maximum size: $size MB")
        if ($has4688 -and $has4689) { return New-Result OK 'Process auditing is on - the logon timeline can show the Userinit and Active Setup phases.' $detail }
        $fix = Format-Steps @(
            'Preferred: GPO Computer > Windows Settings > Security Settings > Advanced Audit Policy > Detailed Tracking > "Audit Process Creation" and "Audit Process Termination" = Success.'
            'Or use the one-click fix on this host (auditpol), which also raises the Security log to 256 MB if it is smaller.'
            'Then use the Logon timeline tab after the next logons.'
        )
        $impact = Format-Bullets @(
            'The Security log gets an event for every process start and stop (several thousand per day on a busy multi-session host), so it wraps sooner - the log size increase compensates.'
            'If Security events are forwarded to Sentinel / a SIEM, ingestion volume (and cost) increases.'
            'Negligible CPU impact; no reboot. A GPO that configures advanced audit policy overrides the local setting.'
        )
        $cmd = @'
auditpol.exe /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null
auditpol.exe /set /subcategory:"{0CCE922C-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null
'Process creation and termination auditing enabled.'
$log = Get-WinEvent -ListLog Security
if ($log.MaximumSizeInBytes -lt 268435456) { wevtutil.exe sl Security /ms:268435456; 'Security log size raised to 256 MB.' }
'@
        $auto = New-AutoFix -Label 'Enable process auditing' -Changes 'Enables success auditing for Process Creation and Process Termination (auditpol) and raises the Security log to 256 MB if smaller.'
        New-Result Info 'Process auditing is off - the logon timeline cannot show the Userinit and Active Setup phases.' $detail $fix $cmd -Impact $impact -AutoFix $auto
    }
#endregion

# ----------------------------------------------------------------------------------------
# Runner / report / history
# ----------------------------------------------------------------------------------------
$StatusOrder = @{ 'Problem' = 0; 'Warning' = 1; 'Error' = 2; 'Info' = 3; 'OK' = 4; 'N/A' = 5 }

function Invoke-AllChecks {
    param($E, [scriptblock]$OnResult, [string[]]$OnlyIds, [string]$Tag)
    $i = 0; $n = $script:Checks.Count
    foreach ($c in $script:Checks) {
        $i++
        if ($OnlyIds -and $OnlyIds -notcontains $c.Id) { continue }
        if ($Tag -and @($c.Tags) -notcontains $Tag) { continue }
        $applies = $true
        if ($c.AppliesTo) { try { $applies = [bool](& $c.AppliesTo $E) } catch { $applies = $false } }
        if (-not $applies) {
            $r = New-Result -Status 'N/A' -Summary $c.NotApplicableReason -Detail "Host: $($E.Family) (build $($E.BuildString)); roles: $($E.Roles)"
        }
        else {
            try {
                $out = @(& $c.Test $E)
                $r = $out | Where-Object { $_ -is [pscustomobject] -and $_.PSObject.Properties['Status'] -and $_.PSObject.Properties['Summary'] } | Select-Object -Last 1
                if (-not $r) { $r = New-Result Error 'Check returned no result.' }
            }
            catch { $r = New-Result Error "Check failed: $($_.Exception.Message)" "$($_.ScriptStackTrace)" }
        }
        if (($r.Status -eq 'Problem' -or $r.Status -eq 'Warning') -and -not $r.Impact) { $r.Impact = $NoChangeImpact }
        $score = 0
        if ($r.Status -eq 'Problem') { $score = 3 * [math]::Max(1, $c.Weight) }
        elseif ($r.Status -eq 'Warning') { $score = [math]::Max(1, $c.Weight) }
        $r | Add-Member -NotePropertyMembers ([ordered]@{
            Id = $c.Id; Category = $c.Category; Name = $c.Name; Weight = $c.Weight; Score = $score; Tags = @($c.Tags)
            SortKey = '{0}{1:D2}{2:D3}' -f $StatusOrder[$r.Status], (99 - $score), $i
        }) -Force
        if ($OnResult) { & $OnResult $r $i $n }
        $r
    }
}

function Get-TopCauses {
    param($Results, [int]$Top = 5)
    $Results | Where-Object { $_.Status -eq 'Problem' -or $_.Status -eq 'Warning' } | Sort-Object Score -Descending | Select-Object -First $Top
}

function Save-ScanHistory {
    param($E, $Results)
    try {
        $dir = Join-Path (Get-ToolDataDir) 'History'
        New-Item -ItemType Directory -Force $dir | Out-Null
        $rec = [ordered]@{
            Time = (Get-Date).ToString('o'); Computer = $E.ComputerName; Build = $E.BuildString; ToolVersion = $ToolVersion
            Results = @($Results | ForEach-Object { [ordered]@{ Id = $_.Id; Status = $_.Status; Summary = $_.Summary; Metrics = $_.Metrics } })
        }
        $file = Join-Path $dir ('scan-{0}-{1}.json' -f $E.ComputerName, (Get-Date -Format 'yyyyMMdd-HHmmss'))
        [System.IO.File]::WriteAllText($file, ($rec | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding $false))
        Get-ChildItem $dir -Filter 'scan-*.json' | Sort-Object Name -Descending | Select-Object -Skip 500 | Remove-Item -Force -ErrorAction SilentlyContinue
        $file
    } catch { $null }
}

# Shared look for the HTML reports (matches the GUI theme)
$ReportCss = @'
body{font-family:"Segoe UI",Arial,sans-serif;margin:0;color:#101828;background:#F5F7FA}
header{background:#fff;border-bottom:1px solid #E4E7EC;padding:20px 28px}
header h1{font-size:20px;margin:0;font-weight:600} header div{color:#475467;font-size:13px;margin-top:6px}
main{padding:20px 28px;max-width:1400px}
.card{background:#fff;border:1px solid #E4E7EC;border-radius:8px;padding:14px 18px;margin-bottom:16px}
table{border-collapse:collapse;width:100%;font-size:13px;background:#fff;border:1px solid #E4E7EC;border-radius:8px}
th,td{border-bottom:1px solid #F2F4F7;padding:9px 12px;text-align:left;vertical-align:top}
th{background:#F9FAFB;color:#667085;font-size:11px;text-transform:uppercase;letter-spacing:.03em}
.st{border-radius:10px;padding:2px 9px;font-weight:600;font-size:11px;white-space:nowrap}
.Problem{background:#FEE4E2;color:#B42318}.Warning{background:#FEF0C7;color:#B54708}.Info{background:#E0EAFF;color:#3538CD}
.OK{background:#DCFAE6;color:#067647}.NA{background:#F2F4F7;color:#475467}.Error{background:#F4EBFF;color:#6941C6}
pre{white-space:pre-wrap;font-family:Consolas,monospace;font-size:12px;margin:6px 0;background:#F9FAFB;border:1px solid #E4E7EC;color:#101828;padding:10px;border-radius:6px}
.impact{background:#FFFAEB;border:1px solid #FEDF89;border-radius:6px;padding:8px 12px;color:#93370D;margin:6px 0}
.auto{background:#EFF4FF;border:1px solid #C7D7FE;border-radius:6px;padding:8px 12px;color:#1849A9;margin:6px 0}
details summary{cursor:pointer;color:#2563EB;margin-top:4px}
.muted{color:#667085}
'@

function Get-StatusCssClass { param([string]$Status) if ($Status -eq 'N/A') { 'NA' } else { $Status } }

function Export-HtmlReport {
    param($E, $Results, [string]$Path)
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $br  = { param($s) (& $enc $s) -replace "`r?`n", '<br>' }
    $top = @(Get-TopCauses $Results)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Logon black screen - $(& $enc $E.ComputerName)</title>
<style>$ReportCss</style></head><body>
<header><h1>Logon black screen analysis - $(& $enc $E.ComputerName)</h1>
<div>$(& $enc $E.Caption) &middot; $(& $enc $E.Family) build $(& $enc $E.BuildString) &middot; $(& $enc $E.Roles)<br>
Scanned $(& $enc $E.ScanTime) as $(& $enc $E.UserName) (admin: $($E.IsAdmin)) &middot; event lookback $($E.LookbackDays) days &middot; tool $ToolVersion</div></header><main>
"@)
    if ($top) {
        [void]$sb.Append('<div class="card"><b>Most likely causes on this host</b><ol>')
        foreach ($t in $top) { [void]$sb.Append("<li><b>$(& $enc $t.Name)</b> - $(& $enc $t.Summary)</li>") }
        [void]$sb.Append('</ol></div>')
    }
    [void]$sb.Append('<table><tr><th>Status</th><th>Check</th><th>Result, fix and impact</th></tr>')
    foreach ($r in ($Results | Sort-Object SortKey)) {
        [void]$sb.Append("<tr><td><span class='st $(Get-StatusCssClass $r.Status)'>$(& $enc $r.Status)</span></td><td><b>$(& $enc $r.Name)</b><br><span class='muted'>$(& $enc $r.Id) - $(& $enc $r.Category)</span></td><td>$(& $enc $r.Summary)")
        if ($r.Fix)     { [void]$sb.Append("<p><b>How to fix</b><br>$(& $br $r.Fix)</p>") }
        if ($r.Impact)  { [void]$sb.Append("<div class='impact'><b>Impact on users and system</b><br>$(& $br $r.Impact)</div>") }
        if ($r.AutoFix) { [void]$sb.Append("<div class='auto'><b>One-click fix available in the GUI:</b> $(& $enc $r.AutoFix.Label)<br>$(& $enc $r.AutoFix.Changes)</div>") }
        if ($r.Detail -or $r.FixCommand) {
            [void]$sb.Append('<details><summary>Evidence and commands</summary>')
            if ($r.Detail)     { [void]$sb.Append("<pre>$(& $enc $r.Detail)</pre>") }
            if ($r.FixCommand) { [void]$sb.Append("<pre>$(& $enc $r.FixCommand)</pre>") }
            [void]$sb.Append('</details>')
        }
        if ($r.Reference) { [void]$sb.Append("<p class='muted'>Reference: $(& $enc $r.Reference)</p>") }
        [void]$sb.Append('</td></tr>')
    }
    [void]$sb.Append('</table></main></body></html>')
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding $true))
}

function ConvertTo-ResultJson {
    param($E, $Results)
    [ordered]@{
        Tool = 'LogonBlackScreenAnalyser'; ToolVersion = $ToolVersion; Computer = $E.ComputerName; Os = $E.Caption; Build = $E.BuildString
        Roles = $E.Roles; ScanTime = (Get-Date).ToString('o')
        Results = @($Results | ForEach-Object { [ordered]@{ Id = $_.Id; Category = $_.Category; Name = $_.Name; Status = $_.Status; Summary = $_.Summary; Fix = $_.Fix; Impact = $_.Impact; OneClickFix = $(if ($_.AutoFix) { $_.AutoFix.Label }); Metrics = $_.Metrics } })
    } | ConvertTo-Json -Depth 5
}
}
#endregion EngineBlock

#region ExtrasBlock
# Timeline, history, undo, baselines, bundle, trace, probe installer, Intune, gate, fleet, Azure
$ExtrasBlock = {
# Extras: logon timeline, probe data, history/undo, baselines, support bundle, trace, probe installer,
# Intune export, image gate, fleet scan, Azure / Graph.
$ToolBase = Join-Path $env:ProgramData 'LogonBlackScreenAnalyzer'

#region Small helpers
function Resolve-Sid {
    param([string]$Sid)
    try { (New-Object System.Security.Principal.SecurityIdentifier $Sid).Translate([System.Security.Principal.NTAccount]).Value } catch { $Sid }
}

function ConvertFrom-IsoDate {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value }
    try { [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime() } catch { $null }
}

function Format-Time { param($Date) if ($Date) { ([datetime]$Date).ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture) } else { '' } }

function Get-Median { param([double[]]$Values) Get-Percentile -Values $Values -Percent 50 }

function Get-Percentile {
    param([double[]]$Values, [double]$Percent)
    $v = @($Values | Where-Object { $null -ne $_ } | Sort-Object)
    if (-not $v) { return $null }
    $idx = [math]::Ceiling(($Percent / 100) * $v.Count) - 1
    if ($idx -lt 0) { $idx = 0 }
    [math]::Round($v[[int]$idx], 1)
}

function Assert-Module {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) { throw "The PowerShell module '$Name' is not installed. Use 'Install missing modules' at the top of the Azure tab, or run:  Install-Module $Name -Scope CurrentUser" }
    Import-Module $Name -ErrorAction Stop
}

# PowerShell modules used by the Azure features (AVD Insights, host pool list, release health)
$RequiredModules = @(
    [pscustomobject]@{ Name = 'Az.Accounts';                    Purpose = 'Azure sign-in (AVD Insights, host pool list)' }
    [pscustomobject]@{ Name = 'Az.OperationalInsights';         Purpose = 'AVD Insights queries (Log Analytics)' }
    [pscustomobject]@{ Name = 'Az.DesktopVirtualization';       Purpose = 'Load session hosts from an AVD host pool (Fleet tab)' }
    [pscustomobject]@{ Name = 'Microsoft.Graph.Authentication'; Purpose = 'Windows release health known issues (Microsoft Graph)' }
)

function Get-RequiredModuleStatus {
    foreach ($m in $RequiredModules) {
        $mod = Get-Module -ListAvailable -Name $m.Name -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
        [pscustomobject]@{ Name = $m.Name; Purpose = $m.Purpose; Installed = [bool]$mod; Version = $(if ($mod) { "$($mod.Version)" } else { '' }) }
    }
}

# Installs the missing modules from the PowerShell Gallery (existing modules are not changed)
function Install-RequiredModules {
    param([switch]$AllUsers)
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $scope = if ($AllUsers) { 'AllUsers' } else { 'CurrentUser' }
    $out = New-Object System.Collections.Generic.List[string]
    $nuget = Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue | Where-Object { $_.Version -ge [version]'2.8.5.201' }
    if (-not $nuget) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope $scope -Force -ErrorAction Stop | Out-Null
        $out.Add('NuGet package provider installed.')
    }
    foreach ($m in @(Get-RequiredModuleStatus | Where-Object { -not $_.Installed })) {
        try {
            Install-Module -Name $m.Name -Repository PSGallery -Scope $scope -Force -AllowClobber -ErrorAction Stop
            $v = (Get-Module -ListAvailable -Name $m.Name | Sort-Object Version -Descending | Select-Object -First 1).Version
            $out.Add("Installed $($m.Name) $v ($scope)")
        } catch { $out.Add("FAILED $($m.Name): $($_.Exception.Message)") }
    }
    if ($out.Count -eq 0) { $out.Add('All required modules are already installed.') }
    $out -join "`r`n"
}
#endregion

#region Tool configuration
# The settings file lives next to the analyser (LogonBlackScreenAnalyser.settings.json, $SettingsPath).
# The probe / report scripts on a host read a small copy (share path + webhook) from ProgramData\...\config.json,
# written when the probe is installed or when settings are saved while the probe is installed.
if (-not $SettingsPath) { $SettingsPath = Join-Path $ToolBase 'LogonBlackScreenAnalyser.settings.json' }
$ProbeConfigPath = Join-Path $ToolBase 'config.json'

function Get-ToolConfig {
    $cfg = [ordered]@{ SharePath = ''; WebhookUrl = ''; WorkspaceId = ''; SubscriptionId = ''; HostPoolResourceGroup = ''; HostPoolName = '' }
    $f = $SettingsPath
    if (-not (Test-Path -LiteralPath $f) -and (Test-Path -LiteralPath $ProbeConfigPath)) { $f = $ProbeConfigPath }   # settings from older versions
    if (Test-Path -LiteralPath $f) {
        try { $j = [System.IO.File]::ReadAllText($f) | ConvertFrom-Json; foreach ($p in $j.PSObject.Properties) { $cfg[$p.Name] = $p.Value } } catch { }
    }
    [pscustomobject]$cfg
}

function Write-ProbeConfig {
    param($Config)
    New-Item -ItemType Directory -Force $ToolBase | Out-Null
    $probe = [ordered]@{ SharePath = $Config.SharePath; WebhookUrl = $Config.WebhookUrl }
    [System.IO.File]::WriteAllText($ProbeConfigPath, ($probe | ConvertTo-Json), (New-Object System.Text.UTF8Encoding $false))
}

# Returns a note about the probe copy (empty when the probe is not installed on this host)
function Save-ToolConfig {
    param($Config)
    [System.IO.File]::WriteAllText($SettingsPath, ($Config | ConvertTo-Json), (New-Object System.Text.UTF8Encoding $false))
    if (Test-Path (Join-Path $ToolBase 'bin\Start-LogonProbe.ps1')) {
        try { Write-ProbeConfig $Config; 'The share path and webhook were also updated for the logon probe on this host.' }
        catch { 'The logon probe on this host still uses the old share path / webhook - save again as administrator to update it.' }
    }
}

function Get-ProbePaths {
    param([string]$Sub = 'Probe')
    $cfg = Get-ToolConfig
    $p = @(Join-Path $ToolBase $Sub)
    if ($cfg.SharePath) { $p += (Join-Path $cfg.SharePath $Sub) }
    $p
}
#endregion

#region Probe / user report data
function Get-ProbeRecords {
    param([string[]]$Paths, [int]$Days = 30, [string]$Type = 'Probe')
    $since = (Get-Date).AddDays(-$Days)
    $seen = @{}
    foreach ($p in @($Paths | Where-Object { $_ } | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $p -Filter '*.json' -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $since })) {
            if ($seen.ContainsKey($f.Name)) { continue }
            $seen[$f.Name] = $true
            try {
                $o = [System.IO.File]::ReadAllText($f.FullName) | ConvertFrom-Json
                if ($Type -and $o.Type -and $o.Type -ne $Type) { continue }
                foreach ($n in 'LogonTime', 'SihostStart', 'ExplorerStart', 'TaskbarReady', 'ProbeStart', 'Time') {
                    if ($o.PSObject.Properties[$n]) { $o | Add-Member -NotePropertyName "${n}Dt" -NotePropertyValue (ConvertFrom-IsoDate $o.$n) -Force }
                }
                $o | Add-Member -NotePropertyName File -NotePropertyValue $f.FullName -Force
                $o
            } catch { }
        }
    }
}

function Get-UserReports {
    param([int]$Days = 60)
    @(Get-ProbeRecords -Paths (Get-ProbePaths 'Reports') -Days $Days -Type 'UserReport') | Sort-Object TimeDt -Descending
}
#endregion

#region Per-logon timeline
function New-Phase {
    param([string]$Name, $Start, $End, [string]$Source)
    if (-not $Start -or -not $End -or $End -lt $Start) { return $null }
    [pscustomobject]@{ Name = $Name; Start = $Start; End = $End; Seconds = [math]::Round(($End - $Start).TotalSeconds, 1); Source = $Source }
}

function Get-PhaseAdvice {
    param($Phase, [bool]$TimedOut)
    if ($TimedOut) { return 'The taskbar never appeared within the probe timeout - Explorer did not start or crashed. See SHL-01, UPD-01 and UPD-03.' }
    if (-not $Phase) { return 'Not enough data for this logon. Install the logon probe (Tools tab) and enable process auditing (AUD-01) for a full breakdown.' }
    if ($Phase.Seconds -lt 5) { return "No slow phase in the measured parts of this logon (longest: $($Phase.Name), $($Phase.Seconds) s). If the user still saw a long black screen, the time was spent in a phase that was not measured - install the logon probe (Tools tab) and enable process auditing (AUD-01)." }
    switch -Wildcard ($Phase.Name) {
        'Profile load*'    { "Most time was spent loading the profile ($($Phase.Seconds) s). See TIM-03, PRF-01 (FSLogix), PRF-02 (antivirus exclusions) and PRF-04." }
        'Group Policy*'    { "Most time was spent in user Group Policy ($($Phase.Seconds) s). See TIM-01, CFG-02, CFG-03 and NET-03 (domain controller)." }
        'Pre-shell*'       { "Most time was spent between Userinit and Explorer ($($Phase.Seconds) s) - logon scripts and Userinit add-ons. See CFG-03, CFG-05 and NET-01." }
        'Active Setup*'    { "Most time was spent in Active Setup ($($Phase.Seconds) s). See APX-05." }
        'Shell start*'     { "Explorer started but the desktop took $($Phase.Seconds) s to appear - AppX registration, network paths or shell problems. See APX-01, APX-02, NET-01, NET-02, UPD-01, UPD-03 and SHL-01." }
        'Logon to Explorer*' { "Most time passed before Explorer started ($($Phase.Seconds) s) - profile, Group Policy and logon scripts. Enable process auditing (AUD-01) for more detail." }
        'Before profile*'  { "Most time passed between sign-in and profile load ($($Phase.Seconds) s) - session setup, credential providers, RDS. See CFG-09 and UPD-02." }
        default            { '' }
    }
}

function Get-LogonTimelines {
    param([int]$Days = $LookbackDays, [int]$Max = 40, [string[]]$ProbePaths)
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $ups = @(Get-Events -LogName 'Microsoft-Windows-User Profile Service/Operational' -Id 1, 2 -Days $Days -Max 6000 | Sort-Object TimeCreated)
    $gp  = @(Get-Events -LogName 'Microsoft-Windows-GroupPolicy/Operational' -Id 4001, 8001 -Days $Days -Max 6000 | Sort-Object TimeCreated)
    $sh  = @(Get-Events -LogName 'Microsoft-Windows-Shell-Core/Operational' -Id 9705, 9706 -Days $Days -Max 20000 | Sort-Object TimeCreated)
    $probe = @(Get-ProbeRecords -Paths $ProbePaths -Days $Days | Where-Object { $_.Computer -eq $env:COMPUTERNAME })
    $gpEnd = @{}
    foreach ($e in $gp) { if ($e.Id -eq 8001 -and $e.ActivityId) { $gpEnd["$($e.ActivityId)"] = $e } }

    $starts = @($ups | Where-Object { $_.Id -eq 1 -and $_.UserId -and $_.UserId.Value -match '^S-1-(5-21|12-1)-' })
    if ($starts.Count -gt $Max) { $starts = $starts[($starts.Count - $Max)..($starts.Count - 1)] }
    $usedProbe = @{}
    $list = New-Object System.Collections.Generic.List[object]

    foreach ($s in $starts) {
        $sid = $s.UserId.Value; $t0 = $s.TimeCreated; $win = $t0.AddMinutes(15)
        $user = Resolve-Sid $sid
        $phases = New-Object System.Collections.Generic.List[object]
        $hasAudit = $false

        $u2 = $ups | Where-Object { $_.Id -eq 2 -and $_.UserId -and $_.UserId.Value -eq $sid -and $_.TimeCreated -ge $t0 -and $_.TimeCreated -le $win } | Select-Object -First 1
        if ($u2) { $p = New-Phase 'Profile load (incl. FSLogix)' $t0 $u2.TimeCreated 'User Profile Service 1/2'; if ($p) { $phases.Add($p) } }

        $g1 = $gp | Where-Object { $_.Id -eq 4001 -and $_.TimeCreated -ge $t0.AddSeconds(-10) -and $_.TimeCreated -le $win -and ((Get-EventDataMap $_)['PrincipalSamName'] -eq $user) } | Select-Object -First 1
        if ($g1 -and $gpEnd.ContainsKey("$($g1.ActivityId)")) { $p = New-Phase 'Group Policy (user)' $g1.TimeCreated $gpEnd["$($g1.ActivityId)"].TimeCreated 'GroupPolicy 4001/8001'; if ($p) { $phases.Add($p) } }

        $userinitT = $null; $explorerT = $null
        if ($isAdmin) {
            $sec = @(try { Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688, 4689; StartTime = $t0.AddSeconds(-30); EndTime = $win } -MaxEvents 5000 -ErrorAction Stop } catch { })
            if ($sec) {
                $hasAudit = $true
                $created = foreach ($e in ($sec | Where-Object { $_.Id -eq 4688 })) {
                    $m = Get-EventDataMap $e
                    [pscustomobject]@{ Time = $e.TimeCreated; Name = [string]$m['NewProcessName']; ProcId = [string]$m['NewProcessId']; Subject = [string]$m['SubjectUserSid']; Target = [string]$m['TargetUserSid'] }
                }
                $ended = @{}
                foreach ($e in ($sec | Where-Object { $_.Id -eq 4689 })) { $m = Get-EventDataMap $e; $ended[[string]$m['ProcessId']] = $e.TimeCreated }
                $mine = @($created | Where-Object { $_.Subject -eq $sid -or $_.Target -eq $sid } | Sort-Object Time)
                $pUi = $mine | Where-Object { $_.Name -like '*\userinit.exe' } | Select-Object -First 1
                $pEx = $mine | Where-Object { $_.Name -like '*\explorer.exe' } | Select-Object -First 1
                if ($pUi) { $userinitT = $pUi.Time }
                if ($pEx) { $explorerT = $pEx.Time }
                $p = New-Phase 'Pre-shell (Userinit, logon scripts)' $userinitT $explorerT 'Security 4688'; if ($p) { $phases.Add($p) }
                $ro = $mine | Where-Object { $_.Name -like '*\runonce.exe' } | Select-Object -First 1
                if ($ro -and $ended.ContainsKey($ro.ProcId)) { $p = New-Phase 'Active Setup (runonce)' $ro.Time $ended[$ro.ProcId] 'Security 4688/4689'; if ($p) { $phases.Add($p) } }
            }
        }

        $pr = $probe | Where-Object { $_.UserSid -eq $sid -and $_.LogonTimeDt -and [math]::Abs(($_.LogonTimeDt - $t0).TotalSeconds) -le 300 } | Select-Object -First 1
        if ($pr) { $usedProbe[$pr.File] = $true; if (-not $explorerT -and $pr.ExplorerStartDt) { $explorerT = $pr.ExplorerStartDt } }

        $r1 = $sh | Where-Object { $_.Id -eq 9705 -and $_.UserId -and $_.UserId.Value -eq $sid -and $_.TimeCreated -ge $t0 -and $_.TimeCreated -le $win } | Select-Object -First 1
        $r2 = $null
        if ($r1) { $r2 = $sh | Where-Object { $_.Id -eq 9706 -and $_.UserId -and $_.UserId.Value -eq $sid -and $_.TimeCreated -ge $r1.TimeCreated } | Select-Object -First 1 }

        $desktop = $null; $src = 'Not measured'
        if ($pr -and $pr.TaskbarReadyDt) { $desktop = $pr.TaskbarReadyDt; $src = 'Logon probe (taskbar visible)' }
        elseif ($r1) { $desktop = $r1.TimeCreated; $src = 'Shell-Core (Run keys started)' }
        elseif ($explorerT) { $desktop = $explorerT; $src = 'Explorer start (lower bound)' }

        $start = $t0
        if ($pr -and $pr.LogonTimeDt -and $pr.LogonTimeDt -lt $t0) {
            $start = $pr.LogonTimeDt
            $p = New-Phase 'Before profile load (sign-in, session setup)' $start $t0 'Logon probe'; if ($p -and $p.Seconds -gt 0) { $phases.Insert(0, $p) }
        }
        if ($explorerT -and $desktop -and $desktop -gt $explorerT) { $p = New-Phase 'Shell start to desktop' $explorerT $desktop $src; if ($p) { $phases.Add($p) } }
        if ($r1 -and $r2) { $p = New-Phase 'Run keys (after desktop)' $r1.TimeCreated $r2.TimeCreated 'Shell-Core 9705/9706'; if ($p) { $phases.Add($p) } }

        $timedOut = [bool]($pr -and $pr.TimedOut)
        $big = @($phases | Where-Object { $_.Name -notlike 'Run keys*' } | Sort-Object Seconds -Descending) | Select-Object -First 1
        $list.Add([pscustomobject]@{
            Time = $start; User = $user; Sid = $sid; Computer = $env:COMPUTERNAME
            TotalSec = $(if ($desktop) { [math]::Round(($desktop - $start).TotalSeconds, 1) } else { $null })
            DesktopSource = $src; TimedOut = $timedOut; Phases = @($phases | Sort-Object Start)
            Biggest = $(if ($big) { $big.Name } else { '' }); Advice = (Get-PhaseAdvice $big $timedOut)
            HasAudit = $hasAudit; HasProbe = [bool]$pr
        })
    }

    # Probe-only logons (e.g. the Operational log has already rolled over)
    foreach ($pr in $probe) {
        if ($usedProbe.ContainsKey($pr.File) -or -not $pr.LogonTimeDt) { continue }
        $phases = New-Object System.Collections.Generic.List[object]
        $p = New-Phase 'Logon to Explorer start' $pr.LogonTimeDt $pr.ExplorerStartDt 'Logon probe'; if ($p) { $phases.Add($p) }
        $p = New-Phase 'Shell start to desktop' $pr.ExplorerStartDt $pr.TaskbarReadyDt 'Logon probe'; if ($p) { $phases.Add($p) }
        $big = @($phases | Sort-Object Seconds -Descending) | Select-Object -First 1
        $list.Add([pscustomobject]@{
            Time = $pr.LogonTimeDt; User = $pr.User; Sid = $pr.UserSid; Computer = $pr.Computer
            TotalSec = $pr.TimeToDesktopSec; DesktopSource = $(if ($pr.TaskbarReadyDt) { 'Logon probe (taskbar visible)' } else { 'Not measured' })
            TimedOut = [bool]$pr.TimedOut; Phases = @($phases); Biggest = $(if ($big) { $big.Name } else { '' })
            Advice = (Get-PhaseAdvice $big ([bool]$pr.TimedOut)); HasAudit = $false; HasProbe = $true
        })
    }
    @($list | Sort-Object Time -Descending)
}
#endregion

#region Scan history, fix history and undo
function Get-ScanHistory {
    param([int]$Max = 200)
    $dir = Join-Path (Get-ToolDataDir) 'History'
    foreach ($f in @(Get-ChildItem $dir -Filter 'scan-*.json' -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First $Max)) {
        try {
            $o = [System.IO.File]::ReadAllText($f.FullName) | ConvertFrom-Json
            $o | Add-Member -NotePropertyName TimeDt -NotePropertyValue (ConvertFrom-IsoDate $o.Time) -Force
            $o
        } catch { }
    }
}

function Write-FixHistory {
    param([string]$CheckId, [string]$Label, [bool]$Success, [string]$ErrorText, [string]$Output, [string]$Kind = 'Fix')
    try {
        $backups = @([regex]::Matches([string]$Output, 'Backup written to (\S+?\.(?:reg|absent\.txt))') | ForEach-Object { $_.Groups[1].Value })
        $rec = [ordered]@{
            Time = (Get-Date).ToString('o'); Kind = $Kind; Computer = $env:COMPUTERNAME; User = "$env:USERDOMAIN\$env:USERNAME"
            CheckId = $CheckId; Label = $Label; Success = $Success; Error = $ErrorText; Backups = $backups; Output = $Output
        }
        Add-Content -Path (Join-Path (Get-ToolDataDir) 'FixHistory.jsonl') -Value ($rec | ConvertTo-Json -Compress -Depth 3) -Encoding UTF8
    } catch { }
}

function Get-FixHistory {
    $f = Join-Path (Get-ToolDataDir) 'FixHistory.jsonl'
    if (-not (Test-Path $f)) { return }
    $i = 0
    foreach ($l in (Get-Content $f -Encoding UTF8)) {
        if (-not $l.Trim()) { continue }
        try {
            $o = $l | ConvertFrom-Json
            $o | Add-Member -NotePropertyName TimeDt -NotePropertyValue (ConvertFrom-IsoDate $o.Time) -Force
            $o | Add-Member -NotePropertyName Line -NotePropertyValue $i -Force
            $o
        } catch { }
        $i++
    }
}

# Restores a registry key to exactly the state in the backup (or deletes it when it did not exist)
function Restore-RegBackup {
    param([Parameter(Mandatory)][string]$File)
    if (-not (Test-Path -LiteralPath $File)) { throw "Backup file not found: $File" }
    $bk = Join-Path $ToolBase 'Backups'
    New-Item -ItemType Directory -Force $bk | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    if ($File -like '*.absent.txt') {
        $full = ([System.IO.File]::ReadAllText($File)).Trim()
        if (Test-Path -LiteralPath "Registry::$full") {
            $pre = Join-Path $bk "PreUndo-$stamp.reg"
            reg.exe export ($full -replace '^HKEY_LOCAL_MACHINE', 'HKLM' -replace '^HKEY_CURRENT_USER', 'HKCU') $pre /y | Out-Null
            Remove-Item -LiteralPath "Registry::$full" -Recurse -Force
            return "Deleted $full again (it did not exist before the fix). Its state before the undo was saved to $pre."
        }
        return "$full does not exist - nothing to undo."
    }
    $header = Get-Content -LiteralPath $File -TotalCount 10 | Where-Object { $_ -match '^\[(HKEY_[^\]]+)\]' } | Select-Object -First 1
    if (-not $header -or $header -notmatch '^\[(HKEY_[^\]]+)\]') { throw 'Could not read the registry key from the backup file.' }
    $full = $Matches[1]
    $short = $full -replace '^HKEY_LOCAL_MACHINE', 'HKLM' -replace '^HKEY_CURRENT_USER', 'HKCU'
    $pre = Join-Path $bk "PreUndo-$stamp.reg"
    if (Test-Path -LiteralPath "Registry::$full") {
        reg.exe export $short $pre /y | Out-Null
        Remove-Item -LiteralPath "Registry::$full" -Recurse -Force
    }
    $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\reg.exe') -ArgumentList @('import', "`"$File`"") -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode -ne 0) { throw "reg import failed with exit code $($p.ExitCode). The state before the undo is in $pre." }
    "Restored $full from $(Split-Path $File -Leaf). Its state before the undo was saved to $pre."
}
#endregion

#region Host snapshot (baseline) and compare
function Get-HostSnapshot {
    param($Results)
    $snap = [ordered]@{}
    $add = { param($cat, $item, $val) if (-not $snap.Contains($cat)) { $snap[$cat] = [ordered]@{} }; $snap[$cat][[string]$item] = [string]$val }
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    & $add 'Windows' 'Edition' $cv.EditionID
    & $add 'Windows' 'Build' "$($cv.CurrentBuildNumber).$($cv.UBR)"
    foreach ($h in @(Get-HotFix -ErrorAction SilentlyContinue)) { & $add 'Updates' $h.HotFixID 'installed' }
    foreach ($s in @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '_[0-9a-f]{4,8}$' })) {
        $v = "$($s.StartType)"; if ($v -eq 'Automatic') { $v += " / $($s.Status)" }
        & $add 'Services' $s.Name $v
    }
    foreach ($p in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                   'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce') {
        if (Test-Path $p) { $k = Get-Item $p; foreach ($n in $k.GetValueNames()) { & $add 'Run keys' "$((Split-Path $p -Leaf))\$n" $k.GetValue($n) } }
    }
    foreach ($root in 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components') {
        foreach ($k in @(Get-ChildItem $root -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
            if ($p.StubPath) { & $add 'Active Setup' $k.PSChildName "$($p.'(default)') | v$($p.Version) | $($p.StubPath)" }
        }
    }
    foreach ($e in @(Get-UninstallEntry '*')) { if ($e.DisplayName) { & $add 'Installed programs' $e.DisplayName $e.DisplayVersion } }
    try { foreach ($a in @(Get-AppxProvisionedPackage -Online -ErrorAction Stop)) { & $add 'Provisioned apps' $a.DisplayName $a.Version } } catch { }
    $count = 0
    foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Policies' -Recurse -ErrorAction SilentlyContinue)) {
        foreach ($n in $k.GetValueNames()) {
            if ($count++ -gt 5000) { break }
            $v = $k.GetValue($n); if ($n -match 'pass|secret|token|key$') { $v = '***' }
            & $add 'Machine policies' "$($k.Name -replace '^HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\', '')\$n" ($(if ($v -is [array]) { $v -join ';' } else { $v }))
        }
    }
    foreach ($root in 'HKLM:\SOFTWARE\FSLogix\Profiles', 'HKLM:\SOFTWARE\Policies\FSLogix\Profiles') {
        if (Test-Path $root) { $k = Get-Item $root; foreach ($n in $k.GetValueNames()) { & $add 'FSLogix' "$((Split-Path (Split-Path $root) -Leaf))\$n" $k.GetValue($n) } }
    }
    $wl = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    foreach ($n in 'Userinit', 'Shell', 'EnableFirstLogonAnimation') { & $add 'Winlogon' $n $wl.GetValue($n) }
    foreach ($n in 'DelayedDesktopSwitchTimeout', 'EnableFirstLogonAnimation', 'VerboseStatus', 'DisableStatusMessages') {
        $v = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' $n; if ($null -ne $v) { & $add 'Winlogon' "Policies\System\$n" $v }
    }
    foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers' -ErrorAction SilentlyContinue)) {
        & $add 'Credential providers' $k.PSChildName (Get-RegValue "HKLM:\SOFTWARE\Classes\CLSID\$($k.PSChildName)\InprocServer32" '(default)')
    }
    $appr = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved'
    if (Test-Path $appr) { $k = Get-Item $appr; foreach ($n in $k.GetValueNames()) { & $add 'Shell extensions' $n $k.GetValue($n) } }
    try {
        foreach ($l in @(& { $ErrorActionPreference = 'Continue'; fltmc.exe filters 2>$null } | Select-Object -Skip 3)) {
            if ($l -match '^(\S+)\s+\d+\s+([\d\.]+)') { & $add 'Filter drivers' $Matches[1] "altitude $($Matches[2])" }
        }
    } catch { }
    foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })) { & $add 'Scheduled tasks' "$($t.TaskPath)$($t.TaskName)" "$($t.State)" }
    foreach ($r in @($Results)) { if ($r.Id) { & $add 'Check results' "$($r.Id) $($r.Name)" $r.Status } }
    [pscustomobject]@{ Tool = 'LogonBlackScreenAnalyser'; Version = $ToolVersion; Computer = $env:COMPUTERNAME; Time = (Get-Date).ToString('o'); Snapshot = $snap }
}

function Get-Pairs {
    param($Object)
    $h = [ordered]@{}
    if ($null -eq $Object) { return $h }
    if ($Object -is [System.Collections.IDictionary]) { foreach ($k in $Object.Keys) { $h[[string]$k] = $Object[$k] } }
    else { foreach ($p in $Object.PSObject.Properties) { $h[$p.Name] = $p.Value } }
    $h
}

function Compare-HostSnapshot {
    param($Baseline, $Current)
    $b = Get-Pairs $Baseline.Snapshot; $c = Get-Pairs $Current.Snapshot
    $cats = @($b.Keys) + @($c.Keys) | Select-Object -Unique
    foreach ($cat in $cats) {
        $bi = Get-Pairs $b[$cat]; $ci = Get-Pairs $c[$cat]
        foreach ($item in (@($bi.Keys) + @($ci.Keys) | Select-Object -Unique | Sort-Object)) {
            $inB = $bi.Contains($item); $inC = $ci.Contains($item)
            if ($inB -and $inC) {
                if ([string]$bi[$item] -ne [string]$ci[$item]) { [pscustomobject]@{ Category = $cat; Item = $item; Baseline = [string]$bi[$item]; ThisHost = [string]$ci[$item]; Change = 'Different' } }
            }
            elseif ($inC) { [pscustomobject]@{ Category = $cat; Item = $item; Baseline = ''; ThisHost = [string]$ci[$item]; Change = 'Only on this host' } }
            else { [pscustomobject]@{ Category = $cat; Item = $item; Baseline = [string]$bi[$item]; ThisHost = ''; Change = 'Only on baseline' } }
        }
    }
}
#endregion

#region Support bundle and logon trace
function New-SupportBundle {
    param($E, $Results, [string]$OutDir, [int]$Days = $LookbackDays, [switch]$IncludeSecurity, [string]$TracePath)
    if (-not $OutDir) { $OutDir = Join-Path (Get-ToolDataDir) 'Bundles' }
    New-Item -ItemType Directory -Force $OutDir | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $work = Join-Path $env:TEMP "LBS-Bundle-$env:COMPUTERNAME-$stamp"
    foreach ($d in $work, "$work\EventLogs", "$work\FSLogix", "$work\ToolData", "$work\System") { New-Item -ItemType Directory -Force $d | Out-Null }
    $notes = New-Object System.Collections.Generic.List[string]
    try { Export-HtmlReport -E $E -Results $Results -Path "$work\Report.html" } catch { $notes.Add("Report: $($_.Exception.Message)") }
    try { [System.IO.File]::WriteAllText("$work\Results.json", (ConvertTo-ResultJson -E $E -Results $Results)) } catch { }
    try {
        $p = Start-Process gpresult.exe -ArgumentList @('/h', "`"$work\System\gpresult.html`"", '/f') -WindowStyle Hidden -PassThru
        if (-not $p.WaitForExit(180000)) { try { $p.Kill() } catch { }; $notes.Add('gpresult timed out') }
    } catch { $notes.Add("gpresult: $($_.Exception.Message)") }
    $ms = [int64]$Days * 86400000
    $logs = @('Application', 'System', 'Microsoft-Windows-User Profile Service/Operational', 'Microsoft-Windows-GroupPolicy/Operational',
              'Microsoft-Windows-Winlogon/Operational', 'Microsoft-Windows-Shell-Core/Operational', 'Microsoft-Windows-AppXDeploymentServer/Operational',
              'Microsoft-Windows-AppReadiness/Admin', 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
              'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin', 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
              'Microsoft-FSLogix-Apps/Operational', 'Microsoft-Windows-User Device Registration/Admin')
    if ($IncludeSecurity) { $logs += 'Security' }
    foreach ($l in $logs) {
        $file = Join-Path "$work\EventLogs" (($l -replace '[\\/:*?"<>| ]', '_') + '.evtx')
        & { $ErrorActionPreference = 'Continue'; wevtutil.exe epl "$l" "$file" "/q:*[System[TimeCreated[timediff(@SystemTime)<=$ms]]]" /ow:true 2>$null }
    }
    $since = (Get-Date).AddDays(-$Days)
    $fsl = Join-Path $env:ProgramData 'FSLogix\Logs'
    if (Test-Path $fsl) {
        foreach ($f in @(Get-ChildItem $fsl -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $since })) {
            $dest = Join-Path "$work\FSLogix" ($f.FullName.Substring($fsl.Length).TrimStart('\'))
            New-Item -ItemType Directory -Force (Split-Path $dest) | Out-Null
            Copy-Item $f.FullName $dest -ErrorAction SilentlyContinue
        }
    }
    $dd = Get-ToolDataDir
    Copy-Item (Join-Path $dd 'FixHistory.jsonl') "$work\ToolData" -ErrorAction SilentlyContinue
    foreach ($sub in 'History', 'Probe', 'Reports') {
        $src = Join-Path $ToolBase $sub; if ($sub -eq 'History') { $src = Join-Path $dd $sub }
        if (Test-Path $src) {
            New-Item -ItemType Directory -Force "$work\ToolData\$sub" | Out-Null
            Get-ChildItem $src -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $since } | Sort-Object LastWriteTime -Descending | Select-Object -First 200 | Copy-Item -Destination "$work\ToolData\$sub" -ErrorAction SilentlyContinue
        }
    }
    & { $ErrorActionPreference = 'Continue'; dsregcmd.exe /status 2>&1 } | Out-File "$work\System\dsregcmd.txt" -Encoding UTF8
    & { $ErrorActionPreference = 'Continue'; systeminfo.exe 2>&1 } | Out-File "$work\System\systeminfo.txt" -Encoding UTF8
    Get-HotFix -ErrorAction SilentlyContinue | Select-Object HotFixID, Description, InstalledOn | Export-Csv "$work\System\hotfixes.csv" -NoTypeInformation
    Get-Service | Select-Object Name, DisplayName, Status, StartType | Export-Csv "$work\System\services.csv" -NoTypeInformation
    if ($TracePath -and (Test-Path $TracePath)) { Copy-Item $TracePath "$work\System" -ErrorAction SilentlyContinue }
    if ($notes.Count) { $notes | Out-File "$work\notes.txt" -Encoding UTF8 }
    $zip = Join-Path $OutDir "LogonBlackScreen-Bundle-$env:COMPUTERNAME-$stamp.zip"
    Compress-Archive -Path "$work\*" -DestinationPath $zip -Force
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
    $zip
}

function Get-WprPath {
    $w = Join-Path $env:SystemRoot 'System32\wpr.exe'
    if (-not (Test-Path $w)) { throw 'wpr.exe (Windows Performance Recorder) is not available on this Windows version.' }
    $w
}

function Start-LogonTrace {
    $w = Get-WprPath
    $o = (& { $ErrorActionPreference = 'Continue'; & $w -start GeneralProfile -start Registry -filemode 2>&1 }) | Out-String
    if ($LASTEXITCODE -ne 0) { throw "wpr failed: $($o.Trim())" }
    'Trace recording started.'
}

function Stop-LogonTrace {
    param([string]$OutFile)
    $w = Get-WprPath
    if (-not $OutFile) { $dir = Join-Path (Get-ToolDataDir) 'Traces'; New-Item -ItemType Directory -Force $dir | Out-Null; $OutFile = Join-Path $dir "logon-$env:COMPUTERNAME-$(Get-Date -Format yyyyMMdd-HHmmss).etl" }
    $o = (& { $ErrorActionPreference = 'Continue'; & $w -stop $OutFile 2>&1 }) | Out-String
    if ($LASTEXITCODE -ne 0) { throw "wpr failed: $($o.Trim())" }
    $OutFile
}
#endregion

#region Logon probe installer
function Get-UsersGroupName { try { (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-545').Translate([System.Security.Principal.NTAccount]).Value } catch { 'BUILTIN\Users' } }

function Install-LogonProbe {
    param([Parameter(Mandatory)][string]$ProbeScriptText, [Parameter(Mandatory)][string]$ReportScriptText, [string]$SharePath, [switch]$DesktopShortcut)
    $bin = Join-Path $ToolBase 'bin'
    foreach ($d in $ToolBase, $bin, (Join-Path $ToolBase 'Probe'), (Join-Path $ToolBase 'Reports')) { New-Item -ItemType Directory -Force $d | Out-Null }
    # Users may create files (their own probe / report records) but not change other users' files
    foreach ($d in (Join-Path $ToolBase 'Probe'), (Join-Path $ToolBase 'Reports')) { & icacls.exe $d /grant '*S-1-5-32-545:(CI)(RX,WD,AD)' | Out-Null }
    # The probe and report scripts are embedded in the analyser and written out here
    $utf8Bom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText((Join-Path $bin 'Start-LogonProbe.ps1'), $ProbeScriptText.Trim() + "`r`n", $utf8Bom)
    [System.IO.File]::WriteAllText((Join-Path $bin 'Report-SlowLogon.ps1'), $ReportScriptText.Trim() + "`r`n", $utf8Bom)
    $cfg = Get-ToolConfig
    if ($PSBoundParameters.ContainsKey('SharePath')) { $cfg.SharePath = $SharePath; try { [void](Save-ToolConfig $cfg) } catch { } }
    Write-ProbeConfig $cfg
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $action = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$bin\Start-LogonProbe.ps1`" -Background"
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -GroupId (Get-UsersGroupName) -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 15) -MultipleInstances Parallel
    Register-ScheduledTask -TaskName 'LogonProbe' -TaskPath '\LogonBlackScreenAnalyzer\' -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description 'Logon Black Screen Analyser: measures the time from sign-in until the taskbar is visible for each user logon.' -Force | Out-Null
    $out = @("Probe scripts copied to $bin", 'Scheduled task \LogonBlackScreenAnalyzer\LogonProbe registered (runs at every user logon, as the user, hidden).', "Probe data: $(Join-Path $ToolBase 'Probe')")
    if ($cfg.SharePath) { $out += "Probe data is also copied to $(Join-Path $cfg.SharePath 'Probe')" }
    if ($DesktopShortcut) {
        $ws = New-Object -ComObject WScript.Shell
        $lnk = $ws.CreateShortcut((Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Report slow sign-in.lnk'))
        $lnk.TargetPath = $ps
        $lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$bin\Report-SlowLogon.ps1`""
        $lnk.IconLocation = "$env:SystemRoot\System32\imageres.dll,76"
        $lnk.Description = 'Tell IT that your sign-in was slow or showed a black screen'
        $lnk.Save()
        $out += 'Shortcut "Report slow sign-in" added to the public desktop.'
    }
    $out -join "`r`n"
}

function Uninstall-LogonProbe {
    $out = @()
    $t = Get-ScheduledTask -TaskName 'LogonProbe' -TaskPath '\LogonBlackScreenAnalyzer\' -ErrorAction SilentlyContinue
    if ($t) { Unregister-ScheduledTask -TaskName 'LogonProbe' -TaskPath '\LogonBlackScreenAnalyzer\' -Confirm:$false; $out += 'Scheduled task removed.' }
    $lnk = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Report slow sign-in.lnk'
    if (Test-Path $lnk) { Remove-Item $lnk -Force; $out += 'Desktop shortcut removed.' }
    $bin = Join-Path $ToolBase 'bin'
    if (Test-Path $bin) { Remove-Item $bin -Recurse -Force; $out += 'Probe scripts removed.' }
    $out += 'Collected probe data and user reports were kept.'
    $out -join "`r`n"
}

function Get-LogonProbeStatus {
    $t = Get-ScheduledTask -TaskName 'LogonProbe' -TaskPath '\LogonBlackScreenAnalyzer\' -ErrorAction SilentlyContinue
    $info = $null; if ($t) { $info = $t | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue }
    $dir = Join-Path $ToolBase 'Probe'
    $n = @(Get-ChildItem $dir -Filter '*.json' -ErrorAction SilentlyContinue).Count
    [pscustomobject]@{ Installed = [bool]$t; LastRun = $(if ($info) { $info.LastRunTime }); Records = $n; Shortcut = (Test-Path (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Report slow sign-in.lnk')) }
}
#endregion

#region Intune remediations and image gate
function Export-IntuneRemediations {
    param([Parameter(Mandatory)][string]$OutDir, [Parameter(Mandatory)][string]$EngineText)
    New-Item -ItemType Directory -Force $OutDir | Out-Null
    $utf8 = New-Object System.Text.UTF8Encoding $false
    $checks = @($script:Checks | Where-Object { @($_.Tags) -contains 'Intune' })
    $readme = New-Object System.Collections.Generic.List[string]
    $readme.Add('# Intune remediations - Logon Black Screen Analyser')
    $readme.Add('')
    $readme.Add("Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') by Logon Black Screen Analyser $ToolVersion.")
    $readme.Add('')
    $readme.Add('Each folder contains a detection script and a remediation script. The scripts embed the analyser engine, so the')
    $readme.Add('remediation re-runs the same check on the device and applies exactly the fix that the GUI shows (including the registry backup).')
    $readme.Add('')
    $readme.Add('## Import in Intune')
    $readme.Add('1. Intune admin center > Devices > Scripts and remediations > Remediations > Create.')
    $readme.Add('2. Upload Detect.ps1 as the detection script and Remediate.ps1 as the remediation script.')
    $readme.Add('3. Run this script using the logged-on credentials: **No** (runs as SYSTEM). Run script in 64-bit PowerShell: **Yes**.')
    $readme.Add('4. Assign to the device group with your session hosts, e.g. schedule daily. Test on a validation host pool first.')
    $readme.Add('')
    $readme.Add('Detection exits 1 (needs remediation) only when the check reports a problem that has a one-click fix.')
    $readme.Add('Read the impact of each fix in the analyser GUI before you assign it.')
    $readme.Add('')
    $readme.Add('## Remediations')
    foreach ($c in $checks) {
        $safe = (($c.Name -replace '[^\w\- ]', '') -replace '\s+', ' ').Trim()
        if ($safe.Length -gt 50) { $safe = $safe.Substring(0, 50).Trim() }
        $folder = Join-Path $OutDir "$($c.Id) - $safe"
        New-Item -ItemType Directory -Force $folder | Out-Null
        $header = "# Generated by Logon Black Screen Analyser $ToolVersion on $(Get-Date -Format 'yyyy-MM-dd')`r`n# Check $($c.Id): $($c.Name)`r`n"
        $prefix = "`$LookbackDays = 1`r`n" + $EngineText + "`r`n"
        $detect = $header + "# Detection: exit 1 when the check finds a problem that the remediation can fix.`r`n" + $prefix + @"
`$E = Get-HostEnvironment
`$r = @(Invoke-AllChecks -E `$E -OnlyIds '$($c.Id)') | Select-Object -First 1
Write-Output "`$(`$r.Id) `$(`$r.Status): `$(`$r.Summary)"
if ((`$r.Status -eq 'Problem' -or `$r.Status -eq 'Warning' -or `$r.Status -eq 'Info') -and `$r.AutoFix -and `$r.FixCommand) { exit 1 }
exit 0
"@
        $remed = $header + "# Remediation: re-runs the check and applies its fix command.`r`n" + $prefix + @"
`$E = Get-HostEnvironment
`$r = @(Invoke-AllChecks -E `$E -OnlyIds '$($c.Id)') | Select-Object -First 1
if (-not (`$r.AutoFix -and `$r.FixCommand)) { Write-Output "Nothing to fix: `$(`$r.Status) - `$(`$r.Summary)"; exit 0 }
try {
    `$ErrorActionPreference = 'Stop'
    `$out = & ([scriptblock]::Create(`$r.FixCommand)) 2>&1 | Out-String
    Write-Output `$out.Trim()
    exit 0
} catch { Write-Output "Fix failed: `$(`$_.Exception.Message)"; exit 1 }
"@
        [System.IO.File]::WriteAllText((Join-Path $folder 'Detect.ps1'), $detect, $utf8)
        [System.IO.File]::WriteAllText((Join-Path $folder 'Remediate.ps1'), $remed, $utf8)
        $readme.Add("- **$($c.Id) - $($c.Name)** ($($c.Category))")
    }
    [System.IO.File]::WriteAllText((Join-Path $OutDir 'README.md'), ($readme -join "`r`n"), $utf8)
    $checks.Count
}

function Invoke-ImageGate {
    param($E, [ValidateSet('Problem', 'Warning')][string]$Level = 'Problem')
    $res = @(Invoke-AllChecks -E $E -Tag 'Image')
    $fail = @($res | Where-Object { $_.Status -eq 'Problem' -or $_.Status -eq 'Error' -or ($Level -eq 'Warning' -and $_.Status -eq 'Warning') })
    [pscustomobject]@{ Passed = ($fail.Count -eq 0); Level = $Level; Failed = $fail; Results = $res }
}
#endregion

#region Fleet scan
function Invoke-FleetScan {
    param([Parameter(Mandatory)][string[]]$ComputerName, [pscredential]$Credential, [int]$Days = $LookbackDays, [Parameter(Mandatory)][string]$CoreText, [string]$KnownIssuesText)
    $sb = {
        param($core, $days, $ki)
        $LookbackDays = $days
        $KnownIssuesJson = $ki
        . ([scriptblock]::Create($core))
        $E = Get-HostEnvironment
        $r = @(Invoke-AllChecks -E $E)
        [pscustomobject]@{ Computer = $env:COMPUTERNAME; Env = $E; Results = $r }
    }
    $p = @{ ComputerName = $ComputerName; ScriptBlock = $sb; ArgumentList = @($CoreText, $Days, $KnownIssuesText); ThrottleLimit = 16; ErrorAction = 'SilentlyContinue'; ErrorVariable = 'fleetErr' }
    if ($Credential) { $p.Credential = $Credential }
    $out = @(Invoke-Command @p)
    $failed = @(foreach ($er in @($fleetErr)) {
        $name = $null
        if ($er.TargetObject) { $name = "$($er.TargetObject)" }
        if (-not $name -and $er.OriginInfo) { $name = $er.OriginInfo.PSComputerName }
        [pscustomobject]@{ Computer = $name; Error = $er.Exception.Message }
    })
    [pscustomobject]@{ Hosts = $out; Failed = $failed; Time = Get-Date }
}

function Export-FleetReport {
    param($Fleet, [string]$Path)
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $ids = @($Fleet.Hosts | ForEach-Object { $_.Results } | ForEach-Object { $_.Id } | Select-Object -Unique)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<!doctype html><html><head><meta charset='utf-8'><title>Logon black screen - fleet report</title><style>$ReportCss td.c{text-align:center;padding:4px}</style></head><body>")
    [void]$sb.Append("<header><h1>Logon black screen - fleet report</h1><div>$(@($Fleet.Hosts).Count) host(s) scanned $(& $enc $Fleet.Time), $(@($Fleet.Failed).Count) unreachable</div></header><main>")
    [void]$sb.Append('<div class="card"><table><tr><th>Host</th><th>OS / build</th><th>Problems</th><th>Warnings</th><th>Most likely cause</th></tr>')
    foreach ($h in ($Fleet.Hosts | Sort-Object Computer)) {
        $p = @($h.Results | Where-Object Status -eq 'Problem').Count; $w = @($h.Results | Where-Object Status -eq 'Warning').Count
        $top = Get-TopCauses $h.Results 1
        [void]$sb.Append("<tr><td><b>$(& $enc $h.Computer)</b></td><td>$(& $enc $h.Env.Family) $(& $enc $h.Env.BuildString)</td><td>$p</td><td>$w</td><td>$(if ($top) { (& $enc "$($top.Name): $($top.Summary)") })</td></tr>")
    }
    [void]$sb.Append('</table></div><div class="card" style="overflow-x:auto"><table><tr><th>Host</th>')
    foreach ($id in $ids) { [void]$sb.Append("<th>$(& $enc $id)</th>") }
    [void]$sb.Append('</tr>')
    foreach ($h in ($Fleet.Hosts | Sort-Object Computer)) {
        [void]$sb.Append("<tr><td><b>$(& $enc $h.Computer)</b></td>")
        foreach ($id in $ids) {
            $r = $h.Results | Where-Object Id -eq $id | Select-Object -First 1
            if ($r) { [void]$sb.Append("<td class='c'><span class='st $(Get-StatusCssClass $r.Status)' title='$(& $enc $r.Summary)'>$(& $enc $r.Status)</span></td>") } else { [void]$sb.Append('<td></td>') }
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</table></div>')
    if ($Fleet.Failed) {
        [void]$sb.Append('<div class="card"><b>Hosts that could not be scanned</b><ul>')
        foreach ($f in $Fleet.Failed) { [void]$sb.Append("<li>$(& $enc $f.Computer): $(& $enc $f.Error)</li>") }
        [void]$sb.Append('</ul></div>')
    }
    [void]$sb.Append('</main></body></html>')
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding $true))
}
#endregion

#region Azure (AVD Insights) and Microsoft Graph (Windows release health)
# Azure and Graph calls run in a separate, visible Windows PowerShell window ("helper"). Sign-in dialogs work
# normally there, and the analyser window never blocks: started from inside the WPF app the Azure / Graph
# sign-in can hang and freeze the GUI. The helper writes its result to a temp file that is read back here.
function Assert-ModuleAvailable {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) { throw "The PowerShell module '$Name' is not installed. Use 'Install missing modules' at the top of the Azure tab, or run:  Install-Module $Name -Scope CurrentUser" }
}

function Invoke-HelperProcess {
    param([Parameter(Mandatory)][string]$Code, [string]$Title = 'Working', [int]$TimeoutMinutes = 15)
    $out = Join-Path $env:TEMP ('LBS-helper-{0}.json' -f [guid]::NewGuid().ToString('N'))
    $full = @"
`$Host.UI.RawUI.WindowTitle = 'Logon Black Screen Analyser - $Title'
`$ErrorActionPreference = 'Stop'
`$result = `$null
try {
$Code
    ConvertTo-Json -InputObject @(`$result) -Depth 10 | Set-Content -Path '$out' -Encoding UTF8
    Write-Host 'Done - this window closes by itself.' -ForegroundColor Green
    Start-Sleep -Seconds 1
    exit 0
} catch {
    ('ERROR: ' + `$_.Exception.Message) | Set-Content -Path '$out' -Encoding UTF8
    Write-Host "Failed: `$(`$_.Exception.Message)" -ForegroundColor Red
    Start-Sleep -Seconds 6
    exit 1
}
"@
    $enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($full))
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $p = Start-Process -FilePath $ps -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $enc) -PassThru
    if (-not $p.WaitForExit($TimeoutMinutes * 60000)) { try { $p.Kill() } catch { }; throw "No answer within $TimeoutMinutes minutes - the helper window was closed." }
    if (-not (Test-Path $out)) { throw "The $Title window was closed before it finished." }
    $text = [System.IO.File]::ReadAllText($out).Trim()
    Remove-Item $out -Force -ErrorAction SilentlyContinue
    if ($text -like 'ERROR: *') { throw $text.Substring(7) }
    $parsed = $text | ConvertFrom-Json
    foreach ($x in $parsed) { $x }
}

# Azure sign-in part of every helper: reuses the saved Azure sign-in, signs in interactively only when needed
function Get-AzPrelude {
    param([string]$SubscriptionId, [switch]$ForceSignIn)
    $sub = $SubscriptionId -replace "'", "''"
    $force = if ($ForceSignIn) { '$true' } else { '$false' }
@"
Import-Module Az.Accounts
Enable-AzContextAutosave -Scope CurrentUser | Out-Null
if ($force -or -not (Get-AzContext)) {
    Write-Host 'Sign in to Azure in the window or browser that opens...' -ForegroundColor Cyan
    Connect-AzAccount | Out-Null
}
if ('$sub') { Set-AzContext -Subscription '$sub' | Out-Null }
`$ctx = Get-AzContext
Write-Host "Azure: `$(`$ctx.Account.Id) - `$(`$ctx.Subscription.Name)" -ForegroundColor Cyan
"@
}

function ConvertTo-B64 { param([string]$Text) [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Text)) }

function Connect-ToolAzure {
    param([string]$SubscriptionId)
    Assert-ModuleAvailable 'Az.Accounts'
    $code = (Get-AzPrelude -SubscriptionId $SubscriptionId -ForceSignIn) + "`r`n`$result = [pscustomobject]@{ Account = `$ctx.Account.Id; Subscription = `$ctx.Subscription.Name }"
    $r = Invoke-HelperProcess -Code $code -Title 'Azure sign-in' | Select-Object -First 1
    "$($r.Account) - subscription $($r.Subscription)"
}

function Get-AvdSessionHostNames {
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$HostPool, [string]$SubscriptionId)
    Assert-ModuleAvailable 'Az.Accounts'; Assert-ModuleAvailable 'Az.DesktopVirtualization'
    $code = (Get-AzPrelude -SubscriptionId $SubscriptionId) + @"

Import-Module Az.DesktopVirtualization
Write-Host 'Loading session hosts of host pool $($HostPool -replace "'", '')...' -ForegroundColor Cyan
`$rg = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$(ConvertTo-B64 $ResourceGroup)'))
`$hp = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$(ConvertTo-B64 $HostPool)'))
`$result = @(Get-AzWvdSessionHost -ResourceGroupName `$rg -HostPoolName `$hp | ForEach-Object { (`$_.Name -split '/')[-1] })
"@
    foreach ($n in (Invoke-HelperProcess -Code $code -Title 'AVD host pool')) { if ($n) { [string]$n } }
}

# Connections of one user plus all their checkpoints / errors, in one helper run
function Invoke-AvdInsightsQuery {
    param([Parameter(Mandatory)][string]$WorkspaceId, [Parameter(Mandatory)][string]$User, [int]$Days = 7, [string]$SubscriptionId)
    Assert-ModuleAvailable 'Az.Accounts'; Assert-ModuleAvailable 'Az.OperationalInsights'
    $u = $User -replace "'", "''"
    $q1 = @"
WVDConnections
| where TimeGenerated > ago(${Days}d)
| where UserName =~ '$u'
| summarize Started = min(TimeGenerated), Connected = minif(TimeGenerated, State == 'Connected'), Completed = maxif(TimeGenerated, State == 'Completed'), SessionHost = take_any(SessionHostName), Client = take_any(ClientOS) by CorrelationId
| extend SecondsToConnect = datetime_diff('second', Connected, Started)
| order by Started desc
| take 50
"@
    $q2 = @"
union
  (WVDCheckpoints | where TimeGenerated > ago(${Days}d) | where UserName =~ '$u' | project TimeGenerated, CorrelationId, Kind = 'Checkpoint', Name, Source, Details = tostring(Parameters)),
  (WVDErrors | where TimeGenerated > ago(${Days}d) | where UserName =~ '$u' | project TimeGenerated, CorrelationId, Kind = 'Error', Name = CodeSymbolic, Source, Details = Message)
| order by TimeGenerated asc
| take 5000
"@
    $code = (Get-AzPrelude -SubscriptionId $SubscriptionId) + @"

Import-Module Az.OperationalInsights
Write-Host 'Querying AVD Insights...' -ForegroundColor Cyan
`$ws = '$($WorkspaceId -replace "'", '')'
`$q1 = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$(ConvertTo-B64 $q1)'))
`$q2 = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$(ConvertTo-B64 $q2)'))
`$c = @((Invoke-AzOperationalInsightsQuery -WorkspaceId `$ws -Query `$q1).Results | Select-Object *)
`$k = @((Invoke-AzOperationalInsightsQuery -WorkspaceId `$ws -Query `$q2).Results | Select-Object *)
`$result = [pscustomobject]@{ Connections = `$c; Checkpoints = `$k }
"@
    Invoke-HelperProcess -Code $code -Title 'AVD Insights' | Select-Object -First 1
}

function Get-ReleaseHealthIssues {
    param($E)
    Assert-ModuleAvailable 'Microsoft.Graph.Authentication'
    $code = @'
Import-Module Microsoft.Graph.Authentication
Write-Host 'Signing in to Microsoft Graph (WindowsUpdates.ReadWrite.All)...' -ForegroundColor Cyan
Connect-MgGraph -Scopes 'WindowsUpdates.ReadWrite.All' -NoWelcome
Write-Host 'Loading Windows release health known issues...' -ForegroundColor Cyan
$uri = 'https://graph.microsoft.com/beta/admin/windows/updates/products?$expand=knownIssues($expand=originatingKnowledgeBaseArticle,resolvingKnowledgeBaseArticle)'
$result = @()
do { $resp = Invoke-MgGraphRequest -Method GET -Uri $uri; $result += @($resp.value); $uri = $resp.'@odata.nextLink' } while ($uri)
'@
    $products = @(Invoke-HelperProcess -Code $code -Title 'Windows release health')
    $want = @()
    if ($E.IsServer) { $want = @($products | Where-Object { "$($_.name)" -like 'Windows Server*' -and "$($_.name)" -like "*$(($E.Family -split ' ')[-1])*" }) }
    else { $fam = ($E.Family -split ' ')[0..1] -join ' '; $want = @($products | Where-Object { "$($_.name)" -like "*$fam*" -and "$($_.name)" -like "*$($E.DisplayVersion)*" }) }
    $matched = $true
    if (-not $want) { $want = $products; $matched = $false }
    $rx = 'black screen|sign[- ]?in|logon|log on|explorer|start menu|taskbar|remote desktop|\bRDP\b|Azure Virtual Desktop|FSLogix|profile|shell'
    foreach ($p in $want) {
        foreach ($ki in @($p.knownIssues)) {
            if (-not $ki) { continue }
            $okb = $null; $rkb = $null
            if ($ki.originatingKnowledgeBaseArticle) { $okb = "KB$($ki.originatingKnowledgeBaseArticle.kbNumber)" }
            if ($ki.resolvingKnowledgeBaseArticle) { $rkb = "KB$($ki.resolvingKnowledgeBaseArticle.kbNumber)" }
            $text = "$($ki.title) $($ki.description)"
            [pscustomobject]@{
                Product = $p.name; Title = $ki.title; Status = $ki.status
                Started = ConvertFrom-IsoDate $ki.startDateTime; Updated = ConvertFrom-IsoDate $ki.lastUpdatedDateTime
                OriginatingKB = $okb; ResolvingKB = $rkb
                InstalledHere = $(if ($okb) { $E.HotFixIds -contains $okb } else { $false })
                FixInstalled = $(if ($rkb) { $E.HotFixIds -contains $rkb } else { $false })
                Relevant = ($text -match $rx); MatchedProduct = $matched
                Url = $ki.webViewUrl
                Description = ([System.Net.WebUtility]::HtmlDecode(([string]$ki.description -replace '<[^>]+>', ' ')) -replace '\s+', ' ').Trim()
            }
        }
    }
}
#endregion
}
#endregion ExtrasBlock

#region ProbeBlock
# Logon probe script - written to C:\ProgramData\LogonBlackScreenAnalyzer\bin\Start-LogonProbe.ps1 by -InstallProbe
$ProbeBlock = {
<#
.SYNOPSIS
    Logon probe for the Logon Black Screen Analyser. Measures, for the current user session, the time from
    sign-in until the taskbar is visible - the black screen the user actually experiences - and writes one
    small JSON record per logon.

.DESCRIPTION
    Runs in the user's session (scheduled task at logon, or a user logon script). Without -Background it
    starts itself again detached and returns immediately, so a synchronous logon script never delays Explorer.

    Record fields: Computer, User, UserSid, SessionId, ClientName, OsBuild, LogonTime (from the session
    information in Windows), SihostStart, ExplorerStart, TaskbarReady, TimeToDesktopSec, PreShellSec,
    ShellSec, ProbeLate (the probe started after the taskbar existed), TimedOut (no taskbar within the timeout).

    Output: C:\ProgramData\LogonBlackScreenAnalyzer\Probe (or -OutputPath) and <SharePath>\Probe when a central
    share is configured in C:\ProgramData\LogonBlackScreenAnalyzer\config.json (or -SharePath).
#>
param(
    [string]$OutputPath,
    [string]$SharePath,
    [int]$TimeoutSeconds = 600,
    [switch]$Background
)
$ErrorActionPreference = 'SilentlyContinue'
$base = Join-Path $env:ProgramData 'LogonBlackScreenAnalyzer'
if (-not $OutputPath) { $OutputPath = Join-Path $base 'Probe' }
if (-not $PSBoundParameters.ContainsKey('SharePath')) {
    try { $SharePath = ([System.IO.File]::ReadAllText((Join-Path $base 'config.json')) | ConvertFrom-Json).SharePath } catch { }
}

if (-not $Background) {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $a = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', "`"$PSCommandPath`"", '-Background', '-TimeoutSeconds', $TimeoutSeconds, '-OutputPath', "`"$OutputPath`"")
    if ($SharePath) { $a += @('-SharePath', "`"$SharePath`"") }
    Start-Process -FilePath $ps -ArgumentList $a -WindowStyle Hidden
    return
}

$probeStart = Get-Date
if (-not ('LbsProbe' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class LbsProbe {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WTSINFOW {
        public int State; public int SessionId;
        public int IncomingBytes; public int OutgoingBytes; public int IncomingFrames; public int OutgoingFrames;
        public int IncomingCompressedBytes; public int OutgoingCompressedBytes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string WinStationName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 17)] public string Domain;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)] public string UserName;
        public long ConnectTime; public long DisconnectTime; public long LastInputTime; public long LogonTime; public long CurrentTime;
    }
    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);
    [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr memory);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr FindWindow(string className, string windowName);
    public static DateTime GetLogonTime() {
        IntPtr buf; int len;
        if (!WTSQuerySessionInformationW(IntPtr.Zero, -1, 24, out buf, out len)) return DateTime.MinValue;
        try {
            WTSINFOW info = (WTSINFOW)Marshal.PtrToStructure(buf, typeof(WTSINFOW));
            if (info.LogonTime <= 0) return DateTime.MinValue;
            return DateTime.FromFileTimeUtc(info.LogonTime).ToLocalTime();
        } finally { WTSFreeMemory(buf); }
    }
    public static bool TaskbarExists() { return FindWindow("Shell_TrayWnd", null) != IntPtr.Zero; }
}
'@
}

$sessionId = (Get-Process -Id $PID).SessionId
$logon = [LbsProbe]::GetLogonTime()
if ($logon -eq [datetime]::MinValue) { $logon = $null }

$late = [LbsProbe]::TaskbarExists()
$tray = $null
if (-not $late) {
    $deadline = $probeStart.AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ([LbsProbe]::TaskbarExists()) { $tray = Get-Date; break }
        Start-Sleep -Milliseconds 250
    }
}
$firstStart = { param($name) $p = Get-Process -Name $name -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $sessionId } | Sort-Object StartTime | Select-Object -First 1; if ($p) { $p.StartTime } }
$explorer = & $firstStart 'explorer'
$sihost = & $firstStart 'sihost'
$iso = { param($d) if ($d) { ([datetime]$d).ToString('o') } else { $null } }
$sec = { param($a, $b) if ($a -and $b) { [math]::Round(([datetime]$b - [datetime]$a).TotalSeconds, 1) } else { $null } }
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

$rec = [ordered]@{
    Schema           = 1
    Type             = 'Probe'
    Computer         = $env:COMPUTERNAME
    User             = "$env:USERDOMAIN\$env:USERNAME"
    UserSid          = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    SessionId        = $sessionId
    ClientName       = $env:CLIENTNAME
    OsBuild          = "$($cv.CurrentBuildNumber).$($cv.UBR)"
    LogonTime        = & $iso $logon
    SihostStart      = & $iso $sihost
    ExplorerStart    = & $iso $explorer
    TaskbarReady     = & $iso $tray
    ProbeStart       = & $iso $probeStart
    ProbeLate        = [bool]$late
    TimedOut         = [bool](-not $late -and -not $tray)
    TimeToDesktopSec = & $sec $logon $tray
    PreShellSec      = & $sec $logon $explorer
    ShellSec         = & $sec $explorer $tray
}
$json = $rec | ConvertTo-Json -Compress
$name = '{0}_{1}_{2}_{3}.json' -f $env:COMPUTERNAME, ($env:USERNAME -replace '[^\w\.-]', '_'), (Get-Date -Format 'yyyyMMdd-HHmmss'), $sessionId
$targets = @($OutputPath)
if ($SharePath) { $targets += (Join-Path $SharePath 'Probe') }
foreach ($dir in $targets) {
    try {
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
        [System.IO.File]::WriteAllText((Join-Path $dir $name), $json, (New-Object System.Text.UTF8Encoding $false))
    } catch { }
}
}
#endregion ProbeBlock

#region ReportBlock
# "Report slow sign-in" script - written to C:\ProgramData\LogonBlackScreenAnalyzer\bin\Report-SlowLogon.ps1 by -InstallProbe
$ReportBlock = {
<#
.SYNOPSIS
    "Report slow sign-in" for the Logon Black Screen Analyser. A user clicks the desktop shortcut after a slow
    sign-in or black screen; the script asks for an optional note, collects the timing of the current sign-in
    and quick evidence from the user session, and saves a report for IT (optionally posting to a Teams webhook).

.DESCRIPTION
    Reports are written to C:\ProgramData\LogonBlackScreenAnalyzer\Reports and <SharePath>\Reports when a central
    share is configured. The webhook URL (Teams Workflows "When a webhook request is received") is read from
    C:\ProgramData\LogonBlackScreenAnalyzer\config.json (WebhookUrl).

    -NoUi sends the report without showing any window (for testing / automation).
#>
param(
    [string]$Note,
    [switch]$BlackScreen,
    [switch]$NoUi,
    [string]$OutputPath,
    [string]$SharePath
)
$ErrorActionPreference = 'SilentlyContinue'
$base = Join-Path $env:ProgramData 'LogonBlackScreenAnalyzer'
$cfg = $null
try { $cfg = [System.IO.File]::ReadAllText((Join-Path $base 'config.json')) | ConvertFrom-Json } catch { }
if (-not $OutputPath) { $OutputPath = Join-Path $base 'Reports' }
if (-not $PSBoundParameters.ContainsKey('SharePath') -and $cfg) { $SharePath = $cfg.SharePath }

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

$styles = @'
    <Style x:Key="Btn" TargetType="Button">
      <Setter Property="Foreground" Value="#344054"/><Setter Property="Background" Value="#FFFFFF"/>
      <Setter Property="BorderBrush" Value="#D0D5DD"/><Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="16,7"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Opacity" Value="0.88"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Primary" TargetType="Button" BasedOn="{StaticResource Btn}">
      <Setter Property="Background" Value="#2563EB"/><Setter Property="BorderBrush" Value="#2563EB"/><Setter Property="Foreground" Value="#FFFFFF"/>
    </Style>
'@

function Show-Window {
    param([string]$Xaml)
    [xml]$x = $Xaml.Replace('%STYLES%', $styles)
    [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $x))
}

if (-not $NoUi) {
    $w = Show-Window @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Report a slow sign-in" Width="480" SizeToContent="Height" WindowStartupLocation="CenterScreen" ResizeMode="NoResize"
        FontFamily="Segoe UI" FontSize="13" Background="#FFFFFF" Foreground="#101828" Topmost="True">
  <Window.Resources>
%STYLES%
  </Window.Resources>
  <DockPanel>
    <Border DockPanel.Dock="Bottom" Background="#F9FAFB" BorderBrush="#EAECF0" BorderThickness="0,1,0,0" Padding="20,12">
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="BtnCancel" Style="{StaticResource Btn}" Content="Cancel" Margin="0,0,8,0" IsCancel="True"/>
        <Button x:Name="BtnSend" Style="{StaticResource Primary}" Content="Send to IT" IsDefault="True"/>
      </StackPanel>
    </Border>
    <StackPanel Margin="22,20,22,18">
      <TextBlock Text="Report a slow sign-in" FontSize="17" FontWeight="SemiBold"/>
      <TextBlock TextWrapping="Wrap" Foreground="#475467" Margin="0,6,0,14" Text="This sends the timing of your current sign-in and some technical information about this session to IT, so they can find out why it was slow. It takes a few seconds."/>
      <CheckBox x:Name="ChkBlack" Content="I saw a black screen for a long time" Foreground="#344054" Margin="0,0,0,12"/>
      <TextBlock Text="What happened? (optional)" FontSize="11" FontWeight="SemiBold" Foreground="#667085" Margin="0,0,0,4"/>
      <TextBox x:Name="TxtNote" Height="80" TextWrapping="Wrap" AcceptsReturn="True" Padding="8,6" BorderBrush="#D0D5DD" VerticalScrollBarVisibility="Auto"/>
    </StackPanel>
  </DockPanel>
</Window>
'@
    $script:sendIt = $false
    $w.FindName('BtnSend').Add_Click({ $script:sendIt = $true; $w.Close() })
    $w.FindName('TxtNote').Text = $Note
    [void]$w.ShowDialog()
    if (-not $script:sendIt) { return }
    $Note = $w.FindName('TxtNote').Text
    $BlackScreen = [bool]$w.FindName('ChkBlack').IsChecked
}

# ---- Collect -------------------------------------------------------------------------
if (-not ('LbsProbe' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class LbsProbe {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WTSINFOW {
        public int State; public int SessionId;
        public int IncomingBytes; public int OutgoingBytes; public int IncomingFrames; public int OutgoingFrames;
        public int IncomingCompressedBytes; public int OutgoingCompressedBytes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string WinStationName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 17)] public string Domain;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)] public string UserName;
        public long ConnectTime; public long DisconnectTime; public long LastInputTime; public long LogonTime; public long CurrentTime;
    }
    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);
    [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr memory);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr FindWindow(string className, string windowName);
    public static DateTime GetLogonTime() {
        IntPtr buf; int len;
        if (!WTSQuerySessionInformationW(IntPtr.Zero, -1, 24, out buf, out len)) return DateTime.MinValue;
        try {
            WTSINFOW info = (WTSINFOW)Marshal.PtrToStructure(buf, typeof(WTSINFOW));
            if (info.LogonTime <= 0) return DateTime.MinValue;
            return DateTime.FromFileTimeUtc(info.LogonTime).ToLocalTime();
        } finally { WTSFreeMemory(buf); }
    }
    public static bool TaskbarExists() { return FindWindow("Shell_TrayWnd", null) != IntPtr.Zero; }
}
'@
}
$iso = { param($d) if ($d) { ([datetime]$d).ToString('o') } else { $null } }
$sessionId = (Get-Process -Id $PID).SessionId
$sid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$logon = [LbsProbe]::GetLogonTime(); if ($logon -eq [datetime]::MinValue) { $logon = $null }
$explorer = Get-Process explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $sessionId } | Sort-Object StartTime | Select-Object -First 1
$explorerStart = $null; if ($explorer) { $explorerStart = $explorer.StartTime }

# Probe record of this sign-in, if the logon probe is installed
$probe = $null
foreach ($dir in @((Join-Path $base 'Probe'))) {
    $f = Get-ChildItem $dir -Filter "$($env:COMPUTERNAME)_*_$sessionId.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($f) { try { $p = [System.IO.File]::ReadAllText($f.FullName) | ConvertFrom-Json; if ($p.UserSid -eq $sid) { $probe = $p } } catch { } }
}
$ttd = $null
if ($probe -and $null -ne $probe.TimeToDesktopSec) { $ttd = $probe.TimeToDesktopSec }
elseif ($logon -and $explorerStart) { $ttd = [math]::Round(($explorerStart - $logon).TotalSeconds, 1) }

# Quick evidence from this session
$since = (Get-Date).AddHours(-6); if ($logon -and $logon -lt $since) { $since = $logon.AddMinutes(-5) }
$shellApps = 'explorer.exe', 'sihost.exe', 'ShellExperienceHost.exe', 'StartMenuExperienceHost.exe', 'SearchHost.exe', 'userinit.exe'
$crashes = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1000, 1002; StartTime = $since } -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object { $shellApps -contains [string]$_.Properties[0].Value } | ForEach-Object { "$(& $iso $_.TimeCreated) $($_.Properties[0].Value) $(if ($_.Id -eq 1000) { 'crash ' + $_.Properties[3].Value } else { 'hang' })" })
$paths = @()
foreach ($d in @(Get-ChildItem 'HKCU:\Network' -ErrorAction SilentlyContinue)) { $paths += [pscustomobject]@{ Kind = 'Drive'; Name = "$($d.PSChildName):"; Path = $d.GetValue('RemotePath') } }
$usf = Get-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction SilentlyContinue
if ($usf) { foreach ($n in $usf.GetValueNames()) { $v = [Environment]::ExpandEnvironmentVariables([string]$usf.GetValue($n)); if ($v -like '\\*') { $paths += [pscustomobject]@{ Kind = 'Folder'; Name = $n; Path = $v } } } }
$netEvidence = foreach ($p in $paths) {
    $server = ($p.Path -replace '^\\\\', '').Split('\')[0]
    $ok = $false
    $c = New-Object System.Net.Sockets.TcpClient
    try { $iar = $c.BeginConnect($server, 445, $null, $null); $ok = $iar.AsyncWaitHandle.WaitOne(1500) -and $c.Connected } catch { } finally { $c.Close() }
    "$($p.Kind) $($p.Name) $($p.Path): $(if ($ok) { 'reachable' } else { 'NOT reachable' })"
}
$profileLoad = $null
try {
    $ups = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-User Profile Service/Operational'; Id = 1, 2; StartTime = $since } -MaxEvents 200 -ErrorAction Stop |
        Where-Object { $_.UserId -and $_.UserId.Value -eq $sid } | Sort-Object TimeCreated)
    $u1 = $ups | Where-Object Id -eq 1 | Select-Object -Last 1
    if ($u1) { $u2 = $ups | Where-Object { $_.Id -eq 2 -and $_.TimeCreated -ge $u1.TimeCreated } | Select-Object -First 1; if ($u2) { $profileLoad = [math]::Round(($u2.TimeCreated - $u1.TimeCreated).TotalSeconds, 1) } }
} catch { }

$id = ([guid]::NewGuid().ToString('N')).Substring(0, 8).ToUpper()
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$rec = [ordered]@{
    Schema = 1; Type = 'UserReport'; Id = $id; Time = (Get-Date).ToString('o')
    Computer = $env:COMPUTERNAME; User = "$env:USERDOMAIN\$env:USERNAME"; UserSid = $sid; SessionId = $sessionId; ClientName = $env:CLIENTNAME
    OsBuild = "$($cv.CurrentBuildNumber).$($cv.UBR)"; Note = $Note; BlackScreen = [bool]$BlackScreen
    LogonTime = & $iso $logon; ExplorerStart = & $iso $explorerStart; TaskbarReady = $(if ($probe) { $probe.TaskbarReady })
    TimeToDesktopSec = $ttd; MeasuredBy = $(if ($probe -and $null -ne $probe.TimeToDesktopSec) { 'Logon probe' } elseif ($ttd) { 'Explorer start (lower bound)' } else { 'Not measured' })
    Evidence = [ordered]@{ ProfileLoadSec = $profileLoad; ShellCrashes = @($crashes); NetworkPaths = @($netEvidence); ProbeRecord = $probe }
}
$json = $rec | ConvertTo-Json -Depth 6
$name = '{0}_{1}_{2}_report-{3}.json' -f $env:COMPUTERNAME, ($env:USERNAME -replace '[^\w\.-]', '_'), (Get-Date -Format 'yyyyMMdd-HHmmss'), $id
$saved = @()
foreach ($dir in @($OutputPath, $(if ($SharePath) { Join-Path $SharePath 'Reports' }))) {
    if (-not $dir) { continue }
    try {
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
        [System.IO.File]::WriteAllText((Join-Path $dir $name), $json, (New-Object System.Text.UTF8Encoding $false))
        $saved += $dir
    } catch { }
}

# Optional Teams notification (Teams Workflows webhook expects an Adaptive Card message)
$posted = $false
if ($cfg -and $cfg.WebhookUrl) {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $facts = @(
            @{ title = 'Host'; value = $env:COMPUTERNAME }
            @{ title = 'Time to desktop'; value = $(if ($ttd) { "$ttd s ($($rec.MeasuredBy))" } else { 'not measured' }) }
            @{ title = 'Black screen'; value = $(if ($BlackScreen) { 'Yes' } else { 'No' }) }
            @{ title = 'Client'; value = "$env:CLIENTNAME" }
            @{ title = 'Note'; value = $(if ($Note) { $Note } else { '-' }) }
            @{ title = 'Reference'; value = $id }
        )
        $card = @{ type = 'message'; attachments = @(@{ contentType = 'application/vnd.microsoft.card.adaptive'; content = @{
            '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'; type = 'AdaptiveCard'; version = '1.4'
            body = @(@{ type = 'TextBlock'; size = 'Medium'; weight = 'Bolder'; text = "Slow sign-in reported by $env:USERDOMAIN\$env:USERNAME" }, @{ type = 'FactSet'; facts = $facts })
        } }) }
        Invoke-RestMethod -Uri $cfg.WebhookUrl -Method Post -ContentType 'application/json; charset=utf-8' -Body ([System.Text.Encoding]::UTF8.GetBytes(($card | ConvertTo-Json -Depth 10))) -TimeoutSec 15 | Out-Null
        $posted = $true
    } catch { }
}

if ($NoUi) {
    [pscustomobject]@{ Id = $id; SavedTo = $saved; Posted = $posted; TimeToDesktopSec = $ttd }
    return
}
$msg = if ($saved) { "Thank you - your report was sent to IT.`r`n`r`nReference: $id" } else { "Sorry - the report could not be saved. Please contact IT and mention reference $id." }
[void][System.Windows.MessageBox]::Show($msg, 'Report a slow sign-in', 'OK', $(if ($saved) { 'Information' } else { 'Warning' }))
}
#endregion ReportBlock

#region GuiBlock
# User interface
$GuiBlock = {
# WPF user interface.
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Data, System.Windows.Forms

#region Theme and XAML
# Design tokens: background #F5F7FA, surface #FFFFFF, border #E4E7EC, text #101828 / #475467 / #667085, accent #2563EB
$StylesXaml = @'
    <Style x:Key="BtnBase" TargetType="Button">
      <Setter Property="Foreground" Value="#344054"/>
      <Setter Property="Background" Value="#FFFFFF"/>
      <Setter Property="BorderBrush" Value="#D0D5DD"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="14,7"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="HorizontalContentAlignment" Value="Center"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Opacity" Value="0.88"/></Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="Bd" Property="Opacity" Value="0.75"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="Bd" Property="Opacity" Value="0.45"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="BtnPrimary" TargetType="Button" BasedOn="{StaticResource BtnBase}">
      <Setter Property="Background" Value="#2563EB"/><Setter Property="BorderBrush" Value="#2563EB"/><Setter Property="Foreground" Value="#FFFFFF"/>
    </Style>
    <Style x:Key="BtnSecondary" TargetType="Button" BasedOn="{StaticResource BtnBase}"/>
    <Style x:Key="BtnLink" TargetType="Button" BasedOn="{StaticResource BtnBase}">
      <Setter Property="Background" Value="Transparent"/><Setter Property="BorderBrush" Value="Transparent"/><Setter Property="Foreground" Value="#2563EB"/>
      <Setter Property="Padding" Value="6,4"/>
    </Style>
    <Style x:Key="Tile" TargetType="Button" BasedOn="{StaticResource BtnBase}">
      <Setter Property="Background" Value="#FFFFFF"/><Setter Property="BorderBrush" Value="#E4E7EC"/>
      <Setter Property="Padding" Value="16,12"/><Setter Property="FontWeight" Value="Normal"/>
      <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
    </Style>
    <Style x:Key="CauseBtn" TargetType="Button">
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Background="Transparent" CornerRadius="6" Padding="8,7">
              <ContentPresenter HorizontalAlignment="Stretch"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="#F2F4F7"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="#FFFFFF"/><Setter Property="BorderBrush" Value="#E4E7EC"/>
      <Setter Property="BorderThickness" Value="1"/><Setter Property="CornerRadius" Value="8"/>
    </Style>
    <Style x:Key="CardTitle" TargetType="TextBlock">
      <Setter Property="FontSize" Value="14"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Foreground" Value="#101828"/>
    </Style>
    <Style x:Key="Hint" TargetType="TextBlock">
      <Setter Property="FontSize" Value="12"/><Setter Property="Foreground" Value="#667085"/><Setter Property="TextWrapping" Value="Wrap"/>
    </Style>
    <Style x:Key="Lbl" TargetType="TextBlock">
      <Setter Property="FontSize" Value="11"/><Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Foreground" Value="#667085"/><Setter Property="Margin" Value="0,10,0,4"/>
    </Style>
    <Style x:Key="Ro" TargetType="TextBox">
      <Setter Property="IsReadOnly" Value="True"/><Setter Property="TextWrapping" Value="Wrap"/>
      <Setter Property="BorderThickness" Value="0"/><Setter Property="Background" Value="Transparent"/>
      <Setter Property="Padding" Value="0"/><Setter Property="Margin" Value="0,0,0,8"/>
      <Setter Property="Foreground" Value="#344054"/>
    </Style>
    <Style x:Key="Input" TargetType="TextBox">
      <Setter Property="Padding" Value="8,6"/><Setter Property="BorderBrush" Value="#D0D5DD"/>
      <Setter Property="Background" Value="#FFFFFF"/><Setter Property="Foreground" Value="#101828"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
    </Style>
    <Style x:Key="Code" TargetType="TextBox">
      <Setter Property="IsReadOnly" Value="True"/><Setter Property="FontFamily" Value="Consolas"/><Setter Property="FontSize" Value="12"/>
      <Setter Property="TextWrapping" Value="NoWrap"/><Setter Property="HorizontalScrollBarVisibility" Value="Auto"/>
      <Setter Property="VerticalScrollBarVisibility" Value="Auto"/><Setter Property="Background" Value="#F9FAFB"/>
      <Setter Property="Foreground" Value="#101828"/><Setter Property="BorderBrush" Value="#E4E7EC"/><Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="10"/><Setter Property="MaxHeight" Value="300"/>
    </Style>
'@

$GridStylesXaml = @'
    <Style TargetType="DataGrid">
      <Setter Property="IsReadOnly" Value="True"/><Setter Property="SelectionMode" Value="Single"/><Setter Property="SelectionUnit" Value="FullRow"/>
      <Setter Property="HeadersVisibility" Value="Column"/><Setter Property="GridLinesVisibility" Value="Horizontal"/>
      <Setter Property="HorizontalGridLinesBrush" Value="#F2F4F7"/><Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Background" Value="#FFFFFF"/><Setter Property="RowBackground" Value="#FFFFFF"/>
      <Setter Property="CanUserAddRows" Value="False"/><Setter Property="CanUserResizeRows" Value="False"/>
      <Setter Property="Foreground" Value="#344054"/>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="#F9FAFB"/><Setter Property="Foreground" Value="#667085"/>
      <Setter Property="FontSize" Value="11"/><Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Padding" Value="10,9"/><Setter Property="BorderBrush" Value="#EAECF0"/>
      <Setter Property="BorderThickness" Value="0,0,0,1"/>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="8,6"/>
      <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridCell">
            <Border Background="{TemplateBinding Background}" Padding="{TemplateBinding Padding}">
              <ContentPresenter VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="#EFF4FF"/><Setter Property="Foreground" Value="#101828"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="DataGridRow">
      <Setter Property="MinHeight" Value="36"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#F9FAFB"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="TabItem">
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border x:Name="Bd" Padding="14,10" Margin="0,0,4,0" BorderThickness="0,0,0,2" BorderBrush="Transparent" Background="Transparent"
                    Cursor="Hand" TextElement.Foreground="#667085" TextElement.FontWeight="SemiBold">
              <ContentPresenter ContentSource="Header"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="TextElement.Foreground" Value="#344054"/></Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="#2563EB"/><Setter TargetName="Bd" Property="TextElement.Foreground" Value="#1849A9"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
'@

$StatusPillTemplate = @'
<DataTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <Border x:Name="B" CornerRadius="10" Padding="8,2" Background="#F2F4F7" HorizontalAlignment="Left" VerticalAlignment="Center" ToolTip="{Binding [%COL%]}">
    <TextBlock x:Name="T" Text="{Binding [%COL%]}" Foreground="#475467" FontWeight="SemiBold" FontSize="11"/>
  </Border>
  <DataTemplate.Triggers>
    <DataTrigger Binding="{Binding [%COL%]}" Value="Problem"><Setter TargetName="B" Property="Background" Value="#FEE4E2"/><Setter TargetName="T" Property="Foreground" Value="#B42318"/></DataTrigger>
    <DataTrigger Binding="{Binding [%COL%]}" Value="Warning"><Setter TargetName="B" Property="Background" Value="#FEF0C7"/><Setter TargetName="T" Property="Foreground" Value="#B54708"/></DataTrigger>
    <DataTrigger Binding="{Binding [%COL%]}" Value="Info"><Setter TargetName="B" Property="Background" Value="#E0EAFF"/><Setter TargetName="T" Property="Foreground" Value="#3538CD"/></DataTrigger>
    <DataTrigger Binding="{Binding [%COL%]}" Value="OK"><Setter TargetName="B" Property="Background" Value="#DCFAE6"/><Setter TargetName="T" Property="Foreground" Value="#067647"/></DataTrigger>
    <DataTrigger Binding="{Binding [%COL%]}" Value="Error"><Setter TargetName="B" Property="Background" Value="#F4EBFF"/><Setter TargetName="T" Property="Foreground" Value="#6941C6"/></DataTrigger>
  </DataTemplate.Triggers>
</DataTemplate>
'@

$MainXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Logon Black Screen Analyser" Width="1480" Height="940" MinWidth="1120" MinHeight="700"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" FontSize="13" Background="#F5F7FA" Foreground="#101828"
        UseLayoutRounding="True" SnapsToDevicePixels="True" TextOptions.TextFormattingMode="Display">
  <Window.Resources>
%STYLES%
%GRIDSTYLES%
  </Window.Resources>

  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Header -->
    <Border Grid.Row="0" Background="#FFFFFF" BorderBrush="#E4E7EC" BorderThickness="0,0,0,1" Padding="24,14,24,0">
      <StackPanel>
        <DockPanel>
          <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
            <Button x:Name="BtnElevate" Style="{StaticResource BtnSecondary}" Content="Restart as administrator" Margin="0,0,8,0" Visibility="Collapsed"/>
            <Button x:Name="BtnExport" Style="{StaticResource BtnSecondary}" Content="Export report" Margin="0,0,8,0" IsEnabled="False"/>
            <Button x:Name="BtnScan" Style="{StaticResource BtnPrimary}" Content="Rescan" IsEnabled="False"/>
          </StackPanel>
          <StackPanel>
            <TextBlock Text="Logon Black Screen Analyser" FontSize="19" FontWeight="SemiBold" Foreground="#101828"/>
            <TextBlock Text="Finds why users get a long black screen at sign-in, explains each fix and its impact, and can apply safe fixes for you." Foreground="#667085" FontSize="12" Margin="0,2,0,0"/>
          </StackPanel>
        </DockPanel>
        <WrapPanel x:Name="HostChips" Margin="0,10,0,4"/>
        <TabControl x:Name="Tabs" Background="Transparent" BorderThickness="0" Padding="0" Margin="-14,4,0,-1" Height="42">
          <TabItem Header="Findings" Tag="Findings"/>
          <TabItem Header="Logon timeline" Tag="Timeline"/>
          <TabItem Header="Trends" Tag="Trends"/>
          <TabItem Header="User reports" Tag="Reports"/>
          <TabItem Header="Compare hosts" Tag="Compare"/>
          <TabItem Header="Fleet" Tag="Fleet"/>
          <TabItem Header="Azure" Tag="Azure"/>
          <TabItem Header="Fix history" Tag="FixHistory"/>
          <TabItem Header="Tools" Tag="Tools"/>
        </TabControl>
      </StackPanel>
    </Border>

    <Grid Grid.Row="1" Margin="24,18,24,16">

      <!-- ===================== Findings ===================== -->
      <Grid x:Name="PageFindings">
        <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
        <UniformGrid Grid.Row="0" Rows="1" Columns="5" Margin="0,0,0,16">
          <Button x:Name="TileProblem" Tag="Problem" Style="{StaticResource Tile}" Margin="0,0,12,0" ToolTip="Show only problems (click again to show all)">
            <DockPanel><Border DockPanel.Dock="Left" Width="4" CornerRadius="2" Background="#D92D20" Margin="0,2,14,2"/>
              <StackPanel><TextBlock x:Name="NProblem" Text="-" FontSize="26" FontWeight="SemiBold" Foreground="#101828"/><TextBlock Text="Problems" Foreground="#667085" FontSize="12"/></StackPanel></DockPanel>
          </Button>
          <Button x:Name="TileWarning" Tag="Warning" Style="{StaticResource Tile}" Margin="0,0,12,0" ToolTip="Show only warnings (click again to show all)">
            <DockPanel><Border DockPanel.Dock="Left" Width="4" CornerRadius="2" Background="#DC6803" Margin="0,2,14,2"/>
              <StackPanel><TextBlock x:Name="NWarning" Text="-" FontSize="26" FontWeight="SemiBold" Foreground="#101828"/><TextBlock Text="Warnings" Foreground="#667085" FontSize="12"/></StackPanel></DockPanel>
          </Button>
          <Button x:Name="TileInfo" Tag="Info" Style="{StaticResource Tile}" Margin="0,0,12,0" ToolTip="Show only info and tips (click again to show all)">
            <DockPanel><Border DockPanel.Dock="Left" Width="4" CornerRadius="2" Background="#444CE7" Margin="0,2,14,2"/>
              <StackPanel><TextBlock x:Name="NInfo" Text="-" FontSize="26" FontWeight="SemiBold" Foreground="#101828"/><TextBlock Text="Info and tips" Foreground="#667085" FontSize="12"/></StackPanel></DockPanel>
          </Button>
          <Button x:Name="TileOK" Tag="OK" Style="{StaticResource Tile}" Margin="0,0,12,0" ToolTip="Show only passed checks (click again to show all)">
            <DockPanel><Border DockPanel.Dock="Left" Width="4" CornerRadius="2" Background="#079455" Margin="0,2,14,2"/>
              <StackPanel><TextBlock x:Name="NOK" Text="-" FontSize="26" FontWeight="SemiBold" Foreground="#101828"/><TextBlock Text="OK" Foreground="#667085" FontSize="12"/></StackPanel></DockPanel>
          </Button>
          <Button x:Name="TileNA" Tag="N/A" Style="{StaticResource Tile}" ToolTip="Show checks that do not apply to this Windows version or configuration">
            <DockPanel><Border DockPanel.Dock="Left" Width="4" CornerRadius="2" Background="#98A2B3" Margin="0,2,14,2"/>
              <StackPanel><TextBlock x:Name="NNA" Text="-" FontSize="26" FontWeight="SemiBold" Foreground="#101828"/><TextBlock Text="Not applicable" Foreground="#667085" FontSize="12"/></StackPanel></DockPanel>
          </Button>
        </UniformGrid>

        <Grid Grid.Row="1">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*" MinWidth="520"/><ColumnDefinition Width="16"/><ColumnDefinition Width="490" MinWidth="360"/>
          </Grid.ColumnDefinitions>
          <Grid Grid.Column="0">
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
            <Border Grid.Row="0" Style="{StaticResource Card}" Padding="16,12">
              <StackPanel>
                <DockPanel>
                  <TextBlock DockPanel.Dock="Right" Text="Click a cause to open it" Style="{StaticResource Hint}" VerticalAlignment="Center"/>
                  <TextBlock Text="Most likely causes on this host" Style="{StaticResource CardTitle}"/>
                </DockPanel>
                <TextBlock x:Name="CausesHint" Text="Scanning..." Style="{StaticResource Hint}" Margin="0,6,0,0"/>
                <StackPanel x:Name="CausesList" Margin="-8,4,-8,0"/>
              </StackPanel>
            </Border>
            <DockPanel Grid.Row="1" Margin="0,14,0,10" LastChildFill="False">
              <TextBlock x:Name="TxtFilter" DockPanel.Dock="Right" VerticalAlignment="Center" Style="{StaticResource Hint}"/>
              <Grid Width="260">
                <TextBox x:Name="TxtSearch" Style="{StaticResource Input}"/>
                <TextBlock x:Name="SearchHint" Text="Search checks..." Foreground="#98A2B3" Margin="11,0,0,0" VerticalAlignment="Center" IsHitTestVisible="False"/>
              </Grid>
              <ComboBox x:Name="CmbCategory" Width="240" Margin="10,0,0,0" VerticalContentAlignment="Center" Padding="8,6"/>
              <CheckBox x:Name="ChkNA" Content="Show not applicable" Margin="14,0,0,0" VerticalAlignment="Center" Foreground="#344054"/>
            </DockPanel>
            <Border Grid.Row="2" Style="{StaticResource Card}" Padding="1">
              <DataGrid x:Name="Grid" AutoGenerateColumns="False" HorizontalScrollBarVisibility="Disabled" CanUserSortColumns="True">
                <DataGrid.Columns>
                  <DataGridTemplateColumn Header="STATUS" Width="96" SortMemberPath="SortKey">
                    <DataGridTemplateColumn.CellTemplate>
                      <DataTemplate>
                        <Border x:Name="B" CornerRadius="10" Padding="8,2" Background="#F2F4F7" HorizontalAlignment="Left">
                          <TextBlock x:Name="T" Text="{Binding Status}" Foreground="#475467" FontWeight="SemiBold" FontSize="11"/>
                        </Border>
                        <DataTemplate.Triggers>
                          <DataTrigger Binding="{Binding Status}" Value="Problem"><Setter TargetName="B" Property="Background" Value="#FEE4E2"/><Setter TargetName="T" Property="Foreground" Value="#B42318"/></DataTrigger>
                          <DataTrigger Binding="{Binding Status}" Value="Warning"><Setter TargetName="B" Property="Background" Value="#FEF0C7"/><Setter TargetName="T" Property="Foreground" Value="#B54708"/></DataTrigger>
                          <DataTrigger Binding="{Binding Status}" Value="Info"><Setter TargetName="B" Property="Background" Value="#E0EAFF"/><Setter TargetName="T" Property="Foreground" Value="#3538CD"/></DataTrigger>
                          <DataTrigger Binding="{Binding Status}" Value="OK"><Setter TargetName="B" Property="Background" Value="#DCFAE6"/><Setter TargetName="T" Property="Foreground" Value="#067647"/></DataTrigger>
                          <DataTrigger Binding="{Binding Status}" Value="Error"><Setter TargetName="B" Property="Background" Value="#F4EBFF"/><Setter TargetName="T" Property="Foreground" Value="#6941C6"/></DataTrigger>
                        </DataTemplate.Triggers>
                      </DataTemplate>
                    </DataGridTemplateColumn.CellTemplate>
                  </DataGridTemplateColumn>
                  <DataGridTemplateColumn Header="CHECK" Width="320" SortMemberPath="Name">
                    <DataGridTemplateColumn.CellTemplate>
                      <DataTemplate>
                        <StackPanel Margin="0,4">
                          <TextBlock Text="{Binding Name}" FontWeight="SemiBold" Foreground="#101828" TextWrapping="Wrap"/>
                          <TextBlock Text="{Binding Category}" Foreground="#667085" FontSize="11" Margin="0,2,0,0"/>
                        </StackPanel>
                      </DataTemplate>
                    </DataGridTemplateColumn.CellTemplate>
                  </DataGridTemplateColumn>
                  <DataGridTemplateColumn Header="RESULT" Width="*" SortMemberPath="Summary">
                    <DataGridTemplateColumn.CellTemplate>
                      <DataTemplate><TextBlock Text="{Binding Summary}" TextWrapping="Wrap" Foreground="#475467" Margin="0,4"/></DataTemplate>
                    </DataGridTemplateColumn.CellTemplate>
                  </DataGridTemplateColumn>
                  <DataGridTemplateColumn Header="FIX" Width="80" SortMemberPath="AutoFix">
                    <DataGridTemplateColumn.CellTemplate>
                      <DataTemplate>
                        <Border x:Name="P" CornerRadius="10" Padding="8,2" Background="#EFF4FF" HorizontalAlignment="Left">
                          <TextBlock Text="1-click" Foreground="#1849A9" FontSize="11" FontWeight="SemiBold"/>
                        </Border>
                        <DataTemplate.Triggers>
                          <DataTrigger Binding="{Binding AutoFix}" Value=""><Setter TargetName="P" Property="Visibility" Value="Collapsed"/></DataTrigger>
                        </DataTemplate.Triggers>
                      </DataTemplate>
                    </DataGridTemplateColumn.CellTemplate>
                  </DataGridTemplateColumn>
                </DataGrid.Columns>
              </DataGrid>
            </Border>
          </Grid>

          <GridSplitter Grid.Column="1" Width="16" HorizontalAlignment="Stretch" Background="Transparent" ResizeBehavior="PreviousAndNext"/>

          <Border Grid.Column="2" Style="{StaticResource Card}">
            <Grid>
              <StackPanel x:Name="DetailEmpty" VerticalAlignment="Center" HorizontalAlignment="Center" Margin="36">
                <TextBlock Text="Select a check" FontSize="15" FontWeight="SemiBold" Foreground="#344054" HorizontalAlignment="Center"/>
                <TextBlock Text="You will see what was found, how to fix it, what the fix means for users and the system, and - where it is safe - a button that applies the fix for you." Style="{StaticResource Hint}" TextAlignment="Center" Margin="0,6,0,0"/>
              </StackPanel>
              <ScrollViewer x:Name="DetailPanel" VerticalScrollBarVisibility="Auto" Visibility="Collapsed">
                <StackPanel Margin="22,18,22,22">
                  <StackPanel Orientation="Horizontal">
                    <Border x:Name="DStatusPill" CornerRadius="10" Padding="9,2"><TextBlock x:Name="DStatusText" FontWeight="SemiBold" FontSize="11"/></Border>
                    <TextBlock x:Name="DMeta" Style="{StaticResource Hint}" VerticalAlignment="Center" Margin="10,0,0,0"/>
                  </StackPanel>
                  <TextBlock x:Name="DName" FontSize="17" FontWeight="SemiBold" Foreground="#101828" TextWrapping="Wrap" Margin="0,10,0,6"/>
                  <TextBox x:Name="DSummary" Style="{StaticResource Ro}" FontSize="13.5"/>

                  <StackPanel x:Name="FixSection">
                    <TextBlock Text="HOW TO FIX" Style="{StaticResource Lbl}"/>
                    <TextBox x:Name="DFix" Style="{StaticResource Ro}"/>
                  </StackPanel>

                  <Border x:Name="ImpactSection" Background="#FFFAEB" BorderBrush="#FEDF89" BorderThickness="1" CornerRadius="6" Padding="12,10" Margin="0,4,0,12">
                    <StackPanel>
                      <TextBlock Text="IMPACT OF THE FIX ON USERS AND SYSTEM" FontSize="11" FontWeight="SemiBold" Foreground="#B54708"/>
                      <TextBox x:Name="DImpact" Style="{StaticResource Ro}" Foreground="#93370D" Margin="0,6,0,0"/>
                    </StackPanel>
                  </Border>

                  <Border x:Name="AutoFixSection" Background="#EFF4FF" BorderBrush="#C7D7FE" BorderThickness="1" CornerRadius="6" Padding="12,10" Margin="0,0,0,12">
                    <StackPanel>
                      <TextBlock Text="ONE-CLICK FIX" FontSize="11" FontWeight="SemiBold" Foreground="#1849A9"/>
                      <TextBlock x:Name="DAutoChanges" TextWrapping="Wrap" Foreground="#1849A9" Margin="0,6,0,8"/>
                      <WrapPanel x:Name="DAutoBadges" Margin="0,0,0,10"/>
                      <Button x:Name="BtnApply" Style="{StaticResource BtnPrimary}" HorizontalAlignment="Left" Content="Apply fix"/>
                      <TextBlock x:Name="DAutoNote" Style="{StaticResource Hint}" Margin="0,8,0,0"/>
                    </StackPanel>
                  </Border>

                  <Expander x:Name="ExpCmd" Margin="0,0,0,10">
                    <Expander.Header><TextBlock Text="Manual commands (review, copy and run yourself)" FontWeight="SemiBold" Foreground="#344054"/></Expander.Header>
                    <StackPanel Margin="0,8,0,0">
                      <Button x:Name="BtnCopy" Style="{StaticResource BtnSecondary}" Content="Copy to clipboard" HorizontalAlignment="Right" Padding="10,4" Margin="0,0,0,6"/>
                      <TextBox x:Name="DCmd" Style="{StaticResource Code}"/>
                    </StackPanel>
                  </Expander>
                  <Expander x:Name="ExpEvidence" Margin="0,0,0,10">
                    <Expander.Header><TextBlock Text="Evidence collected on this host" FontWeight="SemiBold" Foreground="#344054"/></Expander.Header>
                    <TextBox x:Name="DDetail" Style="{StaticResource Code}" Margin="0,8,0,0"/>
                  </Expander>
                  <StackPanel x:Name="RefSection">
                    <TextBlock Text="REFERENCE" Style="{StaticResource Lbl}"/>
                    <TextBox x:Name="DRef" Style="{StaticResource Ro}" Foreground="#2563EB"/>
                  </StackPanel>
                </StackPanel>
              </ScrollViewer>
            </Grid>
          </Border>
        </Grid>
      </Grid>

      <!-- ===================== Logon timeline ===================== -->
      <Grid x:Name="PageTimeline" Visibility="Collapsed">
        <Grid.ColumnDefinitions><ColumnDefinition Width="560"/><ColumnDefinition Width="16"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
        <DockPanel Grid.Column="0">
          <StackPanel DockPanel.Dock="Top" Margin="0,0,0,12">
            <StackPanel Orientation="Horizontal">
              <Button x:Name="BtnTlLoad" Style="{StaticResource BtnPrimary}" Content="Load recent logons"/>
              <TextBlock x:Name="TxtTlInfo" Style="{StaticResource Hint}" VerticalAlignment="Center" Margin="12,0,0,0"/>
            </StackPanel>
            <TextBlock Style="{StaticResource Hint}" Margin="0,10,0,0" Text="Breaks each logon on this host into phases from the event logs, the logon probe and (if enabled) process auditing. Install the probe (Tools) and enable AUD-01 for the most complete picture."/>
          </StackPanel>
          <Border Style="{StaticResource Card}" Padding="1"><DataGrid x:Name="GridTl" AutoGenerateColumns="True"/></Border>
        </DockPanel>
        <Border Grid.Column="2" Style="{StaticResource Card}">
          <ScrollViewer VerticalScrollBarVisibility="Auto">
            <StackPanel Margin="22,18,22,22">
              <TextBlock x:Name="TlTitle" Text="Select a logon" FontSize="16" FontWeight="SemiBold" Foreground="#101828"/>
              <TextBlock x:Name="TlSub" Style="{StaticResource Hint}" Margin="0,4,0,0"/>
              <Canvas x:Name="TlCanvas" Height="120" Margin="0,16,0,8" ClipToBounds="True"/>
              <Border x:Name="TlAdviceBox" Background="#FFFAEB" BorderBrush="#FEDF89" BorderThickness="1" CornerRadius="6" Padding="12,10" Margin="0,6,0,12" Visibility="Collapsed">
                <StackPanel>
                  <TextBlock Text="WHERE TO LOOK" FontSize="11" FontWeight="SemiBold" Foreground="#B54708"/>
                  <TextBlock x:Name="TlAdvice" TextWrapping="Wrap" Foreground="#93370D" Margin="0,6,0,0"/>
                </StackPanel>
              </Border>
              <Expander Margin="0,4,0,0">
                <Expander.Header><TextBlock Text="Phase details" FontWeight="SemiBold" Foreground="#344054"/></Expander.Header>
                <TextBox x:Name="TlDetail" Style="{StaticResource Code}" Margin="0,8,0,0"/>
              </Expander>
            </StackPanel>
          </ScrollViewer>
        </Border>
      </Grid>

      <!-- ===================== Trends ===================== -->
      <ScrollViewer x:Name="PageTrends" Visibility="Collapsed" VerticalScrollBarVisibility="Auto">
        <StackPanel>
          <StackPanel Orientation="Horizontal" Margin="0,0,0,12">
            <Button x:Name="BtnTrLoad" Style="{StaticResource BtnPrimary}" Content="Load logon data"/>
            <CheckBox x:Name="ChkTrAll" Content="Chart all hosts in the data" VerticalAlignment="Center" Margin="14,0,0,0" Foreground="#344054"/>
            <TextBlock x:Name="TxtTrInfo" Style="{StaticResource Hint}" VerticalAlignment="Center" Margin="14,0,0,0" Text="Uses the logon probe data (this host and the central share) and the scan history."/>
          </StackPanel>
          <Border Style="{StaticResource Card}" Padding="18,14" Margin="0,0,0,14">
            <StackPanel>
              <TextBlock Text="Time from sign-in to desktop per day" Style="{StaticResource CardTitle}"/>
              <StackPanel Orientation="Horizontal" Margin="0,6,0,0">
                <Border Width="14" Height="3" Background="#2563EB" VerticalAlignment="Center"/><TextBlock Text=" Median" Style="{StaticResource Hint}" Margin="4,0,14,0"/>
                <Border Width="14" Height="3" Background="#F79009" VerticalAlignment="Center"/><TextBlock Text=" 90th percentile" Style="{StaticResource Hint}" Margin="4,0,14,0"/>
                <Border Width="2" Height="12" Background="#DC6803" VerticalAlignment="Center"/><TextBlock Text=" Windows update installed" Style="{StaticResource Hint}" Margin="4,0,14,0"/>
                <Border Width="2" Height="12" Background="#079455" VerticalAlignment="Center"/><TextBlock Text=" Fix applied" Style="{StaticResource Hint}" Margin="4,0,0,0"/>
              </StackPanel>
              <Canvas x:Name="TrChart" Height="260" Margin="0,12,0,0" ClipToBounds="True"/>
            </StackPanel>
          </Border>
          <Grid Margin="0,0,0,14">
            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="14"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
            <Border Grid.Column="0" Style="{StaticResource Card}" Padding="18,14">
              <StackPanel>
                <TextBlock Text="Before and after each update and fix (this host)" Style="{StaticResource CardTitle}"/>
                <TextBlock Text="Median time to desktop in the 7 days before vs. after - shows whether an update made logons slower or a fix helped." Style="{StaticResource Hint}" Margin="0,4,0,10"/>
                <DataGrid x:Name="GridTrBA" AutoGenerateColumns="True" MaxHeight="280"/>
              </StackPanel>
            </Border>
            <Border Grid.Column="2" Style="{StaticResource Card}" Padding="18,14">
              <StackPanel>
                <TextBlock Text="By Windows build (all hosts in the data)" Style="{StaticResource CardTitle}"/>
                <TextBlock Text="Patch-day canary: if a new build is slower than the previous one, hold the rollout." Style="{StaticResource Hint}" Margin="0,4,0,10"/>
                <DataGrid x:Name="GridTrBuild" AutoGenerateColumns="True" MaxHeight="280"/>
              </StackPanel>
            </Border>
          </Grid>
          <Border Style="{StaticResource Card}" Padding="18,14" Margin="0,0,0,14">
            <StackPanel>
              <TextBlock Text="By host - last 24 hours compared with the previous 7 days" Style="{StaticResource CardTitle}"/>
              <TextBlock Text="Hosts that got noticeably slower are flagged." Style="{StaticResource Hint}" Margin="0,4,0,10"/>
              <DataGrid x:Name="GridTrHost" AutoGenerateColumns="True" MaxHeight="300"/>
            </StackPanel>
          </Border>
          <Border Style="{StaticResource Card}" Padding="18,14">
            <StackPanel>
              <DockPanel>
                <ComboBox x:Name="CmbMetric" DockPanel.Dock="Right" Width="260" Padding="8,5"/>
                <TextBlock Text="Scan history on this host" Style="{StaticResource CardTitle}" VerticalAlignment="Center"/>
              </DockPanel>
              <TextBlock Text="Values measured by each scan over time, e.g. the number of firewall rules or the profile load time." Style="{StaticResource Hint}" Margin="0,4,0,0"/>
              <Canvas x:Name="MetricChart" Height="220" Margin="0,12,0,0" ClipToBounds="True"/>
            </StackPanel>
          </Border>
        </StackPanel>
      </ScrollViewer>

      <!-- ===================== User reports ===================== -->
      <Grid x:Name="PageReports" Visibility="Collapsed">
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="16"/><ColumnDefinition Width="460"/></Grid.ColumnDefinitions>
        <DockPanel Grid.Column="0">
          <StackPanel DockPanel.Dock="Top" Margin="0,0,0,12">
            <StackPanel Orientation="Horizontal">
              <Button x:Name="BtnRepLoad" Style="{StaticResource BtnPrimary}" Content="Load user reports"/>
              <TextBlock x:Name="TxtRepInfo" Style="{StaticResource Hint}" VerticalAlignment="Center" Margin="12,0,0,0"/>
            </StackPanel>
            <TextBlock Style="{StaticResource Hint}" Margin="0,10,0,0" Text="Reports users sent with the 'Report slow sign-in' shortcut (installed with the logon probe). Each report contains the timing of that sign-in and quick evidence collected in the user session."/>
          </StackPanel>
          <Border Style="{StaticResource Card}" Padding="1"><DataGrid x:Name="GridRep" AutoGenerateColumns="True"/></Border>
        </DockPanel>
        <Border Grid.Column="2" Style="{StaticResource Card}" Padding="18,14">
          <DockPanel>
            <TextBlock DockPanel.Dock="Top" Text="Report details" Style="{StaticResource CardTitle}" Margin="0,0,0,10"/>
            <TextBox x:Name="TxtRepDetail" Style="{StaticResource Code}" MaxHeight="2000"/>
          </DockPanel>
        </Border>
      </Grid>

      <!-- ===================== Compare hosts ===================== -->
      <DockPanel x:Name="PageCompare" Visibility="Collapsed">
        <StackPanel DockPanel.Dock="Top" Margin="0,0,0,12">
          <StackPanel Orientation="Horizontal">
            <Button x:Name="BtnSnapSave" Style="{StaticResource BtnSecondary}" Content="Save this host as baseline..."/>
            <Button x:Name="BtnSnapCompare" Style="{StaticResource BtnPrimary}" Content="Compare with a baseline..." Margin="8,0,0,0"/>
            <ComboBox x:Name="CmbDiffCat" Width="220" Margin="16,0,0,0" Padding="8,5"/>
            <TextBlock x:Name="TxtDiffInfo" Style="{StaticResource Hint}" VerticalAlignment="Center" Margin="12,0,0,0"/>
          </StackPanel>
          <TextBlock Style="{StaticResource Hint}" Margin="0,10,0,0" Text="Save a baseline on a host where sign-in is fast, then compare a slow host against it. The list shows every difference in updates, services, Run keys, Active Setup, installed programs, provisioned apps, policies, FSLogix settings, credential providers, shell extensions, filter drivers, scheduled tasks and check results - including causes this tool has no check for."/>
        </StackPanel>
        <Border Style="{StaticResource Card}" Padding="1"><DataGrid x:Name="GridDiff" AutoGenerateColumns="True"/></Border>
      </DockPanel>

      <!-- ===================== Fleet ===================== -->
      <Grid x:Name="PageFleet" Visibility="Collapsed">
        <Grid.ColumnDefinitions><ColumnDefinition Width="320"/><ColumnDefinition Width="16"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
        <Border Grid.Column="0" Style="{StaticResource Card}" Padding="18,14">
          <StackPanel>
            <TextBlock Text="Session hosts" Style="{StaticResource CardTitle}"/>
            <TextBlock Text="One host name per line. The scan runs remotely over WinRM (PowerShell remoting) with administrator rights." Style="{StaticResource Hint}" Margin="0,4,0,8"/>
            <TextBox x:Name="TxtFleetHosts" Style="{StaticResource Input}" AcceptsReturn="True" Height="220" VerticalContentAlignment="Top" VerticalScrollBarVisibility="Auto"/>
            <Button x:Name="BtnFleetPool" Style="{StaticResource BtnSecondary}" Content="Load from AVD host pool" Margin="0,10,0,0" HorizontalAlignment="Stretch"/>
            <CheckBox x:Name="ChkFleetCred" Content="Use other credentials" Margin="0,12,0,0" Foreground="#344054"/>
            <Button x:Name="BtnFleetScan" Style="{StaticResource BtnPrimary}" Content="Scan hosts" Margin="0,12,0,0" HorizontalAlignment="Stretch"/>
            <Button x:Name="BtnFleetExport" Style="{StaticResource BtnSecondary}" Content="Export fleet report" Margin="0,8,0,0" HorizontalAlignment="Stretch" IsEnabled="False"/>
            <TextBlock x:Name="TxtFleetInfo" Style="{StaticResource Hint}" Margin="0,12,0,0"/>
          </StackPanel>
        </Border>
        <Grid Grid.Column="2">
          <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="14"/><RowDefinition Height="240"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Style="{StaticResource Card}" Padding="1"><DataGrid x:Name="GridFleet" AutoGenerateColumns="False" HorizontalScrollBarVisibility="Auto"/></Border>
          <Border Grid.Row="2" Style="{StaticResource Card}" Padding="1">
            <DockPanel>
              <TextBlock x:Name="TxtFleetHost" DockPanel.Dock="Top" Text="Select a host to see its problems and warnings" Style="{StaticResource CardTitle}" Margin="14,10,14,6"/>
              <DataGrid x:Name="GridFleetHost" AutoGenerateColumns="True"/>
            </DockPanel>
          </Border>
        </Grid>
      </Grid>

      <!-- ===================== Azure ===================== -->
      <ScrollViewer x:Name="PageAzure" Visibility="Collapsed" VerticalScrollBarVisibility="Auto">
        <StackPanel>
          <Border Style="{StaticResource Card}" Padding="18,14" Margin="0,0,0,14">
            <DockPanel>
              <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Top">
                <Button x:Name="BtnModCheck" Style="{StaticResource BtnSecondary}" Content="Refresh" Margin="0,0,8,0"/>
                <Button x:Name="BtnModInstall" Style="{StaticResource BtnPrimary}" Content="Install missing modules"/>
              </StackPanel>
              <StackPanel>
                <TextBlock Text="PowerShell modules for the Azure features" Style="{StaticResource CardTitle}"/>
                <TextBlock Text="The features on this tab and 'Load from AVD host pool' (Fleet) need these Microsoft modules from the PowerShell Gallery." Style="{StaticResource Hint}" Margin="0,4,0,8"/>
                <TextBlock x:Name="TxtModules" FontFamily="Consolas" FontSize="12" Foreground="#344054" TextWrapping="Wrap"/>
              </StackPanel>
            </DockPanel>
          </Border>
          <Border Style="{StaticResource Card}" Padding="18,14" Margin="0,0,0,14">
            <StackPanel>
              <TextBlock Text="AVD Insights - connection timing from Azure" Style="{StaticResource CardTitle}"/>
              <TextBlock Text="Reads WVDConnections, WVDCheckpoints and WVDErrors from the Log Analytics workspace of your host pool diagnostics. Needs the Az.Accounts and Az.OperationalInsights modules and Log Analytics Reader rights." Style="{StaticResource Hint}" Margin="0,4,0,12"/>
              <WrapPanel>
                <StackPanel Margin="0,0,12,8"><TextBlock Text="Workspace ID" Style="{StaticResource Lbl}" Margin="0,0,0,4"/><TextBox x:Name="TxtAvdWs" Style="{StaticResource Input}" Width="320"/></StackPanel>
                <StackPanel Margin="0,0,12,8"><TextBlock Text="User (UPN)" Style="{StaticResource Lbl}" Margin="0,0,0,4"/><TextBox x:Name="TxtAvdUser" Style="{StaticResource Input}" Width="260"/></StackPanel>
                <StackPanel Margin="0,0,12,8"><TextBlock Text="Days" Style="{StaticResource Lbl}" Margin="0,0,0,4"/><TextBox x:Name="TxtAvdDays" Style="{StaticResource Input}" Width="60" Text="7"/></StackPanel>
                <Button x:Name="BtnAzLogin" Style="{StaticResource BtnSecondary}" Content="Sign in to Azure" VerticalAlignment="Bottom" Margin="0,0,8,8"/>
                <Button x:Name="BtnAvdQuery" Style="{StaticResource BtnPrimary}" Content="Query connections" VerticalAlignment="Bottom" Margin="0,0,0,8"/>
              </WrapPanel>
              <TextBlock x:Name="TxtAvdInfo" Style="{StaticResource Hint}" Margin="0,4,0,8"/>
              <DataGrid x:Name="GridAvdConn" AutoGenerateColumns="True" MaxHeight="240"/>
              <TextBlock Text="Checkpoints and errors of the selected connection" Style="{StaticResource Lbl}" Margin="0,14,0,6"/>
              <DataGrid x:Name="GridAvdCp" AutoGenerateColumns="True" MaxHeight="300"/>
            </StackPanel>
          </Border>
          <Border Style="{StaticResource Card}" Padding="18,14">
            <StackPanel>
              <TextBlock Text="Windows release health - known issues (Microsoft Graph)" Style="{StaticResource CardTitle}"/>
              <TextBlock Text="Loads Microsoft's known issues for this Windows version and shows whether the update that introduced each issue - and the update that fixes it - is installed here. Needs the Microsoft.Graph.Authentication module and the WindowsUpdates.ReadWrite.All permission (beta API)." Style="{StaticResource Hint}" Margin="0,4,0,12"/>
              <StackPanel Orientation="Horizontal">
                <Button x:Name="BtnRh" Style="{StaticResource BtnPrimary}" Content="Load known issues"/>
                <CheckBox x:Name="ChkRhRelevant" Content="Only issues about sign-in, shell, Start, RDP or black screens" IsChecked="True" VerticalAlignment="Center" Margin="14,0,0,0" Foreground="#344054"/>
                <TextBlock x:Name="TxtRhInfo" Style="{StaticResource Hint}" VerticalAlignment="Center" Margin="14,0,0,0"/>
              </StackPanel>
              <DataGrid x:Name="GridRh" AutoGenerateColumns="True" MaxHeight="300" Margin="0,12,0,0"/>
              <TextBox x:Name="TxtRhDetail" Style="{StaticResource Ro}" Margin="0,10,0,0"/>
            </StackPanel>
          </Border>
        </StackPanel>
      </ScrollViewer>

      <!-- ===================== Fix history ===================== -->
      <DockPanel x:Name="PageFixHistory" Visibility="Collapsed">
        <StackPanel DockPanel.Dock="Top" Margin="0,0,0,12">
          <StackPanel Orientation="Horizontal">
            <Button x:Name="BtnFhRefresh" Style="{StaticResource BtnSecondary}" Content="Refresh"/>
            <Button x:Name="BtnFhUndo" Style="{StaticResource BtnPrimary}" Content="Undo selected fix" Margin="8,0,0,0"/>
            <Button x:Name="BtnFhOpen" Style="{StaticResource BtnLink}" Content="Open backups folder" Margin="8,0,0,0"/>
            <TextBlock x:Name="TxtFhInfo" Style="{StaticResource Hint}" VerticalAlignment="Center" Margin="12,0,0,0"/>
          </StackPanel>
          <TextBlock Style="{StaticResource Hint}" Margin="0,10,0,0" Text="Every one-click fix and undo is listed here. Fixes that changed the registry can be undone: the key is restored to exactly the state before the fix (the state before the undo is backed up too). Fixes that uninstalled software, removed apps or profiles, or started services cannot be undone here."/>
        </StackPanel>
        <Border DockPanel.Dock="Bottom" Style="{StaticResource Card}" Padding="14,10" Margin="0,12,0,0">
          <TextBox x:Name="TxtFhDetail" Style="{StaticResource Code}" BorderThickness="0" Height="160"/>
        </Border>
        <Border Style="{StaticResource Card}" Padding="1"><DataGrid x:Name="GridFh" AutoGenerateColumns="True"/></Border>
      </DockPanel>

      <!-- ===================== Tools ===================== -->
      <ScrollViewer x:Name="PageTools" Visibility="Collapsed" VerticalScrollBarVisibility="Auto">
        <Grid>
          <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="14"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
          <StackPanel Grid.Column="0">
            <Border Style="{StaticResource Card}" Padding="18,14" Margin="0,0,0,14">
              <StackPanel>
                <TextBlock Text="Logon probe and 'Report slow sign-in'" Style="{StaticResource CardTitle}"/>
                <TextBlock Style="{StaticResource Hint}" Margin="0,4,0,10" Text="Measures, for every user logon, the time from sign-in until the taskbar is visible - the black screen users actually experience - and optionally adds a desktop shortcut users can click to report a slow sign-in with evidence attached."/>
                <TextBlock x:Name="TxtProbeStatus" Foreground="#344054" TextWrapping="Wrap"/>
                <TextBlock Text="Central share for probe data and reports (optional, e.g. \\server\LogonData$)" Style="{StaticResource Lbl}"/>
                <TextBox x:Name="TxtSharePath" Style="{StaticResource Input}"/>
                <CheckBox x:Name="ChkProbeShortcut" Content="Add 'Report slow sign-in' shortcut to the public desktop" Margin="0,10,0,0" IsChecked="True" Foreground="#344054"/>
                <Border Background="#FFFAEB" BorderBrush="#FEDF89" BorderThickness="1" CornerRadius="6" Padding="12,10" Margin="0,12,0,12">
                  <StackPanel>
                    <TextBlock Text="IMPACT ON USERS AND SYSTEM" FontSize="11" FontWeight="SemiBold" Foreground="#B54708"/>
                    <TextBlock x:Name="TxtProbeImpact" TextWrapping="Wrap" Foreground="#93370D" Margin="0,6,0,0"/>
                  </StackPanel>
                </Border>
                <StackPanel Orientation="Horizontal">
                  <Button x:Name="BtnProbeInstall" Style="{StaticResource BtnPrimary}" Content="Install / update on this host"/>
                  <Button x:Name="BtnProbeRemove" Style="{StaticResource BtnSecondary}" Content="Remove" Margin="8,0,0,0"/>
                </StackPanel>
              </StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Padding="18,14" Margin="0,0,0,14">
              <StackPanel>
                <TextBlock Text="Support bundle" Style="{StaticResource CardTitle}"/>
                <TextBlock Style="{StaticResource Hint}" Margin="0,4,0,10" Text="One zip file with the report, relevant event logs, FSLogix logs, gpresult, probe data, fix history and system information - ready for a Microsoft support case. It contains user names and computer details."/>
                <CheckBox x:Name="ChkBundleSec" Content="Include the Security event log (large; needs administrator)" Foreground="#344054"/>
                <StackPanel Orientation="Horizontal" Margin="0,12,0,0">
                  <Button x:Name="BtnBundle" Style="{StaticResource BtnPrimary}" Content="Create support bundle"/>
                </StackPanel>
                <TextBlock x:Name="TxtBundle" Style="{StaticResource Hint}" Margin="0,10,0,0"/>
              </StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Padding="18,14" Margin="0,0,0,14">
              <StackPanel>
                <TextBlock Text="Performance trace of a logon (WPR)" Style="{StaticResource CardTitle}"/>
                <TextBlock Style="{StaticResource Hint}" Margin="0,4,0,10" Text="Records a Windows Performance Recorder trace. Start it, let a user sign in, wait until the desktop appears, then stop. The trace is added to the next support bundle and can be opened in Windows Performance Analyzer. Recording uses some CPU and disk - keep it short."/>
                <TextBlock x:Name="TxtWpr" Foreground="#344054" TextWrapping="Wrap" Text="Not recording."/>
                <StackPanel Orientation="Horizontal" Margin="0,12,0,0">
                  <Button x:Name="BtnWprStart" Style="{StaticResource BtnPrimary}" Content="Start recording"/>
                  <Button x:Name="BtnWprStop" Style="{StaticResource BtnSecondary}" Content="Stop and save" Margin="8,0,0,0" IsEnabled="False"/>
                </StackPanel>
              </StackPanel>
            </Border>
          </StackPanel>
          <StackPanel Grid.Column="2">
            <Border Style="{StaticResource Card}" Padding="18,14" Margin="0,0,0,14">
              <StackPanel>
                <TextBlock Text="Golden image gate" Style="{StaticResource CardTitle}"/>
                <TextBlock Style="{StaticResource Hint}" Margin="0,4,0,10" Text="Runs only the checks that belong in the image (firewall setting, provisioned apps, Active Setup, first sign-in animation, WDDM, Entra/Intune first-logon settings, ...) and fails when a problem is found. Add the command below as the last step of your image build (Azure Image Builder / Packer)."/>
                <TextBox x:Name="TxtGateCmd" Style="{StaticResource Code}" TextWrapping="Wrap"/>
                <StackPanel Orientation="Horizontal" Margin="0,12,0,0">
                  <Button x:Name="BtnGate" Style="{StaticResource BtnPrimary}" Content="Run the gate on this machine"/>
                  <Button x:Name="BtnGateCopy" Style="{StaticResource BtnSecondary}" Content="Copy command" Margin="8,0,0,0"/>
                </StackPanel>
              </StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Padding="18,14" Margin="0,0,0,14">
              <StackPanel>
                <TextBlock Text="Intune remediations" Style="{StaticResource CardTitle}"/>
                <TextBlock Style="{StaticResource Hint}" Margin="0,4,0,10" Text="Exports a detection and a remediation script for each safe machine-level fix, so Intune checks and corrects every session host continuously. A README explains how to import them."/>
                <Button x:Name="BtnIntune" Style="{StaticResource BtnPrimary}" Content="Export remediation scripts..." HorizontalAlignment="Left"/>
                <TextBlock x:Name="TxtIntune" Style="{StaticResource Hint}" Margin="0,10,0,0"/>
              </StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Padding="18,14" Margin="0,0,0,14">
              <StackPanel>
                <TextBlock Text="Settings" Style="{StaticResource CardTitle}"/>
                <TextBlock x:Name="TxtCfgPath" Style="{StaticResource Hint}" Margin="0,4,0,4"/>
                <TextBlock Text="Webhook for user reports (Teams Workflows URL, optional)" Style="{StaticResource Lbl}"/>
                <TextBox x:Name="TxtCfgWebhook" Style="{StaticResource Input}"/>
                <TextBlock Text="Log Analytics workspace ID (AVD Insights)" Style="{StaticResource Lbl}"/>
                <TextBox x:Name="TxtCfgWs" Style="{StaticResource Input}"/>
                <TextBlock Text="Azure subscription ID" Style="{StaticResource Lbl}"/>
                <TextBox x:Name="TxtCfgSub" Style="{StaticResource Input}"/>
                <Grid Margin="0,0,0,0">
                  <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="10"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                  <StackPanel Grid.Column="0"><TextBlock Text="Host pool resource group" Style="{StaticResource Lbl}"/><TextBox x:Name="TxtCfgRg" Style="{StaticResource Input}"/></StackPanel>
                  <StackPanel Grid.Column="2"><TextBlock Text="Host pool name" Style="{StaticResource Lbl}"/><TextBox x:Name="TxtCfgPool" Style="{StaticResource Input}"/></StackPanel>
                </Grid>
                <Button x:Name="BtnCfgSave" Style="{StaticResource BtnPrimary}" Content="Save settings" HorizontalAlignment="Left" Margin="0,14,0,0"/>
                <TextBlock Text="Known-issue data" Style="{StaticResource Lbl}" Margin="0,18,0,4"/>
                <TextBlock x:Name="TxtKiPath" Style="{StaticResource Hint}"/>
                <Button x:Name="BtnKiOpen" Style="{StaticResource BtnLink}" Content="Open / create KnownIssues.json" HorizontalAlignment="Left" Margin="-6,4,0,0"/>
              </StackPanel>
            </Border>
          </StackPanel>
        </Grid>
      </ScrollViewer>
    </Grid>

    <!-- Status bar -->
    <Border Grid.Row="2" Background="#FFFFFF" BorderBrush="#E4E7EC" BorderThickness="0,1,0,0" Padding="24,8">
      <DockPanel>
        <TextBlock x:Name="TxtLogPath" DockPanel.Dock="Right" Style="{StaticResource Hint}" VerticalAlignment="Center"/>
        <ProgressBar x:Name="Prog" Width="180" Height="4" Minimum="0" Maximum="100" Foreground="#2563EB" Background="#EAECF0" BorderThickness="0" VerticalAlignment="Center"/>
        <TextBlock x:Name="TxtProg" Margin="12,0,0,0" Foreground="#475467" FontSize="12" VerticalAlignment="Center"/>
      </DockPanel>
    </Border>
  </Grid>
</Window>
'@

$DialogXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Logon Black Screen Analyser" Width="660" SizeToContent="Height" MaxHeight="820"
        WindowStartupLocation="CenterOwner" ResizeMode="NoResize" FontFamily="Segoe UI" FontSize="13"
        Background="#FFFFFF" Foreground="#101828" ShowInTaskbar="False" UseLayoutRounding="True" TextOptions.TextFormattingMode="Display">
  <Window.Resources>
%STYLES%
  </Window.Resources>
  <DockPanel>
    <Border DockPanel.Dock="Top" Padding="22,18,22,8">
      <DockPanel>
        <Border x:Name="DAccent" DockPanel.Dock="Left" Width="4" CornerRadius="2" Background="#2563EB" Margin="0,2,12,2"/>
        <TextBlock x:Name="DTitle" FontSize="16" FontWeight="SemiBold" Foreground="#101828" TextWrapping="Wrap"/>
      </DockPanel>
    </Border>
    <Border DockPanel.Dock="Bottom" Background="#F9FAFB" BorderBrush="#EAECF0" BorderThickness="0,1,0,0" Padding="22,12">
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="DCancel" Style="{StaticResource BtnSecondary}" Content="Cancel" Margin="0,0,8,0" IsCancel="True"/>
        <Button x:Name="DOk" Style="{StaticResource BtnPrimary}" Content="OK" IsDefault="True"/>
      </StackPanel>
    </Border>
    <ScrollViewer VerticalScrollBarVisibility="Auto" MaxHeight="640">
      <StackPanel Margin="22,6,22,16">
        <TextBox x:Name="DMsg" Style="{StaticResource Ro}"/>
        <Border x:Name="DImpBox" Background="#FFFAEB" BorderBrush="#FEDF89" BorderThickness="1" CornerRadius="6" Padding="12,10" Margin="0,6,0,10">
          <StackPanel>
            <TextBlock Text="IMPACT ON USERS AND SYSTEM" FontSize="11" FontWeight="SemiBold" Foreground="#B54708"/>
            <TextBox x:Name="DImp" Style="{StaticResource Ro}" Foreground="#93370D" Margin="0,6,0,0"/>
          </StackPanel>
        </Border>
        <Expander x:Name="DCodeExp">
          <Expander.Header><TextBlock x:Name="DCodeHdr" Text="Commands that will be run" FontWeight="SemiBold" Foreground="#344054"/></Expander.Header>
          <TextBox x:Name="DCode" Style="{StaticResource Code}" Margin="0,8,0,0"/>
        </Expander>
      </StackPanel>
    </ScrollViewer>
  </DockPanel>
</Window>
'@
#endregion

#region UI helpers
$StatusTint = @{
    'Problem' = @('#FEE4E2', '#B42318'); 'Warning' = @('#FEF0C7', '#B54708'); 'Info' = @('#E0EAFF', '#3538CD')
    'OK' = @('#DCFAE6', '#067647'); 'N/A' = @('#F2F4F7', '#475467'); 'Error' = @('#F4EBFF', '#6941C6')
}
$StatusStripe = @{ 'Problem' = '#D92D20'; 'Warning' = '#DC6803'; 'Info' = '#444CE7'; 'OK' = '#079455'; 'N/A' = '#98A2B3'; 'Error' = '#7A5AF8' }

function New-Brush { param([string]$Hex) New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString($Hex)) }

function New-Pill {
    # Margin as numbers (left, top, right, bottom) - string conversion is culture dependent (e.g. Danish decimal comma)
    param([string]$Text, [string]$Bg, [string]$Fg, [double[]]$Margin = @(0, 0, 6, 4))
    $b = New-Object System.Windows.Controls.Border
    $b.CornerRadius = New-Object System.Windows.CornerRadius 10
    $b.Padding = New-Object System.Windows.Thickness 9, 2, 9, 2
    $b.Margin = New-Object System.Windows.Thickness $Margin[0], $Margin[1], $Margin[2], $Margin[3]
    $b.Background = New-Brush $Bg
    $t = New-Object System.Windows.Controls.TextBlock
    $t.Text = $Text; $t.FontSize = 11; $t.FontWeight = 'SemiBold'; $t.Foreground = New-Brush $Fg
    $b.Child = $t
    $b
}
function New-StatusPill { param([string]$Status, [double[]]$Margin = @(0, 0, 10, 0)) New-Pill -Text $Status -Bg $StatusTint[$Status][0] -Fg $StatusTint[$Status][1] -Margin $Margin }

function Show-Dialog {
    param([string]$Title, [string]$Message, [string]$Impact, [string]$Code, [string]$CodeHeader = 'Commands that will be run',
          [string]$OkText = 'OK', [string]$CancelText, [ValidateSet('Info', 'Confirm', 'Success', 'Error', 'Warning')][string]$Kind = 'Info')
    [xml]$dx = $DialogXaml.Replace('%STYLES%', $StylesXaml)
    $d = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $dx))
    if ($win -and $win.IsLoaded) { $d.Owner = $win }
    $accent = @{ Info = '#2563EB'; Confirm = '#2563EB'; Success = '#079455'; Error = '#D92D20'; Warning = '#DC6803' }[$Kind]
    $d.FindName('DAccent').Background = New-Brush $accent
    $d.FindName('DTitle').Text = $Title
    $d.FindName('DMsg').Text = $Message
    if ($Impact) { $d.FindName('DImp').Text = $Impact } else { $d.FindName('DImpBox').Visibility = 'Collapsed' }
    if ($Code) { $d.FindName('DCode').Text = $Code; $d.FindName('DCodeHdr').Text = $CodeHeader } else { $d.FindName('DCodeExp').Visibility = 'Collapsed' }
    $ok = $d.FindName('DOk'); $ok.Content = $OkText
    if ($Kind -eq 'Error') { $ok.Style = $d.FindResource('BtnSecondary') }
    $ok.Add_Click({ $d.DialogResult = $true })
    $cancel = $d.FindName('DCancel')
    if ($CancelText) { $cancel.Content = $CancelText } else { $cancel.Visibility = 'Collapsed' }
    [bool]$d.ShowDialog()
}

function Show-Error { param([string]$Title, [string]$Message) [void](Show-Dialog -Title $Title -Message $Message -OkText 'Close' -Kind Error) }

function Update-UiNow {
    $frame = New-Object System.Windows.Threading.DispatcherFrame
    [void][System.Windows.Threading.Dispatcher]::CurrentDispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::Background,
        [System.Windows.Threading.DispatcherOperationCallback]{ param($f) $f.Continue = $false; $null }, $frame)
    [System.Windows.Threading.Dispatcher]::PushFrame($frame)
}

function Set-Busy { param([string]$Text) $ui.TxtProg.Text = $Text; $ui.Prog.IsIndeterminate = $true }
function Clear-Busy { param([string]$Text) if (-not $script:Scanning -and $script:Jobs.Count -eq 0) { $ui.Prog.IsIndeterminate = $false }; if ($null -ne $Text) { $ui.TxtProg.Text = $Text } }

function Get-InvariantNumber { param($Value) if ($null -eq $Value -or "$Value" -eq '') { return $null }; try { [double]::Parse("$Value", [System.Globalization.CultureInfo]::InvariantCulture) } catch { $null } }

# Generic grid binding: rows are ordered dictionaries (column -> value), source objects are kept for selection
$script:GridSource = @{}
function Set-GridData {
    param($Grid, [object[]]$Rows, [object[]]$Source, [switch]$HideWhenEmpty)
    if ($HideWhenEmpty) { $Grid.Visibility = $(if ($Rows) { 'Visible' } else { 'Collapsed' }) }
    $dt = New-Object System.Data.DataTable
    [void]$dt.Columns.Add('_i', [int])
    $cols = @(); if ($Rows -and $Rows[0]) { $cols = @($Rows[0].Keys) }
    foreach ($c in $cols) {
        $sample = $Rows | ForEach-Object { $_[$c] } | Where-Object { $null -ne $_ -and "$_" -ne '' } | Select-Object -First 1
        if ($sample -is [int] -or $sample -is [long] -or $sample -is [double] -or $sample -is [decimal]) { [void]$dt.Columns.Add([string]$c, [double]) } else { [void]$dt.Columns.Add([string]$c) }
    }
    $i = 0
    foreach ($r in $Rows) {
        $dr = $dt.NewRow(); $dr['_i'] = $i
        foreach ($c in $cols) {
            $v = $r[$c]
            if ($dt.Columns[[string]$c].DataType -eq [double]) { if ($null -ne $v -and "$v" -ne '') { $dr[[string]$c] = [double]$v } }
            elseif ($v -is [datetime]) { $dr[[string]$c] = Format-Time $v }
            elseif ($v -is [bool]) { $dr[[string]$c] = $(if ($v) { 'Yes' } else { 'No' }) }
            elseif ($null -ne $v) { $dr[[string]$c] = [string]$v }
        }
        [void]$dt.Rows.Add($dr); $i++
    }
    $script:GridSource[$Grid.Name] = @($Source)
    $Grid.ItemsSource = $dt.DefaultView
}
function Get-GridSelection {
    param($Grid)
    $row = $Grid.SelectedItem
    if (-not $row) { return $null }
    $src = $script:GridSource[$Grid.Name]
    if (-not $src) { return $null }
    $src[[int]$row['_i']]
}

function Add-CanvasText {
    param($Canvas, [string]$Text, [double]$X, [double]$Y, [string]$Color = '#667085', [double]$Size = 11, [double]$Width = 0, [switch]$Bold)
    $t = New-Object System.Windows.Controls.TextBlock
    $t.Text = $Text; $t.FontSize = $Size; $t.Foreground = New-Brush $Color
    if ($Bold) { $t.FontWeight = 'SemiBold' }
    if ($Width -gt 0) { $t.Width = $Width; $t.TextTrimming = 'CharacterEllipsis'; $t.ToolTip = $Text }
    [System.Windows.Controls.Canvas]::SetLeft($t, $X); [System.Windows.Controls.Canvas]::SetTop($t, $Y)
    [void]$Canvas.Children.Add($t)
}
function Add-CanvasLine {
    param($Canvas, [double]$X1, [double]$Y1, [double]$X2, [double]$Y2, [string]$Color = '#EAECF0', [double]$Thickness = 1, [switch]$Dash)
    $l = New-Object System.Windows.Shapes.Line
    $l.X1 = $X1; $l.Y1 = $Y1; $l.X2 = $X2; $l.Y2 = $Y2; $l.Stroke = New-Brush $Color; $l.StrokeThickness = $Thickness
    if ($Dash) { $dc = New-Object System.Windows.Media.DoubleCollection; $dc.Add(4); $dc.Add(3); $l.StrokeDashArray = $dc }
    [void]$Canvas.Children.Add($l)
}
function Add-CanvasRect {
    param($Canvas, [double]$X, [double]$Y, [double]$W, [double]$H, [string]$Color, [string]$Tip)
    $r = New-Object System.Windows.Shapes.Rectangle
    $r.Width = [math]::Max(2, $W); $r.Height = $H; $r.RadiusX = 4; $r.RadiusY = 4; $r.Fill = New-Brush $Color
    if ($Tip) { $r.ToolTip = $Tip }
    [System.Windows.Controls.Canvas]::SetLeft($r, $X); [System.Windows.Controls.Canvas]::SetTop($r, $Y)
    [void]$Canvas.Children.Add($r)
}

function Get-NiceStep { param([double]$Total) foreach ($s in 1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 1800, 3600, 7200, 86400) { if ($Total / $s -le 8) { return $s } }; 86400 }

function Draw-LineChart {
    param($Canvas, [object[]]$Series, [object[]]$Markers, [string]$YTitle = 'seconds', [string]$Empty = 'No data yet.')
    $Canvas.Children.Clear()
    $w = $Canvas.ActualWidth; if ($w -lt 200) { $w = 900 }
    $h = $Canvas.Height; if (-not $h -or [double]::IsNaN($h)) { $h = 240 }
    $pts = @($Series | ForEach-Object { @($_.Points) } | Where-Object { $_ })
    if (-not $pts) { Add-CanvasText $Canvas $Empty 4 8 '#667085' 13; return }
    $l = 48; $r = 16; $t = 18; $b = 26
    $ticks = @($pts | ForEach-Object { ([datetime]$_.X).Ticks })
    $minX = ($ticks | Measure-Object -Minimum).Minimum; $maxX = ($ticks | Measure-Object -Maximum).Maximum
    if ($maxX -eq $minX) { $minX -= [TimeSpan]::FromHours(12).Ticks; $maxX += [TimeSpan]::FromHours(12).Ticks }
    $maxY = (($pts | ForEach-Object { [double]$_.Y }) | Measure-Object -Maximum).Maximum * 1.15
    if (-not $maxY -or $maxY -le 0) { $maxY = 1 }
    $pw = $w - $l - $r; $ph = $h - $t - $b
    $toX = { param($tk) $l + ($tk - $minX) / ($maxX - $minX) * $pw }
    $toY = { param($v) $t + $ph - ($v / $maxY) * $ph }
    for ($i = 0; $i -le 4; $i++) {
        $v = $maxY * $i / 4; $yy = & $toY $v
        Add-CanvasLine $Canvas $l $yy ($l + $pw) $yy '#F2F4F7' 1
        Add-CanvasText $Canvas ([string][math]::Round($v)) 4 ($yy - 8) '#667085' 10
    }
    Add-CanvasText $Canvas $YTitle $l 0 '#98A2B3' 10
    for ($i = 0; $i -le 4; $i++) {
        $tk = $minX + ($maxX - $minX) * $i / 4
        Add-CanvasText $Canvas ((New-Object DateTime ([long]$tk)).ToString('dd MMM', [System.Globalization.CultureInfo]::InvariantCulture)) ((& $toX $tk) - 16) ($t + $ph + 6) '#667085' 10
    }
    foreach ($m in @($Markers)) {
        if (-not $m) { continue }
        $tk = ([datetime]$m.Time).Ticks
        if ($tk -lt $minX -or $tk -gt $maxX) { continue }
        $xx = & $toX $tk
        Add-CanvasLine $Canvas $xx $t $xx ($t + $ph) $m.Color 1 -Dash
        Add-CanvasText $Canvas $m.Label ($xx + 3) $t $m.Color 10
    }
    foreach ($s in @($Series)) {
        $sp = @($s.Points | Sort-Object { ([datetime]$_.X).Ticks })
        if (-not $sp) { continue }
        $poly = New-Object System.Windows.Shapes.Polyline
        $poly.Stroke = New-Brush $s.Color; $poly.StrokeThickness = 2
        $pc = New-Object System.Windows.Media.PointCollection
        foreach ($p in $sp) { $pc.Add((New-Object System.Windows.Point (& $toX ([datetime]$p.X).Ticks), (& $toY ([double]$p.Y)))) }
        $poly.Points = $pc
        [void]$Canvas.Children.Add($poly)
        foreach ($p in $sp) {
            $e = New-Object System.Windows.Shapes.Ellipse
            $e.Width = 7; $e.Height = 7; $e.Fill = New-Brush '#FFFFFF'; $e.Stroke = New-Brush $s.Color; $e.StrokeThickness = 2
            $e.ToolTip = "$($s.Name) $(([datetime]$p.X).ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)): $([math]::Round([double]$p.Y, 1))"
            [System.Windows.Controls.Canvas]::SetLeft($e, (& $toX ([datetime]$p.X).Ticks) - 3.5); [System.Windows.Controls.Canvas]::SetTop($e, (& $toY ([double]$p.Y)) - 3.5)
            [void]$Canvas.Children.Add($e)
        }
    }
}
#endregion

#region Window
[xml]$xaml = $MainXaml.Replace('%STYLES%', $StylesXaml).Replace('%GRIDSTYLES%', $GridStylesXaml)
$win = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))
$wa = [System.Windows.SystemParameters]::WorkArea
$win.Width = [math]::Min(1500, $wa.Width - 40)
$win.Height = [math]::Min(960, $wa.Height - 40)

$ui = @{}
foreach ($node in $xaml.SelectNodes("//*[@*[local-name()='Name' and namespace-uri()='http://schemas.microsoft.com/winfx/2006/xaml']]")) {
    $n = $node.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml')
    if ($n) { $el = $win.FindName($n); if ($el) { $ui[$n] = $el } }
}
$Tiles = @($ui.TileProblem, $ui.TileWarning, $ui.TileInfo, $ui.TileOK, $ui.TileNA)
$Pages = @{ Findings = $ui.PageFindings; Timeline = $ui.PageTimeline; Trends = $ui.PageTrends; Reports = $ui.PageReports; Compare = $ui.PageCompare; Fleet = $ui.PageFleet; Azure = $ui.PageAzure; FixHistory = $ui.PageFixHistory; Tools = $ui.PageTools }

# Hide helper columns (names starting with "_") in all auto-generated grids
foreach ($g in @($ui.GridTl, $ui.GridTrBA, $ui.GridTrBuild, $ui.GridTrHost, $ui.GridRep, $ui.GridDiff, $ui.GridFleetHost, $ui.GridAvdConn, $ui.GridAvdCp, $ui.GridRh, $ui.GridFh)) {
    $g.Add_AutoGeneratingColumn({ param($s, $e) if ($e.PropertyName -like '_*') { $e.Cancel = $true } else { $e.Column.Header = ([string]$e.Column.Header).ToUpper() } })
}

$script:Table = New-Object System.Data.DataTable
foreach ($c in 'Id', 'Status', 'Category', 'Name', 'Summary', 'SortKey', 'AutoFix') { [void]$script:Table.Columns.Add($c) }
$script:View = $script:Table.DefaultView
$script:View.Sort = 'SortKey ASC'
$ui.Grid.ItemsSource = $script:View

$script:ResultById = @{}
$script:AllResults = New-Object System.Collections.Generic.List[object]
$script:HostEnv = $null
$script:StatusFilter = $null
$script:Current = $null
$script:Scanning = $false
$script:FixBusy = $false
$script:Tracing = $false
$script:LastTrace = $null
$script:Jobs = New-Object System.Collections.ArrayList
$script:DataDir = Get-ToolDataDir
$ui.TxtLogPath.Text = "Data, fix log and backups: $script:DataDir"
[void]$ui.CmbCategory.Items.Add('All categories'); $ui.CmbCategory.SelectedIndex = 0
#endregion

#region Background jobs
$script:JobTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:JobTimer.Interval = [TimeSpan]::FromMilliseconds(250)
$script:JobTimer.Add_Tick({
    foreach ($j in @($script:Jobs)) {
        if (-not $j.Handle.IsCompleted) { continue }
        $out = @(); $err = $null
        try { $out = @($j.Ps.EndInvoke($j.Handle)) }
        catch { $ex = $_.Exception; while ($ex.InnerException) { $ex = $ex.InnerException }; $err = $ex.Message }
        if (-not $err -and -not $out -and $j.Ps.Streams.Error.Count -gt 0) { $err = (@($j.Ps.Streams.Error) | Select-Object -First 3 | ForEach-Object { $_.ToString() }) -join "`r`n" }
        try { $j.Ps.Runspace.Dispose(); $j.Ps.Dispose() } catch { }
        $script:Jobs.Remove($j)
        try { & $j.OnDone $out $err $j.State } catch { Show-Error 'Unexpected error' $_.Exception.Message }
    }
    if ($script:Jobs.Count -eq 0) { $script:JobTimer.Stop(); Clear-Busy $null }
    else { $ui.TxtProg.Text = ((@($script:Jobs) | ForEach-Object { $_.Name }) -join ', ') + '...' }
})

function Start-BgJob {
    param([string]$Name, [string]$Script, [hashtable]$Vars = @{}, [scriptblock]$OnDone, $State)
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'
    $rs.Open()
    $rs.SessionStateProxy.SetVariable('LookbackDays', $LookbackDays)
    $rs.SessionStateProxy.SetVariable('KnownIssuesPath', $KnownIssuesPath)
    $rs.SessionStateProxy.SetVariable('ToolRoot', $ToolRoot)
    $rs.SessionStateProxy.SetVariable('SettingsPath', $SettingsPath)
    foreach ($k in $Vars.Keys) { $rs.SessionStateProxy.SetVariable($k, $Vars[$k]) }
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($script:CoreAll + "`n" + $Script)
    $job = [pscustomobject]@{ Name = $Name; Ps = $ps; Handle = $null; OnDone = $OnDone; State = $State }
    $job.Handle = $ps.BeginInvoke()
    [void]$script:Jobs.Add($job)
    Set-Busy "$Name..."
    if (-not $script:JobTimer.IsEnabled) { $script:JobTimer.Start() }
}
#endregion

#region Findings tab
function Update-Filter {
    $parts = @()
    if ($script:StatusFilter) { $parts += "Status = '$($script:StatusFilter)'" }
    elseif (-not $ui.ChkNA.IsChecked) { $parts += "Status <> 'N/A'" }
    $cat = [string]$ui.CmbCategory.SelectedItem
    if ($cat -and $cat -ne 'All categories') { $parts += "Category = '$($cat -replace "'", "''")'" }
    $q = ($ui.TxtSearch.Text -replace "['\[\]\*%]", '').Trim()
    if ($q) { $parts += "(Name LIKE '%$q%' OR Summary LIKE '%$q%' OR Category LIKE '%$q%' OR Id LIKE '%$q%')" }
    $script:View.RowFilter = $parts -join ' AND '
    $ui.TxtFilter.Text = "Showing $($script:View.Count) of $($script:Table.Rows.Count) checks"
}

function Update-Tiles {
    foreach ($t in $Tiles) {
        if ($script:StatusFilter -and [string]$t.Tag -eq $script:StatusFilter) {
            $t.BorderBrush = New-Brush '#2563EB'; $t.BorderThickness = New-Object System.Windows.Thickness 2
        } else {
            $t.BorderBrush = New-Brush '#E4E7EC'; $t.BorderThickness = New-Object System.Windows.Thickness 1
        }
    }
}

function Update-Counts {
    $cnt = @{}; foreach ($s in 'Problem', 'Warning', 'Info', 'OK', 'N/A', 'Error') { $cnt[$s] = 0 }
    foreach ($r in $script:AllResults) { $cnt[$r.Status]++ }
    $ui.NProblem.Text = [string]($cnt['Problem'] + $cnt['Error']); $ui.NWarning.Text = [string]$cnt['Warning']; $ui.NInfo.Text = [string]$cnt['Info']
    $ui.NOK.Text = [string]$cnt['OK']; $ui.NNA.Text = [string]$cnt['N/A']
    $ui.TxtFilter.Text = "Showing $($script:View.Count) of $($script:Table.Rows.Count) checks"
}

function Select-Check {
    param([string]$Id)
    $ui.Tabs.SelectedIndex = 0
    $script:StatusFilter = $null; $ui.TxtSearch.Text = ''; $ui.CmbCategory.SelectedIndex = 0
    Update-Tiles; Update-Filter
    foreach ($drv in $script:View) {
        if ([string]$drv['Id'] -eq $Id) { $ui.Grid.SelectedItem = $drv; $ui.Grid.ScrollIntoView($drv); break }
    }
    # SelectionChanged does not fire when the row was already selected
    if ($script:ResultById[$Id]) { Show-Detail $script:ResultById[$Id] }
}

function Update-Causes {
    $ui.CausesList.Children.Clear()
    $top = @(Get-TopCauses $script:AllResults)
    if (-not $top) {
        $ui.CausesHint.Visibility = 'Visible'
        $ui.CausesHint.Text = 'No problems or warnings found. If users still get a black screen, look at the Logon timeline tab, run the analyser inside an affected user session right after a slow logon, and record a logon trace (Tools).'
        return
    }
    $ui.CausesHint.Visibility = 'Collapsed'
    $k = 0
    foreach ($t in $top) {
        $k++
        $btn = New-Object System.Windows.Controls.Button
        $btn.Style = $win.FindResource('CauseBtn')
        $btn.Tag = $t.Id
        $dp = New-Object System.Windows.Controls.DockPanel
        $num = New-Object System.Windows.Controls.TextBlock
        $num.Text = "$k"; $num.Width = 18; $num.FontWeight = 'SemiBold'; $num.Foreground = New-Brush '#98A2B3'
        [System.Windows.Controls.DockPanel]::SetDock($num, 'Left')
        $pill = New-StatusPill -Status $t.Status
        $pill.VerticalAlignment = 'Top'
        [System.Windows.Controls.DockPanel]::SetDock($pill, 'Left')
        $tb = New-Object System.Windows.Controls.TextBlock
        $tb.TextWrapping = 'Wrap'; $tb.Foreground = New-Brush '#475467'
        $run1 = New-Object System.Windows.Documents.Run ($t.Name); $run1.FontWeight = 'SemiBold'; $run1.Foreground = New-Brush '#101828'
        $run2 = New-Object System.Windows.Documents.Run ("  -  " + $t.Summary)
        $tb.Inlines.Add($run1); $tb.Inlines.Add($run2)
        if ($t.AutoFix) {
            $af = New-Pill -Text '1-click fix' -Bg '#EFF4FF' -Fg '#1849A9' -Margin 8, 0, 0, 0
            $af.VerticalAlignment = 'Top'
            [System.Windows.Controls.DockPanel]::SetDock($af, 'Right')
            [void]$dp.Children.Add($af)
        }
        [void]$dp.Children.Add($num); [void]$dp.Children.Add($pill); [void]$dp.Children.Add($tb)
        $btn.Content = $dp
        $btn.Add_Click({ Select-Check ([string]$this.Tag) })
        [void]$ui.CausesList.Children.Add($btn)
    }
}

function Set-Section {
    param($Container, $TextBox, [string]$Text)
    if ($Text) { $TextBox.Text = $Text; $Container.Visibility = 'Visible' } else { $Container.Visibility = 'Collapsed' }
}

function Show-Detail {
    param($r)
    $script:Current = $r
    if (-not $r) { $ui.DetailPanel.Visibility = 'Collapsed'; $ui.DetailEmpty.Visibility = 'Visible'; return }
    $ui.DetailEmpty.Visibility = 'Collapsed'; $ui.DetailPanel.Visibility = 'Visible'
    $ui.DStatusPill.Background = New-Brush $StatusTint[$r.Status][0]
    $ui.DStatusText.Foreground = New-Brush $StatusTint[$r.Status][1]
    $ui.DStatusText.Text = $r.Status
    $ui.DMeta.Text = "$($r.Id)   |   $($r.Category)"
    $ui.DName.Text = $r.Name
    $ui.DSummary.Text = $r.Summary
    Set-Section $ui.FixSection $ui.DFix $r.Fix
    Set-Section $ui.ImpactSection $ui.DImpact $r.Impact
    Set-Section $ui.RefSection $ui.DRef $r.Reference

    $a = $r.AutoFix
    if ($a -and $r.Status -ne 'OK' -and $r.Status -ne 'N/A') {
        $ui.AutoFixSection.Visibility = 'Visible'
        $ui.DAutoChanges.Text = $a.Changes
        $ui.DAutoBadges.Children.Clear()
        $isAdmin = $script:HostEnv -and $script:HostEnv.IsAdmin
        if ($a.Admin)     { [void]$ui.DAutoBadges.Children.Add((New-Pill -Text 'Requires administrator' -Bg $(if ($isAdmin) { '#F2F4F7' } else { '#FEF0C7' }) -Fg $(if ($isAdmin) { '#344054' } else { '#B54708' }))) }
        else              { [void]$ui.DAutoBadges.Children.Add((New-Pill -Text 'No admin rights needed' -Bg '#F2F4F7' -Fg '#344054')) }
        if ($a.Backup)    { [void]$ui.DAutoBadges.Children.Add((New-Pill -Text 'Backup first - can be undone' -Bg '#DCFAE6' -Fg '#067647')) }
        if ($a.Reboot)    { [void]$ui.DAutoBadges.Children.Add((New-Pill -Text "Reboot $($a.Reboot.ToLower())" -Bg '#FEE4E2' -Fg '#B42318')) }
        else              { [void]$ui.DAutoBadges.Children.Add((New-Pill -Text 'No reboot' -Bg '#F2F4F7' -Fg '#344054')) }
        if ($a.UserScope) { [void]$ui.DAutoBadges.Children.Add((New-Pill -Text 'Current user only' -Bg '#F4EBFF' -Fg '#6941C6')) }
        $ui.BtnApply.Content = "Apply fix:  $($a.Label)"
        $note = ''; $can = $true
        if ($a.Admin -and -not $isAdmin) { $can = $false; $note = 'Restart the tool as administrator (button at the top) to apply this fix.' }
        elseif ($a.UserScope -and $isAdmin) { $note = "This applies to $($script:HostEnv.UserName) only. To fix another user, run the tool (not elevated) in that user's session." }
        if ($script:FixBusy)  { $can = $false; $note = 'Another fix is running...' }
        if ($script:Scanning) { $can = $false; $note = 'Wait until the scan has finished.' }
        $ui.BtnApply.IsEnabled = $can
        $ui.DAutoNote.Text = $note
        $ui.DAutoNote.Visibility = $(if ($note) { 'Visible' } else { 'Collapsed' })
    } else {
        $ui.AutoFixSection.Visibility = 'Collapsed'
    }

    if ($r.FixCommand) { $ui.ExpCmd.Visibility = 'Visible'; $ui.DCmd.Text = $r.FixCommand; $ui.BtnCopy.Content = 'Copy to clipboard' } else { $ui.ExpCmd.Visibility = 'Collapsed' }
    if ($r.Detail) { $ui.ExpEvidence.Visibility = 'Visible'; $ui.DDetail.Text = $r.Detail } else { $ui.ExpEvidence.Visibility = 'Collapsed' }
    $ui.DetailPanel.ScrollToTop()
}

function Update-ResultRow {
    param($New)
    $old = $script:ResultById[$New.Id]
    $idx = -1; if ($old) { $idx = $script:AllResults.IndexOf($old) }
    if ($idx -ge 0) { $script:AllResults[$idx] = $New } else { $script:AllResults.Add($New) }
    $script:ResultById[$New.Id] = $New
    $rows = $script:Table.Select("Id = '$($New.Id)'")
    if ($rows.Count -gt 0) {
        $row = $rows[0]
        $row['Status'] = $New.Status; $row['Summary'] = $New.Summary; $row['SortKey'] = $New.SortKey
        $row['AutoFix'] = $(if ($New.AutoFix -and $New.Status -ne 'OK' -and $New.Status -ne 'N/A') { 'Yes' } else { '' })
    }
    Update-Counts; Update-Causes; Update-Filter
    if ($script:Current -and $script:Current.Id -eq $New.Id) { Show-Detail $New }
}

function Set-HostChips {
    param($E)
    $ui.HostChips.Children.Clear()
    foreach ($txt in @($E.ComputerName, $E.Family, "Build $($E.BuildString)", $E.Roles)) {
        [void]$ui.HostChips.Children.Add((New-Pill -Text $txt -Bg '#F2F4F7' -Fg '#344054'))
    }
    if ($E.IsAdmin) { [void]$ui.HostChips.Children.Add((New-Pill -Text "Administrator ($($E.UserName))" -Bg '#DCFAE6' -Fg '#067647')) }
    else            { [void]$ui.HostChips.Children.Add((New-Pill -Text "Not elevated ($($E.UserName)) - some checks limited" -Bg '#FEF0C7' -Fg '#B54708')) }
}

function Start-Scan {
    $script:Scanning = $true
    $script:Table.Clear(); $script:ResultById.Clear(); $script:AllResults.Clear()
    $script:HostEnv = $null; $script:StatusFilter = $null
    Show-Detail $null; Update-Tiles; Update-Counts
    $ui.CausesList.Children.Clear(); $ui.CausesHint.Visibility = 'Visible'; $ui.CausesHint.Text = 'Scanning...'
    $ui.BtnScan.IsEnabled = $false; $ui.BtnExport.IsEnabled = $false
    $ui.Prog.IsIndeterminate = $false; $ui.Prog.Value = 0; $ui.TxtProg.Text = 'Collecting host information...'

    $script:Sync = [hashtable]::Synchronized(@{ Results = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList)); Env = $null; Done = $false; Error = $null; I = 0; N = 1; Current = '' })
    $script:Shown = 0
    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $rs.SessionStateProxy.SetVariable('sync', $script:Sync)
    $rs.SessionStateProxy.SetVariable('LookbackDays', $LookbackDays)
    $rs.SessionStateProxy.SetVariable('KnownIssuesPath', $KnownIssuesPath)
    $runner = @'
try {
    $E = Get-HostEnvironment
    $sync.Env = $E
    $null = Invoke-AllChecks -E $E -OnResult { param($r, $i, $n) [void]$sync.Results.Add($r); $sync.I = $i; $sync.N = $n; $sync.Current = $r.Name }
} catch { $sync.Error = $_.Exception.Message }
finally { $sync.Done = $true }
'@
    $script:ScanPs = [powershell]::Create()
    $script:ScanPs.Runspace = $rs
    [void]$script:ScanPs.AddScript($script:EngineText + "`n" + $runner)
    $script:ScanHandle = $script:ScanPs.BeginInvoke()
    $script:ScanTimer.Start()
}

$script:ScanTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:ScanTimer.Interval = [TimeSpan]::FromMilliseconds(200)
$script:ScanTimer.Add_Tick({
    $s = $script:Sync
    if ($s.Env -and -not $script:HostEnv) {
        $script:HostEnv = $s.Env
        Set-HostChips $s.Env
        if (-not $s.Env.IsAdmin) { $ui.BtnElevate.Visibility = 'Visible' }
    }
    while ($script:Shown -lt $s.Results.Count) {
        $r = $s.Results[$script:Shown]; $script:Shown++
        $script:ResultById[$r.Id] = $r
        $script:AllResults.Add($r)
        $af = $(if ($r.AutoFix -and $r.Status -ne 'OK' -and $r.Status -ne 'N/A') { 'Yes' } else { '' })
        [void]$script:Table.Rows.Add($r.Id, $r.Status, $r.Category, $r.Name, $r.Summary, $r.SortKey, $af)
    }
    if ($s.N -gt 0) { $ui.Prog.Value = [math]::Round($s.I / $s.N * 100) }
    if ($s.Current) { $ui.TxtProg.Text = "Checking $($s.I) of $($s.N):  $($s.Current)" }
    Update-Counts
    if (-not $s.Done) { return }
    $script:ScanTimer.Stop()
    try { $script:ScanPs.EndInvoke($script:ScanHandle) } catch { }
    $script:ScanPs.Runspace.Dispose(); $script:ScanPs.Dispose()
    $script:Scanning = $false
    $ui.Prog.Value = 0
    $ui.BtnScan.IsEnabled = $true; $ui.BtnExport.IsEnabled = $true
    $ui.CmbCategory.Items.Clear(); [void]$ui.CmbCategory.Items.Add('All categories')
    foreach ($c in ($script:AllResults | ForEach-Object { $_.Category } | Select-Object -Unique)) { [void]$ui.CmbCategory.Items.Add($c) }
    $ui.CmbCategory.SelectedIndex = 0
    Update-Filter
    if ($s.Error) {
        $ui.TxtProg.Text = "Scan failed: $($s.Error)"
        $ui.CausesHint.Text = "Scan failed: $($s.Error)"
        return
    }
    [void](Save-ScanHistory -E $script:HostEnv -Results $script:AllResults)
    $p = @($script:AllResults | Where-Object { $_.Status -eq 'Problem' }).Count
    $w = @($script:AllResults | Where-Object { $_.Status -eq 'Warning' }).Count
    $ui.TxtProg.Text = "Scan finished at $(Get-Date -Format 'HH:mm:ss') - $p problem(s), $w warning(s)"
    Update-Causes
    $first = Get-TopCauses $script:AllResults 1
    if ($first) { Select-Check $first.Id } elseif ($script:Current) { Show-Detail $script:Current }
})

function Start-Fix {
    param($r)
    $a = $r.AutoFix
    $msg = Join-Lines @(
        "Check:  $($r.Id) - $($r.Name)"
        ''
        'What will be changed on this host:'
        $a.Changes
        ''
        $(if ($a.Backup) { 'The registry key is backed up first, so the fix can be undone from the Fix history tab.' })
        $(if ($a.Reboot -eq 'Required') { 'A REBOOT IS REQUIRED afterwards. The tool does not reboot for you - drain the host and reboot when users have signed out.' })
        $(if ($a.Reboot -eq 'Recommended') { 'A reboot is recommended afterwards. The tool does not reboot for you.' })
        $(if ($a.UserScope) { "The change applies to $($script:HostEnv.UserName) only." })
        "Everything is logged to $script:DataDir\FixHistory.jsonl."
    )
    $ok = Show-Dialog -Title "Apply fix: $($a.Label)?" -Message $msg -Impact $r.Impact -Code $r.FixCommand -OkText 'Apply fix' -CancelText 'Cancel' -Kind Confirm
    if (-not $ok) { return }
    $script:FixBusy = $true
    $ui.BtnApply.IsEnabled = $false; $ui.BtnApply.Content = 'Applying fix...'
    $ui.BtnScan.IsEnabled = $false
    $runner = @'
$buf = New-Object System.Collections.Generic.List[string]
$ok = $true; $errText = ''
try {
    $ErrorActionPreference = 'Stop'
    & ([scriptblock]::Create($FixCode)) 2>&1 | ForEach-Object { [void]$buf.Add([string]$_) }
} catch { $ok = $false; $errText = $_.Exception.Message }
$ErrorActionPreference = 'Continue'
$output = ($buf -join "`r`n").Trim()
Write-FixHistory -CheckId $CheckId -Label $Label -Success $ok -ErrorText $errText -Output $output
$new = $null
try { $E = Get-HostEnvironment; $new = @(Invoke-AllChecks -E $E -OnlyIds $CheckId) | Select-Object -First 1 } catch { }
[pscustomobject]@{ Ok = $ok; Error = $errText; Output = $output; New = $new }
'@
    Start-BgJob -Name "Applying fix: $($a.Label)" -Script $runner -Vars @{ FixCode = [string]$r.FixCommand; CheckId = [string]$r.Id; Label = [string]$a.Label } -State $r -OnDone {
        param($out, $err, $target)
        $script:FixBusy = $false
        $ui.BtnScan.IsEnabled = $true
        $res = $out | Select-Object -Last 1
        if ($res -and $res.New) { Update-ResultRow $res.New } else { Show-Detail $target }
        if ($err -or -not $res) { Show-Error 'Fix could not run' "$err"; return }
        if (-not $res.Ok) {
            $ui.TxtProg.Text = "Fix failed: $($target.AutoFix.Label)"
            $m = Join-Lines @("The fix '$($target.AutoFix.Label)' failed:", '', $res.Error, '', 'Steps after the error were not run. If a backup was taken, the fix can still be undone from the Fix history tab.')
            [void](Show-Dialog -Title 'Fix failed' -Message $m -Code $res.Output -CodeHeader 'Output before the error' -OkText 'Close' -Kind Error)
            return
        }
        $ui.TxtProg.Text = "Fix applied: $($target.AutoFix.Label)"
        $m = Join-Lines @(
            "The fix '$($target.AutoFix.Label)' was applied."
            ''
            $(if ($res.New) { "Re-checked: $($res.New.Status) - $($res.New.Summary)" })
            $(if ($target.AutoFix.Reboot -eq 'Required') { ''; 'Remember: a reboot is required before the change is fully active.' })
            $(if ($target.AutoFix.Reboot -eq 'Recommended') { ''; 'A reboot is recommended.' })
        )
        [void](Show-Dialog -Title 'Fix applied' -Message $m -Code $res.Output -CodeHeader 'Output' -OkText 'Close' -Kind Success)
    }
}
#endregion

#region Logon timeline tab
function Get-PhaseColor {
    param([string]$Name)
    switch -Wildcard ($Name) {
        'Sign-in to desktop*' { '#344054' }
        'Before profile*'     { '#98A2B3' }
        'Profile load*'       { '#2563EB' }
        'Group Policy*'       { '#7A5AF8' }
        'Pre-shell*'          { '#DC6803' }
        'Logon to Explorer*'  { '#DC6803' }
        'Active Setup*'       { '#E31B54' }
        'Shell start*'        { '#079455' }
        'Run keys*'           { '#D0D5DD' }
        default               { '#475467' }
    }
}

function Draw-Timeline {
    param($L)
    $c = $ui.TlCanvas; $c.Children.Clear()
    $rows = @([pscustomobject]@{ Name = 'Sign-in to desktop (total)'; Off = 0; Sec = $L.TotalSec })
    foreach ($p in @($L.Phases)) { $rows += [pscustomobject]@{ Name = $p.Name; Off = [math]::Max(0, ($p.Start - $L.Time).TotalSeconds); Sec = $p.Seconds } }
    $rowH = 34; $top = 28; $labelW = 250
    $c.Height = $top + $rows.Count * $rowH + 8
    $w = $c.ActualWidth; if ($w -lt 300) { $w = 680 }
    $total = (@($rows | Where-Object { $null -ne $_.Sec } | ForEach-Object { [double]$_.Off + [double]$_.Sec }) | Measure-Object -Maximum).Maximum
    if (-not $total -or $total -le 0) { $total = 1 }
    $plotW = $w - $labelW - 70; $scale = $plotW / $total
    $step = Get-NiceStep $total
    for ($s = 0; $s -le $total + 0.001; $s += $step) {
        $x = $labelW + $s * $scale
        Add-CanvasLine $c $x ($top - 6) $x ($top + $rows.Count * $rowH) '#F2F4F7' 1
        Add-CanvasText $c "$([math]::Round($s)) s" ($x - 8) 4 '#667085' 10
    }
    $i = 0
    foreach ($r in $rows) {
        $y = $top + $i * $rowH
        Add-CanvasText $c $r.Name 0 ($y + 8) $(if ($i -eq 0) { '#101828' } else { '#344054' }) 12 ($labelW - 12) -Bold:($i -eq 0)
        if ($null -ne $r.Sec) {
            $x = $labelW + $r.Off * $scale
            Add-CanvasRect $c $x ($y + 7) ($r.Sec * $scale) 20 (Get-PhaseColor $r.Name) "$($r.Name): $($r.Sec) s"
            Add-CanvasText $c "$($r.Sec) s" ($x + [math]::Max(2, $r.Sec * $scale) + 6) ($y + 9) '#475467' 11
        } else {
            Add-CanvasText $c 'not measured' ($labelW + 4) ($y + 9) '#98A2B3' 11
        }
        $i++
    }
}

function Show-Timeline {
    param($L)
    if (-not $L) { return }
    $ui.TlTitle.Text = "$($L.User) - $(Format-Time $L.Time)"
    $tot = if ($null -ne $L.TotalSec) { "$($L.TotalSec) s from sign-in to desktop" } else { 'time to desktop not measured' }
    $ui.TlSub.Text = "$tot  |  desktop measured by: $($L.DesktopSource)  |  probe: $(if ($L.HasProbe) { 'yes' } else { 'no' })  |  process auditing: $(if ($L.HasAudit) { 'yes' } else { 'no' })"
    Draw-Timeline $L
    if ($L.Advice) { $ui.TlAdvice.Text = $L.Advice; $ui.TlAdviceBox.Visibility = 'Visible' } else { $ui.TlAdviceBox.Visibility = 'Collapsed' }
    $ui.TlDetail.Text = Join-Lines (@($L.Phases) | ForEach-Object { "{0,-44} {1}  ->  {2}   {3,7} s   ({4})" -f $_.Name, (Format-Time $_.Start), (Format-Time $_.End), $_.Seconds, $_.Source })
}
#endregion

#region Trends tab
function Update-Trends {
    $d = $script:TrendData
    if (-not $d) { return }
    $recs = @($d.Probe | Where-Object { $_.LogonTimeDt -and $null -ne $_.TimeToDesktopSec })
    $mine = @($recs | Where-Object { $_.Computer -eq $env:COMPUTERNAME })
    $useAll = $ui.ChkTrAll.IsChecked -or -not $mine
    $use = if ($useAll) { $recs } else { $mine }
    $hostCount = @($recs | ForEach-Object { $_.Computer } | Select-Object -Unique).Count
    $ui.TxtTrInfo.Text = "$($recs.Count) measured logon(s) from $hostCount host(s). Chart: $(if ($useAll) { 'all hosts' } else { 'this host' })."
    if (-not $recs) { $ui.TxtTrInfo.Text = 'No logon probe data yet - install the logon probe in the Tools tab (and set a central share to collect data from all hosts).' }

    $med = @(); $p90 = @()
    foreach ($g in ($use | Group-Object { $_.LogonTimeDt.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture) })) {
        $day = $g.Group[0].LogonTimeDt.Date.AddHours(12)
        $vals = @($g.Group | ForEach-Object { [double]$_.TimeToDesktopSec })
        $med += [pscustomobject]@{ X = $day; Y = (Get-Median $vals) }
        $p90 += [pscustomobject]@{ X = $day; Y = (Get-Percentile $vals 90) }
    }
    $markers = @()
    if ($script:HostEnv) { foreach ($h in @($script:HostEnv.HotFixList)) { if ($h.InstalledOn) { $markers += [pscustomobject]@{ Time = [datetime]$h.InstalledOn; Label = $h.Id; Color = '#DC6803'; What = "Update $($h.Id)" } } } }
    foreach ($f in @($d.Fixes | Where-Object { $_.Success -and $_.TimeDt -and $_.Computer -eq $env:COMPUTERNAME })) { $markers += [pscustomobject]@{ Time = $f.TimeDt; Label = $f.CheckId; Color = '#079455'; What = "$($f.Kind) $($f.CheckId): $($f.Label)" } }
    Draw-LineChart $ui.TrChart @(@{ Name = 'Median'; Color = '#2563EB'; Points = $med }, @{ Name = '90th percentile'; Color = '#F79009'; Points = $p90 }) $markers 'seconds to desktop' 'No logon probe data yet.'

    $ba = foreach ($m in ($markers | Sort-Object Time -Descending)) {
        $before = @($mine | Where-Object { $_.LogonTimeDt -ge $m.Time.AddDays(-7) -and $_.LogonTimeDt -lt $m.Time } | ForEach-Object { [double]$_.TimeToDesktopSec })
        $after  = @($mine | Where-Object { $_.LogonTimeDt -ge $m.Time -and $_.LogonTimeDt -lt $m.Time.AddDays(7) } | ForEach-Object { [double]$_.TimeToDesktopSec })
        if (-not $before -and -not $after) { continue }
        $mb = Get-Median $before; $ma = Get-Median $after
        [ordered]@{ 'When' = $m.Time; 'What' = $m.What; 'Logons before' = $before.Count; 'Median before (s)' = $mb; 'Logons after' = $after.Count; 'Median after (s)' = $ma
                    'Change' = $(if ($mb -and $ma) { '{0:+0;-0;0}%' -f [math]::Round(($ma - $mb) / $mb * 100) } else { '' }) }
    }
    Set-GridData $ui.GridTrBA @($ba) @($ba) -HideWhenEmpty

    $bb = foreach ($g in ($recs | Group-Object OsBuild | Sort-Object Name -Descending)) {
        $vals = @($g.Group | ForEach-Object { [double]$_.TimeToDesktopSec })
        [ordered]@{ 'Build' = $g.Name; 'Logons' = $g.Count; 'Hosts' = @($g.Group | ForEach-Object { $_.Computer } | Select-Object -Unique).Count
                    'Median (s)' = (Get-Median $vals); '90th pct (s)' = (Get-Percentile $vals 90)
                    'First seen' = ($g.Group | Sort-Object LogonTimeDt | Select-Object -First 1).LogonTimeDt; 'Last seen' = ($g.Group | Sort-Object LogonTimeDt | Select-Object -Last 1).LogonTimeDt }
    }
    Set-GridData $ui.GridTrBuild @($bb) @($bb) -HideWhenEmpty

    $now = Get-Date
    $bh = foreach ($g in ($recs | Group-Object Computer | Sort-Object Name)) {
        $last = @($g.Group | Where-Object { $_.LogonTimeDt -ge $now.AddDays(-1) } | ForEach-Object { [double]$_.TimeToDesktopSec })
        $prev = @($g.Group | Where-Object { $_.LogonTimeDt -ge $now.AddDays(-8) -and $_.LogonTimeDt -lt $now.AddDays(-1) } | ForEach-Object { [double]$_.TimeToDesktopSec })
        $ml = Get-Median $last; $mp = Get-Median $prev
        $chg = $null; if ($ml -and $mp) { $chg = [math]::Round(($ml - $mp) / $mp * 100) }
        $verdict = if ($null -eq $chg) { 'Not enough data' } elseif ($chg -ge 30 -and $last.Count -ge 3) { 'Slower - check this host' } elseif ($chg -le -30) { 'Faster' } else { 'Unchanged' }
        $timeouts = @($g.Group | Where-Object { $_.TimedOut -and $_.LogonTimeDt -ge $now.AddDays(-1) }).Count
        if ($timeouts) { $verdict = "$timeouts logon(s) without desktop in 24 h" }
        [ordered]@{ 'Host' = $g.Name; 'Logons 24 h' = $last.Count; 'Median 24 h (s)' = $ml; 'Median previous 7 days (s)' = $mp; 'Change %' = $chg; 'Verdict' = $verdict }
    }
    Set-GridData $ui.GridTrHost @($bh) @($bh) -HideWhenEmpty

    # Scan history metrics
    $hist = @($d.History | Where-Object { $_.Computer -eq $env:COMPUTERNAME })
    $names = @($hist | ForEach-Object { $_.Results } | ForEach-Object { if ($_.Metrics) { $_.Metrics.PSObject.Properties.Name } } | Select-Object -Unique | Sort-Object)
    $sel = [string]$ui.CmbMetric.SelectedItem
    $ui.CmbMetric.Items.Clear(); foreach ($n in $names) { [void]$ui.CmbMetric.Items.Add($n) }
    if ($sel -and $names -contains $sel) { $ui.CmbMetric.SelectedItem = $sel } elseif ($names -contains 'FirewallRules') { $ui.CmbMetric.SelectedItem = 'FirewallRules' } elseif ($names) { $ui.CmbMetric.SelectedIndex = 0 }
    Update-MetricChart
}

function Update-MetricChart {
    $d = $script:TrendData; if (-not $d) { return }
    $name = [string]$ui.CmbMetric.SelectedItem
    $pts = @()
    if ($name) {
        foreach ($h in @($d.History | Where-Object { $_.Computer -eq $env:COMPUTERNAME -and $_.TimeDt })) {
            foreach ($r in @($h.Results)) {
                if ($r.Metrics -and $r.Metrics.PSObject.Properties[$name] -and $null -ne $r.Metrics.$name) { $pts += [pscustomobject]@{ X = $h.TimeDt; Y = [double]$r.Metrics.$name }; break }
            }
        }
    }
    Draw-LineChart $ui.MetricChart @(@{ Name = $name; Color = '#2563EB'; Points = $pts }) @() $name 'No scan history for this value yet - it is recorded with every scan.'
}
#endregion

#region Fleet tab
$FleetCellXaml = $StatusPillTemplate

function Show-Fleet {
    param($Fleet)
    $script:Fleet = $Fleet
    $hosts = @($Fleet.Hosts | Sort-Object Computer)
    $ids = @($hosts | ForEach-Object { $_.Results } | ForEach-Object { $_.Id } | Select-Object -Unique)
    $dt = New-Object System.Data.DataTable
    [void]$dt.Columns.Add('_i', [int])
    foreach ($c in 'Host', 'Build', 'Most likely cause') { [void]$dt.Columns.Add($c) }
    [void]$dt.Columns.Add('Problems', [int]); [void]$dt.Columns.Add('Warnings', [int])
    foreach ($id in $ids) { [void]$dt.Columns.Add($id) }
    $i = 0
    foreach ($h in $hosts) {
        $dr = $dt.NewRow(); $dr['_i'] = $i
        $dr['Host'] = $h.Computer; $dr['Build'] = $h.Env.BuildString
        $dr['Problems'] = @($h.Results | Where-Object { $_.Status -eq 'Problem' }).Count
        $dr['Warnings'] = @($h.Results | Where-Object { $_.Status -eq 'Warning' }).Count
        $top = Get-TopCauses $h.Results 1
        $dr['Most likely cause'] = $(if ($top) { "$($top.Id) $($top.Name)" } else { '' })
        foreach ($r in $h.Results) { $dr[$r.Id] = $r.Status }
        [void]$dt.Rows.Add($dr); $i++
    }
    $script:GridSource['GridFleet'] = $hosts
    $g = $ui.GridFleet
    $g.Columns.Clear()
    foreach ($c in 'Host', 'Build', 'Problems', 'Warnings', 'Most likely cause') {
        $col = New-Object System.Windows.Controls.DataGridTextColumn
        $col.Header = $c.ToUpper(); $col.Binding = New-Object System.Windows.Data.Binding "[$c]"; $col.SortMemberPath = $c
        [void]$g.Columns.Add($col)
    }
    foreach ($id in $ids) {
        $col = New-Object System.Windows.Controls.DataGridTemplateColumn
        $col.Header = $id; $col.SortMemberPath = $id
        $col.CellTemplate = [Windows.Markup.XamlReader]::Parse($FleetCellXaml.Replace('%COL%', $id))
        [void]$g.Columns.Add($col)
    }
    $g.ItemsSource = $dt.DefaultView
    $failed = @($Fleet.Failed)
    $ui.TxtFleetInfo.Text = "$($hosts.Count) host(s) scanned$(if ($failed) { ", $($failed.Count) failed:`r`n" + (($failed | ForEach-Object { "$($_.Computer): $($_.Error)" }) -join "`r`n") })"
    $ui.BtnFleetExport.IsEnabled = $true
}
#endregion

#region Fix history tab
function Update-FixHistory {
    $script:FixHist = @(Get-FixHistory | Sort-Object TimeDt -Descending)
    $rows = foreach ($f in $script:FixHist) {
        [ordered]@{ 'Time' = $f.TimeDt; 'Type' = $f.Kind; 'Check' = $f.CheckId; 'Fix' = $f.Label
                    'Result' = $(if ($f.Success) { 'OK' } else { "Failed: $($f.Error)" }); 'Backups' = @($f.Backups).Count; 'Can undo' = $(if ($f.Kind -eq 'Fix' -and @($f.Backups).Count -gt 0 -and $f.Success) { 'Yes' } else { 'No' }); 'User' = $f.User; 'Computer' = $f.Computer }
    }
    Set-GridData $ui.GridFh @($rows) $script:FixHist
    $ui.TxtFhInfo.Text = "$($script:FixHist.Count) entr$(if ($script:FixHist.Count -eq 1) { 'y' } else { 'ies' })"
}
#endregion

#region Tools tab
$ui.TxtProbeImpact.Text = Format-Bullets @(
    'Adds a scheduled task that starts a small hidden PowerShell process at each user logon. It checks every 250 ms until the taskbar appears (max. 10 minutes) and then exits - negligible CPU.'
    'Writes one small JSON file per logon (user name, host, client name, timings) to C:\ProgramData\LogonBlackScreenAnalyzer\Probe and, if set, to the central share. This is personal data (who signed in when) - check it is OK under your data protection rules.'
    'Users can create their own records in the probe and report folders but cannot change other users files.'
    'No reboot. The Remove button deletes the task, shortcut and scripts again (collected data is kept).'
    'With AppLocker / Constrained Language Mode the probe script may be blocked - allow or sign C:\ProgramData\LogonBlackScreenAnalyzer\bin.'
)

function Update-ProbeStatus {
    try {
        $s = Get-LogonProbeStatus
        $ui.TxtProbeStatus.Text = if ($s.Installed) { "Installed on this host. Last run: $(if ($s.LastRun) { Format-Time $s.LastRun } else { 'not yet' }). $($s.Records) local record(s). Shortcut: $(if ($s.Shortcut) { 'yes' } else { 'no' })." } else { "Not installed on this host. $($s.Records) local record(s)." }
    } catch { $ui.TxtProbeStatus.Text = "Status unknown: $($_.Exception.Message)" }
}

function Update-SettingsFields {
    $cfg = Get-ToolConfig
    $ui.TxtSharePath.Text = $cfg.SharePath; $ui.TxtCfgWebhook.Text = $cfg.WebhookUrl; $ui.TxtCfgWs.Text = $cfg.WorkspaceId
    $ui.TxtCfgSub.Text = $cfg.SubscriptionId; $ui.TxtCfgRg.Text = $cfg.HostPoolResourceGroup; $ui.TxtCfgPool.Text = $cfg.HostPoolName
    if (-not $ui.TxtAvdWs.Text) { $ui.TxtAvdWs.Text = $cfg.WorkspaceId }
    $ui.TxtCfgPath.Text = "Saved next to the analyser in $SettingsPath. When the logon probe is installed on a host, it gets a copy of the share path and webhook."
    $ui.TxtKiPath.Text = $(if (Test-Path $KnownIssuesPath) { "Using $KnownIssuesPath" } else { "Built-in data is used. Click below to create an editable copy: $KnownIssuesPath" })
}
$ui.TxtGateCmd.Text = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$MainScriptPath`" -Gate -GateLevel Problem -JsonPath C:\Windows\Temp\image-gate.json"
#endregion

#region Events
$ui.Tabs.Add_SelectionChanged({
    param($s, $e)
    if ($e.OriginalSource -ne $ui.Tabs) { return }
    $tag = [string]$ui.Tabs.SelectedItem.Tag
    foreach ($k in $Pages.Keys) { $Pages[$k].Visibility = $(if ($k -eq $tag) { 'Visible' } else { 'Collapsed' }) }
    switch ($tag) {
        'FixHistory' { Update-FixHistory }
        'Tools'      { Update-ProbeStatus; Update-SettingsFields }
        'Azure'      { Update-SettingsFields; Update-ModuleStatus }
    }
})

# Findings
$ui.Grid.Add_SelectionChanged({
    $row = $ui.Grid.SelectedItem
    if (-not $row) { return }
    $r = $script:ResultById[[string]$row['Id']]
    if ($r) { Show-Detail $r }
})
foreach ($t in $Tiles) {
    $t.Add_Click({
        $s = [string]$this.Tag
        if ($script:StatusFilter -eq $s) { $script:StatusFilter = $null } else { $script:StatusFilter = $s }
        Update-Tiles; Update-Filter
    })
}
$ui.TxtSearch.Add_TextChanged({ $ui.SearchHint.Visibility = $(if ($ui.TxtSearch.Text) { 'Collapsed' } else { 'Visible' }); Update-Filter })
$ui.CmbCategory.Add_SelectionChanged({ Update-Filter })
$ui.ChkNA.Add_Click({ Update-Filter })
$ui.BtnApply.Add_Click({ if ($script:Current -and $script:Current.AutoFix -and -not $script:FixBusy) { Start-Fix $script:Current } })
$ui.BtnCopy.Add_Click({ if ($ui.DCmd.Text) { [System.Windows.Clipboard]::SetText($ui.DCmd.Text); $ui.BtnCopy.Content = 'Copied' } })
$ui.BtnScan.Add_Click({ Start-Scan })
$ui.BtnExport.Add_Click({
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'HTML report (*.html)|*.html|JSON results (*.json)|*.json'
    $dlg.FileName = "LogonBlackScreen-$env:COMPUTERNAME-$(Get-Date -Format yyyyMMdd-HHmm)"
    if (-not $dlg.ShowDialog($win)) { return }
    try {
        if ($dlg.FileName -like '*.json') { [System.IO.File]::WriteAllText($dlg.FileName, (ConvertTo-ResultJson -E $script:HostEnv -Results $script:AllResults)) }
        else { Export-HtmlReport -E $script:HostEnv -Results $script:AllResults -Path $dlg.FileName }
        Start-Process $dlg.FileName
    } catch { Show-Error 'Export failed' $_.Exception.Message }
})
$ui.BtnElevate.Add_Click({
    try {
        Start-Process (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Verb RunAs `
            -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$MainScriptPath`"", '-LookbackDays', $LookbackDays)
        $win.Close()
    } catch { }
})

# Timeline
$ui.BtnTlLoad.Add_Click({
    $ui.BtnTlLoad.IsEnabled = $false
    Start-BgJob -Name 'Reading logon events' -Script 'Get-LogonTimelines -Days $Days -ProbePaths $ProbePaths' -Vars @{ Days = [math]::Max($LookbackDays, 7); ProbePaths = @(Get-ProbePaths 'Probe') } -OnDone {
        param($out, $err)
        $ui.BtnTlLoad.IsEnabled = $true
        if ($err) { Show-Error 'Could not read logons' $err; return }
        $script:Timelines = @($out)
        $rows = foreach ($l in $script:Timelines) { [ordered]@{ 'Signed in' = $l.Time; 'User' = $l.User; 'To desktop (s)' = $l.TotalSec; 'Biggest phase' = $l.Biggest; 'Desktop measured by' = $l.DesktopSource } }
        Set-GridData $ui.GridTl @($rows) $script:Timelines
        $ui.TxtTlInfo.Text = "$($script:Timelines.Count) logon(s) found"
        if ($script:Timelines) { $ui.GridTl.SelectedIndex = 0 } else { $ui.TlTitle.Text = 'No logons found'; $ui.TlSub.Text = 'The User Profile Service log has no logons in the window, and no probe data was found.' }
        Clear-Busy "Loaded $($script:Timelines.Count) logon(s)"
    }
})
$ui.GridTl.Add_SelectionChanged({ Show-Timeline (Get-GridSelection $ui.GridTl) })
$ui.TlCanvas.Add_SizeChanged({ $l = Get-GridSelection $ui.GridTl; if ($l) { Draw-Timeline $l } })

# Trends
$ui.BtnTrLoad.Add_Click({
    $ui.BtnTrLoad.IsEnabled = $false
    $code = '[pscustomobject]@{ Probe = @(Get-ProbeRecords -Paths $ProbePaths -Days 90); History = @(Get-ScanHistory); Fixes = @(Get-FixHistory) }'
    Start-BgJob -Name 'Loading logon data' -Script $code -Vars @{ ProbePaths = @(Get-ProbePaths 'Probe') } -OnDone {
        param($out, $err)
        $ui.BtnTrLoad.IsEnabled = $true
        if ($err) { Show-Error 'Could not load logon data' $err; return }
        $script:TrendData = $out | Select-Object -Last 1
        Update-Trends
        Clear-Busy 'Logon data loaded'
    }
})
$ui.ChkTrAll.Add_Click({ Update-Trends })
$ui.CmbMetric.Add_SelectionChanged({ Update-MetricChart })
$ui.TrChart.Add_SizeChanged({ if ($script:TrendData) { Update-Trends } })

# User reports
$ui.BtnRepLoad.Add_Click({
    Start-BgJob -Name 'Loading user reports' -Script 'Get-UserReports -Days 90' -OnDone {
        param($out, $err)
        if ($err) { Show-Error 'Could not load user reports' $err; return }
        $script:Reports = @($out)
        $rows = foreach ($r in $script:Reports) { [ordered]@{ 'Reported' = $r.TimeDt; 'User' = $r.User; 'Host' = $r.Computer; 'To desktop (s)' = $r.TimeToDesktopSec; 'Black screen' = [bool]$r.BlackScreen; 'Note' = $r.Note } }
        Set-GridData $ui.GridRep @($rows) $script:Reports
        $ui.TxtRepInfo.Text = "$($script:Reports.Count) report(s) in the last 90 days"
        Clear-Busy $null
    }
})
$ui.GridRep.Add_SelectionChanged({
    $r = Get-GridSelection $ui.GridRep
    if ($r) { $ui.TxtRepDetail.Text = ($r | Select-Object * -ExcludeProperty File, *Dt | ConvertTo-Json -Depth 6) }
})

# Compare
$ui.BtnSnapSave.Add_Click({
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'Baseline (*.json)|*.json'; $dlg.FileName = "Baseline-$env:COMPUTERNAME-$(Get-Date -Format yyyyMMdd).json"
    if (-not $dlg.ShowDialog($win)) { return }
    Start-BgJob -Name 'Saving baseline' -Script '$s = Get-HostSnapshot -Results $Results; [System.IO.File]::WriteAllText($Path, ($s | ConvertTo-Json -Depth 5)); $Path' -Vars @{ Results = @($script:AllResults); Path = $dlg.FileName } -OnDone {
        param($out, $err)
        if ($err) { Show-Error 'Could not save the baseline' $err; return }
        [void](Show-Dialog -Title 'Baseline saved' -Message "The baseline of $env:COMPUTERNAME was saved to:`r`n$($out | Select-Object -Last 1)`r`n`r`nCopy it to a slow host and use 'Compare with a baseline' there." -Kind Success)
    }
})
$ui.BtnSnapCompare.Add_Click({
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Filter = 'Baseline (*.json)|*.json'
    if (-not $dlg.ShowDialog($win)) { return }
    Start-BgJob -Name 'Comparing with baseline' -Script '$b = [System.IO.File]::ReadAllText($Path) | ConvertFrom-Json; $c = Get-HostSnapshot -Results $Results; [pscustomobject]@{ Baseline = $b.Computer; BaselineTime = $b.Time; Diff = @(Compare-HostSnapshot -Baseline $b -Current $c) }' -Vars @{ Results = @($script:AllResults); Path = $dlg.FileName } -OnDone {
        param($out, $err)
        if ($err) { Show-Error 'Could not compare' $err; return }
        $res = $out | Select-Object -Last 1
        $script:Diff = @($res.Diff)
        $ui.CmbDiffCat.Items.Clear(); [void]$ui.CmbDiffCat.Items.Add('All categories')
        foreach ($c in ($script:Diff | ForEach-Object { $_.Category } | Select-Object -Unique)) { [void]$ui.CmbDiffCat.Items.Add($c) }
        $ui.CmbDiffCat.SelectedIndex = 0
        $ui.TxtDiffInfo.Text = "$($script:Diff.Count) difference(s) between $env:COMPUTERNAME and baseline $($res.Baseline) ($((ConvertFrom-IsoDate $res.BaselineTime) | ForEach-Object { Format-Time $_ }))"
        Clear-Busy 'Compare finished'
    }
})
$ui.CmbDiffCat.Add_SelectionChanged({
    $cat = [string]$ui.CmbDiffCat.SelectedItem
    $items = @($script:Diff | Where-Object { -not $cat -or $cat -eq 'All categories' -or $_.Category -eq $cat })
    $rows = foreach ($d in $items) { [ordered]@{ 'Category' = $d.Category; 'Item' = $d.Item; 'Change' = $d.Change; 'Baseline' = $d.Baseline; 'This host' = $d.ThisHost } }
    Set-GridData $ui.GridDiff @($rows) $items
})

# Fleet
$ui.BtnFleetPool.Add_Click({
    $cfg = Get-ToolConfig
    if (-not $cfg.HostPoolResourceGroup -or -not $cfg.HostPoolName) { [void](Show-Dialog -Title 'Host pool not configured' -Message 'Enter the host pool resource group and name in Tools > Settings first.' -Kind Warning); return }
    $ui.BtnFleetPool.IsEnabled = $false
    $ui.TxtFleetInfo.Text = 'Loading session hosts in a separate PowerShell window - sign in there if Azure asks you to.'
    Start-BgJob -Name 'Loading session hosts from the AVD host pool' -Script 'Get-AvdSessionHostNames -ResourceGroup $Rg -HostPool $Pool -SubscriptionId $Sub' `
        -Vars @{ Rg = $cfg.HostPoolResourceGroup; Pool = $cfg.HostPoolName; Sub = $cfg.SubscriptionId } -State $cfg.HostPoolName -OnDone {
        param($out, $err, $pool)
        $ui.BtnFleetPool.IsEnabled = $true
        if ($err) { $ui.TxtFleetInfo.Text = ''; Show-Error 'Could not load the host pool' $err; return }
        $names = @($out | ForEach-Object { "$_" } | Where-Object { $_ })
        $ui.TxtFleetHosts.Text = $names -join "`r`n"
        $ui.TxtFleetInfo.Text = "$($names.Count) session host(s) loaded from $pool."
        Clear-Busy "$($names.Count) session host(s) loaded"
    }
})
$ui.BtnFleetScan.Add_Click({
    $hosts = @($ui.TxtFleetHosts.Text -split "[`r`n,;]+" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if (-not $hosts) { [void](Show-Dialog -Title 'No hosts' -Message 'Enter at least one host name, or load them from the AVD host pool.' -Kind Warning); return }
    $cred = $null
    if ($ui.ChkFleetCred.IsChecked) { $cred = Get-Credential -Message 'Account with administrator rights on the session hosts'; if (-not $cred) { return } }
    $ki = ''; if ($KnownIssuesPath -and (Test-Path $KnownIssuesPath)) { $ki = [System.IO.File]::ReadAllText($KnownIssuesPath) }
    $ui.BtnFleetScan.IsEnabled = $false
    Start-BgJob -Name "Scanning $($hosts.Count) host(s)" -Script 'Invoke-FleetScan -ComputerName $Hosts -Credential $Cred -Days $Days -CoreText $EngineText -KnownIssuesText $Ki' `
        -Vars @{ Hosts = $hosts; Cred = $cred; Days = $LookbackDays; EngineText = $script:EngineText; Ki = $ki } -OnDone {
        param($out, $err)
        $ui.BtnFleetScan.IsEnabled = $true
        if ($err) { Show-Error 'Fleet scan failed' $err; return }
        Show-Fleet ($out | Select-Object -Last 1)
        Clear-Busy 'Fleet scan finished'
    }
})
$ui.GridFleet.Add_SelectionChanged({
    $h = Get-GridSelection $ui.GridFleet
    if (-not $h) { return }
    $ui.TxtFleetHost.Text = "$($h.Computer) - $($h.Env.Family) build $($h.Env.BuildString) - $($h.Env.Roles)"
    $items = @($h.Results | Where-Object { $_.Status -in 'Problem', 'Warning', 'Error' } | Sort-Object SortKey)
    $rows = foreach ($r in $items) { [ordered]@{ 'Status' = $r.Status; 'Check' = "$($r.Id) $($r.Name)"; 'Result' = $r.Summary } }
    Set-GridData $ui.GridFleetHost @($rows) $items
})
$ui.BtnFleetExport.Add_Click({
    if (-not $script:Fleet) { return }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'HTML report (*.html)|*.html'; $dlg.FileName = "LogonBlackScreen-Fleet-$(Get-Date -Format yyyyMMdd-HHmm).html"
    if (-not $dlg.ShowDialog($win)) { return }
    try { Export-FleetReport -Fleet $script:Fleet -Path $dlg.FileName; Start-Process $dlg.FileName } catch { Show-Error 'Export failed' $_.Exception.Message }
})

# Azure - PowerShell modules
function Update-ModuleStatus {
    Set-Busy 'Checking PowerShell modules...'; Update-UiNow
    $script:ModuleStatus = @(Get-RequiredModuleStatus)
    $ui.TxtModules.Text = ($script:ModuleStatus | ForEach-Object { "{0,-32} {1,-18} {2}" -f $_.Name, $(if ($_.Installed) { "installed $($_.Version)" } else { 'MISSING' }), $_.Purpose }) -join "`r`n"
    $missing = @($script:ModuleStatus | Where-Object { -not $_.Installed })
    $ui.BtnModInstall.IsEnabled = $missing.Count -gt 0
    $ui.BtnModInstall.Content = $(if ($missing) { "Install $($missing.Count) missing module(s)" } else { 'All modules installed' })
    Clear-Busy ''
}
$ui.BtnModCheck.Add_Click({ Update-ModuleStatus })
$ui.BtnModInstall.Add_Click({
    $missing = @($script:ModuleStatus | Where-Object { -not $_.Installed })
    if (-not $missing) { return }
    $admin = [bool]($script:HostEnv -and $script:HostEnv.IsAdmin)
    $where = if ($admin) { 'for all users of this computer (C:\Program Files\WindowsPowerShell\Modules)' } else { 'for your account only (Documents\WindowsPowerShell\Modules)' }
    $msg = Join-Lines @(
        "These Microsoft modules will be downloaded from the PowerShell Gallery (www.powershellgallery.com) and installed $($where):"
        ($missing | ForEach-Object { "  - $($_.Name): $($_.Purpose)" })
        ''
        'The NuGet package provider is installed first if it is missing.'
    )
    $impact = Format-Bullets @(
        'Needs internet access to www.powershellgallery.com. Downloads a few tens of MB and can take a few minutes.'
        'Only the missing modules are installed - modules and versions that are already installed are not changed.'
        $(if ($admin) { 'Installed for all users of this computer.' } else { 'Installed for your account only. With OneDrive Known Folder Move the Documents folder - and so the modules - is synced to OneDrive. Restart the tool as administrator to install for all users instead.' })
        'No reboot. The Azure features can be used right after the installation.'
        'If your organisation blocks the PowerShell Gallery, install the modules from your internal repository instead.'
    )
    if (-not (Show-Dialog -Title 'Install PowerShell modules?' -Message $msg -Impact $impact -OkText 'Install' -CancelText 'Cancel' -Kind Confirm)) { return }
    $ui.BtnModInstall.IsEnabled = $false; $ui.BtnModInstall.Content = 'Installing...'
    Start-BgJob -Name 'Installing PowerShell modules (this can take a few minutes)' -Script 'Install-RequiredModules -AllUsers:$All' -Vars @{ All = $admin } -OnDone {
        param($out, $err)
        Update-ModuleStatus
        if ($err) { Show-Error 'Module installation failed' $err; return }
        $text = (@($out) | ForEach-Object { "$_" }) -join "`r`n"
        if ($text -match 'FAILED') { [void](Show-Dialog -Title 'Some modules could not be installed' -Message $text -OkText 'Close' -Kind Error) }
        else { [void](Show-Dialog -Title 'Modules installed' -Message $text -Kind Success) }
    }
})

# Azure
$ui.BtnAzLogin.Add_Click({
    $ui.BtnAzLogin.IsEnabled = $false
    $ui.TxtAvdInfo.Text = 'Sign in to Azure in the PowerShell window that opened.'
    Start-BgJob -Name 'Waiting for the Azure sign-in' -Script 'Connect-ToolAzure -SubscriptionId $Sub' -Vars @{ Sub = (Get-ToolConfig).SubscriptionId } -OnDone {
        param($out, $err)
        $ui.BtnAzLogin.IsEnabled = $true
        if ($err) { $ui.TxtAvdInfo.Text = ''; Show-Error 'Azure sign-in failed' $err; return }
        $ui.TxtAvdInfo.Text = "Signed in: $($out | Select-Object -Last 1)"
        Clear-Busy 'Signed in to Azure'
    }
})
$ui.BtnAvdQuery.Add_Click({
    $ws = $ui.TxtAvdWs.Text.Trim(); $user = $ui.TxtAvdUser.Text.Trim()
    $days = 7; [void][int]::TryParse($ui.TxtAvdDays.Text, [ref]$days)
    if (-not $ws -or -not $user) { [void](Show-Dialog -Title 'Missing input' -Message 'Enter the Log Analytics workspace ID and the user principal name.' -Kind Warning); return }
    $ui.BtnAvdQuery.IsEnabled = $false
    $ui.TxtAvdInfo.Text = 'Querying AVD Insights in a separate PowerShell window - sign in there if Azure asks you to.'
    Start-BgJob -Name 'Querying AVD Insights' -Script 'Invoke-AvdInsightsQuery -WorkspaceId $Ws -User $User -Days $Days -SubscriptionId $Sub' `
        -Vars @{ Ws = $ws; User = $user; Days = $days; Sub = (Get-ToolConfig).SubscriptionId } -State @{ User = $user; Days = $days } -OnDone {
        param($out, $err, $st)
        $ui.BtnAvdQuery.IsEnabled = $true
        if ($err) { $ui.TxtAvdInfo.Text = ''; Show-Error 'AVD Insights query failed' $err; return }
        $res = $out | Select-Object -Last 1
        $script:AvdConns = @($res.Connections | Where-Object { $_ })
        $script:AvdCheckpoints = @($res.Checkpoints | Where-Object { $_ })
        $rows = foreach ($c in $script:AvdConns) { [ordered]@{ 'Started' = (ConvertFrom-IsoDate $c.Started); 'Session host' = $c.SessionHost; 'Client' = $c.Client; 'Seconds to connect' = (Get-InvariantNumber $c.SecondsToConnect); 'Correlation ID' = $c.CorrelationId } }
        Set-GridData $ui.GridAvdConn @($rows) $script:AvdConns
        Set-GridData $ui.GridAvdCp @() @()
        $ui.TxtAvdInfo.Text = "$($script:AvdConns.Count) connection(s) for $($st.User) in the last $($st.Days) days. Select one to see its checkpoints."
        Clear-Busy 'AVD Insights query finished'
    }
})
$ui.GridAvdConn.Add_SelectionChanged({
    $c = Get-GridSelection $ui.GridAvdConn
    if (-not $c) { return }
    $cp = @($script:AvdCheckpoints | Where-Object { $_.CorrelationId -eq $c.CorrelationId } | Sort-Object { ConvertFrom-IsoDate $_.TimeGenerated })
    $t0 = $null; if ($cp) { $t0 = ConvertFrom-IsoDate $cp[0].TimeGenerated }
    $rows = foreach ($p in $cp) { $t = ConvertFrom-IsoDate $p.TimeGenerated; [ordered]@{ '+ s' = $(if ($t -and $t0) { [math]::Round(($t - $t0).TotalSeconds, 1) }); 'Time' = $t; 'Type' = $p.Kind; 'Name' = $p.Name; 'Source' = $p.Source; 'Details' = $p.Details } }
    Set-GridData $ui.GridAvdCp @($rows) $cp
})
function Update-Rh {
    $items = @($script:RhIssues)
    if ($ui.ChkRhRelevant.IsChecked) { $items = @($items | Where-Object { $_.Relevant }) }
    $items = @($items | Sort-Object Started -Descending)
    $rows = foreach ($i in $items) { [ordered]@{ 'Status' = $i.Status; 'Title' = $i.Title; 'Product' = $i.Product; 'Started' = $i.Started; 'Caused by' = $i.OriginatingKB; 'Installed here' = $i.InstalledHere; 'Fixed by' = $i.ResolvingKB; 'Fix installed' = $i.FixInstalled } }
    Set-GridData $ui.GridRh @($rows) $items
    $ui.TxtRhInfo.Text = "$($items.Count) issue(s) shown of $(@($script:RhIssues).Count)"
}
$ui.BtnRh.Add_Click({
    if (-not $script:HostEnv) { [void](Show-Dialog -Title 'Scan first' -Message 'Wait for the scan to finish - the host version is needed.' -Kind Warning); return }
    $ui.BtnRh.IsEnabled = $false
    $ui.TxtRhInfo.Text = 'Loading in a separate PowerShell window - sign in to Microsoft Graph there.'
    Start-BgJob -Name 'Loading Windows release health' -Script 'Get-ReleaseHealthIssues -E $E' -Vars @{ E = $script:HostEnv } -OnDone {
        param($out, $err)
        $ui.BtnRh.IsEnabled = $true
        if ($err) { $ui.TxtRhInfo.Text = ''; Show-Error 'Could not load release health' $err; return }
        $script:RhIssues = @($out | Where-Object { $_ })
        Update-Rh
        Clear-Busy 'Release health loaded'
    }
})
$ui.ChkRhRelevant.Add_Click({ if ($script:RhIssues) { Update-Rh } })
$ui.GridRh.Add_SelectionChanged({ $i = Get-GridSelection $ui.GridRh; if ($i) { $ui.TxtRhDetail.Text = Join-Lines @($i.Description, '', $i.Url) } })

# Fix history
$ui.BtnFhRefresh.Add_Click({ Update-FixHistory })
$ui.BtnFhOpen.Add_Click({ $d = Join-Path $ToolBase 'Backups'; New-Item -ItemType Directory -Force $d | Out-Null; Start-Process explorer.exe $d })
$ui.GridFh.Add_SelectionChanged({
    $f = Get-GridSelection $ui.GridFh
    if ($f) { $ui.TxtFhDetail.Text = Join-Lines @("Backups:", (@($f.Backups) | ForEach-Object { "  $_" }), '', 'Output:', $f.Output, $(if ($f.Error) { "`r`nError: $($f.Error)" })) }
})
$ui.BtnFhUndo.Add_Click({
    $f = Get-GridSelection $ui.GridFh
    if (-not $f) { [void](Show-Dialog -Title 'Select a fix' -Message 'Select the fix you want to undo in the list.' -Kind Warning); return }
    $backups = @($f.Backups | Where-Object { $_ })
    if ($f.Kind -ne 'Fix' -or -not $backups) { [void](Show-Dialog -Title 'Cannot be undone here' -Message "This entry has no registry backup, so it cannot be undone automatically.`r`n`r`nFixes that uninstalled software, removed apps or profiles, reset the search index or started a service have to be reverted manually (for example by reinstalling the software)." -Kind Warning); return }
    if (-not ($script:HostEnv -and $script:HostEnv.IsAdmin)) { [void](Show-Dialog -Title 'Administrator needed' -Message 'Restart the tool as administrator to undo machine-level fixes.' -Kind Warning); return }
    $msg = Join-Lines @("Undo: $($f.CheckId) - $($f.Label) (applied $(Format-Time $f.TimeDt))", '', 'These registry backups will be restored:', ($backups | ForEach-Object { "  $_" }))
    $impact = Format-Bullets @(
        'Each registry key is put back exactly as it was before the fix. Changes made to the same key by others since then (for example by Group Policy) are reverted too - Group Policy re-applies its own values at the next refresh.'
        'Keys that did not exist before the fix are deleted again.'
        'The current state is backed up first, so the undo itself can be reverted with the backup files.'
        'If the original fix needed a reboot (firewall, WDDM), reboot again after the undo.'
    )
    if (-not (Show-Dialog -Title 'Undo this fix?' -Message $msg -Impact $impact -OkText 'Undo fix' -CancelText 'Cancel' -Kind Confirm)) { return }
    $runner = @'
$out = New-Object System.Collections.Generic.List[string]; $ok = $true; $errText = ''
$list = @($Backups); [array]::Reverse($list)
try { foreach ($b in $list) { $out.Add((Restore-RegBackup -File $b)) } } catch { $ok = $false; $errText = $_.Exception.Message }
Write-FixHistory -CheckId $CheckId -Label "Undo: $Label" -Success $ok -ErrorText $errText -Output ($out -join "`r`n") -Kind 'Undo'
$new = $null; try { $E = Get-HostEnvironment; $new = @(Invoke-AllChecks -E $E -OnlyIds $CheckId) | Select-Object -First 1 } catch { }
[pscustomobject]@{ Ok = $ok; Error = $errText; Output = ($out -join "`r`n"); New = $new }
'@
    Start-BgJob -Name 'Undoing fix' -Script $runner -Vars @{ Backups = $backups; CheckId = [string]$f.CheckId; Label = [string]$f.Label } -OnDone {
        param($out, $err)
        $res = $out | Select-Object -Last 1
        if ($res -and $res.New) { Update-ResultRow $res.New }
        Update-FixHistory
        if ($err -or -not $res) { Show-Error 'Undo could not run' "$err"; return }
        if (-not $res.Ok) { [void](Show-Dialog -Title 'Undo failed' -Message $res.Error -Code $res.Output -CodeHeader 'Output' -OkText 'Close' -Kind Error); return }
        [void](Show-Dialog -Title 'Fix undone' -Message (Join-Lines @($res.Output, '', $(if ($res.New) { "Re-checked: $($res.New.Status) - $($res.New.Summary)" }))) -OkText 'Close' -Kind Success)
    }
})

# Tools
$ui.BtnProbeInstall.Add_Click({
    if (-not ($script:HostEnv -and $script:HostEnv.IsAdmin)) { [void](Show-Dialog -Title 'Administrator needed' -Message 'Restart the tool as administrator to install the probe.' -Kind Warning); return }
    $share = $ui.TxtSharePath.Text.Trim()
    $msg = Join-Lines @('This installs on this host:', '- Scheduled task \LogonBlackScreenAnalyzer\LogonProbe (runs at every user logon)', "- Scripts in $ToolBase\bin", $(if ($ui.ChkProbeShortcut.IsChecked) { "- 'Report slow sign-in' shortcut on the public desktop" }), $(if ($share) { "- Data is also written to $share (users need permission to create files there)" }), '', 'For many hosts, run the analyser with -InstallProbe in the golden image build instead.')
    if (-not (Show-Dialog -Title 'Install the logon probe?' -Message $msg -Impact $ui.TxtProbeImpact.Text -OkText 'Install' -CancelText 'Cancel' -Kind Confirm)) { return }
    Start-BgJob -Name 'Installing logon probe' -Script 'Install-LogonProbe -ProbeScriptText $ProbeText -ReportScriptText $ReportText -SharePath $Share -DesktopShortcut:$Sc' -Vars @{ ProbeText = $script:ProbeText; ReportText = $script:ReportText; Share = $share; Sc = [bool]$ui.ChkProbeShortcut.IsChecked } -OnDone {
        param($out, $err)
        Update-ProbeStatus
        if ($err) { Show-Error 'Probe installation failed' $err; return }
        [void](Show-Dialog -Title 'Logon probe installed' -Message (($out | ForEach-Object { "$_" }) -join "`r`n") -Kind Success)
    }
})
$ui.BtnProbeRemove.Add_Click({
    if (-not ($script:HostEnv -and $script:HostEnv.IsAdmin)) { [void](Show-Dialog -Title 'Administrator needed' -Message 'Restart the tool as administrator to remove the probe.' -Kind Warning); return }
    if (-not (Show-Dialog -Title 'Remove the logon probe?' -Message 'Removes the scheduled task, the desktop shortcut and the probe scripts from this host. Collected data is kept.' -OkText 'Remove' -CancelText 'Cancel' -Kind Confirm)) { return }
    Start-BgJob -Name 'Removing logon probe' -Script 'Uninstall-LogonProbe' -OnDone { param($out, $err) Update-ProbeStatus; if ($err) { Show-Error 'Removal failed' $err } else { [void](Show-Dialog -Title 'Logon probe removed' -Message (($out | ForEach-Object { "$_" }) -join "`r`n") -Kind Success) } }
})
$ui.BtnBundle.Add_Click({
    if (-not $script:HostEnv) { [void](Show-Dialog -Title 'Scan first' -Message 'Wait for the scan to finish before creating a bundle.' -Kind Warning); return }
    $sec = [bool]$ui.ChkBundleSec.IsChecked -and $script:HostEnv.IsAdmin
    $ui.BtnBundle.IsEnabled = $false
    Start-BgJob -Name 'Creating support bundle (gpresult and event logs can take a few minutes)' -Script 'New-SupportBundle -E $E -Results $Results -IncludeSecurity:$Sec -TracePath $Trace' -Vars @{ E = $script:HostEnv; Results = @($script:AllResults); Sec = $sec; Trace = $script:LastTrace } -OnDone {
        param($out, $err)
        $ui.BtnBundle.IsEnabled = $true
        if ($err) { Show-Error 'Support bundle failed' $err; return }
        $zip = [string]($out | Select-Object -Last 1)
        $ui.TxtBundle.Text = "Created: $zip"
        Clear-Busy 'Support bundle created'
        Start-Process explorer.exe "/select,`"$zip`""
    }
})
$ui.BtnWprStart.Add_Click({
    if (-not ($script:HostEnv -and $script:HostEnv.IsAdmin)) { [void](Show-Dialog -Title 'Administrator needed' -Message 'Restart the tool as administrator to record a trace.' -Kind Warning); return }
    try {
        [void](Start-LogonTrace)
        $script:Tracing = $true
        $ui.TxtWpr.Text = "Recording since $(Get-Date -Format 'HH:mm:ss'). Let a user sign in, wait until the desktop appears, then click 'Stop and save'."
        $ui.BtnWprStart.IsEnabled = $false; $ui.BtnWprStop.IsEnabled = $true
    } catch { Show-Error 'Could not start the trace' $_.Exception.Message }
})
$ui.BtnWprStop.Add_Click({
    $ui.BtnWprStop.IsEnabled = $false
    Start-BgJob -Name 'Saving the logon trace (can take a minute)' -Script 'Stop-LogonTrace' -OnDone {
        param($out, $err)
        $script:Tracing = $false; $ui.BtnWprStart.IsEnabled = $true
        if ($err) { $ui.BtnWprStop.IsEnabled = $true; Show-Error 'Could not save the trace' $err; return }
        $script:LastTrace = [string]($out | Select-Object -Last 1)
        $ui.TxtWpr.Text = "Saved: $script:LastTrace (added to the next support bundle; open it in Windows Performance Analyzer)."
        Clear-Busy 'Trace saved'
    }
})
$ui.BtnIntune.Add_Click({
    $fb = New-Object System.Windows.Forms.FolderBrowserDialog
    $fb.Description = 'Choose a folder for the Intune remediation scripts'
    if ($fb.ShowDialog() -ne 'OK') { return }
    try {
        $dir = Join-Path $fb.SelectedPath "LogonBlackScreen-Intune-$(Get-Date -Format yyyyMMdd)"
        $n = Export-IntuneRemediations -OutDir $dir -EngineText $script:EngineText
        $ui.TxtIntune.Text = "$n remediation pair(s) written to $dir"
        Start-Process explorer.exe $dir
    } catch { Show-Error 'Export failed' $_.Exception.Message }
})
$ui.BtnGate.Add_Click({
    $ui.BtnGate.IsEnabled = $false
    Start-BgJob -Name 'Running the image gate' -Script '$E = Get-HostEnvironment; Invoke-ImageGate -E $E -Level Problem' -OnDone {
        param($out, $err)
        $ui.BtnGate.IsEnabled = $true
        if ($err) { Show-Error 'Image gate failed to run' $err; return }
        $g = $out | Select-Object -Last 1
        $lines = @($g.Results | Sort-Object SortKey | ForEach-Object { "{0,-8} {1,-7} {2}" -f $_.Status, $_.Id, $_.Summary })
        if ($g.Passed) { [void](Show-Dialog -Title 'Image gate passed' -Message "No problems in the image-related checks." -Code ($lines -join "`r`n") -CodeHeader 'Checked' -Kind Success) }
        else { [void](Show-Dialog -Title "Image gate failed - $(@($g.Failed).Count) problem(s)" -Message (($g.Failed | ForEach-Object { "$($_.Id) $($_.Name): $($_.Summary)" }) -join "`r`n`r`n") -Code ($lines -join "`r`n") -CodeHeader 'All image checks' -Kind Error -OkText 'Close') }
    }
})
$ui.BtnGateCopy.Add_Click({ [System.Windows.Clipboard]::SetText($ui.TxtGateCmd.Text); $ui.BtnGateCopy.Content = 'Copied' })
$ui.BtnCfgSave.Add_Click({
    try {
        $cfg = Get-ToolConfig
        $cfg.SharePath = $ui.TxtSharePath.Text.Trim(); $cfg.WebhookUrl = $ui.TxtCfgWebhook.Text.Trim(); $cfg.WorkspaceId = $ui.TxtCfgWs.Text.Trim()
        $cfg.SubscriptionId = $ui.TxtCfgSub.Text.Trim(); $cfg.HostPoolResourceGroup = $ui.TxtCfgRg.Text.Trim(); $cfg.HostPoolName = $ui.TxtCfgPool.Text.Trim()
        $note = Save-ToolConfig $cfg
        [void](Show-Dialog -Title 'Settings saved' -Message (Join-Lines @("Saved to $SettingsPath", $(if ($note) { ''; $note }))) -Kind Success)
    } catch { Show-Error 'Could not save the settings' "$($_.Exception.Message)`r`n`r`nCheck that the folder of the analyser is writable." }
})
$ui.BtnKiOpen.Add_Click({
    if (-not (Test-Path $KnownIssuesPath)) {
        # Create an editable copy of the built-in known-issue data next to the analyser
        try {
            $ki = [ordered]@{ '_comment' = 'Known Windows update issues used by the UPD-* checks. Edit when Microsoft publishes new information. FirstAffectedUBR / FixedUBR are keyed by build, e.g. { "26100": 6899 }. Delete this file to go back to the built-in data.' }
            foreach ($k in ($KnownIssues.Keys | Sort-Object)) { $ki[$k] = $KnownIssues[$k] }
            [System.IO.File]::WriteAllText($KnownIssuesPath, ($ki | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding $false))
        } catch { Show-Error 'Could not create KnownIssues.json' $_.Exception.Message; return }
        Update-SettingsFields
    }
    Start-Process notepad.exe "`"$KnownIssuesPath`""
})

$win.Add_ContentRendered({ Start-Scan })
$win.Add_Closing({
    param($sender, $e)
    if ($script:FixBusy) {
        $e.Cancel = $true
        [void](Show-Dialog -Title 'A fix is still running' -Message 'Please wait until the fix has finished before closing the tool.' -Kind Warning)
        return
    }
    if ($script:Tracing) {
        if (-not (Show-Dialog -Title 'Trace is still recording' -Message "A WPR trace is still recording. Close anyway? Stop it later with:  wpr.exe -cancel" -OkText 'Close anyway' -CancelText 'Go back' -Kind Warning)) { $e.Cancel = $true; return }
    }
    $script:ScanTimer.Stop(); $script:JobTimer.Stop()
    if ($script:ScanPs -and $script:Sync -and -not $script:Sync.Done) { try { $script:ScanPs.Stop() } catch { } }
})
#endregion
}
#endregion GuiBlock

# ======================================================================================================
# Main
# ======================================================================================================
$ToolRoot = $PSScriptRoot
$MainScriptPath = $PSCommandPath
if (-not $KnownIssuesPath) { $KnownIssuesPath = Join-Path $ToolRoot 'KnownIssues.json' }
# Settings are saved next to this script
$SettingsPath = [System.IO.Path]::ChangeExtension($PSCommandPath, '.settings.json')
$script:EngineText = $EngineBlock.ToString()
$script:CoreAll = $script:EngineText + "`n" + $ExtrasBlock.ToString()
$script:ProbeText = $ProbeBlock.ToString()
$script:ReportText = $ReportBlock.ToString()
. $EngineBlock
. $ExtrasBlock

#region Command-line modes
function Write-Results {
    param($E, $Results)
    Write-Host "`n$($E.ComputerName) - $($E.Family) build $($E.BuildString) - $($E.Roles)" -ForegroundColor Cyan
    if (-not $E.IsAdmin) { Write-Warning 'Not elevated - some checks are limited.' }
    $top = @(Get-TopCauses $Results)
    if ($top) {
        Write-Host "`nMost likely causes:" -ForegroundColor Yellow
        $k = 0; foreach ($t in $top) { $k++; Write-Host ("  {0}. [{1}] {2} - {3}" -f $k, $t.Status, $t.Name, $t.Summary) }
    }
    $Results | Where-Object Status -ne 'N/A' | Sort-Object SortKey | Format-Table Status, Id, Name, Summary -AutoSize -Wrap | Out-Host
    foreach ($r in ($Results | Where-Object { $_.Status -in 'Problem', 'Warning' } | Sort-Object SortKey)) {
        Write-Host ("`n[{0}] {1} - {2}" -f $r.Status, $r.Id, $r.Name) -ForegroundColor $(if ($r.Status -eq 'Problem') { 'Red' } else { 'Yellow' })
        Write-Host $r.Summary
        if ($r.Fix)     { Write-Host 'How to fix:' -ForegroundColor Cyan; Write-Host $r.Fix }
        if ($r.Impact)  { Write-Host 'Impact on users and system:' -ForegroundColor Cyan; Write-Host $r.Impact }
        if ($r.AutoFix) { Write-Host "One-click fix available in the GUI: $($r.AutoFix.Label)" -ForegroundColor Green }
    }
}

function Invoke-LocalScan {
    $E = Get-HostEnvironment
    $results = @(Invoke-AllChecks -E $E -OnResult { param($r, $i, $n) Write-Progress -Activity 'Analysing logon' -Status $r.Name -PercentComplete ($i / $n * 100) })
    Write-Progress -Activity 'Analysing logon' -Completed
    [void](Save-ScanHistory -E $E -Results $results)
    [pscustomobject]@{ E = $E; Results = $results }
}

$isAdminNow = (New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($InstallProbe -or $UninstallProbe) {
    if (-not $isAdminNow) { Write-Error 'Run elevated to install or remove the logon probe.'; exit 2 }
    if ($UninstallProbe) { Uninstall-LogonProbe } else {
        $p = @{ ProbeScriptText = $script:ProbeText; ReportScriptText = $script:ReportText; DesktopShortcut = [bool]$ReportShortcut }
        if ($PSBoundParameters.ContainsKey('SharePath')) { $p.SharePath = $SharePath }
        Install-LogonProbe @p
    }
    return
}

if ($InstallModules) {
    Get-RequiredModuleStatus | Format-Table Name, Installed, Version, Purpose -AutoSize | Out-Host
    Install-RequiredModules -AllUsers:$isAdminNow
    return
}

if ($ExportIntune) {
    $n = Export-IntuneRemediations -OutDir $ExportIntune -EngineText $script:EngineText
    Write-Host "$n Intune remediation pair(s) written to $ExportIntune (see README.md there)." -ForegroundColor Green
    return
}

if ($Gate) {
    try {
        $E = Get-HostEnvironment
        $g = Invoke-ImageGate -E $E -Level $GateLevel
        $g.Results | Sort-Object SortKey | Format-Table Status, Id, Name, Summary -AutoSize -Wrap | Out-Host
        if ($JsonPath) {
            $json = [ordered]@{ Passed = $g.Passed; Level = $g.Level; Computer = $E.ComputerName; Build = $E.BuildString; Time = (Get-Date).ToString('o')
                                Results = @($g.Results | ForEach-Object { [ordered]@{ Id = $_.Id; Name = $_.Name; Status = $_.Status; Summary = $_.Summary; Fix = $_.Fix } }) } | ConvertTo-Json -Depth 4
            [System.IO.File]::WriteAllText($JsonPath, $json, (New-Object System.Text.UTF8Encoding $false))
        }
        if ($g.Passed) { Write-Host "IMAGE GATE PASSED ($GateLevel level)" -ForegroundColor Green; exit 0 }
        Write-Host "IMAGE GATE FAILED - $(@($g.Failed).Count) check(s): $((@($g.Failed) | ForEach-Object { $_.Id }) -join ', ')" -ForegroundColor Red
        exit 1
    } catch { Write-Error "Image gate error: $($_.Exception.Message)"; exit 2 }
}

if ($ComputerName) {
    $hosts = @($ComputerName | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $ki = ''; if (Test-Path $KnownIssuesPath) { $ki = [System.IO.File]::ReadAllText($KnownIssuesPath) }
    Write-Host "Scanning $($hosts.Count) host(s) over PowerShell remoting..." -ForegroundColor Cyan
    $fleet = Invoke-FleetScan -ComputerName $hosts -Credential $Credential -Days $LookbackDays -CoreText $script:EngineText -KnownIssuesText $ki
    $fleet.Hosts | Sort-Object Computer | ForEach-Object {
        $top = Get-TopCauses $_.Results 1
        [pscustomobject]@{ Host = $_.Computer; Build = $_.Env.BuildString; Problems = @($_.Results | Where-Object Status -eq 'Problem').Count; Warnings = @($_.Results | Where-Object Status -eq 'Warning').Count; 'Most likely cause' = $(if ($top) { "$($top.Id) $($top.Summary)" }) }
    } | Format-Table -AutoSize -Wrap | Out-Host
    foreach ($f in $fleet.Failed) { Write-Warning "$($f.Computer): $($f.Error)" }
    if ($ReportPath) { Export-FleetReport -Fleet $fleet -Path $ReportPath; Write-Host "Fleet report written to $ReportPath" -ForegroundColor Green }
    if ($JsonPath) {
        $json = @($fleet.Hosts | ForEach-Object { [ordered]@{ Computer = $_.Computer; Build = $_.Env.BuildString; Results = @($_.Results | ForEach-Object { [ordered]@{ Id = $_.Id; Status = $_.Status; Summary = $_.Summary } }) } }) | ConvertTo-Json -Depth 5
        [System.IO.File]::WriteAllText($JsonPath, $json, (New-Object System.Text.UTF8Encoding $false))
    }
    return
}

if ($cliMode) {
    $scan = Invoke-LocalScan
    if ($SaveBaseline) {
        $s = Get-HostSnapshot -Results $scan.Results
        [System.IO.File]::WriteAllText($SaveBaseline, ($s | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding $false))
        Write-Host "Baseline of $env:COMPUTERNAME saved to $SaveBaseline" -ForegroundColor Green
    }
    if ($CompareBaseline) {
        $b = [System.IO.File]::ReadAllText($CompareBaseline) | ConvertFrom-Json
        $diff = @(Compare-HostSnapshot -Baseline $b -Current (Get-HostSnapshot -Results $scan.Results))
        Write-Host "`n$($diff.Count) difference(s) between $env:COMPUTERNAME and baseline $($b.Computer):" -ForegroundColor Cyan
        $diff | Format-Table Category, Item, Change, Baseline, ThisHost -AutoSize -Wrap | Out-Host
        if ($JsonPath -and -not $NoGui) { [System.IO.File]::WriteAllText($JsonPath, ($diff | ConvertTo-Json -Depth 3), (New-Object System.Text.UTF8Encoding $false)) }
    }
    if ($SupportBundle) {
        $zip = New-SupportBundle -E $scan.E -Results $scan.Results -OutDir $SupportBundle -IncludeSecurity:$isAdminNow
        Write-Host "Support bundle: $zip" -ForegroundColor Green
    }
    if ($NoGui) {
        Write-Results -E $scan.E -Results $scan.Results
        if ($ReportPath) { Export-HtmlReport -E $scan.E -Results $scan.Results -Path $ReportPath; Write-Host "`nReport written to $ReportPath" -ForegroundColor Green }
        if ($JsonPath) { [System.IO.File]::WriteAllText($JsonPath, (ConvertTo-ResultJson -E $scan.E -Results $scan.Results), (New-Object System.Text.UTF8Encoding $false)); Write-Host "Results written to $JsonPath" -ForegroundColor Green }
    }
    return
}
#endregion

#region GUI
. $GuiBlock
[void]$win.ShowDialog()
#endregion