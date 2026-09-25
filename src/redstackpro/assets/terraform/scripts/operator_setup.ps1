# redStackPRO Windows operator setup. A STANDALONE PowerShell script, delivered
# verbatim (never through a terraform template, so its $ and ${ need no escaping)
# and run once at first boot on the offense Windows operator only. It installs
# the operator kit and pre-configures MobaXterm and the browser, so the box is a
# ready operator workstation the moment someone RDPs in -- a faithful port of the
# original redStack windows_setup. See PAI / range-access-model.
#
# Two things are passed in through the environment by the caller (the boot
# script), so this file stays static:
#   RSP_HOSTS    - a hosts-file block mapping the range's teamservers/redirector
#                  by name, appended to the machine hosts file.
#   RSP_OPERATOR - the account the operator actually logs in as (redop for ops).
#                  The per-user kit (MobaXterm sessions, browser bookmarks,
#                  desktop markers) is seeded into the Default profile so the
#                  operator's not-yet-created profile inherits it at first logon,
#                  and dropped straight into the operator profile too if it
#                  already exists. Writing only to Administrator (as the first
#                  cut did) put the kit in a profile the operator never opens.
#
# The Adaptix client is deliberately NOT installed here. It is a build-it-yourself
# GUI, and these operator VMs are large enough to compile it after the fact;
# the recommended flow is to compile the Windows client (or keep a prebuilt one)
# and upload it to this box when Adaptix is actually needed.

$ErrorActionPreference = 'Continue'
Start-Transcript -Path "C:\Windows\Temp\operator-setup.log" -Append

Write-Host "===== redStackPRO operator setup started $(Get-Date) ====="

# The profiles the per-user kit lands in. Default seeds the operator's future
# profile; the operator's own profile is added when it already exists.
$operator = $env:RSP_OPERATOR
if ([string]::IsNullOrWhiteSpace($operator)) { $operator = "Administrator" }
$profileDirs = @("C:\Users\Default")
if (Test-Path "C:\Users\$operator") { $profileDirs += "C:\Users\$operator" }

# The range's teamservers/redirector by name, so MobaXterm's saved sessions and
# the browser bookmarks resolve without hardcoded IPs. The caller fills RSP_HOSTS.
if ($env:RSP_HOSTS) {
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "`n$($env:RSP_HOSTS)"
}

# The stack's SSH key, so the saved sessions key-auth instead of prompting for
# the password. Its public half is already an authorized key for the platform
# account on every host (it is the Guacamole key the portal's SSH tiles use), so
# nothing has to be authorized here -- the key just has to be present. Password
# auth stays enabled on the hosts as the fallback, so a session still works if
# the key is ever absent. Kept at one machine-wide path the sessions reference by
# absolute path, so it does not matter which profile logs in. The caller fills
# RSP_SSH_KEY. Written LF-only with no BOM: an OpenSSH key with CRLF or a BOM is
# rejected as malformed.
$RspKeyPath = "C:\redstackpro\id_ed25519"
if ($env:RSP_SSH_KEY) {
    New-Item -ItemType Directory -Force -Path "C:\redstackpro" | Out-Null
    $keyText = ($env:RSP_SSH_KEY -replace "`r`n", "`n").Trim() + "`n"
    [System.IO.File]::WriteAllText($RspKeyPath, $keyText,
        (New-Object System.Text.UTF8Encoding $false))
    # Lock it down: SYSTEM and Administrators, plus the operator who reads it.
    # SSH refuses a world-readable private key.
    & icacls $RspKeyPath /inheritance:r /grant:r `
        "SYSTEM:R" "Administrators:R" "$operator`:R" 2>&1 | Out-Null
    # A convenience copy at the operator's own default identity path, for the
    # Windows OpenSSH client, git, and the VS Code terminal.
    foreach ($dir in $profileDirs) {
        $sshDir = "$dir\.ssh"
        New-Item -ItemType Directory -Force -Path $sshDir | Out-Null
        [System.IO.File]::WriteAllText("$sshDir\id_ed25519", $keyText,
            (New-Object System.Text.UTF8Encoding $false))
    }
}

# A visible "still running" marker plus a shortcut that tails the live log, so
# anyone who RDPs in mid-provision knows to wait. Seeded into every target
# profile's desktop.
foreach ($dir in $profileDirs) {
    $deskDir = "$dir\Desktop"
    New-Item -ItemType Directory -Force -Path $deskDir | Out-Null
    Set-Content -Path "$deskDir\_SETUP-IN-PROGRESS.txt" -Encoding ASCII -Value @"
redStackPRO operator setup is STILL RUNNING - do not rely on this box yet.
This file is replaced by _SETUP-COMPLETE.txt when provisioning finishes.
Live log: C:\Windows\Temp\operator-setup.log  (or the "Setup Log" desktop shortcut)
"@
    try {
        $wshLog = New-Object -ComObject WScript.Shell
        $logLnk = $wshLog.CreateShortcut("$deskDir\Setup Log.lnk")
        $logLnk.TargetPath = "powershell.exe"
        $logLnk.Arguments = "-NoExit -Command `"Get-Content 'C:\Windows\Temp\operator-setup.log' -Wait`""
        $logLnk.IconLocation = "powershell.exe,0"
        $logLnk.Save()
    } catch {}
}

# This is the operator's own workstation, and it runs offensive tooling (C2
# clients, payload artifacts) that Defender would quarantine. Turn real-time
# protection off and exclude the tools drive, the way the original redStack
# operator box did. This is the OPERATOR box only -- range targets keep their
# posture (Defender there is a per-host toggle).
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath "C:\Tools" -ErrorAction SilentlyContinue

# And the host firewall, which the original redStack operator box also turned
# off and this port had dropped. It matters for more than convenience: an
# operator box receives things -- a listener, a callback, a relayed auth -- and
# the host firewall blocks those inbound silently, which reads as a broken tool
# rather than a blocked port. The box has no public address and its exposure is
# already decided by the cloud security groups, so this removes a second
# enforcement point that only gets in the way. OPERATOR box only: range targets
# keep their posture, since their firewall state is part of what is being
# attacked. Verified needed on a live deploy, where all three profiles were
# still Enabled after setup reported success.
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False `
    -ErrorAction SilentlyContinue
# Belt and braces for an image where the cmdlet is unavailable or refuses.
& netsh advfirewall set allprofiles state off 2>&1 | Out-Null

# Easier browsing on a training box: drop IE Enhanced Security.
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey  = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path $UserKey  -Name "IsInstalled" -Value 0 -Force -ErrorAction SilentlyContinue

# Chocolatey, then the operator kit. MobaXterm first: it is the operator's SSH
# client to every box in the range, and it gets its saved sessions below.
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
$env:chocolateyUseWindowsCompression = 'true'
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
$choco = "$env:ProgramData\chocolatey\bin\choco.exe"

foreach ($pkg in @('mobaxterm', '7zip', 'chromium', 'vscode', 'git')) {
    Write-Host "[*] choco install $pkg"
    & $choco install $pkg -y --no-progress
}

# --- MobaXterm saved sessions -------------------------------------------------
# The INI is derived from a fully-initialized MobaXterm: [Misc] LocalShell
# suppresses the first-run wizard, and each session uses the ' = #109#' format
# (the leading space matters). Sessions point at the range hosts by name -- the
# canvas node names, resolved through RSP_HOSTS, with the conventional aliases
# (mythic/sliver/adaptix/redirector/kali) also mapped there for the stock names.
#
# Each session names the private key in the field after `%0%-1%0%`, so it
# key-auths instead of prompting. The path is inserted into an existing empty
# field, so the field COUNT is unchanged: if this ever turns out to be the wrong
# slot on a MobaXterm build, the session degrades to the password prompt rather
# than breaking. UseInternalMobAgent is on below so the key is offered even
# where the session field is not honored.
#
# The path is a __RSP_KEY__ token substituted below rather than written inline.
# It was inline, and the backslash-r of C:\redstackpro had become a real carriage
# return byte, so every session carried C:<CR>edstackpro\id_ed25519. MobaXterm
# read up to the CR and reported: Unable to use key file "C:". Five sessions,
# all silently password-only, and the corruption is invisible when the file is
# printed because the CR just returns the cursor to the start of the line.
# Found on the win-op RDP check the field comment above was asking for.
$mobaIni = @'
[Misc]
PasswordsInRegistry=1
LocalShell=Bash (64 bit)
SlashDir=_AppDataDir_\MobaXterm\slash
HomeDir=_AppDataDir_\MobaXterm\home
RDMSessionsAlreadyImported=1
SkinSat=80
SkinName3=Windows dark theme
DefTextEditor=<MobaTextEditor>
StorePasswords=Ask
AllowMultiInstances=0

[SSH]
SFTPShowDotFiles=1
MonitorHost=1
UseInternalMobAgent=1
DisplaySSHBanner=1
UseNewMoTTY=1
StrictHostKeyChecking=1
AutoStartSSHGUI=1
EnableSFTP=1
RemoteMonitoring=1
UseGSSAPI=1

[Display]
SidebarRight=0
VisibleTabNum=1
MenuAndButtons=2
IconsTheme=0
RoundedTabs=1

[Bookmarks]
SubRep=redStackPRO Sessions
ImgNum=42
Mythic C2 (SSH)= #109#0%mythic%22%redop%%-1%-1%%%%%0%-1%0%__RSP_KEY__%%-1%-1%0%0%%%%0%0%1%%0%%%%0%-1%-1%0%%%0#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%0%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%0%-1%0%#0# #-1
Sliver C2 (SSH)= #109#0%sliver%22%redop%%-1%-1%%%%%0%-1%0%__RSP_KEY__%%-1%-1%0%0%%%%0%0%1%%0%%%%0%-1%-1%0%%%0#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%0%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%0%-1%0%#0# #-1
Adaptix C2 (SSH)= #109#0%adaptix%22%redop%%-1%-1%%%%%0%-1%0%__RSP_KEY__%%-1%-1%0%0%%%%0%0%1%%0%%%%0%-1%-1%0%%%0#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%0%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%0%-1%0%#0# #-1
Apache Redirector (SSH)= #109#0%redirector%22%redop%%-1%-1%%%%%0%-1%0%__RSP_KEY__%%-1%-1%0%0%%%%0%0%1%%0%%%%0%-1%-1%0%%%0#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%0%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%0%-1%0%#0# #-1
Kali Linux (SSH)= #109#0%kali%22%redop%%-1%-1%%%%%0%-1%0%__RSP_KEY__%%-1%-1%0%0%%%%0%0%1%%0%%%%0%-1%-1%0%%%0#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%0%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%0%-1%0%#0# #-1
'@
# Point every session at the key this script actually wrote, from the one
# variable that holds the path, so the two can never drift again.
$mobaIni = $mobaIni.Replace('__RSP_KEY__', $RspKeyPath)

# No BOM: MobaXterm silently rejects a UTF-8 BOM and recreates a blank config.
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
foreach ($dir in $profileDirs) {
    $mobaDir = "$dir\AppData\Roaming\MobaXterm"
    New-Item -ItemType Directory -Force -Path $mobaDir | Out-Null
    [System.IO.File]::WriteAllText("$mobaDir\MobaXterm.ini", $mobaIni, $utf8NoBom)
}

# --- Chromium bookmarks -------------------------------------------------------
$bookmarks = @'
{
   "checksum": "00000000000000000000000000000000",
   "roots": {
      "bookmark_bar": {
         "children": [
            { "date_added": "13000000000000000", "guid": "11111111-1111-1111-1111-111111111111", "id": "2", "name": "Mythic C2", "type": "url", "url": "https://mythic:7443" },
            { "date_added": "13000000000000001", "guid": "22222222-2222-2222-2222-222222222222", "id": "3", "name": "Guacamole", "type": "url", "url": "https://guac/guacamole" }
         ],
         "date_added": "13000000000000000", "date_modified": "13000000000000000",
         "guid": "0bc5d13f-2cba-5d74-951f-3f233fe6c908", "id": "1", "name": "Bookmarks bar", "type": "folder"
      },
      "other":  { "children": [], "date_added": "13000000000000000", "guid": "82b081ec-3d0b-5e97-a7b6-c3c8e4cce5c4", "id": "4", "name": "Other bookmarks", "type": "folder" },
      "synced": { "children": [], "date_added": "13000000000000000", "guid": "4cf2e351-0e85-532b-bb37-df045d8f8d0f", "id": "5", "name": "Mobile bookmarks", "type": "folder" }
   },
   "version": 1
}
'@
foreach ($dir in $profileDirs) {
    $chromiumDir = "$dir\AppData\Local\Chromium\User Data\Default"
    New-Item -ItemType Directory -Force -Path $chromiumDir | Out-Null
    [System.IO.File]::WriteAllText("$chromiumDir\Bookmarks", $bookmarks, $utf8NoBom)
    [System.IO.File]::WriteAllText("$chromiumDir\Preferences", '{"bookmark_bar":{"show_on_all_tabs":true}}', $utf8NoBom)
}

# Adaptix client: not installed here by design -- compile it on this box or
# upload a prebuilt Windows client when needed (see the header). A Tools folder
# is created for it and is already a Defender exclusion.
New-Item -ItemType Directory -Force -Path "C:\Tools" | Out-Null

# Done markers, one per seeded profile.
foreach ($dir in $profileDirs) {
    $deskDir = "$dir\Desktop"
    Remove-Item "$deskDir\_SETUP-IN-PROGRESS.txt" -Force -ErrorAction SilentlyContinue
    Set-Content -Path "$deskDir\_SETUP-COMPLETE.txt" -Encoding ASCII -Value @"
redStackPRO operator setup COMPLETE - $(Get-Date)
All operator tools are installed and MobaXterm has its saved sessions.
Full log: C:\Windows\Temp\operator-setup.log
"@
}
Write-Host "===== redStackPRO operator setup completed $(Get-Date) ====="
Stop-Transcript
