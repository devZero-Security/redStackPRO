# redStackPRO: plant the SCCM attack surface on an installed MECM site (clean-room
# MIT). Drives the ConfigurationManager module as a CM Full Administrator. Each
# primitive is wrapped so one failure does not sink the rest, and the outcomes are
# written to a result file the caller reads. See goad-fidelity-build.
param($SiteCode, $Password, $NaaAccount, $PushAccount, $DaAccount, $AdminGroup,
      $ManagedGroup, $SiteFqdn)
$ErrorActionPreference = "Continue"
$log = @()
function Step($name, $block) {
  try { & $block; $script:log += "$name = ok" }
  catch { $script:log += "$name = ERR $($_.Exception.Message)" }
}

$modPath = $env:SMS_ADMIN_UI_PATH.Replace("\bin\i386", "\bin\configurationmanager.psd1")
Import-Module $modPath -Force

# The SMS provider (and its WMI namespace) can lag the site install by minutes, so
# the CMSite PSDrive may not mount on the first try. Retry mounting it before doing
# any work; if it never comes up, still write a result file so the caller does not
# just time out with no signal.
$mounted = $false
for ($i = 0; $i -lt 30; $i++) {
  try {
    if (-not (Get-PSDrive -Name $SiteCode -ErrorAction SilentlyContinue)) {
      New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $SiteFqdn -Scope Global -ErrorAction Stop | Out-Null
    }
    Set-Location "${SiteCode}:" -ErrorAction Stop
    $mounted = $true
    break
  } catch { Start-Sleep -Seconds 20 }
}
if (-not $mounted) {
  Set-Content C:\Windows\Temp\rsp-mecm-config.txt "provider = ERR CMSite drive did not mount (SMS provider not ready)"
  return
}
$sec = ConvertTo-SecureString $Password -AsPlainText -Force

# 1. Register the SCCM accounts in the CM credential store.
foreach ($acct in @($PushAccount, $NaaAccount, $DaAccount)) {
  if ($acct) {
    Step "account:$acct" {
      if (-not (Get-CMAccount -UserName $acct -ErrorAction SilentlyContinue)) {
        New-CMAccount -UserName $acct -Password $sec -SiteCode $SiteCode | Out-Null
      }
    }
  }
}

# 2. Discovery: AD Forest (auto-create boundaries) + AD Group (managed devices).
Step "forest-discovery" {
  Set-CMDiscoveryMethod -ActiveDirectoryForestDiscovery -SiteCode $SiteCode `
    -Enabled $true -EnableActiveDirectorySiteBoundaryCreation $true `
    -EnableSubnetBoundaryCreation $true | Out-Null
}
Step "system-discovery" {
  # Find the domain computers so client push has targets, and the domain users;
  # scoped to the domain root so discovery actually returns objects.
  $ldap = "LDAP://" + ([ADSI]"LDAP://RootDSE").defaultNamingContext.ToString()
  Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $SiteCode `
    -Enabled $true -EnableDeltaDiscovery $true `
    -AddActiveDirectoryContainer $ldap -Recursive | Out-Null
  Set-CMDiscoveryMethod -ActiveDirectoryUserDiscovery -SiteCode $SiteCode `
    -Enabled $true `
    -AddActiveDirectoryContainer $ldap -Recursive | Out-Null
}

# 3. Boundary + boundary group so push/DP service the subnet.
Step "boundary" {
  if (-not (Get-CMBoundary -BoundaryName "Default-First-Site-Name" -ErrorAction SilentlyContinue)) {
    New-CMBoundary -Type ADSite -Name "Default-First-Site-Name" -Value "Default-First-Site-Name" | Out-Null
  }
  if (-not (Get-CMBoundaryGroup -Name "redStackPro-BG" -ErrorAction SilentlyContinue)) {
    New-CMBoundaryGroup -Name "redStackPro-BG" -DefaultSiteCode $SiteCode | Out-Null
  }
  $b = Get-CMBoundary -BoundaryName "Default-First-Site-Name"
  Add-CMBoundaryToGroup -BoundaryGroupName "redStackPro-BG" -BoundaryId $b.BoundaryID -ErrorAction SilentlyContinue
}

# 4. NAA: write the Network Access Account into the Software Distribution component
# (WMI). Pushed to every client in machine policy, DPAPI-stored -> harvestable.
if ($NaaAccount) {
  Step "naa" {
    $ns = "root\sms\site_$SiteCode"
    $comp = Get-WmiObject -Class SMS_SCI_ClientComp -Namespace $ns | Where-Object { $_.ItemName -eq "Software Distribution" }
    $props = $comp.PropLists
    $naa = $props | Where-Object { $_.PropertyListName -eq "Network Access User Names" }
    if ($naa) { $naa.Values = @($NaaAccount) }
    $comp.PropLists = $props
    $comp.Put() | Out-Null
  }
}

# 5. Client push with NTLM fallback -> coercible/relayable to site takeover.
Step "client-push" {
  Set-CMClientPushInstallation -SiteCode $SiteCode `
    -EnableAutomaticClientPushInstallation $true `
    -EnableSystemTypeConfigurationManager $true -EnableSystemTypeServer $true `
    -EnableSystemTypeWorkstation $true -InstallClientToDomainController $false `
    -AllownNTLMFallback $true -InstallationProperty "SMSSITECODE=$SiteCode" | Out-Null
  if ($PushAccount) {
    Set-CMClientPushInstallation -SiteCode $SiteCode -AddAccount $PushAccount -ErrorAction SilentlyContinue | Out-Null
  }
}

# 6. Password-less PXE on the distribution point -> PXE secret extraction.
Step "pxe" {
  $dp = Get-CMDistributionPoint -SiteSystemServerName $SiteFqdn -ErrorAction SilentlyContinue
  if ($dp) {
    Set-CMDistributionPoint -InputObject $dp -EnablePxe $true -AllowPxeResponse $true `
      -EnableUnknownComputerSupport $true | Out-Null
  }
}

# 7. Full Administrator RBAC granted to a group (a low-priv member becomes site admin).
if ($AdminGroup) {
  Step "rbac" {
    if (-not (Get-CMAdministrativeUser -Name $AdminGroup -ErrorAction SilentlyContinue)) {
      New-CMAdministrativeUser -Name $AdminGroup -RoleName "Full Administrator" | Out-Null
    }
  }
}

Set-Content C:\Windows\Temp\rsp-mecm-config.txt ($log -join "`n")
$log -join "`n"
