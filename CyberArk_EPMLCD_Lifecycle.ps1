<#PSScriptInfo

.VERSION 1.5.0

.GUID cf187d04-2d7d-48aa-94cf-80d4f33f6a68

.AUTHOR @cgeneske

.DESCRIPTION CyberArk Privilege Access Management (PAM) account lifecycle utility for Endpoint Privilege Management (EPM) Loosely Connected Devices (LCD)

.COPYRIGHT Copyright (c) 2024 Craig Geneske

.LICENSEURI https://github.com/cgeneske/CyberArkEPMLCDLifecycle/blob/main/LICENSE.md 

.PROJECTURI https://github.com/cgeneske/CyberArkEPMLCDLifecycle

#>

#Requires -Version 5.0

<#
.SYNOPSIS
CyberArk Privilege Access Management (PAM) account lifecycle utility for Endpoint Privilege Management (EPM) Loosely Connected Devices (LCD).
Latest solution and full README are available at https://github.com/cgeneske/CyberArkEPMLCDLifecycle 

.DESCRIPTION
Organizations seeking to reduce and eliminate privilege escalation abuse, credential theft, and ransomware threats often turn to CyberArk's 
Endpoint Privilege Manager (EPM) for its effective suite of controls.  In concert with dialing in these least-privilege and application controls, 
EPM can also seamlessly integrate with CyberArk's Self-Hosted Privilege Access Management (PAM) and Privilege Cloud SaaS platforms, to provide 
agent-enhanced, loosely-connected, credential management capabilities for their local administrator accounts.

The design of this utility is to automate the CyberArk PAM account lifecycle for one or more standardized local accounts, on endpoints with an 
EPM agent.  These would be accounts that inherently exist on every endpoint of a given platform type (Windows, Mac, or Linux) as a part of its 
standard baseline (i.e. The Windows Built-In "Administrator").  It achieves this using data obtained exclusively from user-defined script variables, 
the CyberArk PAM and EPM APIs, and optionally DNS (for endpoint FQDN resolution).

The utility leverages both PAM and EPM APIs to compare the computers (agents) that exist in EPM against related local accounts that exist in PAM, 
automatically determining and executing the needed onboarding and offboarding actions in PAM.  As new agents come online in EPM, one or more 
standardized local accounts will be onboarded to PAM.  Likewise as endpoints are pruned from EPM, either through organic inactivity-based attrition 
or proactive computer decomissioning flows, their local accounts will be offboarded from PAM.

**This utility does not scan, discover, nor communicate directly with loosely-connected endpoints in any way.  It will NOT validate the existence of 
any local accounts prior to conducting onboarding activities in CyberArk PAM!**

Key Features:

- Complete lifecycle management (on/offboarding) for named local accounts in PAM that are based on LCD
- Designed to be run interactively or via Scheduled Task from a central endpoint
- Supports separate onboarding Safes for staging Windows, MacOS and Linux accounts
- Supports onboarding across a pool of Safes to optimize per-Safe object counts and keep under desired limits
- Supports an offboarding delay to serve as a buffer against rapid turnover in the EPM database
- Flexible Safe and Platform scoping provides continuous management throughout the account lifecycle
- Dynamic FQDN discovery via DNS for "mixed" EPM Sets that contain endpoints with varied domain memberships
- **No hard-coded secrets!**  Choice of CyberArk Central Credential Provider (CCP) or Windows Credential Manager
- Implementation of CCP supports OS User (IWA), Client Certificate, and Allowed Machines authentication
- Non-invasive Report-Only mode, useful for determining candidates for on/offboarding, prior to go-live
- Safety mechanism to prevent sweeping changes in PAM brought by unexpected environmental changes

Requirements:

- CyberArk Privilege Access Management (PAM) Self-Hosted v11.6+ OR CyberArk Privilege Cloud
- CyberArk Endpoint Privilege Management (EPM) SaaS
- PAM and EPM API credentials added to CyberArk PAM (CCP) or the Windows Credential Manager
- PowerShell v5 or greater

For a complete description of all user assigned varaibles, see the GitHub README linked in the solution synopsis.

.EXAMPLE
CyberArk_EPMLCD_Lifecycle.ps1

.INPUTS
None

.OUTPUTS
None

.NOTES
AUTHOR:
Craig Geneske

VERSION HISTORY:
1.0.0   8/24/2023   - Initial Release
1.1.0   8/29/2023   - Added safety mechanism
1.2.0   9/15/2023   - Added safe pooling
1.3.0   11/30/2023  - Added E-Mail notification, PSScriptInfo version check, Linux LCD, and Privilege Cloud Shared Services support
1.4.0   1/29/2024   - Added ability to exclude hostname patterns from management scope (regex), and optional E-Mail attachments for 
                      the log and report files.
1.4.1   4/9/2024    - Fixed a bug that caused an unexpected interrupt if $SafeSearchList was defined.  Fixed a bug where duplicate
                      entries of the same computer in EPM (reimaging scenarios) would result in duplicate onboarding actions in PAM.
1.5.0   8/7/2024    - Added configurable offboarding delay and improved reporting when configured to skip on/offboarding.

DISCLAIMER:
This solution is provided as-is - it is not supported by CyberArk nor an official CyberArk solution.
#>

using namespace System.Collections.Generic 

################################################### SCRIPT VARIABLES ####################################################
#region Script Variables

###############################
### BEGIN CHANGE-ME SECTION ###
###############################

#Run Mode Options
$ReportOnlyMode = $true
$SkipOnBoarding = $false
$SkipOffBoarding = $false
$SkipWindows = $false
$SkipMac = $false
$SkipLinux = $false

#Auxillary Options
$SendSummaryEmail = $true
$EmailWithSsl = $true
$EmailFullReportAndLog = $false
$VersionCheck = $true
$ValidateDomainNamesDNS = $true
$SkipIfNotInDNS = $false
$IgnoreSSLCertErrors = $false
$OffboardingDelayDays = 0

#General Environment Details
$EndpointUserNamesWin = "Administrator"
$EndpointUserNamesMac = "mac_admin"
$EndpointUserNamesLinux = "root"
$OnboardingPlatformIdWin = "WinLooselyDevice"
$OnboardingPlatformIdMac = "MACLooselyDevice"
$OnboardingPlatformIdLinux = "UnixLooselyDevice"
$OnboardingSafesWin = "EPMLCDSTG01","EPMLCDSTG02","EPMLCDSTG03"
$OnboardingSafesMac = "EPMLCDSTG01","EPMLCDSTG02","EPMLCDSTG03"
$OnboardingSafesLinux = "EPMLCDSTG01","EPMLCDSTG02","EPMLCDSTG03"
$EndpointDomainNames = ""
$EndpointHostnameExclusionsRegex = ""
$LCDPlatformSearchRegex = ".*"
$SafeSearchList = ""
$EPMSetIDs = ""
$EPMRegion = "US"
$PAMHostname = "hostname"
$SMTPRelayHostname = "hostname"
$EmailFromAddress = "donotreply@domaindotcom"
$EmailToAddress = "recipient@domaindotcom"

#Source for PAM and EPM API credentials
$APIUserSource = [APIUserSource]::CyberArkCCP 

#Populate When API User Source is [APIUserSource]::WinCredMgr
$PAMCredTarget = "EPMLCD_Lifecycle_PAMAPI"
$EPMCredTarget = "EPMLCD_Lifecycle_EPMAPI"

#Populate when API User Source is [APIUserSource]::CyberArkCCP
$CCPAuthType = [CCPAuthType]::OSUser
$CertThumbprint = ""
$PAMAccountName = "lifecycle_pam_api.pass"
$PAMObjectSafe = "EPM Lifecycle API"
$EPMAccountName = "lifecycle_epm_api.pass"
$EPMObjectSafe = "EPM Lifecycle API"
$CCPHostname = "hostname"
$CCPPort = 443
$CCPServiceRoot = "AIMWebService"
$CCPAppID = "EPM LCD Lifecycle"

#############################
### END CHANGE-ME SECTION ###
#############################

$LogFilePath = $PSScriptRoot + "\Logs\$($MyInvocation.MyCommand.Name.Substring(0, $MyInvocation.MyCommand.Name.Length - 4))_" + (Get-Date -Format "MM-dd-yyyy_HHmmss") + ".log"
$ReportFilePath = $PSScriptRoot + "\Reports\$($MyInvocation.MyCommand.Name.Substring(0, $MyInvocation.MyCommand.Name.Length - 4))_" + (Get-Date -Format "MM-dd-yyyy_HHmmss") + ".csv"
$DatFilePath = $($PSCommandPath).Substring(0, $PSCommandPath.Length - 4) + ".dat"
$PSScriptInfo = Test-ScriptFileInfo -Path $PSCommandPath

$EnableSafety = $true
$SafetyTriggered = $false
$SafetyThresholdEPM = 0.10 # 10%
$SafetyThresholdPAM = 0.10 # 10%

$PAMPageSize = 1000 # Maximum is 1,000
$EPMPageSize = 5000 # Maximum is 5,000
$MaximumDNSFailures = 10
$StatusPingInterval = 15
$MaxSafeObjects = 20000
$WarnSafeObjects = 18000
$BulkChunkLimit = 10000

$OriginScriptUri = "https://raw.githubusercontent.com/cgeneske/CyberArkEPMLCDLifecycle/main/CyberArk_EPMLCD_Lifecycle.ps1"

if ($PAMHostname -match "\.cyberark\.cloud$") {
    $PrivCloudHostname = $PAMHostname.Replace(".cyberark.cloud", ".privilegecloud.cyberark.cloud")
    $PAMBaseURI = "https://$PrivCloudHostname/PasswordVault"
}
else {
    $PAMBaseURI = "https://$PAMHostname/PasswordVault"
}

$PAMSessionToken = $null

$PAMAuthLogonUrl = $PAMBaseURI + "/api/auth/CyberArk/Logon"
$PAMAuthLogoffUrl = $PAMBaseURI + "/api/auth/Logoff"
$PAMAccountsUrl = $PAMBaseURI + "/api/Accounts"
$PAMPlatformsUrl = $PAMBaseURI + "/api/Platforms"
$PAMBulkAccountsUrl = $PAMBaseURI + "/api/bulkactions/accounts"

$EPMAuthLogonUrl = "https://{0}.epm.cyberark.com/EPM/API/Auth/EPM/Logon"
$EPMSetsListUrl = "/EPM/API/Sets"
$EPMComputersUrl = "/EPM/API/Sets/{0}/Computers"

#endregion

################################################### ENUM DECLARATIONS ###################################################
#region Enums

enum APIUserSource {
    WinCredMgr
    CyberArkCCP
}

enum CCPAuthType {
    OSUser
    Certificate
    AllowedMachines
}

#endregion

#################################################### LOADING TYPES ######################################################
#region Loading Types

#Used for URL safe encoding within System.Web.HttpUtility
Add-Type -AssemblyName System.Web -ErrorAction Stop 

#Used for ignoring SSL Certificate errors if so specified in script variables - Technique to remain compatible with PowerShell version 5 and below
if (!("CACertValidation" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class CACertValidation {
    public static bool IgnoreSSLErrors(object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors) { return true; }

    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(CACertValidation.IgnoreSSLErrors);
    }
}
"@
}

#Used for accessing the Microsoft Windows Credential Manager via WinAPI (advapi32.dll)
if (!("CredManager.Utility" -as [type])) {
    Add-Type -TypeDefinition @"
using System.Text;
using System;
using System.Runtime.InteropServices;

namespace CredManager {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CredentialMem {
        public int flags;
        public int type;
        public string targetName;
        public string comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME lastWritten;
        public int credentialBlobSize;
        public IntPtr credentialBlob;
        public int persist;
        public int attributeCount;
        public IntPtr credAttribute;
        public string targetAlias;
        public string userName;
    }

    public class Credential {
        public string target;
        public string username;
        public string password;
        public Credential(string target, string username, string password) {
            this.target = target;
            this.username = username;
            this.password = password;
        }
    }

    public class Utility {
        [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credentialPtr);

        [DllImport("advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
        private static extern bool CredFree([In] IntPtr credentialBufferPtr);

        public static Credential GetUserCredential(string target) {
            CredentialMem credMem;
            IntPtr credPtr;
            bool credIsRead;
            int lastError;
            
            credIsRead = CredRead(target, 1, 0, out credPtr);
            lastError = Marshal.GetLastWin32Error();
            try {
                if (credIsRead) {
                    credMem = Marshal.PtrToStructure<CredentialMem>(credPtr);
                    byte[] passwordBytes = new byte[credMem.credentialBlobSize];
                    Marshal.Copy(credMem.credentialBlob, passwordBytes, 0, credMem.credentialBlobSize);
                    Credential cred = new Credential(credMem.targetName, credMem.userName, Encoding.Unicode.GetString(passwordBytes));
                    return cred;
                }
                else {
                    string reason = String.Format("[{0}] - An unknown error occured", lastError);

                    if (lastError == 1168) {
                        reason = String.Format("[ERROR_NOT_FOUND] - No credential exists with the specified target name of \'{0}\'", target);
                    }

                    if (lastError == 1312) {
                        reason = "[ERROR_NO_SUCH_LOGON_SESSION] - The logon session does not exist or there is no credential set associated with this logon session";
                    }

                    throw new Exception(String.Format("Failed to retrieve credentials - {0}", reason));
                }
            }
            finally {
                if(!credPtr.Equals(IntPtr.Zero)) {
                    CredFree(credPtr);
                }
            } 
        }
    }
}
"@
}

#endregion

################################################# FUNCTION DECLARATIONS #################################################
#region Function Declarations

Function Write-Log {
    <#
    .SYNOPSIS
        Writes a consistently formatted log entry to stdout and a log file
    .DESCRIPTION
        This function is designed to provide a way to consistently format log entries and extend them to
        one or more desired outputs (i.e. stdout and/or a log file).  Each log entry consists of three main
        sections:  Date/Time, Event Type, and the Event Message.  This function is also extended to output
        a standard header during script invocation and footer at script conclusion.
    .PARAMETER Type
        Sets the type of event message to be output.  This must be a member of the defined ValidateSet:
        INF [Informational], WRN [Warning], ERR [Error].
    .PARAMETER Message
        The message to prepend to the log event
    .PARAMETER Header
        Prints the log header
    .PARAMETER Footer
        Prints the log footer
    .EXAMPLE
        [FUNCTION CALL]     : Write-Log -Type INF -Message "Account was onboarded successfully"
        [FUNCTION RESULT]   : 02/09/2023 09:43:25 | [INF] | Account was onboarded successfully
    .NOTES
        Author: Craig Geneske
    #>
    Param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('INF','WRN','ERR')]
        [string]$Type,

        [Parameter(Mandatory = $false)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [switch]$Header,

        [Parameter(Mandatory = $false)]
        [switch]$Footer
    )

    $eventColor = [System.Console]::ForegroundColor
    if ($Header) {
        if ([Environment]::UserInteractive) {
            $eventString = @"
###############################################################################################################################
#                                                                                                                             #
#                                            CyberArk EPM LCD | Lifecycle Utility                                             #
#                                                                                                                             #
###############################################################################################################################
"@
        }
        else {
            $eventString = ""
        }

        $eventString += "`n`n-----------------------> BEGINNING SCRIPT @ $(Get-Date -Format "MM/dd/yyyy HH:mm:ss") <-----------------------`n"
        $eventColor = "Cyan"
    }
    elseif ($Footer) {
        $eventString = "`n------------------------> ENDING SCRIPT @ $(Get-Date -Format "MM/dd/yyyy HH:mm:ss") <------------------------`n"
        $eventColor = "Cyan"
    }
    else {
        $eventString =  $(Get-Date -Format "MM/dd/yyyy HH:mm:ss") + " | [$Type] | " + $Message
        switch ($Type){
            "WRN" { $eventColor = "Yellow"; Break }
            "ERR" { $eventColor = "Red"; Break }
        }
    }

    #Console Output (Interactive)
    Write-Host $eventString -ForegroundColor $eventColor

    #Logfile Output (Non-Interactive)
    Add-Content -Path $LogFilePath -Value $eventString -ErrorAction SilentlyContinue *> $null
}

Function Invoke-ParseFailureResponse {
    <#
    .SYNOPSIS
        Parses the ErrorRecord from a Failed REST API call to present more user-friendly feedback
    .DESCRIPTION
        PAM, CCP, and EPM components will return a number of situationally common response codes and error codes.
        The goal of this function is to provide a means of parsing those responses, in order to deliver more
        consistent, formatted, and meaningful feedback to stdout and/or a log file.
    .PARAMETER Component
        The CyberArk component that is supplying the response failure.  This must be a member of the defined
        ValidateSet: PAM, CCP, EPM
    .PARAMETER Message
        An optional message to prepend to the error output, providing useful context to the raw response
    .EXAMPLE
        Invoke-ParseFailureResponse -Component PAM -Message "A failure occurred while searching for existing accounts"
    .NOTES
        Author: Craig Geneske
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('CCP','PAM','EPM')]
        [string]$Component,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    #Universal failure response presentation
    $ErrorText = $null
    if (!$ErrorRecord.ErrorDetails){
        $ErrorText = $ErrorRecord.Exception.Message
        if ($ErrorRecord.Exception.InnerException) {
            $ErrorText += " --> " + $ErrorRecord.Exception.InnerException.Message
        }
    }
    else{
        $ErrorText = $ErrorRecord.ErrorDetails
    }

    switch ($Component){
        "CCP" { 
            #TODO - Expand for more human-readable presentation of specific error scenarios at CCP?
            Break
        }
        "PAM" {
            #TODO - Expand for more human-readable presentation of specific error scenarios at PAM?
            Break
         }
         "EPM" {
            #TODO - Expand for more human-readable presentation of specific error scenarios at EPM?
            Break
         }
    }
    Write-Log -Type ERR -Message $($Message + " --> " + $ErrorText)
}

Function Get-APICredential {
    <#
    .SYNOPSIS
        Retrieves a CyberArk API credential from the configured user source
    .DESCRIPTION
        Retrieves a PAM or EPM API credential from the configured user source.  If the attempt is successful,
        the credential is serialized into a simple PSObject with a Username and Password property.
        If the attempt fails, an exception is thrown.
    .PARAMETER App
        The application to retrieve the needed credential for, must be part of the validate set (PAM or EPM)
    .EXAMPLE
        $APICred = Get-APICredential -App PAM
    .NOTES
        Author: Craig Geneske

        The following script-level variables are used:
            - $APIUserSource
            - $CCPAuthType
            - $CertThumbprint
            - $CCPHostname
            - $CCPPort
            - $CCPServiceRoot
            - $PAMObjectSafe
            - $PAMAccountName
            - $EPMObjectSafe
            - $EPMAccountName
            - $CCPAppID
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('PAM','EPM')]
        [string]$App
    )

    switch ($APIUserSource) {
        ([APIUserSource]::CyberArkCCP) {
            Write-Log -Type INF -Message "Attempting to retrieve the [$App] API credential from CCP..."
            $result = $null
            $CCPGetCredentialUrl = $null
            
            switch ($App) {
                "PAM" {
                    $CCPGetCredentialUrl = "https://$($CCPHostname):$CCPPort/$CCPServiceRoot/api/Accounts?" + `
                    "Safe=$([System.Web.HttpUtility]::UrlEncode($PAMObjectSafe))" + `
                    "&Object=$([System.Web.HttpUtility]::UrlEncode($PAMAccountName))" + `
                    "&AppId=$([System.Web.HttpUtility]::UrlEncode($CCPAppID))"
                    Break
                }
                "EPM" {
                    $CCPGetCredentialUrl = "https://$($CCPHostname):$CCPPort/$CCPServiceRoot/api/Accounts?" + `
                    "Safe=$([System.Web.HttpUtility]::UrlEncode($EPMObjectSafe))" + `
                    "&Object=$([System.Web.HttpUtility]::UrlEncode($EPMAccountname))" + `
                    "&AppId=$([System.Web.HttpUtility]::UrlEncode($CCPAppID))"
                    Break
                }
            }

            $methodArgs = @{
                Method = "Get"
                Uri = $CCPGetCredentialUrl
                ContentType = "application/json"
            }

            switch ($CCPAuthType) {
                ([CCPAuthType]::OSUser) {
                    $methodArgs.Add("UseDefaultCredentials", $true)
                    Break
                }
                ([CCPAuthType]::Certificate) {
                    $cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {$_.Thumbprint -eq $CertThumbprint}
                    if(!$cert) {
                        Write-Log ERR -Message "Failed to retrieve the [$App] API credential from CCP - The certificate thumbprint is invalid"
                        throw
                    }
                    if(!$cert.PrivateKey) {
                        Write-Log ERR -Message "Failed to retrieve the [$App] API credential from CCP - You do not have read access to the certificate's private key"
                        throw
                    }
                    $methodArgs.Add("Certificate", $cert)
                    Break
                }
            }
        
            try {
                $result = Invoke-RestMethod @methodArgs
                if ($result.UserName -and $result.Content) {
                    Write-Log -Type INF -Message "Successfully retrieved the [$App] API credential from CCP"
                    return [PSCustomObject]@{
                        Username = $result.Username
                        Password = $result.Content
                    }
                }
                else {
                    throw "Invalid response. Check CCP logs to ensure the request is being received"
                }
            } 
            catch {
                Invoke-ParseFailureResponse -Component CCP -ErrorRecord $_ -Message "Failed to retrieve the [$App] API credential from CCP"
                throw
            }
        }
        ([APIUserSource]::WinCredMgr) {
            Write-Log -Type INF -Message "Attempting to retrieve the [$App] API credential from Windows Credential Manager..."
            $credTarget = $null
            switch ($App) {
                "PAM" {
                    $credTarget = $PAMCredTarget
                    Break
                }
                "EPM" {
                    $credTarget = $EPMCredTarget
                    Break
                }
            }
            try {
                $cred = [CredManager.Utility]::GetUserCredential($credTarget)
                Write-Log -Type INF -Message "Successfully retrieved the [$App] API credential from Windows Credential Manager"
                return [PSCustomObject]@{
                    Username = $cred.Username
                    Password = $cred.Password
                }
            }
            catch {
                Write-Log -Type ERR -Message "Failed to retrieve [$App] API user details from Windows Credential Manager --> $($_.Exception.Message)"
                throw
            }
        }
        Default {
            Write-Log -Type ERR -Message "Unable to retrieve [$App] API User details - API User Source [$APIUserSource] has not been implemented"
            throw
        }
    }
}

Function Invoke-APIAuthentication {
    <#
    .SYNOPSIS
        Authenticates to the CyberArk PAM or EPM APIs
    .DESCRIPTION
        Authenticates to the CyberArk PAM or EPM APIs via UN/PW authentication, with concurrency set true (for PAM)
        to support parallel script executions.  If authentication succeeds, the result is returned.  If
        authentication fails, an exception is thrown.
    .PARAMETER App
        The application to initiate API authentication for, must be part of the validate set (PAM or EPM)
    .EXAMPLE
        $PAMSessionToken = Invoke-APIAuthentication -App PAM
    .NOTES
        The following script-level variables are used: 
            - $PAMAuthLogonUrl
            - $EPMAuthLogonUrl
            - $PAMHostname
        
        Author: Craig Geneske
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('PAM','EPM')]
        [string]$App
    )

    $APICred = Get-APICredential -App $App
    $APIAuthUrl = $null
    $postBody = $null

    Write-Log -Type INF -Message "Attempting to authenticate to [$App] API..."

    switch ($App) {
        "PAM" {
            if ($PAMHostname -match "\.cyberark\.cloud$") {
                try{
                    $IdentityTenantUri = [System.Uri](Invoke-WebRequest -Uri "https://$PAMHostname" -MaximumRedirection 0 -ErrorAction Ignore).Headers.Location
                    $APIAuthUrl = "https://$($IdentityTenantUri.Host)/oauth2/platformtoken"
                    $postBody = "grant_type=client_credentials&client_id=$([System.Web.HttpUtility]::UrlEncode($APICred.Username))&client_secret=$([System.Web.HttpUtility]::UrlEncode($APICred.Password))"
                    $contentType = "application/x-www-form-urlencoded"
                }
                catch {
                    Invoke-ParseFailureResponse -Component $App -ErrorRecord $_ -Message "Failed to authenticate to [$App] API, there was a problem trying to locate the CyberArk Identity Shared Services tenant"
                    $APICred = $null
                    $postBody = $null
                    throw
                }
            }
            else {
                $APIAuthUrl = $PAMAuthLogonUrl
                $postBody = @{
                    concurrentSession = $true 
                    Username = $APICred.Username
                    Password = $APICred.Password
                } | ConvertTo-Json
                $contentType = "application/json"
            }
            Break
        }
        "EPM" {
            $APIAuthUrl = $EPMAuthLogonUrl
            $postBody = @{
                Username = $APICred.Username
                Password = $APICred.Password
                ApplicationID = "EPM LCD Lifecycle"
            } | ConvertTo-Json
            $contentType = "application/json"
            Break
        }
    }
    
    try {
        $result = Invoke-RestMethod -Method Post -Uri $APIAuthUrl -Body $postBody -ContentType $contentType
        Write-Log -Type INF -Message "Successfully authenticated to [$App] API"
        if ($App -match "PAM" -and $PAMHostname -match "\.cyberark\.cloud$") {
            return "Bearer " + $result.access_token
        }
        else {
            return $result
        }
    }
    catch {
        Invoke-ParseFailureResponse -Component $App -ErrorRecord $_ -Message "Failed to authenticate to [$App] API"
        throw
    }
    finally {
        $APICred = $null
        $postBody = $null
    } 
}

Function Invoke-APILogoff {
    <#
    .SYNOPSIS
        Executes logoff from the CyberArk PAM API
    .DESCRIPTION
        Logoff from the CyberArk PAM API, removing the Vault session.  This as an explicit step is 
        important for immediately freeing the session, when API concurrency is in effect
    .EXAMPLE
        Invoke-APILogoff
    .NOTES
        The following script-level parameteres are used:
            - $PAMAuthLogoffUrl
            - $PAMSessionToken
            - $PAMHostname

        Author: Craig Geneske
    #>
    try {
        if ($PAMHostname -notmatch "\.cyberark\.cloud$") {
            Write-Log -Type INF -Message "Attempting to logoff PAM API..."
            Invoke-RestMethod -Method Post -Uri $PAMAuthLogoffUrl -Headers @{ Authorization = $PAMSessionToken} *> $null
            Write-Log -Type INF -Message "PAM API logoff was successful"
        }
    } 
    catch {
        Write-Log -Type WRN -Message "Unable to logoff PAM API - $($_.Exception.Message)"
    }
} 

Function Invoke-EPMRestMethod {
    <#
    .SYNOPSIS
        Executes Invoke-RestMethod against the EPM API with throttle handling 
    .DESCRIPTION
        Executes Invoke-RestMethod against the EPM API.  When throttling has been detected, will
        suspend and retry the API call until a success or unexpected failure has been received 
    .PARAMETER Parameters
        A Hashtable containing all of the desired Invoke-RestMethod parameters and their values
    .EXAMPLE
        Invoke-EPMRestMethod -Parameters $ht
    .NOTES
        Author: Craig Geneske
    #>
    Param(
        [hashtable]$Parameters
    )
    $retryLimit = 20 #5 Minutes
    $retryCount = 0
    while ($retryCount -le $retryLimit) {
        try {
            $result = Invoke-RestMethod @Parameters
            return $result
        }
        catch {
            if ($_.ErrorDetails.Message -match "too many calls") {
                $retryCount++
                if ($retryCount -le $retryLimit) {
                    Write-Log -Type WRN -Message "EPM API throttling detected, attempting retry [$retryCount] of [$retryLimit] in 15 seconds..."
                    Start-Sleep -Seconds 15
                }
            }
            else {
                throw
            }
        }
    }
    throw "EPM API throttle retry limit has been reached"
}

Function Invoke-PAMRestMethod {
    <#
    .SYNOPSIS
        Executes Invoke-RestMethod against the PAM API with re-authentication handling 
    .DESCRIPTION
        Executes Invoke-RestMethod against the PAM API.  When an expired session/token has 
        been detected, will attempt to re-authenticate and retry.  If any other exception is
        caught, it will be re-thrown.
    .PARAMETER Parameters
        A Hashtable containing all of the desired Invoke-RestMethod parameters (authorization header optional)
    .EXAMPLE
        Invoke-PAMRestMethod -Parameters $ht
    .NOTES
        Author: Craig Geneske
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Parameters
    )
    $authRetryLimit = 3
    $authRetryCount = 0
    while ($authRetryCount -le $authRetryLimit) {
        try {
            $result = Invoke-RestMethod @Parameters
            return $result
        }
        catch {
            if ($_.ErrorDetails.Message -match "The session token is missing, invalid or expired" -or `
                $_.ErrorDetails.Message -match "User was automatically logged off from Vault") {
                    $authRetryCount++
                    Write-Log -Type WRN -Message "PAM Session token has expired"
                    Set-Variable -Scope Script -Name PAMSessionToken -Value $(Invoke-APIAuthentication -App PAM)
                    $Parameters['Headers']['Authorization'] = $PAMSessionToken
            }
            else {
                throw
            }
        }
    }
    throw "PAM API maximum re-authentication attempts has been reached"
}

Function Get-PAMActiveLCDPlatforms {
    <#
    .SYNOPSIS
        Gets all Active LCD derived platforms from PAM.
    .DESCRIPTION
        Gets all Active LCD derived platforms from PAM, filtered further via optionally supplied regex, and returns all platform IDs in a list of string.
    .EXAMPLE
        Get-PAMLCDPlatforms
    .NOTES
        The following script-level variables are used:
            - $PAMPlatformsUrl
            - $PAMSessionToken
            - $LCDPlatformSearchRegex
            - $PAMSessionToken

        Author: Craig Geneske
    #>
    $result = $null
    [List[PSCustomObject]]$platformList = @()
    $finalUrl = $PAMPlatformsUrl + "?Active=True"

    try {
        Write-Log -Type INF -Message "Getting all active LCD platforms from PAM..."
        $paramsHt = @{
            Method = "Get"
            Uri = $finalUrl
            ContentType = "application/json"
            Headers = @{ Authorization = $PAMSessionToken }
        }
        $result = Invoke-PAMRestMethod -Parameters $paramsHt
        foreach ($platform in $result.Platforms) {
            if ($platform.general.platformBaseId -match "^WinLooselyDevice$" -and $SkipWindows) {
                continue
            }
            elseif ($platform.general.platformBaseId -match "^Unix$" -and $SkipMac) {
                continue
            }
            elseif ($platform.general.platformBaseId -match "^UnixLooselyDevice$" -and $SkipLinux) {
                continue
            }
            else {
                foreach ($pattern in $LCDPlatformSearchRegex) {
                    if ($platform.general.id -match $pattern -and `
                        ($platform.general.platformBaseId -match "^WinLooselyDevice$" -or `
                         $platform.general.platformBaseId -match "^Unix$" -or `
                         $platform.general.platformBaseId -match "^UnixLooselyDevice$")) {
                        $platformList.Add([PSCustomObject]@{
                            PlatformID = $platform.general.id
                            PlatformBaseID = $platform.general.platformBaseID
                        })
                    }
                }
            } 
        }
        if ($platformList) {
            Write-Log -Type INF -Message "[$($platformList.Count)] active LCD platforms have been found and will be used:"
            foreach ($platform in $platformList) {
                Write-Log -Type INF -Message "---> $($platform.PlatformID)"
            }
            return $platformList
        }
        else {
            throw "There are no active LCD platforms based on the defined criteria.  Please check Platform status in CyberArk and try again."
        }
    }
    catch {
        Invoke-ParseFailureResponse -Component "PAM" -ErrorRecord $_ -Message "Failed to get LCD derived platforms"
        throw
    }
}

Function Get-PAMLCDAccounts {
    <#
    .SYNOPSIS
        Gets all accounts that are associated with one of the platforms in the input list.
    .DESCRIPTION
        Gets all accounts that are associated with one of the platforms provided in the input list, against an optional safe
        search list, returning a list of accounts, and Safe Pool levels.
    .PARAMETER LCDPlatformList
        The list of LCD platforms for identifying account candidates
    .EXAMPLE
        Get-PAMLCDAccounts -LCDPlatformList "WinLooselyDevice","_CYBR_WindowsLooselyDevice"
    .NOTES
        The following script-level variables are used:
            - $PAMAccountsUrl
            - $PAMSessionToken
            - $SafeSearchList
            - $OnboardingSafesWin
            - $OnBoaridngSafeMac

        Author: Craig Geneske
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [List[PSCustomObject]]$LCDPlatformList
    )

    [List[PSCustomObject]]$PAMAccountsList = @()
    $safePool = @{
        Windows = @{}
        MacOS = @{}
        Linux = @{}
    }
    $result = $null
    $pageCounter = 0
    $accountsCounter = 0
    $candidatesCounter = 0

    foreach ($safe in $OnboardingSafesWin) {
        $data = $safePool['Windows'][$safe]
        if ($data -eq 0) {
            continue
        }
        else {
            $safePool['Windows'][$safe] = 0
        }
    }

    foreach ($safe in $OnboardingSafesMac) {
        $data = $safePool['MacOS'][$safe]
        if ($data -eq 0) {
            continue
        }
        else {
            $safePool['MacOS'][$safe] = 0
        }
    }

    foreach ($safe in $OnboardingSafesLinux) {
        $data = $safePool['Linux'][$safe]
        if ($data -eq 0) {
            continue
        }
        else {
            $safePool['Linux'][$safe] = 0
        }
    }
    
    try {
        $timer = [Diagnostics.Stopwatch]::StartNew()
        foreach ($safe in $SafeSearchList) {
            $accountsUrl = $PAMAccountsUrl
            if (![string]::IsNullOrEmpty($safe)) {
                Write-Log -Type INF -Message "Getting LCD accounts in safe [$safe] (this may take a while)..."
                $accountsUrl = $accountsUrl + "?limit=$($PAMPageSize)&filter=safeName eq $([System.Web.HttpUtility]::UrlEncode($safe))"
            }
            else {
                Write-Log -Type INF -Message "Getting LCD accounts in all safes (this may take a while)..."
                $accountsUrl = $accountsUrl + "?limit=$($PAMPageSize)"
            }
            do {
                $result = $null
                $paramsHt = @{
                    Method = "Get"
                    Uri = $accountsUrl
                    ContentType = "application/json"
                    Headers = @{ Authorization = $PAMSessionToken }
                }
                $result = Invoke-PAMRestMethod -Parameters $paramsHt
                foreach ($account in $result.value) {
                    if ($safePool['Windows'][$account.safeName] -ge 0) {
                        $safePool['Windows'][$account.safeName]++
                    }
                    if ($safePool['MacOS'][$account.safeName] -ge 0) {
                        $safePool['MacOS'][$account.safeName]++
                    }
                    if ($safePool['Linux'][$account.safeName] -ge 0) {
                        $safePool['Linux'][$account.safeName]++
                    }
                    $accountsCounter++
                    $isCandidate = $false
                    $sourcePlatform = $null
                    foreach ($platform in $LCDPlatformList) {
                        if ($account.platformId -eq $platform.PlatformID) {
                            $isCandidate = $true
                            $sourcePlatform = $platform.PlatformBaseID
                            break
                        }
                    }
                    if ($isCandidate) {
                        $candidatesCounter++                      
                        $PAMAccountsList.Add([PSCustomObject]@{
                            Instance = [PSCustomObject]@{
                                UserName = $account.userName
                                Address = $account.address
                                Id = $account.id
                                LastModified = [DateTimeOffset]::FromUnixTimeSeconds($account.categoryModificationTime).UtcDateTime
                            }
                            PlatformBaseID = $sourcePlatform
                        })
                    }
                }
                if ($result.nextLink) {
                    $pagecounter++
                    $accountsUrl = $PAMBaseURI + "/" + $result.nextLink
                }
                if ($timer.elapsed.totalseconds -ge $StatusPingInterval) {
                    Write-Log -Type INF -Message "---> Status Ping: [$accountsCounter] accounts processed in [$pageCounter] pages so far - [$candidatesCounter] LCD accounts and counting"
                    $timer.Restart()
                }
            } 
            while ($result.nextLink)
        }
        Write-Log -Type INF -Message "PAM account search complete, [$candidatesCounter] LCD accounts found out of [$accountsCounter] total accounts"
        if ($accountsCounter -eq 20000) {
            Write-Log -Type WRN -Message "An exact result of 20,000 accounts may indicate a limitation in your current MaxDisplayedRecords setting which may disrupt this utility!"
            Write-Log -Type WRN -Message "Please see this utility's README at https://github.com/cgeneske/CyberArkEPMLCDLifecycle for more information"
        }
    }
    catch {
        Invoke-ParseFailureResponse -Component "PAM" -ErrorRecord $_ -Message "Failed to get PAM accounts associated with an active LCD platform"
        throw
    }
    finally {
        $timer.Reset()
        $timer = $null
    }
    if ($accountsCounter -eq 0) {
        Write-Log -Type WRN -Message "No accounts were found in PAM!  If this is unexpected, ensure your PAM API user has been granted the required privileges to the Safes that are in scope for LCD"
    }
    Compare-ChangeFactorAndUpdate -PropertyName PAMAccounts -Threshold $SafetyThresholdPAM -Value $PAMAccountsList.Count
    return $PAMAccountsList, $safePool
}

Function Get-EPMComputers {
    <#
    .SYNOPSIS
        Gets all computers from the designated EPM sets and qualifies them (FQDN).
    .DESCRIPTION
        Gets all computers from the designated EPM sets, qualifies them (FQDN), and returns
        both the list of qualifed endpoints as well as the ignore list (as per configuration).
    .PARAMETER SessionToken
        Session token that was received from the EPM Logon endpoint
    .PARAMETER ManagerURL
        The EPM Server URL used for CRUD APIs as received from the EPM Logon endpoint
    .EXAMPLE
        $EPMEndpoints, $ignoreList = Get-EPMComputers -SessionToken "Caz2QE%2b%2b8uVbTecoGMBa1Dxr7h..." -ManagerURL "https://na123.epm.cyberark.com"
    .NOTES
        The following script-level variables are used:
            - $EndpointDomainNames
            - $EndpointHostnameExclusionsRegex
            - $EPMSetIDs
            - $EPMSetsListUrl
            - $EPMComputersUrl
            - $ValidateDomainNamesDNS
            - $SkipIfNotInDNS
            - $MaximumDNSFailures

        Author: Craig Geneske
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [string]$SessionToken,

        [Parameter(Mandatory = $true)]
        [string]$ManagerURL
    )

    $confirmedSets = @()
    [List[PSCustomObject]]$EPMComputerList = @()
    [List[PSCustomObject]]$IgnoreList = @()
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $pageCounter = 0
    $computersCounter = 0
    $result = $null

    try{
        Write-Log -Type INF -Message "Getting all EPM Sets..."
        $ParamsHt = @{
            Method = "Get"
            Uri = ($ManagerURL + $EPMSetsListUrl)
            Headers = @{Authorization = "basic $($SessionToken)"}
            ContentType = "application/json"
        }
        $result = Invoke-EPMRestMethod -Parameters $ParamsHt
        Write-Log -Type INF -Message "[$($result.SetsCount)] Sets found"
        if ($EPMSetIDs) {
            Write-Log -Type INF -Message "Confirming provided Set ID(s)..."
            foreach ($providedSet in $EPMSetIDs) {
                $matchingSet = $null
                $isValid = $false
                foreach ($actualSet in $result.Sets) {
                    if ($actualSet.Id -eq $providedSet) {
                        $isValid = $true
                        $matchingSet = $actualSet
                        break
                    }
                }
                if ($isValid) {
                    Write-Log -Type INF -Message "---> Set [$($actualSet.Name) {$($actualSet.Id)}] is confirmed and will be used"
                    $confirmedSets += $matchingSet
                }
                else {
                    Write-Log -Type WRN -Message "---> Set ID [$providedSet] is not confirmed and will be skipped.  Please verify your EPM API login has access to this set"
                }
            }
        }
        else {
            Write-Log -Type INF -Message "Using all Sets!"
            foreach ($set in $result.Sets) {
                Write-Log -Type INF -Message "---> Set [$($set.Name) {$($set.Id)}] is confirmed and will be used"
                $confirmedSets += $set
            }
        }
        Write-Log -Type INF -Message "Getting all EPM Computers (this may take a while)..."
        foreach ($set in $confirmedSets) {
            Write-Log -Type INF -Message "---> Getting computers for set [$($set.Name) {$($set.Id)}]..."
            $computersUri = ($ManagerURL + ($EPMComputersUrl -f $set.Id) + "?limit=$EPMPageSize")
            $offset = 0
            do {
                if ($timer.elapsed.totalseconds -ge $StatusPingInterval) {
                    Write-Log -Type INF -Message "------> Status Ping: [$computersCounter] computers processed in [$pageCounter] pages so far"
                    $timer.Restart()
                }
                $result = $null
                $paramsHt = $null
                $paramsHt = @{
                    Method = "Get"
                    Uri = $computersUri
                    Headers = @{Authorization = "basic $($SessionToken)"}
                    ContentType = "application/json"
                }
                $result = Invoke-EPMRestMethod -Parameters $ParamsHt
                foreach ($computer in $result.Computers) {  
                    #At present, EPM API returns a Platform of "Unknown" for Linux computers.  
                    #Transforming these to a Platform of "Linux". 
                    if ($computer.Platform -eq "Unknown") {
                        $computer.Platform = "Linux"
                    }

                    if (($computer.Platform -eq "MacOS" -and $SkipMac) -or `
                        ($computer.Platform -eq "Windows" -and $SkipWindows) -or `
                        ($computer.Platform -eq "Linux" -and $SkipLinux)) {
                            $ignoreList.Add($computer)
                            Add-Content -Path $ReportFilePath -Value "N/A,$($computer.ComputerName),$($computer.Platform),Inventory,Skipped,Lifecycle for this platform is disabled per the run configuration" -ErrorAction SilentlyContinue *> $null
                            continue
                    }

                    $computersCounter++
                    $EPMComputerList.Add($computer)
                }
                if ($result.Computers.Count -eq $EPMPageSize) {
                    $offset += $EPMPageSize
                    $computersUri = ($ManagerURL + ($EPMComputersUrl -f $set.Id) + "?limit=$EPMPageSize&offset=$offset")
                }
                $pageCounter++
            }
            while ($result.Computers.Count -eq $EPMPageSize)
        }
        Write-Log -Type INF -Message "Retrieved [$($EPMComputerList.Count)] EPM Computers"
    }
    catch {
        Invoke-ParseFailureResponse -Component "EPM" -ErrorRecord $_ -Message "Failed to get all EPM computers"
        throw
    }
    finally {
        $timer.Reset()
        $timer = $null
    }

    [List[PSCustomObject]]$qualifiedComps = @()
    Write-Log -Type INF -Message "Qualifying EPM computers with domain names provided and deduplicating the results (this may take a while)..."
    foreach($comp in $EPMComputerList) {
        $finalSuffix = ""
        if ($ValidateDomainNamesDNS -and $comp.Platform -eq "Windows") {
            $countDNSIssues = 0
            $dnsNameFound = $false
            foreach ($domainName in $EndpointDomainNames) {
                try {
                    Resolve-DnsName -Name ($comp.ComputerName + "." + $domainName) -ErrorAction Stop *> $null
                    $finalSuffix = "." + $domainName
                    $dnsNameFound = $true
                    break
                }
                catch {
                    if ($_.Exception.Message -match "DNS name does not exist") {
                        $Error.Clear()
                        continue
                    }
                    else {
                        if ($countDNSIssues -ge $MaximumDNSFailures) {
                            Write-Log -Type ERR -Message "Maximum general DNS failures reached [$MaximumDNSFailures]."
                            throw
                        }
                        Write-Log -Type WRN -Message "Potential issue with DNS resolution, skipping candidacy for [$($comp.ComputerName)] --> $($_.Exception.Message)"
                        Add-Content -Path $ReportFilePath -Value "N/A,$($comp.ComputerName),$($comp.Platform),Inventory,Skipped,Issue with DNS resolution --> $($_.Exception.Message.Replace(",",";"))" -ErrorAction SilentlyContinue *> $null
                        $countDNSIssues++
                        $ignoreList.Add($comp)
                        $Error.Clear()
                        continue
                    }
                }
            }
            if (!$dnsNameFound) {
                if ($SkipIfNotInDNS) {
                    Write-Log -Type WRN -Message "Domain name not found for [$($comp.ComputerName)], skipping candidacy per the configuration"
                    Add-Content -Path $ReportFilePath -Value "N/A,$($comp.ComputerName),$($comp.Platform),Inventory,Skipped,DNS domain name not found - skipping per run configuration" -ErrorAction SilentlyContinue *> $null
                    $ignoreList.Add($comp)
                    continue
                }
            }
        }
        elseif ($EndpointDomainNames -and $comp.Platform -eq "Windows") {
            $finalSuffix = "." + $EndpointDomainNames
        }
        
        $comp.ComputerName = $comp.ComputerName + $finalSuffix

        if ($EndpointHostnameExclusionsRegex) {
            $matchFound = $false
            foreach ($pattern in $EndpointHostnameExclusionsRegex) {
                if ($comp.ComputerName -match $pattern) {
                    $matchFound = $true
                    $ignoreList.Add($comp)
                    Add-Content -Path $ReportFilePath -Value "N/A,$($comp.ComputerName),$($comp.Platform),Inventory,Skipped,The computer name in EPM matches a hostname exclusion pattern" -ErrorAction SilentlyContinue *> $null
                    break
                }
            }
            if ($matchFound) {
                continue
            }
        }

        $qualifiedComps.Add([PSCustomObject]@{
            ComputerName = $comp.ComputerName
            Platform = $comp.Platform
        })
        
    }
    $qualifiedComps = $qualifiedComps | Sort-Object -Property ComputerName | Get-Unique -AsString
    Write-Log -Type INF -Message "EPM computer qualification and deduplication complet, unique EPM computer total is [$($qualifiedComps.Count)]"
    Compare-ChangeFactorAndUpdate -PropertyName EPMComputers -Threshold $SafetyThresholdEPM -Value $qualifiedComps.Count
    return $qualifiedComps, $ignoreList
}

Function Add-PAMAccountsBulk {
    <#
    .SYNOPSIS
        Adds accounts to PAM via API as a bulk upload job.
    .DESCRIPTION
        Adds accounts to PAM via API as a bulk upload job.
    .PARAMETER AccountList
        List of PSObject representing the return value of Get-OnBoardingCandidates (Members: UserName, Address, Platform)
    .PARAMETER SafePool
        A hashtable containing the onboarding safes for Windows and MacOS and their current quantities
    .EXAMPLE
        Add-PAMAccountsBulk -AccountList $onboardCandidates -SafePool $SafePool
    .NOTES
        The following script-level variables are used:
            - $OnboardingPlatformIdWin
            - $OnboardingPlatformIdMac
            - $PAMAccountsUrl
            - $PAMSessionToken
            - $WarnSafeObjects
            - $MaxSafeObjects

        Author: Craig Geneske
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [List[PSCustomObject]]$AccountList,

        [Parameter(Mandatory = $true)]
        [hashtable]$SafePool
    )

    Write-Log -Type INF -Message "##########################################"
    Write-Log -Type INF -Message "#                                        #"
    Write-Log -Type INF -Message "# BEGIN ONBOARDING ALL CANDIDATES TO PAM #"
    Write-Log -Type INF -Message "#                                        #"
    Write-Log -Type INF -Message "##########################################"
    Write-Log -Type INF -Message "Constructing bulk onboarding job chunks..."
    $haveWarned = $false
    [List[PSCustomObject]]$jobChunks = @()
    $tempList = [PSCustomObject]@{
        accountsList = [List[PSCustomObject]]@()
    }
    $count = 0
    foreach ($account in $AccountList) {
        $safeName = ($SafePool[$account.Platform].GetEnumerator() | Sort-Object -Property "Value" | Select-Object -First 1).Key
        if ($SafePool[$account.Platform][$safeName] -ge $WarnSafeObjects -and !$haveWarned) {
            Write-Log -Type WRN -Message "All safes in the safe pool would reach or exceed the warning threshold of [$WarnSafeObjects] `
                                          objects with this onboarding activity.  Please add more safes to the safe pool!".Replace("`n","")
            $haveWarned = $true
        }
        if ($SafePool[$account.Platform][$safeName] -ge $MaxSafeObjects) {
            Write-Log -Type ERR -Message "All safes in the safe pool would reach or exceed the maximum threshold of [$MaxSafeObjects] `
                                          objects, unable to commit onboarding.  Please add more safes to the safe pool!".Replace("`n","")
            throw
        }
        switch ($account.Platform) {
            "Windows" { $platformId = $OnboardingPlatformIdWin; Break }
            "MacOS" { $platformId = $onboardingPlatformIdMac; Break }
            "Linux" { $platformId = $OnboardingPlatformIdLinux; Break }
            default { throw "Platform not implemented" }
        }
        if ($count++ -eq $BulkChunkLimit) {
            $jobChunks.Add($tempList)
            $tempList = [PSCustomObject]@{
                accountsList = [List[PSCustomObject]]@()
            }
            $count = 1
        }
        $tempList.accountsList.Add([PSCustomObject]@{
            userName = $account.UserName
            address = $account.Address
            secretType = "password"
            safeName = $safename
            platformId = $platformId
        })
        #If Windows, MacOS, and/or Linux safe pools contain the same Safe, we need to increment the account counter in all to keep onboarding distribution even
        foreach ($safeGroup in $SafePool.GetEnumerator()) {
            if ($safeGroup.Value[$safeName] -ge 0) {
                $safeGroup.Value[$safeName]++
            }
        }
    }
    $jobChunks.Add($tempList)

    [List[PSCustomObject]]$jobChunksJson = @()
    foreach ($chunk in $jobChunks) {
        $jobChunksJson.Add([PSCustomObject]@{
            Total = $chunk.accountsList.Count
            Chunk = $($chunk | ConvertTo-Json -Compress)
        })
    }
    Write-Log -Type INF -Message "[$($jobChunksJson.Count)] onboarding job chunks created"

    $successTotal = 0
    $jobIndex = 1
    foreach ($job in $jobChunksJson) {
        try {
            Write-Log -Type INF -Message "Submitting bulk onboarding job [$jobIndex] of [$($jobChunksJson.Count)] to PAM..."
            $paramsHt = @{
                Method = "Post"
                Uri = $PAMBulkAccountsUrl
                Body = $job.Chunk
                ContentType = "application/json"
                Headers = @{ Authorization = $PAMSessionToken }
            }
            $jobId = Invoke-PAMRestMethod -Parameters $paramsHt
            Write-Log -Type INF -Message "Bulk onboarding job [$jobIndex] of [$($jobChunksJson.Count)] has been successfully submitted to PAM"
        }
        catch {
            Invoke-ParseFailureResponse -Component PAM -ErrorRecord $_ -Message "Failed to submit bulk onboarding job [$jobIndex] of [$($jobChunksJson.Count)] to PAM"
            $jobIndex++
            continue
        }

        Write-Log -Type INF -Message "Checking bulk onboarding job status for job [$jobIndex] of [$($jobChunksJson.Count)] on [$StatusPingInterval] second intervals..."
        $shouldRetry = $true
        $inProgLogged = $false
        do {
            Start-Sleep -Seconds $StatusPingInterval
            try{
                $paramsHt = @{
                    Method = "Get"
                    Uri = ($PAMBulkAccountsUrl + "/$jobId")
                    ContentType = "application/json"
                    Headers = @{ Authorization = $PAMSessionToken }
                }
                $jobStatus = Invoke-PAMRestMethod -Parameters $paramsHt
                switch ($jobStatus.Status) {
                    "Pending" {
                        Write-Log -Type INF -Message "Bulk onboarding job [$jobIndex] of [$($jobChunksJson.Count)] is Pending"
                        Break
                    }
                    "inProgress" {
                        if (!$inProgLogged) {
                            Write-Log -Type INF -Message "Bulk onboarding job [$jobIndex] of [$($jobChunksJson.Count)] is In-Progress:"
                            $inProgLogged = $true
                        }
                        $success = [int]$jobStatus.SucceededItems.Total
                        $failed = [int]$jobStatus.FailedItems.Total
                        $subTotal = $([int]$jobStatus.SucceededItems.Total + [int]$jobStatus.FailedItems.Total) 
                        $completed = [math]::Round((([int]$jobStatus.SucceededItems.Total + [int]$jobStatus.FailedItems.Total) / $job.Total) * 100)
                        Write-Log -Type INF -Message "---> Job [$jobIndex] of [$($jobChunksJson.Count)] / [$success] Succeeded / [$failed] Failed / [$subTotal of $($job.Total) ($completed%)] Complete"
                        Break
                    }
                    "completed" {
                        Write-Log -Type INF -Message "Bulk onboarding job [$jobIndex] of [$($jobChunksJson.Count)] has completed successfully"
                        $shouldRetry = $false
                        Break
                    }
                    "completedWithErrors" {
                        Write-Log -Type WRN -Message "Bulk onboarding job [$jobIndex] of [$($jobChunksJson.Count)] has completed with some errors"
                        $shouldRetry = $false
                        Break
                    }
                    "failed" {
                        Write-Log -Type ERR -Message "Bulk onboarding job [$jobIndex] of [$($jobChunksJson.Count)] has failed --> $($jobStatus.Result.Error)"
                        $shouldRetry = $false
                        Break
                    }
                    default { throw "Unexpected value [$($jobStatus.Status)] while waiting for the onboarding job to complete" }
                }
            }
            catch {
                $shouldRetry = $false
                Invoke-ParseFailureResponse -Component PAM -ErrorRecord $_ -Message "Failed to obtain bulk onboarding job status for job [$jobIndex] of [$($jobChunksJson.Count)], committing known progress and proceeding"
                if ($_.Exception.Message -match "PAM API maximum re-authentication attempts has been reached") {
                    throw
                }
            }
            finally {
                if (!$shouldRetry) {
                    if ($jobStatus.Status -match "^failed$") {
                        foreach ($account in $AccountList) {
                            Add-Content -Path $ReportFilePath -Value "$($account.Username),$($account.Address),$($account.Platform),Onboarding,Failed,$($jobStatus.Result.Error.Replace(",", " "))" -ErrorAction SilentlyContinue *> $null
                        }
                    }
                    else {
                        foreach ($account in $jobStatus.SucceededItems.Items) {
                            switch ($account.PlatformId) {
                                $onboardingPlatformIdWin { $platform = "Windows"; Break }
                                $onboardingPlatformIdMac { $platform = "MacOS"; Break }
                            }
                            Add-Content -Path $ReportFilePath -Value "$($account.Username),$($account.Address),$platform,Onboarding,Success," -ErrorAction SilentlyContinue *> $null
                            Update-DatFile -PropertyName PAMAccounts -Value 1 -Append
                            $successTotal++
                        }
                        foreach ($account in $jobStatus.FailedItems.Items) {
                            switch ($account.PlatformId) {
                                $onboardingPlatformIdWin { $platform = "Windows"; Break }
                                $onboardingPlatformIdMac { $platform = "MacOS"; Break }
                            }
                            Add-Content -Path $ReportFilePath -Value "$($account.Username),$($account.Address),$platform,Onboarding,Failed,$($account.error.Replace(",", " "))" -ErrorAction SilentlyContinue *> $null
                        }
                    }
                } 
            }
        } while ($shouldRetry)
        $jobIndex++
        $jobId = $null
        $jobStatus = $null
    }
    Write-Log -Type INF -Message "##############################"
    Write-Log -Type INF -Message "#                            #"
    Write-Log -Type INF -Message "# ONBOARDING TO PAM COMPLETE #"
    Write-Log -Type INF -Message "#                            #"
    Write-Log -Type INF -Message "##############################"
    Write-Log -Type INF -Message "[$successTotal] of [$($AccountList.Count)] accounts were successfully onboarded"
}

Function Remove-PAMAccounts {
    <#
    .SYNOPSIS
        Removes accounts from PAM via API.
    .DESCRIPTION
        Removes accounts from PAM via API.
    .PARAMETER AccountList
       List of PSObject representing the return value of Get-OffBoardCandidates (Members: "Get Accounts" PAM API deserialized object)
    .EXAMPLE
        Remove-PAMAccounts -AccountList $offboardCandidates
    .NOTES
        The following script-level variables are used:
        - $PAMAccountsUrl
        - $PAMSessionToken

        Author: Craig Geneske
    #>
    Param(       
        [Parameter(Mandatory = $true)]
        [List[PSCustomObject]]$AccountList
    )

    $actionedTotal = 0
    $successTotal = 0
    Write-Log -Type INF -Message "#############################################"
    Write-Log -Type INF -Message "#                                           #"
    Write-Log -Type INF -Message "# BEGIN OFFBOARDING ALL CANDIDATES FROM PAM #"
    Write-Log -Type INF -Message "#                                           #"
    Write-Log -Type INF -Message "#############################################"
    foreach ($account in $AccountList) {
        try {
            Write-Log -Type INF -Message "Processing [$($actionedTotal + 1)] of [$($AccountList.Count)] ($([math]::Round(($actionedTotal + 1) / $AccountList.Count * 100))%) - Offboarding account [$($account.id) - $($account.UserName)@$($account.Address)] from PAM..."
            $paramsHt = @{
                Method = "Delete"
                Uri = ($PAMAccountsUrl + "/$($account.id)/")
                ContentType = "application/json"
                Headers = @{ Authorization = $PAMSessionToken }
            }
            Invoke-PAMRestMethod -Parameters $paramsHt *> $null
            Add-Content -Path $ReportFilePath -Value "$($account.UserName),$($account.Address),$($account.CompPlatform),Offboarding,Success" -ErrorAction SilentlyContinue *> $null
            Update-DatFile -PropertyName PAMAccounts -Value -1 -Append
            $successTotal++
            $actionedTotal++
        }
        catch {
            Invoke-ParseFailureResponse -Component PAM -ErrorRecord $_ -Message "Failed to offboard account [$($account.UserName)@$($account.Address)] from PAM"
            Add-Content -Path $ReportFilePath -Value "$($account.Username),$($account.Address),$($account.CompPlatform),Offboarding,Failed,$($_.ErrorDetails.Message.Replace(","," "))" -ErrorAction SilentlyContinue *> $null
            if ($_.Exception.Message -match "PAM API maximum re-authentication attempts has been reached") {
                break
            }
            else {
                $Error.Clear()
                $actionedTotal++
            }
        }
    }
    Write-Log -Type INF -Message "#################################"
    Write-Log -Type INF -Message "#                               #"
    Write-Log -Type INF -Message "# OFFBOARDING FROM PAM COMPLETE #"
    Write-Log -Type INF -Message "#                               #"
    Write-Log -Type INF -Message "#################################"
    Write-Log -Type INF -Message "[$successTotal] of [$($AccountList.Count)] accounts were successfully offboarded"
}

Function Confirm-ScriptVariables {
    <#
    .SYNOPSIS
        Confirms state and value validity for user-defined script variables.
    .DESCRIPTION
        Confirms state and value validity for user-defined script variables.  Throws an exception if 
        any variables are determined to be incorrectly set.
    .EXAMPLE
        Confirm-ScriptVariables
    .NOTES
        Author: Craig Geneske
    #>

    Write-Log -Type INF -Message "Validating Script Variables..."

    if ($ValidateDomainNamesDNS) {
        if (!$EndpointDomainNames) {
            Set-Variable -Name "EndpointDomainNames" -Scope Script -Value $((Get-DNSClientGlobalSetting).SuffixSearchList)
            if (!$EndpointDomainNames) {
                Write-Log -Type ERR -Message "Ambiguous operation.  ValidateDomainNamesDNS is set, but no EndpointDomainNames are specified, and DNS Client Suffix Search List is Empty"
                throw
            }
        }
    
    }
    else {
        if (!($EndpointDomainNames.Count -eq 1 -or [String]::IsNullOrEmpty($EndpointDomainNames))) {
            Write-Log -Type ERR -Message "Ambiguous operation.  ValidateDomainNamesDNS is not set and more than one EndpointDomainNames are defined"
            throw
        }
    }

    try {
        foreach ($pattern in $LCDPlatformSearchRegex) {
            [regex]::Match("", $pattern) *> $null
        }
    }
    catch {
        Write-Log -Type ERR -Message "Problem identified in LCDPlatformSearchRegex, regex pattern [$pattern] failed validation with the following result --> $($_.Exception.InnerException.Message)"
        throw
    }

    if ($APIUserSource -isnot [APIUserSource]) {
        Write-Log -Type ERR -Message "APIUserSource is not set to a valid value, please correct this and try again"
        throw
    }

    if ($APIUserSource -eq [APIUserSource]::CyberArkCCP) {
        if ($CCPAuthType -isnot [CCPAuthType]) {
            Write-Log -Type ERR -Message "CCPAuthType is not set to a valid value, please correct this and try again"
            throw 
        }
    }

    if (!$SafeSearchList) {
        Set-Variable -Name "SafeSearchlist" -Scope Script -Value ""
    }

    if ($EPMRegion) {
        $regionList = @('US', 'AU', 'CA', 'EU', 'IN', 'IT', 'JP', 'SG', 'UK', 'BETA')
        $validRegion = $false
        foreach ($region in $regionList) {
            if ($EPMRegion -match "^$region$") {
                if ($region -match "^US$") {
                    Set-Variable -Name "EPMAuthLogonUrl" -Scope Script -value ($EPMAuthLogonUrl -f "login")
                }
                else {
                    Set-Variable -Name "EPMAuthLogonUrl" -Scope Script -value ($EPMAuthLogonUrl -f $region.ToLower())
                }
                $validRegion = $true
                break
            }
        }
        if (!$validRegion) {
            Write-Log -Type ERR -Message "EPMRegion is not set to a valid value, you must specify one of the following: US, AU, CA, EU, IN, IT, JP, SG, UK, or BETA"
            throw
        }
    }
    else {
        Write-Log -Type ERR -Message "EPMRegion is empty, you must specify one of the following: US, AU, CA, EU, IN, IT, JP, SG, UK, or BETA"
        throw
    }
    
    if (!$EnableSafety) {
        Write-Log -Type WRN -Message "SAFETY IS DISABLED!  DAT file will be updated with values from this execution.  It is not recommended to remain in this state indefinitely!"
    }

    if ($SkipWindows) {
        Write-Log -Type WRN -Message "Windows-based PAM Accounts (LCD) and EPM Endpoints will be skipped per configuration"
    }

    if ($SkipMac) {
        Write-Log -Type WRN -Message "Mac-based PAM Accounts (LCD) and EPM Endpoints will be skipped per configuration"
    }

    if ($SkipLinux) {
        Write-Log -Type WRN -Message "Linux-based PAM Accounts (LCD) and EPM Endpoints will be skipped per configuration"
    }

    if ($SkipOnBoarding) {
        Write-Log -Type WRN -Message "Onboarding activity will be skipped per configuration"
    }

    if ($SkipOffBoarding) {
        Write-Log -Type WRN -Message "Offboarding activity will be skipped per configuration"
    }

    if ($EndpointHostnameExclusionsRegex) {
        try {
            foreach ($pattern in $EndpointHostnameExclusionsRegex) {
                [regex]::Match("", $pattern) *> $null
            }
        }
        catch {
            Write-Log -Type ERR -Message "Problem identified in EndpointHostnameExclusionsRegex, regex pattern [$pattern] failed validation with the following result --> $($_.Exception.InnerException.Message)"
            throw
        }
    }

    if ($OffboardingDelayDays -isnot [Int]) {
        Write-Log -Type ERR -Message "OffboardingDelayDays is not set to a numerical (integer) value."
        throw
    }

    Write-Log -Type INF -Message "Script variables have been successfully validated"
}

Function Compare-ChangeFactorAndUpdate {
     <#
    .SYNOPSIS
        Compares the input value against the DAT file's value to determine if the change factor exceeds the allowed threshold
    .DESCRIPTION
        Compares the input value against the DAT file's value to determine if the change factor exceeds the allowed threshold.
        If within threshold, or safety is disabled, the DAT file is also updated.
    .PARAMETER PropertyName
        Name of the property within the DAT file to look for
    .PARAMETER Threshold
        The threshold to be used in the comparison
    .PARAMETER Value
        Value to use for comparison
    .EXAMPLE
        Compare-ChangeFactorAndUpdate -PropertyName "EPMComputers" -Threshold 0.10 -Value 123
    .NOTES
        The following script-level variables are used:
            - $DatFilePath
            - $EnableSafety
            - $SafetyTriggered
        Author: Craig Geneske
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("EPMComputers","PAMAccounts")]
        [string]$PropertyName,

        [Parameter(Mandatory = $true)]
        [double]$Threshold,
        
        [Parameter(Mandatory = $true)]
        [int]$Value
    )

    if ($enableSafety) {
        try{
            $datFile = Get-Content -Path $DatFilePath | ConvertFrom-Json
            if (!(Get-Member -InputObject $datfile -Name $PropertyName -MemberType Properties)) {
                throw "DAT file does not contain the [$PropertyName] property, consider deleting the DAT file and trying again in report-only mode"
            }
        }
        catch {
            Write-Log -Type ERR -Message "Something went wrong processing the DAT file --> $($_.Exception.Message)"
            throw
        }
        if($datFile.$PropertyName -ne -1 -and $datFile.$PropertyName -ne 0) {
            $changeFactor = [Math]::Abs($value - $datFile.$PropertyName) / $datfile.$PropertyName
            if ($changeFactor -ge $Threshold) {
                Set-Variable -Name SafetyTriggered -Scope Script -Value $true
                if ($ReportOnlyMode) {
                    Write-Log -Type WRN "There has been a change of [$($Value - $datFile.$PropertyName) ($([math]::Round($changeFactor * 100))%)] for [$PropertyName] and this will exceed the configured safety threshold of [$Threshold ($([math]::Round($Threshold * 100))%)] in production mode"
                    return
                }
                else {
                    Write-Log -Type ERR "There has been a change of [$($Value - $datFile.$PropertyName) ($([math]::Round($changeFactor * 100))%)] for [$PropertyName] and this exceeds the configured safety threshold of [$Threshold ($([math]::Round($Threshold * 100))%)]"
                    throw
                }
            }
        }
    }
    Update-DatFile -PropertyName $PropertyName -Value $Value
}

Function Update-DatFile {
      <#
    .SYNOPSIS
        Updates a named property in the dat file (JSON)
    .DESCRIPTION
        Updates a named property in the dat file (JSON)
    .PARAMETER PropertyName
        Name of the property within the dat file whose value needs updating
    .PARAMETER Value
        Value that the property should be updatd to
    .PARAMETER Append
        Whether the input Value should be added to the existing Value
    .EXAMPLE
        Update-DatFile -PropertyName "EPMComputers" -Value 123
    .NOTES
        The following script-level variables are used:
            - $DatFilePath

        Author: Craig Geneske
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("EPMComputers","PAMAccounts")]
        [string]$PropertyName,
        
        [Parameter(Mandatory = $true)]
        [int]$Value,

        [Parameter(Mandatory = $false)]
        [switch]$Append
    )
    
    try{
        $datFile = Get-Content -Path $DatFilePath | ConvertFrom-Json
        if (!(Get-Member -InputObject $datfile -Name $PropertyName -MemberType Properties)) {
            throw "Dat file does not contain the [$PropertyName] property, please delete the dat file and try again"
        }
        if ($Append) {
            $datFile.$PropertyName = [int]$datFile.$PropertyName + $Value
    
        }
        else {
            $datFile.$PropertyName = $Value
        }
        Set-Content -Path $DatFilePath -Value ($datFile | ConvertTo-Json)
    }
    catch {
        Write-Log -Type ERR -Message "Something went wrong processing the dat file --> $($_.Exception.Message)"
        throw
    }
}

Function Get-OnBoardingCandidates {
    <#
    .SYNOPSIS
        Determines all onboarding candidates based on accounts pre-existing in PAM and all existing EPM endpoints.
    .DESCRIPTION
        Determines all onboarding candidates based on accounts pre-existing in PAM and all existing EPM endpoints.
        Returns a List of PSObject containing the Username, Address, and Platform to be used for onboarding candidates
    .PARAMETER PAMAccounts
        A List of PSObject that represent the serialized results of a PAM "Get Accounts" API call
    .PARAMETER EPMEndpoints
        A List of PSObject that represents the serialized results of an EPM "Get Computers" API call (with qualified hostnames)
    .EXAMPLE
        $onboardCandidates = Get-OnBoardingCandidates -PAMAccounts $PAMAccounts -EPMEndpoints $EPMEndpoints
    .NOTES
        The following script-level variables are used:
        - $EndpointUserNamesWin
        - $EndpointUserNamesMac

        Author: Craig Geneske
    #>
    param (
        [Parameter(Mandatory = $false)]
        [List[PSCustomObject]]$PAMAccounts,

        [Parameter(Mandatory = $false)]
        [List[PSCustomObject]]$EPMEndpoints
    )

    [List[PSCustomObject]]$onboardCandidates = @()
    Write-Log -Type INF -Message "Determining onboarding candidates..."

    #Creating PAM Accounts Index
    $PAMAccountsIndex = @{}
    foreach ($account in $PAMAccounts) {
        $key = $account.Instance.("Address")
        $data = $PAMAccountsIndex[$key]
        if ($data -is [Collections.ArrayList]) {
            $data.add($account.Instance) > $null
        }
        elseif ($data) {
            $PAMAccountsIndex[$key] = [Collections.ArrayList]@($data, $account.Instance)
        }
        else {
            $PAMAccountsIndex[$key] = $account.Instance
        }
    }
    
    foreach ($comp in $EPMEndpoints) {
        [List[PSCustomObject]]$potentialOnboardCandidates = @()
        $matchingKeys = $PAMAccountsIndex.Keys -match $("^$([regex]::Escape($comp.ComputerName))$")
        foreach ($key in $matchingKeys) {
            $potentialOnboardCandidates.Add($PAMAccountsIndex[$key])
        }
        $usernameList = @()
        switch ($comp.Platform) {
            "Windows" { $usernameList = $EndpointUserNamesWin; Break}
            "MacOS" { $usernameList = $EndpointUserNamesMac; Break}
            "Linux" { $usernameList = $EndpointUserNamesLinux; Break}
        }
        foreach ($username in $usernameList) {
            if ($potentialOnboardCandidates) {
                $userNameExistsInPAM = $false
                foreach ($account in $potentialOnboardCandidates) {
                    if ($account.userName -match "^$([regex]::escape($username))$") {
                        $userNameExistsInPAM = $true
                        break
                    }
                }
                if (!$userNameExistsInPAM) {
                    if ($SkipOnboarding) {
                        Add-Content -Path $ReportFilePath -Value "$username,$($comp.ComputerName),$($comp.Platform),Onboarding,Skipped,Account would have been onboarded however onboarding is disabled per the current run configuration." -ErrorAction SilentlyContinue *> $null
                        continue
                    }
                    $onboardCandidates.Add([PSCustomObject]@{
                        Username = $username
                        Address = $comp.ComputerName
                        Platform = $comp.Platform
                    })
                }
            }
            else {
                if ($SkipOnboarding) {
                    Add-Content -Path $ReportFilePath -Value "$username,$($comp.ComputerName),$($comp.Platform),Onboarding,Skipped,Account would have been onboarded however onboarding is disabled per the current run configuration." -ErrorAction SilentlyContinue *> $null
                    continue
                }
                $onboardCandidates.Add([PSCustomObject]@{
                    Username = $username
                    Address = $comp.ComputerName
                    Platform = $comp.Platform
                })
            } 
        }
    }
    Write-Log -Type INF -Message "[$($onboardCandidates.Count)] account(s) identified for onboarding"
    return $onboardCandidates
}

Function Get-OffBoardingCandidates {
    <#
    .SYNOPSIS
        Determines all offboarding candidates based on accounts pre-existing in PAM and all existing EPM endpoints.
    .DESCRIPTION
        Determines all offboarding candidates based on accounts pre-existing in PAM and all existing EPM endpoints.
        Returns a List of PSObject containing the deserialized results of a PAM "Get Accounts" API call; .Id being used for offboarding
    .PARAMETER PAMAccounts
        A List of PSObject that represent the deserialized results of a PAM "Get Accounts" API call
    .PARAMETER EPMEndpoints
        A List of PSObject that represents the deserialized results of an EPM "Get Computers" API call (with qualified hostnames)
    .PARAMETER IgnoreList
        A List of PSObject that represent the deserialized results of an EPM "Get Computers" API call
    .EXAMPLE
        $offboardCandidates = Get-OffBoardingCandidates -PAMAccounts $PAMAccounts -EPMEndpoints $EPMEndpoints
    .NOTES
        The following script-level variables are used:
        - $EndpointUserNamesWin
        - $EndpointUserNamesMac
        - $EndpointHostnameExclusionsRegex
        
        Author: Craig Geneske
    #>
    param (
        [Parameter(Mandatory = $false)]
        [List[PSCustomObject]]$PAMAccounts,

        [Parameter(Mandatory = $false)]
        [List[PSCustomObject]]$EPMEndpoints,

        [Parameter(Mandatory = $false)]
        [List[PSCustomObject]]$IgnoreList
    )

    [List[PSCustomObject]]$offboardCandidates = @()
    Write-Log -Type INF -Message "Determining offboarding candidates..."

    #Create EPM Computers Index
    $EPMComputersIndex = @{}
    foreach ($comp in $EPMEndpoints) {
        $key = $comp.("ComputerName")
        $data = $EPMComputersIndex[$key]
        if ($data -is [Collections.ArrayList]) {
            $data.add($comp) > $null
        }
        elseif ($data) {
            $EPMComputersIndex[$key] = [Collections.ArrayList]@($data, $comp)
        }
        else {
            $EPMComputersIndex[$key] = $comp
        }
    }

    #Create Ignore List Index
    $IgnoreListIndex = @{}
    foreach ($comp in $IgnoreList) {
        $key = $comp.("ComputerName")
        $data = $IgnoreListIndex[$key]
        if ($data -is [Collections.ArrayList]) {
            $data.add($comp) > $null
        }
        elseif ($data) {
            $IgnoreListIndex[$key] = [Collections.ArrayList]@($data, $comp)
        }
        else {
            $IgnoreListIndex[$key] = $comp
        }
    }

    foreach ($account in $PAMAccounts) {
        if (!($EPMComputersIndex.Keys -match $("^$([regex]::Escape($account.Instance.Address))$"))) {
            $usernameList = @()
            switch ($account.PlatformBaseID) {
                "WinLooselyDevice" { $usernameList = $EndpointUserNamesWin; $compPlatform = "Windows"; Break }
                "Unix" { $usernameList = $EndpointUserNamesMac; $compPlatform = "MacOS"; Break }
                "UnixLooselyDevice" { $usernameList = $EndpointUserNamesLinux; $compPlatform = "Linux"; Break }
            }
            if ($IgnoreListIndex.Keys -match $("^$([regex]::Escape($account.Instance.Address))$")) {
                Add-Content -Path $ReportFilePath -Value "$($account.Instance.Username),$($account.Instance.Address),$compPlatform,Offboarding,Skipped,There is a matching computer in EPM that should be skipped due to the current run configuration" -ErrorAction SilentlyContinue *> $null
                continue
            }
            if ($EndpointHostnameExclusionsRegex) {
                foreach ($pattern in $EndpointHostnameExclusionsRegex) {
                    $matchFound = $false
                    if ($account.Instance.Address -match $pattern) {
                        $matchFound = $true
                        Add-Content -Path $ReportFilePath -Value "$($account.Instance.Username),$($account.Instance.Address),$compPlatform,Offboarding,Skipped,The account's address in PAM matches a hostname exclusion pattern" -ErrorAction SilentlyContinue *> $null
                        break
                    }
                }
                if ($matchFound) {
                    continue
                }
            }
            foreach ($username in $usernameList) {
                if ($account.Instance.UserName -match "^$([regex]::Escape($username))$") {
                    if ($account.Instance.LastModified -le [DateTime]::UtcNow.AddDays(-$OffboardingDelayDays)) {
                        if ($SkipOffBoarding) {
                            Add-Content -Path $ReportFilePath -Value "$($account.Instance.Username),$($account.Instance.Address),$compPlatform,Offboarding,Skipped,Account would have been offboarded however offboarding is disabled per the current run configuration" -ErrorAction SilentlyContinue *> $null
                            break
                        }
                        $account.Instance | Add-Member -NotePropertyName CompPlatform -NotePropertyValue $compPlatform
                        $offboardCandidates.Add($account.Instance)
                        break
                    }
                    else {
                        $offBoardingTimespan = $account.Instance.LastModified - [DateTime]::UtcNow.AddDays(-$OffboardingDelayDays)
                        $eligibleFrom = [DateTime]::UtcNow.AddDays($offBoardingTimespan.TotalDays)
                        $daysFromOffboarding = $offBoardingTimespan.Days
                        if (!$offBoardingTimespan.Days) {
                            $daysFromOffboarding = "less than 1"
                        }
                        Add-Content -Path $ReportFilePath -Value "$($account.Instance.Username),$($account.Instance.Address),$compPlatform,Offboarding,Skipped,Account will be delayed offboarding for approximately [$daysFromOffboarding] more day(s) - Eligible from [$eligibleFrom] UTC" -ErrorAction SilentlyContinue *> $null
                        break
                    }
                }
            }
        }
    }
    Write-Log -Type INF -Message "[$($offboardCandidates.Count)] account(s) identified for offboarding"
    return $offboardCandidates
}

Function Write-PAMLifecycleReport {
    <#
    .SYNOPSIS
        Writes a report to console, log file, and CSV of all potential onboarding, offboarding and skipped candidates.
    .DESCRIPTION
        Writes a report to console, log file, and CSV of all potential onboarding, offboarding and skipped candidates.
    .PARAMETER OnboardCandidates
        An array of PSObject that represents the deserialized results of an EPM "Get Computers" API call (with qualified hostnames)
        pared down to only the candidates that should be considered for onboarding
    .PARAMETER OffboardCandidates
        An array of PSObject that represents the deserialized results of a PAM "Get Accounts" API call pared down to only
        the candidates that should be considered for offboarding.
    .PARAMETER IgnoreList
        An array of PSObject that represent the deserialized results of an EPM "Get Computers" API call, which should be skipped
    .EXAMPLE
        Write-Report -OnboardCandidates $onboardCandidates -OffboardCandidates $offboardCandidates -IgnoreList $ignoreList
    .NOTES
        The following script-level variables are used:
        - $ReportFilePath
        - $SafetyTriggered
        
        Author: Craig Geneske
    #>
    param (
        [Parameter(Mandatory = $false)]
        [List[PSCustomObject]]$OnboardCandidates,

        [Parameter(Mandatory = $false)]
        [List[PSCustomObject]]$OffboardCandidates,

        [Parameter(Mandatory = $false)]
        [List[PSCustomObject]]$IgnoreList
    )

    Write-Log -Type INF -Message "###################################################################"
    Write-Log -Type INF -Message "#                                                                 #"
    Write-Log -Type INF -Message "#  REPORT ONLY MODE DETECTED!  Sending results to log and CSV...  #"
    Write-Log -Type INF -Message "#                                                                 #"
    Write-Log -Type INF -Message "###################################################################"
    if ($OnboardCandidates) {
        Write-Log -Type INF -Message "The following [$($OnboardCandidates.Count)] account(s) have been identified for onboarding:"
        foreach ($candidate in $OnboardCandidates) {
            Write-Log -Type INF -Message "---> Username: [$($candidate.Username)] | Address: [$($candidate.Address)]"
            Add-Content -Path $ReportFilePath -Value "$($candidate.Username),$($candidate.Address),$($candidate.Platform),Onboarding,Reported," -ErrorAction SilentlyContinue *> $null
        }
    }
    else {
        Write-Log -Type INF -Message "No accounts have been identified for onboarding"
    }

    if ($OffboardCandidates) {
        Write-Log -Type INF -Message "The following [$($OffboardCandidates.Count)] account(s) have been identified for offboarding:"
        foreach ($candidate in $OffboardCandidates) {
            Write-Log -Type INF -Message "---> Username: [$($candidate.Username)] | Address: [$($candidate.Address)]"
            Add-Content -Path $ReportFilePath -Value "$($candidate.Username),$($candidate.Address),$($candidate.CompPlatform),Offboarding,Reported," -ErrorAction SilentlyContinue *> $null
        }
    }
    else {
        Write-Log -Type INF -Message "No accounts have been identified for offboarding"
    }

    if ($IgnoreList) {
        Write-Log -Type INF -Message "The following [$($ignoreList.Count)] endpoint(s) were skipped -- see the report file for full context:"
        foreach ($comp in $ignoreList) {
            Write-Log -Type INF -Message "---> Endpoint: [$($comp.ComputerName)]"
            #Skipped endpoints are added to the report file at their time of discovery regardless of the run mode, so we don't need to Add-Content here
        }
    }
    else {
        Write-Log -Type INF -Message "No endpoints have been skipped"
    }
    if($SafetyTriggered) {
        Write-Log -Type WRN -Message "--> SAFETY TRIGGERED <--"
        Write-Log -Type WRN -Message "EPM Computers or PAM accounts have changed by more than their respective thresholds since last execution.  See log entry above for more details"
    }
    Write-Log -Type INF -Message "###################################################################"
}

Function Test-LatestScriptVersion {
    <#
    .SYNOPSIS
        Determines if this script is the lastest version available on GitHub.
    .DESCRIPTION
        Determines if this script is the latest version available on GitHub.  If a newer version is available, logs
        an event and returns the latest version as a string.  If up-to-date, returns an empty string.
    .EXAMPLE
        $Version = Test-LatestScriptVersion
    .NOTES
        The following script-level variables are used:
        - $OriginScriptUri
        - $PSScriptInfo
        
        Author: Craig Geneske
    #>
    try {
        Write-Log -Type INF -Message "Checking script version - current version is [$($PSScriptInfo.Version.ToString())]..."   
        $tmpFile = New-TemporaryFile -ErrorAction Stop
        $withNewExtension = $tmpFile.BaseName + ".ps1"
        $tmpFile = $tmpFile | Rename-Item -NewName $withNewExtension -PassThru -ErrorAction Stop
        (Invoke-WebRequest -UseBasicParsing -Uri $OriginScriptUri -ErrorAction Stop).Content | Set-Content -Path $tmpFile
        $originScriptVer = [version](Test-ScriptFileInfo -Path $tmpFile -ErrorAction Stop).Version
        if ($originScriptVer -gt [version]$PSScriptInfo.Version) {
            Write-Log -Type WRN -Message "There is a newer version [$($originScriptVer.ToString())] available on GitHub!"
            return $originScriptVer.ToString()
        }
        else {
            Write-Log -Type INF -Message "Script is on the latest version"
        }
    }
    catch {
        Write-Log -Type WRN -Message "There was an issue determining script latest version --> $($_.Exception.Message)"
        $Error.Clear()
    }
    finally {
        if (Test-Path -Path $tmpFile) {
            Remove-Item -Path $tmpFile -ErrorAction SilentlyContinue *> $null
        }
    }
    return ""
}

Function Send-PAMLifecycleEmail {
<#
    .SYNOPSIS
        Compiles summary of execution results and sends via plaintext E-Mail.
    .DESCRIPTION
        Compiles summary of execution results and sends via plaintext E-Mail.  If a newer script version is
        available on GitHub, this detail will also be included in the subject and body.  If a failure is 
        detected either in the core flow or in lifecycle actions for a particular account in PAM, this is
        also indicated in the subject and body.
    .PARAMETER NewVersionAvailable
        Version number as a string.
    .PARAMETER StartTime
        DateTime that denotes the time that script execution began.
    .PARAMETER EndTime
        DateTime that denotes the time that script execution ended.
    .EXAMPLE
        Send-PAMLifecycleEmail
    .NOTES
        The following script-level variables are used:
        - $SendSummaryEmail
        - $SafetyTriggered
        - $ReportOnlyMode
        - $EmailFullReportAndLog
        - $EmailWithSsl
        - $SMTPRelayHostname
        - $EmailFromAddress
        - $EmailToAddress
        - $PSScriptInfo
        
        Author: Craig Geneske
    #>

    Param(
        [Parameter(Mandatory = $false)]
        [string]$NewVersionAvailable = "",

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,

        [Parameter(Mandatory = $true)]
        [datetime]$EndTime
    )

    Write-Log -Type INF -Message "Attempting to send summary E-Mail..."

    try {
        $subject = "CyberArk EPM LCD Lifecycle Utility [$($PSScriptInfo.Version.ToString())] VarSubjNewVer- Execution Summary | + VarSubjOnBoarded | - VarSubjOffBoarded | VarSubjStatusVarSubjMode"
        $body = @"
Dear CyberArk Administrator,
VarNewVer
An execution of the CyberArk EPM LCD Lifecycle UtilityVarReportOnly has completed VarCompletionStatus

Execution Start - VarExecutionStart
Execution End   - VarExecutionEnded
Elapsed [HH:MM:SS] - VarExecutionTime

Total # OnboardedVarIsPlanned: VarOnBoarded VarOnboardingFailures
Total # OffboardedVarIsPlanned: VarOffBoarded VarOffboardingFailures
Total # SkippedVarIsPlanned: VarSkipped VarAnyFailures VarReportExists VarReviewLog VarAttachments

Regards,
Your Friendly Neighborhood CyberArk Automation
"@
        if ($NewVersionAvailable) {
            $subject = $subject.Replace("VarSubjNewVer", "(New Ver. Available!) ")
            $body = $body.Replace("VarNewVer", "`nA new version of this utility [$NewVersionAvailable] is available at the project page $($PSScriptInfo.PROJECTURI)`n")
        }
        else {
            $subject = $subject.Replace("VarSubjNewVer", "")
            $body = $body.Replace("VarNewVer", "")
        }

        $body = $body.Replace("VarExecutionStart", $StartTime.ToString())
        $body = $body.Replace("VarExecutionEnded", $EndTime.ToString())
        $body = $body.Replace("VarExecutionTime", ($EndTime - $StartTime).ToString().Substring(0, ($EndTime - $StartTime).ToString().IndexOf('.')))

        $onBoardSuccess = 0
        $offBoardSuccess = 0
        $onBoardFailures = 0
        $offBoardFailures = 0
        $skipped = 0
        if (Test-Path -Path $ReportFilePath) {
            if (!$EmailFullReportAndLog) {
                $body = $body.Replace("VarReportExists", "`n`nFor more information on the lifecycle activitiesVarWouldHave conducted in PAM, please see the full report on your utility host at `"$ReportFilePath`"`n")
            }            
            $results = Import-Csv -Path $ReportFilePath
            foreach ($result in $results) {
                if ($result.Status -match "Skipped") {
                    $skipped++
                    continue
                }
                if ($result.Action -match "Onboarding") {
                    if ($result.Status -match "Reported|Success") {
                        $onBoardSuccess++
                        continue
                    }
                    else {
                        $onBoardFailures++
                        continue
                    }
                }
                if ($result.Action -match "Offboarding") {
                    if ($result.Status -match "Reported|Success") {
                        $offBoardSuccess++
                        continue
                    }
                    else {
                        $offBoardFailures++
                        continue
                    }
                }
            }
        }

        $body = $body.Replace("VarReportExists", "")

        if ($EmailFullReportAndLog) {
            $body = $body.Replace("VarAttachments", "`n`nThe log and report (when applicable) are attached for your convenience.")
        }
        else {
            $body = $body.Replace("VarAttachments", "")
        }

        $subject = $subject.Replace("VarSubjOnBoarded", $onBoardSuccess)
        $subject = $subject.Replace("VarSubjOffBoarded", $offBoardSuccess)
        $body = $body.Replace("VarOnBoarded", $onBoardSuccess)
        $body = $body.Replace("VarOffBoarded", $offBoardSuccess)
        $body = $body.Replace("VarSkipped", $skipped)

        if ($onBoardFailures) {
            $body = $body.Replace("VarOnboardingFailures", "`nTotal # Onboarding Failures: $onBoardFailures")
            $subject = $subject.Replace("VarSubjStatus", "FAILURE")
        }
        if ($offBoardFailures) {
            $body = $body.Replace("VarOffboardingFailures", "`nTotal # Offboarding Failures: $offBoardFailures")
            $subject = $subject.Replace("VarSubjStatus", "FAILURE")
        }
        if ($SafetyTriggered) {
            $body = $body.Replace("VarAnyFailures", "`n`nThe safety mechanism has been triggered due to excessive changes in PAM or EPM.")
            if (!$EmailFullReportAndLog){
                $body = $body.Replace("VarReviewLog", "`n`nPlease review the log file on your utility host at `"$LogFilePath`" for more details.")
            }
            else {
                $body = $body.Replace("VarReviewLog", "")
            }

            $subject = $subject.Replace("VarSubjStatus", "FAILURE")
            $body = $body.Replace("VarCompletionStatus", "with errors.")
        }
        elseif (!$onBoardFailures -and !$offBoardFailures) {
            if (!$ReportOnlyMode -and ($onBoardSuccess -or $offBoardSuccess)) {
                $body = $body.Replace("VarAnyFailures", "`n`nThere were no reported lifecycle activity failures against PAM during this execution.")
            }
        }

        $body = $body.Replace("VarOnboardingFailures", "")
        $body = $body.Replace("VarOffboardingFailures", "")
        $body = $body.Replace("VarAnyFailures", "")

        if ($Error.Count) {
            $subject = $subject.Replace("VarSubjStatus", "FAILURE")
            $body = $body.Replace("VarCompletionStatus", "with errors.")
            if (!$EmailFullReportAndLog) {
                $body = $body.Replace("VarReviewLog", "`n`nPlease review the log file on your utility host at `"$LogFilePath`" for more details.")
            }
            else {
                $body = $body.Replace("VarReviewLog", "")
            }

        }
        else {
            $subject = $subject.Replace("VarSubjStatus", "SUCCESS")
            $body = $body.Replace("VarCompletionStatus", "successfully.")
            $body = $body.Replace("VarReviewLog", "")
        }

        if ($ReportOnlyMode) {
            $subject = $subject.Replace("VarSubjMode", " (Report-Only Mode)")
            $body = $body.Replace("VarReportOnly", " in report-only mode")
            $body = $body.Replace("VarIsPlanned", " (Planned)")
            $body = $body.Replace("VarWouldHave", " that would have been")
        }
        else {
            $subject = $subject.Replace("VarSubjMode", "")
            $body = $body.Replace("VarReportOnly", "")
            $body = $body.Replace("VarIsPlanned", " (Actual)")
            $body = $body.Replace("VarWouldHave", "")
        }
    }
    catch {
        Write-Log -Type WRN -Message "Failed to prepare E-Mail subject and body --> $($_.Exception.Message)"
        return
    }
    try {
        $params = @{
            Subject = $subject
            Body = $body
            To = $EmailToAddress
            From = $EmailFromAddress
            SmtpServer = $SMTPRelayHostname
            usessl = $EmailWithSsl
            ErrorAction = "Stop"
        }

        if ($EmailFullReportAndLog) {
            $attachments = @($LogFilePath)
            if (Test-Path -Path $ReportFilePath) {
                $attachments += $ReportFilePath
            }
            $params.Add("Attachments", $attachments)
        }

        Send-MailMessage @params *> $null
        Write-Log -Type INF -Message "Summary E-Mail has been sent successfully"
    }
    catch {
        Write-Log -Type WRN -Message "Failed to send summary E-Mail --> $($_.Exception.Message)"
    }
}

#endregion

################################################### SCRIPT ENTRY POINT ##################################################
#region Script Entry Point

$MainStart = [datetime]::Now
$Error.Clear()

#Create Log File
try {
    New-Item -Path $LogFilePath -Force -ErrorAction Stop *> $null
}
catch {
    Write-Host "Unable to create log file at [$LogFilePath], aborting script --> $($_.Exception.Message)"
    exit 1
}

#Print Log/Console Header
Write-Log -Header

try {
    #Create Report File
    try{
        if ($ReportOnlyMode) {
            Set-Variable -Name ReportFilePath -Scope Script -Value ($ReportFilePath.Substring(0,$ReportFilePath.Length - 4) + "_RO.csv")
        }
        New-Item -Path $ReportFilePath -Force -ErrorAction Stop *> $null
        Add-Content -Path $ReportFilePath -Value "Username,Address,Platform,Action,Status,Reason" -ErrorAction Stop
    }
    catch {
        Write-Log -Type ERR -Message "Unable to create report file at [$ReportFilePath], aborting script --> $($_.Exception.Message)"
        throw
    }

    #Create DAT File
    if (!(Test-Path -Path $DatFilePath)) {
        try {
            New-Item -Path $DatFilePath -Force -ErrorAction Stop *> $null
            $datFileSeed = [PSCustomObject]@{
                EPMComputers = -1
                PAMAccounts = -1
            } | ConvertTo-Json
            Add-Content -Path $DatFilePath -Value $datFileSeed
        }
        catch {
            Write-Log -Type ERR -Message "Unable to create DAT file at [$DatFilePath], aborting script --> $($_.Exception.Message)"
            throw
        }
    }

    #Set Certificate Validation Preference
    if ($IgnoreSSLCertErrors) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [CACertValidation]::GetDelegate()
        Write-Log -Type WRN -Message "You have disabled SSL Certificate validation, this setting is NOT recommended!"
    }
    else {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }

    #Enforce TLS 1.2
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

    #Check if Script is Latest Available
    $Version = ""
    if ($VersionCheck) {
        $Version = Test-LatestScriptVersion
    }

    Confirm-ScriptVariables

    Set-Variable -Scope Script -Name PAMSessionToken -Value $(Invoke-APIAuthentication -App PAM)

    $LCDPlatforms = Get-PAMActiveLCDPlatforms

    #Get all existing LCD Accounts in PAM
    [List[PSCustomObject]]$PAMAccounts, [hashtable]$SafePool = Get-PAMLCDAccounts -LCDPlatformList $LCDPlatforms

    #Get all EPM Computers
    $EPMSessionInfo = Invoke-APIAuthentication -App EPM
    [List[PSCustomObject]]$EPMEndpoints, [List[PSCustomObject]]$ignoreList = Get-EPMComputers -SessionToken $EPMSessionInfo.EPMAuthenticationResult -ManagerURL $EPMSessionInfo.ManagerURL

    #Determine onboarding candidates
    [List[PSCustomObject]]$onboardCandidates = Get-OnBoardingCandidates -PAMAccounts $PAMAccounts -EPMEndpoints $EPMEndpoints

    #Determine offboarding candidates
    [List[PSCustomObject]]$offboardCandidates = Get-OffBoardingCandidates -PAMAccounts $PAMAccounts -EPMEndpoints $EPMEndpoints -IgnoreList $ignoreList

    #Printing report if in Report-Only mode, then exiting
    if ($ReportOnlyMode) {
        Write-PAMLifecycleReport -OnboardCandidates $onboardCandidates -OffboardCandidates $offboardCandidates -IgnoreList $ignoreList
        exit
    }

    #Onboarding Accounts to PAM
    if ($onboardCandidates) {
        if (!$SkipOnBoarding) {
            Add-PAMAccountsBulk -AccountList $onboardCandidates -SafePool $SafePool
        }
        else {
            Write-Log -Type WRN -Message "Skipping onboarding activity per solution configuration"
        }
    }

    #Offboarding Accounts from PAM
    if ($offboardCandidates) {
        if (!$SkipOffBoarding) {
            Remove-PAMAccounts -AccountList $offboardCandidates
        }
        else {
            Write-Log -Type WRN -Message "Skipping offboarding activity per solution configuration"
        }
    }
}
catch {
    #Nothing to do but maintaining catch block to suppress error output as this is processed and formatted lower in the call stack
    #Write-Log -Type ERR -Message $_.Exception.Message
} 
finally {
    $returnCode = 0
    $MainEnd = [datetime]::Now
    if ($Error.Count) {
        Write-Log -Type WRN -Message "Script execution is being interrupted, aborting"
        $returnCode = 1
    }
    else {
        Write-Log -Type INF -Message "All actions have completed successfully"
    }

    if ($PAMSessionToken) {
        Invoke-APILogoff
    }

    $EPMSessionInfo = $null
    $PAMSessionToken = $null

    #Deleting report file if nothing was written to it
    if (Test-Path -Path $ReportFilePath) {
        $numLines = (Get-Content -Path $ReportFilePath | Measure-Object -Line).Lines
        if ($numLines -eq 1) {
            Remove-Item -Path $ReportFilePath -Force -ErrorAction SilentlyContinue *> $null
        }
    }

    if($SendSummaryEmail) {
        Send-PAMLifecycleEmail -NewVersionAvailable $Version -StartTime $MainStart -EndTime $MainEnd
    }

    Write-Log -Footer
    exit $returnCode
}

#endRegion