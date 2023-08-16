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
EPM agent.  These would be accounts that inherently exist on every endpoint of a given platform type (Windows or Mac) as a part of its standard 
baseline (i.e. The Windows Built-In "Administrator").  It achieves this using data obtained exclusively from user-defined script variables, the 
CyberArk PAM and EPM APIs, and optionally DNS (for endpoint FQDN resolution).

The utility leverages both PAM and EPM APIs to compare the computers (agents) that exist in EPM against related local accounts that exist in PAM, 
automatically determining and executing the needed on-boarding and off-boarding actions in PAM.  As new agents come online in EPM, one or more 
standardized local accounts will be on-boarded to PAM.  Likewise as endpoints are pruned from EPM, either through organic inactivity-based attrition 
or proactive computer decomissioning flows, their local accounts will be off-boarded from PAM.

**This utility does not scan, discover, nor communicate directly with loosely-connected endpoints in any way.  It will NOT validate the existence of 
any local accounts prior to conducting on-boarding activities in CyberArk PAM!**


Key Features:

- Complete lifecycle management (on/off-boarding) for named local accounts in PAM that are based on LCD
- Designed to be run interactively or via Scheduled Task from a central endpoint
- Supports separate on-boarding Safes for staging Mac and Windows accounts
- Flexible Safe and Platform scoping provides continuous management throughout the account lifecycle
- Dynamic FQDN discovery via DNS for "mixed" EPM Sets that contain endpoints with varied domain memberships
- **No hard-coded secrets!**  Choice of CyberArk Central Credential Provider (CCP) or Windows Credential Manager
- Implementation of CCP supports OS User (IWA), Client Certificate, and Allowed Machines authentication
- Non-invasive Report-Only mode, useful for determining candidates for on/off-boarding, prior to go-live


Requirements:

- CyberArk Privilege Access Management (PAM) Self-Hosted v11.3+ OR CyberArk Privilege Cloud (Standard/Standalone)
- CyberArk Endpoint Privilege Management (EPM) SaaS
- PAM and EPM API credentials added to CyberArk PAM (CCP) or the Windows Credential Manager
- PowerShell v5 or greater


Script Variables (User-Defined):

ReportOnlyMode          - When set to "$true" will report in console, log, and CSV, which accounts would be on-boarded to, and/or off-boarded from, PAM.  
                          This is a read-only run mode!

SkipOnBoarding          - When set to "$true" will skip the on-boarding logic.

SkipOffBoarding         - When set to "$true" will skip the off-boarding logic.

EndpointUserNamesWin    - List of one or more usernames to lifecycle manage for all Windows-based EPM endpoints.

EndpointUserNamesMac    - List of one or more usernames to lifecycle manage for all Mac-based EPM endpoints.

EndpointDomainNames     - List of one or more DNS domain names that EPM endpoints have membership to.  
                          Applicable only for Windows endpoints as Mac endpoints are assumed to have no domain name.  
                          Used with the "ValidateDomainNamesDNS" and "SkipIfNotInDNS" -- See below for complete info on these variables
                            - If "ValidateDomainNamesDNS" is set to "$false", "EndpointDomainNames" must be set to a single domain name or empty (i.e. "").  
                            - If "ValidateDomainNamesDNS" is set to "$true", "EndpointDomainNames" may remain empty, contain a single domain name, or 
                              contain multiple domain names.  
                            - If "ValidateDomainNamesDNS" is set to "$true" and "EndpointDomainNames" is empty, the DNS Client's Suffix Search List 
                              will be used.

                          Valid Examples / Scenarios:

                          Disable Domain Name resolution via DNS and consider all EPM endpoints as having a standard domain-name of "cybr.com"
                            $EndpointDomainNames = "cybr.com"
                            $ValidateDomainNamesDNS = $false

                          Disable Domain Name resolution via DNS and consider all EPM endpoints as having no domain name
                            $EndpointDomainNames = ""
                            $ValidateDomainNamesDNS = $false
                          
                          Enable Domain Name resolution via DNS and consider EPM endpoints WILL have membership in one of several possible domain names
                          (will skip candidacy if unable to resolve in DNS)
                            $EndpointDomainNames = @("cybr.com", "childA.cybr.com", "childB.cybr.com")
                            $ValidateDomainNamesDNS = $true
                            $SkipIfNotInDNS = $true

                          Enable Domain Name resolution via DNS and consider EPM endpoints MAY have membership in one of several possible domain names
                          or are otherwise domain-less (Will assume no domain name for candidacy, if unable to resolve in DNS)
                            $EndpointDomainNames = @("cybr.com", "childA.cybr.com", "childB.cybr.com")
                            $ValidateDomainNamesDNS = $true
                            $SkipIfNotInDNS = $false

OnboardingPlatformIdWin - Platform ID for the platform to use when on-boarding Windows LCD accounts.

OnboardingPlatformIdMac - Platform ID for the platform to use when on-boarding Mac LCD accounts.

OnboardingSafeWin       - The CyberArk Safe name that Windows LCD accounts will be on-boarded into.

OnboardingSafeMac       - The CyberArk Safe name that Mac LCD accounts will be on-boarded into.

LCDPlatformSearchRegex  - Regular expression for determining which accounts, as assigned to the regex matched LCD-derived platforms, should be 
                          considered "in scope" for making off-boarding determinations.  Used in more advanced setups that require silo'd scopes, 
                          for running multiple script processes against different EPM sets (each associated with a different DNS domain).  
                          In most situations the default value of ".*" will be sufficient.

SafeSearchList          - List of CyberArk Safes which will be searched for existing LCD accounts in PAM, when determining lifecycle candidates.
                          May be left empty (i.e. "") to search all safes.  NOTE: The PAM API user's permissions will also dictate which Safes
                          can and will be searched!

EPMSetIDs               - List of the EPM Set IDs to use for this process.  May be left empty (i.e. "") to use all Sets within the EPM tenant.

PAMHostname             - The base hostname of the Self-Hosted PAM or Privilege Cloud (Standard/Standalone) (i.e. "subdomain.privilegecloud.cyberark.com")

IgnoreSSLCertErrors     - When set to "$true" will ignore any TLS/SSL untrusted certificate errors that would normally prevent the connection.
                          It is recommended to leave this value as "$false" to ensure certificates are verified!

ValidateDomainNamesDNS  - When set to "$true" will leverage DNS lookups to attempt discovery of EPM endpoint FQDNs for on-boarding accuracy.
                          Used with "EndpointDomainNames" (See entry above for more details).
                          Used with "SkipIfNotInDNS" (See entry below for more details).

SkipIfNotInDNS          - When set to "$true" will skip candidacy for any EPM Endpoints that cannot be explicitly resolved in DNS.  When set to "$false",
                          endpoints in EPM that cannot be DNS resolved, will be considered "domain-less" for lifecycle candidacy.
                          Only used when "ValidateDomainNamesDNS" is set to $true, otherwise this can be ignored.

APIUserSource           - Determines the source for PAM and EPM API credential lookup.  There are two possible settings:

                          [APIUserSource]::WinCredMgr  - Will use the Windows Credential Manager for API credential lookup
                          [APIUserSource]::CyberArkCCP - Will use CyberArk Central Credential Provider for API credential lookup

                          CyberArk CCP is generally recommended wherein available, as this simplifies solution setup and allows for regular 
                          credential rotation for the API users without the need to update any configuration points on the solution's host.

PAMCredTarget           - The "Internet or network address" value that was used when entering the PAM API credential into Windows Credential Manager.
                          Used with an APIUserSource of "[APIUserSource]::WinCredMgr", otherwise this can be ignored.

EPMCredTarget           - The "Internet or network address" value that was used when entering the EPM API credential into Windows Credential Manager.
                          Used with an APIUserSource of "[APIUserSource]::WinCredMgr", otherwise this can be ignored.

CCPAuthType             - Determines the authentication type against CCP when used as the API user source.  There are three possible settings:

                          [CCPAuthType]::OSUser          - **RECOMMENDED** Will use OS User (Integrated Windows Authentication) to authenticate to the CCP
                          [CCPAuthType]::Certificate     - **RECOMMENDED** Will use Client Certificate to authenticate to the CCP
                          [CCPAuthType]::AllowedMachines - Will depend solely upon an allowed machines listing in CyberArk for authentication

                          NOTE:  Allowed Machines authentication may be layered on to OSUser or Certificate based authentication in the CyberArk configuration
                          Used with an APIUserSource of "[APIUserSource]::CyberArkCCP", otherwise this can be ignored.

CertThumbprint          - The SHA1 thumbprint of the client certificate to use for authentication to CCP.
                          Used with an APIUserSource of "[APIUserSource]::CyberArkCCP", and with a CCPAuthType of "[CCPAuthType]::Certificate", 
                          otherwise this can be ignored.

PAMAccountName          - The account name (aka object name) of the vaulted account that represents the PAM API credential.
                          Used with an APIUserSource of "[APIUserSource]::CyberArkCCP", otherwise this can be ignored.

PAMObjectSafe           - The Safe where the vaulted account that represents the PAM API credential is held in CyberArk.
                          Used with an APIUserSource of "[APIUserSource]::CyberArkCCP", otherwise this can be ignored.

EPMAccountName          - The account name (aka object name) of the vaulted account that represents the EPM API credential.
                          Used with an APIUserSource of "[APIUserSource]::CyberArkCCP", otherwise this can be ignored.

EPMObjectSafe           - The Safe where the vaulted account that represents the EPM API credential is held in CyberArk.
                          Used with an APIUserSource of "[APIUserSource]::CyberArkCCP", otherwise this can be ignored.

CCPHostname             - The base hostname of the CyberArk CCP (i.e. "ccp.cybr.com")
                          Used with an APIUserSource of "[APIUserSource]::CyberArkCCP", otherwise this can be ignored.

CCPPort                 - The port number for the CyberArk CCP listener (i.e. 443)
                          Used with an APIUserSource of "[APIUserSource]::CyberArkCCP", otherwise this can be ignored.

CCPServiceRoot          - The IIS application/service root that should be used for the web call to CCP (i.e. AIMWebService)
                          Used with an APIUserSource of "[APIUserSource]::CyberArkCCP", otherwise this can be ignored.

CCPAppID                - The Application ID registered in CyberArk that should be used identification to CCP
                          Used with an APIUserSource of "[APIUserSource]::CyberArkCCP", otherwise this can be ignored.

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
1.0 8/10/2023 - Initial Release

DISCLAIMER:
This solution is provided as-is - it is not supported by CyberArk nor an official CyberArk solution.
#>

#Requires -Version 5.0

################################################### SCRIPT VARIABLES ####################################################
#region Script Variables

###############################
### BEGIN CHANGE-ME SECTION ###
###############################

#Run Mode Options
$ReportOnlyMode = $true
$SkipOnBoarding = $false
$SkipOffBoarding = $false

#General Environment Details
$EndpointUserNamesWin = "Administrator"
$EndpointUserNamesMac = "mac_admin"
$EndpointDomainNames = ""
$OnboardingPlatformIdWin = "WinLooselyDevice"
$OnboardingPlatformIdMac = "MACLooselyDevice"
$OnboardingSafeWin = "EPM LCD Staging"
$OnboardingSafeMac = "EPM LCD Staging"
$LCDPlatformSearchRegex = ".*"
$SafeSearchList = ""
$EPMSetIDs = ""
$PAMHostname = "hostname"
$IgnoreSSLCertErrors = $false

#Dynamic FQDN Lookup Options
$ValidateDomainNamesDNS = $true
$SkipIfNotInDNS = $false

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

$LogFilePath = $($PSCommandPath).Substring(0, $($PSCommandPath).LastIndexOf('\')) + "\Logs\CyberArk_LCDLifecycle_" + (Get-Date -Format "MM-dd-yyyy_HHmmss") + ".log"
$ReportFilePath = $($PSCommandPath).Substring(0, $($PSCommandPath).LastIndexOf('\')) + "\Logs\CyberArk_LCDLifecycle_" + (Get-Date -Format "MM-dd-yyyy_HHmmss") + ".csv"

$PAMPageSize = 1000
$EPMPageSize = 5000
$MaximumDNSFailures = 10

$PAMBaseURI = "https://$PAMHostname/PasswordVault"

$PAMAuthLogonUrl = $PAMBaseURI + "/api/auth/CyberArk/Logon"
$PAMAuthLogoffUrl = $PAMBaseURI + "/api/auth/Logoff"
$PAMAccountsUrl = $PAMBaseURI + "/api/Accounts"
$PAMPlatformsUrl = $PAMBaseURI + "/api/Platforms"

$EPMAuthLogonUrl = "https://login.epm.cyberark.com/EPM/API/Auth/EPM/Logon"
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
    if (!(Test-Path -Path $LogFilePath)) {
        try {
            New-Item -Path $LogFilePath -Force -ErrorAction Stop *> $null
        }
        catch {
            Write-Host "Unable to create log file, aborting script --> $($_.Exception.Message)"
            exit -1
        }
    }
    Add-Content -Path $LogFilePath -Value $eventString
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
            $result = $null
            $CCPGetCredentialUrl = $null
            
            switch ($App) {
                "PAM" {
                    $CCPGetCredentialUrl = "https://$($CCPHostname):$CCPPort/$CCPServiceRoot/api/Accounts?" + `
                    "Safe=$([System.Web.HttpUtility]::UrlEncode($PAMObjectSafe))" + `
                    "&Object=$([System.Web.HttpUtility]::UrlEncode($PAMAccountName))" + `
                    "&AppId=$([System.Web.HttpUtility]::UrlEncode($CCPAppID))"
                }
                "EPM" {
                    $CCPGetCredentialUrl = "https://$($CCPHostname):$CCPPort/$CCPServiceRoot/api/Accounts?" + `
                    "Safe=$([System.Web.HttpUtility]::UrlEncode($EPMObjectSafe))" + `
                    "&Object=$([System.Web.HttpUtility]::UrlEncode($EPMAccountname))" + `
                    "&AppId=$([System.Web.HttpUtility]::UrlEncode($CCPAppID))"
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
                }
            }
        
            try {
                Write-Log -Type INF -Message "Attempting to retrieve the [$App] API credential from CCP..."
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
            $credTarget = $null
            switch ($App) {
                "PAM" {
                    $credTarget = $PAMCredTarget
                }
                "EPM" {
                    $credTarget = $EPMCredTarget
                }
            }
            try {
                Write-Log -Type INF -Message "Attempting to retrieve the [$App] API credential from Windows Credential Manager..."
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
            Write-Log -Type ERR -Message "Failed to retrieve [$App] API User details - API User Source [$APIUserSource] has not been implemented"
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

    switch ($App) {
        "PAM" {
            $APIAuthUrl = $PAMAuthLogonUrl
            $postBody = @{
                concurrentSession = $true 
            }
        }
        "EPM" {
            $APIAuthUrl = $EPMAuthLogonUrl
            $postBody = @{
                ApplicationID = "EPM LCD Lifecycle"
            }
        }
    }

    $postBody.Add("Username", $APICred.Username)
    $postBody.Add("Password", $APICred.Password)
    $postBody = $postBody | ConvertTo-Json
    
    try {
        Write-Log -Type INF -Message "Attempting to authenticate to [$App] API..."
        $result = Invoke-RestMethod -Method Post -Uri $APIAuthUrl -Body $postBody -ContentType "application/json"
        Write-Log -Type INF -Message "Successfully authenticated to [$App] API"
        return $result
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
    .PARAMETER SessionToken
        Session token that was received from the PVWA Logon endpoint
    .EXAMPLE
        Invoke-APILogoff -SessionToken "YmNlODFhZjktNjdkMS00Yzg3LThiMDctMTAxOGMzNzU3ZWJkOzFFNj...."
    .NOTES
        The following script-level parameteres are used:
            - $PAMAuthLogoffUrl

        Author: Craig Geneske
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [string]$SessionToken
    )

    try {
        Write-Log -Type INF -Message "Attempting to logoff PAM API..."
        Invoke-RestMethod -Method Post -Uri $PAMAuthLogoffUrl -Headers @{ Authorization = $SessionToken} *> $null
        Write-Log -Type INF -Message "PAM API logoff was successful"
    } 
    catch {
        Write-Log -Type WRN -Message "Unable to logoff PAM API - $($_.Exception.Message)"
    }
}

Function Get-PAMActiveLCDPlatforms {
    <#
    .SYNOPSIS
        Gets all Active LCD derived platforms from PAM.
    .DESCRIPTION
        Gets all Active LCD derived platforms from PAM, filtered further via optionally supplied regex, and returns all platform IDs in a list of string.
    .PARAMETER SessionToken
        Session token that was received from the PAM Logon endpoint
    .EXAMPLE
        Get-PAMLCDPlatforms -SessionToken "YmNlODFhZjktNjdkMS00Yzg3LThiMDctMTAxOGMzNzU3ZWJkOzFFNj...."
    .NOTES
        The following script-level variables are used:
            - $PAMPlatformsUrl
            - $LCDPlatformSearchRegex

        Author: Craig Geneske
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [string]$SessionToken
    )

    $result = $null
    $platformList = @()
    $finalUrl = $PAMPlatformsUrl + "?Active=True"

    try {
        Write-Log -Type INF -Message "Getting all active LCD platforms from PAM..."
        $result = Invoke-RestMethod -Method Get -Uri $finalUrl -Headers @{Authorization = $SessionToken} -ContentType "application/json"
        foreach ($platform in $result.Platforms) {
            foreach ($pattern in $LCDPlatformSearchRegex) {
                if ($platform.general.id -match $pattern -and `
                    ($platform.general.platformBaseId -match "^WinLooselyDevice$" -or $platform.general.platformBaseId -match "^Unix$")) {
                    $platformList += [PSCustomObject]@{
                        PlatformID = $platform.general.id
                        PlatformBaseID = $platform.general.platformBaseID
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
        search list, returning a list of accounts.
    .PARAMETER SessionToken
        Session token that was received from the PAM Logon endpoint
    .PARAMETER LCDPlatformList
        The list of LCD platforms for identifying account candidates
    .EXAMPLE
        Get-PAMLCDAccounts -SessionToken "YmNlODFhZjktNjdkMS00Yzg3LThiMDctMTAxOGMzNzU3ZWJkOzFFNj...." -LCDPlatformList "WinLooselyDevice","_CYBR_WindowsLooselyDevice"
    .NOTES
        The following script-level variables are used:
            - $PAMAccountsUrl
            - $SafeSearchList

        Author: Craig Geneske
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [string]$SessionToken,

        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$LCDPlatformList
    )

    $PAMAccountsList = @()
    $result = $null
    $pageCounter = 0
    $accountsCounter = 0
    $candidatesCounter = 0
    
    try {
        foreach ($safe in $SafeSearchList) {
            $accountsUrl = $PAMAccountsUrl
            if (![string]::IsNullOrEmpty($safe)) {
                Write-Log -Type INF -Message "Getting LCD accounts in safe [$safe]..."
                $accountsUrl = $accountsUrl + "?limit=$($PAMPageSize)&filter=safeName eq $([System.Web.HttpUtility]::UrlEncode($safe))"
            }
            else {
                Write-Log -Type INF -Message "Getting LCD accounts in all safes (this may take a while)..."
                $accountsUrl = $accountsUrl + "?limit=$($PAMPageSize)"
            }
            do {
                $result = $null
                $result = Invoke-RestMethod -Method Get -Uri $accountsUrl -Headers @{Authorization = $SessionToken} -ContentType "application/json"
                foreach ($account in $result.value) {
                    $accountsCounter++
                    $isCandidate = $false
                    foreach ($platform in $LCDPlatformList) {
                        if ($account.platformId -eq $platform.PlatformID) {
                            $isCandidate = $true
                            break
                        }
                    }
                    if ($isCandidate) {
                        foreach ($platform in $LCDPlatformList) {
                            if ($account.platformId -eq $platform.PlatformID) {
                                $PAMAccountsList += [PSCustomObject]@{
                                    Instance = $account
                                    PlatformBaseID = $platform.PlatformBaseID
                                }
                                $candidatesCounter++
                            }
                        }
                    }
                }
                if ($result.nextLink) {
                    $pagecounter++
                    if ($pageCounter % 5 -eq 0){
                        Write-Log -Type INF -Message "---> Status Ping: [$accountsCounter] accounts processed in [$pageCounter] pages so far -- [$candidatesCounter] LCD accounts and counting"
                    }
                    $accountsUrl = $PAMBaseURI + "/" + $result.nextLink
                }
            } 
            while ($result.nextLink)
        }
        Write-Log -Type INF -Message "PAM account search complete, [$candidatesCounter] LCD accounts found out of [$accountsCounter] total accounts"
        return $PAMAccountsList
    }
    catch {
        Invoke-ParseFailureResponse -Component "PAM" -ErrorRecord $_ -Message "Failed to get PAM accounts associated with an active LCD platform"
        throw
    }
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
            - $EPMSetIDs
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
    $EPMComputerList = @()
    $pageCounter = 0
    $computersCounter = 0
    $result = $null

    try{
        Write-Log -Type INF -Message "Getting all EPM Sets..."
        $result = Invoke-RestMethod -Method Get -Uri ($ManagerURL + $EPMSetsListUrl) -Headers @{Authorization = "basic $($SessionToken)"} -ContentType "application/json"
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
        Write-Log -Type INF -Message "Getting all EPM Computers..."
        foreach ($set in $confirmedSets) {
            Write-Log -Type INF -Message "---> Getting computers for set [$($set.Name) {$($set.Id)}]..."
            $computersUri = ($ManagerURL + ($EPMComputersUrl -f $set.Id) + "?limit=$EPMPageSize")
            $offset = 0
            do {
                $result = $null
                $result = Invoke-RestMethod -Method Get -Uri $computersUri -Headers @{Authorization = "basic $($SessionToken)"} -ContentType "application/json"
                foreach ($computer in $result.Computers) {
                    if ($computer.Platform -ne "Unknown") {
                        $computersCounter++
                        $EPMComputerList += [PSCustomObject]@{
                            ComputerName = $computer.ComputerName
                            Platform = $computer.Platform
                        }
                    }   
                }
                if ($result.Computers.Count -eq $EPMPageSize) {
                    $offset += $EPMPageSize
                    $computersUri = ($ManagerURL + ($EPMComputersUrl -f $set.Id) + "?limit=$EPMPageSize&offset=$offset")
                }
                $pageCounter++
                if ($pageCounter % 5 -eq 0){
                    Write-Log -Type INF -Message "------> Status Ping: [$computersCounter] computers processed in [$pageCounter] pages so far"
                }
            }
            while ($result.Computers.Count -eq $EPMPageSize)
        }
        Write-Log -Type INF -Message "Retrieved [$computersCounter] EPM Computers"
    }
    catch {
        Invoke-ParseFailureResponse -Component "EPM" -ErrorRecord $_ -Message "Failed to get all EPM computers"
        throw
    }

    #Fully-qualify all EPM Computers via DNS if ValidateDomainDNSNames is set (dynamic), otherwise via EndpointDomainNames (static)
    $qualifiedComps = @()
    $ignoreList = @()
    if ($ValidateDomainNamesDNS) {
        Write-Log -Type INF -Message "Attempting to qualify all Windows EPM computers via dynamic DNS domain name lookup..."
        $countDNSIssues = 0
        foreach ($comp in $EPMComputerList) {
            if ($comp.Platform -eq "MacOS") {
                $qualifiedComps += $comp
                continue
            }
            $dnsNameFound = $false
            foreach ($domainName in $EndpointDomainNames) {
                try {
                    Resolve-DnsName -Name ($comp.ComputerName + "." + $domainName) -ErrorAction Stop *> $null
                    $qualifiedComps += [PSCustomObject]@{
                        ComputerName = ($comp.ComputerName + "." + $domainName)
                        Platform = $comp.Platform
                    }
                    $dnsNameFound = $true
                    break
                }
                catch {
                    if ($_.Exception.Message -match "DNS name does not exist") {
                        $Error.Clear()
                        continue
                    }
                    else {
                        Write-Log -Type WRN -Message "Potential issue with DNS resolution, skipping candidacy for [$($comp.ComputerName)] --> $($_.Exception.Message)"
                        $countDNSIssues++
                        $ignoreList += $comp
                        if ($countDNSIssues -ge $MaximumDNSFailures) {
                            Write-Log -Type ERR -Message "Maximum general DNS failures reached [$MaximumDNSFailures]."
                            throw
                        }
                        $Error.Clear()
                        continue
                    }
                }
            }
            if (!$dnsNameFound) {
                if ($SkipIfNotInDNS) {
                    Write-Log -Type WRN -Message "Domain name not found for [$($comp.ComputerName)], skipping candidacy per the configuration"
                    $ignoreList += $comp
                    continue
                }
                $qualifiedComps += $comp
            }
        }
    }
    else {
        if ($EndpointDomainNames) {
            Write-Log -Type INF -Message "Qualifying all Windows EPM computers with provided domain name [$EndpointDomainNames]..."
            foreach ($comp in $EPMComputerList) {
                if ($comp.Platform -eq "MacOS") {
                    $qualifiedComps += $comp
                    continue
                }
                $qualifiedComps += [PSCustomObject]@{
                    ComputerName = ($comp.ComputerName + "." + $EndpointDomainNames)
                    Platform = $comp.Platform
                }
            }
        }
        else {
            Write-Log -Type INF -Message "Treating all EPM computer names as having no domain name given EndpointDomainNames is empty"
            $qualifiedComps = $EPMComputerList
        }
    }
    Write-Log -Type INF -Message "EPM computer qualification complete"
    return $qualifiedComps, $ignoreList
}

Function Add-PAMAccounts {
    <#
    .SYNOPSIS
        Adds accounts to PAM via API.
    .DESCRIPTION
        Adds accounts to PAM via API.
    .PARAMETER SessionToken
        Session token that was received from the PAM Logon endpoint
    .PARAMETER AccountList
       Array of PSObject representing the return value of Get-OnBoardingCandidates (Members: UserName, Address, Platform)
    .EXAMPLE
        Add-PAMAccounts -PAMSessionToken "YmNlODFhZjktNjdkMS00Yzg3LThiMDctMTAxOGMzNzU3ZWJkOzFFNj...." -AccountList $onboardCandidates
    .NOTES
        The following script-level variables are used:
            - $OnboardingPlatformIdWin
            - $OnboardingPlatformIdMac
            - $OnboardingSafeWin
            - $OnBoaridngSafeMac
            - $PAMAccountsUrl

        Author: Craig Geneske
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [string]$SessionToken,

        [Parameter(Mandatory = $true)]
        [PSObject[]]$AccountList
    )

    $onboardedTotal = 0
    Write-Log -Type INF -Message "###########################################"
    Write-Log -Type INF -Message "#                                         #"
    Write-Log -Type INF -Message "# BEGIN ON-BOARDING ALL CANDIDATES TO PAM #"
    Write-Log -Type INF -Message "#                                         #"
    Write-Log -Type INF -Message "###########################################"
    foreach ($account in $AccountList) {
        try {
            $body = @{
                userName = $account.UserName
                address = $account.Address
                secretType = "password"
            }
            switch($account.Platform) {
                "Windows" { $body.Add("platformId", $OnboardingPlatformIdWin); $body.Add("safeName", $OnboardingSafeWin) }
                "MacOS" { $body.Add("platformId", $OnboardingPlatformIdMac); $body.Add("safeName", $OnboardingSafeMac) }
            }
            $body = $body | ConvertTo-Json
            Write-Log -Type INF -Message "On-boarding account [$($account.UserName)@$($account.Address)] to PAM..."
            Invoke-RestMethod -Method Post -Uri $PAMAccountsUrl -Body $body -Headers @{Authorization = $SessionToken} -ContentType "application/json" *> $null
            $onboardedTotal++
        }
        catch {
            #TODO: If exception caused by invalid PAM Session we should abort, otherwise, treat as non-fatal and continue.
            Invoke-ParseFailureResponse -Component PAM -ErrorRecord $_ -Message "Failed to on-board account [$($account.UserName)@$($account.Address)] to PAM"
            $Error.Clear()
            continue
        }
    }
    Write-Log -Type INF -Message "###############################"
    Write-Log -Type INF -Message "#                             #"
    Write-Log -Type INF -Message "# ON-BOARDING TO PAM COMPLETE #"
    Write-Log -Type INF -Message "#                             #"
    Write-Log -Type INF -Message "###############################"
    Write-Log -Type INF -Message "[$onboardedTotal] of [$($AccountList.Count)] accounts were successfully on-boarded"
}

Function Remove-PAMAccounts {
    <#
    .SYNOPSIS
        Removes accounts from PAM via API.
    .DESCRIPTION
        Removes accounts from PAM via API.
    .PARAMETER SessionToken
        Session token that was received from the PAM Logon endpoint
    .PARAMETER AccountList
       Array of PSObject representing the return value of Get-OffBoardCandidates (Members: "Get Accounts" PAM API deserialized object)
    .EXAMPLE
        Remove-PAMAccounts -SessionToken "YmNlODFhZjktNjdkMS00Yzg3LThiMDctMTAxOGMzNzU3ZWJkOzFFNj...." -AccountList $offboardCandidates
    .NOTES
        The following script-level variables are used:
        - $PAMAccountsUrl

        Author: Craig Geneske
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [string]$SessionToken,
        
        [Parameter(Mandatory = $true)]
        [PSObject[]]$AccountList
    )

    $offboardTotal = 0
    Write-Log -Type INF -Message "##############################################"
    Write-Log -Type INF -Message "#                                            #"
    Write-Log -Type INF -Message "# BEGIN OFF-BOARDING ALL CANDIDATES FROM PAM #"
    Write-Log -Type INF -Message "#                                            #"
    Write-Log -Type INF -Message "##############################################"
    foreach ($account in $AccountList) {
        try {
            Write-Log -Type INF -Message "Off-boarding account [$($account.id) - $($account.UserName)@$($account.Address)] from PAM..."
            Invoke-RestMethod -Method Delete -Uri ($PAMAccountsUrl + "/$($account.id)/") -Headers @{Authorization = $SessionToken} -ContentType "application/json" *> $null
            $offboardTotal++
        }
        catch {
            #TODO: If exception caused by invalid PAM Session we should abort, otherwise, treat as non-fatal and continue.
            Invoke-ParseFailureResponse -Component PAM -ErrorRecord $_ -Message "Failed to off-board account [$($account.UserName)@$($account.Address)] from PAM"
            $Error.Clear()
            continue
        }
    }
    Write-Log -Type INF -Message "##################################"
    Write-Log -Type INF -Message "#                                #"
    Write-Log -Type INF -Message "# OFF-BOARDING FROM PAM COMPLETE #"
    Write-Log -Type INF -Message "#                                #"
    Write-Log -Type INF -Message "##################################"
    Write-Log -Type INF -Message "[$offboardTotal] of [$($AccountList.Count)] accounts were successfully off-boarded"
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

    Write-Log -Type INF -Message "Script Variables have been validated"
}

Function Get-OnBoardingCandidates {
    <#
    .SYNOPSIS
        Determines all on-boarding candidates based on accounts pre-existing in PAM and all existing EPM endpoints.
    .DESCRIPTION
        Determines all on-boarding candidates based on accounts pre-existing in PAM and all existing EPM endpoints.
        Returns an array of PSObject containing the Username, Address, and Platform to be used for on-boarding candidates
    .PARAMETER PAMAccounts
        An array of PSObject that represent the serialized results of a PAM "Get Accounts" API call
    .PARAMETER EPMEndpoints
        An array of PSObject that represents the serialized results of an EPM "Get Computers" API call (with qualified hostnames)
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
        [PSObject[]]$PAMAccounts,

        [Parameter(Mandatory = $false)]
        [PSObject[]]$EPMEndpoints
    )

    $onboardCandidates = @()
    Write-Log -Type INF -Message "Determining on-boarding candidates..."
    foreach ($comp in $EPMEndpoints) {
        $potentialOnboardCandidates = @()
        foreach ($account in $PAMAccounts) {
            if ($account.Instance.address -match "^$($comp.ComputerName)$") {
                $potentialOnboardCandidates += $account
            }
        }

        $usernameList = @()
        switch ($comp.Platform) {
            "Windows" { $usernameList = $EndpointUserNamesWin}
            "MacOS" { $usernameList = $EndpointUserNamesMac}
        }
        foreach ($username in $usernameList) {
            if ($potentialOnboardCandidates) {
                $userNameExistsInPAM = $false
                foreach ($account in $potentialOnboardCandidates) {
                    if ($account.Instance.userName -match "^$username$") {
                        $userNameExistsInPAM = $true
                        break
                    }
                }
                if (!$userNameExistsInPAM) {
                    $onboardCandidates += [PSCustomObject]@{
                        Username = $username
                        Address = $comp.ComputerName
                        Platform = $comp.Platform
                    }
                }
            }
            else {
                $onboardCandidates += [PSCustomObject]@{
                    Username = $username
                    Address = $comp.ComputerName
                    Platform = $comp.Platform
                }
            } 
        }
    }

    Write-Log -Type INF -Message "[$($onboardCandidates.Count)] account(s) identified for on-boarding"
    return $onboardCandidates
}

Function Get-OffBoardingCandidates {
    <#
    .SYNOPSIS
        Determines all off-boarding candidates based on accounts pre-existing in PAM and all existing EPM endpoints.
    .DESCRIPTION
        Determines all off-boarding candidates based on accounts pre-existing in PAM and all existing EPM endpoints.
        Returns an array of PSObject containing the deserialized results of a PAM "Get Accounts" API call; .Id being used for offboarding
    .PARAMETER PAMAccounts
        An array of PSObject that represent the deserialized results of a PAM "Get Accounts" API call
    .PARAMETER EPMEndpoints
        An array of PSObject that represents the deserialized results of an EPM "Get Computers" API call (with qualified hostnames)
    .PARAMETER IgnoreList
        An array of PSObject that represent the deserialized results of an EPM "Get Computers" API call
    .EXAMPLE
        $offboardCandidates = Get-OffBoardingCandidates -PAMAccounts $PAMAccounts -EPMEndpoints $EPMEndpoints
    .NOTES
        The following script-level variables are used:
        - $EndpointUserNamesWin
        - $EndpointUserNamesMac
        
        Author: Craig Geneske
    #>
    param (
        [Parameter(Mandatory = $false)]
        [PSObject[]]$PAMAccounts,

        [Parameter(Mandatory = $false)]
        [PSObject[]]$EPMEndpoints,

        [Parameter(Mandatory = $false)]
        [PSObject[]]$IgnoreList
    )

    $offboardCandidates = @()
    Write-Log -Type INF -Message "Determining off-boarding candidates..."
    foreach ($account in $PAMAccounts) {
        $skipAccount = $false
        if ($IgnoreList) {
            foreach ($comp in $IgnoreList) {
                if ($account.Instance.address -match "^$($comp.ComputerName).*$") {
                    $skipAccount = $true
                    break
                }
            }
            if ($skipAccount) {
                continue
            }
        }
        $validEndpoint = $false
        foreach ($comp in $EPMEndpoints) {
            if ($account.Instance.address -match "^$($comp.ComputerName)$") {
                $validEndpoint = $true
                break
            }
        }
        if (!$validEndpoint) {
            $usernameList = @()
            switch ($account.PlatformBaseID) {
                "WinLooselyDevice" { $usernameList = $EndpointUserNamesWin }
                "Unix" { $usernameList = $EndpointUserNamesMac }
            }
            foreach ($username in $usernameList) {
                if ($account.Instance.userName -match "^$username$") {
                    $offboardCandidates += $account.Instance
                    break
                }
            }
        }
    }
    Write-Log -Type INF -Message "[$($offboardCandidates.Count)] account(s) identified for off-boarding"
    return $offboardCandidates
}

Function Write-PAMLifecycleReport {
    <#
    .SYNOPSIS
        Writes a report to console, log file, and CSV of all potential on-boarding, off-boarding and ignored candidates.
    .DESCRIPTION
        Writes a report to console, log file, and CSV of all potential on-boarding, off-boarding and ignored candidates.
    .PARAMETER OnboardCandidates
        An array of PSObject that represents the deserialized results of an EPM "Get Computers" API call (with qualified hostnames)
        pared down to only the candidates that should be considered for on-boarding
    .PARAMETER OffboardCandidates
        An array of PSObject that represents the deserialized results of a PAM "Get Accounts" API call pared down to only
        the candidates that should be considered for off-boarding.
    .PARAMETER IgnoreList
        An array of PSObject that represent the deserialized results of an EPM "Get Computers" API call, which should be ignored
    .EXAMPLE
        Write-Report -OnboardCandidates $onboardCandidates -OffboardCandidates $offboardCandidates -IgnoreList $ignoreList
    .NOTES
        The following script-level variables are used:
        - ReportFilePath
        
        Author: Craig Geneske
    #>
    param (
        [Parameter(Mandatory = $false)]
        [PSObject[]]$OnboardCandidates,

        [Parameter(Mandatory = $false)]
        [PSObject[]]$OffboardCandidates,

        [Parameter(Mandatory = $false)]
        [PSObject[]]$IgnoreList
    )

    Write-Log -Type INF -Message "###################################################################"
    Write-Log -Type INF -Message "#                                                                 #"
    Write-Log -Type INF -Message "#  REPORT ONLY MODE DETECTED!  Sending results to log and CSV...  #"
    Write-Log -Type INF -Message "#                                                                 #"
    Write-Log -Type INF -Message "###################################################################"
    if (!(Test-Path -Path $ReportFilePath)) {
        New-Item -Path $ReportFilePath -Force *> $null
    }
    Add-Content -Path $ReportFilePath -Value "Username,Address,Action"
    if ($OnboardCandidates) {
        Write-Log -Type INF -Message "The following [$($OnboardCandidates.Count)] account(s) have been identified for on-boarding:"
        foreach ($candidate in $OnboardCandidates) {
            Write-Log -Type INF -Message "---> Username: [$($candidate.Username)] | Address: [$($candidate.Address)]"
            Add-Content -Path $ReportFilePath -Value "$($candidate.Username),$($candidate.Address),Onboarding"
        }
    }
    else {
        Write-Log -Type INF -Message "No accounts have been identified for on-boarding"
    }

    if ($OffboardCandidates) {
        Write-Log -Type INF -Message "The following [$($OffboardCandidates.Count)] account(s) have been identified for off-boarding:"
        foreach ($candidate in $OffboardCandidates) {
            Write-Log -Type INF -Message "---> Username: [$($candidate.Username)] | Address: [$($candidate.Address)]"
            Add-Content -Path $ReportFilePath -Value "$($candidate.Username),$($candidate.Address),Offboarding"
        }
    }
    else {
        Write-Log -Type INF -Message "No accounts have been identified for off-boarding"
    }

    if ($IgnoreList) {
        Write-Log -Type INF -Message "The following [$($ignoreList.Count)] endpoint(s) were ignored as they were unresolved via DNS:"
        foreach ($comp in $ignoreList) {
            Write-Log -Type INF -Message "---> Endpoint: [$($comp.ComputerName)]"
            Add-Content -Path $ReportFilePath -Value "N/A,$($comp.ComputerName),Ignored"
        }
    }
    else {
        Write-Log -Type INF -Message "No endpoints have been ignored"
    }
    Write-Log -Type INF -Message "###################################################################"
}

#endregion

################################################### SCRIPT ENTRY POINT ##################################################

$PAMSessionToken = $null
$EPMSessionToken = $null
$Error.Clear()

#Print Log/Console Header
Write-Log -Header

if ($IgnoreSSLCertErrors) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [CACertValidation]::GetDelegate()
    Write-Log -Type WRN -Message "You have disabled SSL Certificate validation, this setting is NOT recommended!"
}
else {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
}

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

try {
    Confirm-ScriptVariables

    $PAMSessionToken = Invoke-APIAuthentication -App PAM

    $LCDPlatforms = Get-PAMActiveLCDPlatforms -SessionToken $PAMSessionToken

    $getAccountsParams = @{
        SessionToken = $PAMSessionToken
        LCDPlatformList = $LCDPlatforms
    }

    if ($SafeSearchList) {
        $getAccountsParams.Add("SafeSearchList", $SafeSearchList)
    }

    #Get all existing LCD Accounts in PAM
    $PAMAccounts = Get-PAMLCDAccounts @getAccountsParams

    #Get all EPM Computers
    $EPMSessionInfo = Invoke-APIAuthentication -App EPM
    $EPMEndpoints, $ignoreList = Get-EPMComputers -SessionToken $EPMSessionInfo.EPMAuthenticationResult -ManagerURL $EPMSessionInfo.ManagerURL

    #Determine onboarding candidates
    [PSObject[]]$onboardCandidates = Get-OnBoardingCandidates -PAMAccounts $PAMAccounts -EPMEndpoints $EPMEndpoints

    #Determine offboarding candidates
    [PSObject[]]$offboardCandidates = Get-OffBoardingCandidates -PAMAccounts $PAMAccounts -EPMEndpoints $EPMEndpoints -IgnoreList $ignoreList

    #Printing report if in Report-Only mode, then exiting
    if ($ReportOnlyMode) {
        Write-PAMLifecycleReport -OnboardCandidates $onboardCandidates -OffboardCandidates $offboardCandidates -IgnoreList $ignoreList
        exit
    }

    #Onboarding Accounts to PAM
    if ($onboardCandidates) {
        if (!$SkipOnBoarding) {
            Add-PAMAccounts -SessionToken $PAMSessionToken -AccountList $onboardCandidates
        }
        else {
            Write-Log -Type WRN -Message "Skipping on-boarding activity per solution configuration"
        }
    }

    #Offboarding Accounts from PAM
    if ($offboardCandidates) {
        if (!$SkipOffBoarding) {
            Remove-PAMAccounts -SessionToken $PAMSessionToken -AccountList $offboardCandidates
        }
        else {
            Write-Log -Type WRN -Message "Skipping off-boarding activity per solution configuration"
        }
    }
}
catch {
    #Nothing to do but maintaining catch block to suppress error output as this is processed and formatted further down in the call stack
} 
finally {
    $returnCode = 0
    if ($Error.Count) {
        Write-Log -Type WRN -Message "Script execution is being interrupted, aborting"
        $returnCode = 1
    }
    else {
        Write-Log -Type INF -Message "All actions have completed successfully"
    }

    if ($PAMSessionToken) {
        Invoke-APILogoff -SessionToken $PAMSessionToken
        $PAMSessionToken = $null
    }
    if ($EPMSessionToken) {
        $EPMSessionToken = $null
    }

    Write-Log -Footer
    exit $returnCode
}