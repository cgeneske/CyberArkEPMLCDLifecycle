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
- Supports on-boarding across a pool of Safes to optimize per-Safe object counts and keep under desired limits
- Flexible Safe and Platform scoping provides continuous management throughout the account lifecycle
- Dynamic FQDN discovery via DNS for "mixed" EPM Sets that contain endpoints with varied domain memberships
- **No hard-coded secrets!**  Choice of CyberArk Central Credential Provider (CCP) or Windows Credential Manager
- Implementation of CCP supports OS User (IWA), Client Certificate, and Allowed Machines authentication
- Non-invasive Report-Only mode, useful for determining candidates for on/off-boarding, prior to go-live
- Safety mechanism to prevent sweeping changes in PAM brought by unexpected environmental changes


Requirements:

- CyberArk Privilege Access Management (PAM) Self-Hosted v11.6+ OR CyberArk Privilege Cloud (Standard/Standalone)
- CyberArk Endpoint Privilege Management (EPM) SaaS
- PAM and EPM API credentials added to CyberArk PAM (CCP) or the Windows Credential Manager
- PowerShell v5 or greater


Script Variables (User-Defined):

ReportOnlyMode          - When set to "$true" will report in console, log, and CSV, which accounts would be on-boarded to, and/or off-boarded from, PAM.  
                          This is a read-only run mode!

SkipOnBoarding          - When set to "$true" will skip the on-boarding logic.

SkipOffBoarding         - When set to "$true" will skip the off-boarding logic.

SkipWindows             - When set to "$true" will skip the on/off-boarding logic for Windows endpoints and acccounts.

SkipMac                 - When set to "$true" will skip the on/off-boarding logic for MacOS endpoints and acccounts.

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

OnboardingPlatformIdMac - Platform ID for the platform to use when on-boarding MacOS LCD accounts.

OnboardingSafesWin       - A list of one or more Safes that Windows LCD accounts will be on-boarded into.

OnboardingSafesMac       - A list of one or more Safes that MacOS LCD accounts will be on-boarded into.

LCDPlatformSearchRegex  - Regular expression for determining which accounts, as assigned to the regex matched LCD-derived platforms, should be 
                          considered "in scope" for making off-boarding determinations.  Used in more advanced setups that require silo'd scopes, 
                          for running multiple script processes against different EPM sets (each associated with a different DNS domain).  
                          In most situations the default value of ".*" will be sufficient.

SafeSearchList          - List of CyberArk Safes which will be searched for existing LCD accounts in PAM, when determining lifecycle candidates.
                          May be left empty (i.e. "") to search all safes.  NOTE: The PAM API user's permissions will also dictate which Safes
                          can and will be searched!

EPMSetIDs               - List of the EPM Set IDs to use for this process.  May be left empty (i.e. "") to use all Sets within the EPM tenant.

EPMRegion               - The region of your EPM SaaS tenant.  Must be set to one of the following values:  US, AU, CA, EU, IN, IT, JP, SG, UK, or BETA

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
1.0     8/24/2023   - Initial Release
1.0.1   8/29/2023   - Added safety mechanism
1.0.2   9/14/2023   - Added safe pooling

DISCLAIMER:
This solution is provided as-is - it is not supported by CyberArk nor an official CyberArk solution.
#>

#Requires -Version 5.0

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

#General Environment Details
$EndpointUserNamesWin = "Administrator"
$EndpointUserNamesMac = "mac_admin"
$EndpointDomainNames = ""
$OnboardingPlatformIdWin = "WinLooselyDevice"
$OnboardingPlatformIdMac = "MACLooselyDevice"
$OnboardingSafesWin = "EPMLCDSTG01","EPMLCDSTG02","EPMLCDSTG03"
$OnboardingSafesMac = "EPMLCDSTG01","EPMLCDSTG02","EPMLCDSTG03"
$LCDPlatformSearchRegex = ".*"
$SafeSearchList = ""
$EPMSetIDs = ""
$EPMRegion = "US"
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

$LogFilePath = $PSScriptRoot + "\Logs\$($MyInvocation.MyCommand.Name.Substring(0, $MyInvocation.MyCommand.Name.Length - 4))_" + (Get-Date -Format "MM-dd-yyyy_HHmmss") + ".log"
$ReportFilePath = $PSScriptRoot + "\Reports\$($MyInvocation.MyCommand.Name.Substring(0, $MyInvocation.MyCommand.Name.Length - 4))_" + (Get-Date -Format "MM-dd-yyyy_HHmmss") + ".csv"
$DatFilePath = $($PSCommandPath).Substring(0, $PSCommandPath.Length - 4) + ".dat"

$EnableSafety = $true
$SafetyTriggered = $false
$SafetyThresholdEPM = 0.10 # 10%
$SafetyThresholdPAM = 0.10 # 10%

$PAMPageSize = 1000 # Maximum is 1,000
$EPMPageSize = 5000 # Maximum is 5,000
$MaximumDNSFailures = 10
$StatusPingInterval = 15
$MaxSafeObjects = 30000
$WarnSafeObjects = 28000
$BulkChunkLimit = 10000

$PAMBaseURI = "https://$PAMHostname/PasswordVault"
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
                }
                "EPM" {
                    $credTarget = $EPMCredTarget
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
    .EXAMPLE
        Invoke-APILogoff
    .NOTES
        The following script-level parameteres are used:
            - $PAMAuthLogoffUrl
            - $PAMSessionToken

        Author: Craig Geneske
    #>
    try {
        Write-Log -Type INF -Message "Attempting to logoff PAM API..."
        Invoke-RestMethod -Method Post -Uri $PAMAuthLogoffUrl -Headers @{ Authorization = $PAMSessionToken} *> $null
        Write-Log -Type INF -Message "PAM API logoff was successful"
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
            else {
                foreach ($pattern in $LCDPlatformSearchRegex) {
                    if ($platform.general.id -match $pattern -and `
                        ($platform.general.platformBaseId -match "^WinLooselyDevice$" -or $platform.general.platformBaseId -match "^Unix$")) {
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
            Write-Log -Type WRN -Message "An exact result of 20,000 accounts may indicate a limitation in your current MaxDisplayed parameter setting which will disrupt this utility!"
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
    Compare-ChangeFactor -PropertyName PAMAccounts -Threshold $SafetyThresholdPAM -Value $PAMAccountsList.Count
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
                    if ($computer.Platform -eq "MacOS" -and $SkipMac) {
                        $ignoreList.Add($computer)
                        Add-Content -Path $ReportFilePath -Value "N/A,$($computer.ComputerName),$($computer.Platform),Ignored,Reported,MacOS lifecycle is disabled per the run configuration" -ErrorAction SilentlyContinue *> $null
                        continue
                    }
                    elseif ($computer.Platform -eq "Windows" -and $SkipWindows) {
                        $ignoreList.Add($computer)
                        Add-Content -Path $ReportFilePath -Value "N/A,$($computer.ComputerName),$($computer.Platform),Ignored,Reported,Windows lifecycle is disabled per the run configuration" -ErrorAction SilentlyContinue *> $null
                        continue
                    }
                    elseif ($computer.Platform -ne "Unknown") {
                        $computersCounter++
                        $EPMComputerList.Add($computer)
                    }
                }
                if ($result.Computers.Count -eq $EPMPageSize) {
                    $offset += $EPMPageSize
                    $computersUri = ($ManagerURL + ($EPMComputersUrl -f $set.Id) + "?limit=$EPMPageSize&offset=$offset")
                }
                $pageCounter++
                if ($timer.elapsed.totalseconds -ge $StatusPingInterval) {
                    Write-Log -Type INF -Message "------> Status Ping: [$computersCounter] computers processed in [$pageCounter] pages so far"
                    $timer.Restart()
                }
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
    Write-Log -Type INF -Message "Qualifying EPM computers with domain names provided (this may take a while)..."
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
                        Add-Content -Path $ReportFilePath -Value "N/A,$($comp.ComputerName),$($comp.Platform),Ignored,Reported,Issue with DNS resolution --> $($_.Exception.Message.Replace(",",";"))" -ErrorAction SilentlyContinue *> $null
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
                    Add-Content -Path $ReportFilePath -Value "N/A,$($comp.ComputerName),$($comp.Platform),Ignored,Reported,DNS domain name not found - skipping per run configuration" -ErrorAction SilentlyContinue *> $null
                    $ignoreList.Add($comp)
                    continue
                }
            }
        }
        elseif ($EndpointDomainNames -and $comp.Platform -eq "Windows") {
            $finalSuffix = "." + $EndpointDomainNames
        }
        
        $qualifiedComps.Add([PSCustomObject]@{
            ComputerName = ($comp.ComputerName + $finalSuffix)
            Platform = $comp.Platform
        })
        
    }
    Write-Log -Type INF -Message "EPM computer qualification complete"
    Compare-ChangeFactor -PropertyName EPMComputers -Threshold $SafetyThresholdEPM -Value $qualifiedComps.Count
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
        A hashtable containing the on-boarding safes for Windows and MacOS and their current quantities
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

    Write-Log -Type INF -Message "###########################################"
    Write-Log -Type INF -Message "#                                         #"
    Write-Log -Type INF -Message "# BEGIN ON-BOARDING ALL CANDIDATES TO PAM #"
    Write-Log -Type INF -Message "#                                         #"
    Write-Log -Type INF -Message "###########################################"
    Write-Log -Type INF -Message "Constructing bulk on-boarding job chunks..."
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
                                          objects with this on-boarding activity.  Please add more safes to the safe pool!".Replace("`n","")
            $haveWarned = $true
        }
        if ($SafePool[$account.Platform][$safeName] -ge $MaxSafeObjects) {
            Write-Log -Type ERR -Message "All safes in the safe pool would reach or exceed the maximum threshold of [$MaxSafeObjects] `
                                          objects, unable to commit on-boarding.  Please add more safes to the safe pool!".Replace("`n","")
            throw
        }
        switch ($account.Platform) {
            "Windows" { $platformId = $OnboardingPlatformIdWin }
            "MacOS" { $platformId = $onboardingPlatformIdMac }
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
        #If both Windows and MacOS safe pools contain the same Safe, we need to increment account counter in both to keep on-boarding distribution even
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
    Write-Log -Type INF -Message "[$($jobChunksJson.Count)] on-boarding job chunks created"

    $successTotal = 0
    $jobIndex = 1
    foreach ($job in $jobChunksJson) {
        try {
            Write-Log -Type INF -Message "Submitting bulk on-boarding job [$jobIndex] of [$($jobChunksJson.Count)] to PAM..."
            $paramsHt = @{
                Method = "Post"
                Uri = $PAMBulkAccountsUrl
                Body = $job.Chunk
                ContentType = "application/json"
                Headers = @{ Authorization = $PAMSessionToken }
            }
            $jobId = Invoke-PAMRestMethod -Parameters $paramsHt
            Write-Log -Type INF -Message "Bulk on-boarding job [$jobIndex] of [$($jobChunksJson.Count)] has been successfully submitted to PAM"
        }
        catch {
            Invoke-ParseFailureResponse -Component PAM -ErrorRecord $_ -Message "Failed to submit bulk on-boarding job [$jobIndex] of [$($jobChunksJson.Count)] to PAM"
            $jobIndex++
            continue
        }

        Write-Log -Type INF -Message "Checking bulk on-boarding job status for job [$jobIndex] of [$($jobChunksJson.Count)] on [$StatusPingInterval] second intervals..."
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
                        Write-Log -Type INF -Message "Bulk on-boarding job [$jobIndex] of [$($jobChunksJson.Count)] is Pending"
                    }
                    "inProgress" {
                        if (!$inProgLogged) {
                            Write-Log -Type INF -Message "Bulk on-boarding job [$jobIndex] of [$($jobChunksJson.Count)] is In-Progress:"
                            $inProgLogged = $true
                        }
                        $success = [int]$jobStatus.SucceededItems.Total
                        $failed = [int]$jobStatus.FailedItems.Total
                        $subTotal = $([int]$jobStatus.SucceededItems.Total + [int]$jobStatus.FailedItems.Total) 
                        $completed = [math]::Round((([int]$jobStatus.SucceededItems.Total + [int]$jobStatus.FailedItems.Total) / $job.Total) * 100)
                        Write-Log -Type INF -Message "---> Job [$jobIndex] of [$($jobChunksJson.Count)] / [$success] Succeeded / [$failed] Failed / [$subTotal of $($job.Total) ($completed%)] Complete"
                    }
                    "completed" {
                        Write-Log -Type INF -Message "Bulk on-boarding job [$jobIndex] of [$($jobChunksJson.Count)] has completed successfully"
                        $shouldRetry = $false
                    }
                    "completedWithErrors" {
                        Write-Log -Type WRN -Message "Bulk on-boarding job [$jobIndex] of [$($jobChunksJson.Count)] has completed with some errors"
                        $shouldRetry = $false
                    }
                    "failed" {
                        Write-Log -Type ERR -Message "Bulk on-boarding job [$jobIndex] of [$($jobChunksJson.Count)] has failed --> $($jobStatus.Result.Error)"
                        $shouldRetry = $false
                    }
                    default { throw "Unexpected value [$($jobStatus.Status)] while waiting for the on-boarding job to complete" }
                }
            }
            catch {
                $shouldRetry = $false
                Invoke-ParseFailureResponse -Component PAM -ErrorRecord $_ -Message "Failed to obtain bulk on-boarding job status for job [$jobIndex] of [$($jobChunksJson.Count)], committing known progress and proceeding"
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
                                $onboardingPlatformIdWin { $platform = "Windows" }
                                $onboardingPlatformIdMac { $platform = "MacOS" }
                            }
                            Add-Content -Path $ReportFilePath -Value "$($account.Username),$($account.Address),$platform,Onboarding,Success," -ErrorAction SilentlyContinue *> $null
                            Update-DatFile -PropertyName PAMAccounts -Value 1 -Append
                            $successTotal++
                        }
                        foreach ($account in $jobStatus.FailedItems.Items) {
                            switch ($account.PlatformId) {
                                $onboardingPlatformIdWin { $platform = "Windows" }
                                $onboardingPlatformIdMac { $platform = "MacOS" }
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
    Write-Log -Type INF -Message "###############################"
    Write-Log -Type INF -Message "#                             #"
    Write-Log -Type INF -Message "# ON-BOARDING TO PAM COMPLETE #"
    Write-Log -Type INF -Message "#                             #"
    Write-Log -Type INF -Message "###############################"
    Write-Log -Type INF -Message "[$successTotal] of [$($AccountList.Count)] accounts were successfully on-boarded"
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
    Write-Log -Type INF -Message "##############################################"
    Write-Log -Type INF -Message "#                                            #"
    Write-Log -Type INF -Message "# BEGIN OFF-BOARDING ALL CANDIDATES FROM PAM #"
    Write-Log -Type INF -Message "#                                            #"
    Write-Log -Type INF -Message "##############################################"
    foreach ($account in $AccountList) {
        try {
            Write-Log -Type INF -Message "Processing [$($actionedTotal + 1)] of [$($AccountList.Count)] ($([math]::Round(($actionedTotal + 1) / $AccountList.Count * 100))%) - Off-boarding account [$($account.id) - $($account.UserName)@$($account.Address)] from PAM..."
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
            Invoke-ParseFailureResponse -Component PAM -ErrorRecord $_ -Message "Failed to off-board account [$($account.UserName)@$($account.Address)] from PAM"
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
    Write-Log -Type INF -Message "##################################"
    Write-Log -Type INF -Message "#                                #"
    Write-Log -Type INF -Message "# OFF-BOARDING FROM PAM COMPLETE #"
    Write-Log -Type INF -Message "#                                #"
    Write-Log -Type INF -Message "##################################"
    Write-Log -Type INF -Message "[$successTotal] of [$($AccountList.Count)] accounts were successfully off-boarded"
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
            Write-Log -Type ERR -Message "EPMRegion is not set to a valid value, one of the following regions must be defined: US, AU, CA, EU, IN, IT, JP, SG, UK, or BETA"
            throw
        }
    }
    else {
        Write-Log -Type ERR -Message "EPMRegion is empty, one of the following regions must be defined: US, AU, CA, EU, IN, IT, JP, SG, UK, or BETA"
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

    Write-Log -Type INF -Message "Script variables have been successfully validated"
}

Function Compare-ChangeFactor {
     <#
    .SYNOPSIS
        Compares the input value against the DAT file's value to determine if the change factor exceeds the allowed threshold
    .DESCRIPTION
        Compares the input value against the DAT file's value to determine if the change factor exceeds the allowed threshold
    .PARAMETER PropertyName
        Name of the property within the DAT file to look for
    .PARAMETER Threshold
        The threshold to be used in the comparison
    .PARAMETER Value
        Value to use for comparison
    .EXAMPLE
        Compare-ChangeFactor -PropertyName "EPMComputers" -Threshold 0.10 -Value 123
    .NOTES
        The following script-level variables are used:
            - $DatFilePath
            - $EnableSafety
            - $SafetyThreshold
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

    try{
        $datFile = Get-Content -Path $DatFilePath | ConvertFrom-Json
        if (!(Get-Member -InputObject $datfile -Name $PropertyName -MemberType Properties)) {
            throw "DAT file does not contain the [$PropertyName] property, please delete the DAT file and try again"
        }
    }
    catch {
        Write-Log -Type ERR -Message "Something went wrong processing the DAT file --> $($_.Exception.Message)"
        throw
    }
    if($datFile.$PropertyName -ne -1 -and $datFile.$PropertyName -ne 0) {
        $changeFactor = [Math]::Abs($value - $datFile.$PropertyName) / $datfile.$PropertyName
        if ($changeFactor -ge $Threshold) {
            if ($ReportOnlyMode) {
                if ($EnableSafety) {
                    Set-Variable -Name SafetyTriggered -Scope Script -Value $true
                    Write-Log -Type WRN "There has been a change of [$($Value - $datFile.$PropertyName) ($([math]::Round($changeFactor * 100))%)] for [$PropertyName] and this will exceed the configured safety threshold of [$Threshold ($([math]::Round($Threshold * 100))%)] in production mode"
                    return
                }
            }
            else {
                if($EnableSafety) {
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
        Determines all on-boarding candidates based on accounts pre-existing in PAM and all existing EPM endpoints.
    .DESCRIPTION
        Determines all on-boarding candidates based on accounts pre-existing in PAM and all existing EPM endpoints.
        Returns a List of PSObject containing the Username, Address, and Platform to be used for on-boarding candidates
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
    Write-Log -Type INF -Message "Determining on-boarding candidates..."

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
    
    $processedCounter = 0
    $timer = [Diagnostics.Stopwatch]::StartNew()
    foreach ($comp in $EPMEndpoints) {
        [List[PSCustomObject]]$potentialOnboardCandidates = @()
        $potentialOnboardCandidates = $PAMAccountsIndex[$comp.ComputerName]
        $usernameList = @()
        switch ($comp.Platform) {
            "Windows" { $usernameList = $EndpointUserNamesWin}
            "MacOS" { $usernameList = $EndpointUserNamesMac}
        }
        foreach ($username in $usernameList) {
            if ($potentialOnboardCandidates) {
                $userNameExistsInPAM = $false
                foreach ($account in $potentialOnboardCandidates) {
                    if ($account.userName -match "^$username$") {
                        $userNameExistsInPAM = $true
                        break
                    }
                }
                if (!$userNameExistsInPAM) {
                    $onboardCandidates.Add([PSCustomObject]@{
                        Username = $username
                        Address = $comp.ComputerName
                        Platform = $comp.Platform
                    })
                }
            }
            else {
                $onboardCandidates.Add([PSCustomObject]@{
                    Username = $username
                    Address = $comp.ComputerName
                    Platform = $comp.Platform
                })
            } 
        }
        $processedCounter++
        if ($timer.elapsed.totalseconds -ge $StatusPingInterval) {
            Write-Log -Type INF -Message "---> Status Ping: [$processedCounter] of [$($EPMEndpoints.Count)] ($([math]::Round($processedCounter / $EPMEndpoints.Count * 100))%) EPM endpoints processed"
            $timer.Restart()
        }
    }
    $timer.Reset()
    $timer = $null
    Write-Log -Type INF -Message "[$($onboardCandidates.Count)] account(s) identified for on-boarding"
    return $onboardCandidates
}

Function Get-OffBoardingCandidates {
    <#
    .SYNOPSIS
        Determines all off-boarding candidates based on accounts pre-existing in PAM and all existing EPM endpoints.
    .DESCRIPTION
        Determines all off-boarding candidates based on accounts pre-existing in PAM and all existing EPM endpoints.
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
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $processedCounter = 0
    Write-Log -Type INF -Message "Determining off-boarding candidates..."

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

    foreach ($account in $PAMAccounts) {
        foreach ($ignoredComp in $IgnoreList) {
            if ($ignoredComp.ComputerName -match "^$($account.Instance.Address).*$") {
                continue
            }
        }
        if (!$EPMComputersIndex[$account.Instance.Address]) {
            $usernameList = @()
            switch ($account.PlatformBaseID) {
                "WinLooselyDevice" { $usernameList = $EndpointUserNamesWin; $compPlatform = "Windows" }
                "Unix" { $usernameList = $EndpointUserNamesMac; $compPlatform = "MacOS" }
            }
            foreach ($username in $usernameList) {
                if ($account.Instance.UserName -match "^$username$") {
                    $account.Instance | Add-Member -NotePropertyName CompPlatform -NotePropertyValue $compPlatform
                    $offboardCandidates.Add($account.Instance)
                }
            }
        }
        $processedCounter++
        if ($timer.elapsed.totalseconds -ge $StatusPingInterval) {
            Write-Log -Type INF -Message "---> Status Ping: [$processedCounter] of [$($PAMAccounts.Count)] ($([math]::Round($processedCounter / $PAMAccounts.Count * 100))%) PAM accounts processed"
            $timer.Restart()
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
        Write-Log -Type INF -Message "The following [$($OnboardCandidates.Count)] account(s) have been identified for on-boarding:"
        foreach ($candidate in $OnboardCandidates) {
            Write-Log -Type INF -Message "---> Username: [$($candidate.Username)] | Address: [$($candidate.Address)]"
            Add-Content -Path $ReportFilePath -Value "$($candidate.Username),$($candidate.Address),$($candidate.Platform),Onboarding,Reported," -ErrorAction SilentlyContinue *> $null
        }
    }
    else {
        Write-Log -Type INF -Message "No accounts have been identified for on-boarding"
    }

    if ($OffboardCandidates) {
        Write-Log -Type INF -Message "The following [$($OffboardCandidates.Count)] account(s) have been identified for off-boarding:"
        foreach ($candidate in $OffboardCandidates) {
            Write-Log -Type INF -Message "---> Username: [$($candidate.Username)] | Address: [$($candidate.Address)]"
            Add-Content -Path $ReportFilePath -Value "$($candidate.Username),$($candidate.Address),$($candidate.CompPlatform),Offboarding,Reported," -ErrorAction SilentlyContinue *> $null
        }
    }
    else {
        Write-Log -Type INF -Message "No accounts have been identified for off-boarding"
    }

    if ($IgnoreList) {
        Write-Log -Type INF -Message "The following [$($ignoreList.Count)] endpoint(s) were ignored -- see the report file for full context:"
        foreach ($comp in $ignoreList) {
            Write-Log -Type INF -Message "---> Endpoint: [$($comp.ComputerName)]"
            #Ignored endpoints are added to the report file at their time of discovery regardless of the run mode, so we don't need to Add-Content here
        }
    }
    else {
        Write-Log -Type INF -Message "No endpoints have been ignored"
    }
    if($SafetyTriggered) {
        Write-Log -Type WRN -Message "--> SAFETY TRIGGERED <--"
        Write-Log -Type WRN -Message "EPM Computers or PAM accounts have changed by more than their respective thresholds since last execution.  See log entry above for more details"
    }
    Write-Log -Type INF -Message "###################################################################"
}

#endregion

################################################### SCRIPT ENTRY POINT ##################################################

$Error.Clear()

#Create Log File
try {
    New-Item -Path $LogFilePath -Force -ErrorAction Stop *> $null
}
catch {
    Write-Host "Unable to create log file at [$LogFilePath], aborting script --> $($_.Exception.Message)"
    exit 1
}

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
    exit 1
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
        Write-Host "Unable to create DAT file at [$DatFilePath], aborting script --> $($_.Exception.Message)"
        exit 1
    }
}

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

    Set-Variable -Scope Script -Name PAMSessionToken -Value $(Invoke-APIAuthentication -App PAM)

    $LCDPlatforms = Get-PAMActiveLCDPlatforms

    $getAccountsParams = @{
        LCDPlatformList = $LCDPlatforms
    }

    if ($SafeSearchList) {
        $getAccountsParams.Add("SafeSearchList", $SafeSearchList)
    }

    #Get all existing LCD Accounts in PAM
    [List[PSCustomObject]]$PAMAccounts, [hashtable]$SafePool = Get-PAMLCDAccounts @getAccountsParams

    #Get all EPM Computers
    $EPMSessionInfo = Invoke-APIAuthentication -App EPM
    [List[PSCustomObject]]$EPMEndpoints, [List[PSCustomObject]]$ignoreList = Get-EPMComputers -SessionToken $EPMSessionInfo.EPMAuthenticationResult -ManagerURL $EPMSessionInfo.ManagerURL

    #Determine on-boarding candidates
    [List[PSCustomObject]]$onboardCandidates = Get-OnBoardingCandidates -PAMAccounts $PAMAccounts -EPMEndpoints $EPMEndpoints

    #Determine off-boarding candidates
    [List[PSCustomObject]]$offboardCandidates = Get-OffBoardingCandidates -PAMAccounts $PAMAccounts -EPMEndpoints $EPMEndpoints -IgnoreList $ignoreList

    #Printing report if in Report-Only mode, then exiting
    if ($ReportOnlyMode) {
        Write-PAMLifecycleReport -OnboardCandidates $onboardCandidates -OffboardCandidates $offboardCandidates -IgnoreList $ignoreList
        exit
    }

    #On-boarding Accounts to PAM
    if ($onboardCandidates) {
        if (!$SkipOnBoarding) {
            Add-PAMAccountsBulk -AccountList $onboardCandidates -SafePool $SafePool
        }
        else {
            Write-Log -Type WRN -Message "Skipping on-boarding activity per solution configuration"
        }
    }

    #Off-boarding Accounts from PAM
    if ($offboardCandidates) {
        if (!$SkipOffBoarding) {
            Remove-PAMAccounts -AccountList $offboardCandidates
        }
        else {
            Write-Log -Type WRN -Message "Skipping off-boarding activity per solution configuration"
        }
    }
}
catch {
    #Nothing to do but maintaining catch block to suppress error output as this is processed and formatted further down in the call stack
    #Write-Log -Type ERR -Message $_.Exception.Message
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
        Invoke-APILogoff
        Set-Variable -Scope Script -Name PAMSessionToken -Value $null
    }
    if ($EPMSessionInfo) {
        $EPMSessionInfo = $null
    }

    #Deleting report file if nothing was written to it
    if (Test-Path -Path $ReportFilePath) {
        $numLines = (Get-Content -Path $ReportFilePath | Measure-Object -Line).Lines
        if ($numLines -eq 1) {
            Remove-Item -Path $ReportFilePath -Force -ErrorAction SilentlyContinue *> $null
        }
    }

    Write-Log -Footer
    exit $returnCode
}