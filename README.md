# CyberArk EPM LCD Lifecycle Utility

Organizations seeking to reduce and eliminate privilege escalation abuse, credential theft, and ransomware threats often turn to CyberArk's Endpoint Privilege Manager (EPM) for its effective suite of controls.  In concert with dialing in these least-privilege and application controls, EPM can also seamlessly integrate with CyberArk's Self-Hosted Privilege Access Management (PAM) and Privilege Cloud SaaS platforms, to provide agent-enhanced, loosely-connected, credential management capabilities for their local administrator accounts.

This solution leverages both PAM and EPM APIs to compare the computers (agents) that exist in EPM against related local account management subjects that exist in PAM, automatically determining and executing the needed onboarding and offboarding actions in PAM, to maintain parity.  As new agents come online in EPM, named local accounts will be on-boarded to PAM.  Likewise as agents are pruned from EPM through organic inactivity-based attrition, their named local accounts will be off-boarded from PAM.

>**Note**: This solution is provided as-is, it is not supported by CyberArk nor an official CyberArk solution

## Features

- Complete lifecycle management (on-boarding and off-boarding) for named local accounts in PAM that are based on LCD
- Designed to be run interactively or via Scheduled Task, from a central endpoint that has access to the PAM and EPM APIs (i.e. The CPM)
- Supports separate on-boarding Safes for staging Mac and Windows accounts
- Flexible Safe and Platform scoping for continuous management - LCD accounts can move from Staging Safes or Platforms during their lifespan
- Dynamic FQDN discovery via DNS for "mixed" EPM Sets that contain endpoints with heterogeneous domain memberships
- **No hard-coded secrets!**  Supports CyberArk Central Credential Provider (CCP) and Windows Credential Manager for secure retrieval of the needed API credentials
- Implementation of CCP supports OS User (IWA), Client Certificate, and Allowed Machines authentication types
- Non-invasive Report-Only mode, useful for determining which accounts are candidates for on-boarding to, or off-boarding from, PAM, prior to go-live

# Environment Setup

## Prerequisites

- CyberArk Privilege Access Management (PAM) v11.3+ OR CyberArk Privilege Cloud (Standard/Standalone)
- CyberArk Endpoint Privilege Management (EPM) SaaS

## PAM API User Permissions
>Coming Soon!

## Running via Scheduled Task
>Coming Soon!

## Assigning Script Variables

There are a series of script variables that must be set off default, to values that are pertinent to your executing environment.  These variables are declared in the "SCRIPT VARIABLES" region at the top of the script between the `### BEGIN CHANGE-ME SECTION ###` and `### END CHANGE-ME SECTION ###` comment markers:

- `$ReportOnlyMode`
    - When set to `$true` will report in console, log, and CSV, which accounts would be on-boarded to, and/or off-boarded from, PAM. This is a read-only run mode!
- `$SkipOnBoarding`
    - When set to `$true` will skip the on-boarding logic.
- `$SkipOffBoarding`
    - When set to `$true` will skip the off-boarding logic.
- `$EndpointUserNamesWin`
    - List of one or more usernames to lifecycle manage for all Windows-based EPM endpoints.
- `$EndpointUserNamesMac`
    - List of one or more usernames to lifecycle manage for all Mac-based EPM endpoints.
- `$EndpointDomainNames`
    - List of one or more DNS domain names that EPM endpoints have membership to. Applicable only for Windows endpoints as Mac endpoints are assumed to have no domain name. Used with the "ValidateDomainNamesDNS" and "SkipIfNotInDNS" -- See below for complete info on these variables.
        - If `$ValidateDomainNamesDNS` is set to `$false`, `$EndpointDomainNames` must be set to a single domain name or empty (i.e. "").  
        - If `$ValidateDomainNamesDNS` is set to `$true`, `$EndpointDomainNames` may remain empty, contain a single domain name, or contain multiple domain names.  
        - If `$ValidateDomainNamesDNS` is set to `$true` and `$EndpointDomainNames` is empty, the DNS Client's Suffix Search List will be used.

        <br/>
        Valid Examples / Scenarios:
        <br/>
        <br/>
        
        Disable Domain Name resolution via DNS and consider all EPM endpoints as having a standard domain-name of "cybr.com":
        ```powershell
        $EndpointDomainNames = "cybr.com"
        $ValidateDomainNamesDNS = $false
        ```

        Disable Domain Name resolution via DNS and consider all EPM endpoints as having no domain name:
        ```powershell
        $EndpointDomainNames = ""
        $ValidateDomainNamesDNS = $false
        ```
                            
        Enable Domain Name resolution via DNS and consider EPM endpoints WILL have membership in one of several possible domain names (will skip candidacy if unable to resolve in DNS):
        ```powershell
        $EndpointDomainNames = @("cybr.com", "childA.cybr.com", "childB.cybr.com")
        $ValidateDomainNamesDNS = $true`
        $SkipIfNotInDNS = $true`
        ```

        Enable Domain Name resolution via DNS and consider EPM endpoints MAY have membership in one of several possible domain names or are otherwise domain-less (Will assume no domain name for candidacy, if unable to resolve in DNS):
        ```powershell
        $EndpointDomainNames = @("cybr.com", "childA.cybr.com", "childB.cybr.com")
        $ValidateDomainNamesDNS = $true
        $SkipIfNotInDNS = $false
        ```

- `$OnboardingPlatformIdWin`
    - Platform ID for the platform to use when on-boarding Windows LCD accounts.
- `$OnboardingPlatformIdMac`
    - Platform ID for the platform to use when on-boarding Mac LCD accounts.
- `$OnboardingSafeWin`
    - The CyberArk Safe name that Windows LCD accounts will be on-boarded into.
- `$OnboardingSafeMac`
    - The CyberArk Safe name that Mac LCD accounts will be on-boarded into.
- `$LCDPlatformSearchRegex`
    - Regular expression for determining which accounts, as assigned to the regex matched LCD-derived platforms, should be considered "in scope" for making off-boarding determinations.  Used in more advanced setups that require silo'd scopes, for running multiple script processes against different EPM sets (each associated with a different DNS domain).  In most situations the default value of ".*" will be sufficient.
- `$SafeSearchList`
    - List of CyberArk Safes which will be searched for existing LCD accounts in PAM, when determining lifecycle candidates.  May be left empty (i.e. "") to search all safes.  NOTE: The PAM API user's permissions will also dictate which Safes can and will be searched!
- `$EPMSetIDs`
    - List of the EPM Set IDs to use for this process.  May be left empty (i.e. "") to use all Sets within the EPM tenant.
- `$PAMHostname`
    - The base hostname of the Self-Hosted PAM or Privilege Cloud (Standard/Standalone) (i.e. "customer.privilegecloud.cyberark.com")
- `$IgnoreSSLCertErrors`
    - When set to `$true` will ignore any TLS/SSL untrusted certificate errors that would normally prevent the connection. It is recommended to leave this value as `$false` to ensure certificates are verified!
- `$ValidateDomainNamesDNS`
    - When set to `$true` will leverage DNS lookups to attempt discovery of EPM endpoint FQDNs for on-boarding accuracy.
    Used with `$EndpointDomainNames` (See entry above for more details).
    Used with `$SkipIfNotInDNS` (See entry below for more details).
- `$SkipIfNotInDNS`
    - When set to `$true` will skip candidacy for any EPM Endpoints that cannot be explicitly resolved in DNS.  When set to `$false`, endpoints in EPM that cannot be DNS resolved, will be considered "domain-less" for lifecycle candidacy.  Only used when `$ValidateDomainNamesDNS` is set to `$true`, otherwise this can be ignored.
- `$APIUserSource`
    - Determines the source for PAM and EPM API credential lookup.  There are two possible settings:

        ```powershell
        [APIUserSource]::WinCredMgr
        ```
        Will use the Windows Credential Manager for API credential lookup

        ```powershell
        [APIUserSource]::CyberArkCCP
        ```
        Will use CyberArk Central Credential Provider for API credential lookup

        CyberArk CCP is generally recommended wherein available, as this simplifies solution setup and allows for regular credential rotation for the API users without the need to update any configuration points on the solution's host.
- `$PAMCredTarget`
    - The "Internet or network address" value that was used when entering the PAM API credential into Windows Credential Manager.  
    
        Used with an APIUserSource of `[APIUserSource]::WinCredMgr`, otherwise this can be ignored.
- `$EPMCredTarget`
    - The "Internet or network address" value that was used when entering the EPM API credential into Windows Credential Manager.
    
        Used with an APIUserSource of `[APIUserSource]::WinCredMgr`, otherwise this can be ignored.
- `$CCPAuthType`
    - Determines the authentication type against CCP when used as the API user source.  There are three possible settings:

        ```powershell
        [CCPAuthType]::OSUser
        ```
        **RECOMMENDED** Will use OS User (Integrated Windows Authentication) to authenticate to the CCP

        ```powershell
        [CCPAuthType]::Certificate
        ```
        **RECOMMENDED** Will use Client Certificate to authenticate to the CCP

        ```powershell
        [CCPAuthType]::AllowedMachines
        ```
        Will depend solely upon an allowed machines listing in CyberArk for authentication

        >**NOTE:**  Allowed Machines authentication may be layered on to OSUser or Certificate based authentication in the CyberArk configuration.  
        
        Used with an APIUserSource of `[APIUserSource]::CyberArkCCP`, otherwise this can be ignored.
- `$CertThumbprint`
    - The SHA1 thumbprint of the client certificate to use for authentication to CCP.
    
        Used with an APIUserSource of `[APIUserSource]::CyberArkCCP`, and with a CCPAuthType of `[CCPAuthType]::Certificate`, otherwise this can be ignored.
- `$PAMAccountName`
    - The account name (aka object name) of the vaulted account that represents the PAM API credential.
    
        Used with an APIUserSource of `[APIUserSource]::CyberArkCCP`, otherwise this can be ignored.
- `$PAMObjectSafe`
    - The Safe where the vaulted account that represents the PAM API credential is held in CyberArk.
    
        Used with an APIUserSource of `[APIUserSource]::CyberArkCCP`, otherwise this can be ignored.
- `$EPMAccountName`
    - The account name (aka object name) of the vaulted account that represents the EPM API credential.
    
        Used with an APIUserSource of `[APIUserSource]::CyberArkCCP`, otherwise this can be ignored.
- `$EPMObjectSafe`
    - The Safe where the vaulted account that represents the EPM API credential is held in CyberArk.
    
        Used with an APIUserSource of `[APIUserSource]::CyberArkCCP`, otherwise this can be ignored.
- `$CCPHostname`
    - The base hostname of the CyberArk CCP (i.e. "ccp.cybr.com")
    
        Used with an APIUserSource of `[APIUserSource]::CyberArkCCP`, otherwise this can be ignored.
- `$CCPPort`
    - The port number for the CyberArk CCP listener (i.e. 443)
    
        Used with an APIUserSource of `[APIUserSource]::CyberArkCCP`, otherwise this can be ignored.
- `$CCPServiceRoot`
    - The IIS application/service root that should be used for the web call to CCP (i.e. AIMWebService).
    
        Used with an APIUserSource of `[APIUserSource]::CyberArkCCP`, otherwise this can be ignored.
- `$CCPAppID`
    - The Application ID registered in CyberArk that should be used identification to CCP.
    
        Used with an APIUserSource of `[APIUserSource]::CyberArkCCP`, otherwise this can be ignored.

# Usage and Examples

## Advanced EPM Set Targeting and Scoping
>Coming Soon!

## Logging
>Coming Soon!

## Limitations and Known Issues
>Coming Soon!

## Interactive Output Example

```powershell
CyberArk_EPMLCD_Lifecycle.ps1
```

![Example Variables](images/VariablesExample.PNG)
![Example Output](images/OutputExample.PNG)