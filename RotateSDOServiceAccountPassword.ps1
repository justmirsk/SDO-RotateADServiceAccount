<#
.SYNOPSIS
This script automates the rotation of the SDO Service account password in Active Directory.

.DESCRIPTION
Written by Justin Mirsky at Direct Business Technologies. This script is provided as is. 
Direct Business Technologies assumes no responsibility for the content of this script or any outcomes it may have in your environment.
This script retrieves and decrypts the API key for the specified SDO API User, generates a new random password, 
updates the AD account password, and then updates the SDO directory password. 
If any step fails, it sends an error notification; otherwise, it confirms successful execution.

.PARAMETER config
Specifies the path to the JSON configuration file which contains all necessary settings. 
The JSON configuration should include:
- IgnoreTLSErrors: true OR false - Set to true if you do not have a valid TLS certificate on your SDO management console.  Set to false if you have a valid TLS certifcate
- plainTextApiKeyPath: Path to the plaintext API key file.
- encryptedApiKeyPath: Path to the encrypted API key file.
- userId: User ID whose password is to be updated.
- directoryId: SDO directory ID to be updated.
- baseUrl: Base URL for the SDO Management Console.
- apiUserEmail: API user email used for login.
- mailMethod: Preferred method for sending notifications ("SendGrid" or "SMTP").
- SMTP settings if SMTP is used (SMTPServer, SMTPPort, SMTPUsername, SMTPPassword, UseSSL).

.EXAMPLE
PS> .\RotateSDOServiceAccountPassword.ps1
Executes the script to perform the service credential rotation and updates, sending status emails accordingly.

.NOTES
- The machine this script runs on MUST have the ActiveDirectory PowerShell module installed.
- The script requires connectivity to a writable Active Directory Domain Controller.
- The machine must have connectivity to the SDO Management Console (typically on TCP port 8443).
- Only create the API User plaintext document in the specified location for the first run or if you change the API user password/API Key.
  The script will vault the API user credential using Microsoft DPAPI.
- This script is designed to be run as a scheduled task, on a Windows server or machine. 
  It should be run by a gMSA user/service account within Active Directory.
- The gMSA service account in Active Directory will need to be created separately. Instructions on how to create the service account and set up this script can be found at https://www.dbtsupport.com/2024/08/01/creating-gmsa-objects-in-active-directory/.
- Do not change anything in this script, only the JSON file should be updated with the required settings.
- The script and the config.json file should be in the same directory when executed

.LINK
https://dbtsupport.com
#>

Start-Transcript -Path .\"SDO-RotatePassword$(Get-Date -Format yyyyMMddHHmmss).txt"

# Resetting to default secure behavior
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

$jsonContent = Get-Content -Path ".\config.json" | Out-String
$config = ConvertFrom-Json -InputObject $jsonContent

# Convert to hashtable if it's not already
if ($config -isnot [System.Collections.Hashtable]) {
    $tempConfig = @{}
    foreach ($key in $config.PSObject.Properties.Name) {
        $tempConfig[$key] = $config.$key
    }
    $config = $tempConfig
}

#######################
#Function Declarations#
#######################

#Function to ingest credentials and write them out as encrypted files using the DPAPI in Windows
function VaultCredential {
    param (
        [string]$plainTextCredentialPath,
        [string]$encryptedCredentialPath
    )
    
    if (Test-Path -Path $plainTextCredentialPath) {
        $credential = Get-Content -Path $plainTextCredentialPath
        
        $secureCredential = ConvertTo-SecureString -String $credential -AsPlainText -Force
        $encryptedCredential = ConvertFrom-SecureString -SecureString $secureCredential
        Set-Content -Path $encryptedCredentialPath -Value $encryptedCredential
        
        Remove-Item -Path $plainTextCredentialPath -Force
        Write-Output "Credential vaulted and plaintext file removed."
    } else {
        Write-Output "No plaintext credential file found. Using existing encrypted credential."
    }
    
    return $encryptedCredentialPath
}

#Function to decrypt the stored API Keys and Credentials using DPAPI in Windows
function DecryptCredential {
    param (
        [string]$encryptedCredentialPath
    )
    
    $encryptedCredential = Get-Content -Path $encryptedCredentialPath
    $secureCredential = ConvertTo-SecureString -String $encryptedCredential
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureCredential)
    try {
        $decryptedCredential = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    
    return $decryptedCredential
}

#Function to generate a new random password in memory.
function New-RandomPassword {
    $PasswordLength = $config.PasswordLength
    $PasswordChars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@$?"
    $newPassword = -join (1..$PasswordLength | ForEach-Object { Get-Random -Maximum $PasswordChars.Length | ForEach-Object { $PasswordChars[$_] } })
    return $newPassword
}

#Function to set the new password on the Active Directory user object
function Update-ADAccountPassword {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Config,

        [string]$newPassword
    )

    $userid = $config.userId

    try {
        # Convert the plaintext password to a secure string
        $securePassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force
        
        # Attempt to update the AD account password
        Set-ADAccountPassword -Identity $userid -Reset -NewPassword $securePassword
        
        # If successful, write a success message
        Write-Output "Password updated successfully for $userId."
    } catch {
        # Log the error
		$errorMsg = "Failed to update password for $userId. Error: $_"
        Write-Error $errorMsg
        
        # Exit the script with an error code
        throw $errorMsg
    }
}

#Function to check if there are pending publishes on the system.  If there are pending publishes, the script will exit and not update the credential in AD or SDO.
function CheckForPendingPublishes {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Credentials,

        [Parameter(Mandatory = $true)]
        [hashtable]$Config
        )

# Adjust TLS certificate handling based on configuration
    if ($Config.IgnoreTLSErrors) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    } else {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	
    try {
        # Set the login URL
        $apiLoginUrl = $config.baseUrl + "/api/auth/login"
        
        # Prepare JSON payload for the login request
        $jsonLogin = @{
            email = $config.apiUserEmail
            password = $credentials["apiKey"]
        } | ConvertTo-Json

        # Log into the system to get an authentication token
        $loginResponse = Invoke-RestMethod -Method POST -Uri $apiLoginUrl -ContentType 'application/json' -Body $jsonLogin

        # Extract the token and prepare authorization header
        $token = $loginResponse.token
        $header = @{
            "authorization" = "Bearer $token"
        }

        # Check the system for pending publish operations
        $publishUrl = $config.baseUrl + "/api/settings/deploy"
        $pendingPublish = @{
            Method      = "GET"
            Uri         = $publishUrl
            Headers     = $header
            ContentType = "application/json"
        }

        # Invoke the API to check for pending publishes
        $response = Invoke-RestMethod @pendingPublish

        # Output the API response
        Write-Output "Pending Publish API Response: $response"

        # Check if there are pending items
        if ($response -ge 1) {
            $message = "Aborting update due to pending publish items."
            Write-Error $message
            throw $message
        }

    } catch {
        # Catch and handle errors
        $errorMsg = "Error checking for pending publishes. Error: $_"
        Write-Error $errorMsg
        throw $errorMsg
    }
}

#Function to update the SDO Directory with the new service account credential
function Update-SDODirectoryPassword {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Credentials,

        [Parameter(Mandatory = $true)]
        [hashtable]$Config,

        [string]$newPassword
    )

# Adjust TLS certificate handling based on configuration
    if ($Config.IgnoreTLSErrors) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    } else {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	
    try {
        # Set the login URL
        $apiLoginUrl = $config.baseUrl + "/api/auth/login"

        # Prepare JSON payload for the login request
        $jsonLogin = @{
            email = $config.apiUserEmail
            password = $credentials["apiKey"]
        } | ConvertTo-Json

        # Attempt to log into the system to get an authentication token
        $loginResponse = Invoke-RestMethod -Method POST -Uri $apiLoginUrl -ContentType 'application/json' -Body $jsonLogin

        # Extract the token and prepare authorization header
        $token = $loginResponse.token
        $header = @{
            "authorization" = "Bearer $token"
        }

        # Prepare the URL and body for the directory password update
        $directoryUrl = $config.baseUrl + "/api/directories/" + $config.directoryId
        $directoryUpdate = @{
            Method      = "PUT"
            Uri         = $directoryUrl
            Headers     = $header
            ContentType = "application/json"
            Body        = (ConvertTo-Json -InputObject @{ password = $newPassword })
        }

        # Invoke the API to update the directory password
        $response = Invoke-RestMethod @directoryUpdate

        # After updating, perform the publish operation
        $publicationsUrl = $config.baseUrl + "/api/publications"
        $publications = @{
            Method      = "POST"
            Uri         = $publicationsUrl
            Headers     = $header
            ContentType = "application/json"
        }

        # Invoke the API to publish the update
        $publishResponse = Invoke-RestMethod @publications
        
    } catch {
        # Catch and handle errors
        $errorMsg = "Failed to update password for directory ID $config.directoryId. Error: $_"
        Write-Error $errorMsg
        
        # Re-throw the error to be handled at a higher level (e.g., email notification)
        throw $errorMsg
    }
}

#Function to check if Directory ID is associated with LDAP authentication service in SDO.  If it is associated, the script will exit and not change the credential.
# This function is not yet implemented in the script
function CheckLDAPAssociation {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Credentials,

        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )

    # Adjust TLS certificate handling based on configuration
    if ($Config.IgnoreTLSErrors) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    } else {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    try {
        $apiLoginUrl = $config.baseUrl + "/api/auth/login"
        $jsonLogin = @{
            email    = $config.apiUserEmail
            password = $credentials["apiKey"]
        } | ConvertTo-Json

        $loginResponse = Invoke-RestMethod -Method POST -Uri $apiLoginUrl -ContentType 'application/json' -Body $jsonLogin
        $token = $loginResponse.token
        $header = @{
            "authorization" = "Bearer $token"
        }

        $servicesUrl = $config.baseUrl + "/api/services"
        $servicesList = @{
            Method      = "GET"
            Uri         = $servicesUrl
            Headers     = $header
            ContentType = "application/json"
        }

        $response = Invoke-RestMethod @servicesList

        foreach ($service in $response.data) {
            if ($service.type -eq "LDAP") {
                $serviceId = $service.id
				Write-Output "Service ID is $serviceId"
                $ldapServiceURL = $config.baseUrl + "/api/services/" + $serviceId + "/directories"
				Write-Output "ldapserviceUrl is $ldapServiceUrl"
                $serviceDetails = @{
                    Method      = "GET"
                    Uri         = $ldapServiceURL
                    Headers     = $header
                    ContentType = "application/json"
                }

                $serviceResponse = Invoke-RestMethod @serviceDetails

                if ($serviceResponse.id -eq $config.directoryId) {
                    $subject = "Abort: Directory in Use by LDAP Service"
                    $body = "The directory with ID $config.directoryId is currently in use by an LDAP service. Password rotation has been aborted."
                    SendEmail -Subject $subject -Body $body -Credentials $credentials -Config $config
                    throw "Aborting script: Directory in use by LDAP service."
                }
            }
        }
    } catch {
        Write-Error "Failed to check LDAP association: $_"
        throw
    }
}

#Function to send email via SendGrid API (not SMTP)
function Send-SendGridEmail {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Credentials,

        [Parameter(Mandatory = $true)]
        [hashtable]$Config,

        [Parameter(Mandatory=$true)]
        [string]$Subject,

        [Parameter(Mandatory=$true)]
        [string]$Body,

        [Parameter(Mandatory=$false)]
        [string]$SendGridUri = "https://api.sendgrid.com/v3/mail/send"
    )

    # Ensure to access hashtable values correctly
    $SendGridApiKey = $Credentials["sendGridApiKey"]
    $From = $Config["From"]
    $To = $Config["To"]

    $BodyObject = @{
        personalizations = @(
            @{
                to = @(
                    @{
                        email = $To
                    }
                )
                subject = $Subject
            }
        )

        from = @{
            email = $From
        }

        content = @(
            @{
                type = "text/html" # Update content type to HTML
                value = $Body
            }
        )
    }

    $BodyJson = ConvertTo-Json -InputObject $BodyObject -Depth 4

    $Headers = @{
        "Authorization" = "Bearer $SendGridApiKey"
        "Content-Type" = "application/json"
    }

    # Execute the API call and send the email
    try {
        $response = Invoke-RestMethod -Method Post -Uri $SendGridUri -Headers $Headers -Body $BodyJson
    } catch {
        Write-Error "Failed to send email through SendGrid. Error: $_"
        throw
    }
}

#SMTPEmail function has not been fully tested.  Code should work in theory, but it will need to be tested and adjusted possibly.  
function SendEmail {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Subject,

        [Parameter(Mandatory = $true)]
        [string]$Body,

        [Parameter(Mandatory = $true)]
        [hashtable]$Credentials,

        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    # Determine the mail method from configuration and switch accordingly
    switch ($Config.mailMethod) {
        "SendGrid" {
            Send-SendGridEmail -credentials $credentials -config $config -Subject $Subject -Body $Body
        }
        "SMTP" {
			# Create a MailMessage object
            $MailMessage = New-Object System.Net.Mail.MailMessage($Config.From, $Config.To, $Subject, $Body)
            $MailMessage.IsBodyHtml = $true

            # Set up the SMTP client
            $SMTPClient = New-Object System.Net.Mail.SmtpClient($Config.smtpServer, $Config.smtpPort)
            $SMTPClient.EnableSsl = $Config.UseSSL -eq "true"  # Converts string "true"/"false" to Boolean
			Write-Host "SMTPClient SSL is set to $($SMTPClient.EnableSsl)."

            # Add credentials if username is provided
            if ($Config.smtpUsername -and $Credentials["smtpApiKey"]) {
                $SMTPClient.Credentials = New-Object System.Net.NetworkCredential($Config.smtpUsername, $Credentials["smtpApiKey"])
				Write-Host "Username and Password were provided, proceeding with authenticated SMTP session"
            } else {
                $SMTPClient.UseDefaultCredentials = $true
				Write-Host "Username and password do not exist, proceeding with open SMTP relay option"
            }

            try {
                # Send the email
                $SMTPClient.Send($MailMessage)
                Write-Output "Email sent successfully to $($Config.To)"
            } catch {
                Write-Error "Failed to send email. Error: $_"
                throw
            } finally {
                # Dispose of the objects to free up resources
                $MailMessage.Dispose()
                $SMTPClient.Dispose()
            }
        }
    }
}

################
#Initial Checks#
################
# Credential paths mapping
$credentialPaths = @{
    "apiKey" = @{
        "plainText" = $config.plainTextApiKeyPath
        "encrypted" = $config.encryptedApiKeyPath
    }
    "sendGridApiKey" = @{
        "plainText" = $config.plainTextSendGridAPIKeyPath
        "encrypted" = $config.encryptedSendGridAPIKeyPath
    }
    "smtpApiKey" = @{
        "plainText" = $config.plainTextSMTPAPIKeyPath
        "encrypted" = $config.encryptedSMTPKeyPath
    }
}

# Credentials dictionary to hold decrypted values
$credentials = @{}

    # Process each credential
    foreach ($credential in $credentialPaths.Keys) {
        $paths = $credentialPaths[$credential]
        if (Test-Path -Path $paths["plainText"]) {
            VaultCredential -plainTextCredentialPath $paths["plainText"] -encryptedCredentialPath $paths["encrypted"]
        }
        
        if (Test-Path -Path $paths["encrypted"]) {
            $decryptedValue = DecryptCredential -encryptedCredentialPath $paths["encrypted"]
            $credentials[$credential] = $decryptedValue
        } else {
            Write-Host "No encrypted file found for $credential, skipping decryption."
        }
    }

# Check if the API key is present
if (-not $credentials["apiKey"]) {
    $dateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $subject = "ERROR: Missing API Key"
    $body = @"
Errors occurred during the execution:

The SDO API Credential is missing. Either the Encrypted API key file was removed or the PlainText API key was not supplied to be vaulted. Please put the API Key/Password in plain text at $config.plainTextApiKeyPath on host $env:COMPUTERNAME so that the script can vault the credential and run properly.
"@

    # Send email notification about the missing API key
    SendEmail -Subject $subject -Body $body -Credentials $credentials -Config $config
    return
}

# Check if the AD module is available
$adModule = Get-Module -Name "ActiveDirectory" -ListAvailable
if (-not $adModule) {
    # Module not found, prepare the email body with instructions
    $dateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $subject = "ERROR: Active Directory Module Not Installed - $dateTime"
    $body = @"
Failed to import the ActiveDirectory PowerShell module. This module does not appear to be installed on $env:COMPUTERNAME.
Please install the ActiveDirectory module on $env:COMPUTERNAME with the following command in an elevated PowerShell window:

Install-WindowsFeature RSAT-AD-PowerShell
"@
    # Send email notification about the failure
    SendEmail -Subject $subject -Body $body -Credentials $credentials -Config $config
    # Exit the script after sending email
    return
}

# Import the AD module if it's available
Import-Module ActiveDirectory -ErrorAction Stop

###################
#Main Script Logic#
###################

$statusMessages = ""
$isErrorOccurred = $false
try {
    # Check for pending publishes
    CheckForPendingPublishes -credentials $credentials -config $config

	#LDAP Association not working yet, in progress.  Commented out for now.
	#CheckLDAPAssociation -credentials $credentials -config $config
    # If no publishes are pending and directory ID is not associated with LDAP Proxy service, continue with updates
    $newPassword = New-RandomPassword
    Update-ADAccountPassword -config $config -newPassword $newPassword
    Update-SDODirectoryPassword -credentials $credentials -config $config -newPassword $newPassword

} catch {
    $errorMessage = $_.Exception.Message
    $statusMessages += "$errorMessage`n"
    $isErrorOccurred = $true

    # Check if the error was due to authentication failure
    if ($errorMessage -like "*UnauthorizedError*" -or $errorMessage -match "401") {
        $subject = "ERROR: Incorrect API Key - $dateTime"
        $body = "The vaulted API Key for Secret Double Octopus is not accurate. Please update the credential and try again."
        SendEmail -Subject $subject -Body $body -Credentials $credentials -Config $config
        return
    }
}

# Send status email

# Prepare the email details
$dateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
if ($isErrorOccurred) {
    $subject = "ERROR: Automation Status | SDO Service Credential Rotation - $dateTime"
    $body = "Errors occurred during the execution:<br/><br/>$statusMessages"
} else {
    $subject = "SUCCESS: Automation Status | SDO Service Credential Rotation - $dateTime"
    $body = "The SDO Service account credential was successfully updated in Active Directory and the SDO application on $dateTime.<br/><br/>$statusMessages"
}

# Resetting to default secure behavior
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

# Send the email using the SendEmail function
SendEmail -Subject $subject -Body $body -Credentials $credentials -Config $config
