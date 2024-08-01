# SDO Service Account Password Rotation Script

This PowerShell script automates the rotation of the SDO (Secret Double Octopus) service account password in Active Directory and updates the corresponding SDO directory password.

## Description

This script retrieves and decrypts the API key for the specified SDO API User, generates a new random password, updates the AD account password, and then updates the SDO directory password. It is designed to enhance security by automating the process of password rotation for critical service accounts.

## Features

- Secure handling of API keys using Windows DPAPI.
- Automated password rotation to comply with security policies.
- Email notifications on process failures or successes.

## Prerequisites

- PowerShell 5.1 or higher.
- Active Directory PowerShell module.
- Access to SDO Management Console.

## Installation

1. Clone the repository to your local machine or download the zip file.
2. Place the script and the configuration file in a secure directory.

```bash
git clone https://github.com/justmirsk/SDO-RotateADServiceAccount.git
Edit the config.json file to set up the necessary parameters, such as:

baseUrl: The base URL for the SDO Management Console.
apiUserEmail: The email used for API authentication.
Various paths for storing encrypted and plaintext API keys.
SMTP Relay Options
Ignore TLS Errors: true or false

Usage
Run the script using PowerShell with administrative privileges:
.\RotateSDOServiceAccountPassword.ps1

Contributing
Contributions are welcome. Please fork the repository and submit pull requests to the main branch.

License
This project is licensed under the MIT License - see the LICENSE file for details.

Contact
For support or queries, reach out via GitHub Issues.
