# exchange-online-quarantine-report

## Use case description

## Feature overview

## Preparations
1. Create Azure automation account
   1. Create PowerShell runbook
   2. Enable managed identity
2. Create Azure key vault
   1. Create self-signed certificate
   2. Grant access for managed identity to certificate
3. Create Azure AD application
   1. Grant application permission _Exchange.ManageAsApp_
   2. Grant Azure AD role _Exchange Administrator_
   3. Attach certificate

## Links
- [Azure automation runbook](https://docs.microsoft.com/en-us/azure/automation/quickstarts/create-account-portal)
- [Azure key vault](https://docs.microsoft.com/en-us/azure/key-vault/general/quick-create-portal)
- [Azure AD application](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
