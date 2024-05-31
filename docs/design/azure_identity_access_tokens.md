# Azure Identity Access Tokens

Integration with Azure's user managed identities serves two purposes in Athenz:

1. Athenz users can obtain access tokens for Azure APIs, for their Azure identities,
   through ZTS and by being part of designated Athenz roles.
1. ZTS can access Azure APIs to run an instance provider component internally,
   supporting any number of tenants with an Azure subscription in an easy manner.


## Design

Azure allows its users to exchange ID tokens signed by a designated issuer for access tokens
for a configured user managed identity: 
[Azure reference documentation](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow#third-case-access-token-request-with-a-federated-credential).
This API for federated identities is a bit limited; only the `iss`, `sub` and `aud` claims are relevant:

1. The designated issuer must match the `iss` claim.
1. The `aud` is encouraged to be `api://AzureADTokenExchange`.
1. This means the issuer must use the `sub` claim to differentiate between exchange ID tokens for different Azure identities. 

As the main goal here is to allow Athenz users to translate their Athenz credentials into Azure access tokens,
and we want to use Athenz role membership to control who has access to what federated Azure identities, we propose
the following configuration of the federated identity credentials in Azure:

1. ZTS issues ID tokens with its configured OAuth issuer in the `iss` claim.
1. Each Azure identity is linked to a single Athenz role; this link is established by using the full role ARN, e.g.,
   `coretech:role.azure-client`, as the expected `sub` of the exchange tokens.
1. ZTS uses the suggested `api://AzureADTokenExchange` for the `aud` claim.

We also want the Athenz users to be able to obtain credentials for an Azure identity by its _name_ and enclosing _resource group_,
rather than the UUID-type _client ID_ of the credential. This requires ZTS to have read access to the user managed identities of
the user's Azure subscription, which we solve by configuring a dedicated "Athenz Azure client" identity in the Azure subscription,
with the required read privileges. Giving this identity read privileges to VM instance metadata also allows ZTS to run the Azure
instance provider (below), which is easier than setting up a webserver which runs the provider code within each Azure subscription.


### Required setup

To enable the Azure integration, there is some configuration on the Athenz side for the Athenz system administrators.
Users must do some setup in both Athenz and Azure for onboarding, and also for each new Azure identity to assume.


#### Athenz

Globally, for the whole Athenz system:

1. Create a system role `athenz.azure:role.azure-client`. This represents ZTS, and will allow access to Azure APIs needed to
   verify VM instance identity requests and look up Azure identities.
    1. Ensure all instance providers are members of this role, so they can read VM data.
    1. The Azure Access Token Provider obtains ID tokens for this role without memership checks.
1. Required configuration for the ZTS server (which also runs the instance providers):
    1. `athenz.zts.external_creds_providers=gcp,azure` (Azure is not enabled by default.)
    1. `athenz.zts.oauth_issuer=<ZTS API URL>`
    1. `athenz.zts.azure_resource_uri=api://<ZTS HOSTNAME>`
    1. `athenz.zts.azure_dns_suffix=...` (System-specific.)

For each domain that uses Azure as a cloud provider:

1. Specify Azure _subscription_, _tenant_ and _client_ on the domain; these are system meta attributes, see the below RDL changes for details.
1. For each user managed Azure identity to assume, create a designated role under the domain. Members of this role will be
   able to acquire an access token for the linked Azure identity from ZTS, for configured scope(s):
    1. Create a policy `ALLOW azure.scope_access to <identity> on <scope>`, e.g. allow the linked role default scope access:  
       `ALLOW azure.scope_access to azure-log-reader on https://management.azure.com/.default`.
    1. Not implemented, but a suggestion for later:  
       Create a policy `ALLOW azure.assume_identity to XXX on <resource group>.<client name>`
       that can be used by ZMS to list accessible identities for a user, like for AWS and GCP.


#### Azure

For each Azure tenant:

1. Create the "Athenz Azure client" user managed identity, which ZTS assumes when reading data (VMs and user managed identities, see above):
    1. Add a federated credential which allows ZTS to assume the identity with:
        1. issuer: `<ZTS API URL>`
        1. subject: `athenz.azure:role.azure-client`
        1. audience: `api://AzureADTokenExchange`
    1. Create and assign it a role with permissions:
        1. `Microsoft.ManagedIdentity/userAssignedIdentities/read`
        1. `Microsoft.Compute/virtualMachines/read`
    1. Note the ID of the created identity, and register it on the corresponding Athenz domain, together with the tenant and subscription IDs (see above). 
1. Create an app registration to use as the token audience for VM metadata (required configuration for the SIA agent on Azure VMs), with:
    1. sign-in-audience: `AzureADMultipleOrgs`
    1. identifier-uris: `api://<ZTS HOSTNAME>`
1. Set up additional user managed identities with custom roles, as required:
    1. Add a federated credential which allows members of the designated Athenz role to assume the identity:
        1. issuer: `<ZTS API URL>`
        1. subject: `<domain>:role.<role>`
        1. audience: `api://AzureADTokenExchange`
    1. Note the resource group and name of the identity; these are used when obtaining access tokens through Athenz, see below.

Multiple subscriptions within the same tenant can share the same client setup.


### RDL Struct Updates

`DomainMeta` has two new system meta attribute fields `azureTenant` and `azureClient`:

```rdl
type DomainMeta Struct {
    ...
    
    String azureSubscription (optional); //associated azure subscription id (system attribute - uniqueness check - if enabled)
    String azureTenant (optional); //associated azure tenant id (system attribute)
    String azureClient (optional); //associated azure client id (system attribute)
    ...
}
```


### API Changes


#### Configuring domain for Azure

The new `DomainMeta` fields are updated like `azureSubscription`, through `PUT "/domain/{name}/meta/system/{attribute}"`.
The payload must now contain all three fields (above)—not just the `azureSubscription`. 


#### Obtaining Azure access tokens

To get an access token for the example user managed identity `log-reader` in the Azure resource group `system`, associated with
the Athenz role `azure-log-reader` under the Athenz domain `coretech`, simply do:

```
POST <ZTS API URL>/external/azure/coretech/creds
{ 
  "clientId": "coretech.azure",
  "attributes": {
    "athenzRole": "azure-log-reader",
    "azureResourceGroup": "system",
    "azureClientName": "log-reader",
    “azureScope": <optional: defaults to "https://management.azure.com/.default">
  }
}
```

**Note 1:** The :clientId: should be `<domain>.azure`, although it is not really used for anything. This was done to match the GCP setup.

**Note 2:** It is also possible to specify `"azureClientId"` instead of `"azureResourceGroup"` and `"azureClientName"`. When this is specified,
ZTS skips the client ID lookup, and uses the supplied value instead.
