# Developer Guide - Centralized Access Control
----------------------------------------------

* [Client - Obtaining NTokens from SIA Provider](#client---obtaining-ntokens-from-sia-provider)
* [Server - Authorization Checks](#server---authorization-checks)

In the centralized access control model, the service as a principal
requests its NToken from SIA Provider and then presents it to the
target service which would perform an identical check with ZMS to confirm
access.

![Authenticated Service as Principal](images/centralized_authz_for_services.png)

The required steps to setup the environment for provider and tenant
services to support centralized access control are as follows:

* System administrator creates the provider and tenant domains.
* Tenant Domain administrator generates a public/private key pair
  and registers a service in its domain.
* Provider Domain administrator creates a role and policy that
  grants access to the given role with configured action and resource.
* Provider Domain administrator adds the Tenant Service to the
  role to grant access.
* Tenant Domain administrator installs the private key on the host
  that will be running the client/tenant service.
  
The next two sections describe the code changes that the developers
must make to their services to support authorized access.

## Client - Obtaining NTokens from SIA Provider
-----------------------------------------------

First you need to update your Java project `pom.xml` file to indicate
the dependency on the Athenz auth_core Library:

```
<dependency>
    <groupId>com.yahoo.athenz</groupId>
    <artifactId>auth_core</artifactId>
    <version>1.X.Y</version>
</dependency>
```

The domain administrator must have already generated a public/private key pair
for the service and registered public key in Athenz. The private key must be
available on the host where the service will be running.

```
    // we're going to extract our private key from a given file
    
    File rsaPrivateKey = new File("/home/athenz/service/rsa_private.key");
    PrivateKey privateKey = Crypto.loadPrivateKey(rsaPrivateKey);
    
    // setup the key identifier that the corresponding public key
    // has been registered in ZMS, and set the timeout to be 1 hour
    
    String keyId = "v0";
    long tokenTimeout = TimeUnit.SECONDS.convert(1, TimeUnit.HOURS);
    
    // create our authority and sia provider object
    
    Authority authority = new PrincipalAuthority();
    SimpleServiceIdentityProvider siaProvider = 
        new SimpleServiceIdentityProvider(authority, privateKey, keyId, tokenTimeout);
    
    // generate a principal for our given domain and service
    
    Principal principal = siaProvider.getIdentity(domainName, serviceName);
    
    // include the principal.getSignedToken() string as the value for the
    // Athenz-Principal-Auth header
```

## Server - Authorization Checks
--------------------------------

On the server side the we just need to determine the specific requests
action and the resource, extract the NToken string from the
Athenz-Principal-Auth header value and contact ZMS to carry out the
authorization check.

First you need to update your Java project `pom.xml` file to indicate
the dependency on the Athenz zms java client Library:

```
<dependency>
    <groupId>com.yahoo.athenz</groupId>
    <artifactId>zms_java_client</artifactId>
    <version>1.X.Y</version>
</dependency>
```

Now, the most important part of the rest of the required code is to
determine the resource and action based on the given http request.
Once you have those two values determined, then all that is left
is to extract the NToken and contact ZMS for the authorization
check.

```
    HttpServletRequest req = (HttpServletRequest)servletRequest;
    
    // your method of extracting the resource value from the http
    // request. It might need to look at just the URI or possibly
    // the full body of the request.

    String resource = translateToMyServiceResource(req);
    
    // your method of extracting an action string from the http
    // request.
    
    String action = translateToMyServiceAction(req);
    
    // finally extract the ntoken from the header.

    String nToken = req.getHeader(“Athenz-Principal-Auth”);
    
    // create a zms authorizer and contact ZMS to carry out the check
    
    ZMSAuthorizer authorizer = new ZMSAuthorizer(serviceDomain);
    boolean access = authorizer.access(action, resource, nToken, null);
    

 
