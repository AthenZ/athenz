# Developer guide - Decentralized Access Control
------------------------------------------------

* [Client - Obtaining RoleTokens from ZTS Server](#client---obtaining-roletokens-from-zts-server)
    * [Obtaining ServiceIdentityProvider object](#obtaining-serviceidentityprovider-object)
    * [ZTS Client Object](#zts-client-object)
    * [Obtaining a Role Token](#obtaining-a-role-token)
        * [ZTS getRoleToken Error Codes](#zts-getroletoken-error-codes)
    * [Token Caching](#token-caching)
    * [Token Prefetch Caching](#token-prefetch-caching)
* [Server - Authorization Checks](#server---authorization-checks)

In the decentralized access control model, the client service/user
presents an authentication token (NToken) from SIA Provider to get an
authorization token (ZToken) from ZTS, and then presents the ZToken
to a target service to access its resources.

![Decentralized Authorization for Services](images/decentralized_authz_for_services.png)

The required steps to setup the environment for provider and tenant
services to support decentralized access control are as follows:

* System administrator creates the provider and tenant domains.
* Tenant Domain administrator generates a public/private key pair
  and registers a service in its domain.
* Provider Domain administrator creates a role and policy that
  grants access to the given role with configured action and resource.
* Provider Domain administrator adds the Tenant Service to the
  role to grant access.
* Provider Domain administrator installs Athenz Policy Engine
  Updater (ZPU) on the hosts that will be running the provider
  service. ZPU must be configured with the provider domain name
  and setup to run as a cron job to periodically download the
  latest policy files for the server/provider domain.
* Tenant Domain administrator installs the private key on the host
  that will be running the client/tenant service.
  
The next two sections describe the code changes that the developers
must make to their services to support authorized access.

## Client - Obtaining RoleTokens from ZTS Server
------------------------------------------------

The client must carry out two major steps in order to retrieve a role
token from ZTS Server. First, using the service's name and private key
it needs to generate a ServiceIdentityProvider object which then it
can use to retrieve a role token using ZTS Client Library.

### Obtaining ServiceIdentityProvider object
--------------------------------------------

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
```

### ZTS Client Object
---------------------

First you need to update your Java project `pom.xml` file to indicate
the dependency on the ZTS Java Client Library:

```
<dependency>
    <groupId>com.yahoo.athenz</groupId>
    <artifactId>zts_java_client</artifactId>
    <version>1.X.Y</version>
</dependency>
```

ZTS Client Library provides several constructors; however, the most
commonly used one would be the constructor to create a client object
based on a given domain and service identifier.

```
    /**
    * Constructs a new ZTSClient object with the given service identity
    * and media type set to application/json. The url for ZTS Server is
    * automatically retrieved from the athenz_config package's configuration
    * file (zts_url field). The service's principal token will be retrieved
    * from the SIA Provider.
    * Default read and connect timeout values are 30000ms (30sec). The application can
    * change these values by using the yahoo.zts_java_client.read_timeout and
    * yahoo.zts_java_client.connect_timeout system properties. The values specified
    * for timeouts must be in milliseconds.
    * @param domainName name of the domain
    * @param serviceName name of the service
    * @param siaProvider ServiceIdentityProvider object for the given service
    */
    public ZTSClient(String domainName, String serviceName, ServiceIdentityProvider siaProvider);
```

ZTSClient object must be closed to release any allocated resources. ZTSClient
class implements Closeable interface.

The client library automatically retrieves the URL of the ZTS server
from its configuration file.

For example, if you have already registered service called `storage` in
the domain `athenz`, use the command below to instantiate a ZTS
Client object:

```
    SimpleServiceIdentityProvider siaProvider = 
        new SimpleServiceIdentityProvider(authority, privateKey, keyId, tokenTimeout);
    try (ZTSClient ztsClient = new ZTSClient("athenz", "storage", siaProvider)) {
       // carry out requests against ZTS Server
    }
```

If your application will only handle a single service, then rather than
creating and destroying a ZTSClient object for every request, you can
just create a single instance of the ZTSClient and use that instance
by multiple threads to request role tokens:

```
    // in your service initialization method
    
    void initZTSClient(String domainName, String serviceName, String privateKeyPath, String keyId) {
    
        File rsaPrivateKey = new File("/home/athenz/service/rsa_private.key");
        PrivateKey privateKey = Crypto.loadPrivateKey(rsaPrivateKey);
    
        // set the timeout to be 1 hour
    
        long tokenTimeout = TimeUnit.SECONDS.convert(1, TimeUnit.HOURS);
    
        // create our authority and sia provider object
    
        Authority authority = new PrincipalAuthority();
        SimpleServiceIdentityProvider siaProvider = 
            new SimpleServiceIdentityProvider(authority, privateKey, keyId, tokenTimeout);
        ztsClient = new ZTSClient(domainName, serviceName, siaProvider);
    }
    
    // then in our service processing code you can use the ztsClient
    // instance to retrieve role tokens for your requested domain and role
    
    RoleToken roleToken = ztsClient.getRoleToken(providerDomain, roleName);
```

### Obtaining a Role Token
--------------------------

To obtain a Role Token, the application would use one the following methods
from the `ZTSClient` class:

```
    /**
     * For the specified requester(user/service) return the corresponding Role Token that
     * includes the list of roles that the principal has access to in the specified domain.
     * The client will automatically fulfill the request from the cache, if possible.
     * The default minimum expiry time is 900 secs (15 mins).
     * @param domainName name of the domain
     * @return ZTS generated Role Token. ZTSClientException will be thrown in case of failure
     */
    public RoleToken getRoleToken(String domainName);
    
    /**
     * For the specified requester(user/service) return the corresponding Role Token that
     * includes the specified role name that the principal has access to in the specified
     * domain. The client will automatically fulfill the request from the cache, if possible.
     * The default minimum expiry time is 900 secs (15 mins).
     * @param domainName name of the domain
     * @param roleName only interested in roles with this value
     * @return ZTS generated Role Token. ZTSClientException will be thrown in case of failure
     */
    public RoleToken getRoleToken(String domainName, String roleName);
```

In the simplest case, the method only requires the caller to specify the
domain that the application will be accessing. Thus, it needs a Role
Token for that domain. For example, if the `athenz.storage` service
identifier is trying to access a resource from a domain `weather`, then
the API call to retrieve the `roleToken` would be the following:

```
    RoleToken roleToken = null;
    try {
       roleToken = ztsClient.getRoleToken("weather");
    } catch (ZTSClientException ex) {
       // log error using ex.getCode() and ex.getMessage()
    }
```

Then the client will include the retrieved Role Token value as one of
its headers when submitting its request to the provider service:

```
    ztsClient.getHeader();  // returns Header name: "Athenz-Role-Auth"
    roleToken.getToken() // returns header value 
```

However, the above method returns a RoleToken that includes all the roles
the given principal has access to the provider domain. This may not be
desirable as it violates the principle of least privilege. Instead, the
caller should (in fact, the system administrator has the option to require
this rather than making it possible) specify the roleName that it requires
to complete its request.For example, if the `athenz.storage` service
identifier is trying to access a resource from a domain `weather` and requires
only read access which is granted to the service as being member of the `readers`
role in the `weather` domain, then the API call to retrieve the `roleToken`
would be the following:

```
    RoleToken roleToken = null;
    try {
       roleToken = ztsClient.getRoleToken("weather", "readers");
    } catch (ZTSClientException ex) {
       // log error using ex.getCode() and ex.getMessage()
    }
```

#### ZTS getRoleToken Error Codes
---------------------------------

When communicating with ZTS Server to obtain a RoleToken, the ZTS Server
will return the following 4xx error codes if it's unable to successfully
process the request:

-   **400** The domain name specified in the request to issue a
    RoleToken for contains invalid characters.
-   **401** The request could not be successfully authenticated. This
    usually indicates that either the Service is not properly registered
    in ZMS or there is a mismatch between the registered public key and
    the private key that was used to generate the ServiceToken.
-   **403** The service identity does not have access to any resources
    in the specified domain.
-   **404** The domain specified in the request to issue a RoleToken for
    does not exist.

### Token Caching
-----------------

The ZTS Client Library automatically caches any tokens returned by the
ZTS Server, so any subsequent requests for a Role Token for the same
domain are fulfilled from the local cache as opposed to connecting to
the ZTS Server every time. This provides better performance by reusing
the same Role Token because they’re valid for two hours by default. The
client library will only return cached Role Tokens if they’re valid for
at least 15 minutes. If you want to change this default time, the
application can set the following system property before starting their
application:

    athenz.zts.client.token_min_expiry_time

The value of this property must be specified in seconds. If for any
reason you need to disable caching or have better control how long to
cache tokens, the application can use the full `getRoleToken` API as
shown below:

```
    /**
     * For the specified requester(user/service) return the corresponding
     * Role Token that includes the list of roles that the principal has
     * access to in the specified domain
     * @param domainName name of the domain
     * @param roleName (optional) only interested in the specified role
     * @param trustDomain (optional) only look for trusted roles in this domain
     * @param minExpiryTime (optional) specifies that the returned RoleToken
     *        must be at least valid (min/lower bound) for specified number
     *        of seconds,
     * @param maxExpiryTime (optional) specifies that the returned RoleToken
     *        must be at most valid (max/upper bound) for specified number
     *        of seconds.
     * @param ignoreCache ignore the cache and retrieve the token from ZTS Server
     * @return ZTS generated Role Token
    */
    public RoleToken getRoleToken(String domainName, String roleName,
        Integer minExpiryTime, Integer maxExpiryTime, boolean ignoreCache);
```

To completely disable caching, the `ignoreCache` argument (the last
boolean argument) in the `getRoleToken` method can be passed `true`.

For example, the following call disables caching:

```
    RoleToken roleToken = null;
    try {
        roleToken = ztsClient.getRoleToken("weather", "readers", null, null, null, true);
    } catch (ZTSClientException ex) {
        // log error using ex.getCode() and ex.getMessage()
    }
```

The code above will contact the ZTS Server every time the applications
requests a role token for accessing resources in domain `weather`.

The other two important arguments for token caching are the
`minExpiryTime` and `maxExpiryTime` arguments. When passed `null`, the
client library uses the default values, which as described above gets
tokens that are valid for two hours and caches them until they’re 15
minutes from expiration time.

If your application wants to take advantage of longer caching, then it
can request tokens from the ZTS Server with an expiration time longer
than the default two hours. For example, the requirements for your
server might be that you can use role tokens that must be at least 30
minutes from expiration and they can be valid for up to four hours.

For example, the following would set up the API call that requests
tokens from the Weather server that can only be used if they are 30
minutes from expiration and last four hours:

```
    RoleToken roleToken = null;
    try {
        roleToken = ztsClient.getRoleToken("weather", "readers", null,
            30 * 60, 4 * 60 * 60, true);
    } catch (ZTSClientException ex) {
        // log error using ex.getCode() and ex.getMessage()
    }
```

With the above request configuration, your client library will only make
a single connection to the ZTS Server to retrieve a new token once every
three hours and 30 minutes. All other requests within that time frame
will be fulfilled from the local cache.

### Token Prefetch Caching
---------------------------

In addition to the caching described above, the cache can be kept
`fresh` automatically by the ZTS Client library. The library detects
when a token will expire within a short period of time and will actively
retrieve a new token to replace it. In this way, the client will always
get a usable token from the cache. With configuration, the prefetch
mechanism can be triggered automatically upon calling any of the
`getRoleToken` API.

By default the feature is disabled, but can be enabled via a System
Property. Here is an example of enabling automatic prefetch of tokens.

```
    athenz.zts.client.prefetch_auto_enable=true
```

To use the prefetch caching feature with `getRoleToken`, specify the
`ignoreCache` boolean argument with value `false`.

## Server - Authorization Checks
--------------------------------

In the Athenz enabled server the general processing of a client request
goes as follows:

1.  Your service extracts the Role Token from the header
    (`Athenz-Role-Auth`) of the incoming request which it will pass it to
    the ZPE API.
2.  Your service determines the Action and Resource based on the client
    request. Then the service calls the ZPE API with the Action,
    Resource, and Role Token to determine authorization access.

Additionally, the system administrator needs to make sure that
ZPU (Athenz ZPE Policy Updater) utility is installed and configured
to run on the server host. ZPU will download the configured domain
policy data that is used by the ZPE library for authorization
checks.

First, you need to update your Java project `pom.xml` file to indicate
your dependency on the ZPE Java Client Library:

```
<dependency>
    <groupId>com.yahoo.athenz</groupId>
    <artifactId>zpe_java_client</artifactId>
    <version>1.X.Y</version>
</dependency>
```

In your server startup code you must initialize the Athenz
ZPE Client object which will process and load all the policy
files configured and downloaded by ZPU on this host.

```
    AuthZpeClient.init();
```

Now, the most important part of the rest of the required code is to
determine the resource and action based on the given http request.
Once you have those two values determined, then all that is left
is to extract the ZToken and call ZPE method for the authorization
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

    String zToken = req.getHeader(“Athenz-Role-Auth”);
    
    // this is a thread-safe call
    
    AccessCheckStatus status = AuthZpeClient.allowAccess(zToken, resource, action);
    if (status != AccessCheckStatus.ALLOW) {
      // status provides specific enum value for each reason
      // why the access check was denied. For example - here are 
      // some of the possible values that are returned:
      // AccessCheckStatus.DENY - specific rule caused the deny effect
      // AccessCheckStatus.DENY_NO_MATCH - there was no match to any assertions 
      //   defined in the domain policy file so the default DENY effect was returned
      // AccessCheckStatus.DENY_ROLETOKEN_INVALID - The roletoken provided in the 
      //   request was either invalid or expired
      throw new Exception(“Access denied”);
    }
```

If you want to know which role caused the allow or deny a match to be
returned by the API call, you can use the following API:

```
    StringBuilder matchRoleName = new StringBuilder(256);
    AccessCheckStatus status = AuthZpeClient.allowAccess(zToken, resource, action, matchRoleName);
    if (status != AccessCheckStatus.ALLOW) {
      throw new Exception(“Access denied”);
    }
```

The variable `matchRoleName` will include the name of the role from the
assertion that matched the given action and resource.


