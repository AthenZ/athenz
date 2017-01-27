# Java Client/Servlet Example - Centralized Access Control
----------------------------------------------------------

* [Required Components](#required-components)
* [Service Definition](#service-definition)
* [Resource Definition](#resource-definition)
* [Athenz Management Setup](#athenz-management-setup)
* [Code Changes](#code-changes)
    * [Client Changes](#client-changes)
        * [Client Project Dependency Update](#client-project-dependency-update)
        * [Obtaining NTokens from SIA Provider](#obtaining-ntokens-from-sia-provider)
        * [Build Http Client Utility](#build-http-client-utility)
    * [Servlet Changes](#servlet-changes)
        * [Servlet Project Dependency Update](#servlet-project-dependency-update)
        * [Authorization Checks](#authorization-checks)
        * [Build Servlet](#build-servlet)
* [Deploying Example Servlet](#deploying-example-servlet)
* [Test Cases](#test-cases)
    * [Invalid Access Without ServiceToken](#invalid-access-without-servicetoken)
    * [Movie Editor Access](#movie-editor-access)
    * [TvShow Editor Access](#tvshow-editor-access)
    * [Site Editor Access](#site-editor-access)
    * [Other Test Cases](#other-test-cases)

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

## Required Components
----------------------

To support centralized access control in your applications,
you only need to install and configure the Athenz ZMS
server along with the Athenz UI. Please follow these guides
to make sure you have both of those components up and
running in your environment:

* [ZMS Server](setup_zms.md)
* [UI Server](setup_ui.md)

To build the client and servlet components of this example,
you need to download and install Oracle JDK 8, Apache Maven and Git client
if you don't already have these available on your box:

* [Oracle Java Platform JDK 8](http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html)
* [Apache Maven](http://maven.apache.org/download.cgi)
* [Git client](https://git-scm.com/downloads)

## Service Definition
---------------------

Let's first define our service that needs to be Athenz protected.
We have a simple recommendation service that returns either a movie
or tv show for the caller. It has two endpoints:

    GET /rec/v1/movie
    GET /rec/v1/tvshow

So in this first release we just want to protect access to these
endpoints. The traffic is very low - we only expect a couple of
requests an hour so we have decided to use Athenz' centralized
authorization model.

## Resource Definition
----------------------

Defining resources and actions the principals are authorized
to execute is one of the most important tasks
in the authorization process. Based on our endpoints, it's expected
that we'll have 2 general resources:

    movie
    tvshow

The resources are referenced in their own domain namespace. So those
are valid if your domain is specifically created to support this
recommendation service only. But's lets assume we might add rental
support later, so we need to make sure the policies are based on
service specific resources. So we'll define our resources as:

    rec.movie
    rec.tvshow

Support action for these resources would be `read`. We can extend
our authorization policies later on if we need to introduce other
actions - such as `write` or `list` as we add more functionality into
our service.

## Athenz Management Setup
--------------------------

Once we have defined what our resources and actions are, we can
create their respective client and server (also commonly referred
as tenant and provider) roles and policies in Athenz. Go to
Athenz UI and login with your account which should have system
administrator access. Follow the instructions in the following
guide to setup the required access control:

* [Access Control Setup](example_service_athenz_setup.md)

## Code Changes
---------------

Both the client and servlet implementors need to make changes
in their respective code bases to support centralized authorization
checks. The client needs to make sure to submit its service
identity as part of its request, while the servlet needs to
carry out the authorization check based on that service
identity to determine if it request should be processed or not.

### Client Changes
------------------

The full client source code is available from:

https://github.com/yahoo/athenz/tree/master/examples/java/centralized-use-case/client

#### Client Project Dependency Update
-------------------------------------

First you need to update your Java project `pom.xml` file to indicate
the dependency on the Athenz auth_core Library. Checkout the
[Bintray Auth-Core Package Page](https://bintray.com/yahoo/maven/athenz-auth-core/)
to make sure you're using the latest release version:

```
<dependency>
    <groupId>com.yahoo.athenz</groupId>
    <artifactId>auth_core</artifactId>
    <version>1.1.1</version>
</dependency>

<repositories>
  <repository>
    <id>bintray-yahoo-maven</id>
    <name>bintray</name>
    <url>http://yahoo.bintray.com/maven</url>
  </repository>
</repositories>
```

#### Obtaining NTokens from SIA Provider
----------------------------------------

The domain administrator must have already generated a public/private key pair
for the service and registered public key in Athenz. The private key must be
available on the host where the client will be running.

```java
    // the fields used in the following snippet of code
    // privateKeyPath -> includes the path to the service's private key file
    //     the corresponding public key is already registered in Athenz
    // domainName -> 'editors'
    // serviceName -> 'movie', 'tvshow' or 'site'
    // keyId -> 'v0'
    
    PrivateKey privateKey = Crypto.loadPrivateKey(new File(privateKeyPath));
    ServiceIdentityProvider identityProvider = new SimpleServiceIdentityProvider(domainName,
            serviceName, privateKey, keyId);
    Principal principal = identityProvider.getIdentity(domainName, serviceName);
```

Once we have our principal object, then the client before contacting the provider
service needs to extract the service identity credentials and include
them in the request as the value of Athenz principal header.

```java
    // set our Athenz credentials. The authority in the principal provides
    // the header name (Athenz-Principal-Auth) that we must use for credentials
    // while the principal itself provides the credentials (ntoken).

    con.setRequestProperty(principal.getAuthority().getHeader(),
        principal.getCredentials());
```

#### Build Http Client Utility
------------------------------

Checkout and build the client component:

```shell
$ git clone https://github.com/yahoo/athenz.git
$ cd examples/java/centralized-use-case/client/
$ mvn clean package
```

Verify that the client is built successfully:

```shell
$ java -cp target/example-client-ntoken-1.0.jar com.yahoo.athenz.example.ntoken.HttpExampleClient
Missing required options: d, s, p, k, u
usage: http-example-client
 -d,--domain <arg>    domain name
 -k,--keyid <arg>     key identifier
 -p,--pkey <arg>      private key path
 -s,--service <arg>   service name
 -u,--url <arg>       request url
```

### Servlet Changes
-------------------

The full servlet source code is available from:

https://github.com/yahoo/athenz/tree/master/examples/java/centralized-use-case/servlet

#### Servlet Project Dependency Update
--------------------------------------

First you need to update your Java project `pom.xml` file to indicate
the dependency on the Athenz ZMS Java Client Library. Checkout the
[Bintray ZMS Client Package Page](https://bintray.com/yahoo/maven/athenz-zms-java-client/)
to make sure you're using the latest release version:

```
<dependency>
    <groupId>com.yahoo.athenz</groupId>
    <artifactId>zms_java_client</artifactId>
    <version>1.1.1</version>
</dependency>

<repositories>
  <repository>
    <id>bintray-yahoo-maven</id>
    <name>bintray</name>
    <url>http://yahoo.bintray.com/maven</url>
  </repository>
</repositories>
```

#### Authorization Checks
-------------------------

Before any authorization calls, we're going to check to make sure
our request contains the Athenz principal token:

```java
    static final String ATHENZ_HEADER = "Athenz-Principal-Auth";
    
    protected void doGet(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {

        // retrieve and verify that our request contains an Athenz
        // service authentication token
        
        String athenzServiceToken = request.getHeader(ATHENZ_HEADER);
        if (athenzServiceToken == null) {
            response.sendError(403, "Forbidden - No Athenz ServiceToken provided in request");
            return;
        }
        
        ...
    }
```

Next, the most important part is to determine the resource and action
based on the given http request.

```java
    protected void doGet(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {

        ...
    
        switch (reqUri) {
            case "/movie":
                responseText = "Name: Slap Shot; Director: George Roy Hill";
                athenzResource = "rec.movie";
                athenzAction = "read";
                break;
            case "/tvshow":
                responseText = "Name: Middle; Channel: ABC";
                athenzResource = "rec.tvshow";
                athenzAction = "read";
                break;
            default:
                response.sendError(404, "Unknown endpoint");
                return;
        }
    
        ...
    }
```

Once we have those two values determined, then all that is left
is to contact ZMS for the authorization check.

```java
    protected void doGet(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {

        ...
        
        // carry out the authorization check with the expected resource
        // and action values
        
        try (ZMSAuthorizer authorizer = new ZMSAuthorizer(zmsUrl, "recommend")) {
            boolean authorized = authorizer.access(athenzAction, athenzResource,
                    athenzServiceToken, null);
            if (!authorized) {
                response.sendError(403, "Forbidden - Athenz Authorization Rejected");
                return;
            }
        }
    
        ...
    }
```

#### Build Servlet
------------------

Checkout and build the servlet component:

```shell
$ git clone https://github.com/yahoo/athenz.git
$ cd examples/java/centralized-use-case/servlet/
$ mvn clean package
```

## Deploying Example Servlet
----------------------------

* Download and install latest [Jetty 9.3.x container](http://www.eclipse.org/jetty/download.html)
* Copy the `athenz-control.war` from the `servlet/target` directory to the Jetty
distribution's `webapps` directory
* Configure ZMS Server's URL in the expected environment variable:
```shell
export ZMS_SERVER_URL=https://<zms-server-hostname>:4443/zms/v1
```
* If the ZMS Server is running with a self-signed certificate,
we need to generate a truststore for the java http client to use
when communicating with the ZMS Server. From your ZMS Server installation,
copy the `zms_cert.pem` file from the `athenz-zms-X.Y/var/zms_server/certs`
directory to the jetty's `etc` subdirectory and execute the following
commands:
```shell
$ keytool -importcert -noprompt -alias zms -keystore zms_truststore.jks -file zms_cert.pem -storepass athenz
$ export JAVA_OPTIONS=-Djavax.net.ssl.trustStore=<full-path-to-jetty-basedir>/etc/zms_truststore.jks
```
* Start the Jetty server by running the following command from
Jetty's distribution base directory:
```shell
bin/jetty.sh start
```

## Test Cases
-------------

Run the following test cases to verify authorization access
for specific services. We're running jetty server on the local
box so we're using localhost as the hostname.

* Copy the `example-client-ntoken-1.0.jar` file from the client/target
directory to the directory that includes the private keys for the test
services we created in the section [Athenz Management Setup](#athenz-management-setup)
above.

### Invalid Access Without ServiceToken
---------------------------------------

For this test case we'll just use the curl client directly:

```shell
$ curl http://localhost:8080/athenz-control/rec/v1/movie
<html>
...
<title>Error 403 Forbidden - No Athenz ServiceToken provided in request</title>
...
</html>
```

### Movie Editor Access
-----------------------

Movie service can successfully access /rec/v1/movie endpoint:

```shell
$ java -cp ./example-client-ntoken-1.0.jar com.yahoo.athenz.example.ntoken.HttpExampleClient -d editors -s movie -p ./movie_private.pem -k v0 -u http://localhost:8080/athenz-control/rec/v1/movie

Successful response:
Name: Slap Shot; Director: George Roy Hill
```

Movie service does not have access to /rec/v1/tvshow endpoint:

```shell
$ java -cp ./example-client-ntoken-1.0.jar com.yahoo.athenz.example.ntoken.HttpExampleClient -d editors -s movie -p ./movie_private.pem -k v0 -u http://localhost:8080/athenz-control/rec/v1/tvshow

Request was forbidden - not authorized
```

### TvShow Editor Access
------------------------

TvShow service can successfully access /rec/v1/tvshow endpoint:

```shell
$ java -cp ./example-client-ntoken-1.0.jar com.yahoo.athenz.example.ntoken.HttpExampleClient -d editors -s tvshow -p ./tvshow_private.pem -k v0 -u http://localhost:8080/athenz-control/rec/v1/tvshow

Successful response:
Name: Middle; Channel: ABC
```

TvShow service does not have access to /rec/v1/movie endpoint:

```shell
$ java -cp ./example-client-ntoken-1.0.jar com.yahoo.athenz.example.ntoken.HttpExampleClient -d editors -s tvshow -p ./tvshow_private.pem -k v0 -u http://localhost:8080/athenz-control/rec/v1/movie

Request was forbidden - not authorized
```

### Site Editor Access
----------------------

Site service has access to both /rec/v1/tvshow and /rec/v1/movie endpoints:

```shell
$ java -cp ./example-client-ntoken-1.0.jar com.yahoo.athenz.example.ntoken.HttpExampleClient -d editors -s site -p ./site_private.pem -k v0 -u http://localhost:8080/athenz-control/rec/v1/movie

Successful response:
Name: Slap Shot; Director: George Roy Hill

$ java -cp ./example-client-ntoken-1.0.jar com.yahoo.athenz.example.ntoken.HttpExampleClient -d editors -s site -p ./site_private.pem -k v0 -u http://localhost:8080/athenz-control/rec/v1/tvshow

Successful response:
Name: Middle; Channel: ABC
```

### Other Test Cases
--------------------

Now you can modify the `movie_editos, tvshow_editors, and site_editors` roles
in the `recommend` domain to add and remove the defined services and then
run the corresponding test cases to verify your access change.
