# Principal Authentication
--------------------------

* [Authority Work](#authority-work)
* [Configuration](#configuration)
* [Provided Authorities](#provided-authorities)
    * [Unix User Authority](#unix-user-authority)
    * [Principal Authority](#principal-authority)
    * [Kerberos Authority](#kerberos-authority)
    * [Certificate Authority](#certificate-authority)
    * [Role Authority](#role-authority)
    * [LDAP Authority](#LDAP-authority)     
    
For a principal (either user or service) to authenticate himself/herself
in Athenz, the server must have the appropriate authentication authority
implementation configured. Athenz has implementation of several authorities
that support variety of authentication methods. The system administrator
may decide to configure and use one of the provided authorities or
implement a completely new one to satisfy their requirements.

## Authority Work
-----------------

The job of the Authority is authenticate a specific request and, if valid,
generate and return an object representing the authenticated Principal.
The Authority interface is defined in the following file:

[Authority](https://github.com/AthenZ/athenz/blob/master/libs/java/auth_core/src/main/java/com/yahoo/athenz/auth/Authority.java)

The system administrator can configure a list of authorities for
supporting principal authentication. During startup, the server will
call the `initialize()` method for all configured authorities. If
the authority requires access to any of the service public keys
registered within Athenz, then it needs to implement the `AuthorityKeyStore`
interface as well and provide an implementation of the `setKeyStore()` method.
The server implements the `KeyStore` interface and will automatically call
the `setKeyStore()` method to pass its implementation to the authority.

[AuthorityKeyStore](https://github.com/AthenZ/athenz/blob/master/libs/java/auth_core/src/main/java/com/yahoo/athenz/auth/AuthorityKeyStore.java)

When processing a request the server goes through the list of authorities in their
configured order and processes until it receives a successful principal
object. As soon as a successful response is received from the authenticate
method, the server will stop processing other authorities in the list
and continue with the authorization check. If no authority returns an
authenticated principal, the server returns 401 Unauthenticated response
to the calling client.

The Authority defines if the authentication details are based on a header
or certificate: `getCredSource()`. If the returned value is `HEADER` then
the Athenz server will retrieve the header, identified by the value
returned by the `getHeader()` method, that the authority is looking
for and if a value is present, it will call the `authenticate()`
method to see if the request contains valid credentials or not.

The returned principal object contains the Authority object that was
used for authentication. This allows the Athenz servers, if necessary,
to decide if further checks and/or restrictions are necessary.

## Configuration
----------------

Both ZMS and ZTS Servers expect to find the list of authority classes
in their respective system properties:

* ZMS: athenz.zms.authority_classes
* ZTS: athenz.zts.authority_classes

The value of the property must be a comma separated (no spaces) list
of authority class names. For example,

```
-Dathenz.zms.authority_classes=com.yahoo.athenz.auth.impl.PrincipalAuthority,com.yahoo.athenz.auth.impl.UserAuthority
```

If you're installing and running Athenz services using the binary
packages provided, you can configure the list of authorities in the
conf/zms_server/zms.properties or conf/zts_server/zts.properties files
for ZMS and ZTS servers respectively:

```
athenz.zms.authority_classes=com.yahoo.athenz.auth.impl.PrincipalAuthority,com.yahoo.athenz.auth.impl.UserAuthority

athenz.zts.authority_classes=com.yahoo.athenz.auth.impl.PrincipalAuthority,com.yahoo.athenz.auth.impl.UserAuthority
```

## Provided Authorities
-----------------------

Here is the list of Athenz provided authorities with brief description
of each one.

### Unix User Authority
-----------------------

Class: com.yahoo.athenz.auth.impl.UserAuthority

This authority uses the Unix pam `login` profile to authenticate users.
The user that the ZMS process runs as must have read access
to the `/etc/shadow` file. There are two options available:

* Run the process as root using sudo. This is only recommended for a local
  development installation.
* Create a special Unix group that has read access to the `/etc/shadow` file
  and set the user that the ZMS process will be running as a member of that
  group.

User Authority is typically not allowed to carry out any authorized
operation. It is required that the user first must obtain an X509 certificate
for his/her identity and use that certificate to carry out the authorized
request.

### Principal Authority
-----------------------

Class: com.yahoo.athenz.auth.impl.PrincipalAuthority

This authority uses Athenz generated NTokens. It accepts NTokens, parses
to extract the signature and the private key details that were used
to sign this token: domain, service, and key id. Then it requests the
corresponding public key and verifies the signature.

Principal Authority is one of primary authorities in Athenz. It is
used to validate NTokens that were issued by ZTS and service tokens
generated by SIA Providers.

By default, when authenticating an NToken, the authority validates
that the IP address in the NToken matches to the IP address of the request.
This provides extra security that changes to domain data are not
carried out by NTokens that possible have been stolen.

### Kerberos Authority
----------------------

Class: com.yahoo.athenz.auth.impl.KerberosAuthority

This authority supports environments with Kerberos servers. This authority
expects to find the Kerberos Ticket in the `Authorization` header.
There are several system properties that must be set for
proper initialization of this authority:

`athenz.auth.kerberos.service_principal` - Kerberos service principal
`athenz.auth.kerberos.keytab_location` - Kerberos keytab location
`athenz.auth.kerberos.jaas_cfg_section` - JAAS configuration section. If
    using a jaas.conf file then that path is specified by the system
    property `java.security.auth.login.config`

For full details check out the implementation of the Kerberos Authority:

[Kerberos Authority](https://github.com/AthenZ/athenz/blob/master/libs/java/auth_core/src/main/java/com/yahoo/athenz/auth/impl/KerberosAuthority.java)

### Certificate Authority
-------------------------

Class: com.yahoo.athenz.auth.impl.CertificateAuthority

The certificate authority expects that the server has been configured
with a truststore that only includes the CA cert that it tasked with
issuing principal certificates. The Authority only looks at the
CommonName component of the certificate and expects it to include
the service name in the {domain}.{service} format. For example:

```
Certificate Subject DN: c=US;o=Some Athenz Company;cn=sports.fantasy
```

The authenticated principal in this case is service `fantasy` in domain
`sports`.

### LDAP Authority
------------------

Class: com.yahoo.athenz.auth.impl.LDAPAuthority

Lightweight Directory Access Protocol (LDAP) authority uses the bind operation 
to authenticate users. The authentication mechanism used is `simple` where 
plain text username and passwords are used. The `hostname`, `port number` and `base DN`
property of the LDAP server needs to be provided. An example of base dn is: 
 ```
 LDAP Server Base DN: dc=example,dc=com
 ```