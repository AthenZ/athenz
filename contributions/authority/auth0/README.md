<a id="markdown-athenz-oauth2-access-token-for-auth0" name="athenz-oauth2-access-token-for-auth0"></a>
# Athenz OAuth2 access token for Auth0
Athenz Yahoo Server OAuth2 access token implementation for Auth0

<!-- TOC -->

- [Athenz OAuth2 access token for Auth0](#athenz-oauth2-access-token-for-auth0)
    - [Usage](#usage)
        - [Build](#build)
        - [Integrate with Athenz](#integrate-with-athenz)
    - [For developer](#for-developer)
        - [Test coverage](#test-coverage)

<!-- /TOC -->

<a id="markdown-usage" name="usage"></a>
## Usage

<a id="markdown-build" name="build"></a>
### Build
```bash
mvn clean package
ls ./target/athenz_auth_auth0-*.jar
```

<a id="markdown-integrate-with-athenz" name="integrate-with-athenz"></a>
### Integrate with Athenz
1. add `athenz_auth_auth0-*.jar` in Athenz server's classpath
1. overwrite existing system property
    ```properties
    # ZMS server
    athenz.zms.authority_classes=com.yahoo.athenz.auth.oauth.OAuthCertBoundJwtAccessTokenAuthority

    # ZTS server
    athenz.zts.authority_classes=com.yahoo.athenz.auth.oauth.OAuthCertBoundJwtAccessTokenAuthority
    ```
1. setup OAuthCertBoundJwtAccessTokenAuthority for Auth0 (Update the following `https://athenz-oauth-example.auth0.com/` domain to your own domain)
    ```properties
    athenz.auth.oauth.jwt.authn_challenge_realm=registered_users@athenz.io
    athenz.auth.oauth.jwt.cert.exclude_role_certificates=false
    athenz.auth.oauth.jwt.cert.excluded_principals=

    # Auth0 does not support certificate bound access token currently
    athenz.auth.oauth.jwt.verify_cert_thumbprint=false
    athenz.auth.oauth.jwt.authorized_client_ids_path=conf/zms_server/authorized_client_ids.txt

    ### setting for Auth0 JWT validator
    athenz.auth.oauth.jwt.claim.iss=https://athenz-oauth-example.auth0.com/
    athenz.auth.oauth.jwt.claim.aud=https://zms.athenz.io
    athenz.auth.oauth.jwt.claim.scope=openid https://zms.athenz.io/zms/v1
    # full role name format: _domain_._sub_domain_:role._role_name_

    ### setting for Auth0 JWT parser
    athenz.auth.oauth.jwt.parser_factory_class=com.yahoo.athenz.auth.oauth.auth0.Auth0JwtParserFactory
    athenz.auth.oauth.jwt.parser.jwks_url=https://athenz-oauth-example.auth0.com/.well-known/jwks.json
    athenz.auth.oauth.jwt.auth0.claim_client_id=https://athenz-oauth-example.auth0.com/client_id
    athenz.auth.oauth.jwt.auth0.claim_confirm=https://athenz-oauth-example.auth0.com/cnf
    # athenz.user_domain=user
    ```

<a id="markdown-for-developer" name="for-developer"></a>
## For developer

<a id="markdown-test-coverage" name="test-coverage"></a>
### Test coverage
```bash
mvn clover:instrument clover:aggregate clover:clover clover:check
open ./target/site/clover/index.html
```
