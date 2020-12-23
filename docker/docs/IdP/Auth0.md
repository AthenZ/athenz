<a id="markdown-setup-auth0-as-athenz-oauth-idp" name="setup-auth0-as-athenz-oauth-idp"></a>
# Setup Auth0 as Athenz OAuth IdP

<!-- TOC -->

- [Setup Auth0 as Athenz OAuth IdP](#setup-auth0-as-athenz-oauth-idp)
    - [Target](#target)
    - [Setup Auth0](#setup-auth0)
    - [Setup custom claims](#setup-custom-claims)
    - [Setup Athenz Authority](#setup-athenz-authority)
    - [Get access token](#get-access-token)
    - [Verify access token against ZMS](#verify-access-token-against-zms)
    - [Note](#note)
        - [About authorized service](#about-authorized-service)
    - [Reference](#reference)

<!-- /TOC -->

<a id="markdown-target" name="target"></a>
## Target
1. Use Github for user management.
1. Get access token from Auth0.
1. Authorize access token issued by Auth0 to access ZMS API
1. OAuth2 Terminology
    | Terminology | Actual Party |
    |---|---|
    | Resource owner | Github account |
    | Authorization server | Auth0 |
    | Client | My-Athenz-SPA |
    | Resource server | Athenz-ZMS-API |

<a id="markdown-setup-auth0" name="setup-auth0"></a>
## Setup Auth0
1. [Auth0 Sign Up](https://auth0.com/signup)
    1. copy your domain (e.g. `athenz-oauth-example.auth0.com`)
1. Connect to Github. [Connect your app to GitHub](https://auth0.com/docs/connections/social/github)
1. Create an application in auth0. [Register a Single-Page Application](https://auth0.com/docs/dashboard/guides/applications/register-app-spa)
    1. sample configuration
        ```
        Name: My-Athenz-SPA
        Application Type: Single Page Web Applications

        Allowed Callback URLs: http://localhost:3000
        Allowed Web Origins: http://localhost:3000
        ```
    1. make sure to click `SAVE CHANGES` button at the bottom
    1. copy `Client ID` in `Settings` (e.g. `hpnaS7d6NmBHx4QdejenfY4kgx4RdTPH`)
    1. make sure `Connections > github` is `ON`
1. Setup an API in auth0. [Set Up an API](https://auth0.com/docs/getting-started/set-up-api)
    1. sample configuration
        ```
        Name: Athenz-ZMS-API
        Identifier: https://zms.athenz.io
        ```

<a id="markdown-setup-custom-claims" name="setup-custom-claims"></a>
## Setup custom claims

1. [Create Rules](https://auth0.com/docs/dashboard/guides/rules/create-rules)
1. [optional] [Store Configuration for Rules](https://auth0.com/docs/rules/guides/configuration)
    - add `{ "Key": "CERT_THUMB", "Value": "<certificate_thumbprint>" }`  
        - For the specification of `<certificate_thumbprint>`, please refer to [RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens#section-3.1](https://tools.ietf.org/html/rfc8705#section-3.1)
    - Note:
        - Auth0 does not support certificate bound access token currently. To support it, you need to manually manage and inject your client's certificate thumbprint.
        - To simplify the setup, we are going to disable the certificate thumbprint verification in Athenz ZMS server.
1. [Customize the Tokens](https://auth0.com/docs/api-auth/tutorials/authorization-code-grant-pkce#optional-customize-the-tokens)
    ```js
    // sample rules
    function (user, context, callback) {
        const namespace = 'https://myapp.example.com/';
        const req = context.request;

        // 1. append request scopes
        // Get requested scopes
        let scopes = (req.query && req.query.scope) || (req.body && req.body.scope);
        // Normalize scopes into an array
        scopes = (scopes && scopes.split(" ")) || [];
        // append
        context.accessToken.scope = scopes;

        // 2. add client ID
        // azp === client_id
        context.accessToken[namespace + 'client_id'] = context.clientID;

        // 3. [optional] inject certificate thumbprint
        // const CERT_THUMB = configuration.CERT_THUMB;
        // context.accessToken[namespace + 'cnf'] = { 'x5t#S256': CERT_THUMB };

        callback(null, user, context);
    }
    ```

<a id="markdown-setup-athenz-authority" name="setup-athenz-authority"></a>
## Setup Athenz Authority

> Reference: [contributions/authority/auth0](../../../contributions/authority/auth0)

1. build `athenz_auth_auth0-*.jar` and move it to `"${DOCKER_DIR}/jars/"`
1. add a mapping to authorize your application registered in Auth0 to access the ZMS
    ```bash
    CLIENT_ID='hpnaS7d6NmBHx4QdejenfY4kgx4RdTPH'
    DOMAIN='testing-domain'
    SERVICE='My-Athenz-SPA'

    PRINCIPAL="$(echo "${DOMAIN}.${SERVICE}" | tr '[:upper:]' '[:lower:]')"
    cat >> "${DOCKER_DIR}/zms/conf/authorized_client_ids.txt" <<EOF
    ${CLIENT_ID}:${PRINCIPAL}:${PRINCIPAL}
    EOF

    cat "${DOCKER_DIR}/zms/conf/authorized_client_ids.txt"
    ```
1. append the following sample properties to [zms.properties](../../zms/conf/zms.properties) (Update the following `https://athenz-oauth-example.auth0.com/` domain to your own domain)
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

    ### setting for Auth0 JWT parser
    athenz.auth.oauth.jwt.parser_factory_class=com.yahoo.athenz.auth.oauth.auth0.Auth0JwtParserFactory
    athenz.auth.oauth.jwt.parser.jwks_url=https://athenz-oauth-example.auth0.com/.well-known/jwks.json
    athenz.auth.oauth.jwt.auth0.claim_client_id=https://athenz-oauth-example.auth0.com/client_id
    athenz.auth.oauth.jwt.auth0.claim_confirm=https://athenz-oauth-example.auth0.com/cnf
    # athenz.user_domain=user
    ```
1. update the `DOMAIN_ADMIN` value in [env.sh](../../env.sh) to your github user ID
    1. If you are using `DEV` deployment, please update the `DEV_DOMAIN_ADMIN` value in [env.dev.sh](../../sample/env.dev.sh)
1. re-deploy ZMS

<a id="markdown-get-access-token" name="get-access-token"></a>
## Get access token
1. For `code_challenge`, please refer to [Execute an Authorization Code Grant Flow with PKCE](https://auth0.com/docs/api-auth/tutorials/authorization-code-grant-pkce).
    - sample values
        ```
        verifier: LQoKwSy9djyuHHqr6h3yOYaEA9Mq9uap_u8mXpk1fBM
        challenge: soLgG9cEekJtNh23GxQ1hB4AbqKjcVrkOTWVXMqiUMY
        ```
1. Create request URL to get the authorization code.
    ```bash
    DOMAIN='athenz-oauth-example.auth0.com'
    CLIENT_ID='hpnaS7d6NmBHx4QdejenfY4kgx4RdTPH'
    REDIRECT_URI='http%3A%2F%2Flocalhost%3A3000'

    API_AUDIENCE='https%3A%2F%2Fzms.athenz.io'
    SCOPE='openid%20https%3A%2F%2Fzms.athenz.io%2Fzms%2Fv1' # openid https://zms.athenz.io/zms/v1
    CODE_CHALLENGE='soLgG9cEekJtNh23GxQ1hB4AbqKjcVrkOTWVXMqiUMY'

    tr -d '[:space:]' << CURL_EOF; echo '';
    https://${DOMAIN}/authorize?
        audience=${API_AUDIENCE}&
        scope=${SCOPE}&
        response_type=code&
        client_id=${CLIENT_ID}&
        code_challenge=${CODE_CHALLENGE}&
        code_challenge_method=S256&
        redirect_uri=${REDIRECT_URI}
    CURL_EOF
    ```
    ```bash
    # sample output
    https://athenz-oauth-example.auth0.com/authorize?audience=athenz%2Fzms&scope=openid%20zms%2Fv1&response_type=code&client_id=hpnaS7d6NmBHx4QdejenfY4kgx4RdTPH&code_challenge=soLgG9cEekJtNh23GxQ1hB4AbqKjcVrkOTWVXMqiUMY&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A3000
    ```
1. Open your browser in incognito mode (prevent messing up the cookies).
    1. Paste the URL.
    1. The `Sign In with Auth0` page should show up.
    1. Choose `LOG IN WITH GITHUB` and login with the connected Github account.
    1. Authorize the app by clicking the `YES` button.
    1. The browser will be redirected to the callback URL.
    1. Showing error? Don't panic. It is normal for the browser to show error like `ERR_CONNECTION_REFUSED`, as we do not have a server to handle the callback.
    1. Check the browser's address bar. It should have the callback URL with the authorization code (e.g. `http://localhost:3000/?code=NJDuaMpm1R4A6vL4`).
1. Copy the authorization code at the end of the redirected URL (e.g. `NJDuaMpm1R4A6vL4`).
1. Update the authorization code in below code block and execute the command to exchange for the access token. (duplicated env. variables are skipped.)
    ```bash
    YOUR_GENERATED_CODE_VERIFIER='LQoKwSy9djyuHHqr6h3yOYaEA9Mq9uap_u8mXpk1fBM'
    YOUR_AUTHORIZATION_CODE='NJDuaMpm1R4A6vL4'

    curl --request POST \
        --url "https://${DOMAIN}/oauth/token" \
        --header 'content-type: application/x-www-form-urlencoded' \
        --data grant_type=authorization_code \
        --data "client_id=${CLIENT_ID}" \
        --data "code_verifier=${YOUR_GENERATED_CODE_VERIFIER}" \
        --data "code=${YOUR_AUTHORIZATION_CODE}" \
        --data "redirect_uri=${REDIRECT_URI}"; echo '';
    ```
    ```bash
    # sample output
    {
        "access_token": "...",
        "scope": "openid https://zms.athenz.io/zms/v1",
        "expires_in": 86400,
        "token_type": "Bearer"
    }
    ```
1. You can check the JWT and its claims in [JWT.IO](https://jwt.io/)
1. To get the JWKS to verify your JWT, `curl "https://${DOMAIN}/.well-known/jwks.json"; echo '';`

<a id="markdown-verify-access-token-against-zms" name="verify-access-token-against-zms"></a>
## Verify access token against ZMS

1. Start testing ENV.
    1. start up testing container
        ```bash
        # run testing env.
        BASE_DIR="$(git rev-parse --show-toplevel)"
        . "${BASE_DIR}/docker/env.sh"
        docker run --rm -it --network="${DOCKER_NETWORK}" -v "${BASE_DIR}:/athenz" --user "$(id -u):$(id -g)" athenz-setup-env sh
        ```
    1. setup testing container
        ```bash
        # set up env.
        BASE_DIR="$(git rev-parse --show-toplevel)"
        . "${BASE_DIR}/docker/env.sh"
        echo "Done loading ENV. from ${BASE_DIR}/docker/env.sh"
        if [ -f "${DOCKER_DIR}/setup-scripts/dev-env-exports.sh" ]; then
            . "${DOCKER_DIR}/setup-scripts/dev-env-exports.sh"
            echo 'NOTE: You are using the DEV settings in dev-env-exports.sh !!!'
        fi

        # create workspace
        WORKSPACE_DIR="${DOCKER_DIR}/sample/workspace"
        mkdir -p "${WORKSPACE_DIR}"; cd "${WORKSPACE_DIR}"

        # copy CSR config file
        cp "${DOCKER_DIR}/sample/oauth/config.cnf" "${WORKSPACE_DIR}"

        # setup curl credentials
        alias admin_curl="curl --cacert ${ATHENZ_CA_PATH} --key ${DOMAIN_ADMIN_CERT_KEY_PATH} --cert ${DOMAIN_ADMIN_CERT_PATH}"

        # variables
        DOMAIN='testing-domain'
        SERVICE='My-Athenz-SPA'
        SERVICE_LOWER="$(echo "${SERVICE}" | tr '[:upper:]' '[:lower:]')"
        PRINCIPAL="$(echo "${DOMAIN}.${SERVICE}" | tr '[:upper:]' '[:lower:]')"
        KEY_ID='test_public_key'
        ```
1. Get service certificate from ZTS
    1. prepare CSR
        ```bash
        # create CSR
        DOMAIN="${DOMAIN}" SERVICE="${SERVICE_LOWER}" openssl req -nodes \
            -newkey rsa:2048 \
            -keyout "${WORKSPACE_DIR}/key.pem" \
            -out "${WORKSPACE_DIR}/csr.pem" \
            -config "${WORKSPACE_DIR}/config.cnf" -reqexts service_ext
        openssl req -text -in "${WORKSPACE_DIR}/csr.pem" | grep -e 'Subject:' -e 'DNS:'
        # create public key
        openssl rsa -pubout -in "${WORKSPACE_DIR}/key.pem" -out "${WORKSPACE_DIR}/public.pem"
        ```
    1. register service to ZMS
        ```bash
        # reset
        # admin_curl --request DELETE --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain/${DOMAIN}"

        # create testing-domain
        admin_curl --request POST \
            --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain" \
            --header 'content-type: application/json' \
            --data '{"name": "'"${DOMAIN}"'","adminUsers": ["'"${DOMAIN_ADMIN}"'"]}'
        # create My-Athenz-SPA service
        PUBLIC_KEY="$(base64 -w 0 "${WORKSPACE_DIR}/public.pem" | tr '\+\=\/' '\.\-\_'; echo '';)"
        admin_curl --request PUT \
            --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain/${DOMAIN}/service/${SERVICE}" \
            --header 'content-type: application/json' \
            --data '{"name": "'"${PRINCIPAL}"'","publicKeys": [{"id": "'"${KEY_ID}"'","key": "'${PUBLIC_KEY}'"}]}'
        admin_curl --silent --fail --show-error --request GET --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain/${DOMAIN}/service/${SERVICE}" | jq
        ```
    1. get service certificate from ZTS
        ```bash
        CSR="$(cat "${WORKSPACE_DIR}/csr.pem" | awk -v ORS='\\n' '1')"
        admin_curl --silent --fail --show-error --request POST \
            --url "https://${ZTS_HOST}:${ZTS_PORT}/zts/v1/instance/${DOMAIN}/${SERVICE}/refresh" \
            --header 'content-type: application/json' \
            --data '{"csr": "'"${CSR}"'","keyId": "'"${KEY_ID}"'"}' \
            | jq --raw-output '[.certificate, .caCertBundle] | join("")' > "${WORKSPACE_DIR}/src_cert_bundle.pem"
        # P.S. It may take few seconds to sync. data from ZMS to ZTS.
        ```
        ```bash
        # verify the service certifiicate
        curl --silent --fail --show-error \
            --cacert "${ATHENZ_CA_PATH}" \
            --key "${WORKSPACE_DIR}/key.pem" \
            --cert "${WORKSPACE_DIR}/src_cert_bundle.pem" \
            --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/principal" | jq 'del(.token)'
        ```
        ```json
        {
            "domain": "testing-domain",
            "service": "my-athenz-spa"
        }
        ```
1. Verify the access token from Auth0
    1. check Athenz domain admin, make sure your github ID is one of the members
        ```bash
        curl --silent --fail --show-error \
            --cacert "${ATHENZ_CA_PATH}" \
            --key "${WORKSPACE_DIR}/key.pem" \
            --cert "${WORKSPACE_DIR}/src_cert_bundle.pem" \
            --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain/sys.auth/role/admin" | jq
        ```
        ```json
        {
            "name": "sys.auth:role.admin",
            "modified": "2020-03-05T05:34:16.498Z",
            "members": [
                "user.github-7654321"
            ],
            "roleMembers": [
                {
                "memberName": "user.github-7654321",
                "approved": true,
                "auditRef": "System Setup"
                }
            ]
        }
        ```
    1. verify the access token, make sure your github ID is shown
        ```bash
        access_token='<encoded_jwt>'
        curl --silent --fail --show-error \
            -H "Authorization: Bearer ${access_token}" \
            --cacert "${ATHENZ_CA_PATH}" \
            --key "${WORKSPACE_DIR}/key.pem" \
            --cert "${WORKSPACE_DIR}/src_cert_bundle.pem" \
            --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/principal" | jq 'del(.token)'
        ```
        ```json
        {
            "domain": "user",
            "service": "github-7654321"
        }
        ```
    1. verify admin access right of the access token
        ```bash
        curl --silent --fail --show-error \
            -H "Authorization: Bearer ${access_token}" \
            --cacert "${ATHENZ_CA_PATH}" \
            --key "${WORKSPACE_DIR}/key.pem" \
            --cert "${WORKSPACE_DIR}/src_cert_bundle.pem" \
            "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/access/some-action/sys.auth:some-resources" | jq
        ```
        ```json
        {
            "granted": true
        }
        ```

<a id="markdown-note" name="note"></a>
## Note

<a id="markdown-about-authorized-service" name="about-authorized-service"></a>
### About authorized service

ZMS limits the API access using the [authorized_services.json](../../zms/conf/authorized_services.json) file (GET APIs are not included.). When a client application access ZMS using the user's credentials, the application can only use the user's credentials on a pre-defined set of APIs. Hence, even the user is the domain admin of Athenz, he cannot update ZMS data via unregistered client applications.

For example, if we want to allow users to create top level domain via our example application ('testing-domain.my-athenz-spa'), we need to update the [authorized_services.json](../../zms/conf/authorized_services.json) as below and re-deploy ZMS.

```json
{
    "services" : {
        "testing-domain.my-athenz-spa": {
            "allowedOperations": [
                { "name":"posttopleveldomain" }
            ]
        }
    }
}
```

<a id="markdown-reference" name="reference"></a>
## Reference
- [Auth0 JavaScript SDK Quickstarts: Login](https://auth0.com/docs/quickstart/spa/vanillajs/01-login)
- [Auth0 JavaScript SDK Quickstarts: Calling an API](https://auth0.com/docs/quickstart/spa/vanillajs/02-calling-an-api)
- [Execute an Authorization Code Grant Flow with PKCE](https://auth0.com/docs/api-auth/tutorials/authorization-code-grant-pkce)
- [Authentication API Explorer](https://auth0.com/docs/api/authentication?http#social)
