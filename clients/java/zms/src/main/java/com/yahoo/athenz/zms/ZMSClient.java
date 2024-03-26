/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yahoo.athenz.zms;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.common.config.AthenzConfig;
import com.yahoo.athenz.common.utils.SSLUtils;
import com.yahoo.athenz.common.utils.SSLUtils.ClientSSLContextBuilder;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Timestamp;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.DnsResolver;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.Closeable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class ZMSClient implements Closeable {

    private String zmsUrl = null;
    private Principal principal = null;
    private boolean principalCheckDone = false;
    protected ZMSRDLGeneratedClient client = null;
    static private DnsResolver dnsResolver = null;

    private static final String STR_ENV_ROOT = "ROOT";
    private static final String STR_DEF_ROOT = "/home/athenz";
    private static final String HTTP_RFC1123_DATE_FORMAT = "EEE, d MMM yyyy HH:mm:ss zzz";

    public static final String ZMS_CLIENT_PROP_ATHENZ_CONF = "athenz.athenz_conf";
    public static final String ZMS_CLIENT_PROP_READ_TIMEOUT = "athenz.zms.client.read_timeout";
    public static final String ZMS_CLIENT_PROP_CONNECT_TIMEOUT = "athenz.zms.client.connect_timeout";

    public static final String ZMS_CLIENT_PROP_POOL_MAX_PER_ROUTE = "athenz.zms.client.http_pool_max_per_route";
    public static final String ZMS_CLIENT_PROP_POOL_MAX_TOTAL     = "athenz.zms.client.http_pool_max_total";

    public static final String ZMS_CLIENT_PROP_CERT_ALIAS = "athenz.zms.client.cert_alias";

    public static final String ZMS_CLIENT_PROP_KEYSTORE_PATH = "athenz.zms.client.keystore_path";
    public static final String ZMS_CLIENT_PROP_KEYSTORE_TYPE = "athenz.zms.client.keystore_type";
    public static final String ZMS_CLIENT_PROP_KEYSTORE_PASSWORD = "athenz.zms.client.keystore_password";
    public static final String ZMS_CLIENT_PROP_KEYSTORE_PWD_APP_NAME = "athenz.zms.client.keystore_pwd_app_name";

    public static final String ZMS_CLIENT_PROP_KEY_MANAGER_PASSWORD = "athenz.zms.client.keymanager_password";
    public static final String ZMS_CLIENT_PROP_KEY_MANAGER_PWD_APP_NAME = "athenz.zms.client.keymanager_pwd_app_name";

    public static final String ZMS_CLIENT_PROP_TRUSTSTORE_PATH = "athenz.zms.client.truststore_path";
    public static final String ZMS_CLIENT_PROP_TRUSTSTORE_TYPE = "athenz.zms.client.truststore_type";
    public static final String ZMS_CLIENT_PROP_TRUSTSTORE_PASSWORD = "athenz.zms.client.truststore_password";
    public static final String ZMS_CLIENT_PROP_TRUSTSTORE_PWD_APP_NAME = "athenz.zms.client.truststore_pwd_app_name";

    public static final String ZMS_CLIENT_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS = "athenz.zms.client.private_keystore_factory_class";
    public static final String ZMS_CLIENT_PROP_CLIENT_PROTOCOL = "athenz.zms.client.client_ssl_protocol";
    public static final String ZMS_CLIENT_PKEY_STORE_FACTORY_CLASS = "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory";
    public static final String ZMS_CLIENT_DEFAULT_CLIENT_SSL_PROTOCOL = "TLSv1.2";

    private static final Logger LOGGER = LoggerFactory.getLogger(ZMSClient.class);
    private static final Authority PRINCIPAL_AUTHORITY = new PrincipalAuthority();

    private static final PrivateKeyStore PRIVATE_KEY_STORE = loadServicePrivateKey();

    static PrivateKeyStore loadServicePrivateKey() {
        String pkeyFactoryClass = System.getProperty(ZMS_CLIENT_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                ZMS_CLIENT_PKEY_STORE_FACTORY_CLASS);
        return SSLUtils.loadServicePrivateKey(pkeyFactoryClass);
    }

    /**
     * Constructs a new ZMSClient object with default settings.
     * The url for ZMS Server is automatically retrieved from the athenz
     * configuration file (zmsUrl field). The client can only be used
     * to retrieve objects from ZMS that do not require any authentication
     * otherwise addCredentials method must be used to set the principal identity.
     * Default read and connect timeout values are 30000ms (30sec). The application can
     * change these values by using the athenz.zms.client.read_timeout and
     * athenz.zms.client.connect_timeout system properties. The values specified
     * for timeouts must be in milliseconds.
     */
    public ZMSClient() {
        initClient(null, null);
    }

    /**
     * Constructs a new ZMSClient object with the given ZMS Server url. The client
     * can only be used to retrieve objects from ZMS that do not require any authentication
     * otherwise addCredentials method must be used to set the principal identity.
     * Default read and connect timeout values are 30000ms (30sec). The application can
     * change these values by using the athenz.zms.client.read_timeout and
     * athenz.zms.client.connect_timeout system properties. The values specified
     * for timeouts must be in milliseconds.
     *
     * @param url ZMS Server url (e.g. https://server1.athenzcompany.com:4443/zms/v1)
     */
    public ZMSClient(String url) {
        initClient(url, null);
    }

    /**
     * Constructs a new ZMSClient object with the given ZMS Server url and
     * given principal. The credentials from the principal object will be used
     * to set call the addCredentials method for the zms client object.
     * Default read and connect timeout values are 30000ms (30sec). The application can
     * change these values by using the athenz.zms.client.read_timeout and
     * athenz.zms.client.connect_timeout system properties. The values specified
     * for timeouts must be in milliseconds.
     *
     * @param url      ZMS Server url (e.g. https://server1.athenzcompany.com:4443/zms/v1)
     * @param identity Principal object that includes credentials
     */
    public ZMSClient(String url, Principal identity) {
        initClient(url, null);
        addCredentials(identity);
    }

    /**
     * Constructs a new ZMSClient object with default settings and given
     * principal object for credentials. The url for ZMS Server is
     * automatically retrieved from the athenz configuration file
     * (zmsUrl field).
     * Default read and connect timeout values are 30000ms (30sec). The application can
     * change these values by using the athenz.zms.client.read_timeout and
     * athenz.zms.client.connect_timeout system properties. The values specified
     * for timeouts must be in milliseconds.
     *
     * @param identity Principal object that includes credentials
     */
    public ZMSClient(Principal identity) {
        initClient(null, null);
        addCredentials(identity);
    }

    /**
     * Constructs a new ZMSClient object with the given SSLContext object
     * and ZMS Server Url. Default read and connect timeout values are 30000ms (30sec).
     * The application can change these values by using the athenz.zms.client.read_timeout
     * and athenz.zms.client.connect_timeout system properties. The values specified
     * for timeouts must be in milliseconds.
     *
     * @param url        ZMS Server url (e.g. https://server1.athenzcompany.com:4443/zms/v1)
     * @param sslContext SSLContext that includes service's private key and x.509 certificate
     *                   for authenticating requests
     */
    public ZMSClient(String url, SSLContext sslContext) {

        // verify we have a valid ssl context specified

        if (sslContext == null) {
            throw new IllegalArgumentException("SSLContext object must be specified");
        }
        initClient(url, sslContext);
    }

    /**
     * Close the ZMSClient object and release any allocated resources.
     */
    public void close() {
        client.close();
    }

    /**
     * Set the DNSResolver to be used by the ZMS Client
     * @param resolver user supplied dns resolver
     */
    public void setDnsResolver(DnsResolver resolver) {
        dnsResolver = resolver;
    }

    public void setZMSRDLGeneratedClient(ZMSRDLGeneratedClient client) {
        this.client = client;
    }

    /**
     * Set the client credentials using the specified header and token.
     *
     * @param credHeader authentication header name
     * @param credToken  authentication credentials
     */
    public void addCredentials(String credHeader, String credToken) {
        client.addCredentials(credHeader, credToken);
    }

    /**
     * Sets or overrides the current principal identity set in the client.
     *
     * @param identity Principal identity for authenticating requests
     * @return self ZMSClient object
     */
    public ZMSClient addCredentials(Principal identity) {

        // make sure the principal has proper authority assigned

        if (identity == null || identity.getAuthority() == null) {
            throw new IllegalArgumentException("Principal must be valid object with authority field");
        }

        // if we already have a principal set, we're going to
        // clear our credentials first

        if (principal != null) {
            client.addCredentials(principal.getAuthority().getHeader(), null);
        }

        // now we're going to update our principal and set credentials

        principal = identity;
        principalCheckDone = false;

        // we've already verified that our authority in the passed
        // identity object is valid
        final Authority authority = principal.getAuthority();
        client.addCredentials(authority.getHeader(), principal.getCredentials());

        // final check if the authority does not support authorization
        // by the zms server then it's most likely a user authority and
        // we need to get a principal token

        principalCheckDone = authority.allowAuthorization();
        return this;
    }

    /**
     * Clear the principal identity set for the client. Unless a new principal is set
     * using the addCredentials method, the client can only be used to request data
     * from the ZMS Server that doesn't require any authentication.
     *
     * @return self ZMSClient object
     */
    public ZMSClient clearCredentials() {
        if (principal != null) {
            client.addCredentials(principal.getAuthority().getHeader(), null);
            principal = null;
            principalCheckDone = true;
        }
        return this;
    }

    /**
     * If the current principal is the user principal then request
     * a UserToken from ZMS and set the UserToken as the principal
     * identity for authentication.
     */
    private void updatePrincipal() {

        /* if the check has already been done then we have nothing to do */

        if (principalCheckDone) {
            return;
        }

        /* make sure we have a principal specified */

        if (principal == null) {
            principalCheckDone = true;
            return;
        }

        /* so at this point we have some credentials specified
         * but it's not the principal authority so we're going
         * to ask ZMS to return a UserToken for us.
         */

        String userName = principal.getName();
        UserToken userToken = getUserToken(userName, null, true);

        clearCredentials();
        client.addCredentials(userToken.getHeader(), userToken.getToken());
        principalCheckDone = true;
    }

    String lookupZMSUrl() {

        String rootDir = System.getenv(STR_ENV_ROOT);
        if (rootDir == null) {
            rootDir = STR_DEF_ROOT;
        }

        String confFileName = System.getProperty(ZMS_CLIENT_PROP_ATHENZ_CONF,
                rootDir + "/conf/athenz/athenz.conf");
        String url = null;
        try {
            Path path = Paths.get(confFileName);
            AthenzConfig conf = JSON.fromBytes(Files.readAllBytes(path), AthenzConfig.class);
            url = conf.getZmsUrl();
        } catch (Exception ex) {
            LOGGER.error("Unable to extract ZMS Url from {} exc: {}", confFileName, ex.getMessage());
        }

        return url;
    }

    protected PoolingHttpClientConnectionManager createConnectionPooling(SSLContext sslContext) {
        if (sslContext == null) {
            return null;
        }
        Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("https", new SSLConnectionSocketFactory(sslContext))
                .register("http", new PlainConnectionSocketFactory())
                .build();
        PoolingHttpClientConnectionManager poolingHttpClientConnectionManager
                = new PoolingHttpClientConnectionManager(registry, dnsResolver);

        // we'll use the default values from apache http connector - max 20 and per route 2

        int maxPerRoute = Integer.parseInt(System.getProperty(ZMS_CLIENT_PROP_POOL_MAX_PER_ROUTE, "2"));
        int maxTotal = Integer.parseInt(System.getProperty(ZMS_CLIENT_PROP_POOL_MAX_TOTAL, "20"));

        poolingHttpClientConnectionManager.setDefaultMaxPerRoute(maxPerRoute);
        poolingHttpClientConnectionManager.setMaxTotal(maxTotal);

        return poolingHttpClientConnectionManager;
    }

    protected CloseableHttpClient createHttpClient(int connTimeoutMs, int readTimeoutMs,
            PoolingHttpClientConnectionManager poolingHttpClientConnectionManager) {

        //apache http client expects in milliseconds
        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout(connTimeoutMs)
                .setSocketTimeout(readTimeoutMs)
                .setRedirectsEnabled(false)
                .build();
        return HttpClients.custom()
                .setConnectionManager(poolingHttpClientConnectionManager)
                .setDefaultRequestConfig(config)
                .build();
    }

    /**
     * Initialize the client for class constructors
     *
     * @param url        ZMS Server url
     * @param sslContext SSLContext for service authentication
     */
    private void initClient(String url, SSLContext sslContext) {

        // if we have no url specified then we're going to retrieve
        // the value from our configuration package */

        zmsUrl = (url == null) ? lookupZMSUrl() : url;
        if (zmsUrl == null || zmsUrl.isEmpty()) {
            throw new IllegalArgumentException("ZMS url must be specified");
        }

        // verify if the url is ending with /zms/v1 and if it's
        // not we'll automatically append it */

        if (!zmsUrl.endsWith("/zms/v1")) {
            if (zmsUrl.charAt(zmsUrl.length() - 1) != '/') {
                zmsUrl += '/';
            }
            zmsUrl += "zms/v1";
        }

        // determine our read and connect timeouts

        int readTimeout = Integer.parseInt(System.getProperty(ZMS_CLIENT_PROP_READ_TIMEOUT, "30000"));
        int connectTimeout = Integer.parseInt(System.getProperty(ZMS_CLIENT_PROP_CONNECT_TIMEOUT, "30000"));

        // if we are not given an url then use the default value

        if (sslContext == null) {
            sslContext = createSSLContext();
        }

        PoolingHttpClientConnectionManager connManager = createConnectionPooling(sslContext);
        CloseableHttpClient httpClient = createHttpClient(connectTimeout, readTimeout, connManager);

        client = new ZMSRDLGeneratedClient(zmsUrl, httpClient);
    }

    SSLContext createSSLContext() {

        // to create the SSL context we must have the keystore path
        // specified. If it's not specified, then we are not going
        // to create our ssl context

        String keyStorePath = System.getProperty(ZMS_CLIENT_PROP_KEYSTORE_PATH);
        if (keyStorePath == null || keyStorePath.isEmpty()) {
            return null;
        }
        String keyStoreType = System.getProperty(ZMS_CLIENT_PROP_KEYSTORE_TYPE);
        String keyStorePwd = System.getProperty(ZMS_CLIENT_PROP_KEYSTORE_PASSWORD);
        char[] keyStorePassword = null;
        if (null != keyStorePwd && !keyStorePwd.isEmpty()) {
            keyStorePassword = keyStorePwd.toCharArray();
        }
        String keyStorePasswordAppName = System.getProperty(ZMS_CLIENT_PROP_KEYSTORE_PWD_APP_NAME);
        char[] keyManagerPassword = null;
        String keyManagerPwd = System.getProperty(ZMS_CLIENT_PROP_KEY_MANAGER_PASSWORD);
        if (null != keyManagerPwd && !keyManagerPwd.isEmpty()) {
            keyManagerPassword = keyManagerPwd.toCharArray();
        }
        String keyManagerPasswordAppName = System.getProperty(ZMS_CLIENT_PROP_KEY_MANAGER_PWD_APP_NAME);

        // truststore
        String trustStorePath = System.getProperty(ZMS_CLIENT_PROP_TRUSTSTORE_PATH);
        String trustStoreType = System.getProperty(ZMS_CLIENT_PROP_TRUSTSTORE_TYPE);
        String trustStorePwd = System.getProperty(ZMS_CLIENT_PROP_TRUSTSTORE_PASSWORD);
        char[] trustStorePassword = null;
        if (null != trustStorePwd && !trustStorePwd.isEmpty()) {
            trustStorePassword = trustStorePwd.toCharArray();
        }
        String trustStorePasswordAppName = System.getProperty(ZMS_CLIENT_PROP_TRUSTSTORE_PWD_APP_NAME);

        // alias and protocol details
        String certAlias = System.getProperty(ZMS_CLIENT_PROP_CERT_ALIAS);
        String clientProtocol = System.getProperty(ZMS_CLIENT_PROP_CLIENT_PROTOCOL,
                ZMS_CLIENT_DEFAULT_CLIENT_SSL_PROTOCOL);

        ClientSSLContextBuilder builder = new SSLUtils.ClientSSLContextBuilder(clientProtocol)
                .privateKeyStore(PRIVATE_KEY_STORE).keyStorePath(keyStorePath);

        builder.certAlias(certAlias);

        if (null != keyStoreType && !keyStoreType.isEmpty()) {
            builder.keyStoreType(keyStoreType);
        }
        builder.keyStorePassword(keyStorePassword);
        builder.keyStorePasswordAppName(keyStorePasswordAppName);
        builder.keyManagerPassword(keyManagerPassword);

        builder.keyManagerPasswordAppName(keyManagerPasswordAppName);

        builder.trustStorePath(trustStorePath);
        if (null != trustStoreType && !trustStoreType.isEmpty()) {
            builder.trustStoreType(trustStoreType);
        }
        builder.trustStorePassword(trustStorePassword);
        builder.trustStorePasswordAppName(trustStorePasswordAppName);

        return builder.build();
    }

    public String getZmsUrl() {
        return zmsUrl;
    }

    /**
     * Generate a role name as expected by ZMS Server can be used to
     * set the role object's name field (e.g. role.setName(name))
     *
     * @param domain name of the domain
     * @param role   name of the role
     * @return full role name
     */
    public String generateRoleName(String domain, String role) {
        return domain + AuthorityConsts.ROLE_SEP + role;
    }

    /**
     * Generate a policy name as expected by ZMS Server can be used to
     * set the policy object's name field (e.g. policy.setName(name))
     *
     * @param domain name of the domain
     * @param policy name of the policy
     * @return full policy name
     */
    public String generatePolicyName(String domain, String policy) {
        return domain + AuthorityConsts.POLICY_SEP + policy;
    }

    /**
     * Generate a service name as expected by ZMS Server can be used to
     * set the service identity object's name field
     * (e.g. serviceIdentity.setName(name))
     *
     * @param domain  name of the domain
     * @param service name of the service
     * @return full service identity name
     */
    public String generateServiceIdentityName(String domain, String service) {
        return domain + "." + service;
    }

    /**
     * Generate an entity name as expected by ZMS Server can be used to
     * set the entity object's name field
     * (e.g. entity.setName(name))
     *
     * @param domain  name of the domain
     * @param entity name of the service
     * @return full entity name
     */
    public String generateEntityName(String domain, String entity) {
        return domain + AuthorityConsts.ENTITY_SEP + entity;
    }

    /**
     * Retrieve the specified domain object
     *
     * @param domain name of the domain to be retrieved
     * @return Domain object
     * @throws ZMSClientException in case of failure
     */
    public Domain getDomain(String domain) {
        updatePrincipal();
        try {
            return client.getDomain(domain);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the specified singed domain object. The domain
     * object includes all roles, policies, services and
     * domain attributes. The domain data is base64url encoded
     * in the payload field based on JWS RFC 7515
     * https://tools.ietf.org/html/rfc7515#section-7.2.2
     *
     * @param domain name of the domain to be retrieved
     * @return JWSDomain object
     * @throws ZMSClientException in case of failure
     */
    public JWSDomain getJWSDomain(String domain) {
        return getJWSDomain(domain, false, null, null);
    }

    /**
     * Retrieve the specified singed domain object. The domain
     * object includes all roles, policies, services and
     * domain attributes. The domain data is base64url encoded
     * in the payload field based on JWS RFC 7515
     * https://tools.ietf.org/html/rfc7515#section-7.2.2
     *
     * @param domain          name of the domain to be retrieved
     * @param matchingTag     (can be null) contains modified timestamp received
     *                        with last request. If null, then return all domains.
     * @param responseHeaders contains the "tag" returned for modification
     *                        time of the domains, map key = "tag", List should
     *                        contain a single value timestamp String to be used
     *                        with subsequent call as matchingTag to this API
     * @return JWSDomain      object
     * @throws ZMSClientException in case of failure
     */
    public JWSDomain getJWSDomain(String domain, String matchingTag, Map<String, List<String>> responseHeaders) {
        return getJWSDomain(domain, false, matchingTag, responseHeaders);
    }

    /**
     * Retrieve the specified singed domain object. The domain
     * object includes all roles, policies, services and
     * domain attributes. The domain data is base64url encoded
     * in the payload field based on JWS RFC 7515
     * https://tools.ietf.org/html/rfc7515#section-7.2.2
     *
     * @param domain          name of the domain to be retrieved
     * @param signatureP1363Format return signature in P1363 format instead of ASN.1 DER
     * @param matchingTag     (can be null) contains modified timestamp received
     *                        with last request. If null, then return all domains.
     * @param responseHeaders contains the "tag" returned for modification
     *                        time of the domains, map key = "tag", List should
     *                        contain a single value timestamp String to be used
     *                        with subsequent call as matchingTag to this API
     * @return JWSDomain      object
     * @throws ZMSClientException in case of failure
     */
    public JWSDomain getJWSDomain(String domain, Boolean signatureP1363Format, String matchingTag, Map<String, List<String>> responseHeaders) {
        updatePrincipal();
        try {
            return client.getJWSDomain(domain, signatureP1363Format, matchingTag, responseHeaders);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of domains provisioned on the ZMS Server
     * @return list of Domains
     * @throws ZMSClientException in case of failure
     */
    public DomainList getDomainList() {
        return getDomainList(null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null);
    }

    /**
     * Retrieve the list of domains provisioned on the ZMS Server
     * filters based on the specified arguments
     * @param limit  number of domain objects to return
     * @param skip   exclude all the domains including the specified one from the return set
     * @param prefix return domains starting with this value
     * @param depth  maximum depth of the domain (0 - top level domains only)
     * @param modifiedSince return domains only modified since this date
     * @return list of domain names
     * @throws ZMSClientException in case of failure
     */
    public DomainList getDomainList(Integer limit, final String skip, final String prefix,
                                    Integer depth, Date modifiedSince) {
        return getDomainList(limit, skip, prefix, depth, null, null, null, null,
                null, null, null, null, null, null, modifiedSince);
    }

    /**
     * Retrieve the list of domains provisioned on the ZMS Server
     * filters based on the specified arguments
     *
     * @param limit         number of domain objects to return
     * @param skip          exclude all the domains including the specified one from the return set
     * @param prefix        return domains starting with this value
     * @param depth         maximum depth of the domain (0 - top level domains only)
     * @param awsAccount    return domain that has the specified aws account name. If account name
     *                      is specified all other optional attributes are ignored since there must be
     *                      only one domain matching the specified account name.
     * @param productNumber return domain that has the specified product number. If product number
     *                      is specified all other optional attributes are ignored since there must be
     *                      only one domain matching the specified product number.
     * @param modifiedSince return domains only modified since this date
     * @return list of domain names
     * @throws ZMSClientException in case of failure
     */
    @Deprecated
    public DomainList getDomainList(Integer limit, String skip, String prefix, Integer depth,
                                    String awsAccount, Integer productNumber, Date modifiedSince) {
        return getDomainList(limit, skip, prefix, depth, awsAccount, productNumber, null, null,
                null, null, null, null, null, null, modifiedSince);
    }

    /**
     * Retrieve the list of domains provisioned on the ZMS Server
     * filters based on the specified arguments
     *
     * @param limit         number of domain objects to return
     * @param skip          exclude all the domains including the specified one from the return set
     * @param prefix        return domains starting with this value
     * @param depth         maximum depth of the domain (0 - top level domains only)
     * @param awsAccount    return domain that has the specified aws account name. If account name
     *                      is specified all other optional attributes are ignored since there must be
     *                      only one domain matching the specified account name.
     * @param productNumber return domain that has the specified product number. If product number
     *                      is specified all other optional attributes are ignored since there must be
     *                      only one domain matching the specified product nubmer.
     * @param azureSubscription return domain that has the specified azure subscription id. If subscription
     *                      id is specified all other optional attributes are ignored since there must be
     *                      only one domain matching the specified subscription id.
     * @param modifiedSince return domains only modified since this date
     * @return list of domain names
     * @throws ZMSClientException in case of failure
     */
    @Deprecated
    public DomainList getDomainList(Integer limit, String skip, String prefix, Integer depth,
                                    String awsAccount, Integer productNumber, String azureSubscription, Date modifiedSince) {
        return getDomainList(limit, skip, prefix, depth, awsAccount, productNumber, null, null,
                azureSubscription, null, null, null, null, null, modifiedSince);
    }

    /**
     * Retrieve the list of domains provisioned on the ZMS Server
     * filters based on the specified arguments
     *
     * @param limit         number of domain objects to return
     * @param skip          exclude all the domains including the specified one from the return set
     * @param prefix        return domains starting with this value
     * @param depth         maximum depth of the domain (0 - top level domains only)
     * @param awsAccount    return domain that has the specified aws account name. If account name
     *                      is specified all other optional attributes are ignored since there must be
     *                      only one domain matching the specified account name.
     * @param productNumber return domain that has the specified product number. If product number
     *                      is specified all other optional attributes are ignored since there must be
     *                      only one domain matching the specified product number.
     * @param azureSubscription return domain that has the specified azure subscription id. If subscription
     *                      id is specified all other optional attributes are ignored since there must be
     *                      only one domain matching the specified subscription id.
     * @param modifiedSince return domains only modified since this date
     * @param tagKey        query all domains with given tag name
     * @param tagValue      query all domains with given tag key and value
     * @return list of domain names
     * @throws ZMSClientException in case of failure
     */
    @Deprecated
    public DomainList getDomainList(Integer limit, String skip, String prefix, Integer depth,
                                    String awsAccount, Integer productNumber, String azureSubscription,
                                    Date modifiedSince, String tagKey, String tagValue) {
        return getDomainList(limit, skip, prefix, depth, awsAccount, productNumber, null, null,
                azureSubscription, null, tagKey, tagValue, null, null, modifiedSince);
    }

    /**
     * Retrieve the list of domains provisioned on the ZMS Server
     * filters based on the specified arguments
     *
     * @param limit         number of domain objects to return
     * @param skip          exclude all the domains including the specified one from the return set
     * @param prefix        return domains starting with this value
     * @param depth         maximum depth of the domain (0 - top level domains only)
     * @param awsAccount    return domain that has the specified aws account name. If account name
     *                      is specified all other optional attributes are ignored since there must be
     *                      only one domain matching the specified account name.
     * @param productNumber return domain that has the specified product number. If product number
     *                      is specified all other optional attributes are ignored since there must be
     *                      only one domain matching the specified product number.
     * @param azureSubscription return domain that has the specified azure subscription id. If subscription
     *                      id is specified all other optional attributes are ignored since there must be
     *                      only one domain matching the specified subscription id.
     * @param modifiedSince return domains only modified since this date
     * @param tagKey        query all domains with given tag name
     * @param tagValue      query all domains with given tag key and value
     * @param businessService returns domains that have the specified business service.
     * @return list of domain names
     * @throws ZMSClientException in case of failure
     */
    @Deprecated
    public DomainList getDomainList(Integer limit, String skip, String prefix, Integer depth,
                                    String awsAccount, Integer productNumber, String azureSubscription,
                                    Date modifiedSince, String tagKey, String tagValue, String businessService) {
        return getDomainList(limit, skip, prefix, depth, awsAccount, productNumber, null, null,
                azureSubscription, null, tagKey, tagValue, businessService, null, modifiedSince);
    }

    /**
     * Retrieve the list of domains provisioned on the ZMS Server
     * filters based on the specified arguments
     * @param productNumber return domain that has the specified product number
     * @return list of domain names
     * @throws ZMSClientException in case of failure
     */
    public DomainList getDomainListByProductId(Integer productNumber) {
        return getDomainList(null, null, null, null, null, productNumber, null, null,
                null, null, null, null, null, null, null);
    }

    /**
     * Retrieve the list of domains provisioned on the ZMS Server
     * filters based on the specified arguments
     * @param productId return domain that has the specified product id
     * @return list of domain names
     * @throws ZMSClientException in case of failure
     */
    public DomainList getDomainListByProductId(String productId) {
        return getDomainList(null, null, null, null, null, null, null, null,
                null, null, null, null, null, productId, null);
    }

    /**
     * Retrieve the list of domains provisioned on the ZMS Server
     * filters based on the specified arguments
     * @param tagKey query all domains with given tag name
     * @param tagValue query all domains with given tag key and value
     * @return list of domain names
     * @throws ZMSClientException in case of failure
     */
    public DomainList getDomainListByTags(final String tagKey, final String tagValue) {
         return getDomainList(null, null, null, null, null, null, null, null,
                 null, null, tagKey, tagValue, null, null, null);
    }

    /**
     * Retrieve the list of domains provisioned on the ZMS Server
     * filters based on the specified arguments
     * @param businessService returns domains that have the specified business service.
     * @return list of domain names
     * @throws ZMSClientException in case of failure
     */
    public DomainList getDomainListByBusinessService(final String businessService) {

        return getDomainList(null, null, null, null, null, null, null, null,
                null, null, null, null, businessService, null, null);
    }

    /**
     * Retrieve the list of domains provisioned on the ZMS Server
     * filters based on the specified arguments
     * @param awsAccount return domain that has the specified aws account name
     * @return list of domain names
     * @throws ZMSClientException in case of failure
     */
    public DomainList getDomainListByAwsAccount(final String awsAccount) {
        return getDomainList(null, null, null, null, awsAccount, null, null, null,
                null, null, null, null, null, null, null);
    }

    /**
     * Retrieve the list of domains provisioned on the ZMS Server
     * filters based on the specified arguments
     * @param azureSubscription return domain that has the specified azure subscription id
     * @return list of domain names
     * @throws ZMSClientException in case of failure
     */
    public DomainList getDomainListByAzureSubscription(final String azureSubscription) {
        return getDomainList(null, null, null, null, null, null, null, null,
                azureSubscription, null, null, null, null, null, null);
    }

    /**
     * Retrieve the list of domains provisioned on the ZMS Server
     * filters based on the specified arguments
     * @param gcpProject return domain that has the specified gcp project name
     * @return list of domain names
     * @throws ZMSClientException in case of failure
     */
    public DomainList getDomainListByGcpProject(final String gcpProject) {
        return getDomainList(null, null, null, null, null, null, null, null,
                null, gcpProject, null, null, null, null, null);
    }

    /**
     * Retrieve the list of domains provisioned on the ZMS Server
     * filters based on the specified arguments
     * @param roleMember name of the principal
     * @param roleName   name of the role where the principal is a member of
     * @return list of domain names
     * @throws ZMSClientException in case of failure
     */
    public DomainList getDomainListByRole(String roleMember, String roleName) {
        return getDomainList(null, null, null, null, null, null, roleMember, roleName,
                null, null, null, null, null, null, null);
    }

    /**
     * Retrieve the list of domains provisioned on the ZMS Server
     * filters based on the specified arguments
     *
     * @param roleMember name of the principal
     * @param roleName   name of the role where the principal is a member of
     * @return list of domain names
     * @throws ZMSClientException in case of failure
     */
    @Deprecated
    public DomainList getDomainList(String roleMember, String roleName) {
        return getDomainList(null, null, null, null, null, null, roleMember, roleName,
                null, null, null, null, null, null, null);
    }

    private DomainList getDomainList(Integer limit, final String skip, final String prefix, Integer depth,
                             final String awsAccount, Integer productNumber, final String roleMember, final String roleName,
                             final String azureSubscription, final String gcpProject, final String tagKey,
                             final String tagValue, final String businessService, String productId, Date modifiedSince) {
        updatePrincipal();
        String modSinceStr = null;
        if (modifiedSince != null) {
            DateFormat df = new SimpleDateFormat(HTTP_RFC1123_DATE_FORMAT);
            modSinceStr = df.format(modifiedSince);
        }
        try {
            return client.getDomainList(limit, skip, prefix, depth, awsAccount, productNumber, roleMember, roleName,
                    azureSubscription, gcpProject, tagKey, tagValue, businessService, productId, modSinceStr);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create/Update Top level domain. If updating a domain the provided
     * object must contain all attributes as it will replace the full domain
     * object configured on the server (not just some of the attributes).
     *
     * @param auditRef string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @param detail TopLevelDomain object to be created in ZMS
     * @return created Domain object
     * @throws ZMSClientException in case of failure
     */
    public Domain postTopLevelDomain(String auditRef, String resourceOwner, TopLevelDomain detail) {
        updatePrincipal();
        try {
            return client.postTopLevelDomain(auditRef, resourceOwner, detail);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create/Update Top level domain. If updating a domain the provided
     * object must contain all attributes as it will replace the full domain
     * object configured on the server (not just some of the attributes).
     *
     * @param auditRef string containing audit specification or ticket number
     * @param detail TopLevelDomain object to be created in ZMS
     * @return created Domain object
     * @throws ZMSClientException in case of failure
     */
    public Domain postTopLevelDomain(String auditRef, TopLevelDomain detail) {
        return postTopLevelDomain(auditRef, null, detail);
    }

    /**
     * Create/Update a sub-domain in the specified domain. If updating a
     * subdomain the provided object must contain all attributes as it will
     * replace the full domain object configured on the server (not just some
     * of the attributes).
     *
     * @param parent name of the parent domain
     * @param auditRef string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @param detail SubDomain object to be created in ZMS
     * @return created Domain object
     * @throws ZMSClientException in case of failure
     */
    public Domain postSubDomain(String parent, String auditRef, String resourceOwner, SubDomain detail) {
        updatePrincipal();
        try {
            return client.postSubDomain(parent, auditRef, resourceOwner, detail);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create/Update a sub-domain in the specified domain. If updating a
     * subdomain the provided object must contain all attributes as it will
     * replace the full domain object configured on the server (not just some
     * of the attributes).
     *
     * @param parent name of the parent domain
     * @param auditRef string containing audit specification or ticket number
     * @param detail SubDomain object to be created in ZMS
     * @return created Domain object
     * @throws ZMSClientException in case of failure
     */
    public Domain postSubDomain(String parent, String auditRef, SubDomain detail) {
        return postSubDomain(parent, auditRef, null, detail);
    }

    /**
     * Create a top-level user-domain - this is user.&lt;userid&gt; domain.
     *
     * @param name domain to be created, this is the &lt;userid&gt;
     * @param auditRef string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @param detail UserDomain object to be created in ZMS
     * @return created Domain object
     * @throws ZMSClientException in case of failure
     */
    public Domain postUserDomain(String name, String auditRef, String resourceOwner, UserDomain detail) {
        updatePrincipal();
        try {
            return client.postUserDomain(name, auditRef, resourceOwner, detail);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create a top-level user-domain - this is user.&lt;userid&gt; domain.
     *
     * @param name domain to be created, this is the &lt;userid&gt;
     * @param auditRef string containing audit specification or ticket number
     * @param detail UserDomain object to be created in ZMS
     * @return created Domain object
     * @throws ZMSClientException in case of failure
     */
    public Domain postUserDomain(String name, String auditRef, UserDomain detail) {
        return postUserDomain(name, auditRef, null, detail);
    }

    /**
     * Delete a top level domain
     *
     * @param name domain name to be deleted from ZMS
     * @param auditRef string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public void deleteTopLevelDomain(String name, String auditRef, String resourceOwner) {
        updatePrincipal();
        try {
            client.deleteTopLevelDomain(name, auditRef, resourceOwner);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete a top level domain
     *
     * @param name domain name to be deleted from ZMS
     * @param auditRef string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteTopLevelDomain(String name, String auditRef) {
        deleteTopLevelDomain(name, auditRef, null);
    }

    /**
     * Delete a sub-domain
     *
     * @param parent name of the parent domain
     * @param name sub-domain to be deleted
     * @param auditRef string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public void deleteSubDomain(String parent, String name, String auditRef, String resourceOwner) {
        updatePrincipal();
        try {
            client.deleteSubDomain(parent, name, auditRef, resourceOwner);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete a sub-domain
     *
     * @param parent name of the parent domain
     * @param name sub-domain to be deleted
     * @param auditRef string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteSubDomain(String parent, String name, String auditRef) {
        deleteSubDomain(parent, name, auditRef, null);
    }

    /**
     * Delete a top-level user-domain (user.&lt;userid&gt;)
     *
     * @param name domain to be deleted, this is the &lt;userid&gt;
     * @param auditRef string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public void deleteUserDomain(String name, String auditRef, String resourceOwner) {
        updatePrincipal();
        try {
            client.deleteUserDomain(name, auditRef, resourceOwner);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete a top-level user-domain (user.&lt;userid&gt;)
     *
     * @param name domain to be deleted, this is the &lt;userid&gt;
     * @param auditRef string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteUserDomain(String name, String auditRef) {
        deleteUserDomain(name, auditRef, null);
    }

    /**
     * Set the domain meta parameters
     *
     * @param name domain name to be modified
     * @param auditRef string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @param detail meta parameters to be set on the domain
     */
    public void putDomainMeta(String name, String auditRef, String resourceOwner, DomainMeta detail) {
        updatePrincipal();
        try {
            client.putDomainMeta(name, auditRef, resourceOwner, detail);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Set the domain meta parameters
     *
     * @param name domain name to be modified
     * @param auditRef string containing audit specification or ticket number
     * @param detail meta parameters to be set on the domain
     */
    public void putDomainMeta(String name, String auditRef, DomainMeta detail) {
        putDomainMeta(name, auditRef, null, detail);
    }

    /**
     * Set the domain system meta parameters
     *
     * @param name      domain name to be modified
     * @param attribute system attribute being modified in this request
     * @param auditRef  string containing audit specification or ticket number
     * @param detail    meta parameters to be set on the domain
     */
    public void putDomainSystemMeta(String name, String attribute, String auditRef, DomainMeta detail) {
        updatePrincipal();
        try {
            client.putDomainSystemMeta(name, attribute, auditRef, detail);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of roles defined for the specified domain
     *
     * @param domainName name of the domain
     * @return list of role names
     * @throws ZMSClientException in case of failure
     */
    public RoleList getRoleList(String domainName) {
        updatePrincipal();
        try {
            return client.getRoleList(domainName, null, null);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of roles defined for the specified domain
     * filtered based on the parameters specified
     *
     * @param domainName name of the domain
     * @param limit      number of roles to return
     * @param skip       exclude all the roles including the specified one from the return set
     * @return list of role names
     * @throws ZMSClientException in case of failure
     */
    public RoleList getRoleList(String domainName, Integer limit, String skip) {
        updatePrincipal();
        try {
            return client.getRoleList(domainName, limit, skip);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of roles defined for the specified domain. The roles
     * will contain their attributes and, if specified, the list of members.
     *
     * @param domainName name of the domain
     * @param members    include all members for group roles as well
     * @param tagKey     query all roles with given tag name
     * @param tagValue   query all roles with given tag key and value
     * @return list of roles
     * @throws ZMSClientException in case of failure
     */
    public Roles getRoles(String domainName, Boolean members, String tagKey, String tagValue) {
        updatePrincipal();
        try {
            return client.getRoles(domainName, members, tagKey, tagValue);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of roles defined for the specified domain. The roles
     * will contain their attributes and, if specified, the list of members.
     *
     * @param domainName name of the domain
     * @param members    include all members for group roles as well
     * @return list of roles
     * @throws ZMSClientException in case of failure
     */
    public Roles getRoles(String domainName, Boolean members) {
        return getRoles(domainName, members, null, null);
    }

    /**
     * Retrieve the specified role
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @return role object
     * @throws ZMSClientException in case of failure
     */
    public Role getRole(String domainName, String roleName) {
        return getRole(domainName, roleName, false, false, false);
    }

    /**
     * Retrieve the specified role
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param auditLog   include audit log for the role changes in the response
     * @return role object
     * @throws ZMSClientException in case of failure
     */
    public Role getRole(String domainName, String roleName, boolean auditLog) {
        return getRole(domainName, roleName, auditLog, false, false);
    }

    /**
     * Retrieve the specified role
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param auditLog   include audit log for the role changes in the response
     * @param expand     if the requested role is a delegated/trust role, this flag
     *                   will instruct the ZMS server to automatically retrieve the members of the
     *                   role from the delegated domain and return as part of the role object
     * @return role object
     * @throws ZMSClientException in case of failure
     */
    public Role getRole(String domainName, String roleName, boolean auditLog, boolean expand) {
        return getRole(domainName, roleName, auditLog, expand, false);
    }

    /**
     * Retrieve the specified role
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param auditLog   include audit log for the role changes in the response
     * @param expand     if the requested role is a delegated/trust role, this flag
     *                   will instruct the ZMS server to automatically retrieve the members of the
     *                   role from the delegated domain and return as part of the role object
     * @param pending    if this flag is set, then all members for that role will be retrieved
     *                   including pending members
     * @return role object
     * @throws ZMSClientException in case of failure
     */
    public Role getRole(String domainName, String roleName, boolean auditLog, boolean expand, boolean pending) {
        updatePrincipal();
        try {
            return client.getRole(domainName, roleName, auditLog, expand, pending);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create/Update a new role in the specified domain. If updating a role
     * the provided object must contain all attributes as it will replace
     * the full role object configured on the server (not just some of the attributes).
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param auditRef   string containing audit specification or ticket number
     * @param returnObj  Boolean returns the updated object from the database if true
     * @param resourceOwner string containing the owner of the resource
     * @param role       role object to be added to the domain
     * @throws ZMSClientException in case of failure
     */
    public Role putRole(String domainName, String roleName, String auditRef, Boolean returnObj, String resourceOwner, Role role) {
        updatePrincipal();
        try {
            return client.putRole(domainName, roleName, auditRef, returnObj, resourceOwner, role);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create/Update a new role in the specified domain. If updating a role
     * the provided object must contain all attributes as it will replace
     * the full role object configured on the server (not just some of the attributes).
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param auditRef   string containing audit specification or ticket number
     * @param returnObj  Boolean returns the updated object from the database if true
     * @param role       role object to be added to the domain
     * @throws ZMSClientException in case of failure
     */
    public Role putRole(String domainName, String roleName, String auditRef, Boolean returnObj, Role role) {
        return putRole(domainName, roleName, auditRef, returnObj, null, role);
    }

    /**
     * Create/Update a new role in the specified domain. If updating a role
     * the provided object must contain all attributes as it will replace
     * the full role object configured on the server (not just some of the attributes).
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param auditRef   string containing audit specification or ticket number
     * @param role       role object to be added to the domain
     * @throws ZMSClientException in case of failure
     */
    public void putRole(String domainName, String roleName, String auditRef, Role role) {
        putRole(domainName, roleName, auditRef, false, role);
    }

    /**
     * Delete the specified role from domain
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param auditRef   string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public void deleteRole(String domainName, String roleName, String auditRef, String resourceOwner) {
        updatePrincipal();
        try {
            client.deleteRole(domainName, roleName, auditRef, resourceOwner);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete the specified role from domain
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteRole(String domainName, String roleName, String auditRef) {
        deleteRole(domainName, roleName, auditRef, null);
    }

    /**
     * Get membership details for the specified member in the given role
     * in a specified domain
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param memberName name of the member
     * @return Membership object
     * @throws ZMSClientException in case of failure
     */
    public Membership getMembership(String domainName, String roleName, String memberName) {
        return getMembership(domainName, roleName, memberName, null);
    }

    /**
     * Get membership details for the specified member in the given role
     * in a specified domain with an optional expiration
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param memberName name of the member
     * @param expiration member expiration
     * @return Membership object
     * @throws ZMSClientException in case of failure
     */
    public Membership getMembership(String domainName, String roleName, String memberName, String expiration) {
        updatePrincipal();
        try {
            return client.getMembership(domainName, roleName, memberName, expiration);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Get all domain members with overdue review dates
     *
     * @param domainName name of the domain
     * @return Domain members with overdue review dates
     */
    public DomainRoleMembers getOverdueReview(String domainName) {
        updatePrincipal();
        try {
            return client.getOverdueReview(domainName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Add a new member in the specified role.
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param memberName name of the member to be added
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void putMembership(String domainName, String roleName, String memberName, String auditRef) {
        putMembershipWithReview(domainName, roleName, memberName, null, null, auditRef);
    }

    /**
     * Add a new member in the specified role.
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param memberName name of the member to be added
     * @param auditRef   string containing audit specification or ticket number
     * @param returnObj  boolean returns the updated object from the database if true
     * @throws ZMSClientException in case of failure
     */
    public Membership putMembership(String domainName, String roleName, String memberName,
                                    String auditRef, Boolean returnObj) {
        return putMembershipWithReview(domainName, roleName, memberName, null, null, auditRef, returnObj);
    }

    /**
     * Add a temporary member in the specified role with expiration
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param memberName name of the member to be added
     * @param expiration timestamp when this membership will expire (optional)
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void putMembership(String domainName, String roleName, String memberName,
                              Timestamp expiration, String auditRef) {
        putMembershipWithReview(domainName, roleName, memberName, expiration, null, auditRef);
    }

    /**
     * Add a new member in the specified role.
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param memberName name of the member to be added
     * @param auditRef   string containing audit specification or ticket number
     * @param returnObj  boolean returns the updated object from the database if true
     * @throws ZMSClientException in case of failure
     */
    public Membership putMembership(String domainName, String roleName, String memberName, Timestamp expiration,
                                    String auditRef, Boolean returnObj) {
        return putMembershipWithReview(domainName, roleName, memberName, expiration, null, auditRef, returnObj);
    }

    /**
     * Add a member in the specified role with optional expiration and optional review
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param memberName name of the member to be added
     * @param expiration timestamp when this membership will expire (optional)
     * @param review     timestamp when this membership will require review (optional)
     * @param auditRef   string containing audit specification or ticket number
     * @param returnObj  Boolean returns the updated object from the database if true
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public Membership putMembershipWithReview(String domainName, String roleName, String memberName,
            Timestamp expiration, Timestamp review, String auditRef, Boolean returnObj, String resourceOwner) {
        Membership mbr = new Membership().setRoleName(roleName)
                .setMemberName(memberName).setExpiration(expiration).setReviewReminder(review)
                .setIsMember(true);
        updatePrincipal();
        try {
            return client.putMembership(domainName, roleName, memberName, auditRef, returnObj, resourceOwner, mbr);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Add a member in the specified role with optional expiration and optional review
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param memberName name of the member to be added
     * @param expiration timestamp when this membership will expire (optional)
     * @param review     timestamp when this membership will require review (optional)
     * @param auditRef   string containing audit specification or ticket number
     * @param returnObj  Boolean returns the updated object from the database if true
     * @throws ZMSClientException in case of failure
     */
    public Membership putMembershipWithReview(String domainName, String roleName, String memberName,
            Timestamp expiration, Timestamp review, String auditRef, Boolean returnObj) {
        return putMembershipWithReview(domainName, roleName, memberName, expiration, review, auditRef, returnObj, null);
    }

    /**
     * Add a member in the specified role with optional expiration and optional review
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param memberName name of the member to be added
     * @param expiration timestamp when this membership will expire (optional)
     * @param review     timestamp when this membership will require review (optional)
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void putMembershipWithReview(String domainName, String roleName, String memberName,
                              Timestamp expiration, Timestamp review, String auditRef) {
      putMembershipWithReview(domainName, roleName, memberName, expiration, review, auditRef, false);
    }

    /**
     * Remove the specified member from the role
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param memberName name of the member to be removed
     * @param auditRef   string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public void deleteMembership(String domainName, String roleName, String memberName, String auditRef, String resourceOwner) {
        updatePrincipal();
        try {
            client.deleteMembership(domainName, roleName, memberName, auditRef, resourceOwner);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Remove the specified member from the role
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param memberName name of the member to be removed
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteMembership(String domainName, String roleName, String memberName, String auditRef) {
        deleteMembership(domainName, roleName, memberName, auditRef, null);
    }

    /**
     * Remove the specified pending member from the role
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param memberName name of the pending member to be removed
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deletePendingMembership(String domainName, String roleName, String memberName, String auditRef) {
        updatePrincipal();
        try {
            client.deletePendingMembership(domainName, roleName, memberName, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Get list of users defined in the system
     *
     * @param domainName optional name of the user domain and/or alias domain
     * @return list of user names
     * @throws ZMSClientException in case of failure
     */
    public UserList getUserList(String domainName) {
        updatePrincipal();
        try {
            return client.getUserList(domainName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Get list of users defined in the system
     *
     * @return list of user names
     * @throws ZMSClientException in case of failure
     */
    public UserList getUserList() {
        return getUserList(null);
    }

    /**
     * Remove the specified user from Athens system. This will delete any
     * user.{name} domain plus all of its subdomains (if exist) and remove
     * the user from any role in the system. This command requires authorization
     * from the Athens sys.auth domain (delete action on resource user).
     *
     * @param name     name of the user
     * @param auditRef string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteUser(String name, String auditRef) {
        updatePrincipal();
        try {
            client.deleteUser(name, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of policies defined for the specified domain. The policies
     * will contain their attributes and, if specified, the list of assertions.
     *
     * @param domainName name of the domain
     * @param assertions include all assertion for policies as well
     * @return list of policies
     * @throws ZMSClientException in case of failure
     */
    public Policies getPolicies(String domainName, Boolean assertions) {
        return getPoliciesImpl(domainName, assertions, false);
    }

    /**
     * Retrieve the list of policies defined for the specified domain. The policies
     * will contain their attributes and, if specified, the list of assertions.
     *
     * @param domainName name of the domain
     * @param assertions include all assertion for policies as well
     * @param includeNonActive include non-active policy versions
     * @return list of policies
     * @throws ZMSClientException in case of failure
     */
    public Policies getPolicies(String domainName, Boolean assertions, Boolean includeNonActive) {
        return getPoliciesImpl(domainName, assertions, includeNonActive);
    }

    private Policies getPoliciesImpl(String domainName, Boolean assertions, Boolean includeNonActive) {
        updatePrincipal();
        try {
            return client.getPolicies(domainName, assertions, includeNonActive, null, null);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Get list of policies defined in the specified domain
     *
     * @param domainName name of the domain
     * @return list of policy names
     * @throws ZMSClientException in case of failure
     */
    public PolicyList getPolicyList(String domainName) {
        updatePrincipal();
        try {
            return client.getPolicyList(domainName, null, null);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Get list of policies defined in the specified domain filtered
     * based on the specified arguments
     *
     * @param domainName name of the domain
     * @param limit      number of policies to return
     * @param skip       exclude all the policies including the specified one from the return set
     * @return list of policy names
     * @throws ZMSClientException in case of failure
     */
    public PolicyList getPolicyList(String domainName, Integer limit, String skip) {
        updatePrincipal();
        try {
            return client.getPolicyList(domainName, limit, skip);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Get list of policy versions for policy in a domain
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @return list of policy versions
     * @throws ZMSClientException in case of failure
     */
    public PolicyList getPolicyVersionList(String domainName, String policyName) {
        updatePrincipal();
        try {
            return client.getPolicyVersionList(domainName, policyName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Return the specified policy object assertion
     *
     * @param domainName  name of the domain
     * @param policyName  name of the policy
     * @param assertionId the id of the assertion to be retrieved
     * @return Assertion object
     * @throws ZMSClientException in case of failure
     */
    public Assertion getAssertion(String domainName, String policyName, Long assertionId) {
        updatePrincipal();
        try {
            return client.getAssertion(domainName, policyName, assertionId);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Add the specified assertion to the specified policy
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param auditRef   string containing audit specification or ticket number
     * @param resourceOwner the owner of the resource
     * @param assertion  Assertion object to be added to the policy
     * @return updated assertion object that includes the server assigned id
     * @throws ZMSClientException in case of failure
     */
    public Assertion putAssertion(String domainName, String policyName, String auditRef, String resourceOwner,
            Assertion assertion) {
        updatePrincipal();
        try {
            return client.putAssertion(domainName, policyName, auditRef, resourceOwner, assertion);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Add the specified assertion to the specified policy
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param auditRef   string containing audit specification or ticket number
     * @param assertion  Assertion object to be added to the policy
     * @return updated assertion object that includes the server assigned id
     * @throws ZMSClientException in case of failure
     */
    public Assertion putAssertion(String domainName, String policyName, String auditRef, Assertion assertion) {
        return putAssertion(domainName, policyName, auditRef, null, assertion);
    }

    /**
     * Add the specified assertion to the specified policy
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param version    version of the policy
     * @param auditRef   string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @param assertion  Assertion object to be added to the policy
     * @return updated assertion object that includes the server assigned id
     * @throws ZMSClientException in case of failure
     */
    public Assertion putAssertionPolicyVersion(String domainName, String policyName, String version, String auditRef,
            String resourceOwner, Assertion assertion) {
        updatePrincipal();
        try {
            return client.putAssertionPolicyVersion(domainName, policyName, version, auditRef, resourceOwner, assertion);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Add the specified assertion to the specified policy
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param version    version of the policy
     * @param auditRef   string containing audit specification or ticket number
     * @param assertion  Assertion object to be added to the policy
     * @return updated assertion object that includes the server assigned id
     * @throws ZMSClientException in case of failure
     */
    public Assertion putAssertionPolicyVersion(String domainName, String policyName, String version, String auditRef,
            Assertion assertion) {
        return putAssertionPolicyVersion(domainName, policyName, version, auditRef, null, assertion);
    }

    /**
     * Delete specified assertion from the given policy
     *
     * @param domainName  name of the domain
     * @param policyName  name of the policy
     * @param assertionId the id of the assertion to be deleted
     * @param auditRef    string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public void deleteAssertion(String domainName, String policyName, Long assertionId, String auditRef,
            String resourceOwner) {
        updatePrincipal();
        try {
            client.deleteAssertion(domainName, policyName, assertionId, auditRef, resourceOwner);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete specified assertion from the given policy
     *
     * @param domainName  name of the domain
     * @param policyName  name of the policy
     * @param assertionId the id of the assertion to be deleted
     * @param auditRef    string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteAssertion(String domainName, String policyName, Long assertionId, String auditRef) {
        deleteAssertion(domainName, policyName, assertionId, auditRef, null);
    }

    /**
     * Delete specified assertion from the given policy
     *
     * @param domainName  name of the domain
     * @param policyName  name of the policy
     * @param version     name of the version
     * @param assertionId the id of the assertion to be deleted
     * @param auditRef    string containing audit specification or ticket number
     * @param resourceOwner string contianing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public void deleteAssertion(String domainName, String policyName, String version, Long assertionId,
            String auditRef, String resourceOwner) {
        updatePrincipal();
        try {
            client.deleteAssertionPolicyVersion(domainName, policyName, version, assertionId, auditRef, resourceOwner);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete specified assertion from the given policy
     *
     * @param domainName  name of the domain
     * @param policyName  name of the policy
     * @param version     name of the version
     * @param assertionId the id of the assertion to be deleted
     * @param auditRef    string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteAssertion(String domainName, String policyName, String version, Long assertionId, String auditRef) {
        deleteAssertion(domainName, policyName, version, assertionId, auditRef, null);
    }

    /**
     * Return the specified policy object
     *
     * @param domainName name of the domain
     * @param policyName name of the policy to be retrieved
     * @return Policy object
     * @throws ZMSClientException in case of failure
     */
    public Policy getPolicy(String domainName, String policyName) {
        updatePrincipal();
        try {
            return client.getPolicy(domainName, policyName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Return the specified policy version object
     *
     * @param domainName name of the domain
     * @param policyName name of the policy to be retrieved
     * @param version    name of the policy version to be retrieved
     * @return Policy object
     * @throws ZMSClientException in case of failure
     */
    public Policy getPolicyVersion(String domainName, String policyName, String version) {
        updatePrincipal();
        try {
            return client.getPolicyVersion(domainName, policyName, version);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create/Update a new policy in the specified domain. If updating a policy
     * the provided object must contain all attributes as it will replace the
     * full policy object configured on the server (not just some of the attributes).
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param auditRef   string containing audit specification or ticket number
     * @param policy     Policy object with details
     * @param returnObj Boolean returns the updated object from the database if true
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public Policy putPolicy(String domainName, String policyName, String auditRef, Boolean returnObj,
            String resourceOwner, Policy policy) {
        updatePrincipal();
        try {
            return client.putPolicy(domainName, policyName, auditRef, returnObj, resourceOwner, policy);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create/Update a new policy in the specified domain. If updating a policy
     * the provided object must contain all attributes as it will replace the
     * full policy object configured on the server (not just some of the attributes).
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param auditRef   string containing audit specification or ticket number
     * @param policy     Policy object with details
     * @param returnObj Boolean returns the updated object from the database if true
     * @throws ZMSClientException in case of failure
     */
    public Policy putPolicy(String domainName, String policyName, String auditRef, Boolean returnObj, Policy policy) {
        return putPolicy(domainName, policyName, auditRef, returnObj, null, policy);
    }

    /**
     * Create/Update a new policy in the specified domain. If updating a policy
     * the provided object must contain all attributes as it will replace the
     * full policy object configured on the server (not just some of the attributes).
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param auditRef   string containing audit specification or ticket number
     * @param policy     Policy object with details
     * @throws ZMSClientException in case of failure
     */
    public void putPolicy(String domainName, String policyName, String auditRef, Policy policy) {
       putPolicy(domainName, policyName, auditRef, false, policy);
    }

    /**
     * Create a new policy version in the specified domain.
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param version    name of the policy version
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void putPolicyVersion(String domainName, String policyName, String version, String auditRef) {
        putPolicyVersionImpl(domainName, policyName, version, null, auditRef, false, null);
    }

    /**
     * Create a new policy version in the specified domain.
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param version    name of the policy version
     * @param fromVersion    name of the policy version to copy assertions from
     * @param auditRef   string containing audit specification or ticket number
     * @param returnObj Boolean returns the updated object from the database if true
     * @throws ZMSClientException in case of failure
     */
    public Policy putPolicyVersion(String domainName, String policyName, String version, String fromVersion,
            String auditRef, Boolean returnObj) {
        return putPolicyVersionImpl(domainName, policyName, version, fromVersion, auditRef, returnObj, null);
    }

    /**
     * Create a new policy version in the specified domain.
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param version    name of the policy version
     * @param fromVersion    name of the policy version to copy assertions from
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void putPolicyVersion(String domainName, String policyName, String version, String fromVersion, String auditRef) {
        putPolicyVersionImpl(domainName, policyName, version, fromVersion, auditRef, false, null);
    }

    /**
     * Create a new policy version in the specified domain.
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param version    name of the policy version
     * @param fromVersion    name of the policy version to copy assertions from
     * @param auditRef   string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public void putPolicyVersion(String domainName, String policyName, String version, String fromVersion,
            String auditRef, String resourceOwner) {
        putPolicyVersionImpl(domainName, policyName, version, fromVersion, auditRef, false, resourceOwner);
    }

    private Policy putPolicyVersionImpl(String domainName, String policyName, String version, String fromVersion,
            String auditRef, Boolean returnObj, String resourceOwner) {
        updatePrincipal();
        try {
            PolicyOptions policyOptions = new PolicyOptions();
            policyOptions.setVersion(version);
            if (fromVersion != null) {
                policyOptions.setFromVersion(fromVersion);
            }
            return client.putPolicyVersion(domainName, policyName, policyOptions, auditRef, returnObj, resourceOwner);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete specified policy from a domain
     *
     * @param domainName name of the domain
     * @param policyName name of the policy to be deleted
     * @param auditRef   string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public void deletePolicy(String domainName, String policyName, String auditRef, String resourceOwner) {
        updatePrincipal();
        try {
            client.deletePolicy(domainName, policyName, auditRef, resourceOwner);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete specified policy from a domain
     *
     * @param domainName name of the domain
     * @param policyName name of the policy to be deleted
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deletePolicy(String domainName, String policyName, String auditRef) {
        deletePolicy(domainName, policyName, auditRef, null);
    }

    /**
     * Delete specified policy version from a domain
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param version    name of the version to be deleted
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deletePolicyVersion(String domainName, String policyName, String version,
            String auditRef, String resourceOwner) {
        updatePrincipal();
        try {
            client.deletePolicyVersion(domainName, policyName, version, auditRef, resourceOwner);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete specified policy version from a domain
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param version    name of the version to be deleted
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deletePolicyVersion(String domainName, String policyName, String version, String auditRef) {
        deletePolicyVersion(domainName, policyName, version, auditRef, null);
    }

    /**
     * Set a specified policy version active
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param version    name of the version to be activated
     * @param auditRef   string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public void setActivePolicyVersion(String domainName, String policyName, String version,
            String auditRef, String resourceOwner) {
        updatePrincipal();
        try {
            PolicyOptions policyOptions = new PolicyOptions();
            policyOptions.setVersion(version);
            client.setActivePolicyVersion(domainName, policyName, policyOptions, auditRef, resourceOwner);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Set a specified policy version active
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param version    name of the version to be activated
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void setActivePolicyVersion(String domainName, String policyName, String version, String auditRef) {
        setActivePolicyVersion(domainName, policyName, version, auditRef, null);
    }

    /**
     * Create/Update a new service in the specified domain.  If updating a service
     * the provided object must contain all attributes as it will replace the
     * full service object configured on the server (not just some of the attributes).
     *
     * @param domainName  name of the domain
     * @param serviceName name of the service
     * @param auditRef    string containing audit specification or ticket number
     * @param service     ServiceIdentity object with all service details
     * @param returnObj Boolean returns the updated object from the database if true
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public ServiceIdentity putServiceIdentity(String domainName, String serviceName,
            String auditRef, Boolean returnObj, String resourceOwner, ServiceIdentity service) {
        updatePrincipal();
        try {
            return client.putServiceIdentity(domainName, serviceName, auditRef, returnObj, resourceOwner, service);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create/Update a new service in the specified domain.  If updating a service
     * the provided object must contain all attributes as it will replace the
     * full service object configured on the server (not just some of the attributes).
     *
     * @param domainName  name of the domain
     * @param serviceName name of the service
     * @param auditRef    string containing audit specification or ticket number
     * @param service     ServiceIdentity object with all service details
     * @param returnObj Boolean returns the updated object from the database if true
     * @throws ZMSClientException in case of failure
     */
    public ServiceIdentity putServiceIdentity(String domainName, String serviceName,
                                   String auditRef, Boolean returnObj, ServiceIdentity service) {
        return putServiceIdentity(domainName, serviceName, auditRef, returnObj, null, service);
    }

    /**
     * Create/Update a new service in the specified domain.  If updating a service
     * the provided object must contain all attributes as it will replace the
     * full service object configured on the server (not just some of the attributes).
     *
     * @param domainName  name of the domain
     * @param serviceName name of the service
     * @param auditRef    string containing audit specification or ticket number
     * @param service     ServiceIdentity object with all service details
     * @throws ZMSClientException in case of failure
     */
    public void putServiceIdentity(String domainName, String serviceName,
                                   String auditRef, ServiceIdentity service) {
        putServiceIdentity(domainName, serviceName, auditRef, false, service);
    }

    /**
     * Set the service system meta parameters
     *
     * @param domainName  name of the domain
     * @param serviceName name of the service
     * @param attribute   service meta attribute being modified in this request
     * @param auditRef    string containing audit specification or ticket number
     * @param meta        meta parameters to be set on the service
     * @throws ZMSClientException in case of failure
     */
    public void putServiceIdentitySystemMeta(String domainName, String serviceName,
                                             String attribute, String auditRef, ServiceIdentitySystemMeta meta) {
        updatePrincipal();
        try {
            client.putServiceIdentitySystemMeta(domainName, serviceName, attribute, auditRef, meta);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the specified service object from a domain
     *
     * @param domainName  name of the domain
     * @param serviceName name of the service to be retrieved
     * @return ServiceIdentity object
     * @throws ZMSClientException in case of failure
     */
    public ServiceIdentity getServiceIdentity(String domainName, String serviceName) {
        updatePrincipal();
        try {
            return client.getServiceIdentity(domainName, serviceName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete the specified service from a domain
     *
     * @param domainName  name of the domain
     * @param serviceName name of the service to be deleted
     * @param auditRef    string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public void deleteServiceIdentity(String domainName, String serviceName, String auditRef, String resourceOwner) {
        updatePrincipal();
        try {
            client.deleteServiceIdentity(domainName, serviceName, auditRef, resourceOwner);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete the specified service from a domain
     *
     * @param domainName  name of the domain
     * @param serviceName name of the service to be deleted
     * @param auditRef    string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteServiceIdentity(String domainName, String serviceName, String auditRef) {
        deleteServiceIdentity(domainName, serviceName, auditRef, null);
    }

    /**
     * Retrieve the list of services defined for the specified domain. The services
     * will contain their attributes and, if specified, the list of publickeys and hosts.
     *
     * @param domainName name of the domain
     * @param publicKeys include all public keys for services as well
     * @param hosts      include all configured hosts for services as well
     * @return list of services
     * @throws ZMSClientException in case of failure
     */
    public ServiceIdentities getServiceIdentities(String domainName, Boolean publicKeys, Boolean hosts) {
        return getServiceIdentities(domainName, publicKeys, hosts, null, null);
    }

    /**
     * Retrieve the list of services defined for the specified domain. The services
     * will contain their attributes and, if specified, the list of publickeys and hosts.
     *
     * @param domainName name of the domain
     * @param publicKeys include all public keys for services as well
     * @param hosts      include all configured hosts for services as well
     * @param tagKey     query all services with given tag name
     * @param tagValue   query all services with given tag key and value
     * @return list of services
     * @throws ZMSClientException in case of failure
     */
    public ServiceIdentities getServiceIdentities(String domainName, Boolean publicKeys, Boolean hosts,
            String tagKey, String tagValue) {
        updatePrincipal();
        try {
            return client.getServiceIdentities(domainName, publicKeys, hosts, tagKey, tagValue);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the full list of services defined in a domain
     *
     * @param domainName name of the domain
     * @return list of all service names
     * @throws ZMSClientException in case of failure
     */
    public ServiceIdentityList getServiceIdentityList(String domainName) {
        return getServiceIdentityList(domainName, null, null);
    }

    /**
     * Retrieve the list of services defined in a domain filtered
     * based on the specified arguments
     *
     * @param domainName name of the domain
     * @param limit      number of services to return
     * @param skip       exclude all the services including the specified one from the return set
     * @return list of service names
     * @throws ZMSClientException in case of failure
     */
    public ServiceIdentityList getServiceIdentityList(String domainName, Integer limit, String skip) {
        updatePrincipal();
        try {
            return client.getServiceIdentityList(domainName, limit, skip);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the specified public key from the given service object
     *
     * @param domainName  name of the domain
     * @param serviceName name of the service
     * @param keyId       the identifier of the public key to be retrieved
     * @return PublicKeyEntry object
     * @throws ZMSClientException in case of failure
     */
    public PublicKeyEntry getPublicKeyEntry(String domainName, String serviceName, String keyId) {
        updatePrincipal();
        try {
            return client.getPublicKeyEntry(domainName, serviceName, keyId);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Update or add (if doesn't already exist) the specified public key in the service object
     *
     * @param domainName     name of the domain
     * @param serviceName    name of the service
     * @param keyId          the identifier of the public key to be updated
     * @param auditRef       string containing audit specification or ticket number
     * @param publicKeyEntry that contains the public key details
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public void putPublicKeyEntry(String domainName, String serviceName, String keyId, String auditRef,
            String resourceOwner, PublicKeyEntry publicKeyEntry) {
        updatePrincipal();
        try {
            client.putPublicKeyEntry(domainName, serviceName, keyId, auditRef, resourceOwner, publicKeyEntry);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Update or add (if doesn't already exist) the specified public key in the service object
     *
     * @param domainName     name of the domain
     * @param serviceName    name of the service
     * @param keyId          the identifier of the public key to be updated
     * @param auditRef       string containing audit specification or ticket number
     * @param publicKeyEntry that contains the public key details
     * @throws ZMSClientException in case of failure
     */
    public void putPublicKeyEntry(String domainName, String serviceName, String keyId, String auditRef,
            PublicKeyEntry publicKeyEntry) {
        putPublicKeyEntry(domainName, serviceName, keyId, auditRef, null, publicKeyEntry);
    }

    /**
     * Delete the specified public key from the service object. If the key doesn't exist then
     * it is treated as a successful operation and no exception will be thrown.
     *
     * @param domainName  name of the domain
     * @param serviceName name of the service
     * @param keyId       the identifier of the public key to be deleted
     * @param auditRef    string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public void deletePublicKeyEntry(String domainName, String serviceName, String keyId, String auditRef, String resourceOwner) {
        updatePrincipal();
        try {
            client.deletePublicKeyEntry(domainName, serviceName, keyId, auditRef, resourceOwner);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete the specified public key from the service object. If the key doesn't exist then
     * it is treated as a successful operation and no exception will be thrown.
     *
     * @param domainName  name of the domain
     * @param serviceName name of the service
     * @param keyId       the identifier of the public key to be deleted
     * @param auditRef    string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deletePublicKeyEntry(String domainName, String serviceName, String keyId, String auditRef) {
        deletePublicKeyEntry(domainName, serviceName, keyId, auditRef, null);
    }

    /**
     * Create/update an entity object in ZMS
     *
     * @param domainName name of the domain
     * @param entityName name of the entity
     * @param auditRef   string containing audit specification or ticket number
     * @param entity     entity object with details
     * @throws ZMSClientException in case of failure
     */
    public void putEntity(String domainName, String entityName, String auditRef, Entity entity) {
        updatePrincipal();
        try {
            client.putEntity(domainName, entityName, auditRef, entity);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the specified entity from the ZMS Server
     *
     * @param domainName name of the domain
     * @param entityName name of the entity
     * @return Entity object with details
     * @throws ZMSClientException in case of failure
     */
    public Entity getEntity(String domainName, String entityName) {
        updatePrincipal();
        try {
            return client.getEntity(domainName, entityName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete the specified entity from the ZMS Server
     *
     * @param domainName name of the domain
     * @param entityName name of the entity
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteEntity(String domainName, String entityName, String auditRef) {
        updatePrincipal();
        try {
            client.deleteEntity(domainName, entityName, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of entities defined for the specified domain
     *
     * @param domainName name of the domain
     * @return list of entity names
     * @throws ZMSClientException in case of failure
     */
    public EntityList getEntityList(String domainName) {
        updatePrincipal();
        try {
            return client.getEntityList(domainName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Register a new provider service for a given tenant domain
     *
     * @param tenantDomain    name of the tenant domain
     * @param providerService name of the provider service
     *                        format: provider-domain-name.provider-service-name, ex: "sports.storage"
     * @param auditRef        string containing audit specification or ticket number
     * @param tenant          Tenancy object with tenant details
     * @throws ZMSClientException in case of failure
     */
    public void putTenancy(String tenantDomain, String providerService, String auditRef, Tenancy tenant) {
        updatePrincipal();
        try {
            client.putTenancy(tenantDomain, providerService, auditRef, tenant);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete the specified provider service from a tenant domain
     *
     * @param tenantDomain    name of the tenant domain
     * @param providerService name of the provider service,
     *                        format: provider-domain-name.provider-service-name, ex: "sports.storage"
     * @param auditRef        string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteTenancy(String tenantDomain, String providerService, String auditRef) {
        updatePrincipal();
        try {
            client.deleteTenancy(tenantDomain, providerService, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Register a new tenant domain for the provider service
     *
     * @param providerDomain  provider domain name
     * @param providerService provider service name
     * @param tenantDomain    name of the tenant domain
     * @param auditRef        string containing audit specification or ticket number
     * @param tenant          Tenancy object with tenant details
     * @throws ZMSClientException in case of failure
     */
    public void putTenant(String providerDomain, String providerService, String tenantDomain, String auditRef, Tenancy tenant) {
        updatePrincipal();
        try {
            client.putTenant(providerDomain, providerService, tenantDomain, auditRef, tenant);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete the specified tenant from provider service
     *
     * @param providerDomain  provider domain name
     * @param providerService provider service name
     * @param tenantDomain    name of the tenant domain
     * @param auditRef        string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteTenant(String providerDomain, String providerService, String tenantDomain, String auditRef) {
        updatePrincipal();
        try {
            client.deleteTenant(providerDomain, providerService, tenantDomain, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create tenant roles for the specified tenant resource group.
     *
     * @param providerDomain      name of the provider domain
     * @param providerServiceName name of the provider service
     * @param tenantDomain        name of the tenant's domain
     * @param resourceGroup       name of the resource group
     * @param auditRef            string containing audit specification or ticket number
     * @param tenantRoles         Tenant roles
     * @throws ZMSClientException in case of failure
     */
    public void putTenantResourceGroupRoles(String providerDomain, String providerServiceName, String tenantDomain,
                                            String resourceGroup, String auditRef, TenantResourceGroupRoles tenantRoles) {
        updatePrincipal();
        try {
            client.putTenantResourceGroupRoles(providerDomain, providerServiceName, tenantDomain,
                    resourceGroup, auditRef, tenantRoles);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of tenant roles defined for a tenant resource group in a domain
     *
     * @param providerDomain      name of the provider domain
     * @param providerServiceName name of the provider service
     * @param tenantDomain        name of the tenant's domain
     * @param resourceGroup       name of the resource group
     * @return list of tenant roles
     * @throws ZMSClientException in case of failure
     */
    public TenantResourceGroupRoles getTenantResourceGroupRoles(String providerDomain, String providerServiceName,
                                                                String tenantDomain, String resourceGroup) {
        updatePrincipal();
        try {
            return client.getTenantResourceGroupRoles(providerDomain, providerServiceName,
                    tenantDomain, resourceGroup);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete tenant roles for the specified tenant resource group in a domain
     *
     * @param providerDomain      name of the provider domain
     * @param providerServiceName name of the provider service
     * @param tenantDomain        name of tenant's domain
     * @param resourceGroup       name of the resource group
     * @param auditRef            string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteTenantResourceGroupRoles(String providerDomain, String providerServiceName, String tenantDomain,
                                               String resourceGroup, String auditRef) {
        updatePrincipal();
        try {
            client.deleteTenantResourceGroupRoles(providerDomain, providerServiceName, tenantDomain,
                    resourceGroup, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Requests the ZMS to indicate whether or not the specific request for the
     * specified resource with authentication details will be granted or not.
     *
     * @param action      value of the action to be carried out (e.g. "UPDATE", "DELETE")
     * @param resource    resource name. Resource is defined as {DomainName}:{Entity}"
     * @param trustDomain (optional) if the access checks involves cross domain check only
     *                    check the specified trusted domain and ignore all others
     * @return Access object indicating whether or not the request will be granted or not
     * @throws ZMSClientException in case of failure
     */
    public Access getAccess(String action, String resource, String trustDomain) {
        return getAccess(action, resource, trustDomain, null);
    }

    /**
     * Requests the ZMS to indicate whether or not the specific request for the
     * specified resource with authentication details will be granted or not.
     *
     * @param action      value of the action to be carried out (e.g. "UPDATE", "DELETE")
     * @param resource    resource name. Resource is defined as {DomainName}:{Entity}"
     * @param trustDomain (optional) if the access checks involves cross domain check only
     *                    check the specified trusted domain and ignore all others
     * @param principal   (optional) carry out the access check for specified principal
     * @return Access object indicating whether or not the request will be granted or not
     * @throws ZMSClientException in case of failure
     */
    public Access getAccess(String action, String resource, String trustDomain, String principal) {
        try {
            return client.getAccess(action, resource, trustDomain, principal);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }


    /**
     * Requests the ZMS to indicate whether or not the specific request for the
     * specified resource with authentication details will be granted or not.
     *
     * @param action      value of the action to be carried out (e.g. "UPDATE", "DELETE")
     * @param resource    resource string.
     * @param trustDomain (optional) if the access checks involves cross domain check only
     *                    check the specified trusted domain and ignore all others
     * @param principal   (optional) carry out the access check for specified principal
     * @return Access object indicating whether or not the request will be granted or not
     * @throws ZMSClientException in case of failure
     */
    public Access getAccessExt(String action, String resource, String trustDomain, String principal) {
        try {
            return client.getAccessExt(action, resource, trustDomain, principal);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of all domain data from the ZMS Server that
     * is signed with ZMS's private key. It will pass an optional matchingTag
     * so that ZMS can skip returning domains if no changes have taken
     * place since that tag was issued.
     *
     * @param domainName      name of the domain. if specified, the server will
     *                        only return this domain in the result set
     * @param metaOnly        (can be null) must have value of true or false (default).
     *                        if set to true, zms server will only return meta information
     *                        about each domain (description, last modified timestamp, etc) and
     *                        no role/policy/service details will be returned.
     * @param matchingTag     (can be null) contains modified timestamp received
     *                        with last request. If null, then return all domains.
     * @param responseHeaders contains the "tag" returned for modification
     *                        time of the domains, map key = "tag", List should
     *                        contain a single value timestamp String to be used
     *                        with subsequent call as matchingTag to this API
     * @return list of domains signed by ZMS Server
     * @throws ZMSClientException in case of failure
     */
    public SignedDomains getSignedDomains(String domainName, String metaOnly, String matchingTag,
                                          Map<String, List<String>> responseHeaders) {
        return getSignedDomains(domainName, metaOnly, null, true, matchingTag, responseHeaders);
    }

    /**
     * Retrieve the list of all domain data from the ZMS Server that
     * is signed with ZMS's private key. It will pass an optional matchingTag
     * so that ZMS can skip returning domains if no changes have taken
     * place since that tag was issued.
     *
     * @param domainName      name of the domain. if specified, the server will
     *                        only return this domain in the result set
     * @param metaOnly        (can be null) must have value of true or false (default).
     *                        if set to true, zms server will only return meta information
     *                        about each domain (description, last modified timestamp, etc) and
     *                        no role/policy/service details will be returned.
     * @param metaAttr        (can be null) if metaOnly option is set to true, this
     *                        parameter can filter the results based on the presence of the
     *                        requested attribute. Allowed values are: account, ypmid, and all.
     *                        account - only return domains that have the account value set
     *                        ypmid - only return domains that have the ypmid value set
     *                        all - return all domains (no filtering).
     * @param matchingTag     (can be null) contains modified timestamp received
     *                        with last request. If null, then return all domains.
     * @param responseHeaders contains the "tag" returned for modification
     *                        time of the domains, map key = "tag", List should
     *                        contain a single value timestamp String to be used
     *                        with subsequent call as matchingTag to this API
     * @return list of domains signed by ZMS Server
     * @throws ZMSClientException in case of failure
     */
    public SignedDomains getSignedDomains(String domainName, String metaOnly, String metaAttr,
                                          String matchingTag, Map<String, List<String>> responseHeaders) {
        return getSignedDomains(domainName, metaOnly, metaAttr, true, matchingTag, responseHeaders);
    }

    /**
     * Retrieve the list of all domain data from the ZMS Server that
     * is signed with ZMS's private key. It will pass an optional matchingTag
     * so that ZMS can skip returning domains if no changes have taken
     * place since that tag was issued.
     *
     * @param domainName      name of the domain. if specified, the server will
     *                        only return this domain in the result set
     * @param metaOnly        (can be null) must have value of true or false (default).
     *                        if set to true, zms server will only return meta information
     *                        about each domain (description, last modified timestamp, etc) and
     *                        no role/policy/service details will be returned.
     * @param metaAttr        (can be null) if metaOnly option is set to true, this
     *                        parameter can filter the results based on the presence of the
     *                        requested attribute. Allowed values are: account, ypmid, and all.
     *                        account - only return domains that have the account value set
     *                        ypmid - only return domains that have the ypmid value set
     *                        all - return all domains (no filtering).
     * @param masterCopy      system principals can request the request to be processed
     *                        from the master data source instead of read replicas in case
     *                        there are any configured
     * @param matchingTag     (can be null) contains modified timestamp received
     *                        with last request. If null, then return all domains.
     * @param responseHeaders contains the "tag" returned for modification
     *                        time of the domains, map key = "tag", List should
     *                        contain a single value timestamp String to be used
     *                        with subsequent call as matchingTag to this API
     * @return list of domains signed by ZMS Server
     * @throws ZMSClientException in case of failure
     */
    public SignedDomains getSignedDomains(String domainName, String metaOnly, String metaAttr,
                                          boolean masterCopy, String matchingTag, Map<String, List<String>> responseHeaders) {
        return getSignedDomains(domainName, metaOnly, metaAttr, masterCopy, false, matchingTag, responseHeaders);
    }

    /**
     * Retrieve the list of all domain data from the ZMS Server that
     * is signed with ZMS's private key. It will pass an optional matchingTag
     * so that ZMS can skip returning domains if no changes have taken
     * place since that tag was issued.
     *
     * @param domainName      name of the domain. if specified, the server will
     *                        only return this domain in the result set
     * @param metaOnly        (can be null) must have value of true or false (default).
     *                        if set to true, zms server will only return meta information
     *                        about each domain (description, last modified timestamp, etc) and
     *                        no role/policy/service details will be returned.
     * @param metaAttr        (can be null) if metaOnly option is set to true, this
     *                        parameter can filter the results based on the presence of the
     *                        requested attribute. Allowed values are: account, ypmid, and all.
     *                        account - only return domains that have the account value set
     *                        ypmid - only return domains that have the ypmid value set
     *                        all - return all domains (no filtering).
     * @param masterCopy      system principals can request the request to be processed
     *                        from the master data source instead of read replicas in case
     *                        there are any configured
     * @param conditions      an optional parameter to request assertion conditions to be
     *                        included in the response assertions in case
     *                        there are any configured
     * @param matchingTag     (can be null) contains modified timestamp received
     *                        with last request. If null, then return all domains.
     * @param responseHeaders contains the "tag" returned for modification
     *                        time of the domains, map key = "tag", List should
     *                        contain a single value timestamp String to be used
     *                        with subsequent call as matchingTag to this API
     * @return list of domains signed by ZMS Server
     * @throws ZMSClientException in case of failure
     */
    public SignedDomains getSignedDomains(String domainName, String metaOnly, String metaAttr,
                                          boolean masterCopy, boolean conditions, String matchingTag,
                                          Map<String, List<String>> responseHeaders) {
        updatePrincipal();
        try {
            return client.getSignedDomains(domainName, metaOnly, metaAttr, masterCopy, conditions, matchingTag, responseHeaders);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve all valid values for the given attribute and user
     * @param attributeName   name of attribute
     * @param userName        restrict to values associated with the given user
     * @return all valid values for the given attribute and user
     */
    public DomainMetaStoreValidValuesList getDomainMetaStoreValidValuesList(String attributeName, String userName) {
        updatePrincipal();
        try {
            return client.getDomainMetaStoreValidValuesList(attributeName, userName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Get the authorization and token requests history for the domain
     * @param domainName    name of the domain
     * @return list of auth history records for domain
     */
    public AuthHistoryDependencies getAuthHistoryDependencies(String domainName) {
        updatePrincipal();
        try {
            return client.getAuthHistoryDependencies(domainName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * For the specified user credentials return the corresponding User Token that
     * can be used for authenticating other ZMS operations. The client internally
     * automatically calls this method and uses the UserToken if the ZMSClient
     * object was initialized with a user principal.
     *
     * @param userName name of the user. This is only used to verify that it matches
     *                 the user name from the credentials and is optional. The caller can just pass
     *                 the string "_self_" as the userName to bypass this optional check.
     * @return ZMS generated User Token
     * @throws ZMSClientException in case of failure
     */
    public UserToken getUserToken(String userName) {
        return getUserToken(userName, null, null);
    }

    /**
     * For the specified user credentials return the corresponding User Token that
     * can be used for authenticating other ZMS operations by any of the specified
     * authorized services.
     *
     * @param userName     name of the user
     * @param serviceNames comma separated list of authorized service names
     * @param header       boolean flag whether or not return authority header name
     * @return ZMS generated User Token
     * @throws ZMSClientException in case of failure
     */
    public UserToken getUserToken(String userName, String serviceNames, Boolean header) {
        try {
            return client.getUserToken(userName, serviceNames, header);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * For the specified user credentials return the corresponding User Token that
     * can be used for authenticating other ZMS operations by any of the specified
     * authorized services.
     *
     * @param userName     name of the user
     * @param serviceNames comma separated list of authorized service names
     * @return ZMS generated User Token
     * @throws ZMSClientException in case of failure
     */
    public UserToken getUserToken(String userName, String serviceNames) {
        return getUserToken(userName, serviceNames, null);
    }

    /**
     * For the specified domain in domainName, a list of default administrators
     * can be passed to this method and will be added to the domain's admin role
     * In addition this method will ensure that the admin role and policy exist and
     * are properly set up
     *
     * @param domainName    - name of the domain to add default administrators to
     * @param auditRef      - string containing audit specification or ticket number
     * @param defaultAdmins - list of names to be added as default administrators
     * @throws ZMSClientException in case of failure
     */
    public void putDefaultAdmins(String domainName, String auditRef, DefaultAdmins defaultAdmins) {
        updatePrincipal();
        try {
            client.putDefaultAdmins(domainName, auditRef, defaultAdmins);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * The client will validate the given serviceToken against the ZMS Server
     * and if the token is valid, it will return a Principal object.
     *
     * @param serviceToken token to be validated.
     * @return Principal object if the token is successfully validated or
     * @throws ZMSClientException in case of failure
     */
    public Principal getPrincipal(String serviceToken) {
        return getPrincipal(serviceToken, PRINCIPAL_AUTHORITY.getHeader());
    }

    /**
     * The client will validate the given serviceToken against the ZMS Server
     * and if the token is valid, it will return a Principal object.
     *
     * @param serviceToken token to be validated.
     * @param tokenHeader  name of the authorization header for the token
     * @return Principal object if the token is successfully validated or
     * @throws ZMSClientException in case of failure
     */
    public Principal getPrincipal(String serviceToken, String tokenHeader) {

        if (serviceToken == null) {
            throw new ZMSClientException(401, "Null service token provided");
        }

        if (tokenHeader == null) {
            tokenHeader = PRINCIPAL_AUTHORITY.getHeader();
        }

        // verify that service token is valid before sending the data to
        // the ZMS server

        PrincipalToken token;
        try {
            token = new PrincipalToken(serviceToken);
        } catch (IllegalArgumentException ex) {
            throw new ZMSClientException(ResourceException.UNAUTHORIZED,
                    "Invalid service token provided: " + ex.getMessage());
        }

        Principal servicePrincipal = SimplePrincipal.create(token.getDomain(), token.getName(),
                serviceToken, 0, PRINCIPAL_AUTHORITY);

        client.addCredentials(tokenHeader, serviceToken);
        principalCheckDone = true;

        ServicePrincipal validatedPrincipal;
        try {
            validatedPrincipal = client.getServicePrincipal();
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }

        if (validatedPrincipal == null) {
            throw new ZMSClientException(ResourceException.UNAUTHORIZED, "Invalid service token provided");
        }

        // before returning let's validate that domain, name and
        // credentials match to what was passed to

        if (!servicePrincipal.getDomain().equalsIgnoreCase(validatedPrincipal.getDomain())) {
            throw new ZMSClientException(ResourceException.UNAUTHORIZED, "Validated principal domain name mismatch");
        }

        if (!servicePrincipal.getName().equalsIgnoreCase(validatedPrincipal.getService())) {
            throw new ZMSClientException(ResourceException.UNAUTHORIZED, "Validated principal service name mismatch");
        }

        return servicePrincipal;
    }

    /**
     * Create provider roles for the specified tenant resource group in the tenant domain.
     * If the principal requesting this operation has been authorized by the provider
     * service itself, then the corresponding tenant roles will be created in the provider
     * domain as well thus completing the tenancy on-boarding process in one call.
     *
     * @param tenantDomain        name of the tenant's domain
     * @param providerDomain      name of the provider domain
     * @param providerServiceName name of the provider service
     * @param resourceGroup       name of the resource group
     * @param auditRef            string containing audit specification or ticket number
     * @param providerRoles       Provider roles
     * @throws ZMSClientException in case of failure
     */
    public void putProviderResourceGroupRoles(String tenantDomain, String providerDomain,
                                              String providerServiceName, String resourceGroup, String auditRef,
                                              ProviderResourceGroupRoles providerRoles) {
        updatePrincipal();
        try {
            client.putProviderResourceGroupRoles(tenantDomain, providerDomain, providerServiceName,
                    resourceGroup, auditRef, providerRoles);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete the provider roles for the specified tenant resource group from the tenant domain.
     * If the principal requesting this operation has been authorized by the provider
     * service itself, then the corresponding tenant roles will be deleted from the provider
     * domain as well thus completing the process in one call.
     *
     * @param tenantDomain        name of tenant's domain
     * @param providerDomain      name of the provider domain
     * @param providerServiceName name of the provider service
     * @param resourceGroup       name of the resource group
     * @param auditRef            string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteProviderResourceGroupRoles(String tenantDomain, String providerDomain,
                                                 String providerServiceName, String resourceGroup, String auditRef) {
        updatePrincipal();
        try {
            client.deleteProviderResourceGroupRoles(tenantDomain, providerDomain, providerServiceName,
                    resourceGroup, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of provider roles defined for a tenant resource group in a domain
     *
     * @param tenantDomain        name of the tenant's domain
     * @param providerDomain      name of the provider domain
     * @param providerServiceName name of the provider service
     * @param resourceGroup       name of the resource group
     * @return list of provider roles
     * @throws ZMSClientException in case of failure
     */
    public ProviderResourceGroupRoles getProviderResourceGroupRoles(String tenantDomain, String providerDomain,
                                                                    String providerServiceName, String resourceGroup) {
        updatePrincipal();
        try {
            return client.getProviderResourceGroupRoles(tenantDomain, providerDomain, providerServiceName,
                    resourceGroup);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Check the data for the specified domain object
     *
     * @param domain name of the domain to be checked
     * @return DomainDataCheck object
     * @throws ZMSClientException in case of failure
     */
    public DomainDataCheck getDomainDataCheck(String domain) {
        updatePrincipal();
        try {
            return client.getDomainDataCheck(domain);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the specified solution template provisioned on the ZMS Server.
     * The template object will include the list of roles and policies that will
     * be provisioned in the domain when the template is applied.
     *
     * @param template name of the solution template to be retrieved
     * @return template object
     * @throws ZMSClientException in case of failure
     */
    public Template getTemplate(String template) {
        updatePrincipal();
        try {
            return client.getTemplate(template);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of solution templates provisioned on the ZMS Server
     *
     * @return list of template names
     * @throws ZMSClientException in case of failure
     */
    public ServerTemplateList getServerTemplateList() {
        updatePrincipal();
        try {
            return client.getServerTemplateList();
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Provision the specified solution template roles and policies in the domain
     *
     * @param domain    name of the domain to be updated
     * @param auditRef  string containing audit specification or ticket number
     * @param templates contains list of template names to be provisioned in the domain
     * @throws ZMSClientException in case of failure
     */
    public void putDomainTemplate(String domain, String auditRef, DomainTemplate templates) {
        updatePrincipal();
        try {
            client.putDomainTemplate(domain, auditRef, templates);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Provision the specified solution template roles and policies in the domain
     *
     * @param domain    name of the domain to be updated
     * @param template  name of the template to be applied
     * @param auditRef  string containing audit specification or ticket number
     * @param templates containing the single template (must match the template parameter) to be provisioned in the domain
     * @throws ZMSClientException in case of failure
     */
    public void putDomainTemplateExt(String domain, String template, String auditRef, DomainTemplate templates) {
        updatePrincipal();
        try {
            client.putDomainTemplateExt(domain, template, auditRef, templates);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete the specified solution template roles and policies from the domain
     *
     * @param domain   name of the domain to be updated
     * @param template is the name of the provisioned template to be deleted
     * @param auditRef string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteDomainTemplate(String domain, String template, String auditRef) {
        updatePrincipal();
        try {
            client.deleteDomainTemplate(domain, template, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of solution template provisioned for a domain
     *
     * @param domain name of the domain
     * @return TemplateList object that includes the list of provisioned solution template names
     * @throws ZMSClientException in case of failure
     */
    public DomainTemplateList getDomainTemplateList(String domain) {
        updatePrincipal();
        try {
            return client.getDomainTemplateList(domain);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of resources as defined in their respective assertions
     * that the given principal has access to through their role membership
     *
     * @param principal the principal name (e.g. user.joe). Must have special
     *                  privileges to execute this query without specifying the principal.
     *                  Check with Athenz Service Administrators if you have a use case to
     *                  request all principals from Athenz Service
     * @param action    optional field specifying what action to filter assertions on
     * @return ResourceAccessList object that lists the set of assertions per principal
     * @throws ZMSClientException in case of failure
     */
    public ResourceAccessList getResourceAccessList(String principal, String action) {
        updatePrincipal();
        try {
            return client.getResourceAccessList(principal, action);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the quota details for the specified domain
     *
     * @param domainName name of the domain
     * @return quota object
     * @throws ZMSClientException in case of failure
     */
    public Quota getQuota(String domainName) {
        updatePrincipal();
        try {
            return client.getQuota(domainName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the stats for the specified domain
     *
     * @param domainName name of the domain
     * @return stats object
     * @throws ZMSClientException in case of failure
     */
    public Stats getStats(String domainName) {
        updatePrincipal();
        try {
            return client.getStats(domainName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the server info details
     *
     * @return info object
     * @throws ZMSClientException in case of failure
     */
    public Info getInfo() {
        updatePrincipal();
        try {
            return client.getInfo();
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create/Update the quota details for the specified domain
     *
     * @param domainName name of the domain
     * @param auditRef   string containing audit specification or ticket number
     * @param quota      object to be set for the domain
     * @throws ZMSClientException in case of failure
     */
    public void putQuota(String domainName, String auditRef, Quota quota) {
        updatePrincipal();
        try {
            client.putQuota(domainName, auditRef, quota);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete the specified quota details for the specified domain
     *
     * @param domainName name of the domain
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteQuota(String domainName, String auditRef) {
        updatePrincipal();
        try {
            client.deleteQuota(domainName, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete the specified user from all roles in the given domain
     *
     * @param domainName name of the domain
     * @param memberName name of the member to be removed from all roles
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteDomainRoleMember(String domainName, String memberName, String auditRef) {
        updatePrincipal();
        try {
            client.deleteDomainRoleMember(domainName, memberName, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of all members provisioned for a domain
     * in regular roles
     *
     * @param domainName name of the domain
     * @return DomainRoleMembers object that includes the list of members with their roles
     * @throws ZMSClientException in case of failure
     */
    public DomainRoleMembers getDomainRoleMembers(String domainName) {
        updatePrincipal();
        try {
            return client.getDomainRoleMembers(domainName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Fetch all the roles across domains by either calling or specified principal
     * @param principal - Requested principal. If null will return roles for the user making the call
     * @param domainName - Requested domain. If null will return roles from all domains
     * @return Member with roles in all requested domains
     */
    public DomainRoleMember getPrincipalRoles(String principal, String domainName) {
        return getPrincipalRoles(principal, domainName, null);
    }

    /**
     * Fetch all the roles across domains by either calling or specified principal. The expand
     * argument specifies to include any group and/or delegated role membership as well.
     * @param principal - Requested principal. If null will return roles for the user making the call
     * @param domainName - Requested domain. If null will return roles from all domains
     * @param expand - Optional. Include all group and delegated role membership as well.
     * @return Member with roles in all requested domains
     */
    public DomainRoleMember getPrincipalRoles(String principal, String domainName, Boolean expand) {
        updatePrincipal();
        try {
            return client.getPrincipalRoles(principal, domainName, expand);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Set the role system meta parameters
     *
     * @param domainName domain name containing the role to be modified
     * @param roleName   role name to be modified
     * @param attribute  role meta attribute being modified in this request
     * @param auditRef   string containing audit specification or ticket number
     * @param meta       meta parameters to be set on the role
     */
    public void putRoleSystemMeta(String domainName, String roleName, String attribute, String auditRef, RoleSystemMeta meta) {
        updatePrincipal();
        try {
            client.putRoleSystemMeta(domainName, roleName, attribute, auditRef, meta);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Set the role meta parameters
     *
     * @param domainName domain name containing the role to be modified
     * @param roleName   role name to be modified
     * @param auditRef   string containing audit specification or ticket number
     * @param resourceOwner string contain the owner of the resource
     * @param meta       meta parameters to be set on the role
     */
    public void putRoleMeta(String domainName, String roleName, String auditRef, String resourceOwner, RoleMeta meta) {
        updatePrincipal();
        try {
            client.putRoleMeta(domainName, roleName, auditRef, resourceOwner, meta);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Set the role meta parameters
     *
     * @param domainName domain name containing the role to be modified
     * @param roleName   role name to be modified
     * @param auditRef   string containing audit specification or ticket number
     * @param meta       meta parameters to be set on the role
     */
    public void putRoleMeta(String domainName, String roleName, String auditRef, RoleMeta meta) {
        putRoleMeta(domainName, roleName, auditRef, null, meta);
    }

    /**
     * Approve or reject addition of a member in the specified role optionally with expiration
     *
     * @param domainName name of the domain
     * @param roleName   name of the role
     * @param memberName name of the member to be added
     * @param expiration timestamp when this membership will expire (optional)
     * @param approval   flag indicating whether this membership is approved or rejected
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void putMembershipDecision(String domainName, String roleName, String memberName,
                                      Timestamp expiration, boolean approval, String auditRef) {
        Membership mbr = new Membership().setRoleName(roleName)
                .setMemberName(memberName).setExpiration(expiration).setApproved(approval);
        updatePrincipal();
        try {
            client.putMembershipDecision(domainName, roleName, memberName, auditRef, mbr);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Return all the list of pending requests for the given principal. If the principal
     * is null, the server will return the list for the authenticated principal
     * making the call
     * @param principal name of the approver principal (optional)
     * @return DomainRoleMembership object listing all pending users
     * @throws ZMSClientException in case of failure
     */
    public DomainRoleMembership getPendingDomainRoleMembersList(String principal) {
        updatePrincipal();
        try {
            return client.getPendingDomainRoleMembersList(principal, null);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Return all the list of pending requests for the given principal or domain. If the principal
     * is null, the server will return the list for the authenticated principal
     * making the call
     * @param principal name of the approver principal (optional)
     * @param domainName name of the domain to get pending requests for (optional)
     * @return DomainRoleMembership object listing all pending users
     * @throws ZMSClientException in case of failure
     */
    public DomainRoleMembership getPendingDomainRoleMembersList(String principal, String domainName) {
        updatePrincipal();
        try {
            return client.getPendingDomainRoleMembersList(principal, domainName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Review role membership to extend and/or delete role members
     *
     * @param domainName  name of the domain
     * @param roleName    name of the role
     * @param auditRef    string containing audit specification or ticket number
     * @param returnObj Boolean returns the updated object from the database if true
     * @param resourceOwner string containing the owner of the resource
     * @param role        Role object containing updated and/or deleted members
     * @throws ZMSClientException in case of failure
     */
    public Role putRoleReview(String domainName, String roleName, String auditRef, Boolean returnObj,
            String resourceOwner, Role role) {
        updatePrincipal();
        try {
            return client.putRoleReview(domainName, roleName, auditRef, returnObj, resourceOwner, role);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Review role membership to extend and/or delete role members
     *
     * @param domainName  name of the domain
     * @param roleName    name of the role
     * @param auditRef    string containing audit specification or ticket number
     * @param returnObj Boolean returns the updated object from the database if true
     * @param role        Role object containing updated and/or deleted members
     * @throws ZMSClientException in case of failure
     */
    public Role putRoleReview(String domainName, String roleName, String auditRef, Boolean returnObj, Role role) {
        return putRoleReview(domainName, roleName, auditRef, returnObj, null, role);
    }

    /**
     * Review role membership to extend and/or delete role members
     *
     * @param domainName  name of the domain
     * @param roleName    name of the role
     * @param auditRef    string containing audit specification or ticket number
     * @param role        Role object containing updated and/or deleted members
     * @throws ZMSClientException in case of failure
     */
    public void putRoleReview(String domainName, String roleName, String auditRef, Role role) {
        putRoleReview(domainName, roleName, auditRef, false, role);
    }

    /**
     * Delete the specified group from domain
     *
     * @param domainName name of the domain
     * @param groupName  name of the group
     * @param auditRef   string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public void deleteGroup(String domainName, String groupName, String auditRef, String resourceOwner) {
        updatePrincipal();
        try {
            client.deleteGroup(domainName, groupName, auditRef, resourceOwner);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete the specified group from domain
     *
     * @param domainName name of the domain
     * @param groupName  name of the group
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteGroup(String domainName, String groupName, String auditRef) {
        deleteGroup(domainName, groupName, auditRef, null);
    }

    /**
     * Remove the specified member from the group
     *
     * @param domainName name of the domain
     * @param groupName  name of the group
     * @param memberName name of the member to be removed
     * @param auditRef   string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public void deleteGroupMembership(String domainName, String groupName, String memberName,
            String auditRef, String resourceOwner) {
        updatePrincipal();
        try {
            client.deleteGroupMembership(domainName, groupName, memberName, auditRef, resourceOwner);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Remove the specified member from the group
     *
     * @param domainName name of the domain
     * @param groupName  name of the group
     * @param memberName name of the member to be removed
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteGroupMembership(String domainName, String groupName, String memberName, String auditRef) {
        deleteGroupMembership(domainName, groupName, memberName, auditRef, null);
    }

    /**
     * Remove the specified pending member from the group
     *
     * @param domainName name of the domain
     * @param groupName  name of the group
     * @param memberName name of the pending member to be removed
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deletePendingGroupMembership(String domainName, String groupName, String memberName, String auditRef) {
        updatePrincipal();
        try {
            client.deletePendingGroupMembership(domainName, groupName, memberName, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Generate a group name as expected by ZMS Server can be used to
     * set the group object's name field (e.g. group.setName(name))
     *
     * @param domain name of the domain
     * @param group name of the group
     * @return full group name
     */
    public String generateGroupName(String domain, String group) {
        return domain + ":group." + group;
    }

    /**
     * Get membership details for the specified member in the given group
     * in a specified domain with an optional expiration
     *
     * @param domainName name of the domain
     * @param groupName  name of the group
     * @param memberName name of the member
     * @param expiration member expiration
     * @return GroupMembership object
     * @throws ZMSClientException in case of failure
     */
    public GroupMembership getGroupMembership(String domainName, String groupName, String memberName, String expiration) {
        updatePrincipal();
        try {
            return client.getGroupMembership(domainName, groupName, memberName, expiration);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Fetch all the groups across domains by either calling or specified principal
     * @param principal - Requested principal. If null will return groups for the user making the call
     * @param domainName - Requested domain. If null will return groups from all domains
     * @return Member with groups in all requested domains
     */
    public DomainGroupMember getPrincipalGroups(String principal, String domainName) {
        updatePrincipal();
        try {
            return client.getPrincipalGroups(principal, domainName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Set the group system meta parameters
     *
     * @param domainName domain name containing the group to be modified
     * @param groupName  group name to be modified
     * @param attribute  group meta attribute being modified in this request
     * @param auditRef   string containing audit specification or ticket number
     * @param meta       meta parameters to be set on the group
     */
    public void putGroupSystemMeta(String domainName, String groupName, String attribute, String auditRef, GroupSystemMeta meta) {
        updatePrincipal();
        try {
            client.putGroupSystemMeta(domainName, groupName, attribute, auditRef, meta);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Set the group meta parameters
     *
     * @param domainName domain name containing the group to be modified
     * @param groupName  group name to be modified
     * @param auditRef   string containing audit specification or ticket number
     * @param resourceOwner string containering the owner of the resource
     * @param meta       meta parameters to be set on the group
     */
    public void putGroupMeta(String domainName, String groupName, String auditRef, String resourceOwner, GroupMeta meta) {
        updatePrincipal();
        try {
            client.putGroupMeta(domainName, groupName, auditRef, resourceOwner, meta);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Set the group meta parameters
     *
     * @param domainName domain name containing the group to be modified
     * @param groupName  group name to be modified
     * @param auditRef   string containing audit specification or ticket number
     * @param meta       meta parameters to be set on the group
     */
    public void putGroupMeta(String domainName, String groupName, String auditRef, GroupMeta meta) {
        putGroupMeta(domainName, groupName, auditRef, null, meta);
    }

    /**
     * Approve or reject addition of a member in the specified group
     *
     * @param domainName name of the domain
     * @param groupName  name of the group
     * @param memberName name of the member to be added
     * @param approval   flag indicating whether this membership is approved or rejected
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void putGroupMembershipDecision(String domainName, String groupName, String memberName, boolean approval, String auditRef) {

        GroupMembership mbr = new GroupMembership().setGroupName(groupName)
                .setMemberName(memberName).setApproved(approval);
        updatePrincipal();
        try {
            client.putGroupMembershipDecision(domainName, groupName, memberName, auditRef, mbr);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Return all the list of pending requests for the given principal. If the principal
     * is null, the server will return the list for the authenticated principal.
     * making the call
     * @param principal name of the approver principal (optional)
     * @return DomainGroupMembership object listing all pending users
     * @throws ZMSClientException in case of failure
     */
    public DomainGroupMembership getPendingDomainGroupMembersList(String principal) {
        updatePrincipal();
        try {
            return client.getPendingDomainGroupMembersList(principal, null);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Return all the list of pending requests for the given principal or given domain. If the principal
     * is null, the server will return the list for the authenticated principal.
     * making the call
     * @param principal name of the approver principal (optional)
     * @param domainName name of the domain to get pending requests for (optional)
     * @return DomainGroupMembership object listing all pending users
     * @throws ZMSClientException in case of failure
     */
    public DomainGroupMembership getPendingDomainGroupMembersList(String principal, String domainName) {
        updatePrincipal();
        try {
            return client.getPendingDomainGroupMembersList(principal, domainName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Review group membership to extend and/or delete group members
     *
     * @param domainName  name of the domain
     * @param groupName   name of the group
     * @param auditRef    string containing audit specification or ticket number
     * @param group       Group object containing updated and/or deleted members
     * @param returnObj Boolean returns the updated object from the database if true
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public Group putGroupReview(String domainName, String groupName, String auditRef, Boolean returnObj,
            String resourceOwner, Group group) {
        updatePrincipal();
        try {
            return client.putGroupReview(domainName, groupName, auditRef, returnObj, resourceOwner, group);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Review group membership to extend and/or delete group members
     *
     * @param domainName  name of the domain
     * @param groupName   name of the group
     * @param auditRef    string containing audit specification or ticket number
     * @param group       Group object containing updated and/or deleted members
     * @param returnObj Boolean returns the updated object from the database if true
     * @throws ZMSClientException in case of failure
     */
    public Group putGroupReview(String domainName, String groupName, String auditRef, Boolean returnObj, Group group) {
        return putGroupReview(domainName, groupName, auditRef, returnObj, null, group);
    }

    /**
     * Review group membership to extend and/or delete group members
     *
     * @param domainName  name of the domain
     * @param groupName   name of the group
     * @param auditRef    string containing audit specification or ticket number
     * @param group       Group object containing updated and/or deleted members
     * @throws ZMSClientException in case of failure
     */
    public void putGroupReview(String domainName, String groupName, String auditRef, Group group) {
       putGroupReview(domainName, groupName, auditRef, false, group);
    }

    /**
     * Retrieve the specified group
     *
     * @param domainName name of the domain
     * @param groupName  name of the group
     * @param auditLog   include audit log for the group changes in the response
     * @param pending    if this flag is set, then all members for that group will be retrieved
     *                   including pending members
     * @return group object
     * @throws ZMSClientException in case of failure
     */
    public Group getGroup(String domainName, String groupName, boolean auditLog, boolean pending) {
        updatePrincipal();
        try {
            return client.getGroup(domainName, groupName, auditLog, pending);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create/Update a new group in the specified domain. If updating a group
     * the provided object must contain all attributes as it will replace
     * the full group object configured on the server (not just some of the attributes).
     *
     * @param domainName name of the domain
     * @param groupName  name of the group
     * @param auditRef   string containing audit specification or ticket number
     * @param group      group object to be added to the domain
     * @param returnObj Boolean returns the updated object from the database if true
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public Group putGroup(String domainName, String groupName, String auditRef, Boolean returnObj,
            String resourceOwner, Group group) {
        updatePrincipal();
        try {
            return client.putGroup(domainName, groupName, auditRef, returnObj, resourceOwner, group);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create/Update a new group in the specified domain. If updating a group
     * the provided object must contain all attributes as it will replace
     * the full group object configured on the server (not just some of the attributes).
     *
     * @param domainName name of the domain
     * @param groupName  name of the group
     * @param auditRef   string containing audit specification or ticket number
     * @param group      group object to be added to the domain
     * @param returnObj Boolean returns the updated object from the database if true
     * @throws ZMSClientException in case of failure
     */
    public Group putGroup(String domainName, String groupName, String auditRef, Boolean returnObj, Group group) {
        return putGroup(domainName, groupName, auditRef, returnObj, null, group);
    }

    /**
     * Create/Update a new group in the specified domain. If updating a group
     * the provided object must contain all attributes as it will replace
     * the full group object configured on the server (not just some of the attributes).
     *
     * @param domainName name of the domain
     * @param groupName  name of the group
     * @param auditRef   string containing audit specification or ticket number
     * @param group      group object to be added to the domain
     * @throws ZMSClientException in case of failure
     */
    public void putGroup(String domainName, String groupName, String auditRef, Group group) {
       putGroup(domainName, groupName, auditRef, false, group);
    }

    /**
     * Retrieve the list of groups defined for the specified domain. The groups
     * will contain their attributes and, if specified, the list of members.
     *
     * @param domainName name of the domain
     * @param members    include all members for group as well
     * @param tagKey     query all groups with given tag name
     * @param tagValue   query all groups with given tag key and value
     * @return list of groups
     * @throws ZMSClientException in case of failure
     */
    public Groups getGroups(String domainName, Boolean members, String tagKey, String tagValue) {
        updatePrincipal();
        try {
            return client.getGroups(domainName, members, tagKey, tagValue);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of groups defined for the specified domain. The groups
     * will contain their attributes and, if specified, the list of members.
     *
     * @param domainName name of the domain
     * @param members    include all members for groups as well
     * @return list of groups
     * @throws ZMSClientException in case of failure
     */
    public Groups getGroups(String domainName, Boolean members) {
        return getGroups(domainName, members, null, null);
    }

    /**
     * Add a member in the specified group
     *
     * @param domainName name of the domain
     * @param groupName  name of the group
     * @param memberName name of the member to be added
     * @param auditRef   string containing audit specification or ticket number
     * @param returnObj Boolean returns the updated object from the database if true
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public GroupMembership putGroupMembership(String domainName, String groupName, String memberName,
            String auditRef, Boolean returnObj, String resourceOwner) {
        GroupMembership mbr = new GroupMembership().setGroupName(groupName)
                .setMemberName(memberName).setIsMember(true);
        updatePrincipal();
        try {
            return client.putGroupMembership(domainName, groupName, memberName, auditRef, returnObj, resourceOwner, mbr);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Add a member in the specified group
     *
     * @param domainName name of the domain
     * @param groupName  name of the group
     * @param memberName name of the member to be added
     * @param auditRef   string containing audit specification or ticket number
     * @param returnObj Boolean returns the updated object from the database if true
     * @throws ZMSClientException in case of failure
     */
    public GroupMembership putGroupMembership(String domainName, String groupName, String memberName,
            String auditRef, Boolean returnObj) {
        return putGroupMembership(domainName, groupName, memberName, auditRef, returnObj, null);
    }

    /**
     * Add a member in the specified group
     *
     * @param domainName name of the domain
     * @param groupName  name of the group
     * @param memberName name of the member to be added
     * @param auditRef   string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void putGroupMembership(String domainName, String groupName, String memberName, String auditRef) {
        putGroupMembership(domainName, groupName, memberName, auditRef, false);
    }

    /**
     * Store multiple logical assertion conditions. It contains a list of AssertionCondition objects
     * Each AssertionCondition object forms a single logical condition where multiple key, operator, value will be ANDed.
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param assertionId id of the assertion associated with the conditions
     * @param auditRef string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @param assertionConditions object containing conditions associated with the given assertion id
     * @return AssertionConditions object
     * @throws ZMSClientException in case of failure
     */
    public AssertionConditions putAssertionConditions(String domainName, String policyName, Long assertionId,
            String auditRef, String resourceOwner, AssertionConditions assertionConditions) {
        updatePrincipal();
        try {
            return client.putAssertionConditions(domainName, policyName, assertionId, auditRef,
                    resourceOwner, assertionConditions);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Store multiple logical assertion conditions. It contains a list of AssertionCondition objects
     * Each AssertionCondition object forms a single logical condition where multiple key, operator, value will be ANDed.
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param assertionId id of the assertion associated with the conditions
     * @param auditRef string containing audit specification or ticket number
     * @param assertionConditions object containing conditions associated with the given assertion id
     * @return AssertionConditions object
     * @throws ZMSClientException in case of failure
     */
    public AssertionConditions putAssertionConditions(String domainName, String policyName, Long assertionId,
            String auditRef, AssertionConditions assertionConditions) {
        return putAssertionConditions(domainName, policyName, assertionId, auditRef, null, assertionConditions);
    }

    /**
     * Store a single logical assertion condition.
     * AssertionCondition object forms a single logical condition where multiple key, operator, value will be ANDed.
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param assertionId id of the assertion associated with the condition
     * @param auditRef string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @param assertionCondition object containing a single logical condition associated with the given assertion id
     * @return AssertionConditions object
     * @throws ZMSClientException in case of failure
     */
    public AssertionCondition putAssertionCondition(String domainName, String policyName, Long assertionId,
            String auditRef, String resourceOwner, AssertionCondition assertionCondition) {
        updatePrincipal();
        try {
            return client.putAssertionCondition(domainName, policyName, assertionId, auditRef,
                    resourceOwner, assertionCondition);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Store a single logical assertion condition.
     * AssertionCondition object forms a single logical condition where multiple key, operator, value will be ANDed.
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param assertionId id of the assertion associated with the condition
     * @param auditRef string containing audit specification or ticket number
     * @param assertionCondition object containing a single logical condition associated with the given assertion id
     * @return AssertionConditions object
     * @throws ZMSClientException in case of failure
     */
    public AssertionCondition putAssertionCondition(String domainName, String policyName, Long assertionId,
            String auditRef, AssertionCondition assertionCondition) {
        return putAssertionCondition(domainName, policyName, assertionId, auditRef, null, assertionCondition);
    }

    /**
     * Delete all assertion conditions associated with the given assertion id.
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param assertionId id of the assertion associated with the conditions
     * @param auditRef string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public void deleteAssertionConditions(String domainName, String policyName, Long assertionId,
            String auditRef, String resourceOwner) {
        updatePrincipal();
        try {
            client.deleteAssertionConditions(domainName, policyName, assertionId, auditRef, resourceOwner);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete all assertion conditions associated with the given assertion id.
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param assertionId id of the assertion associated with the conditions
     * @param auditRef string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteAssertionConditions(String domainName, String policyName, Long assertionId, String auditRef) {
        deleteAssertionConditions(domainName, policyName, assertionId, auditRef, null);
    }

    /**
     * Delete a single assertion condition associated with the given assertion id.
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param assertionId id of the assertion associated with the conditions
     * @param conditionId id of the condition to be deleted
     * @param auditRef string containing audit specification or ticket number
     * @param resourceOwner string containing the owner of the resource
     * @throws ZMSClientException in case of failure
     */
    public void deleteAssertionCondition(String domainName, String policyName, Long assertionId,
            int conditionId, String auditRef, String resourceOwner) {
        updatePrincipal();
        try {
            client.deleteAssertionCondition(domainName, policyName, assertionId, conditionId, auditRef, resourceOwner);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete a single assertion condition associated with the given assertion id.
     *
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param assertionId id of the assertion associated with the conditions
     * @param conditionId id of the condition to be deleted
     * @param auditRef string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public void deleteAssertionCondition(String domainName, String policyName, Long assertionId,
            int conditionId, String auditRef) {
        deleteAssertionCondition(domainName, policyName, assertionId, conditionId, auditRef, null);
    }

    /**
     * Register domain as a dependency to service
     *
     * @param domainName name of the domain
     * @param auditRef string containing audit specification or ticket number
     * @param dependentService Dependent service provider details
     * @throws ZMSClientException in case of failure
     */
    public DependentService putDomainDependency(String domainName, String auditRef, DependentService dependentService) {
        updatePrincipal();
        try {
            return client.putDomainDependency(domainName, auditRef, dependentService);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * De-register domain as a dependency to service
     *
     * @param domainName name of the domain
     * @param service Dependent service name
     * @param auditRef string containing audit specification or ticket number
     * @throws ZMSClientException in case of failure
     */
    public String deleteDomainDependency(String domainName, String service, String auditRef) {
        updatePrincipal();
        try {
            return client.deleteDomainDependency(domainName, service, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * List registered provider services for domain
     *
     * @param domainName name of the domain
     * @throws ZMSClientException in case of failure
     */
    public ServiceIdentityList getDependentServiceList(String domainName) {
        updatePrincipal();
        try {
            return client.getDependentServiceList(domainName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * List dependent domains for provider service
     *
     * @param service name of the provider service
     * @throws ZMSClientException in case of failure
     */
    public DomainList getDependentDomainList(String service) {
        updatePrincipal();
        try {
            return client.getDependentDomainList(service);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete expired members from roles and groups.
     *
     * @param purgeResources indicates which resource will be purged. possible values are:
     *                       0 - none of them will be purged
     *                       1 - only roles will be purged
     *                       2 - only groups will be purged
     *                       default/3 - both of them will be purged
     * @param auditRef string containing audit specification or ticket number
     * @param returnObj Boolean returns all expired members deleted from roles and groups
     * @throws ZMSClientException in case of failure
     */
    public ExpiredMembers deleteExpiredMembers(Integer purgeResources, String auditRef, Boolean returnObj) {
        updatePrincipal();
        try {
            return client.deleteExpiredMembers(purgeResources, auditRef, returnObj);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Set the role resource ownership
     *
     * @param domainName domain name containing the role to be modified
     * @param roleName role name to be modified
     * @param auditRef string containing audit specification or ticket number
     * @param resourceOwnership resource ownership object
     * @throws ZMSClientException in case of failure
     */
    public ResourceRoleOwnership putResourceRoleOwnership(String domainName, String roleName, String auditRef,
            ResourceRoleOwnership resourceOwnership) {
        updatePrincipal();
        try {
            return client.putResourceRoleOwnership(domainName, roleName, auditRef, resourceOwnership);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Set the domain resource ownership
     *
     * @param domainName domain name to be modified
     * @param auditRef string containing audit specification or ticket number
     * @param resourceOwnership resource ownership object
     * @throws ZMSClientException in case of failure
     */
    public ResourceDomainOwnership putResourceDomainOwnership(String domainName, String auditRef,
            ResourceDomainOwnership resourceOwnership) {
        updatePrincipal();
        try {
            return client.putResourceDomainOwnership(domainName, auditRef, resourceOwnership);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Set the policy resource ownership
     *
     * @param domainName domain name containing the policy to be modified
     * @param policyName policy name to be modified
     * @param auditRef string containing audit specification or ticket number
     * @param resourceOwnership resource ownership object
     * @throws ZMSClientException in case of failure
     */
    public ResourcePolicyOwnership putResourcePolicyOwnership(String domainName, String policyName, String auditRef,
            ResourcePolicyOwnership resourceOwnership) {
        updatePrincipal();
        try {
            return client.putResourcePolicyOwnership(domainName, policyName, auditRef, resourceOwnership);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Set the service identity resource ownership
     *
     * @param domainName domain name containing the service to be modified
     * @param serviceName service name to be modified
     * @param auditRef string containing audit specification or ticket number
     * @param resourceOwnership resource ownership object
     * @throws ZMSClientException in case of failure
     */
    public ResourceServiceIdentityOwnership putResourceServiceIdentityOwnership(String domainName, String serviceName,
            String auditRef, ResourceServiceIdentityOwnership resourceOwnership) {
        updatePrincipal();
        try {
            return client.putResourceServiceIdentityOwnership(domainName, serviceName, auditRef, resourceOwnership);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }
}
