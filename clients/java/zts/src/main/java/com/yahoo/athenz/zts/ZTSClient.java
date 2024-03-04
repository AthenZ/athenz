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

package com.yahoo.athenz.zts;

import java.io.Closeable;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.oath.auth.KeyRefresher;
import com.oath.auth.KeyRefresherException;
import com.oath.auth.KeyRefresherListener;
import com.oath.auth.Utils;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import org.apache.http.HttpHost;
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
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.operator.OperatorCreationException;
import org.ehcache.Cache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.ServiceIdentityProvider;
import com.yahoo.athenz.auth.impl.RoleAuthority;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.common.config.AthenzConfig;
import com.yahoo.athenz.common.utils.SSLUtils;
import com.yahoo.athenz.common.utils.SSLUtils.ClientSSLContextBuilder;
import com.yahoo.rdl.JSON;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.Credentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;

public class ZTSClient implements Closeable {

    private static final Logger LOG = LoggerFactory.getLogger(ZTSClient.class);

    private String ztsUrl = null;
    private String proxyUrl = null;
    private String domain = null;
    private String service = null;
    private SSLContext sslContext = null;
    private ZTSClientNotificationSender notificationSender = null;

    ZTSRDLGeneratedClient ztsClient = null;
    ServiceIdentityProvider siaProvider = null;
    Principal principal = null;
    ZTSClientCache ztsClientCache = ZTSClientCache.getInstance();

    // configurable fields
    //
    static private boolean cacheDisabled = false;
    static private int tokenMinExpiryTime = 900;
    static private int tokenMaxExpiryOffset = 300;
    static private long prefetchInterval = 60; // seconds
    static private boolean prefetchAutoEnable = true;
    static private String x509CsrDn = null;
    static private String x509CsrDomain = null;
    static private int reqReadTimeout = 30000;
    static private int reqConnectTimeout = 30000;
    static private String x509CertDNSName = null;
    static private String confZtsUrl = null;
    static private JwtsSigningKeyResolver resolver = null;
    static private DnsResolver dnsResolver = null;
    
    private boolean enablePrefetch = true;
    private boolean ztsClientOverride = false;

    @SuppressWarnings("unused")
    static private boolean initialized = initConfigValues();
    
    // system properties

    public static final String ZTS_CLIENT_PROP_ATHENZ_CONF               = "athenz.athenz_conf";

    public static final String ZTS_CLIENT_PROP_TOKEN_MIN_EXPIRY_TIME     = "athenz.zts.client.token_min_expiry_time";
    public static final String ZTS_CLIENT_PROP_READ_TIMEOUT              = "athenz.zts.client.read_timeout";
    public static final String ZTS_CLIENT_PROP_CONNECT_TIMEOUT           = "athenz.zts.client.connect_timeout";
    public static final String ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL   = "athenz.zts.client.prefetch_sleep_interval";
    public static final String ZTS_CLIENT_PROP_PREFETCH_AUTO_ENABLE      = "athenz.zts.client.prefetch_auto_enable";
    public static final String ZTS_CLIENT_PROP_X509CERT_DNS_NAME         = "athenz.zts.client.x509cert_dns_name";
    public static final String ZTS_CLIENT_PROP_X509CSR_DN                = "athenz.zts.client.x509csr_dn";
    public static final String ZTS_CLIENT_PROP_X509CSR_DOMAIN            = "athenz.zts.client.x509csr_domain";
    public static final String ZTS_CLIENT_PROP_DISABLE_CACHE             = "athenz.zts.client.disable_cache";

    public static final String ZTS_CLIENT_PROP_CERT_ALIAS                       = "athenz.zts.client.cert_alias";
    
    public static final String ZTS_CLIENT_PROP_KEYSTORE_PATH                    = "athenz.zts.client.keystore_path";
    public static final String ZTS_CLIENT_PROP_KEYSTORE_TYPE                    = "athenz.zts.client.keystore_type";
    public static final String ZTS_CLIENT_PROP_KEYSTORE_PASSWORD                = "athenz.zts.client.keystore_password";
    public static final String ZTS_CLIENT_PROP_KEYSTORE_PWD_APP_NAME            = "athenz.zts.client.keystore_pwd_app_name";
    
    public static final String ZTS_CLIENT_PROP_KEY_MANAGER_PASSWORD             = "athenz.zts.client.keymanager_password";
    public static final String ZTS_CLIENT_PROP_KEY_MANAGER_PWD_APP_NAME         = "athenz.zts.client.keymanager_pwd_app_name";
    
    public static final String ZTS_CLIENT_PROP_TRUSTSTORE_PATH                  = "athenz.zts.client.truststore_path";
    public static final String ZTS_CLIENT_PROP_TRUSTSTORE_TYPE                  = "athenz.zts.client.truststore_type";
    public static final String ZTS_CLIENT_PROP_TRUSTSTORE_PASSWORD              = "athenz.zts.client.truststore_password";
    public static final String ZTS_CLIENT_PROP_TRUSTSTORE_PWD_APP_NAME          = "athenz.zts.client.truststore_pwd_app_name";

    public static final String ZTS_CLIENT_PROP_POOL_MAX_PER_ROUTE               = "athenz.zts.client.http_pool_max_per_route";
    public static final String ZTS_CLIENT_PROP_POOL_MAX_TOTAL                   = "athenz.zts.client.http_pool_max_total";

    public static final String ZTS_CLIENT_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS  = "athenz.zts.client.private_keystore_factory_class";
    public static final String ZTS_CLIENT_PROP_CLIENT_PROTOCOL                  = "athenz.zts.client.client_ssl_protocol";
    public static final String ZTS_CLIENT_PKEY_STORE_FACTORY_CLASS              = "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory";
    public static final String ZTS_CLIENT_DEFAULT_CLIENT_SSL_PROTOCOL           = "TLSv1.2";

    public static final String SPIFFE_URI          = "spiffe://";
    public static final String SPIFFE_COMP_SERVICE = "/sa/";
    public static final String SPIFFE_COMP_ROLE    = "/ra/";

    public static final String ROLE_TOKEN_HEADER = System.getProperty(RoleAuthority.ATHENZ_PROP_ROLE_HEADER,
            RoleAuthority.HTTP_HEADER);

    final static ConcurrentHashMap<String, RoleToken> ROLE_TOKEN_CACHE = new ConcurrentHashMap<>();
    final static ConcurrentHashMap<String, AccessTokenResponseCacheEntry> ACCESS_TOKEN_CACHE = new ConcurrentHashMap<>();
    final static ConcurrentHashMap<String, AWSTemporaryCredentials> AWS_CREDS_CACHE = new ConcurrentHashMap<>();
    final static ConcurrentHashMap<String, OIDCResponse> ID_TOKEN_CACHE = new ConcurrentHashMap<>();

    private static final Queue<PrefetchTokenScheduledItem> PREFETCH_SCHEDULED_ITEMS = new ConcurrentLinkedQueue<>();
    private static Timer FETCH_TIMER;
    private static final Object TIMER_LOCK = new Object();
    static AtomicLong FETCHER_LAST_RUN_AT = new AtomicLong(-1);
    static final ClientKeyRefresherListener KEY_REFRESHER_LISTENER = new ClientKeyRefresherListener();

    // allows outside implementations to get role tokens for special environments - ex. hadoop
    
    private static ServiceLoader<ZTSClientService> ztsTokenProviders;
    private static AtomicReference<Set<String>> svcLoaderCacheKeys;
    private static PrivateKeyStore PRIVATE_KEY_STORE = loadServicePrivateKey();
    private static ZTSAccessTokenFileLoader ztsAccessTokenFileLoader;

    enum TokenType {
        ROLE,
        ACCESS,
        AWS,
        SVC_ROLE,
        ID
    }

    static boolean initConfigValues() {

        // load our service providers tokens
        
        loadSvcProviderTokens();
        
        // set the token min expiry time

        setTokenMinExpiryTime(Integer.parseInt(System.getProperty(ZTS_CLIENT_PROP_TOKEN_MIN_EXPIRY_TIME, "900")));

        // set the prefetch interval
        
        setPrefetchInterval(Integer.parseInt(System.getProperty(ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "60")));

        // set the prefetch support
        
        setPrefetchAutoEnable(Boolean.parseBoolean(System.getProperty(ZTS_CLIENT_PROP_PREFETCH_AUTO_ENABLE, "true")));
        
        // disable the cache if configured
        
        setCacheDisable(Boolean.parseBoolean(System.getProperty(ZTS_CLIENT_PROP_DISABLE_CACHE, "false")));

        // set x509 csr details
        
        setX509CsrDetails(System.getProperty(ZTS_CLIENT_PROP_X509CSR_DN),
                System.getProperty(ZTS_CLIENT_PROP_X509CSR_DOMAIN));
        
        // set connection timeouts
        
        setConnectionTimeouts(Integer.parseInt(System.getProperty(ZTS_CLIENT_PROP_CONNECT_TIMEOUT, "30000")),
                Integer.parseInt(System.getProperty(ZTS_CLIENT_PROP_READ_TIMEOUT, "30000")));
        
        // set our server certificate dns name
        
        setX509CertDnsName(System.getProperty(ZTS_CLIENT_PROP_X509CERT_DNS_NAME));
        
        // finally retrieve our configuration ZTS url from our config file
        
        lookupZTSUrl();

        // init zts file utility

        initZTSAccessTokenFileLoader();
        
        return true;
    }
    
    /**
     * Set the X509 Cert DNS Name in case ZTS Server is running with
     * a certificate not matching its hostname
     * @param dnsName name of the ZTS Servers X.509 Cert dns value
     */
    public static void setX509CertDnsName(final String dnsName) {
        x509CertDNSName = dnsName;
    }
    
    /**
     * Set request connection and read timeout
     * @param connectTimeout timeout for initial connection in milliseconds
     * @param readTimeout timeout for read response in milliseconds
     */
    public static void setConnectionTimeouts(int connectTimeout, int readTimeout) {
         reqConnectTimeout = connectTimeout;
         reqReadTimeout = readTimeout;
    }
    
    /**
     * Set X509 CSR Details - DN and domain name. These values can be specified
     * in the generate csr function as well in which case these will be ignored.
     * @param csrDn string identifying the dn for the csr without the cn component
     * @param csrDomain string identifying the dns domain for generating SAN fields
     */
    public static void setX509CsrDetails(final String csrDn, final String csrDomain) {
        x509CsrDn = csrDn;
        x509CsrDomain = csrDomain;
    }
    
    /**
     * Disable the cache of role tokens if configured.
     * @param cacheState false to disable the cache
     */
    public static void setCacheDisable(boolean cacheState) {
        cacheDisabled = cacheState;
    }
    
    /**
     * Enable prefetch of role tokens
     * @param fetchState state of prefetch
     */
    public static void setPrefetchAutoEnable(boolean fetchState) {
        prefetchAutoEnable = fetchState;
    }
    
    /**
     * Set the prefetch interval. if the prefetch interval is longer than
     * our token min expiry time, then we'll default back to 60 seconds
     * @param interval time in seconds
     */
    public static void setPrefetchInterval(int interval) {
        prefetchInterval = interval;
        if (prefetchInterval >= tokenMinExpiryTime) {
            prefetchInterval = 60;
        }
    }
    /**
     * Set the minimum token expiry time. The server will not give out tokens
     * less than configured expiry time
     * @param minExpiryTime expiry time in seconds
     */
    public static void setTokenMinExpiryTime(int minExpiryTime) {
        
        // The minimum token expiry time by default is 15 minutes (900). By default the
        // server gives out role tokens for 2 hours and with this setting we'll be able
        // to cache tokens for 1hr45mins before requesting a new one from ZTS

        tokenMinExpiryTime = minExpiryTime;
        if (tokenMinExpiryTime < 0) {
            tokenMinExpiryTime = 900;
        }
    }

    public static void lookupZTSUrl() {
        
        String rootDir = System.getenv("ROOT");
        if (rootDir == null) {
            rootDir = "/home/athenz";
        }
        
        String confFileName = System.getProperty(ZTS_CLIENT_PROP_ATHENZ_CONF,
                rootDir + "/conf/athenz/athenz.conf");

        try {
            Path path = Paths.get(confFileName);
            AthenzConfig conf = JSON.fromBytes(Files.readAllBytes(path), AthenzConfig.class);
            confZtsUrl = conf.getZtsUrl();
        } catch (Exception ex) {
            // if we have a zts client service specified and we have keys
            // in our service loader cache then we're running within
            // some managed framework (e.g. hadoop) so we're going to
            // report this exception as a warning rather than an error
            // and default to localhost as the url to avoid further
            // warnings from our generated client

            LOG.warn("Unable to extract ZTS Url from conf file {}, exc: {}",
                    confFileName, ex.getMessage());
            
            if (!svcLoaderCacheKeys.get().isEmpty()) {
                confZtsUrl = "https://localhost:4443/";
            }
        }
    }

    public static void initZTSAccessTokenFileLoader() {
        if (resolver == null) {
            resolver = new JwtsSigningKeyResolver(null, null);
        }
        ztsAccessTokenFileLoader = new ZTSAccessTokenFileLoader(resolver);
        ztsAccessTokenFileLoader.preload();
    }

    public static void setAccessTokenSignKeyResolver(JwtsSigningKeyResolver jwtsSigningKeyResolver) {
        resolver = jwtsSigningKeyResolver;
    }

    /**
     * Constructs a new ZTSClient object with default settings.
     * The url for ZTS Server is automatically retrieved from the athenz
     * configuration file (ztsUrl field). The client can only be used
     * to retrieve objects from ZTS that do not require any authentication
     * otherwise addCredentials method must be used to set the principal identity.
     * Default read and connect timeout values are 30000ms (30sec).
     * The application can change these values by using the
     * athenz.zts.client.read_timeout and athenz.zts.client.connect_timeout
     * system properties. The values specified for timeouts must be in
     * milliseconds.
     */
    public ZTSClient() {
        initClient(null, null, null, null, null);
        enablePrefetch = false; // can't use this domain and service for prefetch
    }
    
    /**
     * Constructs a new ZTSClient object with the given ZTS Server Url.
     * If the specified zts url is null, then it is automatically
     * retrieved from athenz.conf configuration file (ztsUrl field).
     * Default read and connect timeout values are 30000ms (30sec).
     * The application can change these values by using the
     * athenz.zts.client.read_timeout and athenz.zts.client.connect_timeout
     * system properties. The values specified for timeouts must be in
     * milliseconds. This client object can only be used for API calls
     * that require no authentication or setting the principal using
     * addCredentials method before calling any other authentication
     * protected API.
     * @param ztsUrl ZTS Server's URL (optional)
     */
    public ZTSClient(String ztsUrl) {
        initClient(ztsUrl, null, null, null, null);
        enablePrefetch = false; // can't use this domain and service for prefetch
    }
    
    /**
     * Constructs a new ZTSClient object with the given principal identity.
     * The url for ZTS Server is automatically retrieved from the athenz
     * configuration file (ztsUrl field). Default read and connect timeout values
     * are 30000ms (30sec). The application can change these values by using the
     * athenz.zts.client.read_timeout and athenz.zts.client.connect_timeout
     * system properties. The values specified for timeouts must be in milliseconds.
     * @param identity Principal identity for authenticating requests
     */
    public ZTSClient(Principal identity) {
        this(null, identity);
    }
    
    /**
     * Constructs a new ZTSClient object with the given principal identity
     * and ZTS Server Url. Default read and connect timeout values are
     * 30000ms (30sec). The application can change these values by using the
     * athenz.zts.client.read_timeout and athenz.zts.client.connect_timeout
     * system properties. The values specified for timeouts must be in milliseconds.
     * @param ztsUrl ZTS Server's URL (optional)
     * @param identity Principal identity for authenticating requests
     */
    public ZTSClient(String ztsUrl, Principal identity) {
        
        // verify we have a valid principal and authority
        
        if (identity == null) {
            throw new IllegalArgumentException("Principal object must be specified");
        }
        if (identity.getAuthority() == null) {
            throw new IllegalArgumentException("Principal Authority cannot be null");
        }
        initClient(ztsUrl, identity, null, null, null);
        enablePrefetch = false; // can't use this domain and service for prefetch
    }
    
    /**
     * Constructs a new ZTSClient object with the given SSLContext object
     * and ZTS Server Url. Default read and connect timeout values are
     * 30000ms (30sec). The application can change these values by using the
     * athenz.zts.client.read_timeout and athenz.zts.client.connect_timeout
     * system properties. The values specified for timeouts must be in milliseconds.
     * @param ztsUrl ZTS Server's URL (optional)
     * @param sslContext SSLContext that includes service's private key and x.509 certificate
     * for authenticating requests
     */
    public ZTSClient(String ztsUrl, SSLContext sslContext) {
        this(ztsUrl, null, sslContext);
    }

    /**
     * Constructs a new ZTSClient object with the given SSLContext object
     * and ZTS Server Url through the specified Proxy URL. Default read
     * and connect timeout values are 30000ms (30sec). The application can
     * change these values by using the athenz.zts.client.read_timeout and
     * athenz.zts.client.connect_timeout system properties. The values
     * specified for timeouts must be in milliseconds.
     * @param ztsUrl ZTS Server's URL
     * @param proxyUrl Proxy Server's URL
     * @param sslContext SSLContext that includes service's private key and x.509 certificate
     * for authenticating requests
     */
    public ZTSClient(String ztsUrl, String proxyUrl, SSLContext sslContext) {

        // verify we have a valid ssl context specified

        if (sslContext == null) {
            throw new IllegalArgumentException("SSLContext object must be specified");
        }
        this.sslContext = sslContext;
        this.proxyUrl = proxyUrl;
        initClient(ztsUrl, null, null, null, null);
    }
    
    /**
     * Constructs a new ZTSClient object with the given service details
     * identity provider (which will provide the ntoken for the service)
     * The ZTS Server url is automatically retrieved from athenz.conf configuration
     * file (ztsUrl field). Default read and connect timeout values are
     * 30000ms (30sec). The application can change these values by using the
     * athenz.zts.client.read_timeout and athenz.zts.client.connect_timeout
     * system properties. The values specified for timeouts must be in milliseconds.
     * @param domainName name of the domain
     * @param serviceName name of the service
     * @param siaProvider service identity provider for the client to request principals
     */
    public ZTSClient(String domainName, String serviceName, ServiceIdentityProvider siaProvider) {
        this(null, domainName, serviceName, siaProvider);
    }

    /**
     * Constructs a new ZTSClient object with the given service details
     * identity provider (which will provide the ntoken for the service)
     * and ZTS Server Url. If the specified zts url is null, then it is
     * automatically retrieved from athenz.conf configuration file
     * (ztsUrl field). Default read and connect timeout values are
     * 30000ms (30sec). The application can change these values by using the
     * athenz.zts.client.read_timeout and athenz.zts.client.connect_timeout
     * system properties. The values specified for timeouts must be in milliseconds.
     * @param ztsUrl ZTS Server's URL (optional)
     * @param domainName name of the domain
     * @param serviceName name of the service
     * @param siaProvider service identity provider for the client to request principals
     */
    public ZTSClient(String ztsUrl, String domainName, String serviceName,
                     ServiceIdentityProvider siaProvider) {
        if (isEmpty(domainName)) {
            throw new IllegalArgumentException("Domain name must be specified");
        }
        if (isEmpty(serviceName)) {
            throw new IllegalArgumentException("Service name must be specified");
        }
        if (siaProvider == null) {
            throw new IllegalArgumentException("Service Identity Provider must be specified");
        }
        initClient(ztsUrl, null, domainName, serviceName, siaProvider);
    }

    /**
     * Constructs a new ZTSClient object with the given service details
     * identity provider (which will provide the ntoken for the service)
     * and ZTS Server Url. If the specified zts url is null, then it is
     * automatically retrieved from athenz.conf configuration file
     * (ztsUrl field). Default read and connect timeout values are
     * 30000ms (30sec). The application can change these values by using the
     * athenz.zts.client.read_timeout and athenz.zts.client.connect_timeout
     * system properties. The values specified for timeouts must be in milliseconds.
     * @param ztsUrl ZTS Server's URL (optional)
     * @param proxyUrl Proxy Server's URL
     * @param domainName name of the domain
     * @param serviceName name of the service
     * @param siaProvider service identity provider for the client to request principals
     */
    public ZTSClient(String ztsUrl, String proxyUrl, String domainName, String serviceName,
                     ServiceIdentityProvider siaProvider) {
        if (isEmpty(domainName)) {
            throw new IllegalArgumentException("Domain name must be specified");
        }
        if (isEmpty(serviceName)) {
            throw new IllegalArgumentException("Service name must be specified");
        }
        if (siaProvider == null) {
            throw new IllegalArgumentException("Service Identity Provider must be specified");
        }
        this.proxyUrl = proxyUrl;
        initClient(ztsUrl, null, domainName, serviceName, siaProvider);
    }
    
    /**
     * Close the ZTSClient object and release any allocated resources.
     */
    @Override
    public void close() {
        ztsClient.close();
    }

    /**
     * Call to enable/disable prefetch for the current ZTSClient.
     * @param state whether prefetch is enabled or not
     */
    public void setEnablePrefetch(boolean state) {
        enablePrefetch = state;
    }

    /**
     * Set the DNSResolver to be used by the ZTS Client
     * @param resolver user supplied dns resolver
     */
    public static void setDnsResolver(DnsResolver resolver) {
        dnsResolver = resolver;
    }

    /**
     * Sets a notificationSender that will listen to notifications and send them (usually to domain admins)
     * @param notificationSender notification sender
     */
    public void setNotificationSender(ZTSClientNotificationSender notificationSender) {
        this.notificationSender = notificationSender;
    }

    /**
     * Cancel the Prefetch Timer. This removes all the prefetch
     * items from the list, purges and cancels the fetch timer.
     * This should be called before application shutdown.
     */
    public static void cancelPrefetch() {
        PREFETCH_SCHEDULED_ITEMS.clear();
        if (FETCH_TIMER != null) {
            FETCH_TIMER.purge();
            FETCH_TIMER.cancel();
            FETCH_TIMER = null;
        }
    }
    
    /**
     * Returns the locally configured ZTS Server's URL value
     * @return ZTS Server URL
     */
    public String getZTSUrl() {
        return ztsUrl;
    }
    
    public void setZTSRDLGeneratedClient(ZTSRDLGeneratedClient client) {
        this.ztsClient = client;
        ztsClientOverride = true;
    }

    public void setZTSClientCache(ZTSClientCache ztsClientCache) {
        this.ztsClientCache = ztsClientCache;
    }

    /**
     * Generate the SSLContext object based on give key/cert and truststore
     * files. If configured, the method will monitor any changes in the given
     * key/cert files and automatically update the ssl context.
     * @param trustStorePath path to the trust-store
     * @param trustStorePassword trust store password
     * @param publicCertFile path to the certificate file
     * @param privateKeyFile path to the private key file
     * @param monitorKeyCertUpdates boolean flag whether or not monitor file updates
     * @return SSLContext object
     * @throws InterruptedException interrupt exceptions
     * @throws KeyRefresherException any exceptions from the cert refresher
     * @throws IOException io exceptions
     */
    public SSLContext createSSLContext(final String trustStorePath, final char[] trustStorePassword,
                 final String publicCertFile, final String privateKeyFile, boolean monitorKeyCertUpdates)
            throws InterruptedException, KeyRefresherException, IOException {

        // Create our SSL Context object based on our private key and
        // certificate and jdk truststore

        KeyRefresher keyRefresher = Utils.generateKeyRefresher(trustStorePath, trustStorePassword,
                publicCertFile, privateKeyFile, KEY_REFRESHER_LISTENER);
        SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                keyRefresher.getTrustManagerProxy());
        if (monitorKeyCertUpdates) {
            keyRefresher.startup();
        }
        return sslContext;
    }

    private SSLContext createSSLContext() {
        
        // to create the SSL context we must have the keystore path
        // specified. If it's not specified, then we are not going
        // to create our ssl context
        
        String keyStorePath = System.getProperty(ZTS_CLIENT_PROP_KEYSTORE_PATH);
        if (isEmpty(keyStorePath)) {
            return null;
        }
        String keyStoreType = System.getProperty(ZTS_CLIENT_PROP_KEYSTORE_TYPE);
        String keyStorePwd = System.getProperty(ZTS_CLIENT_PROP_KEYSTORE_PASSWORD);
        char[] keyStorePassword = null;
        if (!isEmpty(keyStorePwd)) {
            keyStorePassword = keyStorePwd.toCharArray();
        }
        String keyStorePasswordAppName = System.getProperty(ZTS_CLIENT_PROP_KEYSTORE_PWD_APP_NAME);
        char[] keyManagerPassword = null;
        String keyManagerPwd = System.getProperty(ZTS_CLIENT_PROP_KEY_MANAGER_PASSWORD);
        if (!isEmpty(keyManagerPwd)) {
            keyManagerPassword = keyManagerPwd.toCharArray();
        }
        String keyManagerPasswordAppName = System.getProperty(ZTS_CLIENT_PROP_KEY_MANAGER_PWD_APP_NAME);
        
        // truststore
        String trustStorePath = System.getProperty(ZTS_CLIENT_PROP_TRUSTSTORE_PATH);
        String trustStoreType = System.getProperty(ZTS_CLIENT_PROP_TRUSTSTORE_TYPE);
        String trustStorePwd = System.getProperty(ZTS_CLIENT_PROP_TRUSTSTORE_PASSWORD);
        char[] trustStorePassword = null;
        if (!isEmpty(trustStorePwd)) {
            trustStorePassword = trustStorePwd.toCharArray();
        }
        String trustStorePasswordAppName = System.getProperty(ZTS_CLIENT_PROP_TRUSTSTORE_PWD_APP_NAME);
        
        // alias and protocol details
        String certAlias = System.getProperty(ZTS_CLIENT_PROP_CERT_ALIAS);
        String clientProtocol = System.getProperty(ZTS_CLIENT_PROP_CLIENT_PROTOCOL,
                ZTS_CLIENT_DEFAULT_CLIENT_SSL_PROTOCOL);

        ClientSSLContextBuilder builder = new SSLUtils.ClientSSLContextBuilder(clientProtocol)
                .privateKeyStore(PRIVATE_KEY_STORE).keyStorePath(keyStorePath);
        
        if (!isEmpty(certAlias)) {
            builder.certAlias(certAlias);
        }
        if (!isEmpty(keyStoreType)) {
            builder.keyStoreType(keyStoreType);
        }
        if (null != keyStorePassword) {
            builder.keyStorePassword(keyStorePassword);
        }
        if (null != keyStorePasswordAppName) {
            builder.keyStorePasswordAppName(keyStorePasswordAppName);
        }
        if (null != keyManagerPassword) {
            builder.keyManagerPassword(keyManagerPassword);
        }
        if (null != keyManagerPasswordAppName) {
            builder.keyManagerPasswordAppName(keyManagerPasswordAppName);
        }
        if (!isEmpty(trustStorePath)) {
            builder.trustStorePath(trustStorePath);
        }
        if (!isEmpty(trustStoreType)) {
            builder.trustStoreType(trustStoreType);
        }
        if (null != trustStorePassword) {
            builder.trustStorePassword(trustStorePassword);
        }
        if (null != trustStorePasswordAppName) {
            builder.trustStorePasswordAppName(trustStorePasswordAppName);
        }

        return builder.build();
    }
    
    static PrivateKeyStore loadServicePrivateKey() {
        String pkeyFactoryClass = System.getProperty(ZTS_CLIENT_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                ZTS_CLIENT_PKEY_STORE_FACTORY_CLASS);
        return SSLUtils.loadServicePrivateKey(pkeyFactoryClass);
    }

    protected CloseableHttpClient createHttpClient(int connTimeoutMs, int readTimeoutMs, final String proxyUrl,
            PoolingHttpClientConnectionManager poolingHttpClientConnectionManager) {
        //apache http client expects in milliseconds
        HttpHost proxy = null;
        if (!isEmpty(proxyUrl)) {
            final URI u = URI.create(proxyUrl);
            proxy = new HttpHost(u.getHost(), u.getPort(), u.getScheme());
        }
        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout(connTimeoutMs)
                .setSocketTimeout(readTimeoutMs)
                .setRedirectsEnabled(false)
                .setProxy(proxy)
                .build();
        return HttpClients.custom()
                .setConnectionManager(poolingHttpClientConnectionManager)
                .setDefaultRequestConfig(config)
                .build();
    }

    private void initClient(final String serverUrl, Principal identity, final String domainName,
            final String serviceName, final ServiceIdentityProvider siaProvider) {
        
        ztsUrl = (serverUrl == null) ? confZtsUrl : serverUrl;
        if (isEmpty(ztsUrl)) {
            throw new IllegalArgumentException("ZTS url must be specified");
        }

        // verify if the url is ending with /zts/v1 and if it's
        // not we'll automatically append it
        
        if (!ztsUrl.endsWith("/zts/v1")) {
            if (ztsUrl.charAt(ztsUrl.length() - 1) != '/') {
                ztsUrl += '/';
            }
            ztsUrl += "zts/v1";
        }

        // determine to see if we need a host verifier for our ssl connections
        
        HostnameVerifier hostnameVerifier = null;
        if (!isEmpty(x509CertDNSName)) {
            hostnameVerifier = new AWSHostNameVerifier(x509CertDNSName);
        }
        
        // if we don't have a ssl context specified, check the system
        // properties to see if we need to create one

        if (sslContext == null) {
            sslContext = createSSLContext();
        }
        if (sslContext != null) {
            enablePrefetch = true;
        }

        // determine our read and connect timeouts

        PoolingHttpClientConnectionManager connManager = createConnectionManager(sslContext, hostnameVerifier);
        CloseableHttpClient httpClient = createHttpClient(reqConnectTimeout, reqReadTimeout,
                proxyUrl, connManager);

        ztsClient = new ZTSRDLGeneratedClient(ztsUrl, httpClient);
        principal = identity;
        domain = domainName;
        service = serviceName;
        this.siaProvider = siaProvider;
        
        // if we are given a principal object then we need
        // to update the domain/service settings
        
        if (principal != null) {
            domain  = principal.getDomain();
            service = principal.getName();
            ztsClient.addCredentials(identity.getAuthority().getHeader(), identity.getCredentials());
        }
    }

    PoolingHttpClientConnectionManager createConnectionManager(SSLContext sslContext, HostnameVerifier hostnameVerifier) {

        if (sslContext == null) {
            return null;
        }

        SSLConnectionSocketFactory sslSocketFactory;
        if (hostnameVerifier == null) {
            sslSocketFactory = new SSLConnectionSocketFactory(sslContext);
        } else {
            sslSocketFactory = new SSLConnectionSocketFactory(sslContext, hostnameVerifier);
        }
        Registry<ConnectionSocketFactory> registry = RegistryBuilder
                .<ConnectionSocketFactory>create()
                .register("https", sslSocketFactory)
                .register("http", new PlainConnectionSocketFactory())
                .build();
        PoolingHttpClientConnectionManager poolingHttpClientConnectionManager
                = new PoolingHttpClientConnectionManager(registry, dnsResolver);

        // we'll use the default values from apache http connector - max 20 and per route 2

        int maxPerRoute = Integer.parseInt(System.getProperty(ZTS_CLIENT_PROP_POOL_MAX_PER_ROUTE, "2"));
        int maxTotal = Integer.parseInt(System.getProperty(ZTS_CLIENT_PROP_POOL_MAX_TOTAL, "20"));

        poolingHttpClientConnectionManager.setDefaultMaxPerRoute(maxPerRoute);
        poolingHttpClientConnectionManager.setMaxTotal(maxTotal);
        return poolingHttpClientConnectionManager;
    }

    void setPrefetchInterval(long interval) {
        prefetchInterval = interval;
    }
    
    long getPrefetchInterval() {
        return prefetchInterval;
    }
    
    /**
     * Returns the header name that the client needs to use to pass
     * the received RoleToken to the Athenz protected service.
     * @return HTTP header name
     */
    public static String getHeader() {
        return ROLE_TOKEN_HEADER;
    }

    /**
     * Set client credentials based on the given principal.
     * @param identity Principal identity for authenticating requests
     * @return self ZTSClient object
     */
    public ZTSClient addCredentials(Principal identity) {
        return addPrincipalCredentials(identity, true);
    }
    
    /**
     * Set the client credentials using the specified header and token.
     * @param credHeader authentication header name
     * @param credToken authentication credentials
     */
    public void addCredentials(String credHeader, String credToken) {
        ztsClient.addCredentials(credHeader, credToken);
    }
    
    /**
     * Clear the principal identity set for the client. Unless a new principal is set
     * using the addCredentials method, the client can only be used to requests data
     * from the ZTS Server that doesn't require any authentication.
     * @return self ZTSClient object
     */
    public ZTSClient clearCredentials() {
        
        if (principal != null) {
            ztsClient.addCredentials(principal.getAuthority().getHeader(), null);
            principal = null;
        }
        return this;
    }
    
    ZTSClient addPrincipalCredentials(Principal identity, boolean resetServiceDetails) {
        
        if (identity != null && identity.getAuthority() != null) {
            ztsClient.addCredentials(identity.getAuthority().getHeader(), identity.getCredentials());
        }

        // if the client is adding new principal identity then we have to 
        // clear out the sia provider object reference so that we don't try
        // to get a service token since we already have one given to us

        if (resetServiceDetails) {
            siaProvider = null;
        }
        
        principal = identity;
        return this;
    }

    boolean sameCredentialsAsBefore(Principal svcPrincipal) {
        
        // if we don't have a principal or no credentials
        // then the principal has changed
        
        if (principal == null) {
            return false;
        }
        
        final String creds = principal.getCredentials();
        if (creds == null) {
            return false;
        }
        
        return creds.equals(svcPrincipal.getCredentials());
    }
    
    boolean updateServicePrincipal() {
        
        // if we have a service principal then we need to keep updating
        // our PrincipalToken otherwise it might expire.
        
        if (siaProvider == null) {
            return false;
        }
        
        Principal svcPrincipal = siaProvider.getIdentity(domain, service);
        
        // if we get no principal from our sia provider, then we
        // should log and throw an IllegalArgumentException otherwise the
        // client doesn't know that something bad has happened - in this
        // case illegal domain/service was passed to the constructor
        // and the ZTS Server just rejects the request with 401
        
        if (svcPrincipal == null) {
            final String msg = "UpdateServicePrincipal: Unable to get PrincipalToken "
                    + "from SIA Provider for " + domain + "." + service;
            LOG.error(msg);
            throw new IllegalArgumentException(msg);
        }
        
        // if the principal has the same credentials as before
        // then we don't need to update anything
        
        if (sameCredentialsAsBefore(svcPrincipal)) {
            return false;
        }
            
        addPrincipalCredentials(svcPrincipal, false);
        return true;
    }
    
    /**
     * Retrieve list of services that have been configured to run on the specified host
     * @param host name of the host
     * @return list of service names on success. ZTSClientException will be thrown in case of failure
     */
    public HostServices getHostServices(String host) {
        updateServicePrincipal();
        try {
            return ztsClient.getHostServices(host);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Return OpenID Configuration Metadata object
     * @return configuration object. ZTSClientException will be thrown in case of failure
     */
    public OpenIDConfig getOpenIDConfig() {
        try {
            return ztsClient.getOpenIDConfig();
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve list of ZTS Server public keys in Json WEB Key (JWK) format
     * @param rfcCurveNames EC curve names - use values defined in RFC only
     * @return list of public keys (JWKs) on success. ZTSClientException will be thrown in case of failure
     */
    public JWKList getJWKList(boolean rfcCurveNames) {
        updateServicePrincipal();
        try {
            return ztsClient.getJWKList(rfcCurveNames);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve list of ZTS Server public keys in Json WEB Key (JWK) format
     * @return list of public keys (JWKs) on success. ZTSClientException will be thrown in case of failure
     */
    public JWKList getJWKList() {
        return getJWKList(false);
    }

    /**
     * For the specified requester(user/service) return the corresponding Role Token that
     * includes the list of roles that the principal has access to in the specified domain.
     * The client will automatically fulfill the request from the cache, if possible.
     * The default minimum expiry time is 900 secs (15 mins).
     * @param domainName name of the domain
     * @return ZTS generated Role Token. ZTSClientException will be thrown in case of failure
     */
    public RoleToken getRoleToken(String domainName) {
        return getRoleToken(domainName, null, null, null, false, null);
    }
    
    /**
     * For the specified requester(user/service) return the corresponding Role Token that
     * includes the list of roles that the principal has access to in the specified domain
     * and filtered to include only those that end with the specified suffix.
     * The client will automatically fulfill the request from the cache, if possible.
     * The default minimum expiry time is 900 secs (15 mins).
     * @param domainName name of the domain
     * @param roleNames only interested in roles with these names, comma separated list of roles
     * @return ZTS generated Role Token. ZTSClientException will be thrown in case of failure
     */
    public RoleToken getRoleToken(String domainName, String roleNames) {
        if (isEmpty(roleNames)) {
            throw new IllegalArgumentException("RoleNames cannot be null or empty");
        }
        return getRoleToken(domainName, roleNames, null, null, false, null);
    }
    
    /**
     * For the specified requester(user/service) return the corresponding Role Token that
     * includes the list of roles that the principal has access to in the specified domain
     * @param domainName name of the domain
     * @param roleNames only interested in roles with these names, comma separated list of roles
     * @param minExpiryTime (optional) specifies that the returned RoleToken must be
     *          at least valid (min/lower bound) for specified number of seconds,
     * @param maxExpiryTime (optional) specifies that the returned RoleToken must be
     *          at most valid (max/upper bound) for specified number of seconds.
     * @param ignoreCache ignore the cache and retrieve the token from ZTS Server
     * @return ZTS generated Role Token. ZTSClientException will be thrown in case of failure
     */
    public RoleToken getRoleToken(String domainName, String roleNames, Integer minExpiryTime,
            Integer maxExpiryTime, boolean ignoreCache) {
        return getRoleToken(domainName, roleNames, minExpiryTime, maxExpiryTime,
                ignoreCache, null);
    }
    
    /**
     * For the specified requester(user/service) return the corresponding Role Token that
     * includes the list of roles that the principal has access to in the specified domain
     * @param domainName name of the domain
     * @param roleNames only interested in roles with these names, comma separated list of roles
     * @param minExpiryTime (optional) specifies that the returned RoleToken must be
     *          at least valid (min/lower bound) for specified number of seconds,
     * @param maxExpiryTime (optional) specifies that the returned RoleToken must be
     *          at most valid (max/upper bound) for specified number of seconds.
     * @param ignoreCache ignore the cache and retrieve the token from ZTS Server
     * @param proxyForPrincipal (optional) this request is proxy for this principal
     * @return ZTS generated Role Token. ZTSClientException will be thrown in case of failure
     */
    public RoleToken getRoleToken(String domainName, String roleNames, Integer minExpiryTime,
            Integer maxExpiryTime, boolean ignoreCache, String proxyForPrincipal) {
        
        RoleToken roleToken;

        // first lookup in our cache to see if it can be satisfied
        // only if we're not asked to ignore the cache

        String cacheKey = null;
        if (!cacheDisabled) {
            cacheKey = getRoleTokenCacheKey(domainName, roleNames, proxyForPrincipal);
            if (cacheKey != null && !ignoreCache) {
                roleToken = lookupRoleTokenInCache(cacheKey, minExpiryTime, maxExpiryTime, tokenMinExpiryTime);
                if (roleToken != null) {
                    return roleToken;
                }
                // start prefetch for this token if prefetch is enabled
                if (enablePrefetch && prefetchAutoEnable) {
                    if (prefetchRoleToken(domainName, roleNames, minExpiryTime, maxExpiryTime,
                            proxyForPrincipal)) {
                        roleToken = lookupRoleTokenInCache(cacheKey, minExpiryTime, maxExpiryTime, tokenMinExpiryTime);
                    }
                    if (roleToken != null) {
                        return roleToken;
                    }
                    LOG.error("GetRoleToken: cache prefetch and lookup error");
                }
            }
        }
        
        // 2nd look in service providers
        //
        for (ZTSClientService provider: ztsTokenProviders) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("getRoleToken: found service provider={}", provider);
            }
            
            // provider needs to know who the client is so we'll be passing
            // the client's domain and service names as the first two fields
            
            roleToken = provider.fetchToken(domain, service, domainName, roleNames,
                    minExpiryTime, maxExpiryTime, proxyForPrincipal);
            if (roleToken != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("getRoleToken: service provider={} returns token", provider);
                }
                return roleToken;
            }
        }
        
        // if no hit then we need to request a new token from ZTS
        
        updateServicePrincipal();
        try {
            roleToken = ztsClient.getRoleToken(domainName, roleNames,
                    minExpiryTime, maxExpiryTime, proxyForPrincipal);
        } catch (ResourceException ex) {

            // if we have an entry in our cache then we'll return that
            // instead of returning failure

            if (cacheKey != null && !ignoreCache) {
                roleToken = lookupRoleTokenInCache(cacheKey, null, null, 1);
                if (roleToken != null) {
                    return roleToken;
                }
            }

            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {

            // if we have an entry in our cache then we'll return that
            // instead of returning failure

            if (cacheKey != null && !ignoreCache) {
                roleToken = lookupRoleTokenInCache(cacheKey, null, null, 1);
                if (roleToken != null) {
                    return roleToken;
                }
            }

            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
        
        // need to add the token to our cache. If our principal was
        // updated then we need to retrieve a new cache key
        
        if (!cacheDisabled) {
            if (cacheKey == null) {
                cacheKey = getRoleTokenCacheKey(domainName, roleNames, proxyForPrincipal);
            }
            if (cacheKey != null) {
                ROLE_TOKEN_CACHE.put(cacheKey, roleToken);
            }
        }
        return roleToken;
    }

    /**
     * For the specified requester(user/service) return the corresponding Access Token that
     * includes the list of roles that the principal has access to in the specified domain
     * @param domainName name of the domain
     * @param roleNames (optional) only interested in roles with these names, comma separated list of roles
     * @param expiryTime (optional) specifies that the returned Access must be
     *          at least valid for specified number of seconds. Pass 0 to use
     *          server default timeout.
     * @return ZTS generated Access Token Response object. ZTSClientException will be thrown in case of failure
     */
    public AccessTokenResponse getAccessToken(String domainName, List<String> roleNames, long expiryTime) {
        return getAccessToken(domainName, roleNames, null, null, null, null, expiryTime, false);
    }

    /**
     * For the specified requester(user/service) return the corresponding Access Token that
     * includes the given role with specified authorization details included as claims.
     * The principal must have access to the role in the specified domain, and the domain
     * administrator must have configured the request authorization details type and fields
     * for the requested role.
     * @param domainName name of the domain
     * @param roleName name of the role
     * @param authorizationDetails additional authorization details to be added as a claim in the access token
     * @param expiryTime (optional) specifies that the returned Access must be
     *          at least valid for specified number of seconds. Pass 0 to use
     *          server default timeout.
     * @return ZTS generated Access Token Response object. ZTSClientException will be thrown in case of failure
     */
    public AccessTokenResponse getAccessToken(String domainName, String roleName, String authorizationDetails, long expiryTime) {
        return getAccessToken(domainName, Collections.singletonList(roleName), null, null,
                authorizationDetails, null, expiryTime, false);
    }

    /**
     * For the specified requester(user/service) return the corresponding Access Token that
     * includes the list of roles that the principal has access to in the specified domain
     * @param domainName name of the domain
     * @param roleNames (optional) only interested in roles with these names, comma separated list of roles
     * @param idTokenServiceName (optional) as part of the response return an id token whose audience
     *          is the specified service (only service name e.g. api) in the
     *          domainName domain.
     * @param expiryTime (optional) specifies that the returned Access must be
     *          at least valid for specified number of seconds. Pass 0 to use
     *          server default timeout.
     * @param ignoreCache ignore the cache and retrieve the token from ZTS Server
     * @return ZTS generated Access Token Response object. ZTSClientException will be thrown in case of failure
     */
    public AccessTokenResponse getAccessToken(String domainName, List<String> roleNames,
            String idTokenServiceName, long expiryTime, boolean ignoreCache) {
        return getAccessToken(domainName, roleNames, idTokenServiceName, null, null, null, expiryTime, ignoreCache);
    }

    /**
     * For the specified requester(user/service) return the corresponding Access Token that
     * includes the list of roles that the principal has access to in the specified domain
     * @param domainName name of the domain
     * @param roleNames (optional) only interested in roles with these names, comma separated list of roles
     * @param idTokenServiceName (optional) as part of the response return an id token whose audience
     *          is the specified service (only service name e.g. api) in the
     *          domainName domain.
     * @param proxyForPrincipal (optional) this request is proxy for this principal
     * @param authorizationDetails (optional) rich authorization request details
     * @param expiryTime (optional) specifies that the returned Access must be
     *          at least valid for specified number of seconds. Pass 0 to use
     *          server default timeout.
     * @param ignoreCache ignore the cache and retrieve the token from ZTS Server
     * @return ZTS generated Access Token Response object. ZTSClientException will be thrown in case of failure
     */
    public AccessTokenResponse getAccessToken(String domainName, List<String> roleNames, String idTokenServiceName,
            String proxyForPrincipal, String authorizationDetails, long expiryTime, boolean ignoreCache) {
        return getAccessToken(domainName, roleNames, idTokenServiceName, proxyForPrincipal, authorizationDetails,
                null, expiryTime, ignoreCache);
    }

    /**
     * For the specified requester(user/service) return the corresponding Access Token that
     * includes the list of roles that the principal has access to in the specified domain
     * @param domainName name of the domain
     * @param roleNames (optional) only interested in roles with these names, comma separated list of roles
     * @param idTokenServiceName (optional) as part of the response return an id token whose audience
     *          is the specified service (only service name e.g. api) in the
     *          domainName domain.
     * @param proxyForPrincipal (optional) this request is proxy for this principal
     * @param authorizationDetails (optional) rich authorization request details
     * @param proxyPrincipalSpiffeUris (optional) comma separated list of spiffe uris of proxy
     *          principals that this token will be routed through
     * @param expiryTime (optional) specifies that the returned Access must be
     *          at least valid for specified number of seconds. Pass 0 to use
     *          server default timeout.
     * @param ignoreCache ignore the cache and retrieve the token from ZTS Server
     * @return ZTS generated Access Token Response object. ZTSClientException will be thrown in case of failure
     */
    public AccessTokenResponse getAccessToken(String domainName, List<String> roleNames, String idTokenServiceName,
            String proxyForPrincipal, String authorizationDetails, String proxyPrincipalSpiffeUris, long expiryTime,
            boolean ignoreCache) {

        AccessTokenResponse accessTokenResponse = null;

        // first lookup in our cache to see if it can be satisfied
        // only if we're not asked to ignore the cache

        String cacheKey = null;
        if (!cacheDisabled) {
            cacheKey = getAccessTokenCacheKey(domainName, roleNames, idTokenServiceName,
                    proxyForPrincipal, authorizationDetails, proxyPrincipalSpiffeUris);
            if (cacheKey != null && !ignoreCache) {
                accessTokenResponse = lookupAccessTokenResponseInCache(cacheKey, expiryTime);
                if (accessTokenResponse != null) {
                    return accessTokenResponse;
                }
                // start prefetch for this token if prefetch is enabled
                if (enablePrefetch && prefetchAutoEnable) {
                    if (prefetchAccessToken(domainName, roleNames, idTokenServiceName,
                            proxyForPrincipal, authorizationDetails, proxyPrincipalSpiffeUris, expiryTime)) {
                        accessTokenResponse = lookupAccessTokenResponseInCache(cacheKey, expiryTime);
                    }
                    if (accessTokenResponse != null) {
                        return accessTokenResponse;
                    }
                    LOG.error("GetAccessToken: cache prefetch and lookup error");
                }
            }
        }

        // if no hit then we need to look up in disk
        try {
            accessTokenResponse = ztsAccessTokenFileLoader.lookupAccessTokenFromDisk(domainName, roleNames);
        } catch (IOException ex) {
            LOG.error("GetAccessToken: failed to load access token from disk {}", ex.getMessage());
        }

        // if no hit then we need to request a new token from ZTS

        if (accessTokenResponse == null) {
            updateServicePrincipal();
            try {
                final String requestBody = generateAccessTokenRequestBody(domainName, roleNames,
                        idTokenServiceName, proxyForPrincipal, authorizationDetails,
                        proxyPrincipalSpiffeUris, expiryTime);
                accessTokenResponse = ztsClient.postAccessTokenRequest(requestBody);
            } catch (ResourceException ex) {
                if (cacheKey != null && !ignoreCache) {
                    accessTokenResponse = lookupAccessTokenResponseInCache(cacheKey, -1);
                    if (accessTokenResponse != null) {
                        return accessTokenResponse;
                    }
                }
                throw new ZTSClientException(ex.getCode(), ex.getData());
            } catch (Exception ex) {
                if (cacheKey != null && !ignoreCache) {
                    accessTokenResponse = lookupAccessTokenResponseInCache(cacheKey, -1);
                    if (accessTokenResponse != null) {
                        return accessTokenResponse;
                    }
                }
                throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
            }
        }


        // need to add the token to our cache. If our principal was
        // updated then we need to retrieve a new cache key

        if (!cacheDisabled) {
            if (cacheKey == null) {
                cacheKey = getAccessTokenCacheKey(domainName, roleNames, idTokenServiceName,
                        proxyForPrincipal, authorizationDetails, proxyPrincipalSpiffeUris);
            }
            if (cacheKey != null) {
                ACCESS_TOKEN_CACHE.put(cacheKey, new AccessTokenResponseCacheEntry(accessTokenResponse));
            }
        }

        return accessTokenResponse;
    }

    String generateAccessTokenRequestBody(String domainName, List<String> roleNames, String idTokenServiceName,
            String proxyForPrincipal, String authorizationDetails, String proxyPrincipalSpiffeUris,
            long expiryTime) throws UnsupportedEncodingException {

        StringBuilder body = new StringBuilder(256);
        body.append("grant_type=client_credentials");
        if (expiryTime > 0) {
            body.append("&expires_in=").append(expiryTime);
        }

        StringBuilder scope = new StringBuilder(256);
        if (isEmpty(roleNames)) {
            scope.append(domainName).append(":domain");
        } else {
            for (String role : roleNames) {
                if (scope.length() != 0) {
                    scope.append(' ');
                }
                scope.append(domainName).append(AuthorityConsts.ROLE_SEP).append(role);
            }
        }
        if (!isEmpty(idTokenServiceName)) {
            scope.append(" openid ").append(domainName).append(":service.").append(idTokenServiceName);
        }
        final String scopeStr = scope.toString();
        body.append("&scope=").append(URLEncoder.encode(scopeStr, StandardCharsets.UTF_8));

        if (!isEmpty(proxyForPrincipal)) {
            body.append("&proxy_for_principal=").append(URLEncoder.encode(proxyForPrincipal, StandardCharsets.UTF_8));
        }

        if (!isEmpty(authorizationDetails)) {
            body.append("&authorization_details=").append(URLEncoder.encode(authorizationDetails, StandardCharsets.UTF_8));
        }

        if (!isEmpty(proxyPrincipalSpiffeUris)) {
            body.append("&proxy_principal_spiffe_uris=").append(URLEncoder.encode(proxyPrincipalSpiffeUris, StandardCharsets.UTF_8));
        }

        return body.toString();
    }

    /**
     * For the specified requester(user/service) return the corresponding Role Certificate
     * @param domainName name of the domain
     * @param roleName name of the role
     * @param req Role Certificate Request (csr)
     * @return RoleToken that includes client x509 role certificate
     */
    @Deprecated
    public RoleToken postRoleCertificateRequest(String domainName, String roleName,
            RoleCertificateRequest req) {
        
        updateServicePrincipal();
        try {
            return ztsClient.postRoleCertificateRequest(domainName, roleName, req);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getMessage());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * For the specified requester(user/service) return the corresponding Role Certificate
     * @param req Role Certificate Request (csr)
     * @return RoleCertificate that includes client x509 role certificate
     */
    public RoleCertificate postRoleCertificateRequest(RoleCertificateRequest req) {

        updateServicePrincipal();
        try {
            return ztsClient.postRoleCertificateRequestExt(req);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getMessage());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Generate a Role Certificate request that could be sent to ZTS
     * to obtain a X509 Certificate for the requested role.
     * @param principalDomain name of the principal's domain
     * @param principalService name of the principal's service
     * @param roleDomainName name of the domain where role is defined
     * @param roleName name of the role to get a certificate request for
     * @param privateKey private key for the service identity for the caller
     * @param csrDn string identifying the dn for the csr without the cn component
     * @param csrDomain string identifying the dns domain for generating SAN fields
     * @param expiryTime number of minutes to request certificate to be valid for
     * @return RoleCertificateRequest object
     */
    public static RoleCertificateRequest generateRoleCertificateRequest(final String principalDomain,
            final String principalService, final String roleDomainName, final String roleName,
            PrivateKey privateKey, final String csrDn, final String csrDomain, int expiryTime) {
        
        if (principalDomain == null || principalService == null) {
            throw new IllegalArgumentException("Principal's Domain and Service must be specified");
        }
        
        if (roleDomainName == null || roleName == null) {
            throw new IllegalArgumentException("Role DomainName and Name must be specified");
        }
        
        if (csrDomain == null) {
            throw new IllegalArgumentException("X509 CSR Domain must be specified");
        }
        
        // Athenz uses lower case for all elements, so let's
        // generate our dn which will be our role resource value
        
        final String domain = principalDomain.toLowerCase();
        final String service = principalService.toLowerCase();
        final String rnDomain = roleDomainName.toLowerCase();
        final String rnName = roleName.toLowerCase();
        
        String dn = "cn=" + rnDomain + AuthorityConsts.ROLE_SEP + rnName;
        if (csrDn != null) {
            dn = dn.concat(",").concat(csrDn);
        }
        
        // now let's generate our dsnName and email fields which will based on
        // our principal's details

        final String hostName = service + '.' + domain.replace('.', '-') + '.' + csrDomain;
        final String email = domain + "." + service + "@" + csrDomain;
        
        GeneralName[] sanArray = new GeneralName[4];
        sanArray[0] = new GeneralName(GeneralName.dNSName, new DERIA5String(hostName));
        sanArray[1] = new GeneralName(GeneralName.rfc822Name, new DERIA5String(email));

        final String spiffeUri = SPIFFE_URI + rnDomain + SPIFFE_COMP_ROLE + rnName;
        sanArray[2] = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(spiffeUri));

        final String principalUri = AuthorityConsts.ZTS_CERT_PRINCIPAL_URI + domain + "." + service;
        sanArray[3] = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(principalUri));

        String csr;
        try {
            csr = Crypto.generateX509CSR(privateKey, dn, sanArray);
        } catch (OperatorCreationException | IOException | NoSuchAlgorithmException ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }

        return new RoleCertificateRequest().setCsr(csr).setExpiryTime(expiryTime);
    }
    
    /**
     * Generate a Role Certificate request that could be sent to ZTS
     * to obtain a X509 Certificate for the requested role.
     * @param principalDomain name of the principal's domain
     * @param principalService name of the principal's service
     * @param roleDomainName name of the domain where role is defined
     * @param roleName name of the role to get a certificate request for
     * @param privateKey private key for the service identity for the caller
     * @param cloud string identifying the environment, e.g. aws
     * @param expiryTime number of minutes to request certificate to be valid for
     * @return RoleCertificateRequest object
     */
    public static RoleCertificateRequest generateRoleCertificateRequest(final String principalDomain,
            final String principalService, final String roleDomainName, final String roleName,
            final PrivateKey privateKey, final String cloud, int expiryTime) {
        
        if (cloud == null) {
            throw new IllegalArgumentException("Cloud Environment must be specified");
        }
        
        String csrDomain;
        if (x509CsrDomain != null) {
            csrDomain = cloud + "." + x509CsrDomain;
        } else {
            csrDomain = cloud;
        }

        return generateRoleCertificateRequest(principalDomain, principalService,
                roleDomainName, roleName, privateKey, x509CsrDn, csrDomain,
                expiryTime);
    }
    
    /**
     * Generate an Instance Refresh request that could be sent to ZTS to
     * request a TLS certificate for a service.
     * @param principalDomain name of the principal's domain
     * @param principalService name of the principal's service
     * @param privateKey private key for the service identity for the caller
     * @param csrDn string identifying the dn for the csr without the cn component
     * @param csrDomain string identifying the dns domain for generating SAN fields
     * @param expiryTime number of seconds to request certificate to be valid for
     * @return InstanceRefreshRequest object
     */
    public static InstanceRefreshRequest generateInstanceRefreshRequest(final String principalDomain,
            final String principalService, PrivateKey privateKey, final String csrDn,
            final String csrDomain, int expiryTime) {
        
        if (principalDomain == null || principalService == null) {
            throw new IllegalArgumentException("Principal's Domain and Service must be specified");
        }
        
        if (csrDomain == null) {
            throw new IllegalArgumentException("X509 CSR Domain must be specified");
        }
        
        // Athenz uses lower case for all elements, so let's
        // generate our dn which will be based on our service name
        
        final String domain = principalDomain.toLowerCase();
        final String service = principalService.toLowerCase();
        final String cn = domain + "." + service;
        
        String dn = "cn=" + cn;
        if (csrDn != null) {
            dn = dn.concat(",").concat(csrDn);
        }
        
        // now let's generate our dsnName field based on our principal's details

        GeneralName[] sanArray = new GeneralName[2];

        final String hostName = service + '.' + domain.replace('.', '-') + '.' + csrDomain;
        sanArray[0] = new GeneralName(GeneralName.dNSName, new DERIA5String(hostName));

        final String spiffeUri = SPIFFE_URI + domain + SPIFFE_COMP_SERVICE + service;
        sanArray[1] = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(spiffeUri));

        String csr;
        try {
            csr = Crypto.generateX509CSR(privateKey, dn, sanArray);
        } catch (OperatorCreationException | IOException | NoSuchAlgorithmException ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }

        return new InstanceRefreshRequest().setCsr(csr).setExpiryTime(expiryTime);
    }
    
    /**
     * Generate an Instance Refresh request that could be sent to ZTS to
     * request a TLS certificate for a service.
     * @param principalDomain name of the principal's domain
     * @param principalService name of the principal's service
     * @param privateKey private key for the service identity for the caller
     * @param cloud string identifying the environment, e.g. aws
     * @param expiryTime number of seconds to request certificate to be valid for
     * @return InstanceRefreshRequest object
     */
    public static InstanceRefreshRequest generateInstanceRefreshRequest(String principalDomain,
            String principalService, PrivateKey privateKey, String cloud, int expiryTime) {
        
        if (cloud == null) {
            throw new IllegalArgumentException("Cloud Environment must be specified");
        }
        
        String csrDomain;
        if (x509CsrDomain != null) {
            csrDomain = cloud + "." + x509CsrDomain;
        } else {
            csrDomain = cloud;
        }
        
        return generateInstanceRefreshRequest(principalDomain, principalService, privateKey,
                x509CsrDn, csrDomain, expiryTime);
    }
    
    static class TokenPrefetchTask extends TimerTask {
        
        ZTSClient getZTSClient(PrefetchTokenScheduledItem item) {
            
            ZTSClient client;
            if (item.sslContext != null) {
                client = new ZTSClient(item.providedZTSUrl, item.proxyUrl, item.sslContext);
            } else {
                client = new ZTSClient(item.providedZTSUrl, item.proxyUrl, item.identityDomain,
                        item.identityName, item.siaProvider);
            }
            return client;
        }

        boolean shouldRefresh(TokenType tokenType, long currentTime, long lastFetchTime,
                long lastFailTime, long expiryTime) {

            // if the ssl context has been modified since the fetch time
            // we are going to refresh all access tokens since they are cert bound

            if (tokenType == TokenType.ACCESS && lastFetchTime < KEY_REFRESHER_LISTENER.getLastCertRefreshTime()) {
                return true;
            }

            // if we are still halfway before the token expires then
            // there is no need to refresh it

            if ((expiryTime - lastFetchTime) / 2 + lastFetchTime > currentTime) {
                return false;
            }

            // if we have no failures then we haven't refreshed so
            // we should refresh it now

            if (lastFailTime == 0) {
                return true;
            }

            // otherwise we're going to do the same check to make sure
            // we're halfway since the last failed time, so we'll
            // progressively try to refresh frequently until we have
            // a successful response from ZTS Server

            return (expiryTime - lastFailTime) / 2 + lastFailTime <= currentTime;
        }

        @Override
        public void run() {

            long currentTime = System.currentTimeMillis() / 1000;
            FETCHER_LAST_RUN_AT.set(currentTime);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("PrefetchTask: Fetching tokens from the scheduled queue. Size={}",
                        PREFETCH_SCHEDULED_ITEMS.size());
            }
            if (PREFETCH_SCHEDULED_ITEMS.isEmpty()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("PrefetchTask: No items to fetch. Queue is empty");
                }
                return;
            }
            
            List<PrefetchTokenScheduledItem> toFetch = new ArrayList<>();

            // if this item is to be fetched now, add it to collection
            // special handling for service tokens so we'll keep track
            // of if we have any expired service tokens

            boolean svcTokenRefresh = false;
            for (PrefetchTokenScheduledItem item : PREFETCH_SCHEDULED_ITEMS) {

                // see if item requires refresh

                if (LOG.isDebugEnabled()) {
                    final String itemName = item.sslContext == null ?
                            item.identityDomain + "." + item.identityName : item.sslContext.toString();
                    LOG.debug("PrefetchTask: item={} type={} domain={} roleName={} fetch/fail/expire times {}/{}/{}",
                            itemName, item.tokenType, item.domainName, item.roleName, item.fetchTime,
                            item.lastFailTime, item.expiresAtUTC);
                }
                if (shouldRefresh(item.tokenType, currentTime, item.fetchTime, item.lastFailTime, item.expiresAtUTC)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("PrefetchTask: domain={} roleName={}. Refresh this item.",
                                item.domainName, item.roleName);
                    }
                    toFetch.add(item);
                    if (item.tokenType == TokenType.SVC_ROLE) {
                        svcTokenRefresh = true;
                    }
                }
            }
            
            // if toFetch is not empty, fetch those tokens, and add refreshed
            // scheduled items back to the queue
            
            if (toFetch.isEmpty()) {
                return;
            }

            // if we have any service tokens then we need to fetch
            // the new set from the provider

            Set<String> svcLoaderCache = null;
            if (svcTokenRefresh) {
                try {
                    svcLoaderCache = loadSvcProviderTokens();
                } catch (Exception ex) {
                    LOG.error("Unable to load service provider tokens", ex);
                }
            }

            // fetch items

            for (PrefetchTokenScheduledItem item : toFetch) {

                // create ZTS Client for this particular item

                try (ZTSClient itemZtsClient = getZTSClient(item)) {
                    processPrefetchTask(item, itemZtsClient, svcLoaderCache, currentTime);
                }
            }

            // clean our temporary list

            toFetch.clear();
        }
    }

    static void processPrefetchTask(PrefetchTokenScheduledItem item, ZTSClient itemZtsClient,
            Set<String> svcLoaderCache, long currentTime) {

        // use the zts client if one was given however we need
        // reset back to the original client so we don't close
        // our given client

        ZTSRDLGeneratedClient savedZtsClient = itemZtsClient.ztsClient;
        if (item.ztsClient != null) {
            itemZtsClient.ztsClient = item.ztsClient;
        }

        try {
            switch (item.tokenType) {

                case ROLE:

                    RoleToken token = itemZtsClient.getRoleToken(item.domainName, item.roleName,
                            item.minDuration, item.maxDuration, true, item.proxyForPrincipal);

                    // update the expiry time

                    item.setExpiresAtUTC(token.getExpiryTime());
                    break;

                case ACCESS:

                    AccessTokenResponse response = itemZtsClient.getAccessToken(item.domainName, item.roleNames,
                            item.idTokenServiceName, item.proxyForPrincipal, item.authorizationDetails, item.maxDuration, true);

                    // update the expiry time

                    item.setExpiresAtUTC(System.currentTimeMillis() / 1000 + response.getExpires_in());
                    break;

                case AWS:

                    AWSTemporaryCredentials awsCred = itemZtsClient.getAWSTemporaryCredentials(item.domainName,
                            item.roleName, item.externalId, item.minDuration, item.maxDuration, true);

                    // update the expiry time

                    item.setExpiresAtUTC(awsCred.getExpiration().millis() / 1000);
                    break;

                case SVC_ROLE:

                    // check if the key is in the new key set
                    // if not, mark the item as invalid and
                    // remove it from the fetch list

                    if (svcLoaderCache != null && !svcLoaderCache.contains(item.cacheKey)) {
                        item.setIsInvalid(true);
                        PREFETCH_SCHEDULED_ITEMS.remove(item);
                    }
                    break;

                case ID:

                    OIDCResponse oidcResponse = itemZtsClient.getIDToken(item.responseType, item.idTokenServiceName,
                            item.redirectUri, item.scope, item.state, item.keyType, item.fullArn,
                            item.maxDuration, true);

                    // update the expiry time

                    item.setExpiresAtUTC(oidcResponse.getExpiration_time());
            }

            // update the fetch/fail times

            item.setFetchTime(currentTime);
            item.setLastFailTime(0);

        } catch (ZTSClientException ex) {

            LOG.error("PrefetchTask: Error while trying to prefetch token", ex);

            // if we get either invalid credential, the request is forbidden,
            // or the request is invalid, then there is no point of retrying.
            // so, we'll mark the item as invalid otherwise we'll keep the item
            // in the queue and retry later

            int code = ex.getCode();
            if (code == ResourceException.UNAUTHORIZED || code == ResourceException.FORBIDDEN
                    || code == ResourceException.BAD_REQUEST) {

                // we need to mark it as invalid and then remove it from
                // our list so that we don't match other active requests
                // that might have been already added to the queue

                item.setIsInvalid(true);
                item.setLastFailTime(currentTime);
                PREFETCH_SCHEDULED_ITEMS.remove(item);
            } else {
                item.setLastFailTime(currentTime);
            }

        } catch (Exception ex) {

            // any other exception should remove this item from fetch queue
            // we need to mark it as invalid and then remove it from
            // our list so that we don't match other active requests
            // that might have been already added to the queue

            item.setLastFailTime(currentTime);
            item.setIsInvalid(true);
            PREFETCH_SCHEDULED_ITEMS.remove(item);
            LOG.error("PrefetchTask: Error while trying to prefetch token", ex);
        }

        if (item.shouldSendNotification()) {
            ZTSClientNotification ztsClientNotification = new ZTSClientNotification(
                    itemZtsClient.getZTSUrl(),
                    item.roleName,
                    item.tokenType.toString(),
                    item.expiresAtUTC,
                    item.isInvalid,
                    item.domainName);
            item.setLastNotificationTime(currentTime);
            item.notificationSender.sendNotification(ztsClientNotification);
        }

        // don't forget to restore the original client if case
        // we had overridden with the caller specified client

        itemZtsClient.ztsClient = savedZtsClient;
    }

    // method useful for test purposes only
    int getScheduledItemsSize() {
        return PREFETCH_SCHEDULED_ITEMS.size();
    }

    // method useful for test purposes only
    void clearScheduledItems() {
        PREFETCH_SCHEDULED_ITEMS.clear();
    }

    /**
     * Pre-fetches role tokens so that the client does not take the hit of
     * contacting ZTS Server for its first request (avg ~75ms). The client
     * library will automatically try to keep the cache up to date such
     * that the tokens are never expired and regular getRoleToken requests
     * are fulfilled from the cache instead of contacting ZTS Server.
     * @param domainName name of the domain
     * @param roleName (optional) only interested in roles with this name
     * @param minExpiryTime (optional) specifies that the returned RoleToken must be
     *          at least valid (min/lower bound) for specified number of seconds,
     * @param maxExpiryTime (optional) specifies that the returned RoleToken must be
     *          at most valid (max/upper bound) for specified number of seconds.
     * @return true if all is well, else false
     */
    boolean prefetchRoleToken(String domainName, String roleName,
            Integer minExpiryTime, Integer maxExpiryTime) {
        
        return prefetchRoleToken(domainName, roleName, minExpiryTime, maxExpiryTime, null);
    }
    
    /**
     * Pre-fetches role tokens so that the client does not take the hit of
     * contacting ZTS Server for its first request (avg ~75ms). The client
     * library will automatically try to keep the cache up to date such
     * that the tokens are never expired and regular getRoleToken requests
     * are fulfilled from the cache instead of contacting ZTS Server.
     * @param domainName name of the domain
     * @param roleName (optional) only interested in roles with this name
     * @param minExpiryTime (optional) specifies that the returned RoleToken must be
     *          at least valid (min/lower bound) for specified number of seconds,
     * @param maxExpiryTime (optional) specifies that the returned RoleToken must be
     *          at most valid (max/upper bound) for specified number of seconds.
     * @param proxyForPrincipal (optional) request is proxy for this principal
     * @return true if all is well, else false
     */
    boolean prefetchRoleToken(String domainName, String roleName,
            Integer minExpiryTime, Integer maxExpiryTime, String proxyForPrincipal) {
        
        if (domainName == null || domainName.trim().isEmpty()) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, "Domain Name cannot be empty");
        }
        
        RoleToken token = getRoleToken(domainName, roleName, minExpiryTime, maxExpiryTime,
                true, proxyForPrincipal);
        if (token == null) {
            LOG.error("PrefetchToken: No token fetchable using domain={}, roleSuffix={}",
                        domainName, roleName);
            return false;
        }
        long expiryTimeUTC = token.getExpiryTime();
        
        return prefetchToken(domainName, roleName, null, minExpiryTime, maxExpiryTime,
                proxyForPrincipal, null, null, null, null, null, null, null, null,
                null, expiryTimeUTC, TokenType.ROLE);
    }
    
    boolean prefetchAwsCreds(String domainName, String roleName, String externalId,
            Integer minExpiryTime, Integer maxExpiryTime) {
        
        if (domainName == null || domainName.trim().isEmpty()) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, "Domain Name cannot be empty");
        }

        AWSTemporaryCredentials awsCred = getAWSTemporaryCredentials(domainName, roleName,
                externalId, minExpiryTime, maxExpiryTime, true);
        if (awsCred == null) {
            LOG.error("PrefetchToken: No aws credential fetchable using domain={}, roleName={}",
                        domainName, roleName);
            return false;
        }
        long expiryTimeUTC = awsCred.getExpiration().millis() / 1000;

        return prefetchToken(domainName, roleName, null, minExpiryTime, maxExpiryTime, null,
                externalId, null, null, null, null, null, null, null, null,
                expiryTimeUTC, TokenType.AWS);
    }

    public boolean prefetchAccessToken(String domainName, List<String> roleNames,
            String idTokenServiceName, String proxyForPrincipal, String authorizationDetails,
            String proxyPrincipalSpiffeUris, long expiryTime) {

        if (domainName == null || domainName.trim().isEmpty()) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, "Domain Name cannot be empty");
        }

        AccessTokenResponse tokenResponse = getAccessToken(domainName, roleNames, idTokenServiceName,
                proxyForPrincipal, authorizationDetails, proxyPrincipalSpiffeUris, expiryTime, true);
        if (tokenResponse == null) {
            LOG.error("PrefetchToken: No access token fetchable using domain={}", domainName);
            return false;
        }
        long expiryTimeUTC = System.currentTimeMillis() / 1000 + tokenResponse.getExpires_in();

        return prefetchToken(domainName, null, roleNames, null, (int) expiryTime,
                proxyForPrincipal, null, idTokenServiceName, authorizationDetails,
                null, null, null, null, null, null, expiryTimeUTC, TokenType.ACCESS);
    }

    public boolean prefetchIdToken(String responseType, String clientId, String redirectUri, String scope,
            String state, String keyType, Boolean fullArn, Integer expiryTime) {

        OIDCResponse oidcResponse = getIDToken(responseType, clientId, redirectUri, scope, state,
                keyType, fullArn, expiryTime, true);
        if (oidcResponse == null) {
            LOG.error("PrefetchToken: No id token fetchable for client id={} and scope={}", clientId, scope);
            return false;
        }

        return prefetchToken(null, null, null, null, expiryTime, null, null, clientId, null,
                responseType, redirectUri, scope, state, keyType, fullArn,
                oidcResponse.getExpiration_time(), TokenType.ID);
    }

    boolean prefetchToken(String domainName, String roleName, List<String> roleNames,
            Integer minExpiryTime, Integer maxExpiryTime, String proxyForPrincipal,
            String externalId, String idTokenServiceName, String authorizationDetails,
            String responseType, String redirectUri, String scope, String state,
            String keyType, Boolean fullArn, long expiryTimeUTC, TokenType tokenType) {
        
        // if we're given a ssl context then we don't have domain/service
        // settings configured otherwise those are required
        
        if (sslContext == null) {
            if (isEmpty(domain) || isEmpty(service)) {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("PrefetchToken: setup failure. Both domain({}) and service({}) are required",
                            domain, service);
                }
                return false;
            }
        }

        PrefetchTokenScheduledItem item = new PrefetchTokenScheduledItem()
                .setTokenType(tokenType)
                .setFetchTime(System.currentTimeMillis() / 1000)
                .setDomainName(domainName)
                .setRoleName(roleName)
                .setRoleNames(roleNames)
                .setProxyForPrincipal(proxyForPrincipal)
                .setExternalId(externalId)
                .setMinDuration(minExpiryTime)
                .setMaxDuration(maxExpiryTime)
                .setExpiresAtUTC(expiryTimeUTC)
                .setIdTokenServiceName(idTokenServiceName)
                .setAuthorizationDetails(authorizationDetails)
                .setIdentityDomain(domain)
                .setIdentityName(service)
                .setTokenMinExpiryTime(ZTSClient.tokenMinExpiryTime)
                .setProvidedZTSUrl(this.ztsUrl)
                .setSiaIdentityProvider(siaProvider)
                .setSslContext(sslContext)
                .setProxyUrl(proxyUrl)
                .setKeyType(keyType)
                .setResponseType(responseType)
                .setRedirectUri(redirectUri)
                .setScope(scope)
                .setState(state)
                .setFullArn(fullArn)
                .setNotificationSender(notificationSender);
        
        // include our zts client only if it was overridden by
        // the caller (most likely for unit test mock)
        
        if (ztsClientOverride) {
             item.setZtsClient(this.ztsClient);
        }

        // we need to make sure we don't have duplicates in
        // our prefetch list so since we got a brand-new
        // token now we're going to remove any others we have
        // in the list and add this one. Our item's equals
        // method defines what attributes we're looking for
        // when comparing two items.

        PREFETCH_SCHEDULED_ITEMS.remove(item);
        PREFETCH_SCHEDULED_ITEMS.add(item);

        startPrefetch();
        return true;
    }

    String getAccessTokenCacheKey(String domainName, List<String> roleNames, String idTokenServiceName,
            String proxyForPrincipal, String authorizationDetails, String proxyPrincipalSpiffeUris) {

        // if we don't have a tenant domain specified but we have a ssl context
        // then we're going to use the hash code for our sslcontext as the
        // value for our tenant

        String tenantDomain = domain;
        if (domain == null && sslContext != null) {
            tenantDomain = sslContext.toString();
        }
        return getAccessTokenCacheKey(tenantDomain, service, domainName, roleNames,
                idTokenServiceName, proxyForPrincipal, authorizationDetails, proxyPrincipalSpiffeUris);
    }

    static String getAccessTokenCacheKey(String tenantDomain, String tenantService, String domainName,
            List<String> roleNames, String idTokenServiceName, String proxyForPrincipal,
            String authorizationDetails, String proxyPrincipalSpiffeUris) {

        // before we generate a cache key we need to have a valid domain

        if (tenantDomain == null) {
            return null;
        }

        StringBuilder cacheKey = new StringBuilder(256);
        cacheKey.append("p=");
        cacheKey.append(tenantDomain);
        if (tenantService != null) {
            cacheKey.append(".").append(tenantService);
        }

        cacheKey.append(";d=");
        cacheKey.append(domainName);

        if (!isEmpty(roleNames)) {
            cacheKey.append(";r=");
            cacheKey.append(ZTSClient.multipleRoleKey(roleNames));
        }

        if (!isEmpty(idTokenServiceName)) {
            cacheKey.append(";o=");
            cacheKey.append(idTokenServiceName);
        }

        if (!isEmpty(proxyForPrincipal)) {
            cacheKey.append(";u=");
            cacheKey.append(proxyForPrincipal);
        }

        if (!isEmpty(authorizationDetails)) {
            cacheKey.append(";z=");
            cacheKey.append(Base64.getUrlEncoder().withoutPadding().encodeToString(Crypto.sha256(authorizationDetails)));
        }

        if (!isEmpty(proxyPrincipalSpiffeUris)) {
            cacheKey.append(";s=");
            cacheKey.append(proxyPrincipalSpiffeUris);
        }

        return cacheKey.toString();
    }

    String getRoleTokenCacheKey(String domainName, String roleName, String proxyForPrincipal) {

        // if we don't have a tenant domain specified but we have a ssl context
        // then we're going to use the hash code for our sslcontext as the
        // value for our tenant
        
        String tenantDomain = domain;
        if (domain == null && sslContext != null) {
            tenantDomain = sslContext.toString();
        }
        return getRoleTokenCacheKey(tenantDomain, service, domainName, roleName, proxyForPrincipal);
    }
    
    static String getRoleTokenCacheKey(String tenantDomain, String tenantService, String domainName,
            String roleName, String proxyForPrincipal) {

        // before we generate a cache key we need to have a valid domain

        if (tenantDomain == null) {
            return null;
        }
        
        StringBuilder cacheKey = new StringBuilder(256);
        cacheKey.append("p=");
        cacheKey.append(tenantDomain);
        if (tenantService != null) {
            cacheKey.append(".").append(tenantService);
        }

        cacheKey.append(";d=");
        cacheKey.append(domainName);

        if (!isEmpty(roleName)) {
            cacheKey.append(";r=");
            
            // check to see if we have multiple roles in the values
            // in which case we need to sort the values
            
            if (roleName.indexOf(',') == -1) {
                cacheKey.append(roleName);
            } else {
                List<String> roles = Arrays.asList(roleName.split(","));
                cacheKey.append(ZTSClient.multipleRoleKey(roles));
            }
        }
        
        if (!isEmpty(proxyForPrincipal)) {
            cacheKey.append(";u=");
            cacheKey.append(proxyForPrincipal);
        }
        
        return cacheKey.toString();
    }

    String getIdTokenCacheKey(String responseType, String clientId, String redirectUri, String scope,
            String state, String keyType, Boolean fullArn) {

        if (responseType == null || clientId == null || scope == null || redirectUri == null) {
            return null;
        }

        StringBuilder cacheKey = new StringBuilder(256);
        cacheKey.append("t=");
        cacheKey.append(responseType);

        cacheKey.append(";c=");
        cacheKey.append(clientId);

        cacheKey.append(";s=");
        cacheKey.append(scope);

        cacheKey.append(";r=");
        cacheKey.append(redirectUri);

        if (!isEmpty(state)) {
            cacheKey.append(";a=");
            cacheKey.append(state);
        }

        if (!isEmpty(keyType)) {
            cacheKey.append(";k=");
            cacheKey.append(keyType);
        }

        if (fullArn != null) {
            cacheKey.append(";f=");
            cacheKey.append(fullArn);
        }

        return cacheKey.toString();
    }

    static boolean isExpiredToken(long expiryTime, Integer minExpiryTime, Integer maxExpiryTime,
            int tokenMinExpiryTime) {

        // we'll first make sure if we're given both min and max expiry
        // times then both conditions are satisfied

        if (minExpiryTime != null && expiryTime < minExpiryTime) {
            return true;
        }

        // it's possible the time on the client side is not in sync
        // so we'll allow up to 5 minute offset

        if (maxExpiryTime != null && expiryTime > maxExpiryTime + tokenMaxExpiryOffset) {
            return true;
        }

        // if both limits were null then we need to make sure
        // that our token is valid for based on our min configured value

        return minExpiryTime == null && maxExpiryTime == null && expiryTime < tokenMinExpiryTime;
    }
    
    RoleToken lookupRoleTokenInCache(String cacheKey, Integer minExpiryTime, Integer maxExpiryTime, int serverMinExpiryTime) {

        RoleToken roleToken = ROLE_TOKEN_CACHE.get(cacheKey);
        if (roleToken == null) {
            if (LOG.isInfoEnabled()) {
                LOG.info("LookupRoleTokenInCache: cache-lookup key: {} result: not found", cacheKey);
            }
            return null;
        }
        
        // before returning our cache hit we need to make sure it
        // satisfies the time requirements as specified by the client
        
        long expiryTime = roleToken.getExpiryTime() - (System.currentTimeMillis() / 1000);
        
        if (isExpiredToken(expiryTime, minExpiryTime, maxExpiryTime, serverMinExpiryTime)) {
            
            if (LOG.isInfoEnabled()) {
                LOG.info("LookupRoleTokenInCache: role-cache-lookup key: {} token-expiry: {}"
                        + " req-min-expiry: {} req-max-expiry: {} client-min-expiry: {} result: expired",
                        cacheKey, expiryTime, minExpiryTime, maxExpiryTime, serverMinExpiryTime);
            }

            // if the token is completely expired then we'll remove it from the cache

            if (expiryTime < 1) {
                ROLE_TOKEN_CACHE.remove(cacheKey);
            }

            return null;
        }
        
        return roleToken;
    }

    AccessTokenResponse lookupAccessTokenResponseInCache(String cacheKey, long expiryTime) {

        AccessTokenResponseCacheEntry accessTokenResponseCacheEntry = ACCESS_TOKEN_CACHE.get(cacheKey);
        if (accessTokenResponseCacheEntry == null) {
            if (LOG.isInfoEnabled()) {
                LOG.info("LookupAccessTokenResponseInCache: cache-lookup key: {} result: not found", cacheKey);
            }
            return null;
        }

        // before returning our cache hit we need to make sure
        // it was at least 1/4th time left before the token expires
        // if the expiryTime is -1 then we return the token as
        // long as it's not expired

        if (accessTokenResponseCacheEntry.isExpired(expiryTime)) {
            if (accessTokenResponseCacheEntry.isExpired(-1)) {
                ACCESS_TOKEN_CACHE.remove(cacheKey);
            }
            return null;
        }

        return accessTokenResponseCacheEntry.accessTokenResponse();
    }

    AWSTemporaryCredentials lookupAwsCredInCache(String cacheKey, Integer minExpiryTime,
            Integer maxExpiryTime) {

        AWSTemporaryCredentials awsCred = AWS_CREDS_CACHE.get(cacheKey);
        if (awsCred == null) {
            if (LOG.isInfoEnabled()) {
                LOG.info("LookupAwsCredInCache: aws-cache-lookup key: {} result: not found", cacheKey);
            }
            return null;
        }
        
        // before returning our cache hit we need to make sure it
        // satisfies the time requirements as specified by the client
        
        long expiryTime = awsCred.getExpiration().millis() - System.currentTimeMillis();
        expiryTime /= 1000;  // expiry time is in seconds
        
        if (isExpiredToken(expiryTime, minExpiryTime, maxExpiryTime, tokenMinExpiryTime)) {
            
            if (LOG.isInfoEnabled()) {
                LOG.info("LookupAwsCredInCache: aws-cache-lookup key: {} token-expiry: {}"
                        + " req-min-expiry: {} req-max-expiry: {} client-min-expiry: {} result: expired",
                        cacheKey, expiryTime, minExpiryTime, maxExpiryTime, tokenMinExpiryTime);
            }

            // if the token is completely expired then we'll remove it from the cache

            if (expiryTime < 1) {
                AWS_CREDS_CACHE.remove(cacheKey);
            }
            return null;
        }
        
        return awsCred;
    }

    /**
     * Retrieve the list of roles that the given principal has access to in the domain
     * @param domainName name of the domain
     * @param principal name of the principal
     * @return RoleAccess object on success. ZTSClientException will be thrown in case of failure
     */
    public RoleAccess getRoleAccess(String domainName, String principal) {
        updateServicePrincipal();

        // Try to fetch from cache.
        ZTSClientCache.DomainAndPrincipal cacheKey = null;
        Cache<ZTSClientCache.DomainAndPrincipal, RoleAccess> cache = ztsClientCache.getRoleAccessCache();
        if (cache != null) {
            cacheKey = new ZTSClientCache.DomainAndPrincipal(domainName, principal);
            RoleAccess cachedValue = cache.get(cacheKey);
            if (cachedValue != null) {
                return cachedValue;
            }
        }

        try {
            RoleAccess roleAccess = ztsClient.getRoleAccess(domainName, principal);
            if (cache != null) {
                cache.put(cacheKey, roleAccess);
            }
            return roleAccess;
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getMessage());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Retrieve the specified service object from a domain
     * @param domainName name of the domain
     * @param serviceName name of the service to be retrieved
     * @return ServiceIdentity object on success. ZTSClientException will be thrown in case of failure
     */
    public ServiceIdentity getServiceIdentity(String domainName, String serviceName) {
        updateServicePrincipal();
        try {
            return ztsClient.getServiceIdentity(domainName, serviceName);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the specified public key from the given service object
     * @param domainName name of the domain
     * @param serviceName name of the service
     * @param keyId the identifier of the public key to be retrieved
     * @return PublicKeyEntry object or ZTSClientException will be thrown in case of failure
     */
    public PublicKeyEntry getPublicKeyEntry(String domainName, String serviceName, String keyId) {
        try {
            return ztsClient.getPublicKeyEntry(domainName, serviceName, keyId);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Retrieve the full list of services defined in a domain
     * @param domainName name of the domain
     * @return list of all service names on success. ZTSClientException will be thrown in case of failure
     */
    public ServiceIdentityList getServiceIdentityList(String domainName) {
        updateServicePrincipal();
        try {
            return ztsClient.getServiceIdentityList(domainName);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Fetch all roles that are tagged as requiring role certificates for principal
     * @param principal Name of the principal
     * @return list of roles that are tagged as requiring role certificates for the principal
     */
    public RoleAccess getRolesRequireRoleCert(String principal) {
        updateServicePrincipal();
        try {
            return ztsClient.getRolesRequireRoleCert(principal);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * For a given provider domain get a list of tenant domain names that the user is a member of
     * @param providerDomainName name of the provider domain
     * @param userName is the name of the user to search for in the tenant domains of the provider
     * @param roleName is the name of the role to filter on when searching through the list of tenants with
     *        the specified role name.
     * @param serviceName is the name of the service to filter on that the tenant has on-boarded to
     * @return TenantDomains object which contains a list of tenant domain names for a given provider 
     *         domain, that the user is a member of
     */
    public TenantDomains getTenantDomains(String providerDomainName, String userName,
            String roleName, String serviceName) {
        updateServicePrincipal();
        try {
            return ztsClient.getTenantDomains(providerDomainName, userName, roleName, serviceName);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Request by a service to refresh its NToken. The original NToken must have been
     * obtained by an authorized service by calling the postInstanceTenantRequest
     * method.
     * @param domain Name of the domain
     * @param service Name of the service
     * @param req InstanceRefreshRequest object for th request
     * @return Identity object that includes a refreshed NToken for the service
     */
    public Identity postInstanceRefreshRequest(String domain, String service, InstanceRefreshRequest req) {
        updateServicePrincipal();
        try {
            return ztsClient.postInstanceRefreshRequest(domain, service, req);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * For AWS Lambda functions generate a new private key, request an
     * x.509 certificate based on the requested CSR and return both to
     * the client in order to establish tls connections with other
     * Athenz enabled services.
     * @param domainName name of the domain
     * @param serviceName name of the service
     * @param account AWS account name that the function runs in
     * @param provider name of the provider service for AWS Lambda
     * @return AWSLambdaIdentity with private key and certificate
     */
    public AWSLambdaIdentity getAWSLambdaServiceCertificate(String domainName,
            String serviceName, String account, String provider) {
        
        if (domainName == null || serviceName == null) {
            throw new IllegalArgumentException("Domain and Service must be specified");
        }
        
        if (account == null || provider == null) {
            throw new IllegalArgumentException("AWS Account and Provider must be specified");
        }
        
        if (x509CsrDomain == null) {
            throw new IllegalArgumentException("X509 CSR Domain must be specified");
        }
        
        // first we're going to generate a private key for the request
        
        AWSLambdaIdentity lambdaIdentity = new AWSLambdaIdentity();
        try {
            lambdaIdentity.setPrivateKey(Crypto.generateRSAPrivateKey(2048));
        } catch (CryptoException ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }

        // we need to generate a csr with an instance register object
        
        InstanceRegisterInformation info = new InstanceRegisterInformation();
        info.setDomain(domainName.toLowerCase());
        info.setService(serviceName.toLowerCase());
        info.setProvider(provider.toLowerCase());

        final String athenzService = info.getDomain() + "." + info.getService();
        
        // generate our dn which will be based on our service name

        StringBuilder dnBuilder = new StringBuilder(128);
        dnBuilder.append("cn=");
        dnBuilder.append(athenzService);
        if (x509CsrDn != null) {
            dnBuilder.append(',');
            dnBuilder.append(x509CsrDn);
        }
        
        // now let's generate our dsnName field based on our principal's details

        GeneralName[] sanArray = new GeneralName[3];
        final String hostBuilder = info.getService() + '.' + info.getDomain().replace('.', '-') +
                '.' + x509CsrDomain;
        sanArray[0] = new GeneralName(GeneralName.dNSName, new DERIA5String(hostBuilder));

        final String instanceHostBuilder = "lambda-" + account + '-' + info.getService() +
                ".instanceid.athenz." + x509CsrDomain;
        sanArray[1] = new GeneralName(GeneralName.dNSName, new DERIA5String(instanceHostBuilder));

        final String spiffeUri = SPIFFE_URI + info.getDomain() + SPIFFE_COMP_SERVICE + info.getService();
        sanArray[2] = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(spiffeUri));

        // next generate the csr based on our private key and data
        
        try {
            info.setCsr(Crypto.generateX509CSR(lambdaIdentity.getPrivateKey(),
                    dnBuilder.toString(), sanArray));
        } catch (OperatorCreationException | IOException | NoSuchAlgorithmException ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
        
        // finally obtain attestation data for lambda
        
        info.setAttestationData(getAWSLambdaAttestationData(athenzService, account));
        
        // request the x.509 certificate from zts server
        
        Map<String, List<String>> responseHeaders = new HashMap<>();
        InstanceIdentity identity = postInstanceRegisterInformation(info, responseHeaders);
        
        try {
            lambdaIdentity.setX509Certificate(Crypto.loadX509Certificate(identity.getX509Certificate()));
        } catch (CryptoException ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }

        lambdaIdentity.setCaCertificates(identity.getX509CertificateSigner());
        return lambdaIdentity;
    }
    
    String getAWSLambdaAttestationData(final String athenzService, final String account) {
        
        AWSAttestationData data = new AWSAttestationData();
        data.setRole(athenzService);
        
        Credentials awsCreds = assumeAWSRole(account, athenzService);
        data.setAccess(awsCreds.accessKeyId());
        data.setSecret(awsCreds.secretAccessKey());
        data.setToken(awsCreds.sessionToken());
        
        ObjectMapper mapper = new ObjectMapper();
        String jsonData;
        try {
            jsonData = mapper.writeValueAsString(data);
        } catch (JsonProcessingException ex) {
            LOG.error("Unable to generate attestation json data: {}", ex.getMessage());
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
        
        return jsonData;
    }
    
    AssumeRoleRequest getAssumeRoleRequest(String account, String roleName) {
        
        // assume the target role to get the credentials for the client
        // aws format is arn:aws:iam::<account-id>:role/<role-name>
        
        final String arn = "arn:aws:iam::" + account + ":role/" + roleName;
        return AssumeRoleRequest.builder().roleSessionName(roleName).roleArn(arn).build();
    }
    
    Credentials assumeAWSRole(String account, String roleName) {
        
        try {
            AssumeRoleRequest req = getAssumeRoleRequest(account, roleName);
            return StsClient.builder().build().assumeRole(req).credentials();
        } catch (Exception ex) {
            LOG.error("assumeAWSRole - unable to assume role: {}", ex.getMessage());
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * AWSCredential Provider provides AWS Credentials which the caller can
     * use to authorize an AWS request. It automatically refreshes the credentials
     * when the current credentials become invalid.
     * It uses ZTS client to refresh the AWS Credentials. So the ZTS Client must
     * not be closed while the credential provider is being used.
     * The caller should close the client when the provider is no longer required.
     * For a given domain and role return AWS temporary credential provider
     * @param domainName name of the domain
     * @param roleName is the name of the role
     * @return AWSCredentialsProvider AWS credential provider
     */
    public AWSCredentialsProvider getAWSCredentialProvider(String domainName, String roleName) {
        return new AWSCredentialsProviderImpl(this, domainName, roleName);
    }

    /**
     * AWSCredential Provider provides AWS Credentials which the caller can
     * use to authorize an AWS request. It automatically refreshes the credentials
     * when the current credentials become invalid.
     * It uses ZTS client to refresh the AWS Credentials. So the ZTS Client must
     * not be closed while the credential provider is being used.
     * The caller should close the client when the provider is no longer required.
     * For a given domain and role return AWS temporary credential provider
     * @param domainName name of the domain
     * @param roleName is the name of the role
     * @param externalId (optional) external id to satisfy configured assume role condition
     * @param minExpiryTime (optional) specifies that the returned credentials must be
     *          at least valid (min/lower bound) for specified number of seconds,
     * @param maxExpiryTime (optional) specifies that the returned credentials must be
     *          at most valid (max/upper bound) for specified number of seconds.
     * @return AWSCredentialsProvider AWS credential provider
     */
    public AWSCredentialsProvider getAWSCredentialProvider(String domainName, String roleName,
            String externalId, Integer minExpiryTime, Integer maxExpiryTime) {
        return new AWSCredentialsProviderImpl(this, domainName, roleName, externalId,
                minExpiryTime, maxExpiryTime);
    }

    /**
     * AWSCredential Provider provides AWS Credentials which the caller can
     * use to authorize an AWS request. It automatically refreshes the credentials
     * when the current credentials become invalid.
     * It uses ZTS client to refresh the AWS Credentials. So the ZTS Client must
     * not be closed while the credential provider is being used.
     * The caller should close the client when the provider is no longer required.
     * For a given domain and role return AWS temporary credential provider
     * @param domainName name of the domain
     * @param roleName is the name of the role
     * @return AWSCredentialsProvider AWS credential provider
     */
    public AwsCredentialsProvider getAWSCredentialProviderV2(String domainName, String roleName) {
        return new AWSCredentialsProviderImplV2(this, domainName, roleName);
    }

    /**
     * AWSCredential Provider provides AWS Credentials which the caller can
     * use to authorize an AWS request. It automatically refreshes the credentials
     * when the current credentials become invalid.
     * It uses ZTS client to refresh the AWS Credentials. So the ZTS Client must
     * not be closed while the credential provider is being used.
     * The caller should close the client when the provider is no longer required.
     * For a given domain and role return AWS temporary credential provider
     * @param domainName name of the domain
     * @param roleName is the name of the role
     * @param externalId (optional) external id to satisfy configured assume role condition
     * @param expiryTime (optional) specifies that the returned credentials must be
     *          valid for specified number of seconds
     * @return AwsCredentialsProvider AWS credential provider
     */
    public AwsCredentialsProvider getAWSCredentialProviderV2(String domainName, String roleName,
            String externalId, Integer expiryTime) {
        Integer minExpiryTime = null;
        if (expiryTime != null) {
            if (expiryTime < tokenMinExpiryTime) {
                throw new IllegalArgumentException("Expiry Time must be higher than " + tokenMinExpiryTime);
            } else {
                minExpiryTime = tokenMinExpiryTime;
            }
        }
        return new AWSCredentialsProviderImplV2(this, domainName, roleName, externalId, minExpiryTime, expiryTime);
    }

    /**
     * For a given domain and role return AWS temporary credentials. If the token
     * is present in the local cache and not expired, it will be returned.
     *
     * @param domainName name of the domain
     * @param roleName is the name of the role
     * @return AWSTemporaryCredentials AWS credentials
     */
    public AWSTemporaryCredentials getAWSTemporaryCredentials(String domainName, String roleName) {
        return getAWSTemporaryCredentials(domainName, roleName, null, null, null, false);
    }

    /**
     * For a given domain and role return AWS temporary credentials. If ignoreCache
     * argument is true then the request will be carried against Athenz ZTS Server
     * and ignore any possibly valid credentials from the local cache.
     *
     * @param domainName name of the domain
     * @param roleName is the name of the role
     * @param ignoreCache whether or not ignore the cache for this request
     * @return AWSTemporaryCredentials AWS credentials
     */
    public AWSTemporaryCredentials getAWSTemporaryCredentials(String domainName, String roleName,
            boolean ignoreCache) {
        return getAWSTemporaryCredentials(domainName, roleName, null, null, null, ignoreCache);
    }

    /**
     * For a given domain and role return AWS temporary credentials. If the token
     * is present in the local cache and not expired, it will be returned.
     *
     * @param domainName name of the domain
     * @param roleName is the name of the role
     * @param minExpiryTime (optional) specifies that the returned credentials must be
     *          at least valid (min/lower bound) for specified number of seconds,
     * @param maxExpiryTime (optional) specifies that the returned credentials must be
     *          at most valid (max/upper bound) for specified number of seconds.
     * @param externalId (optional) external id to satisfy configured assume role condition
     * @return AWSTemporaryCredentials AWS credentials
     */
    public AWSTemporaryCredentials getAWSTemporaryCredentials(String domainName, String roleName,
            String externalId, Integer minExpiryTime, Integer maxExpiryTime) {
        return getAWSTemporaryCredentials(domainName, roleName, externalId,
                minExpiryTime, maxExpiryTime, false);
    }

    /**
     * For a given domain and role return AWS temporary credentials. If ignoreCache
     * argument is true then the request will be carried against Athenz ZTS Server
     * and ignore any possibly valid credentials from the local cache.
     *
     * @param domainName name of the domain
     * @param roleName is the name of the role
     * @param minExpiryTime (optional) specifies that the returned credentials must be
     *          at least valid (min/lower bound) for specified number of seconds,
     * @param maxExpiryTime (optional) specifies that the returned credentials must be
     *          at most valid (max/upper bound) for specified number of seconds.
     * @param externalId (optional) external id to satisfy configured assume role condition
     * @param ignoreCache whether or not ignore the cache for this request
     * @return AWSTemporaryCredentials AWS credentials
     */
    public AWSTemporaryCredentials getAWSTemporaryCredentials(String domainName, String roleName,
            String externalId, Integer minExpiryTime, Integer maxExpiryTime, boolean ignoreCache) {

        // first lookup in our cache to see if it can be satisfied
        // only if we're not asked to ignore the cache
        
        AWSTemporaryCredentials awsCred;
        String cacheKey = getRoleTokenCacheKey(domainName, roleName, null);
        if (cacheKey != null && !ignoreCache) {
            awsCred = lookupAwsCredInCache(cacheKey, minExpiryTime, maxExpiryTime);
            if (awsCred != null) {
                return awsCred;
            }

            // start prefetch for this token if prefetch is enabled

            if (enablePrefetch && prefetchAutoEnable) {
                if (prefetchAwsCreds(domainName, roleName, externalId, minExpiryTime, maxExpiryTime)) {
                    awsCred = lookupAwsCredInCache(cacheKey, minExpiryTime, maxExpiryTime);
                }
                if (awsCred != null) {
                    return awsCred;
                }
                LOG.error("GetAWSTemporaryCredentials: cache prefetch and lookup error");
            }
        }
        
        // if no hit then we need to request a new token from ZTS
        
        updateServicePrincipal();

        try {
            awsCred = ztsClient.getAWSTemporaryCredentials(domainName, encodeAWSRoleName(roleName),
                    maxExpiryTime, externalId);
        } catch (ResourceException ex) {

            // if we have an entry in our cache then we'll return that
            // instead of returning failure

            if (cacheKey != null && !ignoreCache) {
                awsCred = lookupAwsCredInCache(cacheKey, null, null);
                if (awsCred != null) {
                    return awsCred;
                }
            }

            throw new ZTSClientException(ex.getCode(), ex.getData());

        } catch (Exception ex) {

            // if we have an entry in our cache then we'll return that
            // instead of returning failure

            if (cacheKey != null && !ignoreCache) {
                awsCred = lookupAwsCredInCache(cacheKey, null, null);
                if (awsCred != null) {
                    return awsCred;
                }
            }

            LOG.error("Unable to get AWS Creds", ex);
            throw new ZTSClientException(getExceptionCode(ex), ex.getMessage());
        }
        
        // need to add the token to our cache. If our principal was
        // updated then we need to retrieve a new cache key

        if (awsCred != null) {
            if (cacheKey == null) {
                cacheKey = getRoleTokenCacheKey(domainName, roleName, null);
            }
            if (cacheKey != null) {
                AWS_CREDS_CACHE.put(cacheKey, awsCred);
            }
        }
        return awsCred;
    }

    int getExceptionCode(Exception ex) {
        // for any temporary with the network or dns, we'll return service
        // unavailable error code so the background thread will continue
        // to retry the request instead of dropping it as invalid
        if (ex instanceof java.net.UnknownHostException || ex instanceof java.net.SocketException
                || ex instanceof java.net.SocketTimeoutException) {
            return ResourceException.SERVICE_UNAVAILABLE;
        }
        return ResourceException.BAD_REQUEST;
    }

    String encodeAWSRoleName(final String roleName) {

        // since our aws role name can contain the path element thus /'s
        // we need to encode the value and use that instead. we're going
        // to need to encode the value twice since one will be decoded
        // by jetty and the second one is decoded by zts aws creds api itself

        if (roleName.indexOf('/') == -1) {
            return roleName;
        }

        return URLEncoder.encode(URLEncoder.encode(roleName, StandardCharsets.UTF_8), StandardCharsets.UTF_8);
    }

    /**
     * Request external credentials for the principal
     * @param provider provider name to request credentials from
     * @param domainName request credentials from account/project associated with this athenz domain
     * @param request request object with optional and required attributes
     * @return ExternalCredentialsResponse object that includes requested external credentials
     */
    public ExternalCredentialsResponse postExternalCredentialsRequest(String provider,
            String domainName, ExternalCredentialsRequest request) {
        updateServicePrincipal();
        try {
            return ztsClient.postExternalCredentialsRequest(provider, domainName, request);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of all policies (not just names) from the ZTS Server that
     * is signed with both ZTS's and ZMS's private keys. It will pass an option matchingTag
     * so that ZTS can skip returning signed policies if no changes have taken
     * place since that tag was issued.
     * @param domainName name of the domain
     * @param matchingTag name of the tag issued with last request
     * @param responseHeaders contains the "tag" returned for modification
     *   time of the policies, map key = "tag", List should contain a single value
     * @return list of policies signed by ZTS Server. ZTSClientException will be thrown in case of failure
     */
    public DomainSignedPolicyData getDomainSignedPolicyData(String domainName, String matchingTag,
            Map<String, List<String>> responseHeaders) {
        try {
            return ztsClient.getDomainSignedPolicyData(domainName, matchingTag, responseHeaders);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of all policies (not just names) from the ZTS Server that
     * is signed and represented as JWS document. It will pass an optional matchingTag
     * so that ZTS can skip returning signed policies if no changes have taken
     * place since that tag was issued. If specific version of policy versions are
     * needed, the request argument must include a map of those policy names along
     * with their requested versions, otherwise an empty request object must be passed
     * @param domainName name of the domain
     * @param request signed policy request with optional map of policy names and version numbers
     * @param matchingTag name of the tag issued with last request
     * @param responseHeaders contains the "tag" returned for modification
     *   time of the policies, map key = "tag", List should contain a single value
     * @return list of policies signed by ZTS Server. ZTSClientException will be thrown in case of failure
     */
    public JWSPolicyData postSignedPolicyRequest(String domainName, SignedPolicyRequest request, String matchingTag,
            Map<String, List<String>> responseHeaders) {
        try {
            return ztsClient.postSignedPolicyRequest(domainName, request, matchingTag, responseHeaders);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Verify if the given principal has access to the specified role in the
     * domain or not.
     * @param domainName name of the domain
     * @param roleName name of the role
     * @param principal name of the principal to check for
     * @return Access object with grant true/false response. ZTSClientException will be thrown in case of failure
     */
    public Access getAccess(String domainName, String roleName, String principal) {
        updateServicePrincipal();
        try {
            return ztsClient.getAccess(domainName, roleName, principal);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Requests the ZTS to indicate whether or not the specific request for the
     * specified resource with authentication details will be granted or not.
     * @param action value of the action to be carried out (e.g. "UPDATE", "DELETE")
     * @param resource resource YRN. YRN is defined as ({ServiceName})?:({LocationName})?:)?{ResourceName}"
     * @param trustDomain (optional) if the access checks involves cross domain check only
     *        check the specified trusted domain and ignore all others
     * @param principal (optional) carry out the access check for specified principal
     * @return ResourceAccess object indicating whether or not the request will be granted or not
     */
    public ResourceAccess getResourceAccess(String action, String resource, String trustDomain, String principal) {
        updateServicePrincipal();
        try {
            return ztsClient.getResourceAccess(action, resource, trustDomain, principal);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getMessage());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Requests the ZTS to indicate whether or not the specific request for the
     * specified resource with authentication details will be granted or not.
     * @param action value of the action to be carried out (e.g. "UPDATE", "DELETE")
     * @param resource resource YRN. YRN is defined as ({ServiceName})?:({LocationName})?:)?{ResourceName}"
     * @param trustDomain (optional) if the access checks involves cross domain check only
     *        check the specified trusted domain and ignore all others
     * @param principal (optional) carry out the access check for specified principal
     * @return ResourceAccess object indicating whether or not the request will be granted or not
     */
    public ResourceAccess getResourceAccessExt(String action, String resource, String trustDomain, String principal) {
        updateServicePrincipal();
        try {
            return ztsClient.getResourceAccessExt(action, resource, trustDomain, principal);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getMessage());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Request by an instance to register itself based on its provider
     * attestation.
     * @param info InstanceRegisterInformation object for the request
     * @param responseHeaders contains the "location" returned for post refresh requests
     *   List should contain a single value
     * @return InstanceIdentity object that includes a x509 certificate for the service
     */
    public InstanceIdentity postInstanceRegisterInformation(InstanceRegisterInformation info,
            Map<String, List<String>> responseHeaders) {
        updateServicePrincipal();
        try {
            return ztsClient.postInstanceRegisterInformation(info, responseHeaders);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Request by an instance to refresh its certificate. The instance must
     * authenticate itself using the certificate it has received from the
     * postInstanceRegisterInformation call.
     * @param provider Provider Service name
     * @param domain instance domain name
     * @param service instance service name
     * @param instanceId instance id as provided in the CSR
     * @param info InstanceRegisterInformation object for the request
     * @return InstanceIdentity object that includes a x509 certificate for the service
     */
    public InstanceIdentity postInstanceRefreshInformation(String provider, String domain,
            String service, String instanceId, InstanceRefreshInformation info) {
        updateServicePrincipal();
        try {
            return ztsClient.postInstanceRefreshInformation(provider, domain, service, instanceId, info);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Revoke an instance from refreshing its certificates.
     * @param provider Provider Service name
     * @param domain instance domain name
     * @param service instance service name
     * @param instanceId instance id as provided in the CSR
     */
    public void deleteInstanceIdentity(String provider, String domain,
            String service, String instanceId) {
        updateServicePrincipal();
        try {
            ztsClient.deleteInstanceIdentity(provider, domain, service, instanceId);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve list of CA Certificates in PEM format for the given bundle name
     * @param bundleName name of the CA Certificate bundle name
     * @return CA Certificate bundle including list of CA certificates on success. ZTSClientException will be thrown in case of failure
     */
    public CertificateAuthorityBundle getCertificateAuthorityBundle(String bundleName) {
        updateServicePrincipal();
        try {
            return ztsClient.getCertificateAuthorityBundle(bundleName);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve list of workloads running on the given ip address
     * @param ipAddress ip address of the workload
     * @return list of workloads on success. ZTSClientException will be thrown in case of failure
     */
    public Workloads getWorkloadsByIP(String ipAddress) {
        updateServicePrincipal();
        try {
            return ztsClient.getWorkloadsByIP(ipAddress);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve list of workloads running with given domain and service
     * @param domain name of the domain
     * @param service name of the service
     * @return list of workloads on success. ZTSClientException will be thrown in case of failure
     */
    public Workloads getWorkloadsByService(String domain, String service) {
        updateServicePrincipal();
        try {
            return ztsClient.getWorkloadsByService(domain, service);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve list of transport rules defined for given domain and service
     * @param domain name of the domain
     * @param service name of the service
     * @return list of transport rules on success. ZTSClientException will be thrown in case of failure
     */
    public TransportRules getTransportRules(String domain, String service) {
        updateServicePrincipal();
        try {
            return ztsClient.getTransportRules(domain, service);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Request an instance register token for the given service instance from the
     * given provider. Not all providers may support such functionality.
     * @param provider name of the provider
     * @param domain name of the domain
     * @param service name of the service
     * @param instanceId unique id assigned to the instance by the provider
     * @return instance register token. ZTSClientException will be thrown in case of failure
     */
    public InstanceRegisterToken getInstanceRegisterToken(String provider, String domain, String service, String instanceId) {
        try {
            return ztsClient.getInstanceRegisterToken(provider, domain, service, instanceId);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the server info details
     * @return info object
     * @throws ZTSClientException in case of failure
     */
    public Info getInfo() {
        updateServicePrincipal();
        try {
            return ztsClient.getInfo();
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * For the specified requester(user/service) return the corresponding Access Token that
     * includes the list of roles that the principal has access to in the specified domain
     * @param domainName name of the domain
     * @param roleName only interested in the specified role name
     * @param clientId name of the audience service name (e.g. sys.auth.gcp)
     * @param redirectUriSuffix the function will generate an auto redirect uri as required by the server
     *          with the format {service-name}.{domain-with-dashes}.{redirect-suffix} and submit as part
     *          of the request.
     * @param fullArn boolean flag indicating whether the groups claim in the token contains only the
     *           role names or the full names including domains (e.g. sports.api:role.hockey-writers).
     * @param expiryTime (optional) specifies that the returned Access must be
     *          at least valid for specified number of seconds. Pass 0 to use
     *          server default timeout.
     * @return ZTS generated ID Token String. ZTSClientException will be thrown in case of failure
     */
    public OIDCResponse getIDToken(String domainName, String roleName, String clientId, String redirectUriSuffix,
                             boolean fullArn, Integer expiryTime) {
        return getIDToken(domainName, Collections.singletonList(roleName), clientId,
                redirectUriSuffix, fullArn, expiryTime);
    }

    /**
     * For the specified requester(user/service) return the corresponding Access Token that
     * includes the list of roles that the principal has access to in the specified domain
     * @param domainName name of the domain
     * @param roleNames (optional) only interested in roles with these names, comma separated list of roles
     * @param clientId name of the audience service name (e.g. sys.auth.gcp)
     * @param redirectUriSuffix the function will generate an auto redirect uri as required by the server
     *          with the format {service-name}.{domain-with-dashes}.{redirect-suffix} and submit as part
     *          of the request.
     * @param fullArn boolean flag indicating whether the groups claim in the token contains only the
     *           role names or the full names including domains (e.g. sports.api:role.hockey-writers).
     * @param expiryTime (optional) specifies that the returned Access must be
     *          at least valid for specified number of seconds. Pass 0 to use
     *          server default timeout.
     * @return ZTS generated ID Token String. ZTSClientException will be thrown in case of failure
     */
    public OIDCResponse getIDToken(String domainName, List<String> roleNames, String clientId, String redirectUriSuffix,
            boolean fullArn, Integer expiryTime) {
         final String redirectUri = generateRedirectUri(clientId, redirectUriSuffix);
         final String scope = generateIdTokenScope(domainName, roleNames);

         return getIDToken("id_token", clientId, redirectUri, scope, null, "EC", fullArn, expiryTime, false);
    }

    /**
     * For the specified requester(user/service) return the corresponding Access Token that
     * includes the list of roles that the principal has access to in the specified domain
     * @param responseType response object type - only id_token is supported for now
     * @param clientId name of the audience service name (e.g. sys.auth.gcp)
     * @param redirectUri the redirect uri for the request
     * @param scope the scope of the request e.g. "openid sports.api:roles.hockey-writers"
     * @param state the state component of the location header. could be empty
     * @param keyType the private key type to sign the token - possible values are "RSA" or "EC"
     * @param fullArn boolean flag indicating whether the groups claim in the token contains only the
     *           role names or the full names including domains (e.g. sports.api:role.hockey-writers).
     * @param expiryTime (optional) specifies that the returned Access must be
     *          at least valid for specified number of seconds. Pass 0 to use
     *          server default timeout.
     * @return ZTS generated ID Token String. ZTSClientException will be thrown in case of failure
     */
    public OIDCResponse getIDToken(String responseType, String clientId, String redirectUri, String scope, String state,
            String keyType, Boolean fullArn, Integer expiryTime, boolean ignoreCache) {

        // check for required attributes

        if (isEmpty(responseType) || isEmpty(clientId) || isEmpty(redirectUri) || isEmpty(scope)) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, "missing required attribute(s)");
        }

        OIDCResponse oidcResponse;

        // first lookup in our cache to see if it can be satisfied
        // only if we're not asked to ignore the cache

        String cacheKey = null;
        if (!cacheDisabled) {
            cacheKey = getIdTokenCacheKey(responseType, clientId, redirectUri, scope, state, keyType, fullArn);
            if (cacheKey != null && !ignoreCache) {
                oidcResponse = lookupIdTokenResponseInCache(cacheKey, expiryTime);
                if (oidcResponse != null) {
                    return oidcResponse;
                }
                // start prefetch for this token if prefetch is enabled
                if (enablePrefetch && prefetchAutoEnable) {
                    if (prefetchIdToken(responseType, clientId, redirectUri, scope,
                            state, keyType, fullArn, expiryTime)) {
                        oidcResponse = lookupIdTokenResponseInCache(cacheKey, expiryTime);
                    }
                    if (oidcResponse != null) {
                        return oidcResponse;
                    }
                    LOG.error("GetIdToken: cache prefetch and lookup error");
                }
            }
        }

        // if no hit then we need to request a new token from ZTS

        updateServicePrincipal();
        try {
            Map<String, List<String>> responseHeaders = new HashMap<>();
            oidcResponse = ztsClient.getOIDCResponse(responseType, clientId, redirectUri, scope,
                    state, Crypto.randomSalt(), keyType, fullArn, expiryTime, "json", false, responseHeaders);

        } catch (ResourceException ex) {

            if (cacheKey != null && !ignoreCache) {

                // if we have an entry in our cache then we'll return that
                // instead of returning failure

                oidcResponse = lookupIdTokenResponseInCache(cacheKey, -1);
                if (oidcResponse != null) {
                    return oidcResponse;
                }
            }
            throw new ZTSClientException(ex.getCode(), ex.getData());

        } catch (Exception ex) {

            // if we have an entry in our cache then we'll return that
            // instead of returning failure

            if (cacheKey != null && !ignoreCache) {
                oidcResponse = lookupIdTokenResponseInCache(cacheKey, -1);
                if (oidcResponse != null) {
                    return oidcResponse;
                }
            }
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        }

        // need to add the token to our cache. If our principal was
        // updated then we need to retrieve a new cache key

        if (!cacheDisabled) {
            if (cacheKey == null) {
                cacheKey = getIdTokenCacheKey(responseType, clientId, redirectUri, scope, state,
                        keyType, fullArn);
            }
            if (cacheKey != null) {
                ID_TOKEN_CACHE.put(cacheKey, oidcResponse);
            }
        }

        return oidcResponse;
    }

    OIDCResponse lookupIdTokenResponseInCache(String cacheKey, Integer expirySeconds) {

        OIDCResponse oidcResponse = ID_TOKEN_CACHE.get(cacheKey);
        if (oidcResponse == null) {
            if (LOG.isInfoEnabled()) {
                LOG.info("LookupIdTokenResponseInCache: cache-lookup key: {} result: not found", cacheKey);
            }
            return null;
        }

        long now = System.currentTimeMillis() / 1000;
        long tokenExpiryTime = oidcResponse.getExpiration_time();

        // default timeout for id tokens is 1 hour

        if (expirySeconds == null) {
            expirySeconds = 60 * 60;
        }

        // if our expiry seconds is -1 then we should return
        // our cached object as long as it's not expired

        if (expirySeconds == -1 && tokenExpiryTime > now) {
            return oidcResponse;
        }

        // before returning our cache hit we need to make sure it
        // was at least 1/4th time left before the token expires
        // if the expiryTime is -1 then we return the token as
        // long as it's not expired

        if (tokenExpiryTime < now + expirySeconds / 4) {

            // if the token is completely expired then we'll remove it from the cache

            if (tokenExpiryTime <= now) {
                ID_TOKEN_CACHE.remove(cacheKey);
            }
            return null;
        }

        return oidcResponse;
    }

    public static String generateIdTokenScope(final String domainName, List<String> roleNames) {
        StringBuilder scope = new StringBuilder(256);
        scope.append("openid");
        if (isEmpty(roleNames)) {
            scope.append(" roles ").append(domainName).append(":domain");
        } else {
            for (String role : roleNames) {
                scope.append(' ').append(domainName).append(AuthorityConsts.ROLE_SEP).append(role);
            }
        }
        return scope.toString();
    }

    public static String generateRedirectUri(final String clientId, final String uriSuffix) {
        int idx = clientId.lastIndexOf('.');
        if (idx == -1) {
            return "";
        }
        final String dashDomain = clientId.substring(0, idx).replace('.', '-');
        final String service = clientId.substring(idx + 1);
        return "https://" + service + "." + dashDomain + "." + uriSuffix;
    }

    static class ClientKeyRefresherListener implements KeyRefresherListener {

        long lastCertRefreshTime = 0;

        @Override
        public void onKeyChangeEvent() {
            lastCertRefreshTime = System.currentTimeMillis() / 1000;
        }

        long getLastCertRefreshTime() {
            return lastCertRefreshTime;
        }
    }

    static class PrefetchTokenScheduledItem {

        TokenType tokenType = TokenType.ACCESS;
        PrefetchTokenScheduledItem setTokenType(TokenType type) {
            tokenType = type;
            return this;
        }

        String providedZTSUrl;
        PrefetchTokenScheduledItem setProvidedZTSUrl(String u) {
            providedZTSUrl = u;
            return this;
        }
        
        ServiceIdentityProvider siaProvider;
        PrefetchTokenScheduledItem setSiaIdentityProvider(ServiceIdentityProvider s) {
            siaProvider = s;
            return this;
        }
        
        ZTSRDLGeneratedClient ztsClient;
        PrefetchTokenScheduledItem setZtsClient(ZTSRDLGeneratedClient z) {
            ztsClient = z;
            return this;
        }
        
        boolean isInvalid = false;
        PrefetchTokenScheduledItem setIsInvalid(boolean invalid) {
            isInvalid = invalid;
            return this;
        }
        
        String identityDomain;
        PrefetchTokenScheduledItem setIdentityDomain(String d) {
            identityDomain = d;
            return this;
        }
        
        String identityName;
        PrefetchTokenScheduledItem setIdentityName(String d) {
            identityName = d;
            return this;
        }
        
        String domainName;
        PrefetchTokenScheduledItem setDomainName(String d) {
            domainName = d;
            return this;
        }

        String cacheKey;
        PrefetchTokenScheduledItem setCacheKey(String key) {
            cacheKey = key;
            return this;
        }

        String roleName;
        PrefetchTokenScheduledItem setRoleName(String s) {
            roleName = s;
            return this;
        }

        List<String> roleNames;
        PrefetchTokenScheduledItem setRoleNames(List<String> stringList) {
            roleNames = stringList;
            return this;
        }

        String proxyForPrincipal;
        PrefetchTokenScheduledItem setProxyForPrincipal(String u) {
            proxyForPrincipal = u;
            return this;
        }

        String externalId;
        PrefetchTokenScheduledItem setExternalId(String id) {
            externalId = id;
            return this;
        }

        String authorizationDetails;
        PrefetchTokenScheduledItem setAuthorizationDetails(String details) {
            authorizationDetails = details;
            return this;
        }

        String idTokenServiceName;
        PrefetchTokenScheduledItem setIdTokenServiceName(String serviceName) {
            idTokenServiceName = serviceName;
            return this;
        }

        Integer minDuration;
        PrefetchTokenScheduledItem setMinDuration(Integer min) {
            minDuration = min;
            return this;
        }
        
        Integer maxDuration;
        PrefetchTokenScheduledItem setMaxDuration(Integer max) {
            maxDuration = max;
            return this;
        }
        
        long expiresAtUTC = 0;
        PrefetchTokenScheduledItem setExpiresAtUTC(long e) {
            expiresAtUTC = e;
            return this;
        }

        long fetchTime = 0;
        PrefetchTokenScheduledItem setFetchTime(long time) {
            fetchTime = time;
            return this;
        }

        ZTSClientNotificationSender notificationSender = null;
        PrefetchTokenScheduledItem setNotificationSender(ZTSClientNotificationSender notificationSender) {
            this.notificationSender = notificationSender;
            return this;
        }

        long lastFailTime = 0;
        PrefetchTokenScheduledItem setLastFailTime(long time) {
            lastFailTime = time;
            return this;
        }

        long lastNotificationTime = 0;
        PrefetchTokenScheduledItem setLastNotificationTime(long time) {
            lastNotificationTime = time;
            return this;
        }

        int tokenMinExpiryTime;
        PrefetchTokenScheduledItem setTokenMinExpiryTime(int t) {
            tokenMinExpiryTime = t;
            return this;
        }

        SSLContext sslContext;
        PrefetchTokenScheduledItem setSslContext(SSLContext ctx) {
            sslContext = ctx;
            return this;
        }
        
        String proxyUrl;
        PrefetchTokenScheduledItem setProxyUrl(String url) {
            proxyUrl = url;
            return this;
        }

        String responseType;
        PrefetchTokenScheduledItem setResponseType(String type) {
            responseType = type;
            return this;
        }

        String redirectUri;
        PrefetchTokenScheduledItem setRedirectUri(String uri) {
            redirectUri = uri;
            return this;
        }

        String scope;
        PrefetchTokenScheduledItem setScope(String value) {
            scope = value;
            return this;
        }

        String state;
        PrefetchTokenScheduledItem setState(String value) {
            state = value;
            return this;
        }

        String keyType;
        PrefetchTokenScheduledItem setKeyType(String type) {
            keyType = type;
            return this;
        }

        Boolean fullArn;
        PrefetchTokenScheduledItem setFullArn(Boolean arn) {
            fullArn = arn;
            return this;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((domainName == null) ? 0 : domainName.hashCode());
            result = prime * result + ((identityDomain == null) ? 0 : identityDomain.hashCode());
            result = prime * result + ((identityName == null) ? 0 : identityName.hashCode());
            result = prime * result + ((roleName == null) ? 0 : roleName.hashCode());
            result = prime * result + ((roleNames == null) ? 0 : roleNames.hashCode());
            result = prime * result + ((proxyForPrincipal == null) ? 0 : proxyForPrincipal.hashCode());
            result = prime * result + ((externalId == null) ? 0 : externalId.hashCode());
            result = prime * result + ((idTokenServiceName == null) ? 0 : idTokenServiceName.hashCode());
            result = prime * result + ((sslContext == null) ? 0 : sslContext.hashCode());
            result = prime * result + ((proxyUrl == null) ? 0 : proxyUrl.hashCode());
            result = prime * result + ((responseType == null) ? 0 : responseType.hashCode());
            result = prime * result + ((redirectUri == null) ? 0 : redirectUri.hashCode());
            result = prime * result + ((scope == null) ? 0 : scope.hashCode());
            result = prime * result + ((state == null) ? 0 : state.hashCode());
            result = prime * result + ((keyType == null) ? 0 : keyType.hashCode());
            result = prime * result + ((fullArn == null) ? 0 : fullArn.hashCode());
            result = prime * result + tokenType.hashCode();
            result = prime * result + Boolean.hashCode(isInvalid);

            return result;
        }
        
        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            PrefetchTokenScheduledItem other = (PrefetchTokenScheduledItem) obj;
            if (domainName == null) {
                if (other.domainName != null) {
                    return false;
                }
            } else if (!domainName.equals(other.domainName)) {
                return false;
            }
            if (identityDomain == null) {
                if (other.identityDomain != null) {
                    return false;
                }
            } else if (!identityDomain.equals(other.identityDomain)) {
                return false;
            }
            if (identityName == null) {
                if (other.identityName != null) {
                    return false;
                }
            } else if (!identityName.equals(other.identityName)) {
                return false;
            }
            if (roleName == null) {
                if (other.roleName != null) {
                    return false;
                }
            } else if (!roleName.equals(other.roleName)) {
                return false;
            }
            if (roleNames == null) {
                if (other.roleNames != null) {
                    return false;
                }
            } else if (!roleNames.equals(other.roleNames)) {
                return false;
            }
            if (proxyForPrincipal == null) {
                if (other.proxyForPrincipal != null) {
                    return false;
                }
            } else if (!proxyForPrincipal.equals(other.proxyForPrincipal)) {
                return false;
            }
            if (externalId == null) {
                if (other.externalId != null) {
                    return false;
                }
            } else if (!externalId.equals(other.externalId)) {
                return false;
            }
            if (idTokenServiceName == null) {
                if (other.idTokenServiceName != null) {
                    return false;
                }
            } else if (!idTokenServiceName.equals(other.idTokenServiceName)) {
                return false;
            }
            if (responseType == null) {
                if (other.responseType != null) {
                    return false;
                }
            } else if (!responseType.equals(other.responseType)) {
                return false;
            }
            if (redirectUri == null) {
                if (other.redirectUri != null) {
                    return false;
                }
            } else if (!redirectUri.equals(other.redirectUri)) {
                return false;
            }
            if (scope == null) {
                if (other.scope != null) {
                    return false;
                }
            } else if (!scope.equals(other.scope)) {
                return false;
            }
            if (state == null) {
                if (other.state != null) {
                    return false;
                }
            } else if (!state.equals(other.state)) {
                return false;
            }
            if (keyType == null) {
                if (other.keyType != null) {
                    return false;
                }
            } else if (!keyType.equals(other.keyType)) {
                return false;
            }
            if (fullArn == null) {
                if (other.fullArn != null) {
                    return false;
                }
            } else if (!fullArn.equals(other.fullArn)) {
                return false;
            }
            if (isInvalid != other.isInvalid) {
                return false;
            }
            if (tokenType != other.tokenType) {
                return false;
            }
            if (sslContext == null) {
                return other.sslContext == null;
            } else {
                return sslContext.equals(other.sslContext);
            }
        }

        public boolean shouldSendNotification() {
            if (notificationSender == null) {
                return false;
            }

            // If we successfully received a token, revert lastNotificationTime to be ready for future failures
            if (lastFailTime == 0) {
                lastNotificationTime = 0;
                return false;
            }

            return lastNotificationTime == 0;
        }
    }
    
    public static class AWSHostNameVerifier implements HostnameVerifier {

        String dnsHostname;
        
        public AWSHostNameVerifier(String hostname) {
            dnsHostname = hostname;
        }
        
        @Override
        public boolean verify(String hostname, SSLSession session) {

            Certificate[] certs = null;
            try {
                certs = session.getPeerCertificates();
            } catch (SSLPeerUnverifiedException ignored) {
            }
            if (certs == null || certs.length == 0) {
                return false;
            }

            List<String> certDnsNames = Crypto.extractX509CertDnsNames((X509Certificate) certs[0]);
            for (String dnsName : certDnsNames) {
                if (dnsHostname.equalsIgnoreCase(dnsName)) {
                    return true;
                }
            }
            return false;
        }
    }
    
    private static Set<String> loadSvcProviderTokens() {
        
        ztsTokenProviders = ServiceLoader.load(ZTSClientService.class);
        svcLoaderCacheKeys = new AtomicReference<>();

        // if we have service loader implementations, then stuff role tokens into cache
        // and keep track of these tokens so that they will get refreshed from
        // service loader and not zts server
        
        Set<String> cacheKeySet = new HashSet<>();
        for (ZTSClientService provider: ztsTokenProviders) {
            Collection<ZTSClientService.RoleTokenDescriptor> descs = provider.loadTokens();
            if (descs == null) {
                if (LOG.isInfoEnabled()) {
                    LOG.info("loadSvcProviderTokens: provider didn't return tokens: prov={}", provider);
                }
                continue;
            }
            for (ZTSClientService.RoleTokenDescriptor desc: descs) {
                if (desc.signedToken != null) {
                    // stuff token in cache and record service loader key
                    String key = cacheSvcProvRoleToken(desc);
                    if (key != null) {
                        cacheKeySet.add(key);
                    }
                }
            }
        }

        svcLoaderCacheKeys.set(cacheKeySet);
        return cacheKeySet;
    }

    static boolean isEmpty(final String value) {
        return (value == null || value.isEmpty());
    }

    static boolean isEmpty(final List<String> list) {
        return (list == null || list.isEmpty());
    }

    /**
     * returns a cache key for the given list of roles.
     * if the list of roles contains multiple entries
     * then we have to sort the array first and then
     * generate the key based on the sorted list since
     * there is no guarantee what order the ZTS Server
     * might return the list of roles
     * 
     * @param roles list of role names
     * @return cache key for the list
     */
    static String multipleRoleKey(List<String> roles) {
        
        // first check to make sure we have valid data
        
        if (roles == null || roles.isEmpty()) {
            return null;
        }
        
        // if we have a single role then that's the key
        
        if (roles.size() == 1) {
            return roles.get(0);
        }
        
        // if we have multiple roles, then we have to
        // sort the values and then generate the key
        // since we might have been given unmodifiable
        // list we need to make a copy so we can sort it

        List<String> modList = new ArrayList<>(roles);
        Collections.sort(modList);
        return String.join(",", modList);
    }
    
    /**
     * stuff pre-loaded service token in cache. in this model an external
     * service (proxy user) has retrieved the role tokens and added to the
     * client cache so it can run without the need to contact zts server.
     * in this model we're going to look at the principal field only and
     * ignore the proxy field since the client doesn't need to know anything
     * about that detail.
     * start prefetch task to reload to prevent expiry
     * return the cache key used
     */
    static String cacheSvcProvRoleToken(ZTSClientService.RoleTokenDescriptor desc) {

        if (cacheDisabled) {
            return null;
        }
        
        com.yahoo.athenz.auth.token.RoleToken rt = new com.yahoo.athenz.auth.token.RoleToken(desc.getSignedToken());
        String domainName = rt.getDomain();
        String principalName = rt.getPrincipal();
        boolean completeRoleSet = rt.getDomainCompleteRoleSet();

        // if the role token was for a complete set then we're not going
        // to use the rolename field (it indicates that the original request
        // was completed without the rolename field being specified)
        
        final String roleName = (completeRoleSet) ? null : multipleRoleKey(rt.getRoles());
        
        // parse principalName for the tenant domain and service name
        // we must have valid components otherwise we'll just
        // ignore the token - you can't have a principal without
        // valid domain and service names
        
        int index = principalName.lastIndexOf('.'); // ex: cities.burbank.mysvc
        if (index == -1) {
            LOG.error("cacheSvcProvRoleToken: Invalid principal in token: {}", rt.getSignedToken());
            return null;
        }

        final String tenantDomain = principalName.substring(0, index);
        final String tenantService = principalName.substring(index + 1);
        Long expiryTime = rt.getExpiryTime();

        RoleToken roleToken = new RoleToken().setToken(desc.getSignedToken()).setExpiryTime(expiryTime);

        final String key = getRoleTokenCacheKey(tenantDomain, tenantService, domainName, roleName, null);

        if (LOG.isInfoEnabled()) {
            LOG.info("cacheSvcProvRoleToken: cache-add key: {} expiry: {}", key, expiryTime);
        }

        ROLE_TOKEN_CACHE.put(key, roleToken);

        // setup prefetch task
        
        prefetchSvcProvTokens(tenantDomain, tenantService, domainName,
            key, roleName, null, null, expiryTime, null);

        return key;
    }
    
    static void prefetchSvcProvTokens(String domain, String service, String domainName,
            String cacheKey, String roleName, Integer minExpiryTime, Integer maxExpiryTime,
            Long expiryTimeUTC, String proxyForPrincipal) {
        
        if (domainName == null || domainName.trim().isEmpty()) {
            throw new ZTSClientException(ResourceException.BAD_REQUEST, "Domain Name cannot be empty");
        }

        PrefetchTokenScheduledItem item = new PrefetchTokenScheduledItem()
            .setTokenType(TokenType.SVC_ROLE)
            .setCacheKey(cacheKey)
            .setDomainName(domainName)
            .setRoleName(roleName)
            .setProxyForPrincipal(proxyForPrincipal)
            .setMinDuration(minExpiryTime)
            .setMaxDuration(maxExpiryTime)
            .setExpiresAtUTC(expiryTimeUTC)
            .setIdentityDomain(domain)
            .setIdentityName(service)
            .setTokenMinExpiryTime(ZTSClient.tokenMinExpiryTime);

        // we need to make sure we don't have duplicates in
        // our prefetch list so since we got a brand new
        // token now we're going to remove any others we have
        // in the list and add this one. Our items equal
        // method defines what attributes we're looking for
        // when comparing two items

        PREFETCH_SCHEDULED_ITEMS.remove(item);
        PREFETCH_SCHEDULED_ITEMS.add(item);

        startPrefetch();
    }

    static void startPrefetch() {

        if (FETCH_TIMER != null) {
            return;
        }

        synchronized (TIMER_LOCK) {
            if (FETCH_TIMER == null) {
                FETCH_TIMER = new Timer(true);
                // check the fetch items every prefetchInterval seconds.
                FETCH_TIMER.schedule(new TokenPrefetchTask(), 0, prefetchInterval * 1000);
            }
        }
    }
}
