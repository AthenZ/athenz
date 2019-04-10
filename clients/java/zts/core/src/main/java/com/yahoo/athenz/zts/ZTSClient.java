/*
 * Copyright 2016 Yahoo Inc.
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
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
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.operator.OperatorCreationException;
import org.glassfish.jersey.apache.connector.ApacheConnectorProvider;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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

public class ZTSClient implements Closeable {

    private static final Logger LOG = LoggerFactory.getLogger(ZTSClient.class);
    
    private String ztsUrl = null;
    private String proxyUrl = null;
    private String domain = null;
    private String service = null;
    private SSLContext sslContext = null;
    
    ZTSRDLGeneratedClient ztsClient = null;
    ServiceIdentityProvider siaProvider = null;
    Principal principal = null;

    // configurable fields
    //
    static private boolean cacheDisabled = false;
    static private int tokenMinExpiryTime = 900;
    static private long prefetchInterval = 60; // seconds
    static private boolean prefetchAutoEnable = true;
    static private String x509CsrDn = null;
    static private String x509CsrDomain = null;
    static private int reqReadTimeout = 30000;
    static private int reqConnectTimeout = 30000;
    static private String x509CertDNSName = null;
    static private String confZtsUrl = null;
    
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

    public static final String ZTS_CLIENT_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS  = "athenz.zts.client.private_keystore_factory_class";
    public static final String ZTS_CLIENT_PROP_CLIENT_PROTOCOL                  = "athenz.zts.client.client_ssl_protocol";
    public static final String ZTS_CLIENT_PKEY_STORE_FACTORY_CLASS              = "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory";
    public static final String ZTS_CLIENT_DEFAULT_CLIENT_SSL_PROTOCOL           = "TLSv1.2";

    public static final String ROLE_TOKEN_HEADER = System.getProperty(RoleAuthority.ATHENZ_PROP_ROLE_HEADER,
            RoleAuthority.HTTP_HEADER);

    final static ConcurrentHashMap<String, RoleToken> ROLE_TOKEN_CACHE = new ConcurrentHashMap<>();
    final static ConcurrentHashMap<String, AccessTokenResponseCacheEntry> ACCESS_TOKEN_CACHE = new ConcurrentHashMap<>();
    final static ConcurrentHashMap<String, AWSTemporaryCredentials> AWS_CREDS_CACHE = new ConcurrentHashMap<>();

    private static final long FETCH_EPSILON = 60; // if cache expires in the next minute, fetch it.
    private static final Queue<PrefetchRoleTokenScheduledItem> PREFETCH_SCHEDULED_ITEMS = new ConcurrentLinkedQueue<>();
    private static Timer FETCH_TIMER;
    private static final Object TIMER_LOCK = new Object();
    static AtomicLong FETCHER_LAST_RUN_AT = new AtomicLong(-1);
    
    // allows outside implementations to get role tokens for special environments - ex. hadoop
    
    private static ServiceLoader<ZTSClientService> ztsTokenProviders;
    private static AtomicReference<Set<String>> svcLoaderCacheKeys;
    private static PrivateKeyStore PRIVATE_KEY_STORE = loadServicePrivateKey();

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
        if (domainName == null || domainName.isEmpty()) {
            throw new IllegalArgumentException("Domain name must be specified");
        }
        if (serviceName == null || serviceName.isEmpty()) {
            throw new IllegalArgumentException("Service name must be specified");
        }
        if (siaProvider == null) {
            throw new IllegalArgumentException("Service Identity Provider must be specified");
        }
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
     * Set new ZTS Client configuration property. This method calls
     * internal javax.ws.rs.client.Client client's property method.
     * If already set, the existing value of the property will be updated.
     * Setting a null value into a property effectively removes the property
     * from the property bag.
     * @param name property name.
     * @param value property value. null value removes the property with the given name.
     */
    public void setProperty(String name, Object value) {
        if (ztsClient != null) {
            ztsClient.setProperty(name, value);
        }
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
    
    private SSLContext createSSLContext() {
        
        // to create the SSL context we must have the keystore path
        // specified. If it's not specified, then we are not going
        // to create our ssl context
        
        String keyStorePath = System.getProperty(ZTS_CLIENT_PROP_KEYSTORE_PATH);
        if (keyStorePath == null || keyStorePath.isEmpty()) {
            return null;
        }
        String keyStoreType = System.getProperty(ZTS_CLIENT_PROP_KEYSTORE_TYPE);
        String keyStorePwd = System.getProperty(ZTS_CLIENT_PROP_KEYSTORE_PASSWORD);
        char[] keyStorePassword = null;
        if (null != keyStorePwd && !keyStorePwd.isEmpty()) {
            keyStorePassword = keyStorePwd.toCharArray();
        }
        String keyStorePasswordAppName = System.getProperty(ZTS_CLIENT_PROP_KEYSTORE_PWD_APP_NAME);
        char[] keyManagerPassword = null;
        String keyManagerPwd = System.getProperty(ZTS_CLIENT_PROP_KEY_MANAGER_PASSWORD);
        if (null != keyManagerPwd && !keyManagerPwd.isEmpty()) {
            keyManagerPassword = keyManagerPwd.toCharArray();
        }
        String keyManagerPasswordAppName = System.getProperty(ZTS_CLIENT_PROP_KEY_MANAGER_PWD_APP_NAME);
        
        // truststore
        String trustStorePath = System.getProperty(ZTS_CLIENT_PROP_TRUSTSTORE_PATH);
        String trustStoreType = System.getProperty(ZTS_CLIENT_PROP_TRUSTSTORE_TYPE);
        String trustStorePwd = System.getProperty(ZTS_CLIENT_PROP_TRUSTSTORE_PASSWORD);
        char[] trustStorePassword = null;
        if (null != trustStorePwd && !trustStorePwd.isEmpty()) {
            trustStorePassword = trustStorePwd.toCharArray();
        }
        String trustStorePasswordAppName = System.getProperty(ZTS_CLIENT_PROP_TRUSTSTORE_PWD_APP_NAME);
        
        // alias and protocol details
        String certAlias = System.getProperty(ZTS_CLIENT_PROP_CERT_ALIAS);
        String clientProtocol = System.getProperty(ZTS_CLIENT_PROP_CLIENT_PROTOCOL,
                ZTS_CLIENT_DEFAULT_CLIENT_SSL_PROTOCOL);

        ClientSSLContextBuilder builder = new SSLUtils.ClientSSLContextBuilder(clientProtocol)
                .privateKeyStore(PRIVATE_KEY_STORE).keyStorePath(keyStorePath);
        
        if (null != certAlias && !certAlias.isEmpty()) {
            builder.certAlias(certAlias);
        }
        if (null != keyStoreType && !keyStoreType.isEmpty()) {
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
        if (null != trustStorePath && !trustStorePath.isEmpty()) {
            builder.trustStorePath(trustStorePath);
        }
        if (null != trustStoreType && !trustStoreType.isEmpty()) {
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
    
    private void initClient(final String serverUrl, Principal identity,
            final String domainName, final String serviceName,
            final ServiceIdentityProvider siaProvider) {
        
        ztsUrl = (serverUrl == null) ? confZtsUrl : serverUrl;
        
        // verify if the url is ending with /zts/v1 and if it's
        // not we'll automatically append it
        
        if (ztsUrl != null && !ztsUrl.isEmpty()) {
            if (!ztsUrl.endsWith("/zts/v1")) {
                if (ztsUrl.charAt(ztsUrl.length() - 1) != '/') {
                    ztsUrl += '/';
                }
                ztsUrl += "zts/v1";
            }
        }

        // determine to see if we need a host verifier for our ssl connections
        
        HostnameVerifier hostnameVerifier = null;
        if (x509CertDNSName != null && !x509CertDNSName.isEmpty()) {
            hostnameVerifier = new AWSHostNameVerifier(x509CertDNSName);
        }
        
        // if we don't have a ssl context specified, check the system
        // properties to see if we need to create one
        
        if (sslContext == null) {
            sslContext = createSSLContext();
        }
        
        // setup our client config object with timeouts
        
        final ClientConfig config = new ClientConfig();
        config.property(ClientProperties.CONNECT_TIMEOUT, reqConnectTimeout);
        config.property(ClientProperties.READ_TIMEOUT, reqReadTimeout);
        config.connectorProvider(new ApacheConnectorProvider());

        // if we're asked to use a proxy for our request
        // we're going to set the property that is supported
        // by the apache connector and use that
        
        if (proxyUrl != null) {
            config.property(ClientProperties.PROXY_URI, proxyUrl);
        }
        
        ClientBuilder builder = ClientBuilder.newBuilder();
        if (sslContext != null) {
            builder = builder.sslContext(sslContext);
            enablePrefetch = true;
        }
        Client rsClient = builder.hostnameVerifier(hostnameVerifier)
            .withConfig(config)
            .build();

        ztsClient = new ZTSRDLGeneratedClient(ztsUrl, rsClient);
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
        
        String creds = principal.getCredentials();
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
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve list of ZTS Server public keys in Json WEB Key (JWK) format
     * @return list of public keys (JWKs) on success. ZTSClientException will be thrown in case of failure
     */
    public JWKList getJWKList() {
        updateServicePrincipal();
        try {
            return ztsClient.getJWKList();
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
        }
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
        if (roleNames == null || roleNames.isEmpty()) {
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

            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
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
        return getAccessToken(domainName, roleNames, null, expiryTime, false);
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
    public AccessTokenResponse getAccessToken(String domainName, List<String> roleNames, String idTokenServiceName,
            long expiryTime, boolean ignoreCache) {

        AccessTokenResponse accessTokenResponse;

        // first lookup in our cache to see if it can be satisfied
        // only if we're not asked to ignore the cache

        String cacheKey = null;
        if (!cacheDisabled) {
            cacheKey = getAccessTokenCacheKey(domainName, roleNames, idTokenServiceName);
            if (cacheKey != null && !ignoreCache) {
                accessTokenResponse = lookupAccessTokenResponseInCache(cacheKey, expiryTime);
                if (accessTokenResponse != null) {
                    return accessTokenResponse;
                }
            }
        }

        // if no hit then we need to request a new token from ZTS

        updateServicePrincipal();
        try {
            final String requestBody = generateAccessTokenRequestBody(domainName, roleNames,
                    idTokenServiceName, expiryTime);
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
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
        }

        // need to add the token to our cache. If our principal was
        // updated then we need to retrieve a new cache key

        if (!cacheDisabled) {
            if (cacheKey == null) {
                cacheKey = getAccessTokenCacheKey(domainName, roleNames, idTokenServiceName);
            }
            if (cacheKey != null) {
                ACCESS_TOKEN_CACHE.put(cacheKey, new AccessTokenResponseCacheEntry(accessTokenResponse));
            }
        }
        return accessTokenResponse;
    }

    String generateAccessTokenRequestBody(String domainName, List<String> roleNames,
            String idTokenServiceName, long expiryTime) throws UnsupportedEncodingException {

        StringBuilder body = new StringBuilder(256);
        body.append("grant_type=client_credentials");
        if (expiryTime > 0) {
            body.append("&expires_in=").append(expiryTime);
        }

        StringBuilder scope = new StringBuilder(256);
        if (roleNames == null || roleNames.isEmpty()) {
            scope.append(domainName).append(":domain");
        } else {
            for (String role : roleNames) {
                if (scope.length() != 0) {
                    scope.append(' ');
                }
                scope.append(domainName).append(":role.").append(role);
            }
        }
        if (idTokenServiceName != null && !idTokenServiceName.isEmpty()) {
            scope.append(" openid ").append(domainName).append(":service.").append(idTokenServiceName);
        }
        final String scopeStr = scope.toString();
        body.append("&scope=").append(URLEncoder.encode(scopeStr, "UTF-8"));
        return body.toString();
    }

    /**
     * For the specified requester(user/service) return the corresponding Role Certificate
     * @param domainName name of the domain
     * @param roleName name of the role
     * @param req Role Certificate Request (csr)
     * @return RoleToken that includes client x509 role certificate
     */
    public RoleToken postRoleCertificateRequest(String domainName, String roleName,
            RoleCertificateRequest req) {
        
        updateServicePrincipal();
        try {
            return ztsClient.postRoleCertificateRequest(domainName, roleName, req);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getMessage());
        } catch (Exception ex) {
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
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
     * @param expiryTime number of seconds to request certificate to be valid for
     * @return RoleCertificateRequest object
     */
    static public RoleCertificateRequest generateRoleCertificateRequest(final String principalDomain,
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
        
        String dn = "cn=" + roleDomainName.toLowerCase() + ":role." + roleName.toLowerCase();
        if (csrDn != null) {
            dn = dn.concat(",").concat(csrDn);
        }
        
        // now let's generate our dsnName and email fields which will based on
        // our principal's details

        final String hostName = service + '.' + domain.replace('.', '-') + '.' + csrDomain;
        final String email = domain + "." + service + "@" + csrDomain;
        
        GeneralName[] sanArray = new GeneralName[2];
        sanArray[0] = new GeneralName(GeneralName.dNSName, new DERIA5String(hostName));
        sanArray[1] = new GeneralName(GeneralName.rfc822Name, new DERIA5String(email));
        
        String csr;
        try {
            csr = Crypto.generateX509CSR(privateKey, dn, sanArray);
        } catch (OperatorCreationException | IOException ex) {
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
        }

        return new RoleCertificateRequest().setCsr(csr).setExpiryTime((long) expiryTime);
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
     * @param expiryTime number of seconds to request certificate to be valid for
     * @return RoleCertificateRequest object
     */
    static public RoleCertificateRequest generateRoleCertificateRequest(final String principalDomain,
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
     * Generate a Instance Refresh request that could be sent to ZTS to
     * request a TLS certificate for a service.
     * @param principalDomain name of the principal's domain
     * @param principalService name of the principal's service
     * @param privateKey private key for the service identity for the caller
     * @param csrDn string identifying the dn for the csr without the cn component
     * @param csrDomain string identifying the dns domain for generating SAN fields
     * @param expiryTime number of seconds to request certificate to be valid for
     * @return InstanceRefreshRequest object
     */
    static public InstanceRefreshRequest generateInstanceRefreshRequest(final String principalDomain,
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

        final String hostName = service + '.' + domain.replace('.', '-') + '.' + csrDomain;
        
        GeneralName[] sanArray = new GeneralName[1];
        sanArray[0] = new GeneralName(GeneralName.dNSName, new DERIA5String(hostName));
        
        String csr;
        try {
            csr = Crypto.generateX509CSR(privateKey, dn, sanArray);
        } catch (OperatorCreationException | IOException ex) {
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
        }

        return new InstanceRefreshRequest().setCsr(csr).setExpiryTime(expiryTime);
    }
    
    /**
     * Generate a Instance Refresh request that could be sent to ZTS to
     * request a TLS certificate for a service.
     * @param principalDomain name of the principal's domain
     * @param principalService name of the principal's service
     * @param privateKey private key for the service identity for the caller
     * @param cloud string identifying the environment, e.g. aws
     * @param expiryTime number of seconds to request certificate to be valid for
     * @return InstanceRefreshRequest object
     */
    static public InstanceRefreshRequest generateInstanceRefreshRequest(String principalDomain,
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
    
    private static class RolePrefetchTask extends TimerTask {
        
        ZTSClient getZTSClient(PrefetchRoleTokenScheduledItem item) {
            
            ZTSClient client;
            if (item.sslContext != null) {
                client = new ZTSClient(item.providedZTSUrl, item.proxyUrl, item.sslContext);
            } else {
                client = new ZTSClient(item.providedZTSUrl, item.identityDomain,
                        item.identityName, item.siaProvider);
            }
            return client;
        }
        
        @Override
        public void run() {
            
            long currentTime = System.currentTimeMillis() / 1000;
            FETCHER_LAST_RUN_AT.set(currentTime);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("RolePrefetchTask: Fetching role token from the scheduled queue. Size={}",
                        PREFETCH_SCHEDULED_ITEMS.size());
            }
            if (PREFETCH_SCHEDULED_ITEMS.isEmpty()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("RolePrefetchTask: No items to fetch. Queue is empty");
                }
                return;
            }
            
            List<PrefetchRoleTokenScheduledItem> toFetch = new ArrayList<>(PREFETCH_SCHEDULED_ITEMS.size());
            synchronized (PREFETCH_SCHEDULED_ITEMS) {
                
                // if this item is to be fetched now, add it to collection
                
                for (PrefetchRoleTokenScheduledItem item : PREFETCH_SCHEDULED_ITEMS) {
                
                    // see if item expires within next two minutes
                    
                    long expiryTime = item.expiresAtUTC - (currentTime + FETCH_EPSILON + prefetchInterval);
                    if (LOG.isDebugEnabled()) {
                        final String itemName = item.sslContext == null ?
                                item.identityDomain + "." + item.identityName : item.sslContext.toString();
                        LOG.debug("RolePrefetchTask: item={} domain={} roleName={} to be expired at {}",
                                itemName, item.domainName, item.roleName, expiryTime);
                    }
                    if (isExpiredToken(expiryTime, item.minDuration, item.maxDuration, item.tokenMinExpiryTime)) {
                        if (LOG.isDebugEnabled()) {
                            final String itemName = item.sslContext == null ?
                                    item.identityDomain + "." + item.identityName : item.sslContext.toString();
                            LOG.debug("RolePrefetchTask: item={} domain={} roleName={} expired {}. Fetch this item.",
                                    itemName, item.domainName, item.roleName, expiryTime);
                        }
                        toFetch.add(item);
                    }
                }
            }
            
            // if toFetch is not empty, fetch those tokens, and add refreshed scheduled items back to the queue
            
            if (!toFetch.isEmpty()) {
                Set<String> oldSvcLoaderCache = svcLoaderCacheKeys.get();
                Set<String> newSvcLoaderCache = null;
                
                // fetch items
                
                for (PrefetchRoleTokenScheduledItem item : toFetch) {
                
                    // create ZTS Client for this particular item

                    try (ZTSClient itemZtsClient = getZTSClient(item)) {
                        
                        // use the zts client if one was given however we need
                        // reset back to the original client so we don't close
                        // our given client

                        ZTSRDLGeneratedClient savedZtsClient = itemZtsClient.ztsClient;
                        if (item.ztsClient != null) {
                            itemZtsClient.ztsClient = item.ztsClient;
                        }
                        
                        if (item.isRoleToken()) {
                            
                            // check if this came from service provider
                            
                            String key = itemZtsClient.getRoleTokenCacheKey(item.domainName, item.roleName,
                                    item.proxyForPrincipal);
                            if (oldSvcLoaderCache.contains(key)) {
                                
                                // if haven't gotten the new list of service
                                // loader tokens then get it now 
                                
                                if (newSvcLoaderCache == null) {
                                    newSvcLoaderCache = loadSvcProviderTokens();
                                }
                                
                                // check if the key is in the new key set
                                // - if not, mark the item as invalid
                                
                                if (!newSvcLoaderCache.contains(key)) {
                                    item.isInvalid(true);
                                }
                            } else {
                                RoleToken token = itemZtsClient.getRoleToken(item.domainName, item.roleName,
                                        item.minDuration, item.maxDuration, true, item.proxyForPrincipal);
                                
                                // update the expire time
                                
                                item.expiresAtUTC(token.getExpiryTime());
                            }
                        } else {
                            AWSTemporaryCredentials awsCred = itemZtsClient.getAWSTemporaryCredentials(item.domainName,
                                    item.roleName, item.externalId, item.minDuration, item.maxDuration, true);
                            item.expiresAtUTC(awsCred.getExpiration().millis() / 1000);
                        }
                        
                        // don't forget to restore the original client if case
                        // we had overridden with the caller specified client
                        
                        itemZtsClient.ztsClient = savedZtsClient;
                        
                    } catch (Exception ex) {
                        
                        // any exception should remove this item from fetch queue
                        
                        item.isInvalid(true);
                        PREFETCH_SCHEDULED_ITEMS.remove(item);
                        LOG.error("RolePrefetchTask: Error while trying to prefetch token", ex);
                    }
                }
                
                // remove all invalid items.
               
                toFetch.removeIf(p -> p.isInvalid);
                
                // now, add items back.
                
                if (!toFetch.isEmpty()) {
                    synchronized (PREFETCH_SCHEDULED_ITEMS) {
                        // make sure there are no items of common
                        PREFETCH_SCHEDULED_ITEMS.removeAll(toFetch);
                        // add them back
                        PREFETCH_SCHEDULED_ITEMS.addAll(toFetch);
                    }
                }
            }
        }
    }
    
    // method useful for test purposes only
    int getScheduledItemsSize() {
        synchronized (PREFETCH_SCHEDULED_ITEMS) {
            // ConcurrentLinkedQueue.size() method is typically not very useful in concurrent applications
            return PREFETCH_SCHEDULED_ITEMS.size();
        }
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
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, "Domain Name cannot be empty");
        }
        
        RoleToken token = getRoleToken(domainName, roleName, minExpiryTime, maxExpiryTime,
                true, proxyForPrincipal);
        if (token == null) {
            LOG.error("PrefetchToken: No token fetchable using domain={}, roleSuffix={}",
                        domainName, roleName);
            return false;
        }
        long expiryTimeUTC = token.getExpiryTime();
        
        return prefetchToken(domainName, roleName, minExpiryTime, maxExpiryTime,
                proxyForPrincipal, null, expiryTimeUTC, true);
    }
    
    boolean prefetchAwsCreds(String domainName, String roleName, String externalId,
            Integer minExpiryTime, Integer maxExpiryTime) {
        
        if (domainName == null || domainName.trim().isEmpty()) {
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, "Domain Name cannot be empty");
        }
        
        AWSTemporaryCredentials awsCred = getAWSTemporaryCredentials(domainName, roleName,
                externalId, minExpiryTime, maxExpiryTime, true);
        if (awsCred == null) {
            LOG.error("PrefetchToken: No aws credential fetchable using domain={}, roleName={}",
                        domainName, roleName);
            return false;
        }
        long expiryTimeUTC = awsCred.getExpiration().millis() / 1000;
        
        return prefetchToken(domainName, roleName, minExpiryTime, maxExpiryTime, null,
                externalId, expiryTimeUTC, false);
    }
    
    boolean prefetchToken(String domainName, String roleName, Integer minExpiryTime,
            Integer maxExpiryTime, String proxyForPrincipal, String externalId,
            long expiryTimeUTC, boolean isRoleToken) {
        
        // if we're given a ssl context then we don't have domain/service
        // settings configured otherwise those are required
        
        if (sslContext == null) {
            if (domain == null || domain.isEmpty() || service == null || service.isEmpty()) {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("PrefetchToken: setup failure. Both domain({}) and service({}) are required",
                            domain, service);
                }
                return false;
            }
        }
        
        PrefetchRoleTokenScheduledItem item = new PrefetchRoleTokenScheduledItem()
            .isRoleToken(isRoleToken)
            .domainName(domainName)
            .roleName(roleName)
            .proxyForPrincipal(proxyForPrincipal)
            .externalId(externalId)
            .minDuration(minExpiryTime)
            .maxDuration(maxExpiryTime)
            .expiresAtUTC(expiryTimeUTC)
            .identityDomain(domain)
            .identityName(service)
            .tokenMinExpiryTime(ZTSClient.tokenMinExpiryTime)
            .providedZTSUrl(this.ztsUrl)
            .siaIdentityProvider(siaProvider)
            .sslContext(sslContext)
            .proxyUrl(proxyUrl);
        
        // include our zts client only if it was overriden by
        // the caller (most likely for unit test mock)
        
        if (ztsClientOverride) {
             item.ztsClient(this.ztsClient);
        }
        
        if (!PREFETCH_SCHEDULED_ITEMS.contains(item)) {
            PREFETCH_SCHEDULED_ITEMS.add(item);
        } else {
            // contains item based on these 6 fields:
            // domainName identityDomain identityName suffix trustDomain isRoleToken
            //
            // So need to remove and append since the new token expiry has changed
            // .expiresAtUTC(token.getExpiryTime())
            //
            PREFETCH_SCHEDULED_ITEMS.remove(item);
            PREFETCH_SCHEDULED_ITEMS.add(item);
        }

        startPrefetch();
        return true;
    }

    String getAccessTokenCacheKey(String domainName, List<String> roleNames, String idTokenServiceName) {

        // if we don't have a tenant domain specified but we have a ssl context
        // then we're going to use the hash code for our sslcontext as the
        // value for our tenant

        String tenantDomain = domain;
        if (domain == null && sslContext != null) {
            tenantDomain = sslContext.toString();
        }
        return getAccessTokenCacheKey(tenantDomain, service, domainName, roleNames, idTokenServiceName);
    }

    String getAccessTokenCacheKey(String tenantDomain, String tenantService, String domainName,
            List<String> roleNames, String idTokenServiceName) {

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

        if (roleNames != null && !roleNames.isEmpty()) {
            cacheKey.append(";r=");
            cacheKey.append(ZTSClient.multipleRoleKey(roleNames));
        }

        if (idTokenServiceName != null && !idTokenServiceName.isEmpty()) {
            cacheKey.append(";o=");
            cacheKey.append(idTokenServiceName);
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

        if (roleName != null && !roleName.isEmpty()) {
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
        
        if (proxyForPrincipal != null && !proxyForPrincipal.isEmpty()) {
            cacheKey.append(";u=");
            cacheKey.append(proxyForPrincipal);
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
        
        if (maxExpiryTime != null && expiryTime > maxExpiryTime) {
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

        // before returning our cache hit we need to make sure it
        // it was at least 1/4th time left before the token expires
        // if the expiryTime is -1 then we return the token as
        // long as its not expired

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
            
            AWS_CREDS_CACHE.remove(cacheKey);
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
        try {
            return ztsClient.getRoleAccess(domainName, principal);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getMessage());
        } catch (Exception ex) {
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
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
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
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
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
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
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
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
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
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
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * For AWS Lambda functions generate a new private key, request a
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
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
        }

        // we need to generate an csr with an instance register object
        
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

        GeneralName[] sanArray = new GeneralName[2];
        final String hostBuilder = info.getService() + '.' + info.getDomain().replace('.', '-') +
                '.' + x509CsrDomain;
        sanArray[0] = new GeneralName(GeneralName.dNSName, new DERIA5String(hostBuilder));

        final String instanceHostBuilder = "lambda-" + account + '-' + info.getService() +
                ".instanceid.athenz." + x509CsrDomain;
        sanArray[1] = new GeneralName(GeneralName.dNSName, new DERIA5String(instanceHostBuilder));
        
        // next generate the csr based on our private key and data
        
        try {
            info.setCsr(Crypto.generateX509CSR(lambdaIdentity.getPrivateKey(),
                    dnBuilder.toString(), sanArray));
        } catch (OperatorCreationException | IOException ex) {
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
        }
        
        // finally obtain attestation data for lambda
        
        info.setAttestationData(getAWSLambdaAttestationData(athenzService, account));
        
        // request the x.509 certificate from zts server
        
        Map<String, List<String>> responseHeaders = new HashMap<>();
        InstanceIdentity identity = postInstanceRegisterInformation(info, responseHeaders);
        
        try {
            lambdaIdentity.setX509Certificate(Crypto.loadX509Certificate(identity.getX509Certificate()));
        } catch (CryptoException ex) {
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
        }

        lambdaIdentity.setCaCertificates(identity.getX509CertificateSigner());
        return lambdaIdentity;
    }
    
    String getAWSLambdaAttestationData(final String athenzService, final String account) {
        
        AWSAttestationData data = new AWSAttestationData();
        data.setRole(athenzService);
        
        Credentials awsCreds = assumeAWSRole(account, athenzService);
        data.setAccess(awsCreds.getAccessKeyId());
        data.setSecret(awsCreds.getSecretAccessKey());
        data.setToken(awsCreds.getSessionToken());
        
        ObjectMapper mapper = new ObjectMapper();
        String jsonData = null;
        try {
            jsonData = mapper.writeValueAsString(data);
        } catch (JsonProcessingException ex) {
            LOG.error("Unable to generate attestation json data: {}", ex.getMessage());
        }
        
        return jsonData;
    }
    
    AssumeRoleRequest getAssumeRoleRequest(String account, String roleName) {
        
        // assume the target role to get the credentials for the client
        // aws format is arn:aws:iam::<account-id>:role/<role-name>
        
        final String arn = "arn:aws:iam::" + account + ":role/" + roleName;
        
        AssumeRoleRequest req = new AssumeRoleRequest();
        req.setRoleArn(arn);
        req.setRoleSessionName(roleName);
        
        return req;
    }
    
    Credentials assumeAWSRole(String account, String roleName) {
        
        try {
            AssumeRoleRequest req = getAssumeRoleRequest(account, roleName);
            return AWSSecurityTokenServiceClientBuilder.defaultClient().assumeRole(req).getCredentials();
        } catch (Exception ex) {
            LOG.error("assumeAWSRole - unable to assume role: {}", ex.getMessage());
            return null;
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
     * @param minExpiryTime (optional) specifies that the returned RoleToken must be
     *          at least valid (min/lower bound) for specified number of seconds,
     * @param maxExpiryTime (optional) specifies that the returned RoleToken must be
     *          at most valid (max/upper bound) for specified number of seconds.
     * @return AWSCredentialsProvider AWS credential provider
     */
    public AWSCredentialsProvider getAWSCredentialProvider(String domainName, String roleName,
            String externalId, Integer minExpiryTime, Integer maxExpiryTime) {
        return new AWSCredentialsProviderImpl(this, domainName, roleName, externalId,
                minExpiryTime, maxExpiryTime);
    }

    /**
     * For a given domain and role return AWS temporary credentials
     *
     * @param domainName name of the domain
     * @param roleName is the name of the role
     * @return AWSTemporaryCredentials AWS credentials
     */
    public AWSTemporaryCredentials getAWSTemporaryCredentials(String domainName, String roleName) {
        return getAWSTemporaryCredentials(domainName, roleName, null, null, null, false);
    }

    public AWSTemporaryCredentials getAWSTemporaryCredentials(String domainName, String roleName,
            boolean ignoreCache) {
        return getAWSTemporaryCredentials(domainName, roleName, null, null, null, ignoreCache);
    }

    /**
     * For a given domain and role return AWS temporary credentials
     *
     * @param domainName name of the domain
     * @param roleName is the name of the role
     * @param minExpiryTime (optional) specifies that the returned RoleToken must be
     *          at least valid (min/lower bound) for specified number of seconds,
     * @param maxExpiryTime (optional) specifies that the returned RoleToken must be
     *          at most valid (max/upper bound) for specified number of seconds.
     * @param externalId (optional) external id to satisfy configured assume role condition
     * @return AWSTemporaryCredentials AWS credentials
     */
    public AWSTemporaryCredentials getAWSTemporaryCredentials(String domainName, String roleName,
            String externalId, Integer minExpiryTime, Integer maxExpiryTime) {
        return getAWSTemporaryCredentials(domainName, roleName, externalId,
                minExpiryTime, maxExpiryTime, false);
    }

    public AWSTemporaryCredentials getAWSTemporaryCredentials(String domainName, String roleName,
            String externalId, Integer minExpiryTime, Integer maxExpiryTime, boolean ignoreCache) {

        // since our aws role name can contain the path element thus /'s
        // we need to encode the value and use that instead
        
        try {
            roleName = URLEncoder.encode(roleName, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            LOG.error("Unable to encode {} - error {}", roleName, ex.getMessage());
        }
        
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
            awsCred = ztsClient.getAWSTemporaryCredentials(domainName, roleName,
                    maxExpiryTime, externalId);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
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
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
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
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Requests the ZTS to indicate whether or not the specific request for the
     * specified resource with authentication details will be granted or not.
     * @param action value of the action to be carried out (e.g. "UPDATE", "DELETE")
     * @param resource resource YRN. YRN is defined as {ServiceName})?:({LocationName})?:)?{ResourceName}"
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
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Requests the ZTS to indicate whether or not the specific request for the
     * specified resource with authentication details will be granted or not.
     * @param action value of the action to be carried out (e.g. "UPDATE", "DELETE")
     * @param resource resource YRN. YRN is defined as {ServiceName})?:({LocationName})?:)?{ResourceName}"
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
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Caller may post set of domain metric attributes for monitoring and logging.
     * ZTSClientException will be thrown in case of failure
     * @param domainName name of the domain
     * @param req list of domain metrics with their values
     */
    public void postDomainMetrics(String domainName, DomainMetrics req) {
        updateServicePrincipal();
        try {
            ztsClient.postDomainMetrics(domainName, req);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
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
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
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
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
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
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    static class PrefetchRoleTokenScheduledItem {
        
        boolean isRoleToken = true;
        PrefetchRoleTokenScheduledItem isRoleToken(boolean isRole) {
            isRoleToken = isRole;
            return this;
        }
        boolean isRoleToken() {
            return isRoleToken;
        }
        
        String providedZTSUrl;
        PrefetchRoleTokenScheduledItem providedZTSUrl(String u) {
            providedZTSUrl = u;
            return this;
        }
        
        ServiceIdentityProvider siaProvider;
        PrefetchRoleTokenScheduledItem siaIdentityProvider(ServiceIdentityProvider s) {
            siaProvider = s;
            return this;
        }
        
        ZTSRDLGeneratedClient ztsClient;
        PrefetchRoleTokenScheduledItem ztsClient(ZTSRDLGeneratedClient z) {
            ztsClient = z;
            return this;
        }
        
        boolean isInvalid = false;
        PrefetchRoleTokenScheduledItem isInvalid(boolean invalid) {
            isInvalid = invalid;
            return this;
        }
        
        String identityDomain;
        PrefetchRoleTokenScheduledItem identityDomain(String d) {
            identityDomain = d;
            return this;
        }
        
        String identityName;
        PrefetchRoleTokenScheduledItem identityName(String d) {
            identityName = d;
            return this;
        }
        
        String domainName;
        PrefetchRoleTokenScheduledItem domainName(String d) {
            domainName = d;
            return this;
        }
        
        String roleName;
        PrefetchRoleTokenScheduledItem roleName(String s) {
            roleName = s;
            return this;
        }
        
        String proxyForPrincipal;
        PrefetchRoleTokenScheduledItem proxyForPrincipal(String u) {
            proxyForPrincipal = u;
            return this;
        }

        String externalId;
        PrefetchRoleTokenScheduledItem externalId(String id) {
            externalId = id;
            return this;
        }

        Integer minDuration;
        PrefetchRoleTokenScheduledItem minDuration(Integer min) {
            minDuration = min;
            return this;
        }
        
        Integer maxDuration;
        PrefetchRoleTokenScheduledItem maxDuration(Integer max) {
            maxDuration = max;
            return this;
        }
        
        long expiresAtUTC;
        PrefetchRoleTokenScheduledItem expiresAtUTC(long e) {
            expiresAtUTC = e;
            return this;
        }
        
        int tokenMinExpiryTime;
        PrefetchRoleTokenScheduledItem tokenMinExpiryTime(int t) {
            tokenMinExpiryTime = t;
            return this;
        }

        SSLContext sslContext;
        PrefetchRoleTokenScheduledItem sslContext(SSLContext ctx) {
            sslContext = ctx;
            return this;
        }
        
        String proxyUrl;
        PrefetchRoleTokenScheduledItem proxyUrl(String url) {
            proxyUrl = url;
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
            result = prime * result + ((proxyForPrincipal == null) ? 0 : proxyForPrincipal.hashCode());
            result = prime * result + ((externalId == null) ? 0 : externalId.hashCode());
            result = prime * result + ((sslContext == null) ? 0 : sslContext.hashCode());
            result = prime * result + ((proxyUrl == null) ? 0 : proxyUrl.hashCode());
            result = prime * result + Boolean.hashCode(isRoleToken);
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
            PrefetchRoleTokenScheduledItem other = (PrefetchRoleTokenScheduledItem) obj;
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
            if (isInvalid != other.isInvalid) {
                return false;
            }
            if (isRoleToken != other.isRoleToken) {
                return false;
            }
            if (sslContext == null) {
                return other.sslContext == null;
            } else {
                return sslContext.equals(other.sslContext);
            }
        }
    }
    
    public class AWSHostNameVerifier implements HostnameVerifier {

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
            if (certs == null) {
                return false;
            }
            
            for (Certificate cert : certs) {
                try {
                    X509Certificate x509Cert = (X509Certificate) cert;
                    if (matchDnsHostname(x509Cert.getSubjectAlternativeNames())) {
                        return true;
                    }
                } catch (CertificateParsingException ignored) {
                }
            }
            return false;
        }
        
        boolean matchDnsHostname(Collection<List<?>> altNames) {
            
            if (altNames == null) {
                return false;
            }
            
            // GeneralName ::= CHOICE {
            //     otherName                       [0]     OtherName,
            //     rfc822Name                      [1]     IA5String,
            //     dNSName                         [2]     IA5String,
            //     x400Address                     [3]     ORAddress,
            //     directoryName                   [4]     Name,
            //     ediPartyName                    [5]     EDIPartyName,
            //     uniformResourceIdentifier       [6]     IA5String,
            //     iPAddress                       [7]     OCTET STRING,
            //     registeredID                    [8]     OBJECT IDENTIFIER}
            
            for (@SuppressWarnings("rawtypes") List item : altNames) {
                Integer type = (Integer) item.get(0);
                if (type == 2) {
                    String dns = (String) item.get(1);
                    if (dnsHostname.equalsIgnoreCase(dns)) {
                        return true;
                    }
                }
            }
            
            return false;
        }
    }
    
    private static Set<String> loadSvcProviderTokens() {
        
        ztsTokenProviders = ServiceLoader.load(ZTSClientService.class);
        svcLoaderCacheKeys = new AtomicReference<>();

        // if have service loader implementations, then stuff role tokens into cache
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
        
        Collections.sort(roles);
        return String.join(",", roles);
    }
    
    /**
     * stuff pre-loaded service token in cache. in this model an external
     * service (proxy user) has retrieved the role tokens and added to the
     * client cache so it can run without the need to contact zts server.
     * in this model we're going to look at the principal field only and
     * ignore the proxy field since the client doesn't need to know anything
     * about that detail.
     *
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
        final String tenantService  = principalName.substring(index + 1);
        Long expiryTime = rt.getExpiryTime();

        RoleToken roleToken = new RoleToken().setToken(desc.getSignedToken()).setExpiryTime(expiryTime);

        String key = getRoleTokenCacheKey(tenantDomain, tenantService, domainName, roleName, null);

        if (LOG.isInfoEnabled()) {
            LOG.info("cacheSvcProvRoleToken: cache-add key: {} expiry: {}", key, expiryTime);
        }

        ROLE_TOKEN_CACHE.put(key, roleToken);

        // setup prefetch task
        
        Long expiryTimeUTC = roleToken.getExpiryTime();
        prefetchSvcProvTokens(tenantDomain, tenantService, domainName,
            roleName, null, null, expiryTimeUTC, null);

        return key;
    }
    
    static void prefetchSvcProvTokens(String domain, String service, String domainName,
            String roleName, Integer minExpiryTime, Integer maxExpiryTime,
            Long expiryTimeUTC, String proxyForPrincipal) {
        
        if (domainName == null || domainName.trim().isEmpty()) {
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, "Domain Name cannot be empty");
        }

        PrefetchRoleTokenScheduledItem item = new PrefetchRoleTokenScheduledItem()
            .isRoleToken(true)
            .domainName(domainName)
            .roleName(roleName)
            .proxyForPrincipal(proxyForPrincipal)
            .minDuration(minExpiryTime)
            .maxDuration(maxExpiryTime)
            .expiresAtUTC(expiryTimeUTC)
            .identityDomain(domain)
            .identityName(service)
            .tokenMinExpiryTime(ZTSClient.tokenMinExpiryTime);

        //noinspection RedundantCollectionOperation
        if (PREFETCH_SCHEDULED_ITEMS.contains(item)) {
            // contains item based on these 5 fields:
            // domainName identityDomain identityName roleName proxyForProfile isRoleToken
            //
            // So need to remove and append since the new token expiry has changed
            // .expiresAtUTC(token.getExpiryTime())
            //
            PREFETCH_SCHEDULED_ITEMS.remove(item);
        }
        PREFETCH_SCHEDULED_ITEMS.add(item);
        startPrefetch();
    }

    static void startPrefetch() {

        if (FETCH_TIMER != null) {
            return;
        }

        synchronized (TIMER_LOCK) {
            if (FETCH_TIMER == null) {
                FETCH_TIMER = new Timer();
                // check the fetch items every prefetchInterval seconds.
                FETCH_TIMER.schedule(new RolePrefetchTask(), 0, prefetchInterval * 1000);
            }
        }
    }
}
