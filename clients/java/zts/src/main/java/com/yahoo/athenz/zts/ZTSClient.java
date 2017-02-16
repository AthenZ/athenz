/**
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.ServiceLoader;
import java.util.Set;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.operator.OperatorCreationException;

import org.glassfish.jersey.client.ClientProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.ServiceIdentityProvider;
import com.yahoo.athenz.auth.impl.RoleAuthority;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.config.AthenzConfig;
import com.yahoo.rdl.JSON;

public class ZTSClient implements Closeable {

    private static final Logger LOG = LoggerFactory.getLogger(ZTSClient.class);
    
    private String ztsUrl = null;
    private String domain = null;
    private String service = null;
    protected ZTSRDLGeneratedClient ztsClient;
    protected ServiceIdentityProvider siaProvider = null;

    // configurable fields
    //
    static private boolean cacheDisabled = false;
    static private int tokenMinExpiryTime = 900;
    static private long prefetchInterval = 60; // seconds
    static private boolean prefetchAutoEnable = false;
    
    @SuppressWarnings("unused")
    static private boolean initialized = initConfigValues();
    
    private boolean enablePrefetch = true;
    Principal principal = null;
    
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
    
    public static final String ROLE_TOKEN_HEADER = System.getProperty(RoleAuthority.ATHENZ_PROP_ROLE_HEADER,
            RoleAuthority.HTTP_HEADER);
    private static final String X509_CSR_DN = System.getProperty(ZTS_CLIENT_PROP_X509CSR_DN);
    private static final String X509_CSR_DOMAIN = System.getProperty(ZTS_CLIENT_PROP_X509CSR_DOMAIN);
    
    final static ConcurrentHashMap<String, RoleToken> ROLE_TOKEN_CACHE = new ConcurrentHashMap<>();
    final static ConcurrentHashMap<String, AWSTemporaryCredentials> AWS_CREDS_CACHE = new ConcurrentHashMap<>();

    private static final long FETCH_EPSILON = 60; // if cache expires in the next minute, fetch it.
    private static final Queue<PrefetchRoleTokenScheduledItem> PREFETCH_SCHEDULED_ITEMS = new ConcurrentLinkedQueue<>();
    private static Timer FETCH_TIMER;
    private static final Object TIMER_LOCK = new Object();
    static AtomicLong FETCHER_LAST_RUN_AT = new AtomicLong(-1);
    
    // allows outside implementations to get role tokens for special environments - ex. hadoop
    
    private static final ServiceLoader<ZTSClientService> ZTS_TOKEN_PROVIDERS = ServiceLoader.load(ZTSClientService.class);
    private static final AtomicReference<Set<String>> SVC_LOADER_CACHE_KEYS = new AtomicReference<>();
    static {
        loadSvcProviderTokens();
    }
    
    static boolean initConfigValues() {

        /* The minimum token expiry time by default is 15 minutes (900). By default the
         * server gives out role tokens for 2 hours and with this setting we'll be able
         * to cache tokens for 1hr45mins before requesting a new one from ZTS */

        tokenMinExpiryTime = Integer.parseInt(System.getProperty(ZTS_CLIENT_PROP_TOKEN_MIN_EXPIRY_TIME, "900"));
        if (tokenMinExpiryTime < 0) {
            tokenMinExpiryTime = 900;
        }

        prefetchInterval = Integer.parseInt(System.getProperty(ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "60"));
        if (prefetchInterval >= tokenMinExpiryTime) {
            prefetchInterval = 60;
        }

        prefetchAutoEnable = Boolean.parseBoolean(System.getProperty(ZTS_CLIENT_PROP_PREFETCH_AUTO_ENABLE, "false"));
        cacheDisabled = Boolean.parseBoolean(System.getProperty(ZTS_CLIENT_PROP_DISABLE_CACHE, "false"));
        return true;
    }
    
    /**
     * Constructs a new ZTSClient object with the given ZTS Server Url.
     * If the specified zts url is null, then it is automatically
     * retrieved from athenz.conf configuration file (ztsUrl field).
     * Default read and connect timeout values are 30000ms (30sec).
     * The application can change these values by using the
     * athenz.zts.client.read_timeout and athenz.zts.client.connct_timeout
     * system properties. The values specified for timeouts must be in
     * milliseconds. This client object can only be used for API calls
     * that require no authentication or setting the principal using
     * addCredentials method before calling any other athentication
     * protected API.
     * @param ztsUrl ZTS Server's URL (optional)
     */
    public ZTSClient(String ztsUrl) {
        initClient(ztsUrl, null, null, null, null);
        enablePrefetch = false; // can't use this domain and service for prefetch
    }
    
    /**
     * Constructs a new ZTSClient object with the given principal identity
     * and ZTS Server Url. If the specified zts url is null, then it is
     * automatically retrieved from athenz.conf configuration file
     * (ztsUrl field). Default read and connect timeout values are
     * 30000ms (30sec). The application can change these values by using the
     * athenz.zts.client.read_timeout and athenz.zts.client.connct_timeout
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
     * Constructs a new ZTSClient object with the given service details
     * identity provider (which will provide the ntoken for the service)
     * and ZTS Server Url. If the specified zts url is null, then it is
     * automatically retrieved from athenz.conf configuration file
     * (ztsUrl field). Default read and connect timeout values are
     * 30000ms (30sec). The application can change these values by using the
     * athenz.zts.client.read_timeout and athenz.zts.client.connct_timeout
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
    
    void removePrefetcher() {
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
    }
    
    String lookupZTSUrl() {
        
        String rootDir = System.getenv("ROOT");
        if (rootDir == null) {
            rootDir = "/home/athenz";
        }
        
        String confFileName = System.getProperty(ZTS_CLIENT_PROP_ATHENZ_CONF,
                rootDir + "/conf/athenz/athenz.conf");
        String url = null;
        try {
            Path path = Paths.get(confFileName);
            AthenzConfig conf = JSON.fromBytes(Files.readAllBytes(path), AthenzConfig.class);
            url = conf.getZtsUrl();
        } catch (Exception ex) {
            // if we have a zts client service specified and we have keys
            // in our service loader cache then we're running within
            // some managed framework (e.g. hadoop) so we're going to
            // report this exception as a warning rather than an error
            // and default to localhost as the url to avoid further
            // warnings from our generated client

            if (!SVC_LOADER_CACHE_KEYS.get().isEmpty()) {
                LOG.warn("Unable to extract ZTS Url from conf file {}, exc: {}",
                        confFileName, ex.getMessage());
                url = "https://localhost:4443/";
            } else {
                LOG.error("Unable to extract ZTS Url from conf file {}, exc: {}",
                        confFileName, ex.getMessage());
            }
        }
        
        return url;
    }
    
    void initClient(String url, Principal identity, String domainName, String serviceName,
            ServiceIdentityProvider siaProvider) {
        
        if (url == null) {
            ztsUrl = lookupZTSUrl();
        } else {
            ztsUrl = url;
        }
        
        /* verify if the url is ending with /zts/v1 and if it's
         * not we'll automatically append it */
        
        if (ztsUrl != null && !ztsUrl.isEmpty()) {
            if (!ztsUrl.endsWith("/zts/v1")) {
                if (ztsUrl.charAt(ztsUrl.length() - 1) != '/') {
                    ztsUrl += '/';
                }
                ztsUrl += "zts/v1";
            }
        }
        
        /* determine our read and connect timeouts */
            
        int readTimeout = Integer.parseInt(System.getProperty(ZTS_CLIENT_PROP_READ_TIMEOUT, "30000"));
        int connectTimeout = Integer.parseInt(System.getProperty(ZTS_CLIENT_PROP_CONNECT_TIMEOUT, "30000"));
        String x509CertDNSName = System.getProperty(ZTS_CLIENT_PROP_X509CERT_DNS_NAME);
        HostnameVerifier hostnameVerifier = null;
        if (x509CertDNSName != null && !x509CertDNSName.isEmpty()) {
            hostnameVerifier = new AWSHostNameVerifier(x509CertDNSName);
        }
            
        ztsClient = new ZTSRDLGeneratedClient(ztsUrl, hostnameVerifier)
                .setProperty(ClientProperties.CONNECT_TIMEOUT, connectTimeout)
                .setProperty(ClientProperties.READ_TIMEOUT, readTimeout);
        
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
     * Clear the principal identity set for the client. Unless a new principal is set
     * using the addCredentials method, the client can only be used to requests data
     * from the ZTS Server that doesn't require any authentication.
     * @param identity Principal identity for authenticating requests
     * @return self ZTSClient object
     */
    public ZTSClient addCredentials(Principal identity) {
        return addPrincipalCredentials(identity, true);
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
        
        /* if we have a service principal then we need to keep updating
         * our PrincipalToken otherwise it might expire. */
        
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
            String msg = "UpdateServicePrincipal: Unable to get PrincipalToken "
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
     * @param roleName only interested in roles with this name
     * @return ZTS generated Role Token. ZTSClientException will be thrown in case of failure
     */
    public RoleToken getRoleToken(String domainName, String roleName) {
        if (roleName == null || roleName.isEmpty()) {
            throw new IllegalArgumentException("RoleName cannot be null or empty");
        }
        return getRoleToken(domainName, roleName, null, null, false, null);
    }
    
    /**
     * For the specified requester(user/service) return the corresponding Role Token that
     * includes the list of roles that the principal has access to in the specified domain
     * @param domainName name of the domain
     * @param roleName (optional) only interested in roles with this name
     * @param minExpiryTime (optional) specifies that the returned RoleToken must be
     *          at least valid (min/lower bound) for specified number of seconds,
     * @param maxExpiryTime (optional) specifies that the returned RoleToken must be
     *          at most valid (max/upper bound) for specified number of seconds.
     * @param ignoreCache ignore the cache and retrieve the token from ZTS Server
     * @return ZTS generated Role Token. ZTSClientException will be thrown in case of failure
     */
    public RoleToken getRoleToken(String domainName, String roleName, Integer minExpiryTime,
            Integer maxExpiryTime, boolean ignoreCache) {
        return getRoleToken(domainName, roleName, minExpiryTime, maxExpiryTime,
                ignoreCache, null);
    }
    
    /**
     * For the specified requester(user/service) return the corresponding Role Token that
     * includes the list of roles that the principal has access to in the specified domain
     * @param domainName name of the domain
     * @param roleName (optional) only interested in roles with this name
     * @param minExpiryTime (optional) specifies that the returned RoleToken must be
     *          at least valid (min/lower bound) for specified number of seconds,
     * @param maxExpiryTime (optional) specifies that the returned RoleToken must be
     *          at most valid (max/upper bound) for specified number of seconds.
     * @param ignoreCache ignore the cache and retrieve the token from ZTS Server
     * @param proxyForPrincipal (optional) this request is proxy for this principal
     * @return ZTS generated Role Token. ZTSClientException will be thrown in case of failure
     */
    public RoleToken getRoleToken(String domainName, String roleName, Integer minExpiryTime,
            Integer maxExpiryTime, boolean ignoreCache, String proxyForPrincipal) {
        
        RoleToken roleToken = null;
        
        // first lookup in our cache to see if it can be satisfied
        // only if we're not asked to ignore the cache

        String cacheKey = null;
        if (!cacheDisabled) {
            cacheKey = getRoleTokenCacheKey(domainName, roleName, proxyForPrincipal);
            if (cacheKey != null && !ignoreCache) {
                roleToken = lookupRoleTokenInCache(cacheKey, minExpiryTime, maxExpiryTime);
                if (roleToken != null) {
                    return roleToken;
                }
                // start prefetch for this token if prefetch is enabled
                if (enablePrefetch && prefetchAutoEnable) {
                    if (prefetchRoleToken(domainName, roleName, minExpiryTime, maxExpiryTime,
                            proxyForPrincipal)) {
                        roleToken = lookupRoleTokenInCache(cacheKey, minExpiryTime, maxExpiryTime);
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
        for (ZTSClientService provider: ZTS_TOKEN_PROVIDERS) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("getRoleToken: found service provider=" + provider);
            }
            
            // provider needs to know who the client is so we'll be passing
            // the client's domain and service names as the first two fields
            
            roleToken = provider.fetchToken(domain, service, domainName, roleName,
                    minExpiryTime, maxExpiryTime, proxyForPrincipal);
            if (roleToken != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("getRoleToken: service provider=" + provider + " returns token");
                }
                return roleToken;
            }
        }
        
        // if no hit then we need to request a new token from ZTS
        
        updateServicePrincipal();
        try {
            roleToken = ztsClient.getRoleToken(domainName, roleName,
                    minExpiryTime, maxExpiryTime, proxyForPrincipal);
        } catch (ResourceException ex) {
            throw new ZTSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
        }
        
        // need to add the token to our cache. If our principal was
        // updated then we need to retrieve a new cache key
        
        if (!cacheDisabled) {
            if (cacheKey == null) {
                cacheKey = getRoleTokenCacheKey(domainName, roleName, proxyForPrincipal);
            }
            if (cacheKey != null) {
                ROLE_TOKEN_CACHE.put(cacheKey, roleToken);
            }
        }
        return roleToken;
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
     * @param cloud string identifying the environment, e.g. aws
     * @param expiryTime number of seconds to request certificate to be valid for
     * @return RoleCertificateRequest object
     */
    static public RoleCertificateRequest generateRoleCertificateRequest(String principalDomain,
            String principalService, String roleDomainName, String roleName, PrivateKey privateKey,
            String cloud, int expiryTime) {
        
        if (principalDomain == null || principalService == null) {
            throw new IllegalArgumentException("Principal's Domain and Service must be specified");
        }
        
        if (roleDomainName == null || roleName == null) {
            throw new IllegalArgumentException("Role DomainName and Name must be specified");
        }
        
        // Athens uses lower case for all elements, so let's
        // generate our dn which will be our role resource value
        
        principalDomain = principalDomain.toLowerCase();
        principalService = principalService.toLowerCase();
        
        roleDomainName = roleDomainName.toLowerCase();
        roleName = roleName.toLowerCase();
        final String dn = "cn=" + roleDomainName + ":role." + roleName + "," + X509_CSR_DN;
        
        // now let's generate our dsnName and email fields which will based on
        // our principal's details
        
        StringBuilder hostBuilder = new StringBuilder(128);
        hostBuilder.append(principalService);
        hostBuilder.append('.');
        hostBuilder.append(principalDomain.replace('.', '-'));
        hostBuilder.append('.');
        hostBuilder.append(cloud);
        hostBuilder.append('.');
        hostBuilder.append(X509_CSR_DOMAIN);
        String hostName = hostBuilder.toString();

        String email = principalDomain + "." + principalService + "@" + cloud + "." + X509_CSR_DOMAIN;
        
        GeneralName[] sanArray = new GeneralName[2];
        sanArray[0] = new GeneralName(GeneralName.dNSName, new DERIA5String(hostName));
        sanArray[1] = new GeneralName(GeneralName.rfc822Name, new DERIA5String(email));
        
        String csr = null;
        try {
            csr = Crypto.generateX509CSR(privateKey, dn, sanArray);
        } catch (OperatorCreationException | IOException ex) {
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
        }
        
        RoleCertificateRequest req = new RoleCertificateRequest().setCsr(csr)
                .setExpiryTime(Long.valueOf(expiryTime));
        return req;
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
        
        if (principalDomain == null || principalService == null) {
            throw new IllegalArgumentException("Principal's Domain and Service must be specified");
        }
        
        // Athenz uses lower case for all elements, so let's
        // generate our dn which will be based on our service name
        
        principalDomain = principalDomain.toLowerCase();
        principalService = principalService.toLowerCase();
        final String cn = principalDomain + "." + principalService;
        
        final String dn = "cn=" + cn + "," + X509_CSR_DN;
        
        // now let's generate our dsnName field based on our principal's details
        
        StringBuilder hostBuilder = new StringBuilder(128);
        hostBuilder.append(principalService);
        hostBuilder.append('.');
        hostBuilder.append(principalDomain.replace('.', '-'));
        hostBuilder.append('.');
        hostBuilder.append(cloud);
        hostBuilder.append('.');
        hostBuilder.append(X509_CSR_DOMAIN);
        String hostName = hostBuilder.toString();
        
        GeneralName[] sanArray = new GeneralName[1];
        sanArray[0] = new GeneralName(GeneralName.dNSName, new DERIA5String(hostName));
        
        String csr = null;
        try {
            csr = Crypto.generateX509CSR(privateKey, dn, sanArray);
        } catch (OperatorCreationException | IOException ex) {
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
        }
        
        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(csr)
                .setExpiryTime(Integer.valueOf(expiryTime));
        return req;
    }
    
    private static class RolePrefetchTask extends TimerTask {
        
        @Override
        public void run() {
            long currentTime = System.currentTimeMillis() / 1000;
            FETCHER_LAST_RUN_AT.set(currentTime);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("RolePrefetchTask: Fetching role token from the scheduled queue. Size=" + PREFETCH_SCHEDULED_ITEMS.size());
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
                        LOG.debug("RolePrefetchTask: item=" + item.identityDomain + "." + item.identityName
                                + " domain=" + item.domainName + " suffix=" + item.roleName
                                + ": to be expired at " + expiryTime);
                    }
                    if (isExpiredToken(expiryTime, item.minDuration, item.maxDuration, item.tokenMinExpiryTime)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("RolePrefetchTask: item=" + item.identityDomain + "."
                                    + item.identityName + " domain=" + item.domainName
                                    + " roleName=" + item.roleName + ": expired. Fetch this item. " + expiryTime);
                        }
                        toFetch.add(item);
                    }
                }
            }
            
            // if toFetch is not empty, fetch those tokens, and add refreshed scheduled items back to the queue
            if (!toFetch.isEmpty()) {
                Set<String> oldSvcLoaderCache = SVC_LOADER_CACHE_KEYS.get();
                Set<String> newSvcLoaderCache = null;
                // fetch items
                for (PrefetchRoleTokenScheduledItem item : toFetch) {
                    // create ZTS Client for this particular item
                    try (ZTSClient itemZtsClient = new ZTSClient(item.providedZTSUrl,
                            item.identityDomain, item.identityName, item.siaProvider)) {
                        if (item.ztsClient != null) {
                            itemZtsClient.ztsClient = item.ztsClient;
                        }
                        if (item.isRoleToken()) {
                            // check if this came from service provider
                            //
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
                                    item.invalid(true);
                                }
                            } else {
                                RoleToken token = itemZtsClient.getRoleToken(item.domainName, item.roleName,
                                        item.minDuration, item.maxDuration, true, item.proxyForPrincipal);
                                // update the expire time
                                item.expiresAtUTC(token.getExpiryTime());
                            }
                        } else {
                            AWSTemporaryCredentials awsCred = itemZtsClient.getAWSTemporaryCredentials(item.domainName,
                                    item.roleName, true);
                            item.expiresAtUTC(awsCred.getExpiration().millis() / 1000);
                        }
                    } catch (Exception ex) {
                        // any exception should remove this item from fetch queue
                        item.invalid(true);
                        PREFETCH_SCHEDULED_ITEMS.remove(item);
                        LOG.error("RolePrefetchTask: Error while trying to prefetch token, msg="
                                + ex.getMessage(), ex);
                    }
                }
                
                // remove all invalid items.
                toFetch.removeIf(p -> p.invalid);
                
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
        return prefetchToken(domainName, roleName, minExpiryTime, maxExpiryTime,
                proxyForPrincipal, true);
    }
    
    boolean prefetchAwsCred(String domainName, String roleName, Integer minExpiryTime,
            Integer maxExpiryTime) {
        return prefetchToken(domainName, roleName, minExpiryTime, maxExpiryTime, null, false);
    }
    
    boolean prefetchToken(String domainName, String roleName, Integer minExpiryTime,
            Integer maxExpiryTime, String proxyForPrincipal, boolean isRoleToken) {
        
        if (domainName == null || domainName.trim().isEmpty()) {
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, "Domain Name cannot be empty");
        }
        
        long expiryTimeUTC = 0;
        if (isRoleToken) {
            RoleToken token = getRoleToken(domainName, roleName, minExpiryTime, maxExpiryTime, true, proxyForPrincipal);
            if (token == null) {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("PrefetchToken: No token fetchable using given params, domain=" + domainName
                        + ", roleSuffix=" + roleName);
                }
                return false;
            }
            expiryTimeUTC = token.getExpiryTime();
        } else {
            AWSTemporaryCredentials awsCred = getAWSTemporaryCredentials(domainName, roleName, true);
            if (awsCred == null) {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("PrefetchToken: No aws credential fetchable using given params, domain=" + domainName
                        + ", roleName=" + roleName);
                }
                return false;
            }
            expiryTimeUTC = awsCred.getExpiration().millis() / 1000;
        }

        if (enablePrefetch == false || domain == null || domain.isEmpty() || service == null || service.isEmpty()) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("PrefetchToken: Failure to setup ongoing prefetch of tokens. Both domain("
                        + domain + ") and service(" + service + ") is required");
            }
            return false;
        }
        PrefetchRoleTokenScheduledItem item = new PrefetchRoleTokenScheduledItem()
            .isRoleToken(isRoleToken)
            .domainName(domainName)
            .roleName(roleName)
            .proxyForPrincipal(proxyForPrincipal)
            .minDuration(minExpiryTime)
            .maxDuration(maxExpiryTime)
            .expiresAtUTC(expiryTimeUTC)
            .identityDomain(domain)
            .identityName(service)
            .tokenMinExpiryTime(ZTSClient.tokenMinExpiryTime)
            .providedZTSUrl(this.ztsUrl)
            .ztsClient(this.ztsClient)
            .siaIdentityProvider(siaProvider);
        
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

        if (FETCH_TIMER == null) {
            synchronized (TIMER_LOCK) {
                if (FETCH_TIMER == null) {
                    FETCH_TIMER = new Timer();
                    // check the fetch items every prefetchInterval seconds.
                    FETCH_TIMER.schedule(new RolePrefetchTask(), 0, prefetchInterval * 1000);
                }
            }
        }

        return true;
    }
    
    String getRoleTokenCacheKey(String domainName, String roleName, String proxyForPrincipal) {
        return getRoleTokenCacheKey(domain, service, domainName, roleName, proxyForPrincipal);
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
            cacheKey.append(roleName);
        }
        if (proxyForPrincipal != null && !proxyForPrincipal.isEmpty()) {
            cacheKey.append(";u=");
            cacheKey.append(proxyForPrincipal);
        }
        
        return cacheKey.toString();
    }
    
    boolean isExpiredToken(long expiryTime, Integer minExpiryTime, Integer maxExpiryTime) {
        return isExpiredToken(expiryTime, minExpiryTime, maxExpiryTime, ZTSClient.tokenMinExpiryTime);
    }
    
    static boolean isExpiredToken(long expiryTime, Integer minExpiryTime, Integer maxExpiryTime, int tokenMinExpiryTime) {
        
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
        
        if (minExpiryTime == null && maxExpiryTime == null && expiryTime < tokenMinExpiryTime) {
            return true;
        }
        
        return false;
    }
    
    RoleToken lookupRoleTokenInCache(String cacheKey, Integer minExpiryTime, Integer maxExpiryTime) {

        RoleToken roleToken = ROLE_TOKEN_CACHE.get(cacheKey);
        if (roleToken == null) {
            if (LOG.isInfoEnabled()) {
                LOG.info("LookupRoleTokenInCache: cache-lookup key: " + cacheKey + " result: not found");
            }
            return null;
        }
        
        // before returning our cache hit we need to make sure it
        // satisfies the time requirements as specified by the client
        
        long expiryTime = roleToken.getExpiryTime() - (System.currentTimeMillis() / 1000);
        
        if (isExpiredToken(expiryTime, minExpiryTime, maxExpiryTime, tokenMinExpiryTime)) {
            
            if (LOG.isInfoEnabled()) {
                LOG.info("LookupRoleTokenInCache: role-cache-lookup key: " + cacheKey + " token-expiry: " + expiryTime
                        + " req-min-expiry: " + minExpiryTime + " req-max-expiry: " + maxExpiryTime
                        + " client-min-expiry: " + tokenMinExpiryTime + " result: expired");
            }
            
            ROLE_TOKEN_CACHE.remove(cacheKey);
            return null;
        }
        
        return roleToken;
    }
    
    AWSTemporaryCredentials lookupAwsCredInCache(String cacheKey, Integer minExpiryTime,
            Integer maxExpiryTime) {

        AWSTemporaryCredentials awsCred = AWS_CREDS_CACHE.get(cacheKey);
        if (awsCred == null) {
            if (LOG.isInfoEnabled()) {
                LOG.info("LookupAwsCredInCache: aws-cache-lookup key: " + cacheKey + " result: not found");
            }
            return null;
        }
        
        // before returning our cache hit we need to make sure it
        // satisfies the time requirements as specified by the client
        
        long expiryTime = awsCred.getExpiration().millis() - System.currentTimeMillis();
        expiryTime /= 1000;  // expiry time is in seconds
        
        if (isExpiredToken(expiryTime, minExpiryTime, maxExpiryTime, tokenMinExpiryTime)) {
            
            if (LOG.isInfoEnabled()) {
                LOG.info("LookupAwsCredInCache: aws-cache-lookup key: " + cacheKey + " token-expiry: " + expiryTime
                        + " req-min-expiry: " + minExpiryTime + " req-max-expiry: " + maxExpiryTime
                        + " client-min-expiry: " + tokenMinExpiryTime + " result: expired");
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
     * For a given domain and role return AWS temporary credentials
     * @param domainName name of the domain
     * @param roleName is the name of the role
     * @return AWSTemporaryCredentials AWS credentials
     */
    public AWSTemporaryCredentials getAWSTemporaryCredentials(String domainName, String roleName) {
        
        return getAWSTemporaryCredentials(domainName, roleName, false);
    }
    
    public AWSTemporaryCredentials getAWSTemporaryCredentials(String domainName, String roleName,
            boolean ignoreCache) {

        // first lookup in our cache to see if it can be satisfied
        // only if we're not asked to ignore the cache
        
        AWSTemporaryCredentials awsCred = null;
        String cacheKey = getRoleTokenCacheKey(domainName, roleName, null);
        if (cacheKey != null && !ignoreCache) {
            awsCred = lookupAwsCredInCache(cacheKey, null, null);
            if (awsCred != null) {
                return awsCred;
            }
            // start prefetch for this token if prefetch is enabled
            if (enablePrefetch && prefetchAutoEnable) {
                if (prefetchAwsCred(domainName, roleName, null, null)) {
                    awsCred = lookupAwsCredInCache(cacheKey, null, null);
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
            awsCred = ztsClient.getAWSTemporaryCredentials(domainName, roleName);
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
            DomainSignedPolicyData sp = ztsClient.getDomainSignedPolicyData(domainName, matchingTag, responseHeaders);
            return sp;
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
        
        boolean invalid;
        PrefetchRoleTokenScheduledItem invalid(boolean i) {
            invalid = i;
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

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((domainName == null) ? 0 : domainName.hashCode());
            result = prime * result + ((identityDomain == null) ? 0 : identityDomain.hashCode());
            result = prime * result + ((identityName == null) ? 0 : identityName.hashCode());
            result = prime * result + ((roleName == null) ? 0 : roleName.hashCode());
            result = prime * result + ((proxyForPrincipal == null) ? 0 : proxyForPrincipal.hashCode());
            result = prime * result + Boolean.hashCode(isRoleToken);

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
            return true;
        }

    }
    
    public class AWSHostNameVerifier implements HostnameVerifier {

        String dnsHostname = null;
        
        public AWSHostNameVerifier(String hostname) {
            dnsHostname = hostname;
        }
        
        @Override
        public boolean verify(String hostname, SSLSession session) {

            Certificate[] certs = null;
            try {
                certs = session.getPeerCertificates();
            } catch (SSLPeerUnverifiedException e) {
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
                } catch (CertificateParsingException e) {
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
        
        // if have service loader implementations, then stuff role tokens into cache
        // and keep track of these tokens so that they will get refreshed from
        // service loader and not zts server
        
        Set<String> cacheKeySet = new HashSet<>();
        for (ZTSClientService provider: ZTS_TOKEN_PROVIDERS) {
            Collection<ZTSClientService.RoleTokenDescriptor> descs = provider.loadTokens();
            if (descs == null) {
                if (LOG.isInfoEnabled()) {
                    LOG.info("loadSvcProviderTokens: provider didn't return tokens: prov=" + provider);
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

        SVC_LOADER_CACHE_KEYS.set(cacheKeySet);
        return cacheKeySet;
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
        List<String> roles = rt.getRoles();
        
        // before doing anything else we need to see if we can cache this
        // token - the requirement is either we have a full set or
        // if it's not then we must have a single role in the list
        
        if (!completeRoleSet && roles.size() != 1) {
            LOG.error("cacheSvcProvRoleToken: Unable to determine original rolename query: "
                    + rt.getUnsignedToken());
            return null;
        }
        
        // if the role token was for a complete set then we're not going
        // to use the rolename field (it indicates that the original request
        // was completed without the rolename field being specified)
        
        final String roleName = (completeRoleSet) ? null : rt.getRoles().get(0);
        
        // parse principalName for the tenant domain and service name
        // we must have valid components otherwise we'll just
        // ignore the token - you can't have a principal without
        // valid domain and service names
        
        int index = principalName.lastIndexOf('.'); // ex: cities.burbank.mysvc
        if (index == -1) {
            LOG.error("cacheSvcProvRoleToken: Invalid principal in token: "  + rt.getSignedToken());
            return null;
        }

        final String tenantDomain = principalName.substring(0, index);
        final String tenantService  = principalName.substring(index + 1);
        Long expiryTime = rt.getExpiryTime();

        RoleToken roleToken = new RoleToken().setToken(desc.getSignedToken()).setExpiryTime(expiryTime);

        String key = getRoleTokenCacheKey(tenantDomain, tenantService, domainName, roleName, null);

        if (LOG.isInfoEnabled()) {
            LOG.info("cacheSvcProvRoleToken: cache-add key: " + key + " expiry: " + expiryTime);
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

        if (FETCH_TIMER == null) {
            synchronized (TIMER_LOCK) {
                if (FETCH_TIMER == null) {
                    FETCH_TIMER = new Timer();
                    // check the fetch items every prefetchInterval seconds.
                    FETCH_TIMER.schedule(new RolePrefetchTask(), 0, prefetchInterval * 1000);
                }
            }
        }
    }
}
