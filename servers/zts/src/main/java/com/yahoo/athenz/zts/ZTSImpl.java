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

import java.io.File;
import java.net.InetAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.EntityTag;
import javax.ws.rs.core.Response;

import com.yahoo.athenz.auth.token.AccessToken;
import com.yahoo.athenz.auth.token.IdToken;
import com.yahoo.athenz.auth.util.StringUtils;
import com.yahoo.athenz.common.server.cert.X509CertRecord;
import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.common.server.dns.HostnameResolverFactory;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import com.yahoo.athenz.common.server.ssh.SSHCertRecord;
import com.yahoo.athenz.common.server.status.StatusCheckException;
import com.yahoo.athenz.common.server.status.StatusChecker;
import com.yahoo.athenz.common.server.status.StatusCheckerFactory;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.common.server.store.ChangeLogStoreFactory;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.zms.RoleMeta;
import com.yahoo.athenz.zts.cert.*;
import com.yahoo.athenz.zts.notification.ZTSNotificationTaskFactory;
import com.yahoo.athenz.zts.store.CloudStore;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.AuthorityKeyStore;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.PrivateKeyStoreFactory;
import com.yahoo.athenz.auth.ServerPrivateKey;
import com.yahoo.athenz.auth.impl.CertificateAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.metrics.MetricFactory;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.log.AuditLoggerFactory;
import com.yahoo.athenz.common.server.rest.Http;
import com.yahoo.athenz.common.server.rest.Http.AuthorityList;
import com.yahoo.athenz.common.server.util.ConfigProperties;
import com.yahoo.athenz.common.server.util.ServletRequestUtil;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.athenz.zts.utils.ZTSUtils;
import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.Validator;
import com.yahoo.rdl.Validator.Result;

import static com.yahoo.athenz.common.ServerCommonConsts.*;

/**
 * An implementation of ZTS.
 */
public class ZTSImpl implements KeyStore, ZTSHandler {

    private static String ROOT_DIR;

    protected DataStore dataStore;
    protected CloudStore cloudStore;
    protected InstanceCertManager instanceCertManager;
    protected InstanceProviderManager instanceProviderManager;
    protected Metric metric = null;
    protected Schema schema = null;
    protected ServerPrivateKey privateKey = null;
    protected ServerPrivateKey privateECKey = null;
    protected ServerPrivateKey privateRSAKey = null;
    protected PrivateKeyStore privateKeyStore = null;
    protected HostnameResolver hostnameResolver = null;
    protected int roleTokenDefaultTimeout;
    protected int roleTokenMaxTimeout;
    protected int idTokenMaxTimeout;
    protected long x509CertRefreshResetTime;
    protected long signedPolicyTimeout;
    protected static String serverHostName = null;
    protected AuditLogger auditLogger = null;
    protected String serverRegion = null;
    protected String userDomain;
    protected String userDomainPrefix;
    protected String userDomainAlias;
    protected String userDomainAliasPrefix;
    protected boolean leastPrivilegePrincipal = false;
    protected boolean singleDomainInRoleCert = false;
    protected Set<String> authorizedProxyUsers = null;
    protected Set<String> validCertSubjectOrgValues = null;
    protected Set<String> validCertSubjectOrgUnitValues = null;
    protected Set<String> validateServiceSkipDomains;
    protected boolean secureRequestsOnly = true;
    protected int svcTokenTimeout = 86400;
    protected Set<String> authFreeUriSet = null;
    protected List<Pattern> authFreeUriList = null;
    protected int httpPort;
    protected int httpsPort;
    protected int statusPort;
    protected boolean statusCertSigner = false;
    protected Status successServerStatus = null;
    protected boolean includeRoleCompleteFlag = true;
    protected boolean readOnlyMode = false;
    protected boolean verifyCertRequestIP = false;
    protected boolean verifyCertSubjectOU = false;
    protected String ztsOAuthIssuer;
    protected File healthCheckFile = null;

    private static final String TYPE_DOMAIN_NAME = "DomainName";
    private static final String TYPE_SIMPLE_NAME = "SimpleName";
    private static final String TYPE_ENTITY_NAME = "EntityName";
    private static final String TYPE_ENTITY_LIST = "EntityList";
    private static final String TYPE_SERVICE_NAME = "ServiceName";
    private static final String TYPE_INSTANCE_REGISTER_INFO = "InstanceRegisterInformation";
    private static final String TYPE_INSTANCE_REFRESH_INFO = "InstanceRefreshInformation";
    private static final String TYPE_INSTANCE_REFRESH_REQUEST = "InstanceRefreshRequest";
    private static final String TYPE_DOMAIN_METRICS = "DomainMetrics";
    private static final String TYPE_ROLE_CERTIFICATE_REQUEST = "RoleCertificateRequest";
    private static final String TYPE_SSH_CERT_REQUEST = "SSHCertRequest";
    private static final String TYPE_COMPOUND_NAME = "CompoundName";
    private static final String TYPE_RESOURCE_NAME = "ResourceName";
    private static final String TYPE_PATH_ELEMENT = "PathElement";
    private static final String TYPE_AWS_ARN_ROLE_NAME = "AWSArnRoleName";
    
    private static final String ZTS_ROLE_TOKEN_VERSION = "Z1";
    private static final String ZTS_REQUEST_LOG_SKIP_QUERY = "com.yahoo.athenz.uri.skip_query";

    private static final long ZTS_NTOKEN_DEFAULT_EXPIRY = TimeUnit.SECONDS.convert(2, TimeUnit.HOURS);
    private static final long ZTS_NTOKEN_MAX_EXPIRY = TimeUnit.SECONDS.convert(7, TimeUnit.DAYS);

    // HTTP operation types used in metrics
    private static final String HTTP_GET = "GET";
    private static final String HTTP_POST = "POST";
    private static final String HTTP_REQUEST = "REQUEST";

    private static final String KEY_SCOPE = "scope";
    private static final String KEY_GRANT_TYPE = "grant_type";
    private static final String KEY_EXPIRES_IN = "expires_in";
    private static final String KEY_PROXY_FOR_PRINCIPAL = "proxy_for_principal";

    private static final String OAUTH_GRANT_CREDENTIALS = "client_credentials";
    private static final String OAUTH_BEARER_TOKEN = "Bearer";

    private static final String USER_AGENT_HDR = "User-Agent";

    // domain metrics prefix
    private static final String DOM_METRIX_PREFIX = "dom_metric_";

    private static final String ACCESS_LOG_ADDL_QUERY = "com.yahoo.athenz.uri.addl_query";

    private static final Logger LOGGER = LoggerFactory.getLogger(ZTSImpl.class);
    
    protected Http.AuthorityList authorities = null;
    protected ZTSAuthorizer authorizer;
    protected static Validator validator;
    protected NotificationManager notificationManager = null;
    protected StatusChecker statusChecker = null;

    enum AthenzObject {
        DOMAIN_METRICS {
            void convertToLowerCase(Object obj) {
                DomainMetrics metrics = (DomainMetrics) obj;
                metrics.setDomainName(metrics.getDomainName().toLowerCase());
            }
        },
        INSTANCE_REGISTER_INFO {
            void convertToLowerCase(Object obj) {
                InstanceRegisterInformation info = (InstanceRegisterInformation) obj;
                info.setDomain(info.getDomain().toLowerCase());
                info.setService(info.getService().toLowerCase());
                info.setProvider(info.getProvider().toLowerCase());
            }
        },
        LIST {
            void convertToLowerCase(Object obj) {
                @SuppressWarnings("unchecked")
                List<String> list = (List<String>) obj;
                if (list != null) {
                    ListIterator<String> iter = list.listIterator();
                    while (iter.hasNext()) {
                        iter.set(iter.next().toLowerCase());
                    }
                }
            }
        },
        SSH_CERT_REQUEST {
            void convertToLowerCase(Object obj) {
                SSHCertRequest req = (SSHCertRequest) obj;
                LIST.convertToLowerCase(req.getCertRequestData().getPrincipals());
                req.getCertRequestMeta().setRequestor(req.getCertRequestMeta().getRequestor().toLowerCase());
            }
        };

        abstract void convertToLowerCase(Object obj);
    }
    
    enum ServiceX509RefreshRequestStatus {
        SUCCESS, DNS_NAME_MISMATCH, PUBLIC_KEY_MISMATCH, IP_NOT_ALLOWED
     }
    
    public ZTSImpl() {
        this(null, null);
    }
    
    public ZTSImpl(CloudStore implCloudStore, DataStore implDataStore) {
        
        // before doing anything else we need to load our
        // system properties from our config file
        
        loadSystemProperties();
        
        // let's first get our server hostname

        ZTSImpl.serverHostName = getServerHostName();
        
        // before we do anything we need to load our configuration
        // settings
        
        loadConfigurationSettings();
        
        // load our schema validator - we need this before we initialize
        // our store, if necessary
        
        loadSchemaValidator();
        
        // let's load our audit logger
        
        loadAuditLogger();
        
        // load any configured authorities to authenticate principals
        
        loadAuthorities();
        
        // we need a private key to sign any tokens and documents
        
        loadServicePrivateKey();
        
        // check if we need to load any metric support for stats
        
        loadMetricObject();

        // check if we need to load our hostname resolver for cert requests

        loadHostnameResolver();

       // create our cloud store if configured

        cloudStore = (implCloudStore == null) ? new CloudStore() : implCloudStore;

        // create our change log store
        
        if (implDataStore == null) {
            String homeDir = System.getProperty(ZTSConsts.ZTS_PROP_CHANGE_LOG_STORE_DIR,
                    getRootDir() + "/var/zts_server");
            ChangeLogStore clogStore = getChangeLogStore(homeDir);
    
            // create our data store. we must have our cloud store and private
            // key details already retrieved at this point
            
            dataStore = new DataStore(clogStore, cloudStore);
            
            // Initialize our storage subsystem which would load all data into
            // memory and if necessary retrieve the data from ZMS. It will also
            // create the thread to monitor for changes from ZMS
            
            dataStore.init();
            
        } else {
            dataStore = implDataStore;
        }

        // set our authorizer

        authorizer = new ZTSAuthorizer(dataStore);

        // create our instance manager and provider
        
        instanceCertManager = new InstanceCertManager(privateKeyStore, authorizer, hostnameResolver, readOnlyMode);

        instanceProviderManager = new InstanceProviderManager(dataStore,
                ZTSUtils.createServerClientSSLContext(privateKeyStore), this);
        
        // make sure to set the keystore for any instance that requires it
        
        setAuthorityKeyStore();

        setNotificationManager();

        // load the StatusChecker

        loadStatusChecker();
    }

    private void setNotificationManager() {
        ZTSNotificationTaskFactory ztsNotificationTaskFactory = new ZTSNotificationTaskFactory(
                instanceCertManager,
                dataStore,
                hostnameResolver,
                userDomainPrefix,
                serverHostName,
                httpsPort);

        notificationManager = new NotificationManager(ztsNotificationTaskFactory.getNotificationTasks());

        // Enable notifications for instanceCertManager
        instanceCertManager.enableCertStoreNotifications(notificationManager, dataStore, serverHostName);
        instanceCertManager.enableSSHStoreNotifications(notificationManager, dataStore, serverHostName);
    }

    void loadSystemProperties() {
        String propFile = System.getProperty(ZTS_PROP_FILE_NAME,
                getRootDir() + "/conf/zts_server/zts.properties");
        ConfigProperties.loadProperties(propFile);
    }
    
    void loadConfigurationSettings() {
        
        // make sure all requests run in secure mode

        secureRequestsOnly = Boolean.parseBoolean(
                System.getProperty(ZTSConsts.ZTS_PROP_SECURE_REQUESTS_ONLY, "true"));
 
        // retrieve the regular and status ports
        
        httpPort = ConfigProperties.getPortNumber(ZTSConsts.ZTS_PROP_HTTP_PORT,
                ZTSConsts.ZTS_HTTP_PORT_DEFAULT);
        httpsPort = ConfigProperties.getPortNumber(ZTSConsts.ZTS_PROP_HTTPS_PORT,
                ZTSConsts.ZTS_HTTPS_PORT_DEFAULT);
        statusPort = ConfigProperties.getPortNumber(ZTSConsts.ZTS_PROP_STATUS_PORT, 0);
        
        successServerStatus = new Status().setCode(ResourceException.OK).setMessage("OK");
        
        statusCertSigner = Boolean.parseBoolean(
                System.getProperty(ZTSConsts.ZTS_PROP_STATUS_CERT_SIGNER, "false"));

        // check to see if we want to disable allowing clients to ask for role
        // tokens without role name thus violating the least privilege principle
        
        leastPrivilegePrincipal = Boolean.parseBoolean(
                System.getProperty(ZTSConsts.ZTS_PROP_LEAST_PRIVILEGE_PRINCIPLE, "false"));

        singleDomainInRoleCert = Boolean.parseBoolean(
                System.getProperty(ZTSConsts.ZTS_PROP_SINGLE_DOMAIN_IN_ROLE_CERT, "false"));

        // Default Role Token timeout is 2 hours. If the client asks for role tokens
        // with a min expiry time of 1 hour, the setting of 2 hours allows the client
        // to at least cache the tokens for 1 hour. We're going to set the ZTS client's
        // min default value to 15 mins so that we can by default cache tokens for
        // an hour and 45 minutes.
        
        long timeout = TimeUnit.SECONDS.convert(2, TimeUnit.HOURS);
        roleTokenDefaultTimeout = Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT, Long.toString(timeout)));
        
        // Max Timeout - 30 days
        
        timeout = TimeUnit.SECONDS.convert(30, TimeUnit.DAYS);
        roleTokenMaxTimeout = Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT, Long.toString(timeout)));

        // default id token timeout - 12 hours

        timeout = TimeUnit.SECONDS.convert(12, TimeUnit.HOURS);
        idTokenMaxTimeout = Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, Long.toString(timeout)));

        // signedPolicyTimeout is in milliseconds but the config setting should be in seconds
        // to be consistent with other configuration properties
        
        timeout = TimeUnit.SECONDS.convert(7, TimeUnit.DAYS);
        signedPolicyTimeout = 1000 * Long.parseLong(
                System.getProperty(ZTSConsts.ZTS_PROP_SIGNED_POLICY_TIMEOUT, Long.toString(timeout)));
        
        // default token timeout for issued tokens
        
        timeout = TimeUnit.SECONDS.convert(1, TimeUnit.DAYS);
        svcTokenTimeout = Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_INSTANCE_NTOKEN_TIMEOUT, Long.toString(timeout)));
        
        // retrieve the list of our authorized proxy users
        
        final String authorizedProxyUserList = System.getProperty(ZTSConsts.ZTS_PROP_AUTHORIZED_PROXY_USERS);
        if (authorizedProxyUserList != null) {
            authorizedProxyUsers = new HashSet<>(Arrays.asList(authorizedProxyUserList.split(",")));
        }
        
        userDomain = System.getProperty(PROP_USER_DOMAIN, ZTSConsts.ATHENZ_USER_DOMAIN);
        userDomainPrefix = userDomain + ".";
        
        userDomainAlias = System.getProperty(ZTSConsts.ZTS_PROP_USER_DOMAIN_ALIAS);
        if (userDomainAlias != null) {
            userDomainAliasPrefix = userDomainAlias + ".";
        }
        
        // get the list of uris that we want to allow an-authenticated access
        
        final String uriList = System.getProperty(ZTSConsts.ZTS_PROP_NOAUTH_URI_LIST);
        if (uriList != null) {
            authFreeUriSet = new HashSet<>();
            authFreeUriList = new ArrayList<>();
            String[] list = uriList.split(",");
            for (String uri : list) {
                if (uri.indexOf('+') != -1) {
                    authFreeUriList.add(Pattern.compile(uri));
                } else {
                    authFreeUriSet.add(uri);
                }
            }
        }
        
        // check to see if we need to include the complete role token flag
        
        includeRoleCompleteFlag = Boolean.parseBoolean(
                System.getProperty(ZTSConsts.ZTS_PROP_ROLE_COMPLETE_FLAG, "true"));
        
        // check if we need to run in maintenance read only mode
        
        readOnlyMode = Boolean.parseBoolean(
                System.getProperty(ZTSConsts.ZTS_PROP_READ_ONLY_MODE, "false"));

        // configure if we should verify the IP address that's included
        // in the certificate request

        verifyCertRequestIP = Boolean.parseBoolean(
                System.getProperty(ZTSConsts.ZTS_PROP_CERT_REQUEST_VERIFY_IP, "false"));

        // configure if we should validate subject ou fields to match
        // provider names

        verifyCertSubjectOU = Boolean.parseBoolean(
                System.getProperty(ZTSConsts.ZTS_PROP_CERT_REQUEST_VERIFY_SUBJECT_OU, "false"));

        // x509 certificate issue reset time if configured

        x509CertRefreshResetTime = Long.parseLong(
                System.getProperty(ZTSConsts.ZTS_PROP_CERT_REFRESH_RESET_TIME, "0"));

        // list of valid O and OU values for any certificate request

        final String validCertSubjectOrgValueList = System.getProperty(ZTSConsts.ZTS_PROP_CERT_ALLOWED_O_VALUES);
        if (validCertSubjectOrgValueList != null) {
            validCertSubjectOrgValues = new HashSet<>(Arrays.asList(validCertSubjectOrgValueList.split("\\|")));
        }

        final String validCertSubjectOrgUnitValueList = System.getProperty(ZTSConsts.ZTS_PROP_CERT_ALLOWED_OU_VALUES);
        if (validCertSubjectOrgUnitValueList != null) {
            validCertSubjectOrgUnitValues = new HashSet<>(Arrays.asList(validCertSubjectOrgUnitValueList.split("\\|")));
        }

        // retrieve our oauth settings

        ztsOAuthIssuer = System.getProperty(ZTSConsts.ZTS_PROP_OAUTH_ISSUER, serverHostName);

        // setup our health check file

        final String healthCheckPath = System.getProperty(ZTSConsts.ZTS_PROP_HEALTH_CHECK_PATH);
        if (healthCheckPath != null && !healthCheckPath.isEmpty()) {
            healthCheckFile = new File(healthCheckPath);
        }

        // get server region

        serverRegion = System.getProperty(ZTSConsts.ZTS_PROP_SERVER_REGION);

        // list of domains to be skipped when validating services for instance
        // register/refresh operations since the services in these domains are
        // dynamic - e.g. screwdriver projects

        final String skipDomains = System.getProperty(ZTSConsts.ZTS_PROP_VALIDATE_SERVICE_SKIP_DOMAINS, "");
        validateServiceSkipDomains = new HashSet<>(Arrays.asList(skipDomains.split(",")));
    }
    
    static String getServerHostName() {
        
        String serverHostName = System.getProperty(ZTSConsts.ZTS_PROP_HOSTNAME);
        if (serverHostName == null || serverHostName.isEmpty()) {
            serverHostName = "localhost";
            try {
                InetAddress localhost = java.net.InetAddress.getLocalHost();
                serverHostName = localhost.getCanonicalHostName();
            } catch (java.net.UnknownHostException e) {
                LOGGER.info("Unable to determine local hostname: " + e.getMessage());
            }
        }
        
        return serverHostName;
    }
    
    void setAuthorityKeyStore() {
        for (Authority authority : authorities.getAuthorities()) {
            if (AuthorityKeyStore.class.isInstance(authority)) {
                ((AuthorityKeyStore) authority).setKeyStore(this);
            }
        }
    }
    
    void loadSchemaValidator() {
        schema = ZTSSchema.instance();
        validator = new Validator(schema);
    }
    
    ChangeLogStore getChangeLogStore(String homeDir) {

        final String clogFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_CHANGE_LOG_STORE_FACTORY_CLASS,
                ZTSConsts.ZTS_CHANGE_LOG_STORE_FACTORY_CLASS);
        ChangeLogStoreFactory clogFactory;
        try {
            clogFactory = (ChangeLogStoreFactory) Class.forName(clogFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOGGER.error("Invalid ChangeLogStoreFactory class: " + clogFactoryClass
                    + " error: " + e.getMessage());
            return null;
        }
        
        // create our struct store

        clogFactory.setPrivateKeyStore(privateKeyStore);
        return clogFactory.create(homeDir, privateKey.getKey(), privateKey.getId());
    }
    
    void loadMetricObject() {
        
        final String metricFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_METRIC_FACTORY_CLASS,
                METRIC_DEFAULT_FACTORY_CLASS);

        MetricFactory metricFactory;
        try {
            metricFactory = (MetricFactory) Class.forName(metricFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOGGER.error("Invalid MetricFactory class: " + metricFactoryClass
                    + " error: " + e.getMessage());
            throw new IllegalArgumentException("Invalid metric class");
        }
        
        // create our metric and increment our startup count
        
        metric = metricFactory.create();
        metric.increment("zts_startup");
    }

    void loadHostnameResolver() {

        final String resolverFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_HOSTNAME_RESOLVER_FACTORY_CLASS);
        if (resolverFactoryClass == null) {
            return;
        }

        HostnameResolverFactory resolverFactory;
        try {
            resolverFactory = (HostnameResolverFactory) Class.forName(resolverFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOGGER.error("Invalid HostnameResolverFactory class: " + resolverFactoryClass
                    + " error: " + e.getMessage());
            throw new IllegalArgumentException("Invalid HostnameResolverFactory class");
        }

        // create our hostname resolver

        hostnameResolver = resolverFactory.create();
    }

    void loadServicePrivateKey() {
        
        final String pkeyFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                ZTSConsts.ZTS_PKEY_STORE_FACTORY_CLASS);
        PrivateKeyStoreFactory pkeyFactory;
        try {
            pkeyFactory = (PrivateKeyStoreFactory) Class.forName(pkeyFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOGGER.error("Invalid PrivateKeyStoreFactory class: " + pkeyFactoryClass
                    + " error: " + e.getMessage());
            throw new IllegalArgumentException("Invalid private key store");
        }
        
        // extract the private key for our service - we're going to ask for our algorithm
        // specific keys and then if neither one is provided our generic one.
        
        privateKeyStore = pkeyFactory.create();

        privateECKey = privateKeyStore.getPrivateKey(ZTSConsts.ZTS_SERVICE, serverHostName,
                serverRegion, ZTSConsts.EC);

        privateRSAKey = privateKeyStore.getPrivateKey(ZTSConsts.ZTS_SERVICE, serverHostName,
                serverRegion, ZTSConsts.RSA);

        // if we don't have ec and rsa specific keys specified then we're going to fall
        // back and use the old private key api and use that for our private key
        // if both ec and rsa keys are provided, we use the ec key as preferred
        // when signing policy files

        if (privateECKey == null && privateRSAKey == null) {
            StringBuilder privKeyId = new StringBuilder(256);
            PrivateKey pkey = privateKeyStore.getPrivateKey(ZTSConsts.ZTS_SERVICE, serverHostName, privKeyId);
            privateKey = new ServerPrivateKey(pkey, privKeyId.toString());
        } else if (privateECKey != null) {
            privateKey = privateECKey;
        } else {
            privateKey = privateRSAKey;
        }
    }
    
    void loadAuthorities() {
        
        // get our authorities
        
        final String authListConfig = System.getProperty(ZTSConsts.ZTS_PROP_AUTHORITY_CLASSES,
                ZTSConsts.ZTS_PRINCIPAL_AUTHORITY_CLASS);
        authorities = new AuthorityList();

        String[] authorityList = authListConfig.split(",");
        for (String authorityClass : authorityList) {
            Authority authority = getAuthority(authorityClass);
            if (authority == null) {
                throw new IllegalArgumentException("Invalid authority");
            }
            authority.initialize();
            authorities.add(authority);
        }
    }
    
    void loadAuditLogger() {
        
        final String auditFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_AUDIT_LOGGER_FACTORY_CLASS,
                ZTSConsts.ZTS_AUDIT_LOGGER_FACTORY_CLASS);
        AuditLoggerFactory auditLogFactory;
        
        try {
            auditLogFactory = (AuditLoggerFactory) Class.forName(auditFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOGGER.error("Invalid AuditLoggerFactory class: " + auditFactoryClass
                    + " error: " + e.getMessage());
            throw new IllegalArgumentException("Invalid audit logger class");
        }
        
        // create our audit logger
        
        auditLogger = auditLogFactory.create();
    }

    void loadStatusChecker() {
        final String statusCheckerFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_STATUS_CHECKER_FACTORY_CLASS);
        StatusCheckerFactory statusCheckerFactory;

        if (statusCheckerFactoryClass != null && !statusCheckerFactoryClass.isEmpty()) {

            try {
                statusCheckerFactory = (StatusCheckerFactory) Class.forName(statusCheckerFactoryClass).newInstance();
            } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
                LOGGER.error("Invalid StatusCheckerFactory class: " + statusCheckerFactoryClass
                        + " error: " + e.getMessage());
                throw new IllegalArgumentException("Invalid status checker factory class");
            }

            // create our status checker

            statusChecker = statusCheckerFactory.create();
        }
    }

    AuditLogMsgBuilder getAuditLogMsgBuilder(ResourceContext ctx, String domainName,
            String caller, String method) {
        
        AuditLogMsgBuilder msgBldr = auditLogger.getMsgBuilder();

        // get the where - which means where this server is running
        
        msgBldr.where(serverHostName).whatDomain(domainName)
            .whatApi(caller).whatMethod(method)
            .when(Timestamp.fromCurrentTime().toString());

        // get the 'who' and set it
        
        Principal princ = ((RsrcCtxWrapper) ctx).principal();
        if (princ != null) {
            final String fullName = princ.getFullName();
            final String unsignedCreds = princ.getUnsignedCredentials();
            msgBldr.who(unsignedCreds == null ? fullName : unsignedCreds);
            msgBldr.whoFullName(fullName);
        }

        // get the client IP
        
        msgBldr.clientIp(ServletRequestUtil.getRemoteAddress(ctx.request()));
        return msgBldr;
    }

    @Override
    public String getPublicKey(String domain, String service, String keyId) {
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case
        
        if (domain != null) {
            domain = domain.toLowerCase();
        }
        if (service != null) {
            service = service.toLowerCase();
        }
        if (keyId != null) {
            keyId = keyId.toLowerCase();
        }
        
        return dataStore.getPublicKey(domain, service, keyId);
    }
    
    ServiceIdentity generateZTSServiceIdentity(com.yahoo.athenz.zms.ServiceIdentity zmsService) {
        
        // zms and zts are using the same definition for service identities but
        // due to RDL generated code they have different classes. So we're going
        // convert our ZMS Service object into a struct and then back to ZTS object
        
        ServiceIdentity ztsService = new ServiceIdentity()
                .setName(zmsService.getName())
                .setExecutable(zmsService.getExecutable())
                .setGroup(zmsService.getGroup())
                .setHosts(zmsService.getHosts())
                .setModified(zmsService.getModified())
                .setProviderEndpoint(zmsService.getProviderEndpoint())
                .setUser(zmsService.getUser());
        List<com.yahoo.athenz.zms.PublicKeyEntry> zmsPublicKeys = zmsService.getPublicKeys();
        if (zmsPublicKeys != null) {
            ArrayList<PublicKeyEntry> ztsPublicKeys = new ArrayList<>();
            for (com.yahoo.athenz.zms.PublicKeyEntry zmsPublicKey : zmsPublicKeys) {
                PublicKeyEntry ztsPublicKey = new PublicKeyEntry()
                        .setId(zmsPublicKey.getId())
                        .setKey(zmsPublicKey.getKey());
                ztsPublicKeys.add(ztsPublicKey);
            }
            ztsService.setPublicKeys(ztsPublicKeys);
        }
        
        return ztsService;
    }
    
    String generateServiceIdentityName(String domain, String service) {
        return domain + "." + service;
    }
    
    ServiceIdentity lookupServiceIdentity(DomainData domainData, String serviceName) {
        
        List<com.yahoo.athenz.zms.ServiceIdentity> services = domainData.getServices();
        if (services == null) {
            return null;
        }
        
        for (com.yahoo.athenz.zms.ServiceIdentity service : services) {
            if (service.getName().equalsIgnoreCase(serviceName)) {
                return generateZTSServiceIdentity(service);
            }
        }
        
        return null;
    }
    
    // ----------------- the ServiceIdentity interface

    public ServiceIdentity getServiceIdentity(ResourceContext ctx, String domainName, String serviceName) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        validateRequest(ctx.request(), principalDomain, caller);
        validate(domainName, TYPE_DOMAIN_NAME, principalDomain, caller);
        validate(serviceName, TYPE_SIMPLE_NAME, principalDomain, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case
        
        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        serviceName = serviceName.toLowerCase();

        DomainData domainData = dataStore.getDomainData(domainName);
        if (domainData == null) {
            setRequestDomain(ctx, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            throw notFoundError("Domain not found: '" + domainName + "'", caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
        
        // update our metric with dimension. we're moving the metric here
        // after the domain name has been confirmed as valid since with
        // dimensions we get stuck with persistent indexes so we only want
        // to create them for valid domain names
        
        String cnService = generateServiceIdentityName(domainName, serviceName);
        ServiceIdentity ztsService = lookupServiceIdentity(domainData, cnService);

        if (ztsService == null) {
            throw notFoundError("Service not found: '" + cnService + "'", caller, domainName, principalDomain);
        }
        
        return ztsService;
    }

    public PublicKeyEntry getPublicKeyEntry(ResourceContext ctx, String domainName,
            String serviceName, String keyId) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        validateRequest(ctx.request(), principalDomain, caller);
        validate(domainName, TYPE_DOMAIN_NAME, principalDomain, caller);
        validate(serviceName, TYPE_SIMPLE_NAME, principalDomain, caller);

        if (keyId == null) {
            throw requestError("Invalid Public Key Id specified", caller, domainName, principalDomain);
        }
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        serviceName = serviceName.toLowerCase();
        keyId = keyId.toLowerCase();

        String publicKey = dataStore.getPublicKey(domainName, serviceName, keyId);
        if (publicKey == null) {
            throw notFoundError("Public Key not found", caller, domainName, principalDomain);
        }

        return new PublicKeyEntry().setId(keyId)
                .setKey(Crypto.ybase64(publicKey.getBytes(StandardCharsets.UTF_8)));
    }
    
    public ServiceIdentityList getServiceIdentityList(ResourceContext ctx, String domainName) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        validateRequest(ctx.request(), principalDomain, caller);
        validate(domainName, TYPE_DOMAIN_NAME, principalDomain, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case
        
        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        DomainData domainData = dataStore.getDomainData(domainName);
        if (domainData == null) {
            setRequestDomain(ctx, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            throw notFoundError("Domain not found: '" + domainName + "'", caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
        
        return generateServiceIdentityList(domainName, domainData.getServices());
    }

    ServiceIdentityList generateServiceIdentityList(final String domainName, List<com.yahoo.athenz.zms.ServiceIdentity> services) {

        ServiceIdentityList result = new ServiceIdentityList();
        if (services != null) {

            List<String> names = new ArrayList<>();
            final String prefix = domainName + ".";

            for (com.yahoo.athenz.zms.ServiceIdentity service : services) {

                final String fullName = service.getName();
                if (fullName.startsWith(prefix)) {
                    names.add(fullName.substring(prefix.length()));
                }
            }
            result.setNames(names);
        }
        return result;
    }

    public HostServices getHostServices(ResourceContext ctx, String host) {

        final String caller = ctx.getApiName();

        final String principalDomain = logPrincipalAndGetDomain(ctx);
        validateRequest(ctx.request(), principalDomain, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case
        
        host = host.toLowerCase();
        return dataStore.getHostServices(host);
    }

    List<Policy> getPolicyList(DomainData domainData) {
        
        ArrayList<Policy> ztsPolicies = new ArrayList<>();

        com.yahoo.athenz.zms.SignedPolicies signedPolicies = domainData.getPolicies();
        if (signedPolicies == null) {
            return ztsPolicies;
        }
        
        com.yahoo.athenz.zms.DomainPolicies domainPolicies = signedPolicies.getContents();
        if (domainPolicies == null) {
            return ztsPolicies;
        }
        
        List<com.yahoo.athenz.zms.Policy> zmsPolicies = domainPolicies.getPolicies();
        if (zmsPolicies == null) {
            return ztsPolicies;
        }
        
        for (com.yahoo.athenz.zms.Policy zmsPolicy : zmsPolicies) {
            Policy ztsPolicy = new Policy()
                    .setModified(zmsPolicy.getModified())
                    .setName(zmsPolicy.getName());
            
            List<com.yahoo.athenz.zms.Assertion> zmsAssertions = zmsPolicy.getAssertions();
            if (zmsAssertions != null) {
                ArrayList<Assertion> ztsAssertions = new ArrayList<>();
                for (com.yahoo.athenz.zms.Assertion zmsAssertion : zmsAssertions) {
                    Assertion ztsAssertion = new Assertion()
                            .setAction(zmsAssertion.getAction())
                            .setResource(zmsAssertion.getResource())
                            .setRole(zmsAssertion.getRole())
                            .setEffect(getAssertionEffect(zmsAssertion.getEffect()));
                    ztsAssertions.add(ztsAssertion);
                }
                ztsPolicy.setAssertions(ztsAssertions);
            }
            ztsPolicies.add(ztsPolicy);
        }
        
        return ztsPolicies;
    }

    AssertionEffect getAssertionEffect(com.yahoo.athenz.zms.AssertionEffect effect) {
        if (effect == com.yahoo.athenz.zms.AssertionEffect.DENY) {
            return AssertionEffect.DENY;
        } else {
            return AssertionEffect.ALLOW;
        }
    }

    public Response getDomainSignedPolicyData(ResourceContext ctx, String domainName, String matchingTag) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        validateRequest(ctx.request(), principalDomain, caller);
        validate(domainName, TYPE_DOMAIN_NAME, principalDomain, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case
        
        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        DomainData domainData = dataStore.getDomainData(domainName);
        if (domainData == null) {
            setRequestDomain(ctx, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            throw notFoundError("Domain not found: '" + domainName + "'", caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
        
        Timestamp modified = domainData.getModified();
        EntityTag eTag = new EntityTag(modified.toString());
        String tag = eTag.toString();
        
        // Set timestamp for domain rather than youngest policy.
        // Since a policy could have been deleted, and can only be detected
        // via the domain modified timestamp.
        
        if (matchingTag != null && matchingTag.equals(tag)) {
            return Response.status(ResourceException.NOT_MODIFIED).header("ETag", tag).build();
        }
        
        // first get our PolicyData object
        
        PolicyData policyData = new PolicyData()
                .setDomain(domainName)
                .setPolicies(getPolicyList(domainData));

        // then get the signed policy data
        
        Timestamp expires = Timestamp.fromMillis(System.currentTimeMillis() + signedPolicyTimeout);

        SignedPolicyData signedPolicyData = new SignedPolicyData()
                .setPolicyData(policyData)
                .setExpires(expires)
                .setModified(modified)
                .setZmsKeyId(domainData.getPolicies().getKeyId())
                .setZmsSignature(domainData.getPolicies().getSignature());

        String signature = Crypto.sign(SignUtils.asCanonicalString(signedPolicyData), privateKey.getKey());
        DomainSignedPolicyData result = new DomainSignedPolicyData()
            .setSignedPolicyData(signedPolicyData)
            .setSignature(signature)
            .setKeyId(privateKey.getId());
        
        return Response.status(ResourceException.OK).entity(result).header("ETag", tag).build();
    }

    String convertEmptyStringToNull(String value) {
        
        if (value != null && value.isEmpty()) {
            return null;
        } else {
            return value;
        }
    }

    long determineIdTokenTimeout(long tokenTimeout) {
        return (tokenTimeout > idTokenMaxTimeout) ? idTokenMaxTimeout : tokenTimeout;
    }

    long determineTokenTimeout(DataCache data, Set<String> roles, Integer minExpiryTime,
            Integer maxExpiryTime) {
        
        // we're going to default our return value to the default token
        // timeout configured in the server
        
        long tokenTimeout = roleTokenDefaultTimeout;
        
        if (maxExpiryTime != null && maxExpiryTime > 0) {
            
            // if our max expiry time is given and it's a positive number then
            // we return that value as our result. We're checking and using the
            // max value first since that allows the biggest opportunity on the
            // client side to cache the token and return on subsequent requests
            
            tokenTimeout = maxExpiryTime;
            
        } else if (minExpiryTime != null && minExpiryTime > roleTokenDefaultTimeout) {
            
            // now we return the min value but only if it's bigger than our
            // default value (if the client is looking for a token that's smaller
            // than the default timeout, then they would have specified their 
            // desired smaller value as the max timeout and the first if block
            // would have set accordingly.
            
            tokenTimeout = minExpiryTime;
        }
        
        // however, we're not going to allow the client to ask for unlimited
        // tokens so we'll max it out to the server's configured max timeout
        
        if (tokenTimeout > roleTokenMaxTimeout) {
            tokenTimeout = roleTokenMaxTimeout;
        }

        // fetch the configured max allowed value for all roles in the set
        // if it's configured and is less that what we have determined so
        // far then we'll reduce it to the configured value

        int maxAllowedExpirySecs = getConfiguredTokenExpiryTimeMins(data, roles) * 60;
        if (maxAllowedExpirySecs > 0 && maxAllowedExpirySecs < tokenTimeout) {
            tokenTimeout =  maxAllowedExpirySecs;
        }

        return tokenTimeout;
    }

    int getConfiguredTokenExpiryTimeMins(DataCache data, Set<String> roles) {

        // first we're going to determine the min allowed expiry
        // time for the given set of roles

        int maxAllowedExpiry = 0;
        for (String role: roles) {
            RoleMeta rm = data.getRoleMeta(role);
            if (rm == null) {
                continue;
            }
            Integer tokenExpiryMins = rm.getTokenExpiryMins();
            if (tokenExpiryMins == null) {
                continue;
            }
            if (tokenExpiryMins > 0 && (maxAllowedExpiry == 0 || tokenExpiryMins < maxAllowedExpiry)) {
                maxAllowedExpiry = tokenExpiryMins;
            }
        }

        // if we don't have a value specified then we're going
        // to look at the domain value if one is configured

        if (maxAllowedExpiry == 0) {
            Integer tokenExpiryMins = data.getDomainData().getTokenExpiryMins();
            if (tokenExpiryMins != null && tokenExpiryMins > 0) {
                maxAllowedExpiry = tokenExpiryMins;
            }
        }

        return maxAllowedExpiry;
    }

    public TenantDomains getTenantDomains(ResourceContext ctx, String providerDomainName,
            String userName, String roleName, String serviceName) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        validateRequest(ctx.request(), principalDomain, caller);
        validate(providerDomainName, TYPE_DOMAIN_NAME, principalDomain, caller);
        validate(userName, TYPE_ENTITY_NAME, principalDomain, caller);
        if (roleName != null) {
            validate(roleName, TYPE_ENTITY_NAME, principalDomain, caller);
        }
        if (serviceName != null) {
            validate(serviceName, TYPE_SERVICE_NAME, principalDomain, caller);
        }
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case
        
        providerDomainName = providerDomainName.toLowerCase();
        setRequestDomain(ctx, providerDomainName);
        if (roleName != null) {
            roleName = roleName.toLowerCase();
        }
        if (serviceName != null) {
            serviceName = serviceName.toLowerCase();
        }
        userName = normalizeDomainAliasUser(userName.toLowerCase());
        
        // first retrieve our domain data object from the cache

        DataCache data = dataStore.getDataCache(providerDomainName);
        if (data == null) {
            setRequestDomain(ctx, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            throw notFoundError("getTenantDomains: No such provider domain: " + providerDomainName,
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        // if the username does not contain a domain then we'll assume
        // user domain and handle accordingly
        
        if (userName.indexOf('.') == -1) {
            userName = this.userDomain + "." + userName;
        }
        
        roleName = convertEmptyStringToNull(roleName);
        String[] requestedRoleList = null;
        if (roleName != null) {
            requestedRoleList = roleName.split(",");
        }
        
        // process our request and retrieve the roles for the principal
        
        Set<String> roles = new HashSet<>();
        
        dataStore.getAccessibleRoles(data, providerDomainName, userName,
                requestedRoleList, roles, false);
        
        // we are going to process the list and only keep the tenant
        // domains - this is based on the role names since our tenant
        // roles are named: <service>.tenant.<domain>.[<resource_group>.]<action>
        
        Set<String> domainNames = new HashSet<>();
        for (String role : roles) {
            
            String domainName = retrieveTenantDomainName(role, serviceName);
            if (domainName != null) {
                domainNames.add(domainName);
            }
        }
        
        TenantDomains tenantDomains = new TenantDomains();
        tenantDomains.setTenantDomainNames(new ArrayList<>(domainNames));

        return tenantDomains;
    }

    String retrieveTenantDomainName(String roleName, String serviceName) {
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("retrieveTenantDomainName: Processing role name: " + roleName);
        }
        
        // roles are named: <service>.tenant.<domain>.[<resource_group>.]<action>
        // so we're going to do the easy checks first
        // check 1: we must have at least 4 components
        
        String[] comps = roleName.split("\\.");
        if (comps.length < 4) {
            return null;
        }
        
        // check 2: our second component must be the word tenant
        
        if (!comps[1].equals("tenant")) {
            return null;
        }
        
        // check 3: if service name is given, it must be the first component
        
        if (serviceName != null && !comps[0].equals(serviceName)) {
            return null;
        }
        
        // if we have 4 components then component 3 is the domain name
        
        if (comps.length == 4) {
            
            // verify it's a valid domain name before returning
            
            if (dataStore.getDataCache(comps[2]) == null) {
                return null;
            }

            return comps[2];
        }
        
        // so if we have more components than 4 then we have two
        // choices to deal with: with and without resource groups
        // first let's generate into two strings - one assuming
        // to be the resource group
        
        String resourceGroup = comps[comps.length - 2];
        StringBuilder domainNameBuf = new StringBuilder(512).append(comps[2]);
        for (int i = 3; i < comps.length - 2; i++) {
            domainNameBuf.append('.').append(comps[i]);
        }
        
        // first we're going to assume the resource group as part
        // of the domain name and see if that domain exists
        
        String fullDomainName = domainNameBuf.toString() + "." + resourceGroup;
        if (dataStore.getDataCache(fullDomainName) != null) {
            return fullDomainName;
        }
        
        // now let's try without the resource group part
        
        fullDomainName = domainNameBuf.toString();
        if (dataStore.getDataCache(fullDomainName) != null) {
            return fullDomainName;
        }
        
        // we didn't have valid domain
        
        return null;
    }
    
    boolean isAuthorizedProxyUser(Set<String> proxyUsers, String principal) {
        if (proxyUsers == null) {
            return false;
        }
        return proxyUsers.contains(principal);
    }
    
    void checkRoleTokenAuthorizedServiceRequest(final Principal principal,
            final String domainName, final String caller) {
        
        final String authorizedService = principal.getAuthorizedService();
        
        // if principal is not an authorized service token then
        // we have nothing to check for
        
        if (authorizedService == null || authorizedService.isEmpty()) {
            return;
        }
        
        // extract the domain from the authorized service and make
        // sure it matches to the requested domain value
        
        int idx = authorizedService.lastIndexOf('.');
        final String checkDomain = authorizedService.substring(0, idx);
        
        if (!domainName.equals(checkDomain)) {
            throw forbiddenError("Authorized service domain " + checkDomain +
                    " does not match request domain " + domainName, caller,
                    domainName, principal.getDomain());
        }
    }
    
    // Token interface
    @Override
    public RoleToken getRoleToken(ResourceContext ctx, String domainName, String roleNames,
            Integer minExpiryTime, Integer maxExpiryTime, String proxyForPrincipal) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        validateRequest(ctx.request(), principalDomain, caller);
        validate(domainName, TYPE_DOMAIN_NAME, principalDomain, caller);
        if (roleNames != null && !roleNames.isEmpty()) {
            validate(roleNames, TYPE_ENTITY_LIST, principalDomain, caller);
        }
        if (proxyForPrincipal != null && !proxyForPrincipal.isEmpty()) {
            validate(proxyForPrincipal, TYPE_ENTITY_NAME, principalDomain, caller);
        }
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case
        
        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        if (roleNames != null) {
            roleNames = roleNames.toLowerCase();
        }
        if (proxyForPrincipal != null) {
            proxyForPrincipal = normalizeDomainAliasUser(proxyForPrincipal.toLowerCase());
        }

        // get our principal's name

        final Principal principal = ((RsrcCtxWrapper) ctx).principal();
        String principalName = principal.getFullName();

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("getRoleToken(domain: {}, principal: {}, role-name: {}, proxy-for: {})",
                    domainName, principalName, roleNames, proxyForPrincipal);
        }
        
        // do not allow empty (not null) values for role
        
        roleNames = convertEmptyStringToNull(roleNames);
        proxyForPrincipal = convertEmptyStringToNull(proxyForPrincipal);
        
        if (leastPrivilegePrincipal && roleNames == null) {
            throw requestError("getRoleToken: Client must specify a roleName to request a token for",
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
        
        // we can only have a proxy for principal request if the original
        // caller is authorized for such operations
        
        if (proxyForPrincipal != null && !isAuthorizedProxyUser(authorizedProxyUsers, principalName)) {
            LOGGER.error("getRoleToken: Principal {} not authorized for proxy role token request", principalName);
            throw forbiddenError("getRoleToken: Principal: " + principalName
                    + " not authorized for proxy role token request", caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        // first retrieve our domain data object from the cache

        DataCache data = dataStore.getDataCache(domainName);
        if (data == null) {
            setRequestDomain(ctx, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            throw notFoundError("getRoleToken: No such domain: " + domainName, caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
        
        // check if the authorized service domain matches to the
        // requested domain name
        
        checkRoleTokenAuthorizedServiceRequest(principal, domainName, caller);
        
        // we need to convert our request role name into array since
        // it could contain multiple values separated by commas
        
        String[] requestedRoleList = null;
        if (roleNames != null) {
            requestedRoleList = roleNames.split(",");
        }
        
        // process our request and retrieve the roles for the principal
        
        Set<String> roles = new HashSet<>();
        dataStore.getAccessibleRoles(data, domainName, principalName, requestedRoleList,
                roles, false);
        
        if (roles.isEmpty()) {
            throw forbiddenError("getRoleToken: No access to any roles in domain: "
                    + domainName, caller, domainName, principalDomain);
        }
        
        // if this is proxy for operation then we want to make sure that
        // both principals have access to the same set of roles so we'll
        // remove any roles that are authorized by only one of the principals
        
        String proxyUser = null;
        if (proxyForPrincipal != null) {
            Set<String> rolesForProxy = new HashSet<>();
            dataStore.getAccessibleRoles(data, domainName, proxyForPrincipal,
                    requestedRoleList, rolesForProxy, false);
            roles.retainAll(rolesForProxy);
            
            // check again in case we removed all the roles and ended up
            // with an empty set
            
            if (roles.isEmpty()) {
                throw forbiddenError("getRoleToken: No access to any roles by User and Proxy Principals",
                        caller, domainName, principalDomain);
            }
            
            // we need to switch our principal and proxy for user
            
            proxyUser = principalName;
            principalName = proxyForPrincipal;
        }

        // if the request was done by a role certificate we need to make sure
        // that it is issued for the roles we're returning in the role token

        if (!isPrincipalRoleCertificateAccessValid(principal, domainName, roles)) {
            throw forbiddenError("getRoleToken: Role based Principal does not include all roles",
                    caller, domainName, principalDomain);
        }

        // generate and return role token

        long tokenTimeout = determineTokenTimeout(data, roles, minExpiryTime, maxExpiryTime);
        List<String> roleList = new ArrayList<>(roles);
        boolean domainCompleteRoleSet = (includeRoleCompleteFlag && roleNames == null);
        com.yahoo.athenz.auth.token.RoleToken token =
                new com.yahoo.athenz.auth.token.RoleToken.Builder(ZTS_ROLE_TOKEN_VERSION, domainName, roleList)
                    .expirationWindow(tokenTimeout).host(serverHostName).keyId(privateKey.getId())
                    .principal(principalName).ip(ServletRequestUtil.getRemoteAddress(ctx.request()))
                    .proxyUser(proxyUser).domainCompleteRoleSet(domainCompleteRoleSet).build();
        token.sign(privateKey.getKey());
        
        RoleToken roleToken = new RoleToken();
        roleToken.setToken(token.getSignedToken());
        roleToken.setExpiryTime(token.getExpiryTime());

        return roleToken;
    }

    String decodeString(final String encodedString) {

        try {
            return URLDecoder.decode(encodedString, "UTF-8");
        } catch (Exception ex) {
            LOGGER.error("Unable to decode: {}, error: {}", encodedString, ex.getMessage());
            return null;
        }
    }

    String getProxyForPrincipalValue(final String proxyName, final String principalName,
                                     final String principalDomain, final String caller) {

        if (proxyName.isEmpty()) {
            return null;
        }

        // validate name matches our schema

        validate(proxyName, TYPE_ENTITY_NAME, principalDomain, caller);

        // we can only have a proxy for principal request if the original
        // caller is authorized for such operations

        if (!isAuthorizedProxyUser(authorizedProxyUsers, principalName)) {
            LOGGER.error("postAccessTokenRequest: Principal {} not authorized for proxy role token request", principalName);
            throw forbiddenError("postAccessTokenRequest: Principal: " + principalName
                    + " not authorized for proxy access token request", caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        return proxyName;
    }

    String getQueryLogData(final String request) {
        // make sure any CRLFs are not set to the logger
        final String clean = request.replace('\n', '_').replace('\r', '_');
        return (clean.length() > 1024) ? clean.substring(0, 1024) : clean;
    }

    @Override
    public AccessTokenResponse postAccessTokenRequest(ResourceContext ctx, String request) {

        final String caller = ctx.getApiName();

        final String principalDomain = logPrincipalAndGetDomain(ctx);
        validateRequest(ctx.request(), principalDomain, caller);

        // get our principal's name

        final Principal principal = ((RsrcCtxWrapper) ctx).principal();
        String principalName = principal.getFullName();

        if (request == null || request.isEmpty()) {
            throw requestError("Empty request body", caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        // we want to log the request body in our access log so
        // we know what is the client asking for but we'll just
        // limit the request up to 1K

        ctx.request().setAttribute(ACCESS_LOG_ADDL_QUERY, getQueryLogData(request));

        // decode and store the attributes that could exist in our
        // request body

        String grantType = null;
        String scope = null;
        String proxyForPrincipal = null;
        int expiryTime = 0;

        String[] comps = request.split("&");
        for (String comp : comps) {
            int idx = comp.indexOf('=');
            if (idx == -1) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("postAccessTokenRequest: skipping invalid component: {}", comp);
                }
                continue;
            }
            final String key = decodeString(comp.substring(0, idx));
            if (key == null) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("postAccessTokenRequest: skipping invalid component: {}", comp);
                }
                continue;
            }
            final String value = decodeString(comp.substring(idx + 1));
            if (value == null) {
                continue;
            }
            switch (key) {
                case KEY_GRANT_TYPE:
                    grantType = value.toLowerCase();
                    break;
                case KEY_SCOPE:
                    scope = value.toLowerCase();
                    break;
                case KEY_EXPIRES_IN:
                    expiryTime = ZTSUtils.parseInt(value, 0);
                    break;
                case KEY_PROXY_FOR_PRINCIPAL:
                    proxyForPrincipal = getProxyForPrincipalValue(value.toLowerCase(), principalName,
                            principalDomain, caller);
                    break;
            }
        }

        // validate the request data

        if (!OAUTH_GRANT_CREDENTIALS.equals(grantType)) {
            throw requestError("Invalid grant request: " + grantType, caller,
                    principal.getDomain(), principalDomain);
        }

        // we must have scope provided so we know what access
        // the client is looking for

        if (scope == null || scope.isEmpty()) {
            throw requestError("Invalid request: no scope provided", caller,
                    principal.getDomain(), principalDomain);
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("postAccessTokenRequest(principal: {}, grant-type: {}, scope: {}, expires-in: {}, proxy-for-principal: {})",
                    principalName, grantType, scope, expiryTime, proxyForPrincipal);
        }

        // our scopes are space separated list of values

        AccessTokenRequest tokenRequest = new AccessTokenRequest(scope);

        // before using any of our values let's validate that they
        // match our schema

        final String domainName = tokenRequest.getDomainName();
        setRequestDomain(ctx, domainName);
        validate(domainName, TYPE_DOMAIN_NAME, principalDomain, caller);

        String[] requestedRoles = tokenRequest.getRoleNames();
        if (requestedRoles != null) {
            for (String requestedRole : requestedRoles) {
                validate(requestedRole, TYPE_ENTITY_NAME, principalDomain, caller);
            }
        }

        // first retrieve our domain data object from the cache

        DataCache data = dataStore.getDataCache(domainName);
        if (data == null) {
            setRequestDomain(ctx, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            throw notFoundError("No such domain: " + domainName, caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        // check if the authorized service domain matches to the
        // requested domain name

        checkRoleTokenAuthorizedServiceRequest(principal, domainName, caller);

        // process our request and retrieve the roles for the principal

        Set<String> roles = new HashSet<>();
        dataStore.getAccessibleRoles(data, domainName, principalName, requestedRoles, roles, false);

        // we return failure if we don't have access to any roles

        if (roles.isEmpty()) {
            throw forbiddenError("No access to any roles in domain: " + domainName, caller,
                    domainName, principalDomain);
        }

        // if this is proxy for operation then we want to make sure that
        // both principals have access to the same set of roles so we'll
        // remove any roles that are authorized by only one of the principals

        String proxyUser = null;
        if (proxyForPrincipal != null) {

            // we also need to verify that we are not returning id tokens.
            // proxy principal functionality is only valid for access tokens

            if (tokenRequest.isOpenidScope()) {
                throw requestError("Proxy Principal cannot request id tokens", caller,
                        domainName, principalDomain);
            }

            // process the role lookup for the proxy principal

            Set<String> rolesForProxy = new HashSet<>();
            dataStore.getAccessibleRoles(data, domainName, proxyForPrincipal, requestedRoles, rolesForProxy, false);
            roles.retainAll(rolesForProxy);

            // check again in case we removed all the roles and ended up
            // with an empty set

            if (roles.isEmpty()) {
                throw forbiddenError("No access to any roles by User and Proxy Principals",
                        caller, domainName, principalDomain);
            }

            // we need to switch our principal and proxy for user

            proxyUser = principalName;
            principalName = proxyForPrincipal;
        }

        // if the request was done by a role certificate we need to make sure
        // that it is issued for the roles we're returning in the role token

        if (!isPrincipalRoleCertificateAccessValid(principal, domainName, roles)) {
            throw forbiddenError("Role based Principal does not include all roles",
                    caller, domainName, principalDomain);
        }

        long tokenTimeout = determineTokenTimeout(data, roles, null, expiryTime);
        long iat = System.currentTimeMillis() / 1000;

        AccessToken accessToken = new AccessToken();
        accessToken.setVersion(1);
        accessToken.setAudience(domainName);
        accessToken.setClientId(principalName);
        accessToken.setIssueTime(iat);
        accessToken.setAuthTime(iat);
        accessToken.setExpiryTime(iat + tokenTimeout);
        accessToken.setUserId(principalName);
        accessToken.setSubject(principalName);
        accessToken.setIssuer(ztsOAuthIssuer);
        accessToken.setProxyPrincipal(proxyUser);
        accessToken.setScope(new ArrayList<>(roles));

        // if we have a certificate used for mTLS authentication then
        // we're going to bind the certificate to the access token

        X509Certificate cert = principal.getX509Certificate();
        if (cert != null) {
            accessToken.setConfirmX509CertHash(cert);
        }

        String accessJwts = accessToken.getSignedToken(privateKey.getKey(), privateKey.getId(), privateKey.getAlgorithm());

        // now let's check to see if we need to create openid token

        String idJwts = null;
        if (tokenRequest.isOpenidScope()) {

            final String serviceName = tokenRequest.getServiceName();
            validate(serviceName, TYPE_SIMPLE_NAME, principalDomain, caller);

            IdToken idToken = new IdToken();
            idToken.setVersion(1);
            idToken.setAudience(tokenRequest.getDomainName() + "." + serviceName);
            idToken.setSubject(principalName);
            idToken.setIssuer(ztsOAuthIssuer);

            // id tokens are only valid for up to 12 hours max
            // (value configured as a system property).
            // we'll use the user specified timeout unless it's
            // over the configured max

            idToken.setIssueTime(iat);
            idToken.setAuthTime(iat);
            idToken.setExpiryTime(iat + determineIdTokenTimeout(tokenTimeout));

            idJwts = idToken.getSignedToken(privateKey.getKey(), privateKey.getId(), privateKey.getAlgorithm());
        }

        AccessTokenResponse response = new AccessTokenResponse().setAccess_token(accessJwts)
                .setToken_type(OAUTH_BEARER_TOKEN).setExpires_in((int) tokenTimeout).setId_token(idJwts);

        // if either we were asked for full domain roles or the requested list of roles
        // does not match the returned list of roles then we need to return the updated
        // set of scopes

        if (tokenRequest.sendScopeResponse() || requestedRoles != null && requestedRoles.length != roles.size()) {
            List<String> domainRoles = new ArrayList<>();
            for (String role : roles) {
                domainRoles.add(domainName + AccessTokenRequest.OBJECT_ROLE + role);
            }
            if (tokenRequest.isOpenidScope()) {
                domainRoles.add(AccessTokenRequest.OBJECT_OPENID);
            }
            response.setScope(String.join(" ", domainRoles));
        }

        return response;
    }

    boolean compareRoleSets(Set<String> set1, Set<String> set2) {

        if (set1.size() != set2.size()) {
            LOGGER.error("Role sets do not have the same size: {} vs. {}", set1.size(), set2.size());
            return false;
        }

        for (String item : set1) {
            if (!set2.contains(item)) {
                return false;
            }
        }

        return true;
    }

    public RoleAccess getRoleAccess(ResourceContext ctx, String domainName, String principal) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        validateRequest(ctx.request(), principalDomain, caller);
        validate(domainName, TYPE_DOMAIN_NAME, principalDomain, caller);
        validate(principal, TYPE_ENTITY_NAME, principalDomain, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        principal = normalizeDomainAliasUser(principal.toLowerCase());

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("getRoleAccess(domain: " + domainName + ", principal: " + principal + ")");
        }
        
        // first retrieve our domain data object from the cache

        DataCache data = dataStore.getDataCache(domainName);
        if (data == null) {
            setRequestDomain(ctx, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            throw notFoundError("getRoleAccess: No such domain: " + domainName,
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
        
        // process our request and retrieve the roles for the principal
        
        Set<String> roles = new HashSet<>();
        dataStore.getAccessibleRoles(data, domainName, principal, null,
                roles, false);
        
        return new RoleAccess().setRoles(new ArrayList<>(roles));
    }
    
    @Override
    public RoleToken postRoleCertificateRequest(ResourceContext ctx, String domainName,
            String roleName, RoleCertificateRequest req) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        if (readOnlyMode) {
            throw requestError("Server in Maintenance Read-Only mode. Please try your request later",
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
        
        validateRequest(ctx.request(), principalDomain, caller);
        validate(domainName, TYPE_DOMAIN_NAME, principalDomain, caller);
        validate(roleName, TYPE_ENTITY_NAME, principalDomain, caller);
        validate(req, TYPE_ROLE_CERTIFICATE_REQUEST, principalDomain, caller);

        // validate principal object to make sure we're not
        // processing a role identity and instead we require
        // a service identity

        final Principal principal = ((RsrcCtxWrapper) ctx).principal();
        validatePrincipalNotRoleIdentity(principal, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case

        String proxyForPrincipal = req.getProxyForPrincipal();

        if (proxyForPrincipal != null) {
            proxyForPrincipal = normalizeDomainAliasUser(proxyForPrincipal.toLowerCase());
        }

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case
        
        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        roleName = roleName.toLowerCase();

        // verify that this is not an authorized service principal
        // which is only supported for get role token operations

        if (isAuthorizedServicePrincipal(principal)) {
            throw forbiddenError("Authorized Service Principals not allowed",
                    caller, domainName, principalDomain);
        }

        // get our principal's name
        
        String principalName = principal.getFullName();
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("postRoleCertificateRequest(domain: {}, principal: {}, role: {}, proxy-for: {})",
                    domainName, principalName, roleName, proxyForPrincipal);
        }

        // we can only have a proxy for principal request if the original
        // caller is authorized for such operations

        if (proxyForPrincipal != null && !isAuthorizedProxyUser(authorizedProxyUsers, principalName)) {
            LOGGER.error("postRoleCertificateRequest: Principal: " + principalName +
                    " not authorized for proxy role certificate request");
            throw forbiddenError("postRoleCertificateRequest: Principal: " + principalName
                            + " not authorized for proxy role certificate request",
                    caller, domainName, domainName);
        }

        // first retrieve our domain data object from the cache

        DataCache data = dataStore.getDataCache(domainName);
        if (data == null) {
            setRequestDomain(ctx, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            throw notFoundError("postRoleCertificateRequest: No such domain: " + domainName,
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
        
        // process our request and retrieve the roles for the principal
        
        String[] requestedRoleList = { roleName };
        Set<String> roles = new HashSet<>();
        dataStore.getAccessibleRoles(data, domainName, principalName, requestedRoleList,
                roles, false);
        
        if (roles.isEmpty()) {
            throw forbiddenError("postRoleCertificateRequest: No access to any roles in domain: "
                    + domainName, caller, domainName, principalDomain);
        }

        // if this is proxy for operation then we want to make sure that
        // both principals have access to the same set of roles so we'll
        // remove any roles that are authorized by only one of the principals

        String proxyUser = null;
        if (proxyForPrincipal != null) {

            Set<String> rolesForProxy = new HashSet<>();
            dataStore.getAccessibleRoles(data, domainName, proxyForPrincipal, requestedRoleList,
                    rolesForProxy, false);
            roles.retainAll(rolesForProxy);

            // check again in case we removed all the roles and ended up
            // with an empty set

            if (roles.isEmpty()) {
                throw forbiddenError("postRoleCertificateRequest: No access to any roles by User and Proxy Principals",
                        caller, domainName, principalDomain);
            }

            // we need to switch our principal

            proxyUser = principalName;
            principalName = proxyForPrincipal;
        }

        // validate request/csr details

        X509Certificate cert = principal.getX509Certificate();
        final String ipAddress = ServletRequestUtil.getRemoteAddress(ctx.request());

        if (!validateRoleCertificateRequest(req.getCsr(), domainName, roles, principalName,
                proxyUser, cert, ipAddress)) {
            throw requestError("postRoleCertificateRequest: Unable to validate cert request",
                    caller, domainName, principalDomain);
        }

        int expiryTime = determineRoleCertTimeout(data, roles, (int) req.getExpiryTime());
        final String x509Cert = instanceCertManager.generateX509Certificate(req.getCsr(),
                InstanceProvider.ZTS_CERT_USAGE_CLIENT, expiryTime);
        if (null == x509Cert || x509Cert.isEmpty()) {
            throw serverError("postRoleCertificateRequest: Unable to create certificate from the cert signer",
                    caller, domainName, principalDomain);
        }

        final X509Certificate roleCert = Crypto.loadX509Certificate(x509Cert);
        RoleToken roleToken = new RoleToken().setToken(x509Cert)
                .setExpiryTime(roleCert.getNotAfter().getTime() / 1000);

        // log our certificate

        instanceCertManager.logX509Cert(principal, ipAddress, ZTSConsts.ZTS_SERVICE, null, roleCert);

        return roleToken;
    }

    int getConfiguredRoleListExpiryTimeMins(Map<String, String[]> requestedRoleList) {

        int maxAllowedExpiry = 0;
        for (String domainName : requestedRoleList.keySet()) {

            DataCache data = dataStore.getDataCache(domainName);
            if (data == null) {
                continue;
            }

            Set<String> roles = new HashSet<>();
            Collections.addAll(roles, requestedRoleList.get(domainName));
            int domainMaxAllowedExpiry = getConfiguredRoleCertExpiryTimeMins(data, roles);

            // now update our total expiry time only if the value we determined
            // for the given domain is smaller

            if (domainMaxAllowedExpiry > 0 && (maxAllowedExpiry == 0 || domainMaxAllowedExpiry < maxAllowedExpiry)) {
                maxAllowedExpiry = domainMaxAllowedExpiry;
            }
        }

        return maxAllowedExpiry;
    }

    int getConfiguredRoleCertExpiryTimeMins(DataCache data, Set<String> roles) {

        // first we're going to determine the min allowed expiry
        // time for the given set of roles

        int maxAllowedExpiry = 0;
        for (String role: roles) {
            RoleMeta rm = data.getRoleMeta(role);
            if (rm == null) {
                continue;
            }
            Integer certExpiryMins = rm.getCertExpiryMins();
            if (certExpiryMins == null) {
                continue;
            }
            if (certExpiryMins > 0 && (maxAllowedExpiry == 0 || certExpiryMins < maxAllowedExpiry)) {
                maxAllowedExpiry = certExpiryMins;
            }
        }

        // if we don't have a value specified then we're going
        // to look at the domain value if one is configured

        if (maxAllowedExpiry == 0) {
            Integer certExpiryMins = data.getDomainData().getRoleCertExpiryMins();
            if (certExpiryMins != null && certExpiryMins > 0) {
                maxAllowedExpiry = certExpiryMins;
            }
        }

        return maxAllowedExpiry;
    }

    int determineRoleCertTimeout(DataCache data, Set<String> roles, int reqTime) {

        // fetch the configured max allowed value for all roles in the set

        int maxAllowedExpiry = getConfiguredRoleCertExpiryTimeMins(data, roles);

        // finally we're going to check if the caller has requested
        // some thing smaller only if we have a limit configured

        if (reqTime > 0 && (maxAllowedExpiry == 0 || reqTime < maxAllowedExpiry)) {
            maxAllowedExpiry = reqTime;
        }

        return maxAllowedExpiry;
    }

    int determineRoleCertTimeout(Map<String, String[]> requestedRoleList, int reqTime) {

        // fetch the configured max allowed value for all roles in the set

        int maxAllowedExpiry = getConfiguredRoleListExpiryTimeMins(requestedRoleList);

        // finally we're going to check if the caller has requested
        // some thing smaller only if we have a limit configured

        if (reqTime > 0 && (maxAllowedExpiry == 0 || reqTime < maxAllowedExpiry)) {
            maxAllowedExpiry = reqTime;
        }

        return maxAllowedExpiry;
    }

    boolean validateRoleCertificateRequest(final String csr, final String domainName,
            Set<String> roles, final String principal, final String proxyUser, X509Certificate cert,
            final String ip) {

        X509RoleCertRequest certReq;
        try {
            certReq = new X509RoleCertRequest(csr);
        } catch (CryptoException ex) {
            LOGGER.error("unable to parse PKCS10 CSR: " + ex.getMessage());
            return false;
        }

        if (!certReq.validate(roles, domainName, principal, proxyUser, validCertSubjectOrgValues)) {
            return false;
        }

        // validate the role cert has the correct subject ou

        if (!validateRoleCertSubjectOU(certReq, cert)) {
            return false;
        }

        // validate uriHostname in request matches the uriHostname in cert
        if (!validateUriHostname(certReq.getUriHostname(), cert)) {
            return false;
        }

        // validate InstanceID in request matches the instanceid in the cert
        if (!validateInstanceId(certReq.getInstanceId(), cert)) {
            // Todo: minitor the logs, and make this a hard failure in later iteration
            LOGGER.error("unable to match request id: {} with cert id: {}", certReq.getInstanceId(), X509CertUtils.extractRequestInstanceId(cert));
        }

        // validate the ip address if any provided

        return !verifyCertRequestIP || certReq.validateIPAddress(cert, ip);
    }

    boolean validateRoleCertSubjectOU(X509RoleCertRequest certReq, X509Certificate cert) {

        if (!verifyCertSubjectOU) {
            return true;
        }

        // the role certificate can use the value from the service
        // certificate so let's fetch that information

        final String certOU = cert != null ? Crypto.extractX509CertSubjectOUField(cert) : null;

        // validate the CSR subject ou field

        return certReq.validateSubjectOUField(null, certOU, validCertSubjectOrgUnitValues);
    }

    /**
     * validateUriHostname verifies that a non-empty uriHostname (typically found in SanURI of the CSR) matches
     * the hostname present in SanURI of the certificate of the request
     * @param uriHostname hostname present in SanURI of the request CSR
     * @param cert incoming request certificate
     * @return true or false
     */
    boolean validateUriHostname(String uriHostname, X509Certificate cert) {
        // if there is no hostname in SanURI, there is nothing to do
        if (uriHostname == null || uriHostname.isEmpty()) {
            return true;
        }

        return uriHostname.equals(X509CertUtils.extractItemFromURI(Crypto.extractX509CertURIs(cert), ZTSConsts.ZTS_CERT_HOSTNAME_URI));
    }

    /**
     * validateInstanceId verifies that when non-empty instanceId (found in SanURI of the CSR) matches the instanceId
     * present in the certificate of the request
     * @param instanceId id present in the CSR
     * @param cert incoming request certificate
     * @return true or false
     */
    boolean validateInstanceId(String instanceId, X509Certificate cert) {
        if (instanceId == null || instanceId.isEmpty()) {
            return true;
        }

        return instanceId.equals(X509CertUtils.extractRequestInstanceId(cert));
    }

    @Override
    public RoleCertificate postRoleCertificateRequestExt(ResourceContext ctx, RoleCertificateRequest req) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        if (readOnlyMode) {
            throw requestError("Server in Maintenance Read-Only mode. Please try your request later",
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        validateRequest(ctx.request(), principalDomain, caller);
        validate(req, TYPE_ROLE_CERTIFICATE_REQUEST, principalDomain, caller);

        // validate principal object to make sure we're not
        // processing a role identity and instead we require
        // a service identity

        final Principal principal = ((RsrcCtxWrapper) ctx).principal();
        validatePrincipalNotRoleIdentity(principal, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case

        String proxyForPrincipal = req.getProxyForPrincipal();

        if (proxyForPrincipal != null) {
            proxyForPrincipal = normalizeDomainAliasUser(proxyForPrincipal.toLowerCase());
        }

        final String domainName = principal.getDomain();
        setRequestDomain(ctx, principalDomain);

        // verify that this is not an authorized service principal
        // which is only supported for get role token operations

        if (isAuthorizedServicePrincipal(principal)) {
            throw forbiddenError("Authorized Service Principals not allowed",
                    caller, domainName, domainName);
        }

        // get our principal's name

        String principalName = principal.getFullName();

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("postRoleCertificateRequestExt(principal: {}, proxy-for: {}",
                    principalName, proxyForPrincipal);
        }

        // we can only have a proxy for principal request if the original
        // caller is authorized for such operations

        if (proxyForPrincipal != null && !isAuthorizedProxyUser(authorizedProxyUsers, principalName)) {
            LOGGER.error("postRoleCertificateRequestExt: Principal: " + principalName +
                    " not authorized for proxy role certificate request");
            throw forbiddenError("postRoleCertificateRequestExt: Principal: " + principalName
                    + " not authorized for proxy role certificate request",
                    caller, domainName, domainName);
        }

        X509RoleCertRequest certReq;
        try {
            certReq = new X509RoleCertRequest(req.getCsr());
        } catch (CryptoException ex) {
            throw requestError("Unable to parse PKCS10 CSR: " + ex.getMessage(),
                    caller, domainName, domainName);
        }

        Map<String, String[]> requestedRoleList = certReq.getRequestedRoleList();
        if (requestedRoleList == null) {
            throw requestError("No roles requested in CSR", caller, domainName, domainName);
        }

        if (singleDomainInRoleCert && requestedRoleList.size() != 1) {
            throw requestError("Role Certificate cannot contain roles from multiple domains",
                    caller, domainName, domainName);
        }

        // verify access to the requested roles

        if (!verifyAccessToRoles(principalName, requestedRoleList)) {
            throw forbiddenError("Not authorized to assume all requested roles by user principal",
                    caller, domainName, domainName);
        }

        // if this is proxy for operation then we want to make sure that
        // both principals have access to the same set of roles so we'll
        // remove any roles that are authorized by only one of the principals

        String proxyUser = null;
        if (proxyForPrincipal != null) {

            if (!verifyAccessToRoles(proxyForPrincipal, requestedRoleList)) {
                throw forbiddenError("Not authorized to assume all requested roles by proxy principal",
                        caller, domainName, domainName);
            }

            // we need to switch our principal

            proxyUser = principalName;
            principalName = proxyForPrincipal;
        }

        // validate request/csr details

        X509Certificate cert = principal.getX509Certificate();
        final String ipAddress = ServletRequestUtil.getRemoteAddress(ctx.request());

        if (!validateRoleCertificateExtRequest(certReq, principalName, proxyUser, cert, ipAddress)) {
            throw requestError("postRoleCertificateRequestExt: Unable to validate cert request",
                    caller, domainName, domainName);
        }

        int expiryTime = determineRoleCertTimeout(requestedRoleList, (int) req.getExpiryTime());
        final String x509Cert = instanceCertManager.generateX509Certificate(req.getCsr(),
                InstanceProvider.ZTS_CERT_USAGE_CLIENT, expiryTime);
        if (null == x509Cert || x509Cert.isEmpty()) {
            throw serverError("postRoleCertificateRequest: Unable to create certificate from the cert signer",
                    caller, domainName, domainName);
        }
        RoleCertificate roleCertificate = new RoleCertificate().setX509Certificate(x509Cert);

        // log our certificate

        instanceCertManager.logX509Cert(principal, ipAddress, ZTSConsts.ZTS_SERVICE,
                null, Crypto.loadX509Certificate(x509Cert));

        return roleCertificate;
    }

    boolean verifyAccessToRoles(final String principalName, Map<String, String[]> requestedRoleList) {

        for (String domainName : requestedRoleList.keySet()) {

            DataCache data = dataStore.getDataCache(domainName);
            if (data == null) {

                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("verifyAccessToRoles - no such domain: {}", domainName);
                }
                return false;
            }

            Set<String> roles = new HashSet<>();
            final String[] requestedRoles = requestedRoleList.get(domainName);
            dataStore.getAccessibleRoles(data, domainName, principalName, requestedRoles,
                    roles, false);

            if (roles.isEmpty() || roles.size() != requestedRoles.length) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("verifyAccessToRoles - unauthorized access to roles in domain: {}", domainName);
                }
                return false;
            }
        }

        return true;
    }

    boolean validateRoleCertificateExtRequest(X509RoleCertRequest certReq, final String principal,
            final String proxyUser, X509Certificate cert, final String ip) {

        if (!certReq.validate(principal, proxyUser, validCertSubjectOrgValues)) {
            return false;
        }

        // validate the role cert has the correct subject ou

        if (!validateRoleCertSubjectOU(certReq, cert)) {
            return false;
        }

        // validate the ip address if any provided

        return !verifyCertRequestIP || certReq.validateIPAddress(cert, ip);
    }

    boolean isAuthorizedServicePrincipal(final Principal principal) {
        final String authorizedService = principal.getAuthorizedService();
        return (authorizedService != null && !authorizedService.isEmpty());
    }

    public AWSTemporaryCredentials getAWSTemporaryCredentials(ResourceContext ctx, String domainName,
            String roleName, Integer durationSeconds, String externalId) {

        final String caller = ctx.getApiName();

        // we need to make sure we don't log the external id in
        // our access log files so we're going to set the attribute
        // to skip the query parameters

        ctx.request().setAttribute(ZTS_REQUEST_LOG_SKIP_QUERY, Boolean.TRUE);

        final String principalDomain = logPrincipalAndGetDomain(ctx);
        validateRequest(ctx.request(), principalDomain, caller);
        validate(domainName, TYPE_DOMAIN_NAME, principalDomain, caller);

        // verify that this is not an authorized service principal
        // which is only supported for get role token operations

        final Principal principal = ((RsrcCtxWrapper) ctx).principal();

        if (isAuthorizedServicePrincipal(principal)) {
            throw forbiddenError("Authorized Service Principals not allowed",
                    caller, domainName, principalDomain);
        }

        // validate principal object to make sure we're not
        // processing a role identity and instead we require
        // a service identity

        validatePrincipalNotRoleIdentity(principal, caller);

        // since the role name might contain a path and thus it has
        // been encoded, we're going to decode it first before using it
        
        try {
            roleName = URLDecoder.decode(roleName, "UTF-8");
        } catch (Exception ex) {
            LOGGER.error("Unable to decode {} - error {}", roleName, ex.getMessage());
        }
        validate(roleName, TYPE_AWS_ARN_ROLE_NAME, principalDomain, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case. However, since
        // for roleName we need to pass that to AWS, we're not going to
        // convert here instead only for the authz check
        
        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("getAWSTemporaryCredentials(domain: {}, role: {}, duration {}",
                    domainName, roleName, durationSeconds);
        }
        
        if (!cloudStore.isAwsEnabled()) {
            throw requestError("getAWSTemporaryCredentials: AWS support is not available",
                    caller, domainName, principalDomain);
        }
        
        // get our principal's name
        
        final String principalName = principal.getFullName();
        final String roleResource = domainName + ":" + roleName.toLowerCase();

        // we need to first verify that our principal is indeed configured
        // with aws assume role assertion for the specified role and domain
        
        if (!verifyAWSAssumeRole(domainName, roleResource, principalName)) {
            throw forbiddenError("getAWSTemporaryCredentials: Forbidden (ASSUME_AWS_ROLE on "
                    + roleResource + " for " + principalName + ")", caller, domainName, principalDomain);
        }
        
        // now need to get the associated cloud account for the domain name
        
        String account = cloudStore.getAwsAccount(domainName);
        if (account == null) {
            throw requestError("getAWSTemporaryCredentials: unable to retrieve AWS account for: "
                    + domainName, caller, domainName, principalDomain);
        }
        
        // obtain the credentials from the cloud store
        
        AWSTemporaryCredentials creds = cloudStore.assumeAWSRole(account, roleName, principalName,
                durationSeconds, externalId);
        if (creds == null) {
            throw requestError("getAWSTemporaryCredentials: unable to assume role " + roleName
                    + " in domain " + domainName + " for principal " + principalName,
                    caller, domainName, principalDomain);
        }
        
        return creds;
    }

    boolean verifyAWSAssumeRole(String domainName, String roleResource, String principal) {
        
        // first retrieve our domain data object from the cache
        
        DataCache data = dataStore.getDataCache(domainName);
        if (data == null) {
            LOGGER.error("verifyAWSAssumeRole: unknown domain: {}", domainName);
            return false;
        }
        
        // retrieve the roles for the principal
        
        Set<String> roles = new HashSet<>();
        dataStore.getAccessibleRoles(data, domainName, principal, null, roles, true);
        
        if (roles.isEmpty()) {
            LOGGER.error("verifyAWSAssumeRole: Principal: {}" +
                    " has no acccess to any roles in domain: {}", principal, domainName);
            return false;
        }

        // check to see if any of the roles give access to the specified resource
        
        Set<String> awsResourceSet;
        for (String role : roles) {
            awsResourceSet = data.getAWSResourceRoleSet(role);
            if (awsResourceSet != null && awsResourceSet.contains(roleResource)) {
                return true;
            }
        }
        
        LOGGER.error("verifyAWSAssumeRole: Principal: {} has no acccess to resource: {}" +
                " in domain: {}", principal, roleResource, domainName);
        
        return false;
    }

    X509CertRecord insertX509CertRecord(ResourceContext ctx, final String cn,
            final String provider, final String instanceId, final String serial,
            final Boolean certUsage, final Date expirationDate, final String hostName) {

        X509CertRecord x509CertRecord = new X509CertRecord();
        x509CertRecord.setService(cn);
        x509CertRecord.setProvider(provider);
        x509CertRecord.setInstanceId(instanceId);

        x509CertRecord.setCurrentSerial(serial);
        x509CertRecord.setCurrentIP(ServletRequestUtil.getRemoteAddress(ctx.request()));
        x509CertRecord.setCurrentTime(new Date());

        x509CertRecord.setPrevSerial(x509CertRecord.getCurrentSerial());
        x509CertRecord.setPrevIP(x509CertRecord.getCurrentIP());
        x509CertRecord.setPrevTime(x509CertRecord.getCurrentTime());
        x509CertRecord.setClientCert(certUsage);
        x509CertRecord.setExpiryTime(expirationDate);
        x509CertRecord.setHostName(hostName);
        x509CertRecord.setSvcDataUpdateTime(new Date());

        // we must be able to update our database otherwise we will not be
        // able to validate the certificate during refresh operations

        if (!instanceCertManager.insertX509CertRecord(x509CertRecord)) {
            return null;
        }

        return x509CertRecord;
    }

    void validateInstanceServiceIdentity(DomainData domainData, final String serviceName, final String caller) {

        // if the domain is one of the skip domains then we have no
        // need to check anything

        if (validateServiceSkipDomains.contains(domainData.getName())) {
            return;
        }

        List<com.yahoo.athenz.zms.ServiceIdentity> services = domainData.getServices();
        if (services != null) {
            for (com.yahoo.athenz.zms.ServiceIdentity service : services) {
                if (service.getName().equalsIgnoreCase(serviceName)) {
                    return;
                }
            }
        }

        // eventually we'll reject these requests but first we want to see
        // how many of these services are still running

        //throw requestError("Service not registered in domain", caller, domainData.getName(), domainData.getName());
        LOGGER.error("validateInstanceServiceIdentity: {} not registered for caller {}", serviceName, caller);
    }

    @Override
    public Response postInstanceRegisterInformation(ResourceContext ctx, InstanceRegisterInformation info) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        if (readOnlyMode) {
            throw requestError("Server in Maintenance Read-Only mode. Please try your request later",
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
        
        validateRequest(ctx.request(), principalDomain, caller);
        validate(info, TYPE_INSTANCE_REGISTER_INFO, principalDomain, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        AthenzObject.INSTANCE_REGISTER_INFO.convertToLowerCase(info);

        final String domain = info.getDomain().toLowerCase();
        setRequestDomain(ctx, domain);
        final String service = info.getService().toLowerCase();
        final String cn = ResourceUtils.serviceResourceName(domain, service);
        ((RsrcCtxWrapper) ctx).logPrincipal(cn);

        // before running any checks make sure it's coming from
        // an authorized ip address

        final String provider = info.getProvider();
        final String ipAddress = ServletRequestUtil.getRemoteAddress(ctx.request());
        if (!instanceCertManager.verifyInstanceCertIPAddress(provider, ipAddress)) {
            throw forbiddenError("Unknown IP: " + ipAddress + " for Provider: " + provider,
                    caller, domain, principalDomain);
        }

        // get our domain object and validate the service is correctly registered

        DomainData domainData = dataStore.getDomainData(domain);
        if (domainData == null) {
            setRequestDomain(ctx, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            throw notFoundError("Domain not found: " + domain, caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        validateInstanceServiceIdentity(domainData, cn, caller);

        // run the authorization checks to make sure the provider has been
        // authorized to launch instances in Athenz and the service has
        // authorized this provider to launch its instances
        
        Principal providerService = createPrincipalForName(provider);
        StringBuilder errorMsg = new StringBuilder(256);

        if (!instanceCertManager.authorizeLaunch(providerService, domain, service, errorMsg)) {
            throw forbiddenError(errorMsg.toString(), caller, domain, principalDomain);
        }

        // validate request/csr details
        
        X509ServiceCertRequest certReq;
        try {
            certReq = new X509ServiceCertRequest(info.getCsr());
        } catch (CryptoException ex) {
            throw requestError("unable to parse PKCS10 CSR: " + ex.getMessage(),
                    caller, domain, principalDomain);
        }

        final String serviceDnsSuffix = domainData.getCertDnsDomain();
        final DataCache athenzSysDomainCache = dataStore.getDataCache(ATHENZ_SYS_DOMAIN);

        if (!certReq.validate(domain, service, provider, validCertSubjectOrgValues, athenzSysDomainCache,
                serviceDnsSuffix, info.getHostname(), info.getHostCnames(), hostnameResolver, errorMsg)) {
            throw requestError("CSR validation failed - " + errorMsg.toString(),
                    caller, domain, principalDomain);
        }

        final String certReqInstanceId = certReq.getInstanceId();

        // validate attestation data is included in the request
        
        InstanceProvider instanceProvider = instanceProviderManager.getProvider(provider, hostnameResolver);
        if (instanceProvider == null) {
            throw requestError("unable to get instance for provider: " + provider,
                    caller, domain, principalDomain);
        }

        // include instance details in the query access log to help
        // with debugging requests

        ctx.request().setAttribute(ACCESS_LOG_ADDL_QUERY,
                getInstanceRegisterQueryLog(provider, certReqInstanceId, info.getHostname()));

        InstanceConfirmation instance = generateInstanceConfirmObject(ctx, provider, domain,
                service, info.getAttestationData(), certReqInstanceId, info.getHostname(),
                certReq, instanceProvider.getProviderScheme());

        // make sure to close our provider when its no longer needed

        Object timerProviderMetric = metric.startTiming("providerregister_timing", provider, principalDomain);
        try {
            instance = instanceProvider.confirmInstance(instance);
        } catch (com.yahoo.athenz.instance.provider.ResourceException ex) {
            metric.increment("providerconfirm_failure", domain, provider);
            int code = (ex.getCode() == ResourceException.GATEWAY_TIMEOUT) ?
                    ResourceException.GATEWAY_TIMEOUT : ResourceException.FORBIDDEN;
            throw error(code, getExceptionMsg("unable to verify attestation data: ", ctx, ex, info.getHostname()),
                    caller, domain, principalDomain);
        } catch (Exception ex) {
            metric.increment("providerconfirm_failure", domain, provider);
            throw forbiddenError(getExceptionMsg("unable to verify attestation data: ", ctx, ex, info.getHostname()),
                    caller, domain, principalDomain);
        } finally {
            metric.stopTiming(timerProviderMetric, provider, principalDomain);
            instanceProvider.close();
        }
        metric.increment("providerconfirm_success", domain, provider);

        // determine what type of certificate the provider is authorizing
        // this instance to get - possible values are: server, client or
        // null (indicating both client and server). Additionally, we're
        // going to see if the provider wants to impose an expiry time
        // though the certificate signer might decide to ignore that
        // request and override it with its own value. Other optional
        // attributes we get back from the provider include whether or
        // not the certs can be refreshed or ssh certs can be requested
        
        String certUsage = null;
        String certSubjectOU = null;
        String instancePrivateIp = null;
        int certExpiryTime = 0;
        boolean certRefresh = true;
        boolean sshCertAllowed = false;
        
        Map<String, String> instanceAttrs = instance.getAttributes();
        if (instanceAttrs != null) {
            certUsage = instanceAttrs.remove(InstanceProvider.ZTS_CERT_USAGE);
            certSubjectOU = instanceAttrs.remove(InstanceProvider.ZTS_CERT_SUBJECT_OU);
            instancePrivateIp = instanceAttrs.remove(InstanceProvider.ZTS_INSTANCE_PRIVATE_IP);
            certExpiryTime = ZTSUtils.parseInt(instanceAttrs.remove(InstanceProvider.ZTS_CERT_EXPIRY_TIME), 0);
            certRefresh = ZTSUtils.parseBoolean(instanceAttrs.remove(InstanceProvider.ZTS_CERT_REFRESH), true);
            sshCertAllowed = ZTSUtils.parseBoolean(instanceAttrs.remove(InstanceProvider.ZTS_CERT_SSH), false);
        }

        // validate the CSR subject ou field. We're doing this check here
        // because the provider can tell us what the ou field should be

        if (verifyCertSubjectOU && !certReq.validateSubjectOUField(provider, certSubjectOU,
                validCertSubjectOrgUnitValues)) {
            throw requestError("CSR Subject OrgUnit validation failed",
                    caller, domain, principalDomain);
        }

        // update the expiry time if one is provided in the request

        certExpiryTime = getServiceCertRequestExpiryTime(certExpiryTime, info.getExpiryTime());

        // generate certificate for the instance

        Object timerX509CertMetric = metric.startTiming("certsignx509_timing", null, principalDomain);
        InstanceIdentity identity = instanceCertManager.generateIdentity(info.getCsr(), cn,
                certUsage, certExpiryTime);
        metric.stopTiming(timerX509CertMetric, null, principalDomain);

        if (identity == null) {
            throw serverError("unable to generate identity", caller, domain, principalDomain);
        }

        // if we're asked then we should also generate a ssh
        // certificate for the instance as well

        if (sshCertAllowed) {
            Object timerSSHCertMetric = metric.startTiming("certsignssh_timing", null, principalDomain);

            // generate a ssh object for recording

            SSHCertRecord certRecord = generateSSHCertRecord(ctx, cn, certReqInstanceId, instancePrivateIp);
            instanceCertManager.generateSSHIdentity(null, identity, info.getHostname(), info.getSsh(),
                    certRecord, ZTSConsts.ZTS_SSH_HOST);
            metric.stopTiming(timerSSHCertMetric, null, principalDomain);
        }

        // set the other required attributes in the identity object

        identity.setAttributes(instanceAttrs);
        identity.setProvider(provider);
        identity.setInstanceId(certReqInstanceId);

        X509Certificate newCert = Crypto.loadX509Certificate(identity.getX509Certificate());
        final String certSerial = newCert.getSerialNumber().toString();
        
        // need to update our cert record with new certificate details
        // unless we're told by the provider that refresh is not allowed
        // thus no need to register the instance details

        if (certRefresh) {

            // we must be able to update our database otherwise we will not be
            // able to validate the certificate during refresh operations

            if (insertX509CertRecord(ctx, cn, provider, certReqInstanceId, certSerial,
                    InstanceProvider.ZTS_CERT_USAGE_CLIENT.equalsIgnoreCase(certUsage), newCert.getNotAfter(), info.getHostname()) == null) {
                throw serverError("unable to update cert db", caller, domain, principalDomain);
            }
        }
        
        // if we're asked to return an NToken in addition to ZTS Certificate
        // then we'll generate one and include in the identity object
        
        if (info.getToken() == Boolean.TRUE) {
            PrincipalToken svcToken = new PrincipalToken.Builder("S1", domain, service)
                .expirationWindow(svcTokenTimeout).keyId(privateKey.getId()).host(serverHostName)
                .ip(ipAddress).keyService(ZTSConsts.ZTS_SERVICE).build();
            svcToken.sign(privateKey.getKey());
            identity.setServiceToken(svcToken.getSignedToken());
        }

        // log our certificate

        instanceCertManager.logX509Cert(null, ipAddress, provider, certReqInstanceId, newCert);

        final String location = "/zts/v1/instance/" + provider + "/" + domain
                + "/" + service + "/" + certReqInstanceId;
        return Response.status(ResourceException.CREATED).entity(identity)
                .header("Location", location).build();
    }

    String getInstanceRegisterQueryLog(final String provider, final String certReqInstanceId, final String hostname) {

        StringBuilder queryLog = new StringBuilder(256);
        queryLog.append("provider=");
        queryLog.append(provider);
        if (certReqInstanceId != null) {
            queryLog.append("&certReqInstanceId=");
            queryLog.append(certReqInstanceId);
        }
        if (hostname != null) {
            queryLog.append("&hostname=");
            queryLog.append(hostname);
        }
        return (queryLog.length() < 1024) ? queryLog.toString() : queryLog.substring(0, 1024);
    }

    SSHCertRecord generateSSHCertRecord(ResourceContext ctx, final String service, final String instanceId,
            final String privateIp) {

        // generate a ssh object for recording

        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setService(service);
        certRecord.setInstanceId(instanceId);
        certRecord.setClientIP(ServletRequestUtil.getRemoteAddress(ctx.request()));
        if (StringUtil.isEmpty(privateIp)) {
            certRecord.setPrivateIP(certRecord.getClientIP());
        } else {
            certRecord.setPrivateIP(privateIp);
        }
        return certRecord;
    }

    InstanceConfirmation generateInstanceConfirmObject(ResourceContext ctx, final String provider,
            final String domain, final String service, final String attestationData,
            final String instanceId, final String instanceHostname, X509CertRequest certReq,
            InstanceProvider.Scheme providerScheme) {
        
        InstanceConfirmation instance = new InstanceConfirmation()
                .setAttestationData(attestationData)
                .setDomain(domain).setService(service).setProvider(provider);
    
        // we're going to include the hostnames and optional IP addresses
        // from the CSR for provider validation
        
        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_ID, instanceId);
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, String.join(",", certReq.getProviderDnsNames()));
        attributes.put(InstanceProvider.ZTS_INSTANCE_CLIENT_IP, ServletRequestUtil.getRemoteAddress(ctx.request()));
        final List<String> certReqIps = certReq.getIpAddresses();
        if (certReqIps != null && !certReqIps.isEmpty()) {
            attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, String.join(",", certReqIps));
        }

        // we have verified our athenz and spiffe uris but we're going
        // to send them all to the provider in case provider wants
        // to do further verification with additional uris if any were
        // included in the csr

        final List<String> certUris = certReq.getUris();
        if (certUris != null && !certUris.isEmpty()) {
            attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, String.join(",", certUris));
        }
        
        // if we have a cloud account setup for this domain, we're going
        // to include it in the optional attributes
        
        final String awsAccount = cloudStore.getAwsAccount(domain);
        if (awsAccount != null) {
            attributes.put(InstanceProvider.ZTS_INSTANCE_AWS_ACCOUNT, awsAccount);
        }
        final String azureSubscription = cloudStore.getAzureSubscription(domain);
        if (azureSubscription != null) {
            attributes.put(InstanceProvider.ZTS_INSTANCE_AZURE_SUBSCRIPTION, azureSubscription);
        }

        // if this is a class based provider then we're also going
        // to provide the public key in the CSR

        if (providerScheme == InstanceProvider.Scheme.CLASS) {
            attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, Crypto.extractX509CSRPublicKey(certReq.getCertReq()));
        }

        // include the hostname if one is specified

        if (instanceHostname != null && !instanceHostname.isEmpty()) {
            attributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, instanceHostname);
        }

        // finally we're going to include the principal if we have one in our request

        final Principal principal = ((RsrcCtxWrapper) ctx).principal();
        if (principal != null) {
            attributes.put(InstanceProvider.ZTS_REQUEST_PRINCIPAL, principal.getFullName());
        }

        instance.setAttributes(attributes);
        return instance;
    }
    
    @Override
    public InstanceIdentity postInstanceRefreshInformation(ResourceContext ctx, String provider,
            String domain, String service, String instanceId, InstanceRefreshInformation info) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        if (readOnlyMode) {
            throw requestError("Server in Maintenance Read-Only mode. Please try your request later",
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
        
        validateRequest(ctx.request(), principalDomain, caller);
        validate(provider, TYPE_SERVICE_NAME, principalDomain, caller);
        validate(domain, TYPE_DOMAIN_NAME, principalDomain, caller);
        validate(service, TYPE_SIMPLE_NAME, principalDomain, caller);
        validate(instanceId, TYPE_PATH_ELEMENT, principalDomain, caller);
        validate(info, TYPE_INSTANCE_REFRESH_INFO, principalDomain, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        provider = provider.toLowerCase();
        domain = domain.toLowerCase();
        setRequestDomain(ctx, domain);
        service = service.toLowerCase();
        
        // before running any checks make sure it's coming from
        // an authorized ip address
        
        final String ipAddress = ServletRequestUtil.getRemoteAddress(ctx.request());
        if (!instanceCertManager.verifyInstanceCertIPAddress(provider, ipAddress)) {
            throw forbiddenError("Unknown IP: " + ipAddress + " for Provider: " + provider,
                    caller, domain, principalDomain);
        }

        // get our domain object and validate the service is correctly registered

        DomainData domainData = dataStore.getDomainData(domain);
        if (domainData == null) {
            setRequestDomain(ctx, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            throw notFoundError("Domain not found: " + domain, caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        validateInstanceServiceIdentity(domainData, ResourceUtils.serviceResourceName(domain, service), caller);

        // we are going to get two use cases here. client asking for:
        // * x509 cert (optionally with ssh certificate)
        // * only ssh certificate
        // both CSRs are marked as optional so we need to make sure
        // at least one of the CSRs is provided
        
        final String x509Csr = convertEmptyStringToNull(info.getCsr());
        final String sshCsr = convertEmptyStringToNull(info.getSsh());

        if (x509Csr == null && sshCsr == null) {
            throw requestError("no csr provided", caller, domain, principalDomain);
        }
        
        // make sure the credentials match to whatever the request is

        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        final String principalName = domain + "." + service;
        if (!principalName.equals(principal.getFullName())) {
            throw requestError("Principal mismatch: " + principalName + " vs. " +
                    principal.getFullName(), caller, domain, principalDomain);
        }

        Authority authority = principal.getAuthority();
        
        // we only support services that already have certificates
        
        if (!(authority instanceof CertificateAuthority)) {
            throw requestError("Unsupported authority for TLS Certs: " +
                    authority.toString(), caller, domain, principalDomain);
        }
        
        // first we need to make sure that the provider has been
        // authorized in Athenz to bootstrap/launch instances
        
        Principal providerService = createPrincipalForName(provider);
        StringBuilder errorMsg = new StringBuilder(256);

        if (!instanceCertManager.authorizeLaunch(providerService, domain, service, errorMsg)) {
            throw forbiddenError(errorMsg.toString(), caller, domain, principalDomain);
        }

        // retrieve the certificate that was used for authentication

        X509Certificate cert = principal.getX509Certificate();
        
        InstanceIdentity identity;
        if (x509Csr != null) {
            identity = processProviderX509RefreshRequest(ctx, domainData, principal, domain, service,
                    provider, instanceId, info, cert, caller);
        } else {
            identity = processProviderSSHRefreshRequest(principal, domain, provider, instanceId, sshCsr, caller);
        }
        
        return identity;
    }
    
    InstanceIdentity processProviderX509RefreshRequest(ResourceContext ctx, DomainData domainData,
            final Principal principal, final String domain, final String service, final String provider,
            final String instanceId, InstanceRefreshInformation info, X509Certificate cert, final String caller) {

        // parse and validate our CSR

        final String principalDomain = principal.getDomain();
        X509ServiceCertRequest certReq;
        try {
            certReq = new X509ServiceCertRequest(info.getCsr());
        } catch (CryptoException ex) {
            throw requestError("unable to parse PKCS10 CSR", caller, domain, principalDomain);
        }

        final String serviceDnsSuffix = domainData.getCertDnsDomain();
        final DataCache athenzSysDomainCache = dataStore.getDataCache(ATHENZ_SYS_DOMAIN);

        StringBuilder errorMsg = new StringBuilder(256);
        if (!certReq.validate(domain, service, provider, validCertSubjectOrgValues, athenzSysDomainCache,
                serviceDnsSuffix, info.getHostname(), info.getHostCnames(), hostnameResolver, errorMsg)) {
            throw requestError("CSR validation failed - " + errorMsg.toString(),
                    caller, domain, principalDomain);
        }

        // validate that the instance id in csr matches to what is
        // specified in the uri and in the principal's certificate

        if (!certReq.validateInstanceId(instanceId, cert)) {
            throw requestError("CSR validation failed - instance id mismatch",
                    caller, domain, principalDomain);
        }
        
        // validate attestation data is included in the request
        
        InstanceProvider instanceProvider = instanceProviderManager.getProvider(provider, hostnameResolver);
        if (instanceProvider == null) {
            throw requestError("unable to get instance for provider: " + provider,
                    caller, domain, principalDomain);
        }
        
        InstanceConfirmation instance = generateInstanceConfirmObject(ctx, provider,
                domain, service, info.getAttestationData(), instanceId, info.getHostname(),
                certReq, instanceProvider.getProviderScheme());
        
        // make sure to close our provider when its no longer needed

        Object timerProviderMetric = metric.startTiming("providerrefresh_timing", provider, principalDomain);
        try {
            instance = instanceProvider.refreshInstance(instance);
        } catch (com.yahoo.athenz.instance.provider.ResourceException ex) {
            metric.increment("providerconfirm_failure", domain, provider);
            int code = (ex.getCode() == ResourceException.GATEWAY_TIMEOUT) ?
                    ResourceException.GATEWAY_TIMEOUT : ResourceException.FORBIDDEN;
            throw error(code, getExceptionMsg("unable to verify attestation data: ", ctx, ex, info.getHostname()),
                    caller, domain, principalDomain);
        } catch (Exception ex) {
            metric.increment("providerconfirm_failure", domain, provider);
            throw forbiddenError(getExceptionMsg("unable to verify attestation data: ", ctx, ex, info.getHostname()),
                    caller, domain, principalDomain);
        } finally {
            metric.stopTiming(timerProviderMetric, provider, principalDomain);
            instanceProvider.close();
        }
        metric.increment("providerconfirm_success", domain, provider);

        // determine what type of certificate the provider is authorizing
        // this instance to refresh - possible values are: server, client or
        // null (indicating both client and server). Additionally, we're
        // going to see if the provider wants to impose an expiry time
        // though the certificate signer might decide to ignore that
        // request and override it with its own value. Other optional
        // attributes we get back from the provider include whether or
        // not the certs can be refreshed or ssh certs can be requested
        
        String certUsage = null;
        String certSubjectOU = null;
        String instancePrivateIp = null;
        int certExpiryTime = 0;
        boolean sshCertAllowed = false;
        boolean certRefreshCheck = true;

        Map<String, String> instanceAttrs = instance.getAttributes();
        if (instanceAttrs != null) {
            certUsage = instanceAttrs.remove(InstanceProvider.ZTS_CERT_USAGE);
            instancePrivateIp = instanceAttrs.remove(InstanceProvider.ZTS_INSTANCE_PRIVATE_IP);
            certExpiryTime = ZTSUtils.parseInt(instanceAttrs.remove(InstanceProvider.ZTS_CERT_EXPIRY_TIME), 0);
            certRefreshCheck = ZTSUtils.parseBoolean(instanceAttrs.remove(InstanceProvider.ZTS_CERT_REFRESH), true);
            certSubjectOU = instanceAttrs.remove(InstanceProvider.ZTS_CERT_SUBJECT_OU);
            sshCertAllowed = ZTSUtils.parseBoolean(instanceAttrs.remove(InstanceProvider.ZTS_CERT_SSH), false);
        }

        // validate the CSR subject ou field. We're doing this check here
        // because the provider can tell us what the ou field should be

        if (verifyCertSubjectOU && !certReq.validateSubjectOUField(provider, certSubjectOU,
                validCertSubjectOrgUnitValues)) {
            throw requestError("CSR Subject OrgUnit validation failed", caller, domain, principalDomain);
        }

        // validate that the tenant domain/service matches to the values
        // in the cert record when it was initially issued

        final String principalName = principal.getFullName();

        // if the provider allows the certs to be refreshed then we need
        // to extract our instance certificate record to make sure it
        // hasn't been revoked already

        X509CertRecord x509CertRecord = null;
        if (certRefreshCheck) {
            x509CertRecord = getValidatedX509CertRecord(ctx, provider, instanceId,
                principalName, cert, caller, domain, principalDomain, info.getHostname());
        }

        if (x509CertRecord != null && x509CertRecord.getClientCert()) {
            certUsage = InstanceProvider.ZTS_CERT_USAGE_CLIENT;
        }

        // update the expiry time if one is provided in the request

        certExpiryTime = getServiceCertRequestExpiryTime(certExpiryTime, info.getExpiryTime());

        // generate identity with the certificate

        Object timerX509CertMetric = metric.startTiming("certsignx509_timing", null, principalDomain);
        InstanceIdentity identity = instanceCertManager.generateIdentity(info.getCsr(), principalName,
                certUsage, certExpiryTime);
        metric.stopTiming(timerX509CertMetric, null, principalDomain);

        if (identity == null) {
            throw serverError("unable to generate identity", caller, domain, principalDomain);
        }

        // if we're asked then we should also generate a ssh
        // certificate for the instance as well

        if (sshCertAllowed) {
            Object timerSSHCertMetric = metric.startTiming("certsignssh_timing", null, principalDomain);

            // generate a ssh object for recording

            SSHCertRecord certRecord = generateSSHCertRecord(ctx, domain + "." + service, instanceId,
                    instancePrivateIp);
            instanceCertManager.generateSSHIdentity(principal, identity, info.getHostname(), info.getSsh(),
                    certRecord, ZTSConsts.ZTS_SSH_HOST);
            metric.stopTiming(timerSSHCertMetric, null, principalDomain);
        }

        // set the other required attributes in the identity object

        identity.setAttributes(instanceAttrs);
        identity.setProvider(provider);
        identity.setInstanceId(instanceId);
        
        // need to update our cert record with new certificate details
        
        X509Certificate newCert = Crypto.loadX509Certificate(identity.getX509Certificate());
        final String certSerialNumber = newCert.getSerialNumber().toString();
        final String reqIp = ServletRequestUtil.getRemoteAddress(ctx.request());

        if (x509CertRecord != null) {

            // if our current IP or hostname has changed, we'll mark
            // the record as svc data updated

            processCertRecordChange(x509CertRecord, reqIp, info.getHostname());

            // now let's update our record

            x509CertRecord.setCurrentSerial(certSerialNumber);
            x509CertRecord.setCurrentIP(reqIp);
            x509CertRecord.setCurrentTime(new Date());
            x509CertRecord.setExpiryTime(newCert.getNotAfter());
            x509CertRecord.setHostName(info.getHostname());

            // we must be able to update our record db otherwise we will
            // not be able to validate the refresh request next time

            if (!instanceCertManager.updateX509CertRecord(x509CertRecord)) {
                throw serverError("unable to update cert db", caller, domain, principalDomain);
            }
        }

        // log our certificate

        instanceCertManager.logX509Cert(principal, reqIp, provider, instanceId, newCert);

        // if we're asked to return an NToken in addition to ZTS Certificate
        // then we'll generate one and include in the identity object
        
        if (info.getToken() == Boolean.TRUE) {
            PrincipalToken svcToken = new PrincipalToken.Builder("S1", domain, service)
                .expirationWindow(svcTokenTimeout).keyId(privateKey.getId()).host(serverHostName)
                .ip(ServletRequestUtil.getRemoteAddress(ctx.request()))
                .keyService(ZTSConsts.ZTS_SERVICE).build();
            svcToken.sign(privateKey.getKey());
            identity.setServiceToken(svcToken.getSignedToken());
        }
        
        return identity;
    }

    void processCertRecordChange(X509CertRecord x509CertRecord, final String reqIp, final String hostname) {
        if (certRecordChanged(x509CertRecord.getCurrentIP(), reqIp) || certRecordChanged(x509CertRecord.getHostName(), hostname)) {
            x509CertRecord.setSvcDataUpdateTime(new Date());
        }
    }

    boolean certRecordChanged(final String value1, final String value2) {
        return ((value1 == null && value2 != null) || (value1 != null && !value1.equals(value2)));
    }

    InstanceIdentity processProviderSSHRefreshRequest(final Principal principal, final String domain,
            final String provider, final String instanceId, final String sshCsr, final String caller) {

        LOGGER.info("User ssh certificate request from {}", principal.getFullName());

        final String principalName = principal.getFullName();
        final String principalDomain = principal.getDomain();

        // generate identity with the ssh certificate
        
        InstanceIdentity identity = new InstanceIdentity().setName(principalName);
        Object timerSSHCertMetric = metric.startTiming("certsignssh_timing", null, principalDomain);
        if (!instanceCertManager.generateSSHIdentity(principal, identity, null, sshCsr, null, ZTSConsts.ZTS_SSH_USER)) {
            throw serverError("unable to generate ssh identity", caller, domain, principalDomain);
        }
        metric.stopTiming(timerSSHCertMetric, null, principalDomain);

        // set the other required attributes in the identity object

        identity.setProvider(provider);
        identity.setInstanceId(instanceId);

        return identity;
    }

    int getServiceCertRequestExpiryTime(int certExpiryTime, Integer reqExpiryTime) {

        if (reqExpiryTime == null || reqExpiryTime < 0) {
            return certExpiryTime;
        }

        // we already verified that reqExpiryTime is not negative
        // so if we certExpiryTime is 0, we'll just return that value

        if (certExpiryTime == 0) {
            return reqExpiryTime;
        } else {
            return reqExpiryTime < certExpiryTime ? reqExpiryTime : certExpiryTime;
        }
    }

    X509CertRecord getValidatedX509CertRecord(ResourceContext ctx, final String provider,
            final String instanceId, final String principalName, X509Certificate cert,
            final String caller, final String requestDomain, final String principalDomain,
            final String hostName) {

        // extract our instance certificate record to make sure it
        // hasn't been revoked already

        X509CertRecord x509CertRecord = instanceCertManager.getX509CertRecord(provider,
                instanceId, principalName);
        if (x509CertRecord == null) {

            // if the record is not present check to see if we're in recovery
            // mode where if the certificate was issued before the configured
            // time we're going to assume it is valid and we'll just create
            // an object based on the configured details

            if (cert.getNotBefore().getTime() < x509CertRefreshResetTime) {
                x509CertRecord = insertX509CertRecord(ctx, principalName, provider, instanceId,
                        cert.getSerialNumber().toString(), false, cert.getNotAfter(), hostName);
            }

            if (x509CertRecord == null) {
                throw forbiddenError("Unable to find certificate record", caller, requestDomain, principalDomain);
            }
        }

        if (!principalName.equals(x509CertRecord.getService())) {
            throw requestError("service name mismatch - csr: " + principalName +
                    " cert db: " + x509CertRecord.getService(), caller, requestDomain, principalDomain);
        }

        // now we need to make sure the serial number for the certificate
        // matches to what we had issued previously. If we have a mismatch
        // then we're going to revoke this instance as it has been possibly
        // compromised

        String serialNumber = cert.getSerialNumber().toString();
        if (x509CertRecord.getCurrentSerial().equals(serialNumber)) {

            // update the record to mark current as previous
            // and we'll update the current set with our existing
            // details

            x509CertRecord.setPrevIP(x509CertRecord.getCurrentIP());
            x509CertRecord.setPrevTime(x509CertRecord.getCurrentTime());
            x509CertRecord.setPrevSerial(x509CertRecord.getCurrentSerial());

        } else if (!x509CertRecord.getPrevSerial().equals(serialNumber)) {

            // check to see if we're in recovery/migration mode in which
            // case the instance refreshed multiple times in a short period
            // and hit both old and new systems thus the sequence is no longer
            // valid - in this case we're going to not revoke since when
            // refreshed again next time, if this is truly invalid, we'll
            // revoke it at that time

            if (cert.getNotBefore().getTime() > x509CertRefreshResetTime) {
                revokeCertificateRefresh(principalName, serialNumber, x509CertRecord);
                throw forbiddenError("Certificate revoked", caller, requestDomain, principalDomain);
            }
        }

        return x509CertRecord;
    }

    void revokeCertificateRefresh(final String principalName, final String serialNumber,
            X509CertRecord x509CertRecord) {

        // we have a mismatch for both current and previous serial
        // numbers so we're going to revoke it

        LOGGER.error("Revoking certificate refresh for cn: {} instance id: {}, current serial: {}, previous serial: {}, cert serial: {}",
                principalName, x509CertRecord.getInstanceId(), x509CertRecord.getCurrentSerial(),
                x509CertRecord.getPrevSerial(), serialNumber);

        x509CertRecord.setPrevSerial("-1");
        x509CertRecord.setCurrentSerial("-1");

        instanceCertManager.updateX509CertRecord(x509CertRecord);
    }

    @Override
    public void deleteInstanceIdentity(ResourceContext ctx, String provider,
            String domain, String service, String instanceId) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        if (readOnlyMode) {
            throw requestError("Server in Maintenance Read-Only mode. Please try your request later",
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
        
        validateRequest(ctx.request(), principalDomain, caller);
        validate(provider, TYPE_SERVICE_NAME, principalDomain, caller);
        validate(domain, TYPE_DOMAIN_NAME, principalDomain, caller);
        validate(service, TYPE_SIMPLE_NAME, principalDomain, caller);
        validate(instanceId, TYPE_PATH_ELEMENT, principalDomain, caller);

        // validate principal object to make sure we're not
        // processing a role identity and instead we require
        // a service identity

        final Principal principal = ((RsrcCtxWrapper) ctx).principal();
        validatePrincipalNotRoleIdentity(principal, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        provider = provider.toLowerCase();
        domain = domain.toLowerCase();
        setRequestDomain(ctx, domain);
        service = service.toLowerCase();
        
        // remove the cert record for this instance

        instanceCertManager.deleteX509CertRecord(provider, instanceId, domain + "." + service);
    }

    @Deprecated
    @Override
    public Identity postInstanceRefreshRequest(ResourceContext ctx, String domain,
            String service, InstanceRefreshRequest req) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        if (readOnlyMode) {
            throw requestError("Server in Maintenance Read-Only mode. Please try your request later",
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
        
        validateRequest(ctx.request(), principalDomain, caller);
        validate(domain, TYPE_DOMAIN_NAME, principalDomain, caller);
        validate(service, TYPE_SIMPLE_NAME, principalDomain, caller);
        validate(req, TYPE_INSTANCE_REFRESH_REQUEST, principalDomain, caller);

        // validate principal object to make sure we're not
        // processing a role identity and instead we require
        // a service identity

        final Principal principal = ((RsrcCtxWrapper) ctx).principal();
        validatePrincipalNotRoleIdentity(principal, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domain = domain.toLowerCase();
        setRequestDomain(ctx, domain);
        service = service.toLowerCase();

        // make sure the credentials match to whatever the request is

        String fullServiceName = domain + "." + service;
        final String principalName = principal.getFullName();
        boolean userRequest = false;

        if (!fullServiceName.equals(principalName)) {
            
            // if this not a match then we're going to allow the operation
            // only if the principal has been authorized to manage
            // services within the given domain
            
            try {
                userRequest = authorizer.access("update", domain + ":service", principal, null);
            } catch (ResourceException ex) {
                LOGGER.error("postInstanceRefreshRequest: access check failure for {}: {}",
                        principalName, ex.getMessage());
            }
           
            if (!userRequest) {
                throw requestError("Principal mismatch: " + fullServiceName + " vs. " +
                        principalName, caller, domain, principalDomain);
            }
        }
         
        // need to verify (a) it's not a user and (b) the public key for the request
        // must match what's in the CSR. Personal domain users cannot get personal
        // TLS certificates from ZTS
        
        if (userDomain.equalsIgnoreCase(domain)) {
            throw requestError("TLS Certificates require ServiceTokens: " +
                    fullServiceName, caller, domain, principalDomain);
        }
        
        // determine if this is a refresh or initial request
        
        final Authority authority = principal.getAuthority();
        boolean refreshOperation = (!userRequest && (authority instanceof CertificateAuthority));
        
        // retrieve the public key for the request for verification
        
        final String keyId = userRequest || refreshOperation ? req.getKeyId() : principal.getKeyId();
        String publicKey = getPublicKey(domain, service, keyId);
        if (publicKey == null) {
            throw requestError("Unable to retrieve public key for " + fullServiceName +
                    " with key id: " + keyId, caller, domain, principalDomain);
        }
        
        // validate that the cn and public key match to the provided details
        
        X509CertRequest x509CertReq;
        try {
            x509CertReq = new X509CertRequest(req.getCsr());
        } catch (CryptoException ex) {
            throw requestError("Unable to parse PKCS10 certificate request",
                    caller, domain, principalDomain);
        }
        
        final PKCS10CertificationRequest certReq = x509CertReq.getCertReq();
        if (!ZTSUtils.verifyCertificateRequest(certReq, domain, service, null)) {
            throw requestError("Invalid CSR - data mismatch", caller, domain, principalDomain);
        }

        // validate that the csr contains a valid subject O field

        if (!x509CertReq.validateSubjectOField(validCertSubjectOrgValues)) {
            throw requestError("Invalid CSR - invalid Subject O field", caller, domain, principalDomain);
        }

        // validate the CSR subject ou field

        if (verifyCertSubjectOU && !x509CertReq.validateSubjectOUField(null, null,
                validCertSubjectOrgUnitValues)) {
            throw requestError("Invalid CSR - invalid Subject OU field", caller, domain, principalDomain);
        }

        // verify that the public key in the csr matches to the service
        // public key registered in Athenz
        
        if (!x509CertReq.validatePublicKeys(publicKey)) {
            throw requestError("Invalid CSR - public key mismatch", caller, domain, principalDomain);
        }

        // verify the IP address in the request matches where the connection
        // is coming from

        final String ipAddress = ServletRequestUtil.getRemoteAddress(ctx.request());
        if (verifyCertRequestIP && !x509CertReq.validateIPAddress(ipAddress)) {
            throw requestError("Invalid CSR - IP address mismatch", caller, domain, principalDomain);
        }

        // if this is not a user request and the principal authority is the
        // certificate authority then we're refreshing our certificate as
        // opposed to requesting a new one for the service so we're going
        // to do further validation based on the certificate we authenticated
        
        if (refreshOperation) {
            ServiceX509RefreshRequestStatus status =  validateServiceX509RefreshRequest(principal,
                    x509CertReq, ipAddress);
            if (status == ServiceX509RefreshRequestStatus.IP_NOT_ALLOWED) {
                throw forbiddenError("IP not allowed for refresh: " + ipAddress,
                        caller, domain, principalDomain);
            }
            if (status != ServiceX509RefreshRequestStatus.SUCCESS) {
                throw requestError("Request validation failed: " + status,
                        caller, domain, principalDomain);
            }
        }
        
        // generate identity with the certificate
        
        int expiryTime = req.getExpiryTime() != null ? req.getExpiryTime() : 0;
        Identity identity = ZTSUtils.generateIdentity(instanceCertManager, req.getCsr(),
                fullServiceName, null, expiryTime);
        if (identity == null) {
            throw serverError("Unable to generate identity", caller, domain, principalDomain);
        }
        identity.setCaCertBundle(instanceCertManager.getX509CertificateSigner());

        // log our certificate

        instanceCertManager.logX509Cert(principal, ipAddress, ZTSConsts.ZTS_SERVICE,
                ZTSUtils.extractCertReqInstanceId(certReq),
                Crypto.loadX509Certificate(identity.getCertificate()));

        return identity;
    }
    
    ServiceX509RefreshRequestStatus validateServiceX509RefreshRequest(final Principal principal,
            final X509CertRequest certReq, final String ipAddress) {
        
        // retrieve the certificate that was used for authentication
        // and verify that the dns names in the certificate match to
        // the values specified in the CSR
        
        X509Certificate cert = principal.getX509Certificate();
        if (!certReq.validateDnsNames(cert)) {
            return ServiceX509RefreshRequestStatus.DNS_NAME_MISMATCH;
        }
        
        // validate that the certificate and csr both are based
        // on the same public key
        
        if (!certReq.validatePublicKeys(cert)) {
            return ServiceX509RefreshRequestStatus.PUBLIC_KEY_MISMATCH;
        }
        
        // finally verify that the ip address is in the allowed range
        
        if (!instanceCertManager.verifyCertRefreshIPAddress(ipAddress)) {
            return ServiceX509RefreshRequestStatus.IP_NOT_ALLOWED;
        }
        
        return ServiceX509RefreshRequestStatus.SUCCESS;
    }

    @Override
    public Response postSSHCertRequest(ResourceContext ctx, SSHCertRequest certRequest) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        if (readOnlyMode) {
            throw requestError("Server in Maintenance Read-Only mode. Please try your request later",
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        validateRequest(ctx.request(), principalDomain, caller);
        validate(certRequest, TYPE_SSH_CERT_REQUEST, principalDomain, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        AthenzObject.SSH_CERT_REQUEST.convertToLowerCase(certRequest);

        // get our principal and domain values

        final Principal principal = ((RsrcCtxWrapper) ctx).principal();
        final String domainName = principal.getDomain();
        setRequestDomain(ctx, domainName);

        // generate our certificate. the ssh signer interface throws
        // rest ResourceExceptions so we'll catch and log those

        SSHCertificates certs;
        try {
            certs = instanceCertManager.generateSSHCertificates(principal, certRequest);
        } catch (com.yahoo.athenz.common.server.rest.ResourceException ex) {
            throw error(ex.getCode(), ex.getMessage(), caller, domainName, principalDomain);
        }

        return Response.status(ResourceException.CREATED).entity(certs).build();
    }

    @Override
    public JWKList getJWKList(ResourceContext ctx, Boolean rfc) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        validateRequest(ctx.request(), principalDomain, caller);

        return dataStore.getZtsJWKList(rfc);
    }

    long getSvcTokenExpiryTime(Integer expiryTime) {
        
        long requestedValue = (expiryTime != null) ? expiryTime : ZTS_NTOKEN_DEFAULT_EXPIRY;
        if (requestedValue <= 0) {
            requestedValue = ZTS_NTOKEN_DEFAULT_EXPIRY;
        } else if (requestedValue > ZTS_NTOKEN_MAX_EXPIRY) {
            requestedValue = ZTS_NTOKEN_MAX_EXPIRY;
        }
        
        return requestedValue;
    }
    
    Principal createPrincipalForName(String principalName) {
        
        String domain;
        String name;
        
        // if we have no . in the principal name we're going to default
        // to our configured user domain
        
        int idx = principalName.lastIndexOf('.');
        if (idx == -1) {
            domain = userDomain;
            name = principalName;
        } else {
            domain = principalName.substring(0, idx);
            if (userDomainAlias != null && userDomainAlias.equals(domain)) {
                domain = userDomain;
            }
            name = principalName.substring(idx + 1);
        }
        
        return SimplePrincipal.create(domain, name, (String) null);
    }
    
    @Override
    public ResourceAccess getResourceAccessExt(ResourceContext ctx, String action, String resource,
            String trustDomain, String checkPrincipal) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        validateRequest(ctx.request(), principalDomain, caller);
        validate(action, TYPE_COMPOUND_NAME, principalDomain, caller);
        
        return getResourceAccessCheck(ctx, ((RsrcCtxWrapper) ctx).principal(), action, resource,
                trustDomain, checkPrincipal);
    }
    
    @Override
    public ResourceAccess getResourceAccess(ResourceContext ctx, String action, String resource,
            String trustDomain, String checkPrincipal) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        validateRequest(ctx.request(), principalDomain, caller);
        validate(action, TYPE_COMPOUND_NAME, principalDomain, caller);
        validate(resource, TYPE_RESOURCE_NAME, principalDomain, caller);

        return getResourceAccessCheck(ctx, ((RsrcCtxWrapper) ctx).principal(), action, resource,
                trustDomain, checkPrincipal);
    }
    
    ResourceAccess getResourceAccessCheck(ResourceContext ctx, Principal principal, String action, String resource,
            String trustDomain, String checkPrincipal) {

        final String domainName = principal.getDomain();
        setRequestDomain(ctx, domainName);

        // if the check principal is given then we need to carry out the access
        // check against that principal
        
        if (checkPrincipal != null) {
            principal = createPrincipalForName(checkPrincipal);
        }
        
        // create our response object and set the flag whether
        // or not the principal has access to the resource
        
        ResourceAccess access = new ResourceAccess();
        access.setGranted(authorizer.access(action, resource, principal, trustDomain));
        
        return access;
    }
    
    @Override
    public Access getAccess(ResourceContext ctx, String domainName, String roleName,
            String principal) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);
        
        validateRequest(ctx.request(), principalDomain, caller);
        validate(domainName, TYPE_DOMAIN_NAME, principalDomain, caller);
        validate(roleName, TYPE_ENTITY_NAME, principalDomain, caller);
        validate(principal, TYPE_ENTITY_NAME, principalDomain, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case
        
        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        roleName = roleName.toLowerCase();
        principal = normalizeDomainAliasUser(principal.toLowerCase());

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("getAccess(domain: " + domainName + ", principal: " + principal +
                    ", role: " + roleName + ")");
        }
        
        // first retrieve our domain data object from the cache

        DataCache data = dataStore.getDataCache(domainName);
        if (data == null) {
            setRequestDomain(ctx, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            throw notFoundError("getAccess: No such domain: " + domainName, caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
        
        // process our request and retrieve the roles for the principal
        
        Set<String> roles = new HashSet<>();
        dataStore.getAccessibleRoles(data, domainName, principal, null,
                roles, false);
        
        // create our response object and set the flag whether
        // or not the principal has access to the role
        
        Access access = new Access();
        access.setGranted(roles.contains(roleName));
        
        return access;
    }

    public CertificateAuthorityBundle getCertificateAuthorityBundle(ResourceContext ctx, String name) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        validateRequest(ctx.request(), name, caller);
        validate(name, TYPE_SIMPLE_NAME, principalDomain, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case

        name = name.toLowerCase();
        setRequestDomain(ctx, name);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("getCertificateAuthorityBundle(name: {})", name);
        }

        // fetch the requested bundle from the cert manager

        CertificateAuthorityBundle bundle = instanceCertManager.getCertificateAuthorityBundle(name);
        if (bundle == null) {
            throw notFoundError("getCertificateAuthorityBundle: No such bundle: " + name,
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        return bundle;
    }

    /*
     * /metrics/{domainName}
     */
    @Override
    public DomainMetrics postDomainMetrics(ResourceContext ctx, String domainName,
            DomainMetrics domainMetrics) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        if (readOnlyMode) {
            throw requestError("Server in Maintenance Read-Only mode. Please try your request later",
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
        
        validateRequest(ctx.request(), principalDomain, caller);
        validate(domainName, TYPE_DOMAIN_NAME, principalDomain, caller);
        validate(domainMetrics, TYPE_DOMAIN_METRICS, principalDomain, caller);
        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
 
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        AthenzObject.DOMAIN_METRICS.convertToLowerCase(domainMetrics);

        // verify valid domain specified
        DataCache data = dataStore.getDataCache(domainName);
        if (data == null) {
            metric.increment(HTTP_REQUEST, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
            metric.increment(caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
            throw notFoundError("postDomainMetrics: No such domain: " + domainName,
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        // verify domain name matches domain name in request object
        
        final String metricDomain = domainMetrics.getDomainName();
        if (!metricDomain.equals(domainName)) {
            final String errMsg = "postDomainMetrics: mismatched domain names: uri domain: "
                    + domainName + " : metric domain: " + metricDomain;
            throw requestError(errMsg, caller, domainName, principalDomain);
        }

        List<DomainMetric> dmList = domainMetrics.getMetricList();
        if (dmList == null || dmList.size() == 0) {
            // no metrics were sent - log error
            final String errMsg = "postDomainMetrics: received no metrics for domain: " + domainName;
            throw requestError(errMsg, caller, domainName, principalDomain);
        }

        // process the DomainMetrics request in order to increment each of its attrs
        
        for (DomainMetric dm: dmList) {
            final String dmt = dm.getMetricType().toString().toLowerCase();
            int count = dm.getMetricVal();
            if (count <= 0) {
                LOGGER.error("postDomainMetrics: ignore metric: {} invalid counter {} received for domain {}",
                        dmt, count, domainName);
                continue;
            }
            String metricName = DOM_METRIX_PREFIX + dmt;
            metric.increment(metricName, domainName, principalDomain, count);
        }

        return domainMetrics;
    }
    
    @Override
    public Status getStatus(ResourceContext ctx) {

        final String caller = ctx.getApiName();
        final String principalDomain = logPrincipalAndGetDomain(ctx);

        // validate our request as status request
        
        validateRequest(ctx.request(), principalDomain, caller, true);

        // for now we're going to verify our certsigner connectivity
        // only if the administrator has configured it. without certsigner
        // we can still issue role tokens and temporary credentials
        // in case of failure we're going to return not found

        if (statusCertSigner) {
            if (instanceCertManager.getCACertificate() == null) {
                throw notFoundError("Unable to communicate with cert signer", caller,
                        ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
            }
        }

        // check if we're configured to check for the status file

        if (healthCheckFile != null && !healthCheckFile.exists()) {
            throw notFoundError("Error - no status available", caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        // if the statusChecker is set, check the status

        if (statusChecker != null) {
            try {
                statusChecker.check();
            } catch (StatusCheckException e) {
                throw error(e.getCode(), e.getMsg(), caller,
                        ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
            }
        }

        return successServerStatus;
    }
    
    @Override
    public Schema getRdlSchema(ResourceContext context) {
        return schema;
    }
    
    void validateRequest(HttpServletRequest request, final String principalDomain, final String caller) {
        validateRequest(request, principalDomain, caller, false);
    }
    
    void validateRequest(HttpServletRequest request, final String principalDomain, final String caller,
                         boolean statusRequest) {
        
        // first validate if we're required process this over TLS only
        
        if (secureRequestsOnly && !request.isSecure()) {
            throw requestError(caller + "request must be over TLS", caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
        
        // second check if this is a status port so we can only
        // process on status requests
        
        if (statusPort > 0 && statusPort != httpPort && statusPort != httpsPort) {
            
            // non status requests must not take place on the status port
            
            if (!statusRequest && request.getLocalPort() == statusPort) {
                throw requestError("incorrect port number for a non-status request",
                        caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
            }
            
            // status requests must not take place on a non-status port
            
            if (statusRequest && request.getLocalPort() != statusPort) {
                throw requestError("incorrect port number for a status request",
                        caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
            }
        }
    }
    
    void validate(Object val, final String type, final String principalDomain, final String caller) {
        if (val == null) {
            throw requestError("Missing or malformed " + type, caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        try {
            Result result = validator.validate(val, type);
            if (!result.valid) {
                throw requestError("Invalid " + type + " error: " + result.error, caller,
                        ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
            }
        } catch (Exception ex) {
            LOGGER.error("Object validation exception", ex);
            throw requestError("Invalid " + type + " error: " + ex.getMessage(), caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
    }

    void validatePrincipalNotRoleIdentity(Principal principal, final String caller) {
        if (principal != null && principal.getRoles() != null) {
            throw forbiddenError("Role Identity not authorized for request", caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principal.getDomain());
        }
    }

    String logPrincipalAndGetDomain(ResourceContext ctx) {
        
        // we are going to log our principal and validate that it
        // contains expected data
        
        final Principal ctxPrincipal = ((RsrcCtxWrapper) ctx).principal();
        ((RsrcCtxWrapper) ctx).logPrincipal(ctxPrincipal);
        if (ctxPrincipal != null && ctxPrincipal.getFullName() != null) {
            final String ctxPrincipalDomain = ctxPrincipal.getDomain();
            validate(ctxPrincipal.getFullName(), TYPE_SERVICE_NAME, "logPrincipal", ctxPrincipalDomain);
            return ctxPrincipalDomain;
        }
        return null;
    }

    String getPrincipalDomain(ResourceContext ctx) {
        if (ctx == null) {
            return null;
        }
        final Principal ctxPrincipal = ((RsrcCtxWrapper) ctx).principal();
        return ctxPrincipal == null ? null : ctxPrincipal.getDomain();
    }

    void setRequestDomain(ResourceContext ctx, String requestDomainName) {
        ((RsrcCtxWrapper) ctx).setRequestDomain(requestDomainName);
    }

    String getRequestDomainName(ResourceContext ctx) {
        if (ctx == null) {
            return null;
        }
        return ((RsrcCtxWrapper) ctx).getRequestDomain();
    }

    Object getTimerMetric(ResourceContext ctx) {
        if (ctx == null) {
            return null;
        }
        return ((RsrcCtxWrapper) ctx).getTimerMetric();
    }

    protected RuntimeException error(int code, final String msg, final String caller,
                                     final String requestDomain, final String principalDomain) {

        LOGGER.error("Error: {} request-domain: {} principal-domain: {} code: {} message: {}",
                caller, requestDomain, principalDomain, code, msg);

        // emit our metrics if configured. the method will automatically
        // return from the caller if caller is null

        ZTSUtils.emitMonmetricError(code, caller, requestDomain, principalDomain, this.metric);
        return new ResourceException(code, new ResourceError().code(code).message(msg));
    }

    protected RuntimeException requestError(final String msg, final String caller, final String requestDomain,
                                            final String principalDomain) {
        return error(ResourceException.BAD_REQUEST, msg, caller, requestDomain, principalDomain);
    }

    protected RuntimeException forbiddenError(final String msg, final String caller, final String requestDomain,
                                              final String principalDomain) {
        return error(ResourceException.FORBIDDEN, msg, caller, requestDomain, principalDomain);
    }

    protected RuntimeException notFoundError(final String msg, final String caller, final String requestDomain,
                                             final String principalDomain) {
        return error(ResourceException.NOT_FOUND, msg, caller, requestDomain, principalDomain);
    }

    protected RuntimeException serverError(final String msg, final String caller, final String requestDomain,
                                           final String principalDomain) {
        return error(ResourceException.INTERNAL_SERVER_ERROR, msg, caller, requestDomain, principalDomain);
    }

    public ResourceContext newResourceContext(HttpServletRequest request,
                                              HttpServletResponse response,
                                              String apiName) {
        Object timerMetric = metric.startTiming("zts_api_latency", null, null, request.getMethod(), apiName.toLowerCase());
        // check to see if we want to allow this URI to be available
        // with optional authentication support

        boolean optionalAuth = StringUtils.requestUriMatch(request.getRequestURI(),
                authFreeUriSet, authFreeUriList);
        return new RsrcCtxWrapper(request, response, authorities, optionalAuth, authorizer, metric, timerMetric, apiName);
    }

    String getExceptionMsg(String prefix, ResourceContext ctx, Exception ex, String hostname) {
        return prefix + ex.getMessage() +
                " client: " + ctx.request().getHeader(USER_AGENT_HDR) +
                " clientIP: " + ctx.request().getRemoteAddr() +
                " clientHost: " + hostname;
    }

    Authority getAuthority(String className) {
        
        LOGGER.debug("Loading authority {}...", className);
        
        Authority authority;
        try {
            authority = (Authority) Class.forName(className).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOGGER.error("Invalid Authority class: " + className + " error: " + e.getMessage());
            return null;
        }
        return authority;
    }
    
    public static String getRootDir() {
        
        if (ROOT_DIR == null) {
            ROOT_DIR = System.getProperty(ZTSConsts.ZTS_PROP_ROOT_DIR, ZTSConsts.ATHENZ_ROOT_DIR);
        }

        return ROOT_DIR;
    }
    
    String normalizeDomainAliasUser(String user) {
        if (user != null && userDomainAliasPrefix != null && user.startsWith(userDomainAliasPrefix)) {
            if (user.indexOf('.', userDomainAliasPrefix.length()) == -1) {
                return userDomainPrefix + user.substring(userDomainAliasPrefix.length());
            }
        }
        return user;
    }

    boolean isPrincipalRoleCertificateAccessValid(Principal principal, String domainName, Set<String> roles) {

        // if the principal has no roles or an empty set then
        // we have nothing to check

        final List<String> princRoles = principal.getRoles();
        if (princRoles == null || princRoles.isEmpty()) {
            return true;
        }

        // verify that every role we're returning in the response
        // matches to a role from the principal object. the role
        // list from the principal object (typically from a role
        // certificate) expected to have full role resource names.

        for (String role : roles) {
            final String roleName = domainName + AuthorityConsts.ROLE_SEP + role;
            if (!princRoles.contains(roleName)) {
                LOGGER.error("Principal Role list does not include '{}'", roleName);
                return false;
            }
        }
        return true;
    }

    public void recordMetrics(ResourceContext ctx, int httpStatus) {
        final String principalDomainName = getPrincipalDomain(ctx);
        final String domainName = getRequestDomainName(ctx);
        final Object timerMetric = getTimerMetric(ctx);
        final String httpMethod = (ctx != null) ? ctx.getHttpMethod() : null;
        final String apiName = (ctx != null) ? ctx.getApiName() : null;
        final String timerName = (apiName != null) ? apiName + "_timing" : null;
        metric.increment("zts_api", domainName, principalDomainName, httpMethod, httpStatus, apiName);
        metric.stopTiming(timerMetric, domainName, principalDomainName, httpMethod, httpStatus, timerName);
    }
}
