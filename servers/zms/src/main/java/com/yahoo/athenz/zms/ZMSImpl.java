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
package com.yahoo.athenz.zms;

import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.Validator;
import com.yahoo.rdl.Validator.Result;
import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.AuthorityKeyStore;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.PrivateKeyStoreFactory;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.metrics.MetricFactory;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.log.AuditLoggerFactory;
import com.yahoo.athenz.common.server.rest.Http;
import com.yahoo.athenz.common.server.rest.Http.AuthorityList;
import com.yahoo.athenz.common.server.util.ConfigProperties;
import com.yahoo.athenz.common.server.util.ServletRequestUtil;
import com.yahoo.athenz.common.server.util.StringUtils;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zms.config.AllowedOperation;
import com.yahoo.athenz.zms.config.AuthorizedService;
import com.yahoo.athenz.zms.config.AuthorizedServices;
import com.yahoo.athenz.zms.config.SolutionTemplates;
import com.yahoo.athenz.zms.store.AthenzDomain;
import com.yahoo.athenz.zms.store.ObjectStore;
import com.yahoo.athenz.zms.store.ObjectStoreFactory;
import com.yahoo.athenz.common.server.audit.AuditReferenceValidator;
import com.yahoo.athenz.common.server.audit.AuditReferenceValidatorFactory;
import com.yahoo.athenz.zms.utils.ZMSUtils;

import java.io.File;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.ListIterator;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.TimeZone;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.ws.rs.core.EntityTag;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ZMSImpl implements Authorizer, KeyStore, ZMSHandler {

    private static final Logger LOG = LoggerFactory.getLogger(ZMSImpl.class);

    private static String ROOT_DIR;
    
    private static final String ROLE_PREFIX = "role.";
    private static final String POLICY_PREFIX = "policy.";
    
    private static final String ADMIN_POLICY_NAME = "admin";
    private static final String ADMIN_ROLE_NAME = "admin";
    
    private static final String ROLE_FIELD = "role";
    private static final String POLICY_FIELD = "policy";
    private static final String SERVICE_FIELD = "service";
    private static final String TEMPLATE_FIELD = "template";
    private static final String META_FIELD = "meta";
    private static final String DOMAIN_FIELD = "domain";

    private static final String META_ATTR_ACCOUNT = "account";
    private static final String META_ATTR_YPM_ID = "ypmid";
    private static final String META_ATTR_ALL = "all";

    private static final String SYS_AUTH = "sys.auth";
    private static final String USER_TOKEN_DEFAULT_NAME = "_self_";
    
    // data validation types
    private static final String TYPE_DOMAIN_NAME = "DomainName";
    private static final String TYPE_ENTITY_NAME = "EntityName";
    private static final String TYPE_SIMPLE_NAME = "SimpleName";
    private static final String TYPE_MEMBER_NAME = "MemberName";
    private static final String TYPE_COMPOUND_NAME = "CompoundName";
    private static final String TYPE_RESOURCE_NAME = "ResourceName";
    private static final String TYPE_SERVICE_NAME = "ServiceName";
    private static final String TYPE_ROLE = "Role";
    private static final String TYPE_POLICY = "Policy";
    private static final String TYPE_ASSERTION = "Assertion";
    private static final String TYPE_SERVICE_IDENTITY = "ServiceIdentity";
    private static final String TYPE_TOP_LEVEL_DOMAIN = "TopLevelDomain";
    private static final String TYPE_SUB_DOMAIN = "SubDomain";
    private static final String TYPE_USER_DOMAIN = "UserDomain";
    private static final String TYPE_DOMAIN_META = "DomainMeta";
    private static final String TYPE_DOMAIN_TEMPLATE = "DomainTemplate";
    private static final String TYPE_TENANT_RESOURCE_GROUP_ROLES = "TenantResourceGroupRoles";
    private static final String TYPE_PROVIDER_RESOURCE_GROUP_ROLES = "ProviderResourceGroupRoles";
    private static final String TYPE_PUBLIC_KEY_ENTRY = "PublicKeyEntry";
    private static final String TYPE_MEMBERSHIP = "Membership";
    private static final String TYPE_QUOTA = "Quota";
    
    public static Metric metric;
    public static String serverHostName  = null;

    protected DBService dbService = null;
    protected Schema schema = null;
    protected PrivateKey privateKey = null;
    protected String privateKeyId = "0";
    protected int userTokenTimeout = 3600;
    protected boolean virtualDomainSupport = true;
    protected boolean productIdSupport = false;
    protected int virtualDomainLimit = 2;
    protected long signedPolicyTimeout;
    protected int domainNameMaxLen;
    protected AuthorizedServices serverAuthorizedServices = null;
    protected static SolutionTemplates serverSolutionTemplates = null;
    protected Map<String, String> serverPublicKeyMap = null;
    protected boolean readOnlyMode = false;
    protected static Validator validator;
    protected String userDomain;
    protected String userDomainPrefix;
    protected String homeDomain;
    protected String homeDomainPrefix;
    protected String userDomainAlias;
    protected String userDomainAliasPrefix;
    protected Http.AuthorityList authorities = null;
    protected List<String> providerEndpoints = null;
    protected Set<String> reservedServiceNames = null;
    protected PrivateKeyStore keyStore = null;
    protected boolean secureRequestsOnly = true;
    protected AuditLogger auditLogger = null;
    protected Authority userAuthority = null;
    protected Authority principalAuthority = null;
    protected Set<String> authFreeUriSet = null;
    protected List<Pattern> authFreeUriList = null;
    protected Set<String> corsOriginList = null;
    protected int httpPort;
    protected int httpsPort;
    protected int statusPort;
    protected int serviceNameMinLength;
    protected Status successServerStatus = null;
    protected Set<String> reservedSystemDomains = null;
    protected File healthCheckFile = null;
    protected AuditReferenceValidator auditReferenceValidator = null;

    // enum to represent our access response since in some cases we want to
    // handle domain not founds differently instead of just returning failure

    enum AccessStatus {
        ALLOWED,
        DENIED,
        DENIED_INVALID_ROLE_TOKEN
    }
    
    enum AthenzObject {
        ASSERTION {
            void convertToLowerCase(Object obj) {
                Assertion assertion = (Assertion) obj;
                assertion.setAction(assertion.getAction().toLowerCase());
                assertion.setResource(assertion.getResource().toLowerCase());
                assertion.setRole(assertion.getRole().toLowerCase());
            }
        },
        DEFAULT_ADMINS {
            void convertToLowerCase(Object obj) {
                DefaultAdmins defaultAdmins = (DefaultAdmins) obj;
                LIST.convertToLowerCase(defaultAdmins.getAdmins());
            }
        },
        DOMAIN_TEMPLATE {
            void convertToLowerCase(Object obj) {
                DomainTemplate template = (DomainTemplate) obj;
                if (template != null) {
                    LIST.convertToLowerCase(template.getTemplateNames());
                    List<TemplateParam> params = template.getParams();
                    if (params != null) {
                        for (TemplateParam param : params) {
                            param.setName(param.getName().toLowerCase());
                            param.setValue(param.getValue().toLowerCase());
                        }
                    }
                }
            }
        },
        DOMAIN_TEMPLATE_LIST {
            void convertToLowerCase(Object obj) {
                DomainTemplateList templates = (DomainTemplateList) obj;
                if (templates != null) {
                    LIST.convertToLowerCase(templates.getTemplateNames());
                }
            }
        },
        ENTITY {
            void convertToLowerCase(Object obj) {
                Entity entity = (Entity) obj;
                entity.setName(entity.getName().toLowerCase());
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
        MEMBERSHIP {
            void convertToLowerCase(Object obj) {
                Membership membership = (Membership) obj;
                membership.setMemberName(membership.getMemberName().toLowerCase());
                if (membership.getRoleName() != null) {
                    membership.setRoleName(membership.getRoleName().toLowerCase());
                }
            }
        },
        POLICY {
            void convertToLowerCase(Object obj) {
                Policy policy = (Policy) obj;
                policy.setName(policy.getName().toLowerCase());
                if (policy.getAssertions() != null) {
                    for (Assertion assertion : policy.getAssertions()) {
                        ASSERTION.convertToLowerCase(assertion);
                    }
                }
            }
        },
        PROVIDER_RESOURCE_GROUP_ROLES {
            void convertToLowerCase(Object obj) {
                ProviderResourceGroupRoles tenantRoles = (ProviderResourceGroupRoles) obj;
                tenantRoles.setDomain(tenantRoles.getDomain().toLowerCase());
                tenantRoles.setService(tenantRoles.getService().toLowerCase());
                tenantRoles.setTenant(tenantRoles.getTenant().toLowerCase());
                tenantRoles.setResourceGroup(tenantRoles.getResourceGroup().toLowerCase());
                if (tenantRoles.getRoles() != null) {
                    for (TenantRoleAction roleAction : tenantRoles.getRoles()) {
                        TENANT_ROLE_ACTION.convertToLowerCase(roleAction);
                    }
                }
            }
        },
        PUBLIC_KEY_ENTRY {
            void convertToLowerCase(Object obj) {
                PublicKeyEntry keyEntry = (PublicKeyEntry) obj;
                keyEntry.setId(keyEntry.getId().toLowerCase());
            }
        },
        ROLE {
            void convertToLowerCase(Object obj) {
                Role role = (Role) obj;
                role.setName(role.getName().toLowerCase());
                if (role.getTrust() != null) {
                    role.setTrust(role.getTrust().toLowerCase());
                }
                LIST.convertToLowerCase(role.getMembers());
                ROLE_MEMBER.convertToLowerCase(role.getRoleMembers());
            }
        },
        ROLE_MEMBER {
            void convertToLowerCase(Object obj) {
                @SuppressWarnings("unchecked")
                List<RoleMember> list = (List<RoleMember>) obj;
                if (list != null) {
                    ListIterator<RoleMember> iter = list.listIterator();
                    while (iter.hasNext()) {
                        RoleMember roleMember = iter.next();
                        iter.set(roleMember.setMemberName(roleMember.getMemberName().toLowerCase()));
                    }
                }
            }
        },
        SERVICE_IDENTITY {
            void convertToLowerCase(Object obj) {
                ServiceIdentity service = (ServiceIdentity) obj;
                service.setName(service.getName().toLowerCase());
                LIST.convertToLowerCase(service.getHosts());
                if (service.getPublicKeys() != null) {
                    for (PublicKeyEntry key : service.getPublicKeys()) {
                        PUBLIC_KEY_ENTRY.convertToLowerCase(key);
                    }
                }
            }
        },
        SUB_DOMAIN {
            void convertToLowerCase(Object obj) {
                SubDomain subdomain = (SubDomain) obj;
                subdomain.setName(subdomain.getName().toLowerCase());
                subdomain.setParent(subdomain.getParent().toLowerCase());
                LIST.convertToLowerCase(subdomain.getAdminUsers());
                DOMAIN_TEMPLATE_LIST.convertToLowerCase(subdomain.getTemplates());
            }
        },
        TENANCY {
            void convertToLowerCase(Object obj) {
                Tenancy tenancy = (Tenancy) obj;
                tenancy.setDomain(tenancy.getDomain().toLowerCase());
                tenancy.setService(tenancy.getService().toLowerCase());
                LIST.convertToLowerCase(tenancy.getResourceGroups());
            }
        },
        TENANT_RESOURCE_GROUP_ROLES {
            void convertToLowerCase(Object obj) {
                TenantResourceGroupRoles tenantRoles = (TenantResourceGroupRoles) obj;
                tenantRoles.setDomain(tenantRoles.getDomain().toLowerCase());
                tenantRoles.setService(tenantRoles.getService().toLowerCase());
                tenantRoles.setTenant(tenantRoles.getTenant().toLowerCase());
                tenantRoles.setResourceGroup(tenantRoles.getResourceGroup().toLowerCase());
                if (tenantRoles.getRoles() != null) {
                    for (TenantRoleAction roleAction : tenantRoles.getRoles()) {
                        TENANT_ROLE_ACTION.convertToLowerCase(roleAction);
                    }
                }
            }
        },
        TENANT_ROLE_ACTION {
            void convertToLowerCase(Object obj) {
                TenantRoleAction roleAction = (TenantRoleAction) obj;
                roleAction.setAction(roleAction.getAction().toLowerCase());
                roleAction.setRole(roleAction.getRole().toLowerCase());
            }
        },
        TOP_LEVEL_DOMAIN {
            void convertToLowerCase(Object obj) {
                TopLevelDomain domain = (TopLevelDomain) obj;
                domain.setName(domain.getName().toLowerCase());
                LIST.convertToLowerCase(domain.getAdminUsers());
                DOMAIN_TEMPLATE_LIST.convertToLowerCase(domain.getTemplates());
            }
        },
        QUOTA {
            void convertToLowerCase(Object obj) {
                Quota quota = (Quota) obj;
                quota.setName(quota.getName().toLowerCase());
            }
        },
        USER_DOMAIN {
            void convertToLowerCase(Object obj) {
                UserDomain userDomain = (UserDomain) obj;
                userDomain.setName(userDomain.getName().toLowerCase());
                DOMAIN_TEMPLATE_LIST.convertToLowerCase(userDomain.getTemplates());
            }
        };
            
        abstract void convertToLowerCase(Object obj);
    }
    
    public ZMSImpl() {
        
        // before doing anything else we need to load our
        // system properties from our config file
        
        loadSystemProperties();
        
        // let's first get our server hostname
        
        ZMSImpl.serverHostName = getServerHostName();
        
        // before we do anything we need to load our configuration
        // settings
        
        loadConfigurationSettings();
        
        // load our schema validator - we need this before we initialize
        // our store, if necessary
        
        loadSchemaValidator();
        
        // let's load our audit logger
        
        loadAuditLogger();

        // load any audit reference validator

        loadAuditRefValidator();
        
        // load any configured authorities to authenticate principals
        
        loadAuthorities();
        
        // we need a private key to sign any tokens and documents
        
        loadPrivateKeyStore();
        
        // check if we need to load any metric support for stats
        
        loadMetricObject();
        
        // our object store - either mysql or file based
        
        loadObjectStore();
        
        // initialize our store with default domains
        // this should only happen when running ZMS in local/debug mode
        // otherwise the store should have been initialized by now
        
        initObjectStore();
        
        // load the list of authorized services
        
        loadAuthorizedServices();
        
        // load the Solution templates
        
        loadSolutionTemplates();
        
        // retrieve our public keys
        
        loadServerPublicKeys();
        
        // make sure to set the keystore for any instance that requires it
        
        setAuthorityKeyStore();
    }
    
    void loadSystemProperties() {
        String propFile = System.getProperty(ZMSConsts.ZMS_PROP_FILE_NAME,
                getRootDir() + "/conf/zms_server/zms.properties");
        ConfigProperties.loadProperties(propFile);
    }
    
    void setAuthorityKeyStore() {
        for (Authority authority : authorities.getAuthorities()) {
            if (AuthorityKeyStore.class.isInstance(authority)) {
                ((AuthorityKeyStore) authority).setKeyStore(this);
            }
        }
    }
    
    void loadSchemaValidator() {
        schema = ZMSSchema.instance();
        validator = new Validator(schema);
    }
    
    void loadConfigurationSettings() {
        
        // make sure all requests run in secure mode

        secureRequestsOnly = Boolean.parseBoolean(System.getProperty(ZMSConsts.ZMS_PROP_SECURE_REQUESTS_ONLY, "true"));
        
        // retrieve the regular and status ports
        
        httpPort = ConfigProperties.getPortNumber(ZMSConsts.ZMS_PROP_HTTP_PORT,
                ZMSConsts.ZMS_HTTP_PORT_DEFAULT);
        httpsPort = ConfigProperties.getPortNumber(ZMSConsts.ZMS_PROP_HTTPS_PORT,
                ZMSConsts.ZMS_HTTPS_PORT_DEFAULT);
        statusPort = ConfigProperties.getPortNumber(ZMSConsts.ZMS_PROP_STATUS_PORT, 0);
        
        successServerStatus = new Status().setCode(ResourceException.OK).setMessage("OK");
        
        // retrieve the user domain we're supposed to use
        
        userDomain = System.getProperty(ZMSConsts.ZMS_PROP_USER_DOMAIN, ZMSConsts.USER_DOMAIN);
        userDomainPrefix = userDomain + ".";
        
        userDomainAlias = System.getProperty(ZMSConsts.ZMS_PROP_USER_DOMAIN_ALIAS);
        if (userDomainAlias != null) {
            userDomainAliasPrefix = userDomainAlias + ".";
        }
        
        homeDomain = System.getProperty(ZMSConsts.ZMS_PROP_HOME_DOMAIN, userDomain);
        homeDomainPrefix = homeDomain + ".";
        
        // default token timeout for issued tokens
        
        userTokenTimeout = Integer.parseInt(
                System.getProperty(ZMSConsts.ZMS_PROP_TIMEOUT, "3600"));
        
        // check if we need to run in maintenance read only mode
        
        readOnlyMode = Boolean.parseBoolean(
                System.getProperty(ZMSConsts.ZMS_PROP_READ_ONLY_MODE, "false"));
        
        // check to see if we need to support product ids as required
        // for top level domains
        
        productIdSupport = Boolean.parseBoolean(
                System.getProperty(ZMSConsts.ZMS_PROP_PRODUCT_ID_SUPPORT, "false"));
        
        // get the list of valid provider endpoints
        
        final String endPoints = System.getProperty(ZMSConsts.ZMS_PROP_PROVIDER_ENDPOINTS);
        if (endPoints != null) {
            providerEndpoints = Arrays.asList(endPoints.split(","));
        }
        
        // retrieve virtual domain support and limit. If we're given an invalid negative
        // value for limit, we'll default back to our configured value of 5
        
        virtualDomainSupport = Boolean.parseBoolean(
                System.getProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN, "true"));
        virtualDomainLimit = Integer.parseInt(
                System.getProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN_LIMIT, "5"));
        if (virtualDomainLimit < 0) {
            virtualDomainLimit = 5;
        }
        
        // signedPolicyTimeout is in milliseconds but the config setting should be in seconds
        // to be consistent with other configuration properties (Default 7 days)
        
        signedPolicyTimeout = 1000 * Long.parseLong(
                System.getProperty(ZMSConsts.ZMS_PROP_SIGNED_POLICY_TIMEOUT, "604800"));
        if (signedPolicyTimeout < 0) {
            signedPolicyTimeout = 1000 * 604800;
        }
        
        // get the maximum length allowed for a top level domain name

        domainNameMaxLen = Integer.parseInt(System.getProperty(
                ZMSConsts.ZMS_PROP_DOMAIN_NAME_MAX_SIZE, ZMSConsts.ZMS_DOMAIN_NAME_MAX_SIZE_DEFAULT));
        if (domainNameMaxLen < 10) { // 10 is arbitrary
            int domNameMaxDefault = Integer.parseInt(ZMSConsts.ZMS_DOMAIN_NAME_MAX_SIZE_DEFAULT);
            LOG.warn("init: Warning: maximum domain name length specified is too small: " +
                domainNameMaxLen + " : reverting to default: " + domNameMaxDefault);
            domainNameMaxLen = domNameMaxDefault;
        }
        LOG.info("init: using maximum domain name length: " + domainNameMaxLen);
        
        // get the list of uris that we want to allow an-authenticated access
        
        final String uriList = System.getProperty(ZMSConsts.ZMS_PROP_NOAUTH_URI_LIST);
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

        // get the list of white listed origin values for cors requests

        final String originList = System.getProperty(ZMSConsts.ZMS_PROP_CORS_ORIGIN_LIST);
        if (originList != null) {
            corsOriginList = new HashSet<>(Arrays.asList(originList.split(",")));
        }

        // get the list of valid provider endpoints

        final String serviceNames = System.getProperty(ZMSConsts.ZMS_PROP_RESERVED_SERVICE_NAMES,
                ZMSConsts.ZMS_RESERVED_SERVICE_NAMES_DEFAULT);
        reservedServiceNames = new HashSet<>(Arrays.asList(serviceNames.split(",")));

        // min length for service names

        serviceNameMinLength = Integer.parseInt(
                System.getProperty(ZMSConsts.ZMS_PROP_SERVICE_NAME_MIN_LENGTH, "3"));

        // setup our reserved system domain names

        reservedSystemDomains = new HashSet<>();
        reservedSystemDomains.add("sys");
        reservedSystemDomains.add("sys.auth");
        reservedSystemDomains.add(userDomain);
        reservedSystemDomains.add(homeDomain);

        // setup our health check file

        final String healthCheckPath = System.getProperty(ZMSConsts.ZMS_PROP_HEALTH_CHECK_PATH);
        if (healthCheckPath != null && !healthCheckPath.isEmpty()) {
            healthCheckFile = new File(healthCheckPath);
        }
    }
    
    void loadObjectStore() {
        
        String objFactoryClass = System.getProperty(ZMSConsts.ZMS_PROP_OBJECT_STORE_FACTORY_CLASS,
                ZMSConsts.ZMS_OBJECT_STORE_FACTORY_CLASS);
        ObjectStoreFactory objFactory;
        try {
            objFactory = (ObjectStoreFactory) Class.forName(objFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOG.error("Invalid ObjectStoreFactory class: " + objFactoryClass
                    + " error: " + e.getMessage());
            throw new IllegalArgumentException("Invalid object store");
        }
        
        ObjectStore store = objFactory.create(keyStore);
        dbService = new DBService(store, auditLogger, userDomain, auditReferenceValidator);
    }
    
    void loadMetricObject() {
        
        String metricFactoryClass = System.getProperty(ZMSConsts.ZMS_PROP_METRIC_FACTORY_CLASS,
                ZMSConsts.ZMS_METRIC_FACTORY_CLASS);
        MetricFactory metricFactory;
        try {
            metricFactory = (MetricFactory) Class.forName(metricFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOG.error("Invalid MetricFactory class: " + metricFactoryClass
                    + " error: " + e.getMessage());
            throw new IllegalArgumentException("Invalid metric class");
        }
        
        // create our metric and increment our startup count
        
        ZMSImpl.metric = metricFactory.create();
        metric.increment("zms_sa_startup");
    }
    
    void loadPrivateKeyStore() {
        
        String pkeyFactoryClass = System.getProperty(ZMSConsts.ZMS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                ZMSConsts.ZMS_PRIVATE_KEY_STORE_FACTORY_CLASS);
        PrivateKeyStoreFactory pkeyFactory;
        try {
            pkeyFactory = (PrivateKeyStoreFactory) Class.forName(pkeyFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOG.error("Invalid PrivateKeyStoreFactory class: " + pkeyFactoryClass
                    + " error: " + e.getMessage());
            throw new IllegalArgumentException("Invalid private key store");
        }
        
        // extract the private key and public keys for our service
        
        StringBuilder privKeyId = new StringBuilder(256);
        keyStore = pkeyFactory.create();
        
        // now that we have our keystore let's load our private key
        
        privateKey = keyStore.getPrivateKey(ZMSConsts.ZMS_SERVICE, serverHostName, privKeyId);
        privateKeyId = privKeyId.toString();
    }
    
    void loadAuthorities() {
        
        // get our authorities
        
        final String authListConfig = System.getProperty(ZMSConsts.ZMS_PROP_AUTHORITY_CLASSES,
                ZMSConsts.ZMS_PRINCIPAL_AUTHORITY_CLASS);
        final String principalAuthorityClass = System.getProperty(ZMSConsts.ZMS_PROP_PRINCIPAL_AUTHORITY_CLASS);
        final String userAuthorityClass = System.getProperty(ZMSConsts.ZMS_PROP_USER_AUTHORITY_CLASS);
        
        authorities = new AuthorityList();

        String[] authorityList = authListConfig.split(",");
        for (String authorityClass : authorityList) {
            Authority authority = getAuthority(authorityClass);
            if (authority == null) {
                throw new IllegalArgumentException("Invalid authority");
            }
            if (authorityClass.equals(principalAuthorityClass)) {
                principalAuthority = authority;
            } else if (authorityClass.equals(userAuthorityClass)) {
                userAuthority = authority;
            }
            authority.initialize();
            authorities.add(authority);
        }
    }
    
    void loadAuditLogger() {
        
        String auditFactoryClass = System.getProperty(ZMSConsts.ZMS_PROP_AUDIT_LOGGER_FACTORY_CLASS,
                ZMSConsts.ZMS_AUDIT_LOGGER_FACTORY_CLASS);
        AuditLoggerFactory auditLogFactory;
        
        try {
            auditLogFactory = (AuditLoggerFactory) Class.forName(auditFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOG.error("Invalid AuditLoggerFactory class: " + auditFactoryClass
                    + " error: " + e.getMessage());
            throw new IllegalArgumentException("Invalid audit logger class");
        }
        
        // create our audit logger
        
        auditLogger = auditLogFactory.create();
    }

    void loadAuditRefValidator() {
        final String auditRefValidatorClass = System.getProperty(ZMSConsts.ZMS_PROP_AUDIT_REF_VALIDATOR_FACTORY_CLASS);
        AuditReferenceValidatorFactory auditReferenceValidatorFactory;

        if (auditRefValidatorClass != null && !auditRefValidatorClass.isEmpty()) {

            try {
                auditReferenceValidatorFactory = (AuditReferenceValidatorFactory) Class.forName(auditRefValidatorClass).newInstance();
            } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
                LOG.error("Invalid AuditReferenceValidatorFactory class: " + auditRefValidatorClass
                        + " error: " + e.getMessage());
                throw new IllegalArgumentException("Invalid audit reference factory class");
            }

            // create our audit reference validator

            auditReferenceValidator = auditReferenceValidatorFactory.create();
        }
    }
    
    void loadServerPublicKeys() {
        
        // initialize our public key map
        
        serverPublicKeyMap = new ConcurrentHashMap<>();
        
        // retrieve our zms service identity object
        
        ServiceIdentity identity = dbService.getServiceIdentity(SYS_AUTH, ZMSConsts.ZMS_SERVICE);
        if (identity != null) {
            
            // process all the public keys and add them to the map
            
            List<PublicKeyEntry> publicKeyList = identity.getPublicKeys();
            if (publicKeyList != null) {
                for (PublicKeyEntry entry : publicKeyList) {
                    serverPublicKeyMap.put(entry.getId(), entry.getKey());
                }
            }
        }
        
        // this should never happen but just in case we'll just
        // use the public key we retrieved ourselves to the map
        
        if (serverPublicKeyMap.isEmpty() && privateKey != null) {
            final String publicKey = Crypto.convertToPEMFormat(Crypto.extractPublicKey(privateKey));
            serverPublicKeyMap.put(privateKeyId, Crypto.ybase64EncodeString(publicKey));
        }
    }
    
    void loadSolutionTemplates() {
        
        // get the configured path for the list of service templates
        
        String solutionTemplatesFname =  System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME,
                getRootDir() + "/conf/zms_server/solution_templates.json");
        
        Path path = Paths.get(solutionTemplatesFname);
        try {
            serverSolutionTemplates = JSON.fromBytes(Files.readAllBytes(path), SolutionTemplates.class);
        } catch (IOException ex) {
            LOG.error("Unable to parse service templates file {}: {}",
                    solutionTemplatesFname, ex.getMessage());
        }
        
        if (serverSolutionTemplates == null) {
            LOG.error("Generating empty solution template list...");
            serverSolutionTemplates = new SolutionTemplates();
            serverSolutionTemplates.setTemplates(new HashMap<>());
        }
    }
    
    void loadAuthorizedServices() {
        
        // get the configured path for the list of authorized services and what operations
        // those services are allowed to process
        
        String authzServiceFname =  System.getProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME,
                getRootDir() + "/conf/zms_server/authorized_services.json");
        
        Path path = Paths.get(authzServiceFname);
        try {
            serverAuthorizedServices = JSON.fromBytes(Files.readAllBytes(path), AuthorizedServices.class);
        } catch (IOException ex) {
            LOG.error("Unable to parse authorized service file {}: {}",
                    authzServiceFname, ex.getMessage());
        }
        
        if (serverAuthorizedServices == null) {
            LOG.error("Generating empty authorized service list...");
            serverAuthorizedServices = new AuthorizedServices();
            serverAuthorizedServices.setTemplates(new HashMap<>());
        }
    }
    
    void initObjectStore() {
        
        final String caller = "initstore";

        List<String> domains = dbService.listDomains(null, 0);
        if (domains.size() > 0 && domains.contains(SYS_AUTH)) {
            return;
        }
        
        String adminUserList = System.getProperty(ZMSConsts.ZMS_PROP_DOMAIN_ADMIN);
        if (adminUserList == null) {
            throw ZMSUtils.internalServerError("init: No ZMS admin user specified", caller);
        }
        
        String[] users = adminUserList.split(",");
        ArrayList<String> adminUsers = new ArrayList<>();
        for (String user : users) {
            final String adminUser = user.trim();
            if (!adminUser.startsWith(userDomainPrefix)) {
                throw ZMSUtils.internalServerError("init: Bad domain user name(" + adminUser +
                        "), must begin with (" + userDomainPrefix + ")", caller);
            }
            adminUsers.add(adminUser);
        }
        
        createTopLevelDomain(null, userDomain, "The reserved domain for user authentication",
                null, null, adminUsers, null, 0, null, null, null);
        if (!ZMSConsts.USER_DOMAIN.equals(userDomain)) {
            createTopLevelDomain(null, ZMSConsts.USER_DOMAIN, "The reserved domain for user authentication",
                    null, null, adminUsers, null, 0, null, null, null);
        }
        if (!homeDomain.equals(userDomain)) {
            createTopLevelDomain(null, homeDomain, "The reserved domain for personal user domains",
                    null, null, adminUsers, null, 0, null, null, null);
        }
        createTopLevelDomain(null, "sys", "The reserved domain for system related information",
                null, null, adminUsers, null, 0, null, null, null);
        createSubDomain(null, "sys", "auth", "The Athenz domain", null, null, adminUsers,
                null, 0, null, null, null, caller);

        if (privateKey != null) {
            List<PublicKeyEntry> pubKeys = new ArrayList<>();
            final String publicKey = Crypto.convertToPEMFormat(Crypto.extractPublicKey(privateKey));
            pubKeys.add(new PublicKeyEntry().setId(privateKeyId).setKey(Crypto.ybase64EncodeString(publicKey)));
            ServiceIdentity id = new ServiceIdentity().setName("sys.auth.zms").setPublicKeys(pubKeys);
            dbService.executePutServiceIdentity(null, SYS_AUTH, ZMSConsts.ZMS_SERVICE, id, null, caller);
        } else {
            if (LOG.isWarnEnabled()) {
                LOG.warn("init: Warning: no public key, cannot register sys.auth.zms identity");
            }
        }
    }

    /**
     * @return the ZMS Schema object, describing its API and types.
     */
    public Schema schema() {
        return schema;
    }

    public DomainList getDomainList(ResourceContext ctx, Integer limit, String skip, String prefix,
            Integer depth, String account, Integer productId, String roleMember, String roleName,
            String modifiedSince) {

        final String caller = "getdomainlist";
        metric.increment(ZMSConsts.HTTP_GET);
        metric.increment(ZMSConsts.HTTP_REQUEST);
        metric.increment(caller);
        Object timerMetric = metric.startTiming("getdomainlist_timing", null);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);

        if (LOG.isDebugEnabled()) {
            LOG.debug("getDomainList: limit: " + limit + " skip: " + skip
                    + " prefix: " + prefix + " depth: " + depth + " modifiedSince: " + modifiedSince);
        }
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        if (skip != null) {
            skip = skip.toLowerCase();
        }
        if (prefix != null) {
            prefix = prefix.toLowerCase();
        }
        if (roleMember != null) {
            roleMember = roleMember.toLowerCase();
            validate(roleMember, TYPE_ENTITY_NAME, caller);
        }
        if (roleName != null) {
            roleName = roleName.toLowerCase();
            validate(roleName, TYPE_ENTITY_NAME, caller);
        }
        if (limit != null && limit <= 0) {
            throw ZMSUtils.requestError("getDomainList: limit must be positive: " + limit, caller);
        }
        
        long modTime = 0;
        if (modifiedSince != null && !modifiedSince.isEmpty()) {
            // we only support RFC1123 format for if-modified-since format
            
            SimpleDateFormat dateFmt = new SimpleDateFormat(ZMSConsts.HTTP_RFC1123_DATE_FORMAT);
            dateFmt.setTimeZone(TimeZone.getTimeZone(ZMSConsts.HTTP_DATE_GMT_ZONE));
            try {
                Date date = dateFmt.parse(modifiedSince);
                modTime = date.getTime();
            } catch (ParseException ex) {
                throw ZMSUtils.requestError("getDomainList: If-Modified-Since header value must be valid RFC1123 date"
                        + ex.getMessage(), caller);
            }
        }
        
        // if we have account specified then we're going to ignore all
        // other fields since there should only be one domain that
        // matches the specified account. Otherwise, we're going to do
        // the same thing for product id since there should also be one
        // domain with that id. If neither one is present, then we'll
        // do our regular domain list
        
        DomainList dlist;
        if (account != null && !account.isEmpty()) {
            dlist = dbService.lookupDomainByAccount(account);
        } else if (productId != null && productId != 0) {
            dlist = dbService.lookupDomainByProductId(productId);
        } else if (roleMember != null || roleName != null) {
            dlist = dbService.lookupDomainByRole(normalizeDomainAliasUser(roleMember), roleName);
        } else {
            dlist = listDomains(limit, skip, prefix, depth, modTime);
        }
        
        metric.stopTiming(timerMetric);
        return dlist;
    }

    public Domain getDomain(ResourceContext ctx, String domainName) {
        
        final String caller = "getdomain";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);

        Object timerMetric = metric.startTiming("getdomain_timing", domainName);
        
        Domain domain = dbService.getDomain(domainName, false);
        if (domain == null) {
            throw ZMSUtils.notFoundError("getDomain: Domain not found: " + domainName, caller);
        }

        metric.stopTiming(timerMetric);
        return domain;
    }

    public Domain postTopLevelDomain(ResourceContext ctx, String auditRef, TopLevelDomain detail) {
        
        final String caller = "posttopleveldomain";
        metric.increment(ZMSConsts.HTTP_POST);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }
        
        validateRequest(ctx.request(), caller);

        validate(detail, TYPE_TOP_LEVEL_DOMAIN, caller);
        
        String domainName = detail.getName();
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        domainName = domainName.toLowerCase();
        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("posttopleveldomain_timing", domainName);
        
        if (domainName.indexOf('_') != -1 && !isSysAdminUser(((RsrcCtxWrapper) ctx).principal())) {
            throw ZMSUtils.requestError("Domain name cannot contain underscores", caller);
        }
        
        // verify length of domain name
        
        if (domainName.length() > domainNameMaxLen) {
            throw ZMSUtils.requestError("Invalid Domain name: " + domainName
                    + " : name length cannot exceed: " + domainNameMaxLen, caller);
        }

        // verify that request is properly authenticated for this request
        
        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        verifyAuthorizedServiceOperation(principal.getAuthorizedService(), caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        AthenzObject.TOP_LEVEL_DOMAIN.convertToLowerCase(detail);
        
        List<String> solutionTemplates = null;
        DomainTemplateList templates = detail.getTemplates();
        if (templates != null) {
            solutionTemplates = templates.getTemplateNames();
            validateSolutionTemplates(solutionTemplates, caller);
        }
        
        // check to see if we need to validate our product id for the top
        // level domains. The server code assumes that product id with
        // 0 indicates no enforcement
        
        int productId = 0;
        if (productIdSupport) {
            if (detail.getYpmId() != null) {
                if ((productId = detail.getYpmId()) <= 0) {
                    throw ZMSUtils.requestError("Product Id must be a positive integer", caller);
                }
            } else {
                throw ZMSUtils.requestError("Product Id is required when creating top level domain", caller);
            }
        }
        
        List<String> adminUsers = normalizedAdminUsers(detail.getAdminUsers());
        Domain domain = createTopLevelDomain(ctx, domainName, detail.getDescription(),
            detail.getOrg(), detail.getAuditEnabled(), adminUsers,
            detail.getAccount(), productId, detail.getApplicationId(), solutionTemplates, auditRef);

        metric.stopTiming(timerMetric);
        return domain;
    }
    
    public void deleteTopLevelDomain(ResourceContext ctx, String domainName, String auditRef) {
        
        final String caller = "deletetopleveldomain";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);

        domainName = domainName.toLowerCase();
        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("deletetopleveldomain_timing", domainName);
        
        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        deleteDomain(ctx, auditRef, domainName, caller);
        metric.stopTiming(timerMetric);
    }

    Domain deleteDomain(ResourceContext ctx, String auditRef, String domainName, String caller) {

        // make sure we're not deleting any of the reserved system domain

        if (reservedSystemDomains.contains(domainName)) {
            throw ZMSUtils.requestError("Cannot delete reserved system domain", caller);
        }

        DomainList subDomainList = listDomains(null, null, domainName + ".", null, 0);
        if (subDomainList.getNames().size() > 0) {
            throw ZMSUtils.requestError(caller + ": Cannot delete domain " +
                    domainName + ": " + subDomainList.getNames().size() + " subdomains of it exist", caller);
        }

        return dbService.executeDeleteDomain(ctx, domainName, auditRef, caller);
    }
    
    boolean isVirtualDomain(String domain) {

        // all virtual domains start with our user domain
        
        return domain.startsWith(homeDomainPrefix);
    }
    
    boolean hasExceededVirtualSubDomainLimit(String domain) {
        
        // we need to find our username which is our second
        // component in the domain name - e.g. user.joe[.subdomain]
        // when counting we need to make to include the trailing .
        // since we're counting subdomains and we need to make sure
        // not to match other users who have the same prefix
        
        String userDomainCheck;
        int idx = domain.indexOf('.', homeDomainPrefix.length());
        if (idx == -1) {
            userDomainCheck = domain + ".";
        } else {
            userDomainCheck = domain.substring(0, idx + 1);
        }
        
        // retrieve the number of domains with this prefix
        
        DomainList dlist = listDomains(null, null, userDomainCheck, null, 0);
        if (dlist.getNames().size() < virtualDomainLimit) {
            return false;
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("hasExceededVirtualSubDomainLimit: subdomains with prefix " + userDomainCheck
                    + ": " + dlist.getNames().size() + " while limit is: " + virtualDomainLimit);
        }
        
        return true;
    }
    
    public Domain postUserDomain(ResourceContext ctx, String name, String auditRef, UserDomain detail) {

        final String caller = "postuserdomain";
        metric.increment(ZMSConsts.HTTP_POST);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);
        validate(detail, TYPE_USER_DOMAIN, caller);
        validate(name, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        name = name.toLowerCase();
        AthenzObject.USER_DOMAIN.convertToLowerCase(detail);

        metric.increment(ZMSConsts.HTTP_REQUEST, name);
        metric.increment(caller, name);
        Object timerMetric = metric.startTiming("postuserdomain_timing", name);
        
        if (detail.getName().indexOf('_') != -1 && !isSysAdminUser(((RsrcCtxWrapper) ctx).principal())) {
            throw ZMSUtils.requestError("Domain name cannot contain underscores", caller);
        }
        
        // verify that request is properly authenticated for this request
        
        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        verifyAuthorizedServiceOperation(principal.getAuthorizedService(), caller);
        
        if (!name.equals(detail.getName())) {
            throw ZMSUtils.forbiddenError("postUserDomain: Request and detail domain names do not match", caller);
        }

        // we're dealing with user's top level domain so the parent is going
        // to be the home domain and the admin of the domain is the user

        List<String> adminUsers = new ArrayList<>();
        adminUsers.add(userDomainPrefix + principal.getName());
        
        List<String> solutionTemplates = null;
        DomainTemplateList templates = detail.getTemplates();
        if (templates != null) {
            solutionTemplates = templates.getTemplateNames();
            validateSolutionTemplates(solutionTemplates, caller);
        }
        
        Domain domain = createSubDomain(ctx, homeDomain, getUserDomainName(detail.getName()),
                detail.getDescription(), detail.getOrg(), detail.getAuditEnabled(), adminUsers,
                detail.getAccount(), 0, detail.getApplicationId(), solutionTemplates, auditRef, caller);

        metric.stopTiming(timerMetric);
        return domain;
    }
    
    public Domain postSubDomain(ResourceContext ctx, String parent, String auditRef, SubDomain detail) {

        final String caller = "postsubdomain";
        metric.increment(ZMSConsts.HTTP_POST);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }
        
        validateRequest(ctx.request(), caller);
        validate(detail, TYPE_SUB_DOMAIN, caller);
        validate(parent, TYPE_DOMAIN_NAME, caller);
        validate(detail.getName(), TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        parent = parent.toLowerCase();
        AthenzObject.SUB_DOMAIN.convertToLowerCase(detail);

        metric.increment(ZMSConsts.HTTP_REQUEST, parent);
        metric.increment(caller, parent);
        Object timerMetric = metric.startTiming("postsubdomain_timing", parent);
        
        if (detail.getName().indexOf('_') != -1 && !isSysAdminUser(((RsrcCtxWrapper) ctx).principal())) {
            throw ZMSUtils.requestError("Domain name cannot contain underscores", caller);
        }
        
        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        if (!parent.equals(detail.getParent())) {
            throw ZMSUtils.forbiddenError("postSubDomain: Request and detail parent domains do not match", caller);
        }

        // if we're dealing with virtual/home domains (in the user's own namespace)
        // and we don't have unlimited support for virtual domains then we need to
        // make sure we don't exceed our configured number of virtual subdomains 
        // allowed per user

        if (virtualDomainLimit != 0 && isVirtualDomain(parent) && hasExceededVirtualSubDomainLimit(parent)) {
            throw ZMSUtils.forbiddenError("postSubDomain: Exceeding the configured number of virtual subdomains", caller);
        }

        List<String> solutionTemplates = null;
        DomainTemplateList templates = detail.getTemplates();
        if (templates != null) {
            solutionTemplates = templates.getTemplateNames();
            validateSolutionTemplates(solutionTemplates, caller);
        }
        
        // while it's not required for sub domains to have product ids
        // we're going to store it in case there is a requirement to
        // generate reports based on product ids even for subdomains
        // unlike top level domains, passing 0 is ok here as it indicates
        // that there is no product id
        
        int productId = 0;
        if (productIdSupport) {
            if (detail.getYpmId() != null) {
                if ((productId = detail.getYpmId()) < 0) {
                    throw ZMSUtils.requestError("Product Id must be a positive integer", caller);
                }
            }
        }
        
        List<String> adminUsers = normalizedAdminUsers(detail.getAdminUsers());
        Domain domain = createSubDomain(ctx, detail.getParent(), detail.getName(), detail.getDescription(),
                detail.getOrg(), detail.getAuditEnabled(), adminUsers, detail.getAccount(),
                productId, detail.getApplicationId(), solutionTemplates, auditRef, caller);

        metric.stopTiming(timerMetric);
        return domain;
    }

    boolean isSysAdminUser(Principal principal) {
        
        // verify we're dealing with system administrator
        // authorize ("CREATE", "sys.auth:domain");

        // first check - the domain must be the user domain
        
        if (!principal.getDomain().equals(userDomain)) {
            return false;
        }
        
        AthenzDomain domain = getAthenzDomain(SYS_AUTH, true);
        
        // evaluate our domain's roles and policies to see if access
        // is allowed or not for the given operation and resource
        // our action are always converted to lowercase
        
        String resource = SYS_AUTH + ":domain";
        AccessStatus accessStatus = evaluateAccess(domain, principal.getFullName(), "create",
                resource, null, null);

        return accessStatus == AccessStatus.ALLOWED;
    }

    boolean isAllowedResourceLookForAllUsers(Principal principal) {
        
        // the authorization policy resides in official sys.auth domain

        AthenzDomain domain = getAthenzDomain(SYS_AUTH, true);
        
        // evaluate our domain's roles and policies to see if access
        // is allowed or not for the given operation and resource
        // our action are always converted to lowercase

        String resource = SYS_AUTH + ":resource-lookup-all";
        AccessStatus accessStatus = evaluateAccess(domain, principal.getFullName(), "access",
                resource, null, null);

        return accessStatus == AccessStatus.ALLOWED;
    }

    boolean isAllowedSystemMetaDelete(Principal principal, final String reqDomain,
            final String attribute) {

        // the authorization policy resides in official sys.auth domain

        AthenzDomain domain = getAthenzDomain(SYS_AUTH, true);

        // evaluate our domain's roles and policies to see if access
        // is allowed or not for the given operation and resource
        // our action are always converted to lowercase

        String resource = SYS_AUTH + ":meta." + attribute + "." + reqDomain;
        AccessStatus accessStatus = evaluateAccess(domain, principal.getFullName(), "delete",
                resource, null, null);

        return accessStatus == AccessStatus.ALLOWED;
    }

    public void deleteSubDomain(ResourceContext ctx, String parent, String name, String auditRef) {

        final String caller = "deletesubdomain";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        parent = parent.toLowerCase();
        name = name.toLowerCase();
        String domainName = parent + "." + name;

        metric.increment(ZMSConsts.HTTP_REQUEST, parent);
        metric.increment(caller, parent);
        Object timerMetric = metric.startTiming("deletesubdomain_timing", parent);

        validate(parent, TYPE_DOMAIN_NAME, caller);
        validate(name, TYPE_SIMPLE_NAME, caller);

        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        deleteDomain(ctx, auditRef, domainName, caller);
        metric.stopTiming(timerMetric);
    }

    public void deleteUserDomain(ResourceContext ctx, String name, String auditRef) {

        final String caller = "deleteuserdomain";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(name, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        name = name.toLowerCase();
        metric.increment(ZMSConsts.HTTP_REQUEST, name);
        metric.increment(caller, name);
        Object timerMetric = metric.startTiming("deleteuserdomain_timing", name);
        
        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        String domainName = homeDomainPrefix + name;
        deleteDomain(ctx, auditRef, domainName, caller);
        metric.stopTiming(timerMetric);
    }
    
    public UserList getUserList(ResourceContext ctx) {
        
        final String caller = "getuserlist";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);

        metric.increment(ZMSConsts.HTTP_REQUEST);
        metric.increment(caller);
        Object timerMetric = metric.startTiming("getuserlist_timing", null);
        
        List<String> names = dbService.listPrincipals(userDomain, true);
        UserList result = new UserList().setNames(names);

        metric.stopTiming(timerMetric);
        return result;
    }

    @Override
    public void deleteDomainRoleMember(ResourceContext ctx, String domainName, String memberName, String auditRef) {

        final String caller = "deletedomainrolemember";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(memberName, TYPE_MEMBER_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        memberName = memberName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("deletedomainrolemember_timing", domainName);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        dbService.executeDeleteDomainRoleMember(ctx, domainName, memberName, auditRef, caller);
        metric.stopTiming(timerMetric);
    }

    @Override
    public void deleteUser(ResourceContext ctx, String name, String auditRef) {
        
        final String caller = "deleteuser";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(name, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        name = name.toLowerCase();
        metric.increment(ZMSConsts.HTTP_REQUEST, userDomain);
        metric.increment(caller, userDomain);
        Object timerMetric = metric.startTiming("deleteuser_timing", name);
        
        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        String userName = userDomainPrefix + name;
        String domainName = homeDomainPrefix + getUserDomainName(name);
        dbService.executeDeleteUser(ctx, userName, domainName, auditRef, caller);
        metric.stopTiming(timerMetric);
    }
    
    String getUserDomainName(String userName) {
        return (userAuthority == null) ? userName : userAuthority.getUserDomainName(userName);
    }
    
    void validateString(final String value, final String type, final String caller) {
        if (value != null && !value.isEmpty()) {
            validate(value, type, caller);
        }
    }

    @Override
    public void putDomainMeta(ResourceContext ctx, String domainName, String auditRef,
            DomainMeta meta) {

        final String caller = "putdomainmeta";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(meta, TYPE_DOMAIN_META, caller);
        validateString(meta.getApplicationId(), TYPE_COMPOUND_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("putdomainmeta_timing", domainName);
        
        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(),
                caller);

        if (LOG.isDebugEnabled()) {
            LOG.debug("putDomainMeta: name={}, meta={}", domainName, meta);
        }

        // process put domain meta request

        dbService.executePutDomainMeta(ctx, domainName, meta, null, false, auditRef, caller);
        metric.stopTiming(timerMetric);
    }

    @Override
    public void putDomainSystemMeta(ResourceContext ctx, String domainName, String attribute,
            String auditRef, DomainMeta meta) {

        final String caller = "putdomainsystemmeta";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(meta, TYPE_DOMAIN_META, caller);
        validate(attribute, TYPE_SIMPLE_NAME, caller);
        validateString(meta.getAccount(), TYPE_COMPOUND_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        attribute = attribute.toLowerCase();
        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("putdomainsystemmeta_timing", domainName);

        // verify that request is properly authenticated for this request

        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        verifyAuthorizedServiceOperation(principal.getAuthorizedService(), caller);

        if (LOG.isDebugEnabled()) {
            LOG.debug("putDomainSystemMeta: name={}, attribute={}, meta={}",
                    domainName, attribute, meta);
        }

        // if we are resetting the configured value then the caller
        // must also have a delete action available for the same resource

        boolean deleteAllowed = isAllowedSystemMetaDelete(principal, domainName, attribute);

        // if this productId is already used by any domain it will be
        // seen in dbService and exception thrown but we want to make
        // sure here if product id support is required then we must
        // have one specified for a top level domain.

        if (productIdSupport && meta.getYpmId() == null && domainName.indexOf('.') == -1 &&
                ZMSConsts.SYSTEM_META_PRODUCT_ID.equals(attribute)) {
             throw ZMSUtils.requestError("Unique Product Id must be specified for top level domain", caller);
        }

        dbService.executePutDomainMeta(ctx, domainName, meta, attribute, deleteAllowed, auditRef, caller);
        metric.stopTiming(timerMetric);
    }

    void validateSolutionTemplates(List<String> templateNames, String caller) {
        for (String templateName : templateNames) {
            if (!serverSolutionTemplates.contains(templateName)) {
                throw ZMSUtils.notFoundError("validateSolutionTemplates: Template not found: "
                        + templateName, caller);
            }
        }
    }
    
    public DomainTemplateList getDomainTemplateList(ResourceContext ctx, String domainName) {

        final String caller = "getdomaintemplatelist";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getdomaintemplatelist_timing", domainName);
        
        DomainTemplateList domainTemplateList = dbService.listDomainTemplates(domainName);
        if (domainTemplateList == null) {
            throw ZMSUtils.notFoundError("getDomainTemplateList: Domain not found: '" + domainName + "'", caller);
        }

        metric.stopTiming(timerMetric);
        return domainTemplateList;
    }

    @Override
    public void putDomainTemplate(ResourceContext ctx, String domainName, String auditRef,
            DomainTemplate domainTemplate) {

        final String caller = "putdomaintemplate";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(domainTemplate, TYPE_DOMAIN_TEMPLATE, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        AthenzObject.DOMAIN_TEMPLATE.convertToLowerCase(domainTemplate);
        
        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("putdomaintemplate_timing", domainName);
        
        // verify that all template names are valid
        
        List<String> templateNames = domainTemplate.getTemplateNames();
        if (templateNames == null || templateNames.size() == 0) {
            throw ZMSUtils.requestError("putDomainTemplate: No templates specified", caller);
        }
        validateSolutionTemplates(templateNames, caller);
        
        // verify that request is properly authenticated for this request
        // Make sure each template name is verified
        
        for (String templateName : domainTemplate.getTemplateNames()) {
            verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(),
                    caller, "name", templateName);
        }

        dbService.executePutDomainTemplate(ctx, domainName, domainTemplate, auditRef, caller);
        metric.stopTiming(timerMetric);
    }

    @Override
    public void putDomainTemplateExt(ResourceContext ctx, String domainName,
            String templateName, String auditRef, DomainTemplate domainTemplate) {

        final String caller = "putdomaintemplateext";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(templateName, TYPE_SIMPLE_NAME, caller);
        validate(domainTemplate, TYPE_DOMAIN_TEMPLATE, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        templateName = templateName.toLowerCase();
        AthenzObject.DOMAIN_TEMPLATE.convertToLowerCase(domainTemplate);
        
        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("putdomaintemplateext_timing", domainName);
        
        // verify that all template names are valid
        
        List<String> templateNames = domainTemplate.getTemplateNames();
        if (templateNames == null) {
            throw ZMSUtils.requestError("putDomainTemplateExt: No templates specified", caller);
        }
        
        // the template name in the object must match to the uri
        
        if (!(templateNames.size() == 1 && templateNames.get(0).equals(templateName))) {
            throw ZMSUtils.requestError("putDomainTemplateExt: template name mismatch", caller);
        }
        validateSolutionTemplates(templateNames, caller);
        
        // verify that request is properly authenticated for this request
        // Make sure each template name is verified
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(),
                caller, "name", templateName);

        dbService.executePutDomainTemplate(ctx, domainName, domainTemplate, auditRef, caller);
        metric.stopTiming(timerMetric);
    }
    
    public void deleteDomainTemplate(ResourceContext ctx, String domainName, String templateName, String auditRef) {

        final String caller = "deletedomaintemplate";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }
        
        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(templateName, TYPE_SIMPLE_NAME, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        templateName = templateName.toLowerCase();
        
        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("deletedomaintemplate_timing", domainName);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("deleteDomainTemplate: domain=" + domainName + ", template=" + templateName);
        }
        
        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(),
                caller, "name", templateName);

        List<String> templateNames = new ArrayList<>();
        templateNames.add(templateName);
        validateSolutionTemplates(templateNames, caller);

        dbService.executeDeleteDomainTemplate(ctx, domainName, templateName, auditRef, caller);
        metric.stopTiming(timerMetric);
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
    
    boolean validRoleTokenAccess(String trustDomain, String domainName, String principalName) {
        
        if (trustDomain != null) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("validRoleTokenAccess: Cannot access cross-domain resources with RoleToken");
            }
            return false;
        }
        
        // for Role tokens we don't have a name component in the principal
        // so the principal name should be the same as the domain value 
        // thus it must match the domain name from the resource
        
        if (!domainName.equalsIgnoreCase(principalName)) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("validRoleTokenAccess: resource domain does not match RoleToken domain");
            }
            return false;
        }
        
        return true;
    }

    AthenzDomain getAthenzDomain(String domainName, boolean ignoreExceptions) {
        return getAthenzDomain(domainName, ignoreExceptions, false);
    }
    
    AthenzDomain getAthenzDomain(String domainName, boolean ignoreExceptions, boolean masterCopy) {
        
        AthenzDomain domain = null;
        try {
            domain = dbService.getAthenzDomain(domainName, masterCopy);
        } catch (ResourceException ex) {
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("getAthenzDomain failure: " + ex.getMessage());
            }
            
            if (!ignoreExceptions) {
                if (ex.getCode() != ResourceException.NOT_FOUND) {
                    throw ex;
                }
            }
        }
        return domain;
    }
    
    AthenzDomain retrieveAccessDomain(String domainName, Principal principal) {
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("retrieveAccessDomain: identity: " + principal.getFullName()
                + " domain: " + domainName);
        }
        
        AthenzDomain domain = getAthenzDomain(domainName, false);
        if (domain != null) {
            return domain;
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("retrieveAccessDomain: domain not found, looking for virtual domain");
        }
        
        // if we don't have virtual/home domains enabled then no need
        // to continue further
        
        if (!virtualDomainSupport) {
            return null;
        }
        
        if (principal.getDomain() == null) {
            return null;
        }
        
        // the principals user name must match to the corresponding
        // home domain name for the user
        
        if (!principal.getDomain().equals(userDomain)) {
            return null;
        }
        
        final String userHomeDomain = homeDomainPrefix + getUserDomainName(principal.getName());
        if (!userHomeDomain.equals(domainName)) {
            return null;
        }
        
        return virtualHomeDomain(principal, domainName);
    }

    AccessStatus evaluateAccess(AthenzDomain domain, String identity, String action, String resource,
            List<String> authenticatedRoles, String trustDomain) {
        
        AccessStatus accessStatus = AccessStatus.DENIED;

        List<Policy> policies = domain.getPolicies();
        List<Role> roles = domain.getRoles();
        
        for (Policy policy : policies) {
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("evaluateAccess: processing policy: " + policy.getName());
            }
            
            // we are going to process all the assertions defined in this
            // policy. As soon as we get a match for an assertion that
            // denies access, we're going to return that result. If we
            // get a match for an assertion that allows access we're
            // going to remember that result and continue looking at
            // all the assertions in case there is something else that
            // explicitly denies access
            
            List<Assertion> assertions = policy.getAssertions();
            if (assertions == null) {
                continue;
            }
            
            for (Assertion assertion : assertions) {
                
                // get the effect for the assertion which is set
                // as allowed by default

                AssertionEffect effect = assertion.getEffect();
                if (effect == null) {
                    effect = AssertionEffect.ALLOW;
                }

                // if we have already matched an allow assertion then
                // we'll automatically skip any assertion that has
                // allow effect since there is no point of matching it
                
                if (accessStatus == AccessStatus.ALLOWED && effect == AssertionEffect.ALLOW) {
                    continue;
                }
                
                // if no match then process the next assertion
                
                if (!assertionMatch(assertion, identity, action, resource, domain.getName(),
                        roles, authenticatedRoles, trustDomain)) {
                    continue;
                }
                
                // if the assertion has matched and the effect is deny
                // then we're going to return right away otherwise we'll
                // set our return allow matched flag to true and continue
                // processing other assertions
                
                if (effect == AssertionEffect.DENY) {
                    return AccessStatus.DENIED;
                }
                
                accessStatus = AccessStatus.ALLOWED;
            }
        }
        
        return accessStatus;
    }
    
    String userHomeDomainResource(String resource) {
        
        // if the resource does not start with user domain prefix then
        // we have nothing to do and we'll return resource as is
        
        if (!resource.startsWith(ZMSConsts.USER_DOMAIN_PREFIX)) {
            return resource;
        }
        
        String homeResource = null;
        
        // if we have different userDomain and homeDomain values then
        // we need to replace both domain and user names otherwise
        // we only need to update the domain value
        
        if (!userDomain.equals(homeDomain)) {
            
            // let's extract the user name. at this point we should
            // have the format user.<user-name>:resource
            
            int idx = resource.indexOf(':');
            if (idx == -1) {
                return resource;
            }
            
            final String userName = resource.substring(ZMSConsts.USER_DOMAIN_PREFIX.length(), idx);
            homeResource = homeDomainPrefix + getUserDomainName(userName) + resource.substring(idx);
            
        } else if (!homeDomain.equals(ZMSConsts.USER_DOMAIN)) {
            homeResource = homeDomainPrefix + resource.substring(ZMSConsts.USER_DOMAIN_PREFIX.length());
        }
        return homeResource == null ? resource : homeResource;
    }
    
    public boolean access(String action, String resource, Principal principal, String trustDomain) {
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        resource = resource.toLowerCase();
        if (trustDomain != null) {
            trustDomain = trustDomain.toLowerCase();
        }
        action = action.toLowerCase();
        
        // if the resource starts with the user domain and the environment is using
        // a different domain name we'll dynamically update the resource value
        
        resource = userHomeDomainResource(resource);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("access:(" + action + ", " + resource + ", " + principal + ", " + trustDomain + ")");
        }
        
        // check to see if the authority is allowed to be processed in
        // authorization checks. If this value is false then the principal
        // must get a usertoken from ZMS first and the submit the request
        // with that token
        
        if (!authorityAuthorizationAllowed(principal)) {
            LOG.error("Authority is not allowed to support authorization checks");
            return false;
        }
        
        // retrieve our domain based on resource and action/trustDomain pair
        // we want to provider better error reporting to the users so if we get a
        // request where the domain is not found instead of just returning 403
        // forbidden (which is confusing since it assumes the user doesn't have
        // access as oppose to possible mistype of the domain name by the user)
        // we want to return 404 not found. The athenz server common has special handling
        // for rest.ResourceExceptions so we'll throw that exception in this
        // special case of not found domains.
        
        String domainName = retrieveResourceDomain(resource, action, trustDomain);
        if (domainName == null) {
            throw new com.yahoo.athenz.common.server.rest.ResourceException(
                    ResourceException.NOT_FOUND, "Domain not found");
        }
        AthenzDomain domain = retrieveAccessDomain(domainName, principal);
        if (domain == null) {
            throw new com.yahoo.athenz.common.server.rest.ResourceException(
                    ResourceException.NOT_FOUND, "Domain not found");
        }
        
        // if the domain is disabled then we're going to reject this
        // request right away
        
        if (domain.getDomain().getEnabled() == Boolean.FALSE) {
            throw new com.yahoo.athenz.common.server.rest.ResourceException(
                    ResourceException.FORBIDDEN, "Disabled Domain");
        }
        
        AccessStatus accessStatus = hasAccess(domain, action, resource, principal, trustDomain);
        return accessStatus == AccessStatus.ALLOWED;
    }
    
    boolean authorityAuthorizationAllowed(Principal principal) {
        
        Authority authority = principal.getAuthority();
        if (authority == null) {
            return true;
        }
        
        return authority.allowAuthorization();
    }
    
    String retrieveResourceDomain(String resource, String op, String trustDomain) {
        
        // special handling for ASSUME_ROLE assertions. Since any assertion with
        // that action refers to a resource in another domain, there is no point
        // to retrieve the domain name from the resource. In these cases the caller
        // must specify the trust domain attribute so we'll use that instead and
        // if one is not specified then we'll fall back to using the domain name
        // from the resource
        
        String domainName;
        if (ZMSConsts.ACTION_ASSUME_ROLE.equalsIgnoreCase(op) && trustDomain != null) {
            domainName = trustDomain;
        } else {
            domainName = extractDomainName(resource);
        }
        return domainName;
    }
    
    AccessStatus hasAccess(AthenzDomain domain, String action, String resource,
            Principal principal, String trustDomain) {
       
        String identity = principal.getFullName();
        
        // if we're dealing with an access check based on a Role token then
        // make sure it's valid before processing it
        
        List<String> authenticatedRoles = principal.getRoles();
        if (authenticatedRoles != null && !validRoleTokenAccess(trustDomain, domain.getName(), identity)) {
            return AccessStatus.DENIED_INVALID_ROLE_TOKEN;
        }
        
        // evaluate our domain's roles and policies to see if access
        // is allowed or not for the given operation and resource
        
        return evaluateAccess(domain, identity, action, resource, authenticatedRoles, trustDomain);
    }
    
    public Access getAccessExt(ResourceContext ctx, String action, String resource,
            String trustDomain, String checkPrincipal) {
        
        final String caller = "getaccessext";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(action, TYPE_COMPOUND_NAME, caller);
        
        return getAccessCheck(((RsrcCtxWrapper) ctx).principal(), action, resource,
                trustDomain, checkPrincipal);
    }
    
    public Access getAccess(ResourceContext ctx, String action, String resource,
            String trustDomain, String checkPrincipal) {

        final String caller = "getaccess";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(action, TYPE_COMPOUND_NAME, caller);
        validate(resource, TYPE_RESOURCE_NAME, caller);
        
        return getAccessCheck(((RsrcCtxWrapper) ctx).principal(), action, resource,
                trustDomain, checkPrincipal);
    }
    
    Access getAccessCheck(Principal principal, String action, String resource,
            String trustDomain, String checkPrincipal) {
        
        final String caller = "getaccess";

        if (LOG.isDebugEnabled()) {
            LOG.debug("getAccessCheck:(" + action + ", " + resource + ", " + principal +
                    ", " + trustDomain + ", " + checkPrincipal + ")");
        }
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        action = action.toLowerCase();
        resource = resource.toLowerCase();
        if (checkPrincipal != null) {
            checkPrincipal = checkPrincipal.toLowerCase();
        }
        if (trustDomain != null) {
            trustDomain = trustDomain.toLowerCase();
        }
        
        // retrieve the domain based on our resource and action/trustDomain pair
        
        String domainName = retrieveResourceDomain(resource, action, trustDomain);
        if (domainName == null) {
            metric.increment(ZMSConsts.HTTP_REQUEST, ZMSConsts.ZMS_INVALID_DOMAIN);
            metric.increment(caller, ZMSConsts.ZMS_INVALID_DOMAIN);
            throw ZMSUtils.notFoundError("getAccessCheck: Unable to extract resource domain", caller);
        }
        AthenzDomain domain = retrieveAccessDomain(domainName, principal);
        if (domain == null) {
            metric.increment(ZMSConsts.HTTP_REQUEST, ZMSConsts.ZMS_UNKNOWN_DOMAIN);
            metric.increment(caller, ZMSConsts.ZMS_UNKNOWN_DOMAIN);
            throw ZMSUtils.notFoundError("getAccessCheck: Resource Domain not found: '"
                    + domainName + "'", caller);
        }
        
        // if the domain is disabled then we're going to reject this
        // request right away
        
        if (domain.getDomain().getEnabled() == Boolean.FALSE) {
            throw ZMSUtils.forbiddenError("getAccessCheck: Disabled domain: '"
                    + domainName + "'", caller);
        }

        // start our counter with domain dimension. we're moving the metric here
        // after the domain name has been confirmed as valid since with
        // dimensions we get stuck with persistent indexes so we only want
        // to create them for valid domain names

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getaccess_timing", domainName);

        // if the check principal is given then we need to carry out the access
        // check against that principal
        
        if (checkPrincipal != null) {
            principal = createPrincipalForName(checkPrincipal);
            if (principal == null) {
                throw ZMSUtils.unauthorizedError("getAccessCheck: Invalid check principal value specified", caller);
            }
        }
        
        boolean accessAllowed = false;
        AccessStatus accessStatus = hasAccess(domain, action, resource, principal, trustDomain);
        if (accessStatus == AccessStatus.ALLOWED) {
            accessAllowed = true;
        }
        Access access = new Access().setGranted(accessAllowed);

        metric.stopTiming(timerMetric);
        return access;
    }

    boolean equalToOrPrefixedBy(String pattern, String name) {
        if (name.equals(pattern)) {
            return true;
        }
        return name.startsWith(pattern + ".");
    }

    void validateEntity(String entityName, Entity entity) {
        
        final String caller = "validateentity";
        
        if (!entityName.equals(entity.getName())) {
            throw ZMSUtils.requestError("validateEntity: Entity name mismatch: " + entityName + " != " + entity.getName(), caller);
        }
        if (entity.getValue() == null) {
            throw ZMSUtils.requestError("validateEntity: Entity value is empty: " + entityName, caller);
        }
    }

    void checkReservedEntityName(String en) {
        
        final String caller = "checkreservedentityname";
        
        final String [] reservedList = {META_FIELD, DOMAIN_FIELD, ROLE_FIELD, POLICY_FIELD, SERVICE_FIELD, TEMPLATE_FIELD};
        for (String reservedName : reservedList) {
            if (equalToOrPrefixedBy(reservedName, en)) {
                throw ZMSUtils.requestError("checkReservedEntityName: Bad entity name: reserved name or prefix: " + en, caller);
            }
        }
    }

    @Override
    public void putEntity(ResourceContext ctx, String domainName, String entityName, String auditRef, Entity resource) {
        
        final String caller = "putentity";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(entityName, TYPE_ENTITY_NAME, caller);
        checkReservedEntityName(entityName);
        validateEntity(entityName, resource);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        entityName = entityName.toLowerCase();
        AthenzObject.ENTITY.convertToLowerCase(resource);

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("putentity_timing", domainName);

        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        dbService.executePutEntity(ctx, domainName, entityName, resource, auditRef, caller);
        metric.stopTiming(timerMetric);
    }

    @Override
    public EntityList getEntityList(ResourceContext ctx, String domainName) {
        
        final String caller = "getentitylist";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getentitylist_timing", domainName);
        
        EntityList result = new EntityList();
        List<String> names = dbService.listEntities(domainName);
        result.setNames(names);

        metric.stopTiming(timerMetric);
        return result;
    }
    
    public Entity getEntity(ResourceContext ctx, String domainName, String entityName) {
        
        final String caller = "getentity";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(entityName, TYPE_ENTITY_NAME, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        entityName = entityName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getentity_timing", null);

        Entity entity = dbService.getEntity(domainName, entityName);
        if (entity == null) {
            throw ZMSUtils.notFoundError("getEntity: Entity not found: '" +
                    ZMSUtils.entityResourceName(domainName, entityName) + "'", caller);
        }
        
        metric.stopTiming(timerMetric);
        return entity;
    }
    
    public void deleteEntity(ResourceContext ctx, String domainName, String entityName, String auditRef) {
        
        final String caller = "deleteentity";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }
        
        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(entityName, TYPE_ENTITY_NAME, caller);
        checkReservedEntityName(entityName);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        entityName = entityName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("deleteentity_timing", null);
        
        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        dbService.executeDeleteEntity(ctx, domainName, entityName, auditRef, caller);
        metric.stopTiming(timerMetric);
    }

    public ServerTemplateList getServerTemplateList(ResourceContext ctx) {
        
        final String caller = "getservertemplatelist";
        metric.increment(ZMSConsts.HTTP_GET);
        metric.increment(ZMSConsts.HTTP_REQUEST);
        metric.increment(caller);
        Object timerMetric = metric.startTiming("getservertemplatelist_timing", null);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);

        ServerTemplateList result = new ServerTemplateList();
        result.setTemplateNames(new ArrayList<>(serverSolutionTemplates.names()));

        metric.stopTiming(timerMetric);
        return result;
    }
    
    public Template getTemplate(ResourceContext ctx, String templateName) {

        final String caller = "gettemplate";
        metric.increment(ZMSConsts.HTTP_GET);
        metric.increment(ZMSConsts.HTTP_REQUEST);
        metric.increment(caller);
        Object timerMetric = metric.startTiming("gettemplate_timing", null);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(templateName, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        templateName = templateName.toLowerCase();
        Template template = serverSolutionTemplates.get(templateName);
        if (template == null) {
            throw ZMSUtils.notFoundError("getTemplate: Template not found: '" + templateName + "'", caller);
        }
        
        List<Role> roles = template.getRoles();
        if (roles != null && !roles.isEmpty()) {
            for (Role role : roles) {
                List<RoleMember> roleMembers = role.getRoleMembers();
                if (roleMembers != null) {
                    role.setMembers(ZMSUtils.convertRoleMembersToMembers(roleMembers));
                }
            }
        }
        
        metric.stopTiming(timerMetric);
        return template;
    }

    public RoleList getRoleList(ResourceContext ctx, String domainName, Integer limit, String skip) {
        
        final String caller = "getrolelist";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        if (skip != null) {
            skip = skip.toLowerCase();
        }

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getrolelist_timing", domainName);
        
        RoleList result = new RoleList();
        
        List<String> names = new ArrayList<>();
        String next = processListRequest(domainName, AthenzObject.ROLE, limit, skip, names);
        result.setNames(names);
        if (next != null) {
            result.setNext(next);
        }

        metric.stopTiming(timerMetric);
        return result;
    }
    
    List<Role> setupRoleList(AthenzDomain domain, Boolean members) {
        
        // if we're asked to return the members as well then we
        // just need to return the data as is without any modifications
        
        List<Role> roles;
        if (members == Boolean.TRUE) {
            roles = domain.getRoles();
        } else {
            roles = new ArrayList<>();
            for (Role role : domain.getRoles()) {
                Role newRole = new Role()
                        .setName(role.getName())
                        .setModified(role.getModified())
                        .setTrust(role.getTrust());
                roles.add(newRole);
            }
        }
        
        return roles;
    }
    
    public Roles getRoles(ResourceContext ctx, String domainName, Boolean members) {
        
        final String caller = "getroles";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getroles_timing", domainName);
        
        Roles result = new Roles();
        
        AthenzDomain domain = getAthenzDomain(domainName, false);
        if (domain == null) {
            throw ZMSUtils.notFoundError("getRoles: Domain not found: '" + domainName + "'", caller);
        }

        result.setList(setupRoleList(domain, members));
        metric.stopTiming(timerMetric);
        return result;
    }

    @Override
    public DomainRoleMembers getDomainRoleMembers(ResourceContext ctx, String domainName) {

        final String caller = "getdomainrolemembers";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getdomainrolemembers_timing", domainName);

        DomainRoleMembers roleMembers = dbService.listDomainRoleMembers(domainName);
        metric.stopTiming(timerMetric);
        return roleMembers;
    }

    @Override
    public Role getRole(ResourceContext ctx, String domainName, String roleName,
            Boolean auditLog, Boolean expand) {
        
        final String caller = "getrole";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        roleName = roleName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getrole_timing", domainName);
        
        Role role = dbService.getRole(domainName, roleName, auditLog, expand);
        if (role == null) {
            throw ZMSUtils.notFoundError("getRole: Role not found: '" +
                    ZMSUtils.roleResourceName(domainName, roleName) + "'", caller);
        }

        metric.stopTiming(timerMetric);
        return role;
    }

    List<String> normalizedAdminUsers(List<String> admins) {
        List<String> normalizedAdmins = new ArrayList<>();
        for (String admin : admins) {
            normalizedAdmins.add(normalizeDomainAliasUser(admin));
        }
        return normalizedAdmins;
    }
    
    String normalizeDomainAliasUser(String user) {
        if (user != null && userDomainAliasPrefix != null && user.startsWith(userDomainAliasPrefix)) {
            if (user.indexOf('.', userDomainAliasPrefix.length()) == -1) {
                return userDomainPrefix + user.substring(userDomainAliasPrefix.length());
            }
        }
        return user;
    }
    
    RoleMember getNormalizedMember(RoleMember member) {
        
        // we're going to check for the domain alias
        // and handle accordingly - user-alias.hga will become user.hga
        
        final String memberName = member.getMemberName();
        final String aliasMemberName = normalizeDomainAliasUser(memberName);
        if (!aliasMemberName.equals(memberName)) {
            member.setMemberName(aliasMemberName);
        }

        return member;
    }
    
    private void addNormalizedRoleMember(Map<String, RoleMember> normalizedMembers,
            RoleMember member) {
        
        RoleMember normalizedMember = getNormalizedMember(member);
        
        // we'll automatically ignore any duplicates
        
        if (!normalizedMembers.containsKey(normalizedMember.getMemberName())) {
            normalizedMembers.put(normalizedMember.getMemberName(), normalizedMember);
        }
    }
    
    void normalizeRoleMembers(Role role) {
        
        Map<String, RoleMember> normalizedMembers = new HashMap<>();
        
        // normalize getMembers() first
        
        List<String> members = role.getMembers();
        if (members != null) {
            for (String memberOld : members) {
                RoleMember member = new RoleMember().setMemberName(memberOld);
                addNormalizedRoleMember(normalizedMembers, member);
            }
        }
        
        // normalize getRoleMembers() now
        
        List<RoleMember> roleMembers = role.getRoleMembers();
        if (roleMembers != null) {
            for (RoleMember member : roleMembers) {
                addNormalizedRoleMember(normalizedMembers, member);
            }
        }
        role.setRoleMembers(new ArrayList<>(normalizedMembers.values()));
        role.setMembers(null);
    }
    
    boolean isConsistentRoleName(final String domainName, final String roleName, Role role) {
        
        String resourceName = ZMSUtils.roleResourceName(domainName, roleName);
        
        // first lets assume we have the expected name specified in the role
        
        if (resourceName.equals(role.getName())) {
            return true;
        }

        // if not check to see if the role contains the relative local name
        // part only instead of the expected resourceName and update accordingly
        
        if (roleName.equals(role.getName())) {
            role.setName(resourceName);
            return true;
        }
        
        // we have a mismatch
        
        return false;
    }

    @Override
    public void putRole(ResourceContext ctx, String domainName, String roleName, String auditRef, Role role) {
        
        final String caller = "putrole";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);
        validate(role, TYPE_ROLE, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        roleName = roleName.toLowerCase();
        AthenzObject.ROLE.convertToLowerCase(role);

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("putrole_timing", domainName);
        
        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        // verify the role name in the URI and request are consistent
        
        if (!isConsistentRoleName(domainName, roleName, role)) {
            throw ZMSUtils.requestError("putRole: Inconsistent role names - expected: "
                    + ZMSUtils.roleResourceName(domainName, roleName) + ", actual: "
                    + role.getName(), caller);
        }
        
        // validate role and trust settings are as expected
        
        ZMSUtils.validateRoleMembers(role, caller, domainName);
        
        // normalize and remove duplicate members
        
        normalizeRoleMembers(role);
        
        // process our request
        
        dbService.executePutRole(ctx, domainName, roleName, role, auditRef, caller);
        metric.stopTiming(timerMetric);
    }
    
    public void deleteRole(ResourceContext ctx, String domainName, String roleName, String auditRef) {
        
        final String caller = "deleterole";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        roleName = roleName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("deleterole_timing", domainName);
        
        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        /* we are not going to allow any user to delete
         * the admin role and policy since those are required
         * for standard domain operations */
        
        if (roleName.equalsIgnoreCase(ADMIN_ROLE_NAME)) {
            throw ZMSUtils.requestError("deleteRole: admin role cannot be deleted", caller);
        }
        
        dbService.executeDeleteRole(ctx, domainName, roleName, auditRef, caller);
        metric.stopTiming(timerMetric);
    }

    boolean memberNameMatch(String memberName, String matchName) {
        // we are supporting 3 formats for role members
        // *, <domain>.* and <domain>.<user>*
        if (memberName.equals("*")) {
            return true;
        } else if (memberName.endsWith("*")) {
            return matchName.startsWith(memberName.substring(0, memberName.length() - 1));
        } else {
            return memberName.equals(matchName);
        }
    }
    
    boolean checkRoleMemberExpiration(List<RoleMember> roleMembers, String member) {
        
        boolean isMember = false;
        for (RoleMember memberInfo: roleMembers) {
            final String memberName = memberInfo.getMemberName();
            if (memberNameMatch(memberName, member)) {
                // check expiration, if is not defined, its not expired.
                Timestamp expiration = memberInfo.getExpiration();
                if (expiration != null) {
                    isMember = !(expiration.millis() < System.currentTimeMillis());
                } else {
                    isMember = true;
                }
                break;
            }
        }
        return isMember;
    }
    
    boolean isMemberOfRole(Role role, String member) {
        List<RoleMember> roleMembers = role.getRoleMembers();
        if (roleMembers == null) {
            return false;
        }
        return checkRoleMemberExpiration(roleMembers, member);
    }
    
    public Membership getMembership(ResourceContext ctx, String domainName,
            String roleName, String memberName) {
        
        final String caller = "getmembership";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);
        validate(memberName, TYPE_MEMBER_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        roleName = roleName.toLowerCase();
        memberName = normalizeDomainAliasUser(memberName.toLowerCase());

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getmembership_timing", domainName);

        Membership result = dbService.getMembership(domainName, roleName, memberName);
        
        metric.stopTiming(timerMetric);
        return result;
    }

    @Override
    public void putMembership(ResourceContext ctx, String domainName, String roleName,
            String memberName, String auditRef, Membership membership) {
        
        final String caller = "putmembership";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);
        validate(memberName, TYPE_MEMBER_NAME, caller);
        validate(membership, TYPE_MEMBERSHIP, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        roleName = roleName.toLowerCase();
        memberName = memberName.toLowerCase();
        AthenzObject.MEMBERSHIP.convertToLowerCase(membership);

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("putmembership_timing", domainName);

        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(),
                caller, "role", roleName);
        
        // verify that the member name in the URI and object provided match
        
        if (!memberName.equals(membership.getMemberName())) {
            throw ZMSUtils.requestError("putMembership: Member name in URI and Membership object do not match", caller);
        }
        
        // role name is optional so we'll verify only if the value is present in the object
        
        if (membership.getRoleName() != null && !roleName.equals(membership.getRoleName())) {
            throw ZMSUtils.requestError("putMembership: Role name in URI and Membership object do not match", caller);
        }
        
        // add the member to the specified role
        
        RoleMember roleMember = new RoleMember();
        roleMember.setMemberName(memberName);
        roleMember.setExpiration(membership.getExpiration());

        dbService.executePutMembership(ctx, domainName, roleName,
                getNormalizedMember(roleMember), auditRef, caller);
        metric.stopTiming(timerMetric);
    }

    public void deleteMembership(ResourceContext ctx, String domainName, String roleName,
            String memberName, String auditRef) {
        
        final String caller = "deletemembership";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);
        validate(memberName, TYPE_MEMBER_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        roleName = roleName.toLowerCase();
        memberName = memberName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("deletemembership_timing", domainName);
        
        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        RoleMember roleMember = new RoleMember();
        roleMember.setMemberName(memberName);
        String normalizedMember = getNormalizedMember(roleMember).getMemberName();
        dbService.executeDeleteMembership(ctx, domainName, roleName, normalizedMember, auditRef, caller);
        metric.stopTiming(timerMetric);
    }

    public Quota getQuota(ResourceContext ctx, String domainName) {
        
        final String caller = "getquota";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getquota_timing", domainName);

        Quota result = dbService.getQuota(domainName);
        
        metric.stopTiming(timerMetric);
        return result;
    }

    @Override
    public void putQuota(ResourceContext ctx, String domainName, String auditRef, Quota quota) {
        
        final String caller = "putQuota";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(quota, TYPE_QUOTA, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        AthenzObject.QUOTA.convertToLowerCase(quota);

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("putquota_timing", domainName);

        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(),
                caller);
        
        // verify that the domain name in the URI and object provided match
        
        if (!domainName.equals(quota.getName())) {
            throw ZMSUtils.requestError("putQuota: Domain name in URI and Quota object do not match", caller);
        }

        dbService.executePutQuota(ctx, domainName, quota, auditRef, caller);
        metric.stopTiming(timerMetric);
    }

    public void deleteQuota(ResourceContext ctx, String domainName, String auditRef) {
        
        final String caller = "deleteQuota";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("deletequota_timing", domainName);
        
        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        dbService.executeDeleteQuota(ctx, domainName, auditRef, caller);
        metric.stopTiming(timerMetric);
    }
    
    boolean hasExceededListLimit(Integer limit, int count) {
        
        if (limit == null) {
            return false;
        }

        return limit > 0 && count > limit;
    }
    
    /**
     * process the list request for the given object type - e.g. role, policy, etc
     * if the limit is specified and we have reached that limit then return
     * the name of the object that should be set at the next item for the
     * subsequent list operation.
     */
    String processListRequest(String domainName, AthenzObject objType, Integer limit,
            String skip, List<String> names) {
        
        switch (objType) {
            case ROLE:
                names.addAll(dbService.listRoles(domainName));
                break;
            case POLICY:
                names.addAll(dbService.listPolicies(domainName));
                break;
            case SERVICE_IDENTITY:
                names.addAll(dbService.listServiceIdentities(domainName));
                break;
            default:
                return null;
        }
        
        int count = names.size();
        if (skip != null) {
            for (int i = 0; i < count; i++) {
                String name = names.get(i);
                if (skip.equals(name)) {
                    names.subList(0, i + 1).clear();
                    count = names.size();
                    break;
                }
            }
        }
        
        String next = null;
        if (hasExceededListLimit(limit, count)) {
            names.subList(limit, count).clear();
            next = names.get(limit - 1);
        }
        
        return next;
    }
    
    public PolicyList getPolicyList(ResourceContext ctx, String domainName, Integer limit, String skip) {
        
        final String caller = "getpolicylist";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        if (skip != null) {
            skip = skip.toLowerCase();
        }

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getpolicylist_timing", domainName);
        
        List<String> names = new ArrayList<>();
        String next = processListRequest(domainName, AthenzObject.POLICY, limit, skip, names);
        PolicyList result = new PolicyList().setNames(names);
        if (next != null) {
            result.setNext(next);
        }
        
        metric.stopTiming(timerMetric);
        return result;
    }

    List<Policy> setupPolicyList(AthenzDomain domain, Boolean assertions) {
        
        // if we're asked to return the assertions as well then we
        // just need to return the data as is without any modifications
        
        List<Policy> policies;
        if (assertions == Boolean.TRUE) {
            policies = domain.getPolicies();
        } else {
            policies = new ArrayList<>();
            for (Policy policy : domain.getPolicies()) {
                Policy newPolicy = new Policy()
                        .setName(policy.getName())
                        .setModified(policy.getModified());
                policies.add(newPolicy);
            }
        }
        
        return policies;
    }
    
    public Policies getPolicies(ResourceContext ctx, String domainName, Boolean assertions) {
        
        final String caller = "getpolicies";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getpolicies_timing", domainName);
        
        Policies result = new Policies();
        
        AthenzDomain domain = getAthenzDomain(domainName, false);
        if (domain == null) {
            throw ZMSUtils.notFoundError("getPolicies: Domain not found: '" + domainName + "'", caller);
        }

        result.setList(setupPolicyList(domain, assertions));
        metric.stopTiming(timerMetric);
        return result;
    }
    
    public Policy getPolicy(ResourceContext ctx, String domainName, String policyName) {
        
        final String caller = "getpolicy";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_ENTITY_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        policyName = policyName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getpolicy_timing", domainName);
        
        Policy policy = dbService.getPolicy(domainName, policyName);
        if (policy == null) {
            throw ZMSUtils.notFoundError("getPolicy: Policy not found: '" +
                    ZMSUtils.policyResourceName(domainName, policyName) + "'", caller);
        }

        metric.stopTiming(timerMetric);
        return policy;
    }
    
    public Assertion getAssertion(ResourceContext ctx, String domainName, String policyName,
            Long assertionId) {
        
        final String caller = "getassertion";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_ENTITY_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        policyName = policyName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getassertion_timing", domainName);
        
        Assertion assertion = dbService.getAssertion(domainName, policyName, assertionId);
        if (assertion == null) {
            throw ZMSUtils.notFoundError("getAssertion: Assertion not found: '" +
                    ZMSUtils.policyResourceName(domainName, policyName) + "' Assertion: '" +
                    assertionId + "'", caller);
        }

        metric.stopTiming(timerMetric);
        return assertion;
    }

    @Override
    public Assertion putAssertion(ResourceContext ctx, String domainName, String policyName,
            String auditRef, Assertion assertion) {
        
        final String caller = "putassertion";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_COMPOUND_NAME, caller);
        validate(assertion, TYPE_ASSERTION, caller);

        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        policyName = policyName.toLowerCase();
        AthenzObject.ASSERTION.convertToLowerCase(assertion);

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("putassertion_timing", domainName);

        // we are not going to allow any user to update
        // the admin policy since that is required
        // for standard domain operations */
        
        if (policyName.equalsIgnoreCase(ADMIN_POLICY_NAME)) {
            throw ZMSUtils.requestError("putAssertion: admin policy cannot be modified", caller);
        }
        
        // validate to make sure we have expected values for assertion fields
        
        validatePolicyAssertion(assertion, caller);
        
        dbService.executePutAssertion(ctx, domainName, policyName, assertion, auditRef, caller);
        metric.stopTiming(timerMetric);
        return assertion;
    }
    
    public void deleteAssertion(ResourceContext ctx, String domainName, String policyName,
            Long assertionId, String auditRef) {
        
        final String caller = "deleteassertion";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_ENTITY_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        policyName = policyName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("deleteassertion_timing", domainName);
        
        // we are not going to allow any user to update
        // the admin policy since that is required
        // for standard domain operations */
        
        if (policyName.equalsIgnoreCase(ADMIN_POLICY_NAME)) {
            throw ZMSUtils.requestError("deleteAssertion: admin policy cannot be modified", caller);
        }
        
        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        dbService.executeDeleteAssertion(ctx, domainName, policyName, assertionId, auditRef, caller);
        metric.stopTiming(timerMetric);
    }
    
    void validatePolicyAssertions(List<Assertion> assertions, String caller) {
        
        if (assertions == null) {
            return;
        }
        
        for (Assertion assertion : assertions) {
            validatePolicyAssertion(assertion, caller);
        }
    }
    
    void validatePolicyAssertion(Assertion assertion, String caller) {
            
        // extract the domain name from the resource
        
        final String resource = assertion.getResource();
        int idx = resource.indexOf(':');
        if (idx == -1) {
            throw ZMSUtils.requestError("Missing domain name from assertion resource: "
                    + resource, caller);
        }

        // we need to validate our domain name with special
        // case of * that is allowed to match any domain
        
        String domainName = resource.substring(0, idx);
        if (!domainName.equals("*")) {
            validate(domainName, TYPE_DOMAIN_NAME, caller);
        }
        
        // we'll also verify that the resource does not contain
        // any control characters since those cause issues when
        // data is serialized/deserialized and signature is generated
        
        if (StringUtils.containsControlCharacter(resource)) {
            throw ZMSUtils.requestError("Assertion resource contains control characters: "
                    + resource, caller);
        }
        
        // verify the action is not empty and does not contain
        // any control characters
        
        final String action = assertion.getAction();
        if (action == null || action.isEmpty()) {
            throw ZMSUtils.requestError("Assertion action cannot be empty", caller);
        }
        
        if (StringUtils.containsControlCharacter(action)) {
            throw ZMSUtils.requestError("Assertion action contains control characters: "
                    + resource, caller);
        }
    }
    
    boolean isConsistentPolicyName(final String domainName, final String policyName, Policy policy) {
        
        String resourceName = ZMSUtils.policyResourceName(domainName, policyName);
        
        // first lets assume we have the expected name specified in the policy
        
        if (resourceName.equals(policy.getName())) {
            return true;
        }

        // if not check to see if the policy contains the relative local name
        // part only instead of the expected resourceName and update accordingly
        
        if (policyName.equals(policy.getName())) {
            policy.setName(resourceName);
            return true;
        }
        
        // we have a mismatch
        
        return false;
    }

    @Override
    public void putPolicy(ResourceContext ctx, String domainName, String policyName, String auditRef, Policy policy) {
        
        final String caller = "putpolicy";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_COMPOUND_NAME, caller);
        validate(policy, TYPE_POLICY, caller);

        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        policyName = policyName.toLowerCase();
        AthenzObject.POLICY.convertToLowerCase(policy);

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("putpolicy_timing", domainName);
        
        // we are not going to allow any user to update
        // the admin policy since that is required
        // for standard domain operations */
        
        if (policyName.equalsIgnoreCase(ADMIN_POLICY_NAME)) {
            throw ZMSUtils.requestError("putPolicy: admin policy cannot be modified", caller);
        }
        
        // verify the policy name in the URI and request are consistent
        
        if (!isConsistentPolicyName(domainName, policyName, policy)) {
            throw ZMSUtils.requestError("putPolicy: Inconsistent policy names - expected: "
                    + ZMSUtils.policyResourceName(domainName, policyName) + ", actual: "
                    + policy.getName(), caller);
        }
        
        // validate to make sure we have expected values for assertion fields
        
        validatePolicyAssertions(policy.getAssertions(), caller);
        
        dbService.executePutPolicy(ctx, domainName, policyName, policy, auditRef, caller);
        metric.stopTiming(timerMetric);
    }
    
    public void deletePolicy(ResourceContext ctx, String domainName, String policyName, String auditRef) {
        
        final String caller = "deletepolicy";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_ENTITY_NAME, caller);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        policyName = policyName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("deletepolicy_timing", domainName);

        // we are not going to allow any user to delete
        // the admin role and policy since those are required
        // for standard domain operations */
        
        if (policyName.equalsIgnoreCase(ADMIN_POLICY_NAME)) {
            throw ZMSUtils.requestError("deletePolicy: admin policy cannot be deleted", caller);
        }
        
        dbService.executeDeletePolicy(ctx, domainName, policyName, auditRef, caller);
        metric.stopTiming(timerMetric);
    }

    boolean matchDelegatedTrustAssertion(Assertion assertion, String roleName, 
            String roleMember, List<Role> roles) {
        
        if (!ZMSUtils.assumeRoleResourceMatch(roleName, assertion)) {
            return false;
        }
        
        String rolePattern = StringUtils.patternFromGlob(assertion.getRole());
        for (Role role : roles) {
            String name = role.getName();
            if (!name.matches(rolePattern)) {
                continue;
            }
            
            if (isMemberOfRole(role, roleMember)) {
                return true;
            }
        }
        
        return false;
    }
    
    boolean matchDelegatedTrustPolicy(Policy policy, String roleName, String roleMember, List<Role> roles) {
        
        List<Assertion> assertions = policy.getAssertions();
        if (assertions == null) {
            return false;
        }
        
        for (Assertion assertion : assertions) {
            if (matchDelegatedTrustAssertion(assertion, roleName, roleMember, roles)) {
                return true;
            }
        }
        
        return false;
    }
    
    boolean delegatedTrust(String domainName, String roleName, String roleMember) {
        
        AthenzDomain domain = getAthenzDomain(domainName, true);
        if (domain == null) {
            return false;
        }
        
        for (Policy policy : domain.getPolicies()) {
            if (matchDelegatedTrustPolicy(policy, roleName, roleMember, domain.getRoles())) {
                return true;
            }
        }
        
        return false;
    }

    boolean matchRole(String domain, List<Role> roles, String rolePattern,
            List<String> authenticatedRoles) {
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("matchRole domain: " + domain + " rolePattern: " + rolePattern);
        }
        
        String prefix = domain + ":role.";
        int prefixLen = prefix.length();
        for (Role role : roles) {
            String name = role.getName();
            if (!name.matches(rolePattern)) {
                continue;
            }
            
            String shortName = name.substring(prefixLen);
            if (authenticatedRoles.contains(shortName)) {
                return true;
            }
        }
        return false;
    }

    boolean shouldRunDelegatedTrustCheck(String trust, String trustDomain) {
        
        // if no trust field field then no delegated trust check
        
        if (trust == null) {
            return false;
        }
        
        // if no specific trust domain specifies then we need
        // run the delegated trust check for this domain
        
        if (trustDomain == null) {
            return true;
        }
        
        // otherwise we'll run the delegated trust check only if
        // domain name matches
        
        return trust.equalsIgnoreCase(trustDomain);
    }
    
    boolean matchPrincipalInRole(Role role, String roleName, String fullUser, String trustDomain) {
        
        // if we have members in the role then we're going to check
        // against that list only
        
        if (role.getRoleMembers() != null) {
            return isMemberOfRole(role, fullUser);
        }
        
        // no members so let's check if this is a trust domain
        
        String trust = role.getTrust();
        if (!shouldRunDelegatedTrustCheck(trust, trustDomain)) {
            return false;
        }

        // delegate to another domain.
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("matchPrincipal: [delegated trust. Checking with: " + trust + "]");
        }
        
        return delegatedTrust(trust, roleName, fullUser);
    }
    
    boolean matchPrincipal(List<Role> roles, String rolePattern, String fullUser, String trustDomain) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("matchPrincipal - rolePattern: " + rolePattern + " user: " + fullUser +
                    " trust: " + trustDomain);
        }

        for (Role role : roles) {
            
            String name = role.getName();
            if (!name.matches(rolePattern)) {
                continue;
            }
            
            if (matchPrincipalInRole(role, name, fullUser, trustDomain)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("assertionMatch: -> OK (by principal)");
                }
                return true;
            }
        }
        return false;
    }

    AthenzDomain virtualHomeDomain(Principal principal, String domainName) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("homeDomain: home domain detected. Create on the fly.");
        }
        
        AthenzDomain athenzDomain = new AthenzDomain(domainName);
        
        Domain domain = new Domain().setName(domainName).setEnabled(Boolean.TRUE);
        athenzDomain.setDomain(domain);
        
        List<String> adminUsers = new ArrayList<>();
        adminUsers.add(principal.getFullName());
        
        Role role = ZMSUtils.makeAdminRole(domainName, adminUsers);
        athenzDomain.getRoles().add(role);
        
        Policy policy = ZMSUtils.makeAdminPolicy(domainName, role);
        athenzDomain.getPolicies().add(policy);
        
        return athenzDomain;
    }
    
    boolean assertionMatch(Assertion assertion, String identity, String action, String resource,
            String domain, List<Role> roles, List<String> authenticatedRoles, String trustDomain) {
        
        String actionPattern = StringUtils.patternFromGlob(assertion.getAction());
        if (LOG.isDebugEnabled()) {
            LOG.debug("assertionMatch: action '{}' pattern '{}'", action, actionPattern);
        }
        if (!action.matches(actionPattern)) {
            return false;
        }
        
        String rezPattern = StringUtils.patternFromGlob(assertion.getResource());
        if (LOG.isDebugEnabled()) {
            LOG.debug("assertionMatch: resource '{}' pattern '{}'", resource, rezPattern);
        }
        if (!resource.matches(rezPattern)) {
            return false;
        }
        
        boolean matchResult;
        String rolePattern = StringUtils.patternFromGlob(assertion.getRole());
        if (authenticatedRoles != null) {
            matchResult = matchRole(domain, roles, rolePattern, authenticatedRoles);
        } else {
            matchResult = matchPrincipal(roles, rolePattern, identity, trustDomain);
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("assertionMatch: -> " + matchResult +
                    " (effect: " + assertion.getEffect() + ")");
        }

        return matchResult;
    }
    
    boolean verifyProviderEndpoint(String providerEndpoint) {
        
        // verify that we have a valid endpoint that ends in one of our
        // configured domains. if it's not present or an empty value then
        // there is no field to verify
        
        if (providerEndpoint == null) {
            return true;
        }
        
        if (providerEndpoint.isEmpty()) {
            return true;
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("verifyProviderEndpoint: verifying endpoint: " + providerEndpoint);
        }
        
        java.net.URI uri;
        try {
            uri = new java.net.URI(providerEndpoint);
        } catch (URISyntaxException ex) {
            return false;
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("verifyProviderEndpoint: host: " + uri.getHost() + " scheme: " + uri.getScheme());
        }
        
        String scheme = uri.getScheme();
        if (scheme == null) {
            return false;
        }
        
        scheme = scheme.toLowerCase();
        
        // if our scheme is class then we have no further checks to carry
        
        if (scheme.equalsIgnoreCase(ZMSConsts.SCHEME_CLASS)) {
            return true;
        }
        
        // otherwise it must be one of our http schemes

        if (!(scheme.equalsIgnoreCase(ZMSConsts.SCHEME_HTTP) || scheme.equalsIgnoreCase(ZMSConsts.SCHEME_HTTPS))) {
            return false;
        }
        
        String host = uri.getHost();
        if (host == null) {
            return false;
        }
        host = host.toLowerCase();
        
        // if we have no endpoint configured then we should
        // allow all hostnames
        
        if (providerEndpoints == null || providerEndpoints.isEmpty()) {
            return true;
        }
        
        // we're going to allow localhost as a special case since
        // that's often used for dev testing
        
        boolean valid = host.equals(ZMSConsts.LOCALHOST);
        if (!valid) {
            for (String endpoint : providerEndpoints) {
                valid = host.endsWith(endpoint);
                if (valid) {
                    break;
                }
            }
        }

        return valid;
    }
    
    boolean verifyServicePublicKey(String key) {
        try {
            PublicKey pub = Crypto.loadPublicKey(Crypto.ybase64DecodeString(key));
            if (LOG.isDebugEnabled()) {
                LOG.debug("verifyServicePublicKey: public key looks valid: " + pub);
            }
        } catch (Exception ex) {
            LOG.error("verifyServicePublicKey: Invalid Public Key: " + ex.getMessage());
            return false;
        }
        return true;
    }
    
    boolean verifyServicePublicKeys(ServiceIdentity service) {

        // verify that the public keys specified are valid
        // It's okay to not specify any public keys

        List<PublicKeyEntry> publicKeyList = service.getPublicKeys();
        if (publicKeyList == null || publicKeyList.size() == 0) {
            return true;
        }

        for (PublicKeyEntry entry : publicKeyList) {
            if (!verifyServicePublicKey(entry.getKey())) {
                return false;
            }
        }
        return true;
    }

    public boolean isValidServiceName(final String serviceName) {

        if (reservedServiceNames != null && reservedServiceNames.contains(serviceName)) {
            return false;
        }

        if (serviceNameMinLength > 0 && serviceNameMinLength > serviceName.length()) {
            return false;
        }

        return true;
    }

    @Override
    public void putServiceIdentity(ResourceContext ctx, String domainName, String serviceName,
                                   String auditRef, ServiceIdentity service) {
        
        final String caller = "putserviceidentity";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(serviceName, TYPE_SIMPLE_NAME, caller);
        validate(service, TYPE_SERVICE_IDENTITY, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        serviceName = serviceName.toLowerCase();
        AthenzObject.SERVICE_IDENTITY.convertToLowerCase(service);

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("putserviceidentity_timing", domainName);

        // validate that the service name is valid

        if (!isValidServiceName(serviceName)) {
            throw ZMSUtils.requestError("putServiceIdentity: Invalid/Reserved service name", caller);
        }

        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        if (!ZMSUtils.serviceResourceName(domainName, serviceName).equals(service.getName())) {
            throw ZMSUtils.requestError("putServiceIdentity: Inconsistent service/domain names", caller);
        }
        
        if (!verifyServicePublicKeys(service)) {
            throw ZMSUtils.requestError("putServiceIdentity: Provided public key is invalid", caller);
        }

        if (!verifyProviderEndpoint(service.getProviderEndpoint())) {
            throw ZMSUtils.requestError("putServiceIdentity: Invalid endpoint: "
                + service.getProviderEndpoint() + " - must be http(s) and in configured domain", caller);
        }
        
        dbService.executePutServiceIdentity(ctx, domainName, serviceName, service, auditRef, caller);
        metric.stopTiming(timerMetric);
    }
    
    public ServiceIdentity getServiceIdentity(ResourceContext ctx, String domainName, String serviceName) {
        
        final String caller = "getserviceidentity";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(serviceName, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        serviceName = serviceName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getserviceidentity_timing", domainName);

        ServiceIdentity service = dbService.getServiceIdentity(domainName, serviceName);
        if (service == null) {
            throw ZMSUtils.notFoundError("getServiceIdentity: Service not found: '" +
                    ZMSUtils.serviceResourceName(domainName, serviceName) + "'", caller);
        }
        
        metric.stopTiming(timerMetric);
        return service;
    }
    
    public void deleteServiceIdentity(ResourceContext ctx, String domainName,
            String serviceName, String auditRef) {
        
        final String caller = "deleteserviceidentity";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(serviceName, TYPE_SIMPLE_NAME, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        serviceName = serviceName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("deleteserviceidentity_timing", domainName);
        
        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        dbService.executeDeleteServiceIdentity(ctx, domainName, serviceName, auditRef, caller);
        metric.stopTiming(timerMetric);
    }

    List<ServiceIdentity> setupServiceIdentityList(AthenzDomain domain, Boolean publicKeys, Boolean hosts) {
        
        // if we're asked to return the public keys and hosts as well then we
        // just need to return the data as is without any modifications
        
        List<ServiceIdentity> services;
        if (publicKeys == Boolean.TRUE && hosts == Boolean.TRUE) {
            services = domain.getServices();
        } else {
            services = new ArrayList<>();
            for (ServiceIdentity service : domain.getServices()) {
                ServiceIdentity newService = new ServiceIdentity()
                        .setName(service.getName())
                        .setModified(service.getModified())
                        .setExecutable(service.getExecutable())
                        .setGroup(service.getGroup())
                        .setUser(service.getUser())
                        .setProviderEndpoint(service.getProviderEndpoint());
                if (publicKeys == Boolean.TRUE) {
                    newService.setPublicKeys(service.getPublicKeys());
                } else if (hosts == Boolean.TRUE) {
                    newService.setHosts(service.getHosts());
                }
                services.add(newService);
            }
        }
        
        return services;
    }
    
    public ServiceIdentities getServiceIdentities(ResourceContext ctx, String domainName,
            Boolean publicKeys, Boolean hosts) {
        
        final String caller = "getserviceidentities";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getserviceidentities_timing", domainName);
        
        ServiceIdentities result = new ServiceIdentities();
        
        AthenzDomain domain = getAthenzDomain(domainName, false);
        if (domain == null) {
            throw ZMSUtils.notFoundError("getServiceIdentities: Domain not found: '"
                    + domainName + "'", caller);
        }

        result.setList(setupServiceIdentityList(domain, publicKeys, hosts));
        metric.stopTiming(timerMetric);
        return result;
    }
    
    public ServiceIdentityList getServiceIdentityList(ResourceContext ctx, String domainName,
            Integer limit, String skip) {
       
        final String caller = "getserviceidentitylist";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        if (skip != null) {
            skip = skip.toLowerCase();
        }

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getserviceidentitylist_timing", domainName);
        
        List<String> names = new ArrayList<>();
        String next = processListRequest(domainName, AthenzObject.SERVICE_IDENTITY, limit, skip, names);
        ServiceIdentityList result = new ServiceIdentityList().setNames(names);
        if (next != null) {
            result.setNext(next);
        }

        metric.stopTiming(timerMetric);
        return result;
    }

    public PublicKeyEntry getPublicKeyEntry(ResourceContext ctx, String domainName, String serviceName, String keyId) {
        
        final String caller = "getpublickeyentry";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(serviceName, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        serviceName = serviceName.toLowerCase();
        keyId = keyId.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getpublickeyentry_timing", domainName);
        
        PublicKeyEntry entry = dbService.getServicePublicKeyEntry(domainName, serviceName, keyId, false);
        if (entry == null) {
            throw ZMSUtils.notFoundError("getPublicKeyEntry: PublicKey " + keyId + " in service " +
                    ZMSUtils.serviceResourceName(domainName, serviceName) + " not found", caller);
        }
        
        metric.stopTiming(timerMetric);
        return entry;
    }

    public void deletePublicKeyEntry(ResourceContext ctx, String domainName, String serviceName,
            String keyId, String auditRef) {
        
        final String caller = "deletepublickeyentry";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }
        
        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(serviceName, TYPE_SIMPLE_NAME, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        serviceName = serviceName.toLowerCase();
        keyId = keyId.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("deletepublickeyentry_timing", domainName);

        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        dbService.executeDeletePublicKeyEntry(ctx, domainName, serviceName, keyId, auditRef, caller);
        metric.stopTiming(timerMetric);
    }

    @Override
    public void putPublicKeyEntry(ResourceContext ctx, String domainName, String serviceName,
            String keyId, String auditRef, PublicKeyEntry keyEntry) {
        
        final String caller = "putpublickeyentry";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(serviceName, TYPE_SIMPLE_NAME, caller);
        validate(keyEntry, TYPE_PUBLIC_KEY_ENTRY, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        serviceName = serviceName.toLowerCase();
        keyId = keyId.toLowerCase();
        AthenzObject.PUBLIC_KEY_ENTRY.convertToLowerCase(keyEntry);

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("putpublickeyentry_timing", domainName);

        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        // verify that key id specified in request and object do match
        
        if (!keyId.equals(keyEntry.getId())) {
            throw ZMSUtils.requestError("putPublicKeyEntry: keyId in URI and PublicKeyEntry object do not match", caller);
        }
        
        // verify we have a valid public key specified
        
        if (!verifyServicePublicKey(keyEntry.getKey())) {
            throw ZMSUtils.requestError("putPublicKeyEntry: Invalid public key", caller);
        }
        
        dbService.executePutPublicKeyEntry(ctx, domainName, serviceName, keyEntry, auditRef, caller);
        metric.stopTiming(timerMetric);
    }

    String removeQuotes(String value) {
        if (value.startsWith("\"")) {
            value = value.substring(1, value.length());
        }
        if (value.endsWith("\"")) {
            value = value.substring(0, value.length() - 1);
        }
        return value;
    }
    
    long getModTimestamp(String matchingTag) {
        
        long timestamp = 0;
        if (matchingTag == null) {
            return timestamp;
        }

        matchingTag = removeQuotes(matchingTag);

        if (LOG.isDebugEnabled()) {
            LOG.debug("getModTimestamp: matching tag ({})", matchingTag);
        }

        if (matchingTag.isEmpty()) {
            return timestamp;
        }

        try {
            Timestamp tagStamp = Timestamp.fromString(matchingTag);
            if (tagStamp == null) {
                throw new IllegalArgumentException("Timestamp failed");
            }
            timestamp = tagStamp.millis();
        } catch (IllegalArgumentException exc) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("getModTimestamp: matching tag({}) has bad format. Return 0 by default.",
                        matchingTag);
            }
        }
        
        return timestamp;
    }

    SignedDomain createSignedDomain(String domainName, long modifiedTime) {
        SignedDomain signedDomain = new SignedDomain();
        DomainData domainData = new DomainData().setName(domainName);
        signedDomain.setDomain(domainData);
        domainData.setModified(Timestamp.fromMillis(modifiedTime));
        return signedDomain;
    }

    SignedDomain retrieveSignedDomainMeta(final String domainName, long modifiedTime,
         final String account, Integer ypmId, final String metaAttr) {

        SignedDomain signedDomain = createSignedDomain(domainName, modifiedTime);
        if (metaAttr != null) {
            switch (metaAttr) {
                case META_ATTR_ACCOUNT:
                    if (account == null) {
                        return null;
                    }
                    signedDomain.getDomain().setAccount(account);
                    break;
                case META_ATTR_YPM_ID:
                    if (ypmId == null) {
                        return null;
                    }
                    signedDomain.getDomain().setYpmId(ypmId);
                    break;
                case META_ATTR_ALL:
                    signedDomain.getDomain().setAccount(account);
                    signedDomain.getDomain().setYpmId(ypmId);
                    break;
            }
        }
        return signedDomain;
    }

    SignedDomain retrieveSignedDomain(Domain domain, final String metaAttr, boolean setMetaDataOnly) {

        // check if we're asked to only return the meta data which
        // we already have - name and last modified time, so we can
        // add the domain to our return list and continue with the
        // next domain

        SignedDomain signedDomain;
        if (setMetaDataOnly) {
            signedDomain = retrieveSignedDomainMeta(domain.getName(), domain.getModified().millis(),
                    domain.getAccount(), domain.getYpmId(), metaAttr);
        } else {
            signedDomain = retrieveSignedDomainData(domain.getName(), domain.getModified().millis());
        }
        return signedDomain;
    }

    SignedDomain retrieveSignedDomain(DomainModified domainModified, final String metaAttr,
            boolean setMetaDataOnly) {

        // check if we're asked to only return the meta data which
        // we already have - name and last modified time, so we can
        // add the domain to our return list and continue with the
        // next domain

        SignedDomain signedDomain;
        if (setMetaDataOnly) {
            signedDomain = retrieveSignedDomainMeta(domainModified.getName(), domainModified.getModified(),
                    domainModified.getAccount(), domainModified.getYpmId(), metaAttr);
        } else {
            signedDomain = retrieveSignedDomainData(domainModified.getName(), domainModified.getModified());
        }
        return signedDomain;
    }

    SignedDomain retrieveSignedDomainData(final String domainName, long modifiedTime) {

        // generate our signed domain object

        SignedDomain signedDomain = createSignedDomain(domainName, modifiedTime);

        // get the policies, roles, and service identities to create the
        // DomainData

        if (LOG.isDebugEnabled()) {
            LOG.debug("retrieveSignedDomain: retrieving domain " + domainName);
        }
        
        AthenzDomain athenzDomain = getAthenzDomain(domainName, true, true);
        
        // it's possible that our domain was deleted by another
        // thread while we were processing this request so
        // we'll return null so the caller can skip this domain
        
        if (athenzDomain == null) {
            return null;
        }

        // set domain attributes - for enabled flag only set it
        // if it set to false

        DomainData domainData = signedDomain.getDomain();

        Boolean enabled = athenzDomain.getDomain().getEnabled();
        if (enabled == Boolean.FALSE) {
            domainData.setEnabled(enabled);
        }
        domainData.setAccount(athenzDomain.getDomain().getAccount());
        domainData.setYpmId(athenzDomain.getDomain().getYpmId());
        domainData.setRoles(athenzDomain.getRoles());
        domainData.setServices(athenzDomain.getServices());
        domainData.setApplicationId(athenzDomain.getDomain().getApplicationId());
        
        // generate the domain policy object that includes the domain
        // name and all policies. Then we'll sign this struct using
        // server's private key to get signed policy object
        
        DomainPolicies domainPolicies = new DomainPolicies().setDomain(domainName);
        domainPolicies.setPolicies(getPolicyListWithoutAssertionId(athenzDomain.getPolicies()));
        SignedPolicies signedPolicies = new SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        domainData.setPolicies(signedPolicies);

        String signature = Crypto.sign(
                SignUtils.asCanonicalString(signedPolicies.getContents()), privateKey);
        signedPolicies.setSignature(signature).setKeyId(privateKeyId);

        // then sign the data and set the data and signature in a SignedDomain
        
        signature = Crypto.sign(SignUtils.asCanonicalString(domainData), privateKey);
        signedDomain.setSignature(signature).setKeyId(privateKeyId);
        return signedDomain;
    }
    
    public Response getSignedDomains(ResourceContext ctx, String domainName, String metaOnly,
            String metaAttr, String matchingTag) {

        final String caller = "getsigneddomains";
        metric.increment(ZMSConsts.HTTP_GET);
        metric.increment(ZMSConsts.HTTP_REQUEST);
        metric.increment(caller);
        Object timerMetric = metric.startTiming("getsigneddomains_timing", null);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        if (domainName != null) {
            domainName = domainName.toLowerCase();
            validate(domainName, TYPE_DOMAIN_NAME, caller);
        }
        if (metaAttr != null) {
            metaAttr = metaAttr.toLowerCase();
            validate(metaAttr, TYPE_SIMPLE_NAME, caller);
        }
        
        boolean setMetaDataOnly = ZMSUtils.parseBoolean(metaOnly, false);
        long timestamp = getModTimestamp(matchingTag);
        
        // if this is one of our system principals then we're going to
        // to use the master copy instead of read-only slaves
        
        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        boolean systemPrincipal = principal.getFullName().startsWith("sys.");
        
        // if we're given a specific domain then we don't need to
        // retrieve the list of modified domains
        
        List<SignedDomain> sdList = new ArrayList<>();
        Long youngestDomMod = -1L;

        if (domainName != null && !domainName.isEmpty()) {
        
            Domain domain = null;
            try {
                domain = dbService.getDomain(domainName, systemPrincipal);
            } catch (ResourceException ex) {
                
                // in case the domain does not exist we're just
                // going to return an empty set
                
                if (ex.getCode() != ResourceException.NOT_FOUND) {
                    throw ex;
                }
            }

            if (domain != null) {
                youngestDomMod = domain.getModified().millis();

                if (timestamp != 0 && youngestDomMod <= timestamp) {
                    EntityTag eTag = new EntityTag(domain.getModified().toString());
                    return Response.status(ResourceException.NOT_MODIFIED)
                            .header("ETag", eTag.toString()).build();
                }
                
                // generate our signed domain object
                
                SignedDomain signedDomain = retrieveSignedDomain(domain, metaAttr, setMetaDataOnly);
                
                if (signedDomain != null) {
                    sdList.add(signedDomain);
                }
            } else {
                youngestDomMod = System.currentTimeMillis();
            }
            
        } else {

            // if we don't have a domain name then the meta flag must
            // be set to true otherwise it's expensive to fetch all
            // domains and sign all domains into a single response
            // unless the request is from a system service

            if (!setMetaDataOnly && !systemPrincipal)  {
                return Response.status(ResourceException.BAD_REQUEST).build();
            }

            // we should get our matching tag before calling get modified list
            // in case we get a domain added/updated right after an empty domain list
            // was returned and before the matchingTag was set to a value
            
            if (matchingTag == null) {
                EntityTag eTag = new EntityTag(Timestamp.fromMillis(0).toString());
                matchingTag = eTag.toString();
            }
            
            DomainModifiedList dmlist = dbService.listModifiedDomains(timestamp);
            List<DomainModified> modlist = dmlist.getNameModList();
            if (modlist == null || modlist.size() == 0) {
                return Response.status(ResourceException.NOT_MODIFIED)
                        .header("ETag", matchingTag).build();
            }
            
            // now we can iterate through our list and retrieve each domain

            //noinspection ConstantConditions
            for (DomainModified dmod : modlist) {
                
                Long domModMillis = dmod.getModified();
                if (domModMillis.compareTo(youngestDomMod) > 0) {
                    youngestDomMod = domModMillis;
                }
                
                // generate our signed domain object
                
                SignedDomain signedDomain = retrieveSignedDomain(dmod, metaAttr, setMetaDataOnly);
                
                // it's possible that our domain was deleted by another
                // thread while we were processing this request so
                // if we get a null object, we'll just skip this
                // item and continue with the next one
                
                if (signedDomain == null) {
                    continue;
                }
                
                // we have a valid domain so we'll add it to our return list
                
                sdList.add(signedDomain);
            }
        }

        SignedDomains sdoms = new SignedDomains();
        sdoms.setDomains(sdList);

        Timestamp youngest = Timestamp.fromMillis(youngestDomMod);
        EntityTag eTag = new EntityTag(youngest.toString());

        metric.stopTiming(timerMetric);
        return Response.status(ResourceException.OK).entity(sdoms)
                .header("ETag", eTag.toString()).build();
    }
    
    List<Policy> getPolicyListWithoutAssertionId(List<Policy> policies) {
        
        if (policies == null) {
            return null;
        }
        
        // we are going to remove the assertion id from our assertions
        // since the data is signed and the clients don't need to be
        // updated due to this new attribute being returned
        
        List<Policy> policyList = new ArrayList<>();

        for (Policy policy : policies) {
            Policy newPolicy = new Policy()
                    .setModified(policy.getModified())
                    .setName(policy.getName());
            if (policy.getAssertions() != null) {
                List<Assertion> assertions = new ArrayList<>();
                for (Assertion assertion : policy.getAssertions()) {
                    Assertion newAssertion = new Assertion()
                            .setAction(assertion.getAction())
                            .setResource(assertion.getResource())
                            .setRole(assertion.getRole());
                    if (assertion.getEffect() != null) {
                        newAssertion.setEffect(assertion.getEffect());
                    } else {
                        newAssertion.setEffect(AssertionEffect.ALLOW);
                    }
                    assertions.add(newAssertion);
                }
                newPolicy.setAssertions(assertions);
            }
            policyList.add(newPolicy);
        }
        return policyList;
    }

    boolean isValidUserTokenRequest(Principal principal, String userName) {
        
        if (principal == null) {
            return false;
        }

        Authority authority = principal.getAuthority();
        if (authority == null) {
            return false;
        }

        // if authority allowed to carry out authorization checks there
        // is no need to request user tokens
        
        if (authority.allowAuthorization()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("User Token request - Authority cannot request user tokens");
            }
            return false;
        }
        
        String authDomain = authority.getDomain();
        if (authDomain == null || !authDomain.equalsIgnoreCase(userDomain)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("User Token request - not authenticated by User Authority");
            }
            return false;
        }

        // if the username is not our pre-defined skip value we are going
        // to verify that it matches to the principal's name
        
        if (userName.equalsIgnoreCase(USER_TOKEN_DEFAULT_NAME)) {
            return true;
        }
        
        if (!userName.equalsIgnoreCase(principal.getName())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("User Token request - mismatch between request user name and userid");
            }
            return false;
        }
        
        return true;
    }
    
    @Override
    public UserToken getUserToken(ResourceContext ctx, String userName, String authorizedServices,
            Boolean header) {

        final String caller = "getusertoken";
        metric.increment(ZMSConsts.HTTP_GET);
        metric.increment(ZMSConsts.HTTP_REQUEST);
        metric.increment(caller);
        Object timerMetric = metric.startTiming("getusertoken_timing", null);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        userName = userName.toLowerCase();
        
        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        if (!isValidUserTokenRequest(principal, userName)) {
            throw ZMSUtils.unauthorizedError("getUserToken: Invalid request - missing User credentials or userName mismatch", caller);
        }

        // if the user is requesting authorized services we need to verify that
        // all the service names are valid
        
        List<String> services = null;
        if (authorizedServices != null && !authorizedServices.isEmpty()) {
            services = Arrays.asList(authorizedServices.split(","));
            for (String service : services) {
                if (!serverAuthorizedServices.contains(service)) {
                    throw ZMSUtils.unauthorizedError("getUserToken: Service " + service + " is not authorized in ZMS", caller);
                }
            }
        }
        
        PrincipalToken token = new PrincipalToken.Builder("U1", userDomain, principal.getName())
            .expirationWindow(userTokenTimeout).keyId(privateKeyId).host(serverHostName)
            .ip(ServletRequestUtil.getRemoteAddress(ctx.request())).authorizedServices(services).build();
        
        token.sign(privateKey);
        UserToken userToken = new UserToken().setToken(token.getSignedToken());
        
        if (header == Boolean.TRUE && principalAuthority != null) {
            userToken.setHeader(principalAuthority.getHeader());
        }
        
        // set our standard CORS headers in our response if we're processing
        // a get user token for an authorized service
        
        if (services != null)  {
            setStandardCORSHeaders(ctx);
        }

        metric.stopTiming(timerMetric);
        return userToken;
    }

    public UserToken optionsUserToken(ResourceContext ctx, String userName, String authorizedServices) {

        final String caller = "optionsusertoken";
        metric.increment(ZMSConsts.HTTP_OPTIONS);
        metric.increment(ZMSConsts.HTTP_REQUEST);
        metric.increment(caller);
        Object timerMetric = metric.startTiming("optionsusertoken_timing", null);
        
        validateRequest(ctx.request(), caller);

        // if the user must be requesting authorized service token
        
        if (authorizedServices == null || authorizedServices.isEmpty()) {
            throw ZMSUtils.requestError("optionsUserToken: No authorized services specified in the request", caller);
        }
        
        // verify that all specified services are valid
        
        String[] services = authorizedServices.split(",");
        for (String service : services) {
            if (!serverAuthorizedServices.contains(service)) {
                throw ZMSUtils.requestError("optionsUserToken: Service " + service + " is not authorized in ZMS", caller);
            }
        }
        
        // set our standard CORS headers in our response
        
        setStandardCORSHeaders(ctx);
        
        // since this is the preflight request we are going to report that
        // we only allow GET method and configure the user-agent to cache
        // this request results for up-to 30 days
        
        ctx.response().addHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_METHODS, ZMSConsts.HTTP_GET);
        ctx.response().addHeader(ZMSConsts.HTTP_ACCESS_CONTROL_MAX_AGE, "2592000");
        
        metric.stopTiming(timerMetric);
        return null;
    }

    boolean isValidCORSOrigin(final String origin) {

        // first check for non-empty origin value

        if (origin == null || origin.isEmpty()) {
            return false;
        }

        // check if we have whitelist configured

        if (corsOriginList == null || corsOriginList.isEmpty()) {
            return true;
        }

        return corsOriginList.contains(origin);
    }

    void setStandardCORSHeaders(ResourceContext ctx) {

        // if we get an Origin header in our request then we're going to return
        // the same value in the Allow-Origin header
        
        String origin = ctx.request().getHeader(ZMSConsts.HTTP_ORIGIN);
        if (isValidCORSOrigin(origin)) {
            ctx.response().addHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        }
        
        // we must allow credentials to be passed by the client
        
        ctx.response().addHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
        
        // if the client is asking us to allow any headers then we're going
        // to return that set back as allowed
        
        String allowHeaders = ctx.request().getHeader(ZMSConsts.HTTP_ACCESS_CONTROL_REQUEST_HEADERS);
        if (allowHeaders != null && !allowHeaders.isEmpty()) {
            ctx.response().addHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_HEADERS, allowHeaders);
        }
    }

    String providerServiceDomain(String provider) {
        int n = provider.lastIndexOf('.');
        if (n <= 0 || n == provider.length() - 1) {
            return null;
        }
        return provider.substring(0, n);
    }
    
    String providerServiceName(String provider) {
        int n = provider.lastIndexOf('.');
        if (n <= 0 || n == provider.length() - 1) {
            return null;
        }
        return provider.substring(n + 1);
    }

    @Override
    public void putTenancy(ResourceContext ctx, String tenantDomain, String provider,
            String auditRef, Tenancy detail) {

        final String caller = "puttenancy";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(tenantDomain, TYPE_DOMAIN_NAME, caller);
        validate(provider, TYPE_SERVICE_NAME, caller); //the fully qualified service name to provision on

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        tenantDomain = tenantDomain.toLowerCase();
        provider = provider.toLowerCase();
        AthenzObject.TENANCY.convertToLowerCase(detail);

        // validate our detail object against uri components

        if (!validateTenancyObject(detail, tenantDomain, provider)) {
            throw ZMSUtils.requestError("Invalid tenancy object", caller);
        }

        metric.increment(ZMSConsts.HTTP_REQUEST, tenantDomain);
        metric.increment(caller, tenantDomain);
        Object timerMetric = metric.startTiming("puttenancy_timing", tenantDomain);

        // verify that request is properly authenticated for this request
        
        String authorizedService = ((RsrcCtxWrapper) ctx).principal().getAuthorizedService();
        verifyAuthorizedServiceOperation(authorizedService, caller);

        String provSvcDomain = providerServiceDomain(provider); // provider service domain
        String provSvcName = providerServiceName(provider); // provider service name

        // we can't have the provider and tenant be in the same domain
        // as we don't allow delegation of roles onto themselves

        if (provSvcDomain.equals(tenantDomain)) {
            throw ZMSUtils.requestError("Provider and tenant domains cannot be the same", caller);
        }

        if (dbService.getServiceIdentity(provSvcDomain, provSvcName) == null) {
            throw ZMSUtils.notFoundError("Unable to retrieve service=" + provider, caller);
        }

        // we are going to allow the authorize service token owner to call
        // put tenancy on its own service

        boolean authzServiceTokenOperation = isAuthorizedProviderService(authorizedService,
                provSvcDomain, provSvcName);

        if (authorizedService != null && !authzServiceTokenOperation) {
            throw ZMSUtils.requestError("Authorized service provider mismatch: "
                    + provider + "/" + authorizedService, caller);
        }

        // set up our tenant admin policy so provider can check admin's access
        
        dbService.setupTenantAdminPolicy(tenantDomain, provSvcDomain,
                provSvcName, auditRef, caller);
        
        // if this is an authorized service token request then we're going to create
        // the corresponding admin role in the provider domain since that's been
        // authenticated already
        
        if (authzServiceTokenOperation) {
            setupTenantAdminPolicyInProvider(ctx, provSvcDomain, provSvcName, tenantDomain,
                    auditRef, caller);
        }

        metric.stopTiming(timerMetric);
    }

    @Override
    public void deleteTenancy(ResourceContext ctx, String tenantDomain, String provider, String auditRef) {
        
        final String caller = "deletetenancy";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(tenantDomain, TYPE_DOMAIN_NAME, caller);
        validate(provider, TYPE_SERVICE_NAME, caller); // fully qualified provider's service name

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        tenantDomain = tenantDomain.toLowerCase();
        provider = provider.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, tenantDomain);
        metric.increment(caller, tenantDomain);
        Object timerMetric = metric.startTiming("deletetenancy_timing", tenantDomain);

        // verify that request is properly authenticated for this request
        
        String authorizedService = ((RsrcCtxWrapper) ctx).principal().getAuthorizedService();
        verifyAuthorizedServiceOperation(authorizedService, caller);

        // make sure we have a valid provider service
        
        String provSvcDomain = providerServiceDomain(provider);
        String provSvcName   = providerServiceName(provider);

        if (dbService.getServiceIdentity(provSvcDomain, provSvcName) == null) {
            throw ZMSUtils.notFoundError("Unable to retrieve service: " + provider, caller);
        }

        // we are going to allow the authorize service token owner to call
        // delete tenancy on its own service without configuring a controller
        // end point
        
        boolean authzServiceTokenOperation = isAuthorizedProviderService(authorizedService,
            provSvcDomain, provSvcName);
        
        if (authzServiceTokenOperation) {
            dbService.executeDeleteTenantRoles(ctx, provSvcDomain, provSvcName, tenantDomain, null,
                auditRef, caller);
        }

        // now clean-up local domain roles and policies for this tenant
        
        dbService.executeDeleteTenancy(ctx, tenantDomain, provSvcDomain, provSvcName,
                null, auditRef, caller);

        metric.stopTiming(timerMetric);
    }

    @Override
    public void putTenant(ResourceContext ctx, String providerDomain, String providerService,
           String tenantDomain, String auditRef, Tenancy detail) {

        final String caller = "puttenant";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(providerDomain, TYPE_DOMAIN_NAME, caller);
        validate(providerService, TYPE_SIMPLE_NAME, caller);
        validate(tenantDomain, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        providerDomain = providerDomain.toLowerCase();
        providerService = providerService.toLowerCase();
        tenantDomain = tenantDomain.toLowerCase();
        AthenzObject.TENANCY.convertToLowerCase(detail);

        // we can't have the provider and tenant be in the same domain
        // as we don't allow delegation of roles onto themselves

        if (providerDomain.equals(tenantDomain)) {
            throw ZMSUtils.requestError("Provider and tenant domains cannot be the same", caller);
        }

        // validate our detail object against uri components

        if (!validateTenancyObject(detail, tenantDomain, providerDomain + "." + providerService)) {
            throw ZMSUtils.requestError("Invalid tenancy object", caller);
        }

        metric.increment(ZMSConsts.HTTP_REQUEST, providerDomain);
        metric.increment(caller, providerDomain);
        Object timerMetric = metric.startTiming("puttenant_timing", providerDomain);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        if (dbService.getServiceIdentity(providerDomain, providerService) == null) {
            throw ZMSUtils.notFoundError("Unable to retrieve service=" + providerService, caller);
        }

        setupTenantAdminPolicyInProvider(ctx, providerDomain, providerService, tenantDomain,
                auditRef, caller);

        metric.stopTiming(timerMetric);
    }

    @Override
    public void deleteTenant(ResourceContext ctx, String providerDomain, String providerService,
            String tenantDomain, String auditRef) {

        final String caller = "deletetenant";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(providerDomain, TYPE_DOMAIN_NAME, caller);
        validate(providerService, TYPE_SIMPLE_NAME, caller);
        validate(tenantDomain, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        providerDomain = providerDomain.toLowerCase();
        providerService = providerService.toLowerCase();
        tenantDomain = tenantDomain.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, providerDomain);
        metric.increment(caller, providerDomain);
        Object timerMetric = metric.startTiming("deletetenant_timing", providerDomain);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        if (dbService.getServiceIdentity(providerDomain, providerService) == null) {
            throw ZMSUtils.notFoundError("Unable to retrieve service=" + providerService, caller);
        }

        dbService.executeDeleteTenantRoles(ctx, providerDomain, providerService, tenantDomain,
                null, auditRef, caller);

        metric.stopTiming(timerMetric);
    }

    boolean validateTenancyObject(Tenancy tenant, final String tenantDomain, final String providerService) {

        if (!tenant.getDomain().equals(tenantDomain)) {
            return false;
        }
        return tenant.getService().equals(providerService);
    }

    boolean validateTenantResourceGroupRolesObject(TenantResourceGroupRoles roles, final String providerDomain,
            final String providerService, final String tenantDomain, final String resourceGroup) {

        if (!providerDomain.equals(roles.getDomain())) {
            return false;
        }
        if (!providerService.equals(roles.getService())) {
            return false;
        }
        if (!tenantDomain.equals(roles.getTenant())) {
            return false;
        }
        if (!resourceGroup.equals(roles.getResourceGroup())) {
            return false;
        }

        // we must have at least one role in the object

        List<TenantRoleAction> list = roles.getRoles();
        return (list != null && list.size() > 0);
    }

    boolean validateProviderResourceGroupRolesObject(ProviderResourceGroupRoles roles, final String providerDomain,
            final String providerService, final String tenantDomain, final String resourceGroup) {

        if (!providerDomain.equals(roles.getDomain())) {
            return false;
        }
        if (!providerService.equals(roles.getService())) {
            return false;
        }
        if (!tenantDomain.equals(roles.getTenant())) {
            return false;
        }
        if (!resourceGroup.equals(roles.getResourceGroup())) {
            return false;
        }

        // we must have at least one role in the object

        List<TenantRoleAction> list = roles.getRoles();
        return (list != null && list.size() > 0);
    }

    // put the trust roles into provider domain
    //
    @Override
    public TenantResourceGroupRoles putTenantResourceGroupRoles(ResourceContext ctx, String provSvcDomain,
            String provSvcName, String tenantDomain, String resourceGroup, String auditRef,
            TenantResourceGroupRoles detail) {

        final String caller = "puttenantresourcegrouproles";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(provSvcDomain, TYPE_DOMAIN_NAME, caller);
        validate(provSvcName, TYPE_SIMPLE_NAME, caller); //not including the domain, this is the domain's service
        validate(tenantDomain, TYPE_DOMAIN_NAME, caller);
        validate(detail, TYPE_TENANT_RESOURCE_GROUP_ROLES, caller);
        validate(resourceGroup, TYPE_COMPOUND_NAME, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        provSvcDomain = provSvcDomain.toLowerCase();
        provSvcName = provSvcName.toLowerCase();
        tenantDomain = tenantDomain.toLowerCase();
        resourceGroup = resourceGroup.toLowerCase();
        AthenzObject.TENANT_RESOURCE_GROUP_ROLES.convertToLowerCase(detail);

        // we can't have the provider and tenant be in the same domain
        // as we don't allow delegation of roles onto themselves

        if (provSvcDomain.equals(tenantDomain)) {
            throw ZMSUtils.requestError("Provider and tenant domains cannot be the same", caller);
        }

        // validate our detail object against uri components

        if (!validateTenantResourceGroupRolesObject(detail, provSvcDomain, provSvcName, tenantDomain,
                resourceGroup)) {
            throw ZMSUtils.requestError("Invalid tenant resource group role object", caller);
        }

        metric.increment(ZMSConsts.HTTP_REQUEST, provSvcDomain);
        metric.increment(caller, provSvcDomain);
        Object timerMetric = metric.startTiming("puttenantresourcegrouproles_timing", provSvcDomain);
        
        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        if (LOG.isInfoEnabled()) {
            LOG.info("putTenantResourceGroupRoles: ==== putTenantRoles(domain=" + provSvcDomain + ", service=" +
                provSvcName + ", tenant-domain=" + tenantDomain + ", resource-group=" + resourceGroup +
                ", detail=" + detail + ")");
        }

        // first setup the domain as a tenant in the provider domain

        setupTenantAdminPolicyInProvider(ctx, provSvcDomain, provSvcName, tenantDomain,
                auditRef, caller);

        // then setup the requested resource group roles

        dbService.executePutTenantRoles(ctx, provSvcDomain, provSvcName, tenantDomain,
                resourceGroup, detail.getRoles(), auditRef, caller);
        metric.stopTiming(timerMetric);
        return detail;
    }

    @SuppressWarnings("ConstantConditions")
    public DomainDataCheck getDomainDataCheck(ResourceContext ctx, String domainName) {
        
        final String caller = "getdomaindatacheck";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        
        domainName = domainName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getdomaindatacheck_timing", domainName);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("getDomainDataCheck: domain=" + domainName);
        }

        AthenzDomain domain = getAthenzDomain(domainName, false);
        if (domain == null) {
            throw ZMSUtils.notFoundError("getDomainDataCheck: Domain not found: '" + domainName + "'", caller);
        }

        // build set of roles
        // iterate them to look for trust roles - in case this is a provider domain
        
        Set<String> roleSet      = new HashSet<>();
        Set<String> trustRoleSet = new HashSet<>();

        // map per trust/tenant domain that contains the trust roles
        
        Map<String, Set<String>> trustRoleMap = new HashMap<>();
        for (Role role : domain.getRoles()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("getDomainDataCheck: processing role - " + role.getName());
            }
            roleSet.add(role.getName());
            String roleName = ZMSUtils.removeDomainPrefix(role.getName(), domainName, ROLE_PREFIX);
            String trustDomain = role.getTrust();
            if (trustDomain != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("trust role for domain: " + trustDomain);
                }
                trustRoleSet.add(trustDomain);
                Set<String> tset = trustRoleMap.computeIfAbsent(trustDomain, k -> new HashSet<>());
                tset.add(roleName);
            }
        }

        // look for dangling roles and policies
        //
        int assertionCount = 0;
        int roleWildcardCount = 0;
        Set<String> usedRoleSet = new HashSet<>(); // keep track of roles used by policies
        Set<String> providerSet = new HashSet<>(); // keep track of providers from assume_role policies

        // assume_role resources are placed into the set per provider service domain
        
        Map<String, Set<String>> svcRoleMap = new HashMap<>();
        List<DanglingPolicy> danglingPolicies = new ArrayList<>();
        List<Policy> policies = domain.getPolicies();
        for (Policy policy : policies) {
            String pname = ZMSUtils.removeDomainPrefix(policy.getName(), domainName, POLICY_PREFIX);
            if (LOG.isDebugEnabled()) {
                LOG.debug("getDomainDataCheck: processing policy=" + pname + " in domain=" + domainName);
            }

            List<Assertion> assertions = policy.getAssertions();
            if (assertions == null) {
                continue;
            }
            
            for (Assertion assertion : assertions) {
                assertionCount++;
                if (ZMSConsts.ACTION_ASSUME_ROLE.equalsIgnoreCase(assertion.getAction())) {
                    // get provider domain+service name and add to set of providers
                    // Note there may be a resource appended - to be dealt with later
                    // ex: testgetdomaindatacheck:policy.tenancy.testgetdomaindatacheckprovider.storage.reader
                    // ex: testgetdomaindatacheck:policy.tenancy.testgetdomaindatacheckprovider.sub.storage.res_group.ravers.reader
                    // index after "tenancy." and index of last dot
                    int index = pname.indexOf("tenancy.");
                    if (index == -1) {
                        continue;
                    }
                    int lindex = pname.lastIndexOf('.');
                    if (lindex == -1) {
                        continue;
                    }
                    String provSvcDomain = pname.substring(index + "tenancy.".length(), lindex);
                    providerSet.add(provSvcDomain);

                    // lets collect the resource field that is name of role in provider
                    // ex: testgetdomaindatacheckprovider.sub:role.storage.tenant.testgetdomaindatacheck.reader
                    // ex: testgetdomaindatacheckprovider.sub:role.storage.tenant.testgetdomaindatacheck.res_group.ravers.reader
                    String rsrc = assertion.getResource();
                    Set<String> rset = svcRoleMap.computeIfAbsent(provSvcDomain, k -> new HashSet<>());
                    rset.add(rsrc);
                }

                String roleName = assertion.getRole();

                // check for wildcard role
                if (roleName.lastIndexOf('*') != -1) {
                    roleWildcardCount++;
                    // make sure there is at least 1 role that can match
                    // this wildcard - else its a dangling policy
                    String rolePattern = StringUtils.patternFromGlob(roleName);
                    boolean wildCardMatch = false;
                    for (String role: roleSet) {
                        if (role.matches(rolePattern)) {
                            wildCardMatch = true;
                            break;
                        }
                    }
                    if (!wildCardMatch) { // dangling policy
                        DanglingPolicy dp = new DanglingPolicy();
                        // we need to remove the domain:role. and domain:policy prefixes
                        // according to RDL definitions for role and policy names
                        dp.setRoleName(ZMSUtils.removeDomainPrefix(roleName, domainName, ROLE_PREFIX));
                        dp.setPolicyName(ZMSUtils.removeDomainPrefix(pname, domainName, POLICY_PREFIX));
                        danglingPolicies.add(dp);
                    }
                } else if (roleSet.contains(roleName)) {
                    usedRoleSet.add(roleName);
                } else { // dangling policy
                    DanglingPolicy dp = new DanglingPolicy();
                    // we need to remove the domain:role. and domain:policy prefixes
                    // according to RDL definitions for role and policy names
                    dp.setRoleName(ZMSUtils.removeDomainPrefix(roleName, domainName, ROLE_PREFIX));
                    dp.setPolicyName(ZMSUtils.removeDomainPrefix(pname, domainName, POLICY_PREFIX));
                    danglingPolicies.add(dp);
                }
            }
        }

        DomainDataCheck ddc = new DomainDataCheck();
        ddc.setPolicyCount(policies.size());
        ddc.setAssertionCount(assertionCount);
        ddc.setRoleWildCardCount(roleWildcardCount);
        if (!danglingPolicies.isEmpty()) {
            ddc.setDanglingPolicies(danglingPolicies);
        }

        if (roleSet.size() != usedRoleSet.size()) {
            // oh oh, some roles are unused - need to subtract the usedRoleSet
            // from roleSet - the leftovers are the unused roles
            roleSet.removeAll(usedRoleSet);
            // we need to remove the domain:role. prefix according to
            // RDL definition for dangling role names
            List<String> danglingRoleList = new ArrayList<>();
            for (String roleName : roleSet) {
                danglingRoleList.add(ZMSUtils.removeDomainPrefix(roleName, domainName, ROLE_PREFIX));
            }
            ddc.setDanglingRoles(danglingRoleList);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("getDomainDataCheck: domain=" + domainName +
                " policy-count=" + policies.size() + " assertion-count=" +
                assertionCount + " wildcard-count==" + roleWildcardCount +
                " dangling-policies=" + danglingPolicies.size() +
                " dangling-roles=" + roleSet.size());
        }

        // Tenant Domain Check: does each provider fully support this tenant?
        // collect Service names (domain.service) for domains that don't contain
        // trust role
        List<String> provsWithoutTrust = new ArrayList<>();
        for (String provSvc : providerSet) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("getDomainDataCheck: domain=" + domainName +
                    " provider-service=" + provSvc);
            }

            // 2 cases to resolve, one with resource group, one without
            // ex: iaas.stuff.storage.read
            // ex: iaas.stuff.storage.res_group.my_resource_group.read
            
            int idx = provSvc.indexOf(".res_group.");
            String provSvcDomain;
            if (idx == -1) {
                provSvcDomain = providerServiceDomain(provSvc);
            } else {
                provSvcDomain = providerServiceDomain(provSvc.substring(0, idx));
            }
            
            AthenzDomain providerDomain = getAthenzDomain(provSvcDomain, true);
            Set<String> rset = svcRoleMap.get(provSvc);
            if (rset == null || rset.isEmpty() || providerDomain == null) {
                provsWithoutTrust.add(provSvc);
                continue;
            }
            
            // find trust role in the provider that contains the tenant domain
            int foundTrust = 0;
            for (Role role : providerDomain.getRoles()) {
                String trustDomain = role.getTrust();
                if (trustDomain != null) {
                    if (domainName.equals(trustDomain)) {
                        // is this role a match for an assume role in the tenant
                        // look for the role in the role set for this service
                        if (rset.contains(role.getName())) {
                            foundTrust++;
                        }
                    }
                }
            }
            if (foundTrust != rset.size()) {
                provsWithoutTrust.add(provSvc);
            }
        }
        if (!provsWithoutTrust.isEmpty()) {
            ddc.setProvidersWithoutTrust(provsWithoutTrust);
        }

        // Provider Domain Check: does each tenant have all the assume_role
        // assertions to match each trust role.

        // tenantsWithoutProv: names of Tenant domains that don't contain assume
        // role assertions if this is a provider domain
        List<String> tenantsWithoutProv = new ArrayList<>();

        // tenantDomMap: optimize reading tenant domains once already read
        // This is optimizing for Providers with lots of tenants.
        Map<String, AthenzDomain> tenantDomMap = new HashMap<>();
        for (String trustRole: trustRoleSet) {
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("getDomainDataCheck: processing trust role: " + trustRole);
            }
            
            AthenzDomain tenantDomain = tenantDomMap.get(trustRole);
            if (tenantDomain == null) {
                tenantDomain = getAthenzDomain(trustRole, true);
                if (tenantDomain == null) {
                    tenantsWithoutProv.add(trustRole);
                    continue;
                } else {
                    tenantDomMap.put(trustRole, tenantDomain);
                }
            }

            // Get set of providers trust roles for trust/tenant domain.
            Set<String> tset = trustRoleMap.get(trustRole);
            if (tset == null || tset.isEmpty()) {
                tenantsWithoutProv.add(trustRole);
                continue;
            }

            int foundProviderCnt = 0;

            // Check for assume_role containing the provider in the tenantDomain
            for (Policy policy : tenantDomain.getPolicies()) {
                List<Assertion> assertions = policy.getAssertions();
                if (assertions == null) {
                    continue;
                }
                for (Assertion assertion : assertions) {
                    if (ZMSConsts.ACTION_ASSUME_ROLE.equalsIgnoreCase(assertion.getAction())) {
                        String rsrc = assertion.getResource();
                        // If the provider domain contains a role that matches
                        // the tenant domain resource - then the tenant is supported
                        if (roleSet.contains(rsrc)) {
                            // HAVE: an assume_role with resource pointing at the provider
                            foundProviderCnt++;
                        }
                    }
                }
            }
            if (foundProviderCnt < tset.size()) {
                // didn't find all required matching provider trust-role to assume_role-resource pairs
                tenantsWithoutProv.add(trustRole);
            }
        }
        if (!tenantsWithoutProv.isEmpty()) {
            ddc.setTenantsWithoutAssumeRole(tenantsWithoutProv);
        }

        metric.stopTiming(timerMetric);
        return ddc;
    }
     
    public void deleteProviderResourceGroupRoles(ResourceContext ctx, String tenantDomain,
             String provSvcDomain, String provSvcName, String resourceGroup, String auditRef) {
         
        final String caller = "deleteproviderresourcegrouproles";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }
        
        validateRequest(ctx.request(), caller);

        validate(provSvcDomain, TYPE_DOMAIN_NAME, caller);
        validate(provSvcName, TYPE_SIMPLE_NAME, caller);
        validate(tenantDomain, TYPE_DOMAIN_NAME, caller);
        validate(resourceGroup, TYPE_COMPOUND_NAME, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        provSvcDomain = provSvcDomain.toLowerCase();
        provSvcName = provSvcName.toLowerCase();
        tenantDomain = tenantDomain.toLowerCase();
        resourceGroup = resourceGroup.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, provSvcDomain);
        metric.increment(caller, provSvcDomain);
        Object timerMetric = metric.startTiming("deleteproviderresourcegrouproles_timing", provSvcDomain);
        
        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        // first clean-up local domain roles and policies for this tenant
        
        dbService.executeDeleteTenancy(ctx, tenantDomain, provSvcDomain, provSvcName,
             resourceGroup, auditRef, caller);

        // at this point the tenant side is complete. If the token was a chained
        // token signed by the provider service then we're going to process the
        // provider side as well thus complete the tenancy delete process
        
        String authorizedService = ((RsrcCtxWrapper) ctx).principal().getAuthorizedService();
        if (isAuthorizedProviderService(authorizedService, provSvcDomain, provSvcName)) {
         
            dbService.executeDeleteTenantRoles(ctx, provSvcDomain, provSvcName, tenantDomain,
                resourceGroup, auditRef, caller);
        }

        metric.stopTiming(timerMetric);
    }

    public ProviderResourceGroupRoles getProviderResourceGroupRoles(ResourceContext ctx, String tenantDomain,
            String provSvcDomain, String provSvcName, String resourceGroup) {

        final String caller = "getproviderresourcegrouproles";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(provSvcDomain, TYPE_DOMAIN_NAME, caller);
        validate(provSvcName, TYPE_SIMPLE_NAME, caller);
        validate(tenantDomain, TYPE_DOMAIN_NAME, caller);
        validate(resourceGroup, TYPE_COMPOUND_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        provSvcDomain = provSvcDomain.toLowerCase();
        provSvcName = provSvcName.toLowerCase();
        tenantDomain = tenantDomain.toLowerCase();
        resourceGroup = resourceGroup.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, provSvcDomain);
        metric.increment(caller, provSvcDomain);
        Object timerMetric = metric.startTiming("getproviderresourcegrouproles_timing", provSvcDomain);

        if (dbService.getDomain(tenantDomain, false) == null) {
            throw ZMSUtils.notFoundError("No such domain: " + tenantDomain, caller);
        }

        // look for this provider roles, ex: storage.tenant.sports.reader

        String rolePrefix = ZMSUtils.getProviderResourceGroupRolePrefix(provSvcDomain, provSvcName, resourceGroup);
        ProviderResourceGroupRoles provRoles = new ProviderResourceGroupRoles().setDomain(provSvcDomain)
                .setService(provSvcName).setTenant(tenantDomain).setResourceGroup(resourceGroup);

        List<TenantRoleAction> tralist = new ArrayList<>();

        // find roles matching the prefix

        List<String> rcollection = dbService.listRoles(tenantDomain);
        for (String rname: rcollection) {

            if (dbService.isTenantRolePrefixMatch(rname, rolePrefix, resourceGroup, null)) {

                // for provider roles we don't have the action, that's
                // for the provider domain only so we're just going
                // to return the list of roles without any actions
                // for the role name we must return the SimpleName
                // part only so we'll remove the prefix section

                TenantRoleAction tra = new TenantRoleAction()
                        .setRole(rname.substring(rolePrefix.length()))
                        .setAction("n/a");
                tralist.add(tra);
            }
        }
        provRoles.setRoles(tralist);

        metric.stopTiming(timerMetric);
        return provRoles;
    }
     
    boolean isAuthorizedProviderService(String authorizedService, String provSvcDomain,
             String provSvcName) {
        
         // make sure we have a service provided and it matches to our provider
         
         if (authorizedService == null) {
             return false;
         }
         
         if (!authorizedService.equals(provSvcDomain + "." + provSvcName)) {
             return false;
         }
         
         // verify that provider service does indeed have access to provision
         // its own tenants. the authorize statement for the putTenantRole
         // command is defined in the RDL as:
         // authorize ("UPDATE", "{domain}:tenant.{service}");

         AthenzDomain domain = getAthenzDomain(provSvcDomain, true);
         if (domain == null) {
             return false;
         }
         
         // evaluate our domain's roles and policies to see if access
         // is allowed or not for the given operation and resource
         
         String resource = provSvcDomain + ":tenant." + provSvcName;
         AccessStatus accessStatus = evaluateAccess(domain, authorizedService, "update",
                 resource, null, null);

        return accessStatus == AccessStatus.ALLOWED;
    }
     
    /**
     * This sets up the assume roles in the tenant. If the tenants admin user
     * token has been authorized by the provider, the providers domain will be
     * updated as well, thus completing the tenancy on-boarding in a single step.
    **/
    @Override
    public ProviderResourceGroupRoles putProviderResourceGroupRoles(ResourceContext ctx, String tenantDomain,
             String provSvcDomain, String provSvcName, String resourceGroup, String auditRef,
             ProviderResourceGroupRoles detail) {

        final String caller = "putproviderresourcegrouproles";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(provSvcDomain, TYPE_DOMAIN_NAME, caller);
        validate(provSvcName, TYPE_SIMPLE_NAME, caller); //not including the domain, this is the domain's service
        validate(tenantDomain, TYPE_DOMAIN_NAME, caller);
        validate(detail, TYPE_PROVIDER_RESOURCE_GROUP_ROLES, caller);
        validate(resourceGroup, TYPE_COMPOUND_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        provSvcDomain = provSvcDomain.toLowerCase();
        provSvcName = provSvcName.toLowerCase();
        tenantDomain = tenantDomain.toLowerCase();
        resourceGroup = resourceGroup.toLowerCase();
        AthenzObject.PROVIDER_RESOURCE_GROUP_ROLES.convertToLowerCase(detail);

        // we can't have the provider and tenant be in the same domain
        // as we don't allow delegation of roles onto themselves

        if (provSvcDomain.equals(tenantDomain)) {
            throw ZMSUtils.requestError("Provider and tenant domains cannot be the same", caller);
        }

        // validate our detail object against uri components

        if (!validateProviderResourceGroupRolesObject(detail, provSvcDomain, provSvcName, tenantDomain,
                resourceGroup)) {
            throw ZMSUtils.requestError("Invalid provider resource group role object", caller);
        }

        metric.increment(ZMSConsts.HTTP_REQUEST, provSvcDomain);
        metric.increment(caller, provSvcDomain);
        Object timerMetric = metric.startTiming("putproviderresourcegrouproles_timing", provSvcDomain);
        
        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        if (LOG.isInfoEnabled()) {
            LOG.info("putProviderResourceGroupRoles: domain=" + provSvcDomain + ", service=" +
                provSvcName + ", tenant-domain=" + tenantDomain + ", resource-group=" + resourceGroup +
                ", detail=" + detail);
        }
        
        // set up our tenant admin policy so provider can check admin's access
        
        dbService.setupTenantAdminPolicy(tenantDomain, provSvcDomain, provSvcName, auditRef, caller);
        
        // now we're going to setup our roles
        
        List<TenantRoleAction> roleActions = detail.getRoles();
        List<String> roles = new ArrayList<>();
        for (TenantRoleAction roleAction : roleActions) {
            roles.add(roleAction.getRole());
        }
        
        // we're going to create a separate role for each one of tenant roles returned
        // based on its action and set the caller as a member in each role
        
        dbService.executePutProviderRoles(ctx, tenantDomain, provSvcDomain, provSvcName, resourceGroup,
            roles, auditRef, caller);
        
        // at this point the tenant side is complete. If the token was a chained
        // token signed by the provider service then we're going to process the
        // provider side as well thus complete the tenancy on-boarding process
        
        String authorizedService = ((RsrcCtxWrapper) ctx).principal().getAuthorizedService();
        if (isAuthorizedProviderService(authorizedService, provSvcDomain, provSvcName)) {

            // first we need to setup the admin roles in case this
            // happens to be the first resource group

            setupTenantAdminPolicyInProvider(ctx, provSvcDomain, provSvcName, tenantDomain,
                    auditRef, caller);

            // now onboard the requested resource group

            dbService.executePutTenantRoles(ctx, provSvcDomain, provSvcName, tenantDomain,
                    resourceGroup, roleActions, auditRef, caller);
        }

        metric.stopTiming(timerMetric);
        return detail;
    }

    void setupTenantAdminPolicyInProvider(ResourceContext ctx, final String provSvcDomain,
            final String provSvcName, final String tenantDomain, final String auditRef,
            final String caller) {

        List<TenantRoleAction> roles = new ArrayList<>();
        TenantRoleAction roleAction = new TenantRoleAction().setAction("*").setRole(ADMIN_ROLE_NAME);
        roles.add(roleAction);
        dbService.executePutTenantRoles(ctx, provSvcDomain, provSvcName, tenantDomain, null,
                roles, auditRef, caller);
    }

    String getProviderRoleAction(String provSvcDomain, String roleName) {
        
        // if no match then we're going to default action of empty string
        
        Policy policy = dbService.getPolicy(provSvcDomain, roleName); // policy has same name
        if (policy == null) {
            return "";
        }
        
        List<Assertion> assertions = policy.getAssertions();
        if (assertions == null) {
            return "";
        }

        for (Assertion assertion : assertions) {
            if (!assertion.getRole().endsWith(roleName)) {
                continue;
            }
            
            return assertion.getAction();
        }
        
        return "";
    }
    
    public TenantResourceGroupRoles getTenantResourceGroupRoles(ResourceContext ctx, String provSvcDomain,
            String provSvcName, String tenantDomain, String resourceGroup) {
        
        final String caller = "gettenantresourcegrouproles";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(provSvcDomain, TYPE_DOMAIN_NAME, caller);
        validate(provSvcName, TYPE_SIMPLE_NAME, caller); // not including the domain, this is the domain's service type
        validate(tenantDomain, TYPE_DOMAIN_NAME, caller);
        validate(resourceGroup, TYPE_COMPOUND_NAME, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        provSvcDomain = provSvcDomain.toLowerCase();
        provSvcName = provSvcName.toLowerCase();
        tenantDomain = tenantDomain.toLowerCase();
        resourceGroup = resourceGroup.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, provSvcDomain);
        metric.increment(caller, provSvcDomain);
        Object timerMetric = metric.startTiming("gettenantresourcegrouproles_timing", provSvcDomain);

        if (dbService.getDomain(provSvcDomain, false) == null) {
            throw ZMSUtils.notFoundError("getTenantResourceGroupRoles: No such domain: " + provSvcDomain, caller);
        }

        // look for this tenants roles, ex: storage.tenant.sports.reader

        String rolePrefix = ZMSUtils.getTenantResourceGroupRolePrefix(provSvcName, tenantDomain, resourceGroup);
        TenantResourceGroupRoles troles = new TenantResourceGroupRoles().setDomain(provSvcDomain)
                .setService(provSvcName).setTenant(tenantDomain).setResourceGroup(resourceGroup);

        List<TenantRoleAction> tralist = new ArrayList<>();
        
        // find roles matching the prefix
        
        List<String> rcollection = dbService.listRoles(provSvcDomain);
        for (String rname: rcollection) {
            if (dbService.isTrustRoleForTenant(provSvcDomain, rname, rolePrefix, resourceGroup, tenantDomain)) {
                
                // good, its exactly what we are looking for, but
                // now we want the ACTION that was set in the provider
                
                String action = getProviderRoleAction(provSvcDomain, rname);
                
                // for the role name we must return the SimpleName
                // part only so we'll remove the prefix section
                
                TenantRoleAction tra = new TenantRoleAction()
                        .setRole(rname.substring(rolePrefix.length()))
                        .setAction(action);
                tralist.add(tra);
            }
        }
        troles.setRoles(tralist);

        metric.stopTiming(timerMetric);
        return troles;
    }

    public void deleteTenantResourceGroupRoles(ResourceContext ctx, String provSvcDomain,
            String provSvcName, String tenantDomain, String resourceGroup, String auditRef) {
        
        final String caller = "deletetenantresourcegrouproles";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(provSvcDomain, TYPE_DOMAIN_NAME, caller);
        validate(provSvcName, TYPE_SIMPLE_NAME, caller); // not including the domain, this is the domain's service type
        validate(tenantDomain, TYPE_DOMAIN_NAME, caller);
        validate(resourceGroup, TYPE_COMPOUND_NAME, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        provSvcDomain = provSvcDomain.toLowerCase();
        provSvcName = provSvcName.toLowerCase();
        tenantDomain = tenantDomain.toLowerCase();
        resourceGroup = resourceGroup.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, provSvcDomain);
        metric.increment(caller, provSvcDomain);
        Object timerMetric = metric.startTiming("deletetenantresourcegrouproles_timing", provSvcDomain);

        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        dbService.executeDeleteTenantRoles(ctx, provSvcDomain, provSvcName, tenantDomain,
                resourceGroup, auditRef, caller);
        metric.stopTiming(timerMetric);
    }
    
    String extractDomainName(String resource) {
        int idx;
        if ((idx = resource.indexOf(':')) == -1) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("extractDomainName: missing domain name: " + resource);
            }
            return null;
        }
        return resource.substring(0, idx);
    }

    void validateRequest(HttpServletRequest request, String caller) {
        validateRequest(request, caller, false);
    }
    
    void validateRequest(HttpServletRequest request, String caller, boolean statusRequest) {
        
        // first validate if we're required process this over TLS only
        
        if (secureRequestsOnly && !request.isSecure()) {
            throw ZMSUtils.requestError(caller + "request must be over TLS", caller);
        }
        
        // second check if this is a status port so we can only
        // process on status requests
        
        if (statusPort > 0 && statusPort != httpPort && statusPort != httpsPort) {
            
            // non status requests must not take place on the status port
            
            if (!statusRequest && request.getLocalPort() == statusPort) {
                throw ZMSUtils.requestError("incorrect port number for a non-status request", caller);
            }
            
            // status requests must not take place on a non-status port
            
            if (statusRequest && request.getLocalPort() != statusPort) {
                throw ZMSUtils.requestError("incorrect port number for a status request", caller);
            }
        }
    }
    
    void validate(Object val, String type, String caller) {
        if (val == null) {
            throw ZMSUtils.requestError("Missing or malformed " + type, caller);
        }
        
        Result result = validator.validate(val, type);
        if (!result.valid) {
            throw ZMSUtils.requestError("Invalid " + type  + " error: " + result.error, caller);
        }
    }
    
    List<String> validatedAdminUsers(List<String> lst) {
        
        final String caller = "validatedadminusers";
        
        if (lst == null || lst.size() == 0) {
            throw ZMSUtils.requestError("validatedAdminUsers: Missing adminUsers", caller);
        }
        Set<String> users = new HashSet<>();
        for (String user : lst) {
            validate(user, TYPE_RESOURCE_NAME, caller);
            users.add(user);
        }
        return new ArrayList<>(users);
    }
    
    Domain createTopLevelDomain(ResourceContext ctx, String domainName, String description,
            String org, Boolean auditEnabled, List<String> adminUsers, String account,
            int productId, String applicationId, List<String> solutionTemplates, String auditRef) {
        List<String> users = validatedAdminUsers(adminUsers);
        return dbService.makeDomain(ctx, domainName, description, org, auditEnabled, 
                users, account, productId, applicationId, solutionTemplates, auditRef);
    }
    
    Domain createSubDomain(ResourceContext ctx, String parentName, String name, String description,
            String org, Boolean auditEnabled, List<String> adminUsers, String account,
            int productId, String applicationId, List<String> solutionTemplates, String auditRef,
            String caller) {

        // verify length of full sub domain name
        String fullSubDomName = parentName + "." + name;
        if (fullSubDomName.length() > domainNameMaxLen) {
            throw ZMSUtils.requestError("Invalid SubDomain name: " + fullSubDomName
                    + " : name length cannot exceed: " + domainNameMaxLen, caller);
        } 

        List<String> users = validatedAdminUsers(adminUsers);
        return dbService.makeDomain(ctx, fullSubDomName, description, org, auditEnabled,
                users, account, productId, applicationId, solutionTemplates, auditRef);
    }

    int countDots(String str) {
        int count = 0;
        int i = str.indexOf('.');
        while (i >= 0) {
            count++;
            i = str.indexOf('.', i + 1);
        }
        return count;
    }

    boolean hasExceededDepthLimit(Integer depth, String name) {
        
        if (depth == null) {
            return false;
        }
        
        // depth=0 means only top level

        return countDots(name) > depth;
    }
    
    DomainList listDomains(Integer limit, String skip, String prefix, Integer depth, long modTime) {
            
        //note: we don't use the store's options, because we also need to filter on depth
        
        List<String> allDomains = dbService.listDomains(prefix, modTime);
        List<String> names = new ArrayList<>();
        
        for (String name : allDomains) {
            if (hasExceededDepthLimit(depth, name)) {
                continue;
            }
            names.add(name);
        }
        
        int count = names.size();
        if (skip != null) {
            for (int i = 0; i < count; i++) {
                String name = names.get(i);
                if (skip.equals(name)) {
                    names = names.subList(i + 1, count);
                    count = names.size();
                    break;
                }
            }
        }
        
        DomainList result = new DomainList();

        // if we have exceeded our requested list then
        // set the next skip entry in our result
        
        if (hasExceededListLimit(limit, count)) {
            names = names.subList(0, limit);
            result.setNext(names.get(limit - 1));
        }
        
        result.setNames(names);
        return result;
    }
    
    boolean isZMSService(String domain, String service) {
        return (SYS_AUTH.equalsIgnoreCase(domain) && ZMSConsts.ZMS_SERVICE.equalsIgnoreCase(service));
    }
    
    /**
     * implements KeyStore getPublicKey
     * @return String with PEM encoded key, which should be ybase64decoded prior
     *         to return if ybase64encoded
     **/
    @Override
    public String getPublicKey(String domain, String service, String keyId) {
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("getPublicKey: service=" + domain + "." + service + " key-id=" + keyId);
        }
        
        if (service == null || keyId == null) {
            return null;
        }
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domain = domain.toLowerCase();
        service = service.toLowerCase();
        keyId = keyId.toLowerCase();
        
        // special handling for service sys.auth.zms which is ourselves
        // so we'll just lookup our key in our map

        String pubKey = null;
        if (isZMSService(domain, service)) {
            pubKey = serverPublicKeyMap.get(keyId);
        }
        
        // if it's not the ZMS Server public key then lookup the 
        // public key from ZMS data
        
        if (pubKey == null) {
            try {
                PublicKeyEntry keyEntry = dbService.getServicePublicKeyEntry(domain, service, keyId, true);
                if (keyEntry != null) {
                    pubKey = keyEntry.getKey();
                }
            } catch (ResourceException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("getPublicKey: unable to get public key: " + ex.getMessage());
                }
                return null;
            }
        }

        if (pubKey == null) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("getPublicKey: service=" + domain + "." + service + " has no public key registered");
            }
            return null;
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("getPublicKey: service public key: " + pubKey);
        }
        
        return Crypto.ybase64DecodeString(pubKey);
    }
    
    @Override
    public void putDefaultAdmins(ResourceContext ctx, String domainName, String auditRef,
            DefaultAdmins defaultAdmins) {
        
        final String caller = "putdefaultadmins";
        metric.increment(ZMSConsts.HTTP_PUT);
        metric.increment(ZMSConsts.HTTP_REQUEST);
        metric.increment(caller);
        Object timerMetric = metric.startTiming("putdefaultadmins_timing", null);
        logPrincipal(ctx);

        if (LOG.isDebugEnabled()) {
            LOG.debug("putDefaultAdmins: domain = " + domainName);
        }
        
        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // verify that request is properly authenticated for this request
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        AthenzObject.DEFAULT_ADMINS.convertToLowerCase(defaultAdmins);
        defaultAdmins.setAdmins(normalizedAdminUsers(defaultAdmins.getAdmins()));
        
        AthenzDomain domain = getAthenzDomain(domainName, false);
        if (domain == null) {
            throw ZMSUtils.notFoundError("putDefaultAdmins: Domain not found: '" + domainName + "'", caller);
        }
        
        Role adminRole = null;
        for (Role role : domain.getRoles()) {
            if (ADMIN_ROLE_NAME.equals(ZMSUtils.removeDomainPrefix(role.getName(), domainName, ROLE_PREFIX))) {
                adminRole = role;
                break;
            }
        }
        if (adminRole == null) {
            // if the admin role does not exist in the role section then add it
            // this typically should never happen since we have added the
            // check to disallow deletion of the admin role but we'll keep
            // the logic in place
        
            if (LOG.isInfoEnabled()) {
                LOG.info("putDefaultAdmins: Adding domain admin role because no domain admin role was found for domain: " + domainName);
            }
            adminRole = ZMSUtils.makeAdminRole(domainName, new ArrayList<>());
            dbService.executePutRole(ctx, domainName, ADMIN_ROLE_NAME, adminRole, auditRef, caller);
        }
            
        Policy adminPolicy = null;
        for (Policy policy : domain.getPolicies()) {
            if (ADMIN_POLICY_NAME.equals(ZMSUtils.removeDomainPrefix(policy.getName(), domainName, POLICY_PREFIX))) {
                adminPolicy = policy;
                break;
            }
        }
        if (adminPolicy == null) {
            // if the admin policy does not exist in the policy section then add it
            // this typically should never happen since we have added the
            // check to disallow deletion of the admin policy but we'll keep
            // the logic in place
            
            if (LOG.isInfoEnabled()) {
                LOG.info("putDefaultAdmins: Adding domain admin policy  because no domain admin policy  was found for domain: " + domainName);
            }
            //Create and add the admin policy
            adminPolicy = ZMSUtils.makeAdminPolicy(domainName, adminRole);
            dbService.executePutPolicy(ctx, domainName, ADMIN_POLICY_NAME, adminPolicy, auditRef, caller);
        }
        
        addDefaultAdminAssertion(ctx, domainName, adminPolicy, auditRef, caller);
        
        removeAdminDenyAssertions(ctx, domainName, domain.getPolicies(), domain.getRoles(), adminRole,
                defaultAdmins, auditRef, caller);
        
        addDefaultAdminMembers(ctx, domainName, adminRole, defaultAdmins, auditRef, caller);
        metric.stopTiming(timerMetric);
    }

    void addDefaultAdminAssertion(ResourceContext ctx, String domainName, Policy adminPolicy,
            String auditRef, String caller) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("addDefaultAdminAssertion");
        }
        
        String domainAllResources = domainName + ":*";
        String domainAdminRole = ZMSUtils.roleResourceName(domainName, ADMIN_ROLE_NAME);
        
        List<Assertion> assertions = adminPolicy.getAssertions();
        if (assertions != null) {
            
            for (Assertion assertion : assertions) {
                String resource = assertion.getResource();
                if (resource == null) {
                    continue;
                }
            
                String action = assertion.getAction();  
                if (action == null) {
                    continue;
                }
            
                String role = assertion.getRole();
                if (role == null) {
                    continue;
                }
            
                // default effect is no value is ALLOW
                AssertionEffect effect = assertion.getEffect();
                if (effect == null) {
                    effect = AssertionEffect.ALLOW;
                }
            
                if (resource.equals(domainAllResources) && action.equals("*") && 
                        role.equals(domainAdminRole) && (effect == AssertionEffect.ALLOW)) {
                    // found an assertion for resource = <domain>:*, with action = "*", 
                    // for role = <domainName>:role.admin and effect = "ALLOW" 
                    // (if effect is null then defaults to ALLOW) so no need to add it
                    return;
                }
            }
        }
        
        if (LOG.isInfoEnabled()) {
            LOG.info("Adding default admin assertion to admin policy because no default admin assertion was found for admin policy for domain: " + domainName);
        }
        
        ZMSUtils.addAssertion(adminPolicy, domainAllResources, "*", domainAdminRole, AssertionEffect.ALLOW);
        dbService.executePutPolicy(ctx, domainName, ADMIN_POLICY_NAME, adminPolicy, auditRef, caller);
    }
    
    void removeAdminDenyAssertions(ResourceContext ctx, String domainName, List<Policy> policies,
            List<Role> roles, Role adminRole, DefaultAdmins defaultAdmins, String auditRef, String caller) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("removeAdminDenyAssertions");
        }
        
        for (Policy policy : policies) {
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("access: processing policy: " + policy.getName());
            }
            
            // Process all the assertions defined in this policy
            // As soon as match for an assertion that 
            // denies access to the admin role is detected, remove it
            
            List<Assertion> assertions = policy.getAssertions();
            if (assertions == null) {
                continue;
            }
            List<Assertion> assertionsToDelete = new ArrayList<>();
            
            for (Assertion assertion : assertions) {

                // If there is no "effect" in the assertion then default is ALLOW
                // so continue because logic is looking for DENY
                AssertionEffect effect = assertion.getEffect();
                if (effect == null || effect != AssertionEffect.DENY) {
                    continue;
                }
                
                // If there is no role in the assertion then admin is not being denied
                String assertionRole = assertion.getRole();
                if (assertionRole == null) {
                    continue;
                }

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Found DENY assertion for role " + assertionRole);
                }
                    
                // role matches admin role then remove it
                if (assertionRole.equals(adminRole.getName())) {
                    assertionsToDelete.add(assertion);
                } else {
                    removeAdminMembers(ctx, domainName, roles, assertionRole, defaultAdmins, auditRef, caller);
                }
            }
            
            if (assertionsToDelete.isEmpty()) {
                continue;
            }
            
            if (LOG.isInfoEnabled()) {
                LOG.info("Removing assertion from policy: " + policy.getName() + " because it was for the domain admin role.");
            }
            
            for (Assertion assertion : assertionsToDelete) {
                assertions.remove(assertion);
            }

            String policyName = ZMSUtils.removeDomainPrefix(policy.getName(), domainName, POLICY_PREFIX);
            if (assertions.size() == 0) {
                if (LOG.isInfoEnabled()) {
                    LOG.info("Removing  policy: " + policyName +
                            " because it did not have any assertions after removing a DENY" +
                            " assertion for the domain admin role.");
                }

                dbService.executeDeletePolicy(ctx, domainName, policyName, auditRef, caller);
            } else {
                dbService.executePutPolicy(ctx, domainName, policyName, policy, auditRef, caller);
            }
        }
    }
    
    void removeAdminMembers(ResourceContext ctx, String domainName, List<Role> roles,
            String assertionRole, DefaultAdmins defaultAdmins, String auditRef, String caller) {
            
        
        for (Role role : roles) {
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("removeAdminMembers: Removing admin members from role: " + role.getName());
            }
            
            if (!assertionRole.equals(role.getName())) {
                continue;
            }

            String roleName = ZMSUtils.removeDomainPrefix(role.getName(), domainName, ROLE_PREFIX);
            for (String adminName : defaultAdmins.getAdmins()) {
                if (isMemberOfRole(role, adminName)) {
                    if (LOG.isInfoEnabled()) {
                        LOG.info("removeAdminMembers: removing member: " + adminName + " from role: " +
                                roleName + " because there is a DENY assertion for this role in this domain.");
                    }
                    
                    dbService.executeDeleteMembership(ctx, domainName, roleName, adminName, auditRef, caller);
                }
            }
        }
    }

    void addDefaultAdminMembers(ResourceContext ctx, String domainName, Role adminRole,
            DefaultAdmins defaultAdmins, String auditRef, String caller) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("addDefaultAdminMembers");
        }
        
        for (String adminName : defaultAdmins.getAdmins()) {
            if (!isMemberOfRole(adminRole, adminName)) {
                if (LOG.isInfoEnabled()) {
                    LOG.info("Adding member: " + adminName + " to admin role for domain: " + domainName);
                }
                RoleMember roleMember = new RoleMember().setMemberName(adminName);
                dbService.executePutMembership(ctx, domainName, ADMIN_ROLE_NAME,
                        roleMember, auditRef, caller);
            }
        }
    }

    public ServicePrincipal getServicePrincipal(ResourceContext ctx) {

        final String caller = "getserviceprincipal";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        
        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        Authority authority = principal.getAuthority();

        metric.increment(ZMSConsts.HTTP_REQUEST, principal.getDomain());
        metric.increment(caller, principal.getDomain());
        Object timerMetric = metric.startTiming("getserviceprincipal_timing", principal.getDomain());

        // If the authority does not support authorization then we're going to
        // generate a new ServiceToken signed by ZMS and send that back.

        ServicePrincipal servicePrincipal = new ServicePrincipal();
        servicePrincipal.setDomain(principal.getDomain());
        servicePrincipal.setService(principal.getName());
        
        if (!authority.allowAuthorization()) {
        
            PrincipalToken sdToken = new PrincipalToken(principal.getCredentials());
            PrincipalToken zmsToken = new PrincipalToken.Builder("S1", sdToken.getDomain(), sdToken.getName())
                .issueTime(sdToken.getTimestamp())
                .expirationWindow(sdToken.getExpiryTime() - sdToken.getTimestamp())
                .ip(sdToken.getIP()).keyId(privateKeyId).host(serverHostName)
                .keyService(ZMSConsts.ZMS_SERVICE).build();
            zmsToken.sign(privateKey);

            servicePrincipal.setToken(zmsToken.getSignedToken());
            
        } else {
            servicePrincipal.setToken(principal.getCredentials());
        }

        metric.stopTiming(timerMetric);
        return servicePrincipal;
    }
    
    void verifyAuthorizedServiceOperation(String authorizedService, String operationName) {
        verifyAuthorizedServiceOperation(authorizedService, operationName, null, null);
    }
    
    /**
     * If opItemType and value are not defined in the authorized_services JSON file,
     * you can simply pass NULL for these two values.
     */
    void verifyAuthorizedServiceOperation(String authorizedService, String operationName,
            String opItemType, String opItemVal) {
        
        // only process this request if we have an authorized service specified
        
        if (authorizedService == null) {
            return;
        }
        
        // lookup the authorized services struct and see if we have the
        // service specified in the allowed list
        
        AuthorizedService authzService = serverAuthorizedServices.get(authorizedService);
        if (authzService == null) {
            throw ZMSUtils.forbiddenError("Unauthorized Service " + authorizedService,
                    operationName);
        }
        
        // if the list is empty then we do not allow any operations
        
        ArrayList<AllowedOperation> ops = authzService.getAllowedOperations();
        if (ops == null || ops.isEmpty()) {
            throw ZMSUtils.forbiddenError("Unauthorized Operation (" + operationName
                    + ") for Service " + authorizedService, operationName);
        }
        
        // otherwise make sure the operation is allowed for this service
        
        boolean opAllowed = false;
        for (AllowedOperation op : ops) {
            if (!op.getName().equalsIgnoreCase(operationName)) {
                continue;
            }
            
            opAllowed = op.isOperationAllowedOn(opItemType, opItemVal);
            break;
        }
        
        if (!opAllowed) {
            throw ZMSUtils.forbiddenError("Unauthorized Operation (" + operationName
                    + ") for Service " + authorizedService
                    + (opItemType != null && !opItemType.isEmpty() ? " on opItemKey " + opItemType + " and opItemVal " + opItemVal : ""),
                    operationName);
        }
    }

    @Override
    public ResourceAccessList getResourceAccessList(ResourceContext ctx, String principal,
            String action) {
        
        final String caller = "getresourceaccesslist";
        metric.increment(ZMSConsts.HTTP_GET);
        metric.increment(ZMSConsts.HTTP_REQUEST);
        metric.increment(caller);
        Object timerMetric = metric.startTiming("getresourceaccesslist_timing", null);
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);

        Principal ctxPrincipal = ((RsrcCtxWrapper) ctx).principal();
        if (LOG.isDebugEnabled()) {
            LOG.debug("getResourceAccessList:(" + ctxPrincipal + ", " + principal
                    + ", " + action + ")");
        }
        
        if (principal != null) {
            validate(principal, TYPE_ENTITY_NAME, caller);
            principal = normalizeDomainAliasUser(principal.toLowerCase());
        }
        if (action != null) {
            validate(action, TYPE_COMPOUND_NAME, caller);
            action = action.toLowerCase();
        }
        
        // if principal is null then we it's a special case
        // so we need to make sure the caller is authorized
        // to make this request
        
        if (principal == null || principal.isEmpty()) {
            if (!isAllowedResourceLookForAllUsers(ctxPrincipal)) {
                throw ZMSUtils.forbiddenError("Principal: " + ctxPrincipal.getFullName() +
                        " not authorized to lookup resources for all users in Athenz", caller);
            }
        }
        
        ResourceAccessList rsrcAccessList = dbService.getResourceAccessList(principal, action);

        metric.stopTiming(timerMetric);
        return rsrcAccessList;
    }

    @Override
    public Status getStatus(ResourceContext ctx) {
        
        final String caller = "getstatus";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        // validate our request as status request
        
        validateRequest(ctx.request(), caller, true);
        
        // create our timer object
        
        metric.increment(caller);
        Object timerMetric = metric.startTiming("getstatus_timing", null);
        
        // for now we're going to verify our database connectivity
        // in case of failure we're going to return not found

        DomainList dlist = listDomains(null, null, null, null, 0);
        if (dlist.getNames() == null || dlist.getNames().isEmpty()) {
            throw ZMSUtils.notFoundError("Error - no domains available", caller);
        }

        // check if we're configured to check for the status file

        if (healthCheckFile != null && !healthCheckFile.exists()) {
            throw ZMSUtils.notFoundError("Error - no status available", caller);
        }

        metric.stopTiming(timerMetric);
        return successServerStatus;
    }
    
    void logPrincipal(ResourceContext ctx) {
        
        // we are going to log our principal and validate that it
        // contains expected data
        
        final Principal ctxPrincipal = ((RsrcCtxWrapper) ctx).principal();
        ((RsrcCtxWrapper) ctx).logPrincipal(ctxPrincipal);
        if (ctxPrincipal != null && ctxPrincipal.getFullName() != null) {
            validate(ctxPrincipal.getFullName(), TYPE_SERVICE_NAME, "logPrincipal");
        }
    }

    public ResourceContext newResourceContext(HttpServletRequest request,
            HttpServletResponse response) {
        
        // check to see if we want to allow this URI to be available
        // with optional authentication support
        
        boolean optionalAuth = StringUtils.requestUriMatch(request.getRequestURI(),
                authFreeUriSet, authFreeUriList);
        return new RsrcCtxWrapper(request, response, authorities, optionalAuth, this);
    }
    
    @Override
    public Schema getRdlSchema(ResourceContext context) {
        return schema;
    }
    
    static String getServerHostName() {
        
        String serverHostName = System.getProperty(ZMSConsts.ZMS_PROP_HOSTNAME);
        if (serverHostName == null || serverHostName.isEmpty()) {
            try {
                InetAddress localhost = java.net.InetAddress.getLocalHost();
                serverHostName = localhost.getCanonicalHostName();
            } catch (java.net.UnknownHostException e) {
                LOG.info("Unable to determine local hostname: " + e.getMessage());
                serverHostName = "localhost";
            }
        }
        
        return serverHostName;
    }
    
    Authority getAuthority(String className) {
        
        LOG.debug("Loading authority {}...", className);
        
        Authority authority;
        try {
            authority = (Authority) Class.forName(className).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOG.error("Invalid Authority class: " + className + " error: " + e.getMessage());
            return null;
        }
        return authority;
    }
    
    public static String getRootDir() {
        
        if (ROOT_DIR == null) {
            ROOT_DIR = System.getProperty(ZMSConsts.ZMS_PROP_ROOT_DIR, ZMSConsts.STR_DEF_ROOT);
        }

        return ROOT_DIR;
    }
}
