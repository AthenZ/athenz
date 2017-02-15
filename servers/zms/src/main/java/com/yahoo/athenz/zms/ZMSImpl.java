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
package com.yahoo.athenz.zms;

import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.Validator;
import com.yahoo.rdl.Validator.Result;
import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.log.AthenzRequestLog;
import com.yahoo.athenz.common.server.log.AuditLogFactory;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.rest.Http;
import com.yahoo.athenz.common.server.util.ServletRequestUtil;
import com.yahoo.athenz.common.server.util.StringUtils;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.provider.ProviderClient;
import com.yahoo.athenz.provider.Tenant;
import com.yahoo.athenz.provider.TenantResourceGroup;
import com.yahoo.athenz.zms.config.AllowedOperation;
import com.yahoo.athenz.zms.config.AuthorizedService;
import com.yahoo.athenz.zms.config.AuthorizedServices;
import com.yahoo.athenz.zms.config.SolutionTemplates;
import com.yahoo.athenz.zms.store.AthenzDomain;
import com.yahoo.athenz.zms.store.ObjectStore;
import com.yahoo.athenz.zms.utils.ZMSUtils;

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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.ws.rs.core.EntityTag;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A reference implementation of ZMS. Uses a StructStore for domain information.
 * This class is not public - use the ZMSCore class to access it.
 */
public class ZMSImpl implements Authorizer, KeyStore, ZMSHandler {

    private static final Logger LOG = LoggerFactory.getLogger(ZMSImpl.class);

    private static final String SERVICE_PREFIX = "service.";
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
    
    private static final String SYS_AUTH = "sys.auth";
    private static final String USER_TOKEN_DEFAULT_NAME = "_self_";

    // data validation types
    private static final String TYPE_DOMAIN_NAME = "DomainName";
    private static final String TYPE_ENTITY_NAME = "EntityName";
    private static final String TYPE_SIMPLE_NAME = "SimpleName";
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
    private static final String TYPE_TENANT_ROLES = "TenantRoles";
    private static final String TYPE_TENANT_RESOURCE_GROUP_ROLES = "TenantResourceGroupRoles";
    private static final String TYPE_PROVIDER_RESOURCE_GROUP_ROLES = "ProviderResourceGroupRoles";
    private static final String TYPE_PUBLIC_KEY_ENTRY = "PublicKeyEntry";
    
    public static Metric metric;
    protected ObjectStore dbStore = null;
    protected DBService dbService = null;
    protected Class<? extends ProviderClient> providerClass = null;
    protected Schema schema = null;
    protected PrivateKey privateKey = null;
    protected String privateKeyId = "0";
    protected int userTokenTimeout = 3600;
    protected boolean virtualDomainSupport = true;
    protected boolean productIdSupport = false;
    protected int virtualDomainLimit = 2;
    protected long signedPolicyTimeout;
    protected static String serverHostName  = null;
    protected static String serverHttpsPort = null;
    protected static String serverHttpPort  = null;
    protected int domainNameMaxLen;
    protected AuthorizedServices serverAuthorizedServices = null;
    protected static SolutionTemplates serverSolutionTemplates = null;
    protected Map<String, String> serverPublicKeyMap = null;
    protected boolean readOnlyMode = false;
    protected static Validator validator;
    protected static String userDomain;
    protected static String userDomainPrefix;
    protected Http.AuthorityList authorities = null;
    protected List<String> providerEndpoints = null;
    
    // enum to represent our access response since in some cases we want to
    // handle domain not founds differently instead of just returning failure

    enum AccessStatus {
        ALLOWED,
        DENIED,
        DENIED_DOMAIN_NOT_FOUND,
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
        DOMAIN_TEMPLATE_LIST {
            void convertToLowerCase(Object obj) {
                DomainTemplateList templates = (DomainTemplateList) obj;
                if (templates != null) {
                    LIST.convertToLowerCase(templates.getTemplateNames());
                }
            }
        },
        DOMAIN_TEMPLATE {
            void convertToLowerCase(Object obj) {
                DomainTemplate template = (DomainTemplate) obj;
                if (template != null) {
                    LIST.convertToLowerCase(template.getTemplateNames());
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
        TENANCY_RESOURCE_GROUP {
            void convertToLowerCase(Object obj) {
                TenancyResourceGroup tenancyResourceGroup = (TenancyResourceGroup) obj;
                tenancyResourceGroup.setDomain(tenancyResourceGroup.getDomain().toLowerCase());
                tenancyResourceGroup.setService(tenancyResourceGroup.getService().toLowerCase());
                tenancyResourceGroup.setResourceGroup(tenancyResourceGroup.getResourceGroup().toLowerCase());
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
        TENANT_ROLES {
            void convertToLowerCase(Object obj) {
                TenantRoles tenantRoles = (TenantRoles) obj;
                tenantRoles.setDomain(tenantRoles.getDomain().toLowerCase());
                tenantRoles.setService(tenantRoles.getService().toLowerCase());
                tenantRoles.setTenant(tenantRoles.getTenant().toLowerCase());
                if (tenantRoles.getRoles() != null) {
                    for (TenantRoleAction roleAction : tenantRoles.getRoles()) {
                        TENANT_ROLE_ACTION.convertToLowerCase(roleAction);
                    }
                }
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
        USER_DOMAIN {
            void convertToLowerCase(Object obj) {
                UserDomain userDomain = (UserDomain) obj;
                userDomain.setName(userDomain.getName().toLowerCase());
                DOMAIN_TEMPLATE_LIST.convertToLowerCase(userDomain.getTemplates());
            }
        };
            
        abstract void convertToLowerCase(Object obj);
    }
    
    AuditLogger auditLogger = null;
    static String auditLoggerMsgBldrClass = null;

    public ZMSImpl(String serverHostName, ObjectStore dbStore, Metric metric,
            PrivateKey privateKey, String privateKeyId, AuditLogger auditLog,
            String auditLogMsgBldrClass) {
        
        auditLogger = auditLog;
        auditLoggerMsgBldrClass = auditLogMsgBldrClass;
        
        this.privateKey = privateKey;
        this.privateKeyId = privateKeyId;
        this.schema = ZMSSchema.instance();
        validator = new Validator(schema);
        userDomain = System.getProperty(ZMSConsts.ZMS_PROP_USER_DOMAIN, ZMSConsts.USER_DOMAIN);
        userDomainPrefix = userDomain + ".";
        
        ZMSImpl.serverHostName = serverHostName;
        ZMSImpl.metric = metric;
        this.dbStore = dbStore;
        dbService = new DBService(dbStore, auditLogger, userDomain);
        userTokenTimeout = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_TIMEOUT, "3600"));
        
        // check if we need to run in maintenance read only mode
        
        readOnlyMode = Boolean.parseBoolean(System.getProperty(ZMSConsts.ZMS_PROP_READ_ONLY_MODE, "false"));
        
        // check to see if we need to support product ids as required
        // for top level domains
        
        productIdSupport = Boolean.parseBoolean(System.getProperty(ZMSConsts.ZMS_PROP_PRODUCT_ID_SUPPORT, "false"));
        
        // get the list of valid provider endpoints
        
        String endPoints = System.getProperty(ZMSConsts.ZMS_PROP_PROVIDER_ENDPOINTS);
        if (endPoints != null) {
            providerEndpoints = Arrays.asList(endPoints.split(","));
        }
        // retrieve virtual domain support and limit. If we're given an invalid negative
        // value for limit, we'll default back to our configured value of 2
        
        virtualDomainSupport = Boolean.parseBoolean(System.getProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN, "true"));
        virtualDomainLimit = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN_LIMIT, "2"));
        if (virtualDomainLimit < 0) {
            virtualDomainLimit = 2;
        }
        
        // signedPolicyTimeout is in milliseconds but the config setting should be in seconds
        // to be consistent with other configuration properties (Default 7 days)
        
        signedPolicyTimeout = 1000 * Long.parseLong(System.getProperty(ZMSConsts.ZMS_PROP_SIGNED_POLICY_TIMEOUT, "604800"));
        if (signedPolicyTimeout < 0) {
            signedPolicyTimeout = 1000 * 604800;
        }
        
        // get the ports the server is configured to listen on

        serverHttpsPort = System.getProperty(ZMSConsts.ZMS_PROP_HTTPS_PORT, Integer.toString(ZMSConsts.ZMS_HTTPS_PORT_DEFAULT));
        serverHttpPort  = System.getProperty(ZMSConsts.ZMS_PROP_HTTP_PORT, Integer.toString(ZMSConsts.ZMS_HTTP_PORT_DEFAULT));

        // get the maximum length allowed for a top level domain name

        domainNameMaxLen = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_DOMAIN_NAME_MAX_SIZE,
                ZMSConsts.ZMS_DOMAIN_NAME_MAX_SIZE_DEFAULT));
        if (domainNameMaxLen < 10) { // 10 is arbitrary
            int domNameMaxDefault = Integer.parseInt(ZMSConsts.ZMS_DOMAIN_NAME_MAX_SIZE_DEFAULT);
            LOG.warn("init: Warning: maximum domain name length specified is too small: " +
                domainNameMaxLen + " : reverting to default: " + domNameMaxDefault);
            domainNameMaxLen = domNameMaxDefault;
        }
        LOG.info("init: using maximum domain name length: " + domainNameMaxLen);
        
        // load the list of authorized services
        
        loadAuthorizedServices();
        
        // load the Solution templates
        
        loadSolutionTemplates();
        
        // this should only happen when running ZMS in local/debug mode
        // otherwise the store should have been initialized by now
        
        initObjectStore();
        
        // retrieve our public keys
        
        loadServerPublicKeys();
    }

    void loadServerPublicKeys() {
        
        // initialize our public key map
        
        serverPublicKeyMap = new ConcurrentHashMap<String, String>();
        
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
    
    public void setProviderClientClass(Class<? extends ProviderClient> providerClass) {
        this.providerClass = providerClass;
    }

    public void putAuthorityList(Http.AuthorityList authList) {
        authorities = authList;
    }
    
    void loadSolutionTemplates() {
        
        // get the configured path for the list of service templates
        
        String solutionTemplatesFname =  System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME,
                ZMS.getRootDir() + "/conf/zms_server/solution_templates.json");
        
        Path path = Paths.get(solutionTemplatesFname);
        try {
            serverSolutionTemplates = JSON.fromBytes(Files.readAllBytes(path), SolutionTemplates.class);
        } catch (IOException e) {
            LOG.info("Unable to parse service templates file " + solutionTemplatesFname);
            return;
        }

        if (serverSolutionTemplates == null) {
            LOG.info("Unable to parse service templates file " + solutionTemplatesFname);
            return;
        }
    }
    
    void loadAuthorizedServices() {
        
        // get the configured path for the list of authorized services and what operations
        // those services are allowed to process
        
        String authzServiceFname =  System.getProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME,
                ZMS.getRootDir() + "/conf/zms_server/authorized_services.json");
        
        // let's read our authorized list into a local struct
        
        File file = new File(authzServiceFname);
        if (file.exists() == false) {
            LOG.info("Authorized Service File " + authzServiceFname + " not found");
            return;
        }
        
        Path path = Paths.get(file.toURI());
        try {
            serverAuthorizedServices = JSON.fromBytes(Files.readAllBytes(path), AuthorizedServices.class);
        } catch (IOException e) {
            LOG.info("Unable to parse authorized service file " + authzServiceFname);
        }
    }
    
    void initObjectStore() {
        
        final String caller = "initstore";

        List<String> domains = dbService.listDomains(null, 0);
        if (domains.size() > 0) {
            return;
        }
        
        String adminUserList = System.getProperty(ZMSConsts.ZMS_PROP_DOMAIN_ADMIN);
        if (adminUserList == null) {
            throw ZMSUtils.internalServerError("init: No ZMS admin user specified", caller);
        }
        
        String[] users = adminUserList.split(",");
        ArrayList<String> adminUsers = new ArrayList<String>();
        for (int i = 0; i < users.length; i++) {
            String adminUser = users[i].trim();
            if (!adminUser.startsWith(userDomainPrefix)) {
                throw ZMSUtils.internalServerError("init: Bad domain user name(" + adminUser +
                        "), must begin with (" + userDomainPrefix + ")", caller);
            }
            adminUsers.add(adminUser);
        }
        
        if (!ZMSConsts.USER_DOMAIN.equals(userDomain)) {
            createTopLevelDomain(null, userDomain, "The reserved domain for user authentication",
                    null, null, adminUsers, null, 0, null, null);
        }
        createTopLevelDomain(null, userDomain, "The reserved domain for user authentication",
                null, null, adminUsers, null, 0, null, null);
        createTopLevelDomain(null, "sys", "The reserved domain for system related information",
                null, null, adminUsers, null, 0, null, null);
        createSubDomain(null, "sys", "auth", "The AuthNG domain", null, null, adminUsers,
                null, 0, null, null, caller);

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

    /**
     * Setup a new AuditLogMsgBuilder object with common values.
    **/
    static AuditLogMsgBuilder getAuditLogMsgBuilder(ResourceContext ctx, String domainName,
            String auditRef, String caller, String method) {
        
        AuditLogMsgBuilder msgBldr = null;
        try {
            msgBldr = AuditLogFactory.getMsgBuilder(auditLoggerMsgBldrClass);
        } catch (Exception exc) {
            LOG.error("getAuditLogMsgBuilder: Using default failed to get an AuditLogMsgBuilder: "
                    + exc.getMessage());
            msgBldr = AuditLogFactory.getMsgBuilder();
        }

        // get the where - which means where this server is running
        
        msgBldr.whereIp(serverHostName).whereHttpsPort(serverHttpsPort).whereHttpPort(serverHttpPort);
        msgBldr.whatDomain(domainName).why(auditRef).whatApi(caller).whatMethod(method);

        // get the 'who' and set it
        
        if (ctx != null) {
            Principal princ = ((RsrcCtxWrapper) ctx).principal();
            if (princ != null) {
                String unsignedCreds = princ.getUnsignedCredentials();
                if (unsignedCreds == null) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("who-name=").append(princ.getName());
                    sb.append(",who-domain=").append(princ.getDomain());
                    sb.append(",who-fullname=").append(princ.getFullName());
                    List<String> roles = princ.getRoles();
                    if (roles != null && roles.size() > 0) {
                        sb.append(",who-roles=").append(roles.toString());
                    }
                    unsignedCreds = sb.toString();
                }
                msgBldr.who(unsignedCreds);
            }

            // get the client IP
            
            msgBldr.clientIp(ServletRequestUtil.getRemoteAddress(ctx.request()));
        }

        return msgBldr;
    }

    // ----------------- the Domain interface {

    public DomainList getDomainList(ResourceContext ctx, Integer limit, String skip, String prefix,
            Integer depth, String account, Integer productId, String roleMember, String roleName,
            String modifiedSince) {

        final String caller = "getdomainlist";
        metric.increment(ZMSConsts.HTTP_GET);
        metric.increment(ZMSConsts.HTTP_REQUEST);
        metric.increment(caller);
        Object timerMetric = metric.startTiming("getdomainlist_timing", null);
        logPrincipal(ctx);

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
        
        DomainList dlist = null;
        if (account != null && !account.isEmpty()) {
            dlist = dbService.lookupDomainByAccount(account);
        } else if (productId != null && productId.intValue() != 0) {
            dlist = dbService.lookupDomainByProductId(productId);
        } else if (roleMember != null || roleName != null) {
            dlist = dbService.lookupDomainByRole(roleMember, roleName);
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

        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);

        Object timerMetric = metric.startTiming("getdomain_timing", domainName);
        
        Domain domain = dbService.getDomain(domainName);
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
        
        Domain domain = null;
        try {
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
                    if ((productId = detail.getYpmId().intValue()) <= 0) {
                        throw ZMSUtils.requestError("Product Id must be a positive integer", caller);
                    }
                } else {
                    throw ZMSUtils.requestError("Product Id is required when creating top level domain", caller);
                }
            }
            
            domain = createTopLevelDomain(ctx, domainName, detail.getDescription(),
                detail.getOrg(), detail.getAuditEnabled(), detail.getAdminUsers(),
                detail.getAccount(), productId, solutionTemplates, auditRef);

            metric.stopTiming(timerMetric);

        } catch (Exception exc) {
            
            String domainName = (detail != null) ? detail.getName() : null;
            auditRequestFailure(ctx, exc, domainName, domainName, caller,
                    ZMSConsts.HTTP_POST, null, auditRef);
            throw exc;
        }

        return domain;
    }
    
    public TopLevelDomain deleteTopLevelDomain(ResourceContext ctx, String domainName, String auditRef) {
        
        final String caller = "deletetopleveldomain";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
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

        } catch (Exception exc) {
            
            auditRequestFailure(ctx, exc, domainName, domainName, caller, ZMSConsts.HTTP_DELETE, null, auditRef);
            throw exc;
        }

        return null;
    }

    Domain deleteDomain(ResourceContext ctx, String auditRef, String domainName, String caller) {

        DomainList subDomainList = listDomains(null, null, domainName + ".", null, 0);
        if (subDomainList.getNames().size() > 0) {
            throw ZMSUtils.requestError(caller + ": Cannot delete domain " +
                    domainName + ": " + subDomainList.getNames().size() + " subdomains of it exist", caller);
        }

        Domain domain = dbService.executeDeleteDomain(ctx, domainName, auditRef, caller);
        return domain;
    }
    
    boolean isVirtualDomain(String domain) {

        // all virtual domains start with our user domain
        
        return domain.startsWith(userDomainPrefix);
    }
    
    boolean hasExceededVirtualSubDomainLimit(String domain) {
        
        // we need to find our username which is our second
        // component in the domain name - e.g. user.joe[.subdomain]
        // when counting we need to make to include the trailing .
        // since we're counting subdomains and we need to make sure
        // not to match other users who have the same prefix
        
        String userDomain = null;
        int idx = domain.indexOf(".", userDomainPrefix.length());
        if (idx == -1) {
            userDomain = domain + ".";
        } else {
            userDomain = domain.substring(0, idx + 1);
        }
        
        // retrieve the number of domains with this prefix
        
        DomainList dlist = listDomains(null, null, userDomain, null, 0);
        if (dlist.getNames().size() < virtualDomainLimit) {
            return false;
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("hasExceededVirtualSubDomainLimit: subdomains with prefix " + userDomain
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
        
        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
        if (!name.equals(detail.getName())) {
            throw ZMSUtils.forbiddenError("postUserDomain: Request and detail domain names do not match", caller);
        }

        // we're dealing with user's top level domain so the parent is going
        // to be the user domain and the admin of the domain is the user

        List<String> adminUsers = new ArrayList<>();
        adminUsers.add(userDomainPrefix + name);
        
        List<String> solutionTemplates = null;
        DomainTemplateList templates = detail.getTemplates();
        if (templates != null) {
            solutionTemplates = templates.getTemplateNames();
            validateSolutionTemplates(solutionTemplates, caller);
        }
        
        Domain domain = createSubDomain(ctx, userDomain, detail.getName(), detail.getDescription(),
                detail.getOrg(), detail.getAuditEnabled(), adminUsers, detail.getAccount(), 0,
                solutionTemplates, auditRef, caller);

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
                if ((productId = detail.getYpmId().intValue()) < 0) {
                    throw ZMSUtils.requestError("Product Id must be a positive integer", caller);
                }
            }
        }
        
        Domain domain = createSubDomain(ctx, detail.getParent(), detail.getName(), detail.getDescription(),
                detail.getOrg(), detail.getAuditEnabled(), detail.getAdminUsers(), detail.getAccount(),
                productId, solutionTemplates, auditRef, caller);

        metric.stopTiming(timerMetric);
        return domain;
    }

    boolean isSysAdminUser(Principal principal) {
        
        // verify we're dealing with system administrator
        // authorize ("CREATE", "sys.auth:domain");

        AthenzDomain domain = getAthenzDomain(SYS_AUTH, true);
        if (domain == null) {
            return false;
        }
        
        // evaluate our domain's roles and policies to see if access
        // is allowed or not for the given operation and resource
        // our action are always converted to lowercase
        
        String resource = SYS_AUTH + ":domain";
        AccessStatus accessStatus = evaluateAccess(domain, principal.getFullName(), "create",
                resource, null, null);
        
        if (accessStatus == AccessStatus.ALLOWED) {
            return true;
        } else {
            return false;
        }
    }

    boolean isAllowedResourceLookForAllUsers(Principal principal) {
        
        // the authorization policy resides in offical sys.auth domain

        AthenzDomain domain = getAthenzDomain(SYS_AUTH, true);
        if (domain == null) {
            return false;
        }
        
        // evaluate our domain's roles and policies to see if access
        // is allowed or not for the given operation and resource
        // our action are always converted to lowercase

        String resource = SYS_AUTH + ":resource-lookup-all";
        AccessStatus accessStatus = evaluateAccess(domain, principal.getFullName(), "access",
                resource, null, null);
        
        if (accessStatus == AccessStatus.ALLOWED) {
            return true;
        } else {
            return false;
        }
    }
    
    public SubDomain deleteSubDomain(ResourceContext ctx, String parent, String name, String auditRef) {

        final String caller = "deletesubdomain";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        parent = parent.toLowerCase();
        name = name.toLowerCase();
        String domainName = parent + "." + name;

        metric.increment(ZMSConsts.HTTP_REQUEST, parent);
        metric.increment(caller, parent);
        Object timerMetric = metric.startTiming("deletesubdomain_timing", parent);

        try {
            validate(parent, TYPE_DOMAIN_NAME, caller);
            validate(name, TYPE_SIMPLE_NAME, caller);

            // verify that request is properly authenticated for this request
            
            verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
            
            deleteDomain(ctx, auditRef, domainName, caller);

        } catch (Exception exc) {
            
            auditRequestFailure(ctx, exc, domainName, domainName, caller, ZMSConsts.HTTP_DELETE, null, auditRef);
            throw exc;
        }

        metric.stopTiming(timerMetric);
        return null;
    }

    public UserDomain deleteUserDomain(ResourceContext ctx, String name, String auditRef) {

        final String caller = "deleteuserdomain";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
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
            
            String domainName = userDomainPrefix + name;
            deleteDomain(ctx, auditRef, domainName, caller);
            metric.stopTiming(timerMetric);

        } catch (Exception exc) {
            
            auditRequestFailure(ctx, exc, name, name, caller, ZMSConsts.HTTP_DELETE, null, auditRef);
            throw exc;
        }

        return null;
    }
    
    public Domain putDomainMeta(ResourceContext ctx, String domainName, String auditRef, DomainMeta meta) {

        final String caller = "putdomainmeta";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
            validate(meta, TYPE_DOMAIN_META, caller);

            // for consistent handling of all requests, we're going to convert
            // all incoming object values into lower case (e.g. domain, role,
            // policy, service, etc name)
            
            domainName = domainName.toLowerCase();
            metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
            metric.increment(caller, domainName);
            Object timerMetric = metric.startTiming("putdomainmeta_timing", domainName);
            
            // verify that request is properly authenticated for this request
            
            verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("putDomainMeta: name=" + domainName + ", meta=" + meta);
            }

            // for top level domains, verify the meta data has a product id and that it is not used by
            // any other domain(other than this one)

            if (productIdSupport && domainName.indexOf('.') == -1) {
                    
                // if this productId is already used by any domain it will be
                // seen in dbService and exception thrown
                
                Integer productId = meta.getYpmId();
                if (productId == null) {
                    throw ZMSUtils.requestError("Unique Product Id must be specified for top level domain", caller);
                }
            }

            dbService.executePutDomainMeta(ctx, domainName, meta, auditRef, caller);
            metric.stopTiming(timerMetric);

        } catch (Exception exc) {
            
            auditRequestFailure(ctx, exc, domainName, domainName, caller, ZMSConsts.HTTP_PUT, null, auditRef);
            throw exc;
        }

        return null;
    }
    
    void validateSolutionTemplates(List<String> templateNames, String caller) {
        for (String templateName : templateNames) {
            if (!serverSolutionTemplates.contains(templateName)) {
                throw ZMSUtils.notFoundError("validateSolutionTemplates: Template not found: " + templateName, caller);
            }
        }
    }
    
    public DomainTemplateList getDomainTemplateList(ResourceContext ctx, String domainName) {

        final String caller = "getdomaintemplatelist";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

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
    
    public DomainTemplate putDomainTemplate(ResourceContext ctx, String domainName, String auditRef,
            DomainTemplate templates) {

        final String caller = "putdomaintemplate";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
            validate(templates, TYPE_DOMAIN_TEMPLATE, caller);
            
            // for consistent handling of all requests, we're going to convert
            // all incoming object values into lower case (e.g. domain, role,
            // policy, service, etc name)
            
            domainName = domainName.toLowerCase();
            AthenzObject.DOMAIN_TEMPLATE.convertToLowerCase(templates);
            
            metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
            metric.increment(caller, domainName);
            Object timerMetric = metric.startTiming("putdomaintemplate_timing", domainName);
            
            // verify that all template names are valid
            
            List<String> templateNames = templates.getTemplateNames();
            if (templateNames == null || templateNames.size() == 0) {
                throw ZMSUtils.requestError("putDomainTemplate: No templates specified", caller);
            }
            validateSolutionTemplates(templateNames, caller);
            
            // verify that request is properly authenticated for this request
            // Make sure each template name is verified
            
            for (String templateName : templates.getTemplateNames()) {
                verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(),
                        caller, "name", templateName);
            }

            dbService.executePutDomainTemplate(ctx, domainName, templateNames, auditRef, caller);
            metric.stopTiming(timerMetric);

        } catch (Exception exc) {
            
            String auditDetails = auditListItems("caller specified templates", templates.getTemplateNames());
            auditRequestFailure(ctx, exc, domainName, domainName, caller, ZMSConsts.HTTP_PUT,
                    auditDetails, auditRef);
            throw exc;
        }

        return null;
    }

    public DomainTemplate deleteDomainTemplate(ResourceContext ctx, String domainName, String templateName, String auditRef) {

        final String caller = "deletedomaintemplate";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }
        
        try {
            // verify that request is properly authenticated for this request
        
            verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
        
            // for consistent handling of all requests, we're going to convert
            // all incoming object values into lower case (e.g. domain, role,
            // policy, service, etc name)
        
            domainName = domainName.toLowerCase();
            metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
            metric.increment(caller, domainName);
            Object timerMetric = metric.startTiming("deletedomaintemplate_timing", domainName);

            if (LOG.isDebugEnabled()) {
                LOG.debug("deleteDomainTemplate: domain=" + domainName + ", template=" + templateName);
            }

            // verify the template name is valid
        
            if (templateName == null || templateName.length() == 0) {
                throw ZMSUtils.requestError("deleteDomainTemplate: No template specified", caller);
            }

            templateName = templateName.toLowerCase();
            List<String> templateNames = new ArrayList<String>();
            templateNames.add(templateName);
            validateSolutionTemplates(templateNames, caller);
        
            dbService.executeDeleteDomainTemplate(ctx, domainName, templateName, auditRef, caller);
            metric.stopTiming(timerMetric);

        } catch (Exception exc) {
            
            StringBuilder sb = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
            sb.append(":caller specified templatename=(").append(templateName).append(")");
            auditRequestFailure(ctx, exc, domainName, domainName, caller, ZMSConsts.HTTP_DELETE,
                    sb.toString(), auditRef);
            throw exc;
        }

        return null;
    }
    
    // ----------------- end of the Domain interface }

    Principal createPrincipalForName(String principalName) {
        
        String domain = null;
        String name = null;
        
        /* if we have no . in the principal name we're going to default to standard user */
        
        int idx = principalName.lastIndexOf('.');
        if (idx == -1) {
            domain = userDomain;
            name = principalName;
        } else {
            domain = principalName.substring(0, idx);
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
        
        AthenzDomain domain = null;
        try {
            domain = dbService.getAthenzDomain(domainName);
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
        
        if (!principal.getFullName().equals(domainName)) {
            return null;
        }
        
        return virtualHomeDomain(principal);
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
        
        if (!userDomain.equals(ZMSConsts.USER_DOMAIN) && resource.startsWith(ZMSConsts.USER_DOMAIN_PREFIX)) {
            resource = userDomain + resource.substring(ZMSConsts.USER_DOMAIN_PREFIX.length());
        }
        
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
            throw new com.yahoo.athenz.common.server.rest.ResourceException(ResourceException.NOT_FOUND, "Domain not found");
        }
        AthenzDomain domain = retrieveAccessDomain(domainName, principal);
        if (domain == null) {
            throw new com.yahoo.athenz.common.server.rest.ResourceException(ResourceException.NOT_FOUND, "Domain not found");
        }
        
        AccessStatus accessStatus = hasAccess(domain, action, resource, principal, trustDomain);
        if (accessStatus == AccessStatus.ALLOWED) {
            return true;
        }
        
        return false;
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
        
        String domainName = null;
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

        validate(action, TYPE_COMPOUND_NAME, caller);
        
        return getAccessCheck(((RsrcCtxWrapper) ctx).principal(), action, resource,
                trustDomain, checkPrincipal);
    }
    
    public Access getAccess(ResourceContext ctx, String action, String resource,
            String trustDomain, String checkPrincipal) {

        final String caller = "getaccess";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

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
        
        // start our counter with domain dimension. we're moving the metric here
        // after the domain name has been confirmed as valid since with
        // dimensions we get stuck with persistent indexes so we only want
        // to create them for valid domain names

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getaccess_timing", domainName);

        /* if the check principal is given then we need to carry out the access
         * check against that principal */
        
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

    // ----------------- the Entity interface

    boolean equalToOrPrefixedBy(String pattern, String name) {
        if (name.equals(pattern)) {
            return true;
        }
        if (name.startsWith(pattern + ".")) {
            return true;
        }
        return false;
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
    
    public Entity putEntity(ResourceContext ctx, String domainName, String entityName, String auditRef, Entity resource) {
        
        final String caller = "putentity";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
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

        } catch (Exception exc) {
            
            auditRequestFailure(ctx, exc, domainName, entityName, caller, ZMSConsts.HTTP_PUT, null, auditRef);
            throw exc;
        }

        return null;
    }

    @Override
    public EntityList getEntityList(ResourceContext ctx, String domainName) {
        
        final String caller = "getentitylist";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

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
    
    public Entity deleteEntity(ResourceContext ctx, String domainName, String entityName, String auditRef) {
        
        final String caller = "deleteentity";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }
        
        try {
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

        } catch (Exception exc) {
            
            auditRequestFailure(ctx, exc, domainName, entityName, caller, ZMSConsts.HTTP_DELETE, null, auditRef);
            throw exc;
        }
        return null;
    }

    public ServerTemplateList getServerTemplateList(ResourceContext ctx) {
        
        final String caller = "getservertemplatelist";
        metric.increment(ZMSConsts.HTTP_GET);
        metric.increment(ZMSConsts.HTTP_REQUEST);
        metric.increment(caller);
        Object timerMetric = metric.startTiming("getservertemplatelist_timing", null);
        logPrincipal(ctx);

        ServerTemplateList result = new ServerTemplateList();
        result.setTemplateNames(new ArrayList<String>(serverSolutionTemplates.names()));

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

        validate(templateName, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        templateName = templateName.toLowerCase();
        Template template = serverSolutionTemplates.get(templateName);
        if (template == null) {
            throw ZMSUtils.notFoundError("getTemplate: Template not found: '" + templateName + "'", caller);
        }
        
        metric.stopTiming(timerMetric);
        return template;
    }

    // ----------------- the Role interface
    
    public RoleList getRoleList(ResourceContext ctx, String domainName, Integer limit, String skip) {
        
        final String caller = "getrolelist";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

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
        
        List<String> names = new ArrayList<String>();
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
        
        List<Role> roles = null;
        if (members != null && members.booleanValue()) {
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
    public Role getRole(ResourceContext ctx, String domainName, String roleName,
            Boolean auditLog, Boolean expand) {
        
        final String caller = "getrole";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

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

    RoleMember getNormalizedMember(RoleMember member) {
        
        String[] resourceParts = member.getMemberName().split(":");
        if (resourceParts.length != 2) {
            return member;
        }
        
        // we are going we normalize and use the common name to
        // represent our principals. The changes are:
        // user:hga will be replaced with user.hga
        // coretech:service.storage will be replaced with coretech.storage
        
        RoleMember normalizedMember = member;
        if (resourceParts[0].equalsIgnoreCase(userDomain)) {
            normalizedMember.setMemberName(userDomainPrefix + resourceParts[1]);
        } else if (resourceParts[1].startsWith(SERVICE_PREFIX)) {
            normalizedMember.setMemberName(resourceParts[0] + resourceParts[1].substring(SERVICE_PREFIX.length() - 1));
        }
        
        return normalizedMember;
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
        role.setRoleMembers(new ArrayList<RoleMember>(normalizedMembers.values()));
        return;
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
    
    public Role putRole(ResourceContext ctx, String domainName, String roleName, String auditRef, Role role) {
        
        final String caller = "putrole";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
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
            
        } catch (Exception exc) {

            auditRequestFailure(ctx, exc, domainName, roleName, caller, ZMSConsts.HTTP_PUT, null, auditRef);
            throw exc;
        }

        return null;
    }
    
    public Role deleteRole(ResourceContext ctx, String domainName, String roleName, String auditRef) {
        
        final String caller = "deleterole";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
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

        } catch (Exception exc) {
            
            auditRequestFailure(ctx, exc, domainName, roleName, caller, ZMSConsts.HTTP_DELETE, null, auditRef);
            throw exc;
        }

        return null;
    }

    boolean checkRoleMemberExpiration(List<RoleMember> roleMembers, String member) {
        
        boolean isMember = false;
        for (RoleMember memberInfo: roleMembers) {
            String memberName = memberInfo.getMemberName();
            Timestamp expiration = memberInfo.getExpiration();
            if (memberName.equals(member)) {
                // check expiration, if is not defined, its not expired.
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

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);
        validate(memberName, TYPE_RESOURCE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        roleName = roleName.toLowerCase();
        memberName = memberName.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        Object timerMetric = metric.startTiming("getmembership_timing", domainName);

        Membership result = dbService.getMembership(domainName, roleName, memberName);
        
        metric.stopTiming(timerMetric);
        return result;
    }
    
    public Membership putMembership(ResourceContext ctx, String domainName, String roleName,
            String memberName, String auditRef, Membership membership) {
        
        final String caller = "putmembership";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
            validate(domainName, TYPE_DOMAIN_NAME, caller);
            validate(roleName, TYPE_ENTITY_NAME, caller);
            validate(memberName, TYPE_RESOURCE_NAME, caller);
            
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

        } catch (Exception exc) {
            
            StringBuilder sb = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
            sb.append(":caller specified memberName=(").append(memberName).append(')');
            auditRequestFailure(ctx, exc, domainName, roleName, caller, ZMSConsts.HTTP_PUT,
                    sb.toString(), auditRef);
            throw exc;
        }

        return null;
    }

    public Membership deleteMembership(ResourceContext ctx, String domainName, String roleName,
            String memberName, String auditRef) {
        
        final String caller = "deletemembership";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
            validate(domainName, TYPE_DOMAIN_NAME, caller);
            validate(roleName, TYPE_ENTITY_NAME, caller);
            validate(memberName, TYPE_RESOURCE_NAME, caller);

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

        } catch (Exception exc) {
            
            StringBuilder sb = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
            sb.append(":caller specified memberName=(").append(memberName).append(')');
            auditRequestFailure(ctx, exc, domainName, roleName, caller, ZMSConsts.HTTP_DELETE,
                    sb.toString(), auditRef);
            throw exc;
        }

        return null;
    }

    boolean hasExceededListLimit(Integer limit, int count) {
        
        if (limit == null) {
            return false;
        }
        
        if (limit > 0 && count > limit) {
            return true;
        } else {
            return false;
        }
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
    
    // ----------------- the Policy interface

    public PolicyList getPolicyList(ResourceContext ctx, String domainName, Integer limit, String skip) {
        
        final String caller = "getpolicylist";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

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
        
        List<String> names = new ArrayList<String>();
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
        
        List<Policy> policies = null;
        if (assertions != null && assertions.booleanValue()) {
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

    public Assertion putAssertion(ResourceContext ctx, String domainName, String policyName,
            String auditRef, Assertion assertion) {
        
        final String caller = "putassertion";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
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

        } catch (Exception exc) {
            
            auditRequestFailure(ctx, exc, domainName, policyName, caller, ZMSConsts.HTTP_PUT, null, auditRef);
            throw exc;
        }

        return assertion;
    }
    
    public Assertion deleteAssertion(ResourceContext ctx, String domainName, String policyName,
            Long assertionId, String auditRef) {
        
        final String caller = "deleteassertion";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
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

        } catch (Exception exc) {
            
            StringBuilder sb = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
            sb.append("assertionId=(").append(assertionId).append(')');
            auditRequestFailure(ctx, exc, domainName, policyName, caller, ZMSConsts.HTTP_DELETE,
                    sb.toString(), auditRef);
            throw exc;
        }

        return null;
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
        
        String resource = assertion.getResource();
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
    
    public Policy putPolicy(ResourceContext ctx, String domainName, String policyName, String auditRef, Policy policy) {
        
        final String caller = "putpolicy";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
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

        } catch (Exception exc) {
            
            auditRequestFailure(ctx, exc, domainName, policyName, caller, ZMSConsts.HTTP_PUT, null, auditRef);
            throw exc;
        }

        return null;
    }
    
    String auditListItems(String heading, List<String> items) {
        StringBuilder sb = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
        sb.append(':').append(heading).append("=(");
        boolean firstEntry = true;
        if (items != null) {
            for (String item : items) {
                if (!firstEntry) {
                    sb.append(',');
                } else {
                    firstEntry = false;
                }
                sb.append('\"').append(item).append('\"');
            }
        }
        sb.append(')');
        return sb.toString();
    }
    
    void auditRequestFailure(ResourceContext ctx, Exception exc, String domainName, String resourceName,
            String caller, String method, String addlDetails, String auditRef) {
        
        AuditLogMsgBuilder msgBldr = getAuditLogMsgBuilder(ctx, domainName, auditRef, caller, method);
        Timestamp when = Timestamp.fromCurrentTime();
        msgBldr.when(when.toString()).whatEntity(resourceName);
        StringBuilder sb = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
        sb.append("ERROR=(");
        if (exc instanceof ResourceException) {
            ResourceError err = (ResourceError) ((ResourceException) exc).getData();
            sb.append(err.message);
        } else {
            sb.append(exc.getMessage());
        }
        sb.append(')');
        if (addlDetails != null) {
            sb.append(';').append(addlDetails);
        }
        msgBldr.whatDetails(sb.toString());
        auditLogger.log(msgBldr);
    }
    
    public Policy deletePolicy(ResourceContext ctx, String domainName, String policyName, String auditRef) {
        
        final String caller = "deletepolicy";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
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

        } catch (Exception exc) {
            
            auditRequestFailure(ctx, exc, domainName, policyName, caller, ZMSConsts.HTTP_DELETE, null, auditRef);
            throw exc;
        }

        return null;
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

    AthenzDomain virtualHomeDomain(Principal principal) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("homeDomain: home domain detected. Create on the fly.");
        }
        
        String name = principal.getFullName();
        AthenzDomain athenzDomain = new AthenzDomain(name);
        
        List<String> adminUsers = new ArrayList<>();
        adminUsers.add(name);
        
        Role role = ZMSUtils.makeAdminRole(name, adminUsers);
        athenzDomain.getRoles().add(role);
        
        Policy policy = ZMSUtils.makeAdminPolicy(name, role);
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
        
        boolean matchResult = false;
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
        
        // verify that we have a valid endpoint that ends in
        // yahoo domain. if it's not present or an empty
        // value then there is no field to verify
        
        if (providerEndpoint == null) {
            return true;
        }
        
        if (providerEndpoint.isEmpty()) {
            return true;
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("verifyProviderEndpoint: verifying endpoint: " + providerEndpoint);
        }
        
        java.net.URI uri = null;
        try {
            uri = new java.net.URI(providerEndpoint);
        } catch (URISyntaxException ex) {
            return false;
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("verifyProviderEndpoint: host: " + uri.getHost() + " scheme: " + uri.getScheme());
        }
        
        // we're going to allow localhost as a special case since
        // that's often used for dev testing
        
        String host = uri.getHost();
        if (host == null) {
            return false;
        }
        host = host.toLowerCase();
        
        boolean valid = host.equals(ZMSConsts.LOCALHOST);
        if (!valid && providerEndpoints != null) {
            for (String endpoint : providerEndpoints) {
                valid = host.endsWith(endpoint);
                if (valid) {
                    break;
                }
            }
        }
        
        if (valid) {
            String scheme = uri.getScheme();
            if (scheme == null) {
                return false;
            }
            valid = scheme.equalsIgnoreCase(ZMSConsts.HTTP_SCHEME) ||
                    scheme.equalsIgnoreCase(ZMSConsts.HTTPS_SCHEME);
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
        
        // verify that the public keys specified are valid public
        // key and we require that at least one key is provided
        
        List<PublicKeyEntry> publicKeyList = service.getPublicKeys();
        if (publicKeyList == null || publicKeyList.size() == 0) {
            return false;
        }
        for (PublicKeyEntry entry : publicKeyList) {
            if (!verifyServicePublicKey(entry.getKey())) {
                return false;
            }
        }
        return true;
    }
    
    // ----------------- the ServiceIdentity interface
    
    public ServiceIdentity putServiceIdentity(ResourceContext ctx, String domainName, String serviceName,
            String auditRef, ServiceIdentity service) {
        
        final String caller = "putserviceidentity";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
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
            
            // verify that request is properly authenticated for this request
            
            verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
            
            if (!ZMSUtils.serviceResourceName(domainName, serviceName).equals(service.getName())) {
                throw ZMSUtils.requestError("putServiceIdentity: Inconsistent service/domain names", caller);
            }
            
            if (!verifyServicePublicKeys(service)) {
                throw ZMSUtils.requestError("putServiceIdentity: No valid public key found or provided public key is invalid", caller);
            }

            if (!verifyProviderEndpoint(service.getProviderEndpoint())) {
                throw ZMSUtils.requestError("putServiceIdentity: Invalid endpoint: "
                    + service.getProviderEndpoint() + " - must be http/https and in yahoo domain", caller);
            }
            
            dbService.executePutServiceIdentity(ctx, domainName, serviceName, service, auditRef, caller);
            metric.stopTiming(timerMetric);

        } catch (Exception exc) {
            
            auditRequestFailure(ctx, exc, domainName, serviceName, caller, ZMSConsts.HTTP_PUT, null, auditRef);
            throw exc;
        }

        return null;
    }
    
    public ServiceIdentity getServiceIdentity(ResourceContext ctx, String domainName, String serviceName) {
        
        final String caller = "getserviceidentity";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

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
    
    public ServiceIdentity deleteServiceIdentity(ResourceContext ctx, String domainName,
            String serviceName, String auditRef) {
        
        final String caller = "deleteserviceidentity";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
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

        } catch (Exception exc) {
            
            auditRequestFailure(ctx, exc, domainName, serviceName, caller, ZMSConsts.HTTP_DELETE, null, auditRef);
            throw exc;
        }

        return null;
    }

    List<ServiceIdentity> setupServiceIdentityList(AthenzDomain domain, Boolean publicKeys, Boolean hosts) {
        
        // if we're asked to return the public keys and hosts as well then we
        // just need to return the data as is without any modifications
        
        List<ServiceIdentity> services = null;
        if (publicKeys != null && publicKeys.booleanValue() && hosts != null && hosts.booleanValue()) {
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
                if (publicKeys != null && publicKeys.booleanValue()) {
                    newService.setPublicKeys(service.getPublicKeys());
                } else if (hosts != null && hosts.booleanValue()) {
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
        
        List<String> names = new ArrayList<String>();
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
        
        PublicKeyEntry entry = dbService.getServicePublicKeyEntry(domainName, serviceName, keyId);
        if (entry == null) {
            throw ZMSUtils.notFoundError("getPublicKeyEntry: PublicKey " + keyId + " in service " +
                    ZMSUtils.serviceResourceName(domainName, serviceName) + " not found", caller);
        }
        
        metric.stopTiming(timerMetric);
        return entry;
    }
    
    public PublicKeyEntry deletePublicKeyEntry(ResourceContext ctx, String domainName, String serviceName,
            String keyId, String auditRef) {
        
        final String caller = "deletepublickeyentry";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }
        
        try {
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

        } catch (Exception exc) {
            
            StringBuilder sb = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
            sb.append(":caller specified keyId=(").append(keyId).append(')');
            auditRequestFailure(ctx, exc, domainName, serviceName, caller, ZMSConsts.HTTP_DELETE,
                    sb.toString(), auditRef);
            throw exc;
        }

        return null;
    }
    
    public PublicKeyEntry putPublicKeyEntry(ResourceContext ctx, String domainName, String serviceName, 
            String keyId, String auditRef, PublicKeyEntry keyEntry) {
        
        final String caller = "putpublickeyentry";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
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

        } catch (Exception exc) {
            
            StringBuilder sb = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
            sb.append(":caller specified keyId=(").append(keyId).append(')');
            auditRequestFailure(ctx, exc, domainName, serviceName, caller, ZMSConsts.HTTP_PUT,
                    sb.toString(), auditRef);
            throw exc;
        }

        return null;
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
            LOG.debug("getModTimestamp: matching tag (" + matchingTag + ")");
        }
        
        try {
            Timestamp tagStamp = Timestamp.fromString(matchingTag);
            if (tagStamp == null) {
                throw new IllegalArgumentException("Timestamp failed");
            }
            timestamp = tagStamp.millis();
        } catch (IllegalArgumentException exc) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("getModTimestamp: matching tag(" + matchingTag + ") has bad format. Return -1L by default.");
            }
        }
        
        return timestamp;
    }
    
    // SignedDomains interface
    public void getSignedDomains(ResourceContext ctx, String domain, String metaOnly,
            String matchingTag, GetSignedDomainsResult result) {

        final String caller = "getsigneddomains";
        metric.increment(ZMSConsts.HTTP_GET);
        metric.increment(ZMSConsts.HTTP_REQUEST);
        metric.increment(caller);
        Object timerMetric = metric.startTiming("getsigneddomains_timing", null);
        logPrincipal(ctx);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        if (domain != null) {
            domain = domain.toLowerCase();
        }
        
        boolean setMetaDataOnly = false;
        if (metaOnly != null) {
            // only true or false is valid
            setMetaDataOnly = metaOnly.trim().equalsIgnoreCase("true");
            if (LOG.isDebugEnabled()) {
                LOG.debug("getSignedDomains: metaonly: " + metaOnly, caller);
            }
        }
        
        long timestamp = getModTimestamp(matchingTag);
        
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
            result.done(304, matchingTag);
        }

        Long youngestDomMod = -1L;
        List<SignedDomain> sdList = new ArrayList<SignedDomain>();

        // now we can iterate through our list and retrieve each domain
        
        boolean domainFilterDone = false;
        for (DomainModified dmod : modlist) {
            
            // if we were processing only our given domain then
            // we can stop iterating through the list if the
            // filter done flag has been set
            
            if (domainFilterDone) {
                break;
            }
            
            // if we're given a specific domain then ignore all others
            
            if (domain != null && !domain.isEmpty()) {
                if (domain.compareToIgnoreCase(dmod.getName()) != 0) {
                    continue;
                }
                domainFilterDone = true;
            }
            
            Long domModMillis = dmod.getModified();
            if (domModMillis.compareTo(youngestDomMod) > 0) {
                youngestDomMod = domModMillis;
            }
            
            // generate our signed domain object
                
            SignedDomain signedDomain = new SignedDomain();
            DomainData domainData = new DomainData().setName(dmod.getName());
            signedDomain.setDomain(domainData);
            domainData.setModified(Timestamp.fromMillis(dmod.getModified()));
            
            // check if we're asked to only return the meta data which
            // we already have - name and last modified time, so we can
            // add the domain to our return list and continue with the
            // next domain
            
            if (setMetaDataOnly) {
                sdList.add(signedDomain);
                continue;
            }
            
            // get the policies, roles, and service identities to create the
            // DomainData

            if (LOG.isDebugEnabled()) {
                LOG.debug("getSignedDomains: retrieving domain " + dmod.getName());
            }
            
            AthenzDomain athenzDomain = getAthenzDomain(dmod.getName(), true);
            
            // it's possible that our domain was deleted by another
            // thread while we were processing this request so
            // if we get a null object, we'll just skip this 
            // item and continue with the next one
            
            if (athenzDomain == null) {
                continue;
            }

            // we have a valid domain so first we need to add
            // our object to the return list
            
            sdList.add(signedDomain);

            // set domain attributes
            
            domainData.setAccount(athenzDomain.getDomain().getAccount());
            domainData.setYpmId(athenzDomain.getDomain().getYpmId());
            domainData.setRoles(athenzDomain.getRoles());
            domainData.setServices(athenzDomain.getServices());
            
            // generate the domain policy object that includes the domain
            // name and all policies. Then we'll sign this struct using
            // server's private key to get signed policy object
            
            DomainPolicies domainPolicies = new DomainPolicies().setDomain(dmod.getName());
            domainPolicies.setPolicies(getPolicyListWithoutAssertionId(athenzDomain.getPolicies()));
            SignedPolicies signedPolicies = new SignedPolicies();
            signedPolicies.setContents(domainPolicies);
            domainData.setPolicies(signedPolicies);

            String signature = Crypto.sign(SignUtils.asCanonicalString(signedDomain.getDomain().getPolicies().getContents()), privateKey);
            signedDomain.getDomain().getPolicies().setSignature(signature).setKeyId(privateKeyId);

            // then sign the data and set the data and signature in a SignedDomain
            
            signature = Crypto.sign(SignUtils.asCanonicalString(signedDomain.getDomain()), privateKey);
            signedDomain.setSignature(signature).setKeyId(privateKeyId);
        }

        SignedDomains sdoms = new SignedDomains();
        sdoms.setDomains(sdList);

        Timestamp youngest = Timestamp.fromMillis(youngestDomMod);
        EntityTag eTag = new EntityTag(youngest.toString());

        metric.stopTiming(timerMetric);
        result.done(200, sdoms, eTag.toString());
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
    
    public UserToken getUserToken(ResourceContext ctx, String userName, String authorizedServices) {

        final String caller = "getusertoken";
        metric.increment(ZMSConsts.HTTP_GET);
        metric.increment(ZMSConsts.HTTP_REQUEST);
        metric.increment(caller);
        Object timerMetric = metric.startTiming("getusertoken_timing", null);
        logPrincipal(ctx);

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
        
        // if the user must be requesting authorized service token
        
        if (authorizedServices == null || authorizedServices.isEmpty()) {
            throw ZMSUtils.requestError("optionsUserToken: No authorized services specified in the request", caller);
        }
        
        // verify that all specified services are valid
        
        List<String> services = Arrays.asList(authorizedServices.split(","));
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

    void setStandardCORSHeaders(ResourceContext ctx) {

        // if we get an Origin header in our request then we're going to return
        // the same value in the Allow-Origin header otherwise we'll just
        // return * value to match everything
        
        String origin = ctx.request().getHeader(ZMSConsts.HTTP_ORIGIN);
        if (origin != null && !origin.isEmpty()) {
            ctx.response().addHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        } else {
            ctx.response().addHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_ORIGIN, "*");
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

    // Tenancy interface

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

    ProviderClient getProviderClient(String url, Principal tenantAdmin) {
        
        final String caller = "getproviderclient";
        
        ProviderClient prov = null;
        if (providerClass == null) {
            prov = new ProviderClient(url);
            prov.addCredentials(tenantAdmin.getAuthority().getHeader(), tenantAdmin.getCredentials());
        } else {
            try {
                prov = providerClass.getConstructor(new Class[] { String.class, Principal.class })
                        .newInstance(url, tenantAdmin);
            } catch (Exception e) {
                throw ZMSUtils.requestError("getProviderClient: Provider Class does not have the appropriate constructor", caller);
            }
        }
        
        return prov;
    }
    
    public Tenancy putTenancy(ResourceContext ctx, String tenantDomain, String provider,
            String auditRef, Tenancy detail) {

        final String caller = "puttenancy";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
            validate(tenantDomain, TYPE_DOMAIN_NAME, caller);
            validate(provider, TYPE_SERVICE_NAME, caller); //the fully qualified service name to provision on

            // for consistent handling of all requests, we're going to convert
            // all incoming object values into lower case (e.g. domain, role,
            // policy, service, etc name)
            
            tenantDomain = tenantDomain.toLowerCase();
            provider = provider.toLowerCase();
            AthenzObject.TENANCY.convertToLowerCase(detail);

            metric.increment(ZMSConsts.HTTP_REQUEST, tenantDomain);
            metric.increment(caller, tenantDomain);
            Object timerMetric = metric.startTiming("puttenancy_timing", tenantDomain);

            // verify that request is properly authenticated for this request
            
            String authorizedService = ((RsrcCtxWrapper) ctx).principal().getAuthorizedService();
            verifyAuthorizedServiceOperation(authorizedService, caller);

            final String logPrefix = "putTenancy: tenant domain(" + tenantDomain + "): ";
            
            if (LOG.isInfoEnabled()) {
                LOG.info("---- BEGIN put Tenant on provider(" + provider + ", ...)");
            }
            
            String provSvcDomain = providerServiceDomain(provider); // provider service domain
            String provSvcName = providerServiceName(provider); // provider service name

            ServiceIdentity ent = dbService.getServiceIdentity(provSvcDomain, provSvcName);
            if (ent == null) {
                throw ZMSUtils.requestError(logPrefix + "Unable to retrieve service=" + provider, caller);
            }
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("serviceIdentity: provider=" + ent);
            }
            
            // we are going to allow the authorize service token owner to call
            // put tenancy on its own service without configuring a controller
            // end point
            
            boolean authzServiceTokenOperation = isAuthorizedProviderService(authorizedService,
                provSvcDomain, provSvcName, tenantDomain, auditRef);
            
            String url = ent.getProviderEndpoint();
            if ((url == null || url.isEmpty()) && !authzServiceTokenOperation) {
                throw ZMSUtils.requestError(logPrefix + "Cannot put tenancy on provider service=" +
                    provider + " -- not a provider service", caller);
            }
            
            if (LOG.isInfoEnabled()) {
                LOG.info("let's talk to the provider on this endpoint: " + url);
            }

            //ok, set up the policy for trust so the provider can check it
            
            if (LOG.isInfoEnabled()) {
                LOG.info("---- set up the ASSUME_ROLE for admin, so provider can check I'm an admin");
            }
            
            // set up our tenant admin policy so provider can check admin's access
            
            dbService.setupTenantAdminPolicy(ctx, tenantDomain, provSvcDomain,
                    provSvcName, auditRef, caller);
            
            // if this is an authorized service token request then we're going to create
            // the corresponding admin role in the provider domain since that's been
            // authenticated already. otherwise, we're going to continue and process
            // a standard provider controller based implementation when we contact the
            // controller to complete the tenancy request
            
            if (authzServiceTokenOperation) {
                
                List<TenantRoleAction> roles = new ArrayList<>();
                TenantRoleAction roleAction = new TenantRoleAction().setAction("*").setRole(ADMIN_ROLE_NAME);
                roles.add(roleAction);
                dbService.executePutTenantRoles(ctx, provSvcDomain, provSvcName, tenantDomain, null,
                    roles, auditRef, caller);
                
            } else {
                
                Principal tenantAdmin = ((RsrcCtxWrapper) ctx).principal();
                if (LOG.isInfoEnabled()) {
                    LOG.info("---- now tell the provider to setTenant, as " + tenantAdmin.getFullName()
                        + ", creds = " + tenantAdmin.getCredentials());
                }
                
                Tenant tenant = new Tenant().setService(provSvcName).setName(tenantDomain);
                Tenant tenantWithRoles = null;
                try {
                    ProviderClient prov = getProviderClient(url, tenantAdmin);
                    tenantWithRoles = prov.putTenant(provSvcName, tenantDomain, auditRef, tenant);
                } catch (Exception exc) {
                    throw ZMSUtils.requestError(logPrefix + "Failed to put tenant on provider service("
                            + provider + "): " + exc.getMessage(), caller);
                }
                
                if (LOG.isInfoEnabled()) {
                    LOG.info("---- result of provider.putTenant: " + tenantWithRoles);
                }
                
                // now set up the roles and policies for all the provider roles returned
                // if the provider supports resource groups, during the putTenant call
                // we're just setting up tenancy and as such we won't get back any roles
                
                List<String> providerRoles = tenantWithRoles.getRoles();
                if (providerRoles != null && !providerRoles.isEmpty()) {
                    
                    // we're going to create a separate role for each one of tenant roles returned
                    // based on its action and set the caller as a member in each role
                    
                    dbService.executePutProviderRoles(ctx, tenantDomain, provSvcDomain, provSvcName, null,
                        providerRoles, auditRef, caller);
                }
            }
            
            if (LOG.isInfoEnabled()) {
                LOG.info("---- END put Tenant -> " + detail);
            }

            metric.stopTiming(timerMetric);
            
        } catch (Exception exc) {
            
            StringBuilder sb = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
            sb.append(":caller specified tenant-domain-(").append(tenantDomain).append(')');
            auditRequestFailure(ctx, exc, tenantDomain, provider, caller, ZMSConsts.HTTP_PUT,
                    sb.toString(), auditRef);
            throw exc;
        }
        
        return null;
    }
    
    public TenancyResourceGroup putTenancyResourceGroup(ResourceContext ctx, String tenantDomain, String provider,
            String resourceGroup, String auditRef, TenancyResourceGroup detail) {

        final String caller = "puttenancyresourcegroup";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
            validate(tenantDomain, TYPE_DOMAIN_NAME, caller);
            validate(provider, TYPE_SERVICE_NAME, caller); //the fully qualified service name to provision on
            validate(resourceGroup, TYPE_COMPOUND_NAME, caller);
            
            // for consistent handling of all requests, we're going to convert
            // all incoming object values into lower case (e.g. domain, role,
            // policy, service, etc name)
            
            tenantDomain = tenantDomain.toLowerCase();
            provider = provider.toLowerCase();
            resourceGroup = resourceGroup.toLowerCase();
            AthenzObject.TENANCY_RESOURCE_GROUP.convertToLowerCase(detail);

            metric.increment(ZMSConsts.HTTP_REQUEST, tenantDomain);
            metric.increment(caller, tenantDomain);
            Object timerMetric = metric.startTiming("puttenancyresourcegroup_timing", tenantDomain);
            
            // verify that request is properly authenticated for this request
            
            verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("putTenancyResourceGroup: tenant domain(" + tenantDomain
                        + ") resourceGroup(" + resourceGroup + ")");
            }
            
            String provSvcDomain = providerServiceDomain(provider); // provider service domain
            String provSvcName = providerServiceName(provider); // provider service name

            ServiceIdentity ent = dbService.getServiceIdentity(provSvcDomain, provSvcName);
            if (ent == null) {
                throw ZMSUtils.requestError("Unable to retrieve service=" + provider, caller);
            }
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("serviceIdentity: provider=" + ent);
            }
            String url = ent.getProviderEndpoint();
            if (url == null || url.isEmpty()) {
                throw ZMSUtils.requestError("Cannot put tenancy resource group on provider service="
                    + provider + " -- not a provider service", caller);
            }
            
            Principal tenantAdmin = ((RsrcCtxWrapper) ctx).principal();
            
            TenantResourceGroup tenantResourceGroup = new TenantResourceGroup();
            tenantResourceGroup.setService(provSvcName).setName(tenantDomain).setResourceGroup(resourceGroup);
            
            TenantResourceGroup tenantWithRoles = null;
            try {
                ProviderClient prov = getProviderClient(url, tenantAdmin);
                tenantWithRoles = prov.putTenantResourceGroup(provSvcName, tenantDomain, resourceGroup,
                    auditRef, tenantResourceGroup);
            } catch (Exception exc) {
                throw ZMSUtils.requestError("Failed to put tenant resource group(" + resourceGroup +
                    ") on provider service(" + provider + "): " + exc.getMessage(), caller);
            }
            
            if (LOG.isInfoEnabled()) {
                LOG.info("---- result of provider.putTenantResourceGroup: " + tenantWithRoles);
            }

            List<String> providerRoles = tenantWithRoles.getRoles();
            if (providerRoles == null || providerRoles.isEmpty()) {
                throw ZMSUtils.requestError("Provider Controller did not return any roles to provision", caller);
            }
            
            // we're going to create a separate role for each one of tenant roles returned
            // based on its action and set the caller as a member in each role
            
            dbService.executePutProviderRoles(ctx, tenantDomain, provSvcDomain, provSvcName, resourceGroup,
                providerRoles, auditRef, caller);
            
            if (LOG.isInfoEnabled()) {
                LOG.info("---- END put Tenant Resource Group -> " + detail);
            }
            
            metric.stopTiming(timerMetric);
            
        } catch (Exception exc) {
            
            StringBuilder sb = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
            sb.append(":caller specified resource-group=(").append(resourceGroup).append(')');
            auditRequestFailure(ctx, exc, tenantDomain, provider, caller, ZMSConsts.HTTP_PUT,
                    sb.toString(), auditRef);
            throw exc;
        }
        
        return null;
    }
    
    boolean verifyTenancyPolicies(String tenantDomain, List<String> tenantPolicies, Set<String> providerPolicies,
            String provSvcDomain, String provSvcName, String resourceGroup) {
        
        // generate the tenant policy name
        
        StringBuilder nameBuilder = new StringBuilder(256);
        nameBuilder.append("tenancy.")
            .append(ZMSUtils.getProviderResourceGroupRolePrefix(provSvcDomain, provSvcName, resourceGroup));
        String pnamePrefix = nameBuilder.toString();
        String rsrcMatchStr = ":role.";
        int rsrcMatchStrLen = rsrcMatchStr.length();

        String provPolName = null;
        for (String pname : tenantPolicies) {
            if (pname.startsWith(pnamePrefix)) {
                Policy pol = dbService.getPolicy(tenantDomain,  pname);
                if (pol == null) {
                    break;
                }
                List<Assertion> assertions = pol.getAssertions();
                if (assertions != null) {
                    for (Assertion assertion : assertions) {
                        if (ZMSConsts.ACTION_ASSUME_ROLE.equalsIgnoreCase(assertion.getAction())) {
                            String rsrc = assertion.getResource();
                            // parse rsrc, ex: "weather:role.storage.tenant.sports.deleter"
                            int index = rsrc.indexOf(rsrcMatchStr);
                            if (index > -1) {
                                rsrc = rsrc.substring(index + rsrcMatchStrLen);
                            }
                            provPolName = rsrc;
                            break;
                        }
                    }
                }
            }
        }

        if (provPolName == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("verifyTenancyPolicies: No ASSUME_ROLE with policy prefix: " + pnamePrefix);
            }
            return false;
        }
        
        // verify the tenant is in the provider too
        // look for the policy in the provider
        
        if (!providerPolicies.contains(provPolName)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("verifyTenancyPolicies: No tenant policy in provider: " + provPolName);
            }
            return false;
        }
        
        return true;
    }
    
    public Tenancy getTenancy(ResourceContext ctx, String tenantDomain, String providerService) {
        
        final String caller = "gettenancy";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validate(tenantDomain, TYPE_DOMAIN_NAME, caller);
        validate(providerService, TYPE_SERVICE_NAME, caller); // fully qualified provider's service name

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        tenantDomain = tenantDomain.toLowerCase();
        providerService = providerService.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, tenantDomain);
        metric.increment(caller, tenantDomain);
        Object timerMetric = metric.startTiming("gettenancy_timing", tenantDomain);
        
        // first verify that we have a valid tenant domain with policies
        
        Domain domain = dbService.getDomain(tenantDomain);
        if (domain == null) {
            throw ZMSUtils.notFoundError("getTenancy: No such tenant domain: " + tenantDomain, caller);
        }

        // we need to contact the provider to retrieve tenancy details
        // since we don't know if the provider supports resource groups
        // and as such the policies we have are for tenant's subdomains
        // or for tenant's domain with resource groups.
        
        String provSvcDomain = providerServiceDomain(providerService);
        String provSvcName = providerServiceName(providerService);
        
        Domain providerDomain = dbService.getDomain(provSvcDomain);
        if (providerDomain == null) {
            throw ZMSUtils.requestError("getTenancy: No such provider domain: " + provSvcDomain, caller);
        }
        
        // now retrieve our provider service object

        ServiceIdentity service = dbService.getServiceIdentity(provSvcDomain, provSvcName);
        if (service == null) {
            throw ZMSUtils.requestError("getTenancy: unable to retrieve service=" + providerService, caller);
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("getTenancy: serviceIdentity: provider=" + service);
        }
        
        // contact the provider and get the tenant object
        
        String url = service.getProviderEndpoint();
        if (url == null || url.isEmpty()) {
            throw ZMSUtils.requestError("getTenancy: cannot get tenancy on provider service="
                    + providerService + " -- not a provider service", caller);
        }
        
        Principal tenantAdmin = ((RsrcCtxWrapper) ctx).principal();
        Tenant tenant = null;
        try {
            ProviderClient prov = getProviderClient(url, tenantAdmin);
            tenant = prov.getTenant(provSvcName, tenantDomain);
        } catch (ResourceException exc) {
            // if we have a ZMS ResourceException then let's throw it
            // as is so that the client knows that the provider returned
            throw exc;
        } catch (Exception exc) {
            throw ZMSUtils.requestError("getTenancy: failed to get tenant on provider service("
                    + providerService + "): " + exc.getMessage(), caller);
        }
        
        if (tenant == null) {
            throw ZMSUtils.notFoundError("getTenancy: Provider reports no such tenant: " + tenantDomain, caller);
        }
        
        if (LOG.isInfoEnabled()) {
            LOG.info("getTenancy: ---- result of provider.getTenant: " + tenant);
        }
        
        // now we are going to verify to make sure that both tenant
        // and provider domains have the appropriate policies. however we
        // are not going to reject any requests because of missing policies
        // and instead for resource group support we'll just not report
        // the resource group as a valid provisioned one.
        
        Tenancy tenancy = new Tenancy();
        tenancy.setDomain(tenantDomain).setService(providerService);
        List<String> resourceGroups = tenant.getResourceGroups();
        if (resourceGroups != null) {
            List<String> tenantPolicies = dbService.listPolicies(tenantDomain);
            Set<String> providerPolicies = new HashSet<>(dbService.listPolicies(provSvcDomain));
            List<String> tenancyResouceGroups = new ArrayList<>();
            for (String resourceGroup : resourceGroups) {
                if (!verifyTenancyPolicies(tenantDomain, tenantPolicies, providerPolicies,
                        provSvcDomain, provSvcName, resourceGroup)) {
                    if (LOG.isInfoEnabled()) {
                        LOG.info("getTenancy: Invalid Resource Group: " + resourceGroup
                                + " for tenant: " + tenantDomain);
                    }
                } else {
                    tenancyResouceGroups.add(resourceGroup);
                }
            }
            tenancy.setResourceGroups(tenancyResouceGroups);
        }

        metric.stopTiming(timerMetric);
        return tenancy;
    }
    
    public Tenancy deleteTenancy(ResourceContext ctx, String tenantDomain, String provider, String auditRef) {
        
        final String caller = "deletetenancy";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
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
            
            // for delete tenant operation we're going to go through the steps of
            // lookup up provider's service object and make sure it has an endpoint
            // configured and we can talk to it and request the tenant to be deleted
            // if any of these operations fail, we're not going to reject the request
            // but rather continue on and do the local cleanup. However, at the end
            // we're going to return an exception with an error message stating exactly
            // what failed so the administrator can go ahead and contact the provider
            // manually, if necessary, to complete the delete tenancy process

            String errorMessage = null;

            // before local clean-up, we're going to contact the provider at their
            // configured endpoint and request the tenant to be deleted. We need
            // to do this before the local cleanup in ZMS because provider rdl
            // has an authorize statement to validate that the specified domain
            // is a valid tenant for the given provider.
            
            String provSvcDomain = providerServiceDomain(provider);
            String provSvcName   = providerServiceName(provider);

            // we are going to allow the authorize service token owner to call
            // delete tenancy on its own service without configuring a controller
            // end point
            
            boolean authzServiceTokenOperation = isAuthorizedProviderService(authorizedService,
                provSvcDomain, provSvcName, tenantDomain, auditRef);
            
            // if this is an authorized service token operation there is no
            // need to go through the provider check since the provider
            // already handled that part
            
            if (authzServiceTokenOperation) {

                dbService.executeDeleteTenantRoles(ctx, provSvcDomain, provSvcName, tenantDomain, null,
                    auditRef, caller);
                
            } else {
                
                ServiceIdentity provSvcId = dbService.getServiceIdentity(provSvcDomain, provSvcName);
                if (provSvcId == null) {
                    errorMessage = "service does not exist";
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("provider serviceIdentity(" + provSvcId + ")");
                    }
                    
                    String url = provSvcId.getProviderEndpoint();
                    if (url == null || url.isEmpty()) {
                        errorMessage = "service does not have endpoint configured";
                    } else {
                        if (LOG.isInfoEnabled()) {
                        LOG.info("Tenant will contact provider at endpoint: " + url);
                        }
                        
                        try {
                            Principal tenantAdmin = ((RsrcCtxWrapper) ctx).principal();
                            ProviderClient prov = getProviderClient(url, tenantAdmin);
                            prov.deleteTenant(provSvcName, tenantDomain, auditRef);
                        } catch (Exception exc) {
                            errorMessage = "failed to delete tenant. Error: " + exc.getMessage();
                        }
                    }
                }
            }

            // now clean-up local domain roles and policies for this tenant
            
            dbService.executeDeleteTenancy(ctx, tenantDomain, provSvcDomain, provSvcName,
                    null, auditRef, caller);

            metric.stopTiming(timerMetric);
            
            // so if we have an error message then we're going to throw an exception
            // otherwise the operation was completed successfully
            
            if (errorMessage != null) {
                final String tenantCleanupMsg = "deleteTenancy: Tenant cleanup in(" + tenantDomain + "): ";
                throw ZMSUtils.requestError(tenantCleanupMsg + "completed successfully. However, there "
                    + "was an error when contacting the Provider Service: " + provider + ":"
                    + errorMessage + ". Please contact the Provider administrator directly "
                    + "to complete this delete tenancy request", caller);
            }
            
        } catch (Exception exc) {
            
            auditRequestFailure(ctx, exc, tenantDomain, provider, caller, ZMSConsts.HTTP_DELETE, null, auditRef);
            throw exc;
        }
        
        return null;
    }
    
    public TenancyResourceGroup deleteTenancyResourceGroup(ResourceContext ctx, String tenantDomain,
            String provider, String resourceGroup, String auditRef) {
        
        final String caller = "deletetenancyresourcegroup";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
            validate(tenantDomain, TYPE_DOMAIN_NAME, caller);
            validate(provider, TYPE_SERVICE_NAME, caller); // fully qualified provider's service name
            validate(resourceGroup, TYPE_COMPOUND_NAME, caller);
            
            // for consistent handling of all requests, we're going to convert
            // all incoming object values into lower case (e.g. domain, role,
            // policy, service, etc name)
            
            tenantDomain = tenantDomain.toLowerCase();
            provider = provider.toLowerCase();
            resourceGroup = resourceGroup.toLowerCase();

            metric.increment(ZMSConsts.HTTP_REQUEST, tenantDomain);
            metric.increment(caller, tenantDomain);
            Object timerMetric = metric.startTiming("deletetenancyresourcegroup_timing", tenantDomain);

            // verify that request is properly authenticated for this request
            
            verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
            
            // for delete tenant resource group operation we're going to go through
            // the steps of lookup up provider's service object and make sure it has
            // an endpoint configured and we can talk to it and request the tenant
            // resource group to be deleted. if any of these operations fail, we're not
            // going to reject the request but rather continue on and do the local cleanup.
            // However, at the end we're going to return an exception with an error message
            // stating exactly what failed so the administrator can go ahead and contact
            // the provider manually, if necessary, to complete the delete tenancy
            // resource group process

            String errorMessage = null;
            
            // before local clean-up, we're going to contact the provider at their
            // configured endpoint and request the tenant resource group to be deleted.
            
            String provSvcDomain = providerServiceDomain(provider);
            String provSvcName   = providerServiceName(provider);

            ServiceIdentity provSvcId = dbService.getServiceIdentity(provSvcDomain, provSvcName);
            if (provSvcId == null) {
                errorMessage = "service does not exist";
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("provider serviceIdentity(" + provSvcId + ")");
                }

                String url = provSvcId.getProviderEndpoint();
                if (url == null) {
                    errorMessage = "service does not have endpoint configured";
                } else {
                    if (LOG.isInfoEnabled()) {
                        LOG.info("Tenant will contact provider at endpoint: " + url);
                    }

                    try {
                        Principal tenantAdmin = ((RsrcCtxWrapper) ctx).principal();
                        ProviderClient prov = getProviderClient(url, tenantAdmin);
                        prov.deleteTenantResourceGroup(provSvcName, tenantDomain, resourceGroup, auditRef);
                    } catch (Exception exc) {
                        errorMessage = "failed to delete tenant resource group. Error: " + exc.getMessage();
                    }
                }
            }

            // now clean-up local domain roles and policies for this tenant
            
            dbService.executeDeleteTenancy(ctx, tenantDomain, provSvcDomain, provSvcName,
                    resourceGroup, auditRef, caller);

            metric.stopTiming(timerMetric);
            
            // so if we have an error message then we're going to throw an exception
            // otherwise the operation was completed successfully
            
            if (errorMessage != null) {
                final String tenantCleanupMsg = "Tenant cleanup in(" + tenantDomain + "): ";
                throw ZMSUtils.requestError(tenantCleanupMsg + "completed successfully. However, there "
                    + "was an error when contacting the Provider Service: " + provider + ":"
                    + errorMessage + ". Please contact the Provider administrator directly "
                    + "to complete this delete tenancy resource group request", caller);
            }

        } catch (Exception exc) {
            
            StringBuilder sb = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
            sb.append(":caller specified resource-group=(").append(resourceGroup).append(')');
            auditRequestFailure(ctx, exc, tenantDomain, provider, caller, ZMSConsts.HTTP_DELETE,
                    sb.toString(), auditRef);
            throw exc;
        }
        
        return null;
    }
    
    long sleepBeforeRetryingRequest(long millisToExpire, long sleepTimeout, String caller) {
         
        // before sleeping we're going to check to see if it makes
        // sense since if the while loop is going to break out then
        // there is no point of us sleeping now
         
        if (millisToExpire <= 0) {
            return sleepTimeout;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug(caller + ": concurrent update exception, retry after " + sleepTimeout + "ms");
        }
        
        try {
            Thread.sleep(sleepTimeout);
        } catch (InterruptedException e) {
        }
        
        // since we know we're going to retry our operation next
        // lets increment our domain update retry counter
        
        metric.increment("domainupdateretry");
         
        // we're going to sleep a bit longer after each iteration
        // so our next timeout is twice as long

        return (2 * sleepTimeout);
    }

    public TenantRoles putTenantRoles(ResourceContext ctx, String provSvcDomain, String provSvcName,
            String tenantDomain, String auditRef, TenantRoles detail) {
             
        final String caller = "puttenantroles";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        try {
            validate(provSvcDomain, TYPE_DOMAIN_NAME, caller);
            validate(provSvcName, TYPE_SIMPLE_NAME, caller); //not including the domain, this is the domain's service
            validate(tenantDomain, TYPE_DOMAIN_NAME, caller);
            validate(detail, TYPE_TENANT_ROLES, caller);

            // for consistent handling of all requests, we're going to convert
            // all incoming object values into lower case (e.g. domain, role,
            // policy, service, etc name)
            
            provSvcDomain = provSvcDomain.toLowerCase();
            provSvcName = provSvcName.toLowerCase();
            tenantDomain = tenantDomain.toLowerCase();
            AthenzObject.TENANT_ROLES.convertToLowerCase(detail);

            metric.increment(ZMSConsts.HTTP_REQUEST, provSvcDomain);
            metric.increment(caller, provSvcDomain);
            Object timerMetric = metric.startTiming("puttenantroles_timing", provSvcDomain);

            // verify that request is properly authenticated for this request
            
            verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
            
            if (LOG.isInfoEnabled()) {
                LOG.info("putTenantRoles: ==== putTenantRoles(domain=" + provSvcDomain + ", service=" +
                provSvcName + ", tenant-domain=" + tenantDomain + ", detail=" + detail + ")");
            }
            
            List<TenantRoleAction> roles = detail.getRoles();
            if (roles == null || roles.size() == 0) {
                throw ZMSUtils.requestError("putTenantRoles: must include at least one role", caller);
            }
            
            dbService.executePutTenantRoles(ctx, provSvcDomain, provSvcName, tenantDomain, null,
                roles, auditRef, caller);
            metric.stopTiming(timerMetric);

        } catch (Exception exc) {
            
            StringBuilder sb = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
            sb.append(":caller specified provider-service=(").append(provSvcName).append(')');
            auditRequestFailure(ctx, exc, provSvcDomain, tenantDomain, caller, ZMSConsts.HTTP_PUT,
                    sb.toString(), auditRef);
            throw exc;
        }
        
        return detail;
    }
     
    // put the trust roles into provider domain
    //
    public TenantResourceGroupRoles putTenantResourceGroupRoles(ResourceContext ctx, String provSvcDomain,
            String provSvcName, String tenantDomain, String resourceGroup, String auditRef,
            TenantResourceGroupRoles detail) {

        final String caller = "puttenantresourcegrouproles";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
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
            
            List<TenantRoleAction> roles = detail.getRoles();
            if (roles == null || roles.size() == 0) {
                throw ZMSUtils.requestError("putTenantResourceGroupRoles: must include at least one role", caller);
            }
            
            dbService.executePutTenantRoles(ctx, provSvcDomain, provSvcName, tenantDomain,
                    resourceGroup, roles, auditRef, caller);
            metric.stopTiming(timerMetric);

        } catch (Exception exc) {
            
            StringBuilder sb = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
            sb.append(":caller specified resource-group=(").append(resourceGroup).append(')');
            auditRequestFailure(ctx, exc, provSvcDomain, tenantDomain, caller, ZMSConsts.HTTP_PUT,
                    sb.toString(), auditRef);
            throw exc;
        }

        return detail;
    }

    public DomainDataCheck getDomainDataCheck(ResourceContext ctx, String domainName) {
        
        final String caller = "getdomaindatacheck";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

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
        
        Map<String, Set<String>> trustRoleMap = new HashMap<String, Set<String>>();
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
                Set<String> tset = trustRoleMap.get(trustDomain);
                if (tset == null) {
                    tset = new HashSet<String>();
                    trustRoleMap.put(trustDomain, tset);
                }
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
        
        Map<String, Set<String>> svcRoleMap = new HashMap<String, Set<String>>();
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
                    Set<String> rset = svcRoleMap.get(provSvcDomain);
                    if (rset == null) {
                        rset = new HashSet<String>();
                        svcRoleMap.put(provSvcDomain, rset);
                    }
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
                    if (wildCardMatch == false) { // dangling policy
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
            // ohoh, some roles are unused - need to subtract the usedRoleSet
            // from roleSet - the leftovers are the unused roles
            roleSet.removeAll(usedRoleSet);
            // we need to remove the domain:role. prefix according to
            // RDL definition for dangling role names
            List<String> danglingRoleList = new ArrayList<String>();
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
            String provSvcDomain = null;
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

        // tenantsWithoutProv: names of Tenant domains that dont contain assume
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
                // didnt find all required matching provider trust-role to assume_role-resource pairs
                tenantsWithoutProv.add(trustRole);
            }
        }
        if (!tenantsWithoutProv.isEmpty()) {
            ddc.setTenantsWithoutAssumeRole(tenantsWithoutProv);
        }

        metric.stopTiming(timerMetric);
        return ddc;
    }
     
    public ProviderResourceGroupRoles deleteProviderResourceGroupRoles(ResourceContext ctx, String tenantDomain,
             String provSvcDomain, String provSvcName, String resourceGroup, String auditRef) {
         
        final String caller = "deleteproviderresourcegrouproles";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }
        
        try {
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
            if (isAuthorizedProviderService(authorizedService, provSvcDomain, provSvcName,
                tenantDomain, auditRef)) {
             
                dbService.executeDeleteTenantRoles(ctx, provSvcDomain, provSvcName, tenantDomain,
                    resourceGroup, auditRef, caller);
            }

            metric.stopTiming(timerMetric);
            
        } catch (Exception exc) {
            
            StringBuilder sb = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
            sb.append(":caller specified provider-service=(").append(provSvcName)
                .append(");resource-group=(").append(resourceGroup).append(")");
            auditRequestFailure(ctx, exc, tenantDomain, provSvcDomain, caller, ZMSConsts.HTTP_DELETE,
                    sb.toString(), auditRef);
            throw exc;
        }
         
        return null;
    }

    public ProviderResourceGroupRoles getProviderResourceGroupRoles(ResourceContext ctx, String tenantDomain,
            String provSvcDomain, String provSvcName, String resourceGroup) {

        final String caller = "getproviderresourcegrouproles";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

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

        Domain domain = dbService.getDomain(tenantDomain);
        if (domain == null) {
            throw ZMSUtils.notFoundError("No such domain: " + tenantDomain, caller);
        }

        // look for this provider roles, ex: storage.tenant.sports.reader

        String rolePrefix = ZMSUtils.getProviderResourceGroupRolePrefix(provSvcDomain, provSvcName, resourceGroup);
        ProviderResourceGroupRoles provRoles = new ProviderResourceGroupRoles().setDomain(provSvcDomain)
                .setService(provSvcName).setTenant(tenantDomain).setResourceGroup(resourceGroup);

        List<TenantRoleAction> tralist = new ArrayList<TenantRoleAction>();

        // find roles matching the prefix

        List<String> rcollection = dbService.listRoles(tenantDomain);
        for (String rname: rcollection) {

            if (dbService.isTenantRolePrefixMatch(rname, rolePrefix, null)) {

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
             String provSvcName, String tenantDomain, String auditRef) {
        
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
         // authorize ("UPDATE", "{domain}:tenant.{tenantDomain}");

         AthenzDomain domain = getAthenzDomain(provSvcDomain, true);
         if (domain == null) {
             return false;
         }
         
         // evaluate our domain's roles and policies to see if access
         // is allowed or not for the given operation and resource
         
         String resource = provSvcDomain + ":tenant." + tenantDomain;
         AccessStatus accessStatus = evaluateAccess(domain, authorizedService, "update",
                 resource, null, null);
         
         if (accessStatus == AccessStatus.ALLOWED) {
             return true;
         } else {
             return false;
         }
    }
     
    /**
     * This sets up the assume roles in the tenant. If the tenants admin user
     * token has been authorized by the provider, the providers domain will be
     * updated as well, thus completing the tenancy on-boarding in a single step.
    **/
    public ProviderResourceGroupRoles putProviderResourceGroupRoles(ResourceContext ctx, String tenantDomain,
             String provSvcDomain, String provSvcName, String resourceGroup, String auditRef,
             ProviderResourceGroupRoles detail) {

        final String caller = "putproviderresourcegrouproles";
        metric.increment(ZMSConsts.HTTP_PUT);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
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
            
            dbService.setupTenantAdminPolicy(ctx, tenantDomain, provSvcDomain, provSvcName, auditRef, caller);
            
            // now we're going to setup our roles
            
            List<TenantRoleAction> roleActions = detail.getRoles();
            if (roleActions == null || roleActions.size() == 0) {
                throw ZMSUtils.requestError("putProviderResourceGroupRoles: must include at least one role", caller);
            }
            
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
            if (isAuthorizedProviderService(authorizedService, provSvcDomain, provSvcName,
                tenantDomain, auditRef)) {
                
                dbService.executePutTenantRoles(ctx, provSvcDomain, provSvcName, tenantDomain,
                        resourceGroup, roleActions, auditRef, caller);
            }

            metric.stopTiming(timerMetric);
            
        } catch (Exception exc) {
            
            StringBuilder sb = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
            sb.append(":caller specified provider-service=(").append(provSvcName)
                .append(");resource-group=(").append(resourceGroup).append(")");
            auditRequestFailure(ctx, exc, tenantDomain, provSvcDomain, caller, ZMSConsts.HTTP_PUT,
                    sb.toString(), auditRef);
            throw exc;
        }

        return detail;
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

    public TenantRoles getTenantRoles(ResourceContext ctx, String provSvcDomain, String provSvcName,
            String tenantDomain) {
        
        final String caller = "gettenantroles";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

        validate(provSvcDomain, TYPE_DOMAIN_NAME, caller);
        validate(provSvcName, TYPE_SIMPLE_NAME, caller); // not including the domain, this is the domain's service type
        validate(tenantDomain, TYPE_DOMAIN_NAME, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        provSvcDomain = provSvcDomain.toLowerCase();
        provSvcName = provSvcName.toLowerCase();
        tenantDomain = tenantDomain.toLowerCase();

        metric.increment(ZMSConsts.HTTP_REQUEST, provSvcDomain);
        metric.increment(caller, provSvcDomain);
        Object timerMetric = metric.startTiming("gettenantroles_timing", provSvcDomain);
        
        // look for this tenants roles, ex: storage.tenant.sports.reader
        String rolePrefix = ZMSUtils.getTenantResourceGroupRolePrefix(provSvcName, tenantDomain, null);
        TenantRoles troles = new TenantRoles().setDomain(provSvcDomain).setService(provSvcName)
                .setTenant(tenantDomain);

        Domain domain = dbService.getDomain(provSvcDomain);
        if (domain == null) {
            throw ZMSUtils.notFoundError("getTenantRoles: No such domain: " + provSvcDomain, caller);
        }

        List<TenantRoleAction> tralist = new ArrayList<TenantRoleAction>();
        
        // find roles matching the prefix
        List<String> rcollection = dbService.listRoles(provSvcDomain);
        for (String rname: rcollection) {
            if (dbService.isTrustRoleForTenant(provSvcDomain, rname, rolePrefix, tenantDomain)) {
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
    
    public TenantResourceGroupRoles getTenantResourceGroupRoles(ResourceContext ctx, String provSvcDomain,
            String provSvcName, String tenantDomain, String resourceGroup) {
        
        final String caller = "gettenantresourcegrouproles";
        metric.increment(ZMSConsts.HTTP_GET);
        logPrincipal(ctx);

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

        // look for this tenants roles, ex: storage.tenant.sports.reader

        String rolePrefix = ZMSUtils.getTenantResourceGroupRolePrefix(provSvcName, tenantDomain, resourceGroup);
        TenantResourceGroupRoles troles = new TenantResourceGroupRoles().setDomain(provSvcDomain)
                .setService(provSvcName).setTenant(tenantDomain).setResourceGroup(resourceGroup);

        Domain domain = dbService.getDomain(provSvcDomain);
        if (domain == null) {
            throw ZMSUtils.notFoundError("getTenantResourceGroupRoles: No such domain: " + provSvcDomain, caller);
        }
        
        List<TenantRoleAction> tralist = new ArrayList<TenantRoleAction>();
        
        // find roles matching the prefix
        
        List<String> rcollection = dbService.listRoles(provSvcDomain);
        for (String rname: rcollection) {
            if (dbService.isTrustRoleForTenant(provSvcDomain, rname, rolePrefix, tenantDomain)) {
                
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
    
    public TenantRoles deleteTenantRoles(ResourceContext ctx, String provSvcDomain, String provSvcName,
            String tenantDomain, String auditRef) {
        
        final String caller = "deletetenantroles";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
            validate(provSvcDomain, TYPE_DOMAIN_NAME, caller);
            validate(provSvcName, TYPE_SIMPLE_NAME, caller); // not including the domain, this is the domain's service type
            validate(tenantDomain, TYPE_DOMAIN_NAME, caller);
            
            // for consistent handling of all requests, we're going to convert
            // all incoming object values into lower case (e.g. domain, role,
            // policy, service, etc name)
            
            provSvcDomain = provSvcDomain.toLowerCase();
            provSvcName = provSvcName.toLowerCase();
            tenantDomain = tenantDomain.toLowerCase();

            metric.increment(ZMSConsts.HTTP_REQUEST, provSvcDomain);
            metric.increment(caller, provSvcDomain);
            Object timerMetric = metric.startTiming("deletetenantroles_timing", provSvcDomain);

            // verify that request is properly authenticated for this request
            
            verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
            
            dbService.executeDeleteTenantRoles(ctx, provSvcDomain, provSvcName, tenantDomain,
                    null, auditRef, caller);
            metric.stopTiming(timerMetric);

        } catch (Exception exc) {
            
            StringBuilder sb = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
            sb.append(":caller specified provider-service=(").append(provSvcName).append(')');
            auditRequestFailure(ctx, exc, provSvcDomain, tenantDomain, caller, ZMSConsts.HTTP_DELETE,
                    sb.toString(), auditRef);
            throw exc;
        }

        return null;
    }

    public TenantResourceGroupRoles deleteTenantResourceGroupRoles(ResourceContext ctx, String provSvcDomain,
            String provSvcName, String tenantDomain, String resourceGroup, String auditRef) {
        
        final String caller = "deletetenantresourcegrouproles";
        metric.increment(ZMSConsts.HTTP_DELETE);
        logPrincipal(ctx);

        if (readOnlyMode) {
            throw ZMSUtils.requestError("Server in Maintenance Read-Only mode. Please try your request later", caller);
        }

        try {
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

        } catch (Exception exc) {
            
            StringBuilder sb = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
            sb.append(":caller specified provider-service=(").append(provSvcName).append(')');
            auditRequestFailure(ctx, exc, provSvcDomain, tenantDomain, caller, ZMSConsts.HTTP_DELETE,
                    sb.toString(), auditRef);
            throw exc;
        }

        return null;
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
        return new ArrayList<String>(users);
    }
    
    Domain createTopLevelDomain(ResourceContext ctx, String domainName, String description,
            String org, Boolean auditEnabled, List<String> adminUsers, String account,
            int productId, List<String> solutionTemplates, String auditRef) {
        List<String> users = validatedAdminUsers(adminUsers);
        return dbService.makeDomain(ctx, domainName, description, org, auditEnabled, 
                users, account, productId, solutionTemplates, auditRef);
    }
    
    Domain createSubDomain(ResourceContext ctx, String parentName, String name, String description,
            String org, Boolean auditEnabled, List<String> adminUsers, String account,
            int productId, List<String> solutionTemplates, String auditRef, String caller) {

        // verify length of full sub domain name
        String fullSubDomName = parentName + "." + name;
        if (fullSubDomName.length() > domainNameMaxLen) {
            throw ZMSUtils.requestError("Invalid SubDomain name: " + fullSubDomName + " : name length cannot exceed: " + domainNameMaxLen, caller);
        } 

        List<String> users = validatedAdminUsers(adminUsers);
        return dbService.makeDomain(ctx, fullSubDomName, description, org, auditEnabled,
                users, account, productId, solutionTemplates, auditRef);
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
        
        if (countDots(name) > depth) {
            return true;
        } else {
            return false;
        }
    }
    
    DomainList listDomains(Integer limit, String skip, String prefix, Integer depth, long modTime) {
            
        //note: we don't use the store's options, because we also need to filter on depth
        
        List<String> allDomains = dbService.listDomains(prefix, modTime);
        List<String> names = new ArrayList<String>();
        
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
                PublicKeyEntry keyEntry = dbService.getServicePublicKeyEntry(domain, service, keyId);
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
    public DefaultAdmins putDefaultAdmins(ResourceContext ctx, String domainName, String auditRef,
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

        try {
            validate(domainName, TYPE_DOMAIN_NAME, caller);

            // verify that request is properly authenticated for this request
            
            verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);
            
            // for consistent handling of all requests, we're going to convert
            // all incoming object values into lower case (e.g. domain, role,
            // policy, service, etc name)
            
            domainName = domainName.toLowerCase();
            AthenzObject.DEFAULT_ADMINS.convertToLowerCase(defaultAdmins);
            
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
                adminRole = ZMSUtils.makeAdminRole(domainName, new ArrayList<String>());
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

        } catch (Exception exc) {
            
            String auditDetails = auditListItems("caller specified default-admins", defaultAdmins.getAdmins());
            auditRequestFailure(ctx, exc, domainName, domainName, caller, ZMSConsts.HTTP_PUT,
                    auditDetails, auditRef);
            throw exc;
        }

        metric.stopTiming(timerMetric);
        return null;
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

        // we need to make sure we're only validating service/user tokens
        // so any thing that's been authenticated by the PrincipalAuthority
        // and/or authorities that do not support authorization
        
        ServicePrincipal servicePrincipal = null;
        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        Authority authority = principal.getAuthority();

        metric.increment(ZMSConsts.HTTP_REQUEST, principal.getDomain());
        metric.increment(caller, principal.getDomain());
        Object timerMetric = metric.startTiming("getserviceprincipal_timing", principal.getDomain());

        // If the authority is our PrincipalAuthority, then we're not making
        // any changes and sending the authenticated token as is. However,
        // if the authority does not support authorization then we're going to
        // generate a new ServiceToken signed by ZMS and send that back.
        
        if (authority instanceof com.yahoo.athenz.auth.impl.PrincipalAuthority) {
            
            servicePrincipal = new ServicePrincipal();
            servicePrincipal.setDomain(principal.getDomain());
            servicePrincipal.setService(principal.getName());
            servicePrincipal.setToken(principal.getCredentials());
            
        } else if (!authority.allowAuthorization()) {
            
            PrincipalToken sdToken = new PrincipalToken(principal.getCredentials());
            PrincipalToken zmsToken = new PrincipalToken.Builder("S1", sdToken.getDomain(), sdToken.getName())
                .issueTime(sdToken.getTimestamp())
                .expirationWindow(sdToken.getExpiryTime() - sdToken.getTimestamp())
                .ip(sdToken.getIP()).keyId(privateKeyId).host(serverHostName)
                .keyService(ZMSConsts.ZMS_SERVICE).build();
            zmsToken.sign(privateKey);
            servicePrincipal = new ServicePrincipal();
            servicePrincipal.setDomain(principal.getDomain());
            servicePrincipal.setService(principal.getName());
            servicePrincipal.setToken(zmsToken.getSignedToken());
            
        } else {
            throw ZMSUtils.requestError("getServicePrincipal: Provided Token is not a Service/User Token", caller);
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
        
        // if the list is empty then we allow all the operations
        ArrayList<AllowedOperation> ops = authzService.getAllowedOperations();
        if (ops == null || ops.isEmpty()) {
            return;
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
                    + (opItemType != null && opItemType != "" ? " on opItemKey " + opItemType + " and opItemVal " + opItemVal : ""),
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

        Principal ctxPrincipal = ((RsrcCtxWrapper) ctx).principal();
        if (LOG.isDebugEnabled()) {
            LOG.debug("getResourceAccessList:(" + ctxPrincipal + ", " + principal
                    + ", " + action + ")");
        }
        
        if (principal != null) {
            validate(principal, TYPE_ENTITY_NAME, caller);
            principal = principal.toLowerCase();
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

    void logPrincipal(ResourceContext ctx) {
        final Principal principal = ((RsrcCtxWrapper) ctx).principal();
        if (principal != null) {
            ctx.request().setAttribute(AthenzRequestLog.REQUEST_PRINCIPAL, principal.getFullName());
        }
    }
    
    static class RsrcCtxWrapper implements ResourceContext {

        com.yahoo.athenz.common.server.rest.ResourceContext ctx = null;

        RsrcCtxWrapper(HttpServletRequest request,
                       HttpServletResponse response,
                       Http.AuthorityList authList, Authorizer authorizer) {
            ctx = new com.yahoo.athenz.common.server.rest.ResourceContext(request,
                    response, authList, authorizer);
        }

        com.yahoo.athenz.common.server.rest.ResourceContext context() {
            return ctx;
        }

        Principal principal() {
            return ctx.principal();
        }

        @Override
        public HttpServletRequest request() {
            return ctx.request();
        }

        @Override
        public HttpServletResponse response() {
            return ctx.response();
        }

        @Override
        public void authenticate() {
            try {
                ctx.authenticate();
            } catch (com.yahoo.athenz.common.server.rest.ResourceException restExc) {
                throwZmsException(restExc);
            }
        }

        @Override
        public void authorize(String action, String resource, String trustedDomain) {
            try {
                ctx.authorize(action, resource, trustedDomain);
            } catch (com.yahoo.athenz.common.server.rest.ResourceException restExc) {
                throwZmsException(restExc);
            }
        }

        void throwZmsException(com.yahoo.athenz.common.server.rest.ResourceException restExc) {
            String msg  = null;
            Object data = restExc.getData();
            if (data instanceof String) {
                msg = (String) data;
            }
            if (msg == null) {
                msg = restExc.getMessage();
            }
            throw new com.yahoo.athenz.zms.ResourceException(restExc.getCode(),
                    new ResourceError().code(restExc.getCode()).message(msg));
        }
    }

    public ResourceContext newResourceContext(HttpServletRequest request,
            HttpServletResponse response) {
        return new RsrcCtxWrapper(request, response, authorities, this);
    }
    
    @Override
    public Schema getRdlSchema(ResourceContext context) {
        return schema;
    }
}
