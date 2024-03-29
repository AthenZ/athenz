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

import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.primitives.Bytes;
import com.oath.auth.KeyRefresherException;
import com.yahoo.athenz.auth.*;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.StringUtils;
import com.yahoo.athenz.common.config.AuthzDetailsEntity;
import com.yahoo.athenz.common.config.AuthzDetailsField;
import com.yahoo.athenz.common.messaging.ChangePublisher;
import com.yahoo.athenz.common.messaging.ChangePublisherFactory;
import com.yahoo.athenz.common.messaging.DomainChangeMessage;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.metrics.MetricFactory;
import com.yahoo.athenz.common.server.audit.AuditReferenceValidator;
import com.yahoo.athenz.common.server.audit.AuditReferenceValidatorFactory;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.log.AuditLoggerFactory;
import com.yahoo.athenz.common.server.metastore.DomainMetaStore;
import com.yahoo.athenz.common.server.metastore.DomainMetaStoreFactory;
import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import com.yahoo.athenz.common.server.notification.NotificationToEmailConverterCommon;
import com.yahoo.athenz.common.server.rest.Http;
import com.yahoo.athenz.common.server.rest.Http.AuthorityList;
import com.yahoo.athenz.common.server.status.StatusCheckException;
import com.yahoo.athenz.common.server.status.StatusChecker;
import com.yahoo.athenz.common.server.status.StatusCheckerFactory;
import com.yahoo.athenz.common.server.util.AuthzHelper;
import com.yahoo.athenz.common.server.util.ConfigProperties;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.common.server.util.ServletRequestUtil;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigCsv;
import com.yahoo.athenz.common.server.util.config.providers.ConfigProviderFile;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zms.config.*;
import com.yahoo.athenz.zms.notification.PutGroupMembershipNotificationTask;
import com.yahoo.athenz.zms.notification.PutRoleMembershipNotificationTask;
import com.yahoo.athenz.zms.notification.ZMSNotificationTaskFactory;
import com.yahoo.athenz.zms.provider.DomainDependencyProviderResponse;
import com.yahoo.athenz.zms.provider.ServiceProviderClient;
import com.yahoo.athenz.zms.provider.ServiceProviderManager;
import com.yahoo.athenz.zms.purge.PurgeResourcesEnum;
import com.yahoo.athenz.zms.store.*;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import com.yahoo.rdl.UUID;
import com.yahoo.rdl.*;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.core.EntityTag;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.RuntimeDelegate;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.yahoo.athenz.common.ServerCommonConsts.METRIC_DEFAULT_FACTORY_CLASS;
import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.common.server.util.config.ConfigManagerSingleton.CONFIG_MANAGER;
import static com.yahoo.athenz.zms.ZMSConsts.PROVIDER_RESPONSE_DENY;
import static com.yahoo.athenz.zms.ZMSConsts.ZMS_PROP_DOMAIN_CHANGE_TOPIC_NAMES;

public class ZMSImpl implements Authorizer, KeyStore, ZMSHandler {

    private static final Logger LOG = LoggerFactory.getLogger(ZMSImpl.class);
    private static final RuntimeDelegate.HeaderDelegate<EntityTag> ENTITY_TAG_HEADER_DELEGATE =
            RuntimeDelegate.getInstance().createHeaderDelegate(EntityTag.class);

    private static String ROOT_DIR;

    private static final String ROLE_PREFIX = "role.";
    private static final String POLICY_PREFIX = "policy.";

    private static final String ADMIN_POLICY_NAME = "admin";
    private static final String ADMIN_ROLE_NAME = "admin";

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
    private static final String TYPE_GROUP_MEMBERSHIP = "GroupMembership";
    private static final String TYPE_QUOTA = "Quota";
    private static final String TYPE_ROLE_SYSTEM_META = "RoleSystemMeta";
    private static final String TYPE_ROLE_META = "RoleMeta";
    private static final String TYPE_SERVICE_IDENTITY_SYSTEM_META = "ServiceIdentitySystemMeta";
    private static final String TYPE_RESOURCE_NAMES = "ResourceNames";
    private static final String TYPE_AUTHORITY_KEYWORD = "AuthorityKeyword";
    private static final String TYPE_AUTHORITY_KEYWORDS = "AuthorityKeywords";
    private static final String TYPE_GROUP = "Group";
    private static final String TYPE_GROUP_SYSTEM_META = "GroupSystemMeta";
    private static final String TYPE_GROUP_META = "GroupMeta";
    private static final String TYPE_ASSERTION_CONDITIONS = "AssertionConditions";
    private static final String TYPE_ASSERTION_CONDITION = "AssertionCondition";
    private static final String TYPE_POLICY_OPTIONS = "PolicyOptions";
    private static final String TYPE_TAG_KEY = "TagKey";
    private static final String TYPE_TAG_COMPOUND_VALUE = "TagCompoundValue";

    private static final String SERVER_READ_ONLY_MESSAGE = "Server in Maintenance Read-Only mode. Please try your request later";

    private static final byte[] PERIOD = { 46 };

    public static Metric metric;
    public static String serverHostName  = null;

    protected DBService dbService = null;
    protected Schema schema = null;
    protected ServerPrivateKey privateKey = null;
    protected ServerPrivateKey privateECKey = null;
    protected ServerPrivateKey privateRSAKey = null;
    protected int userTokenTimeout = 3600;
    protected boolean virtualDomainSupport = true;
    protected boolean productIdSupport = false;
    protected int virtualDomainLimit = 2;
    protected long signedPolicyTimeout;
    protected int domainNameMaxLen;
    protected AuthorizedServices serverAuthorizedServices = null;
    protected SolutionTemplates serverSolutionTemplates = null;
    protected List<String> serverSolutionTemplateNames = null;
    protected Map<String, String> serverPublicKeyMap = null;
    protected DynamicConfigBoolean readOnlyMode;
    protected DynamicConfigBoolean validateServiceRoleMembers;
    protected DynamicConfigBoolean validateUserRoleMembers;
    protected DynamicConfigBoolean validatePolicyAssertionRoles;
    protected DynamicConfigBoolean allowUnderscoreInServiceNames;
    protected boolean useMasterCopyForSignedDomains = false;
    protected List<String> validateServiceMemberSkipDomains;
    protected static Validator validator;
    protected String userDomain;
    protected String userDomainPrefix;
    protected String headlessUserDomain;
    protected String headlessUserDomainPrefix;
    protected String homeDomain;
    protected String homeDomainPrefix;
    protected String userDomainAlias;
    protected String userDomainAliasPrefix;
    protected String serverRegion = null;
    protected Set<String> addlUserCheckDomainSet = null;
    protected List<String> addlUserCheckDomainPrefixList = null;
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
    protected Set<String> corsRequestHeaderList = null;
    protected int httpPort;
    protected int httpsPort;
    protected int statusPort;
    protected int serviceNameMinLength;
    protected Status successServerStatus = null;
    protected Set<String> reservedSystemDomains = null;
    protected DynamicConfigCsv reservedDomainNames = null;
    protected File healthCheckFile = null;
    protected AuditReferenceValidator auditReferenceValidator = null;
    protected NotificationManager notificationManager = null;
    protected ObjectMapper jsonMapper;
    protected StatusChecker statusChecker = null;
    protected ObjectStore objectStore = null;
    protected AuthHistoryStore authHistoryStore = null;
    protected ZMSGroupMembersFetcher groupMemberFetcher = null;
    protected DomainMetaStore domainMetaStore = null;
    protected NotificationToEmailConverterCommon notificationToEmailConverterCommon;
    protected List<ChangePublisher<DomainChangeMessage>> domainChangePublishers = new ArrayList<>();
    protected ServiceProviderManager serviceProviderManager;
    protected ServiceProviderClient serviceProviderClient;
    protected Info serverInfo = null;
    protected Set<String> domainContactTypes = new HashSet<>();
    protected Set<String> domainEnvironments = new HashSet<>();
    protected List<String> domainDeleteMetaAttributes = new ArrayList<>();

    // enum to represent our access response since in some cases we want to
    // handle domain not founds differently instead of just returning failure

    enum AccessStatus {
        ALLOWED,
        DENIED,
        DENIED_INVALID_ROLE_TOKEN
    }

    enum AthenzObject {
        ASSERTION {
            @Override
            void convertToLowerCase(Object obj) {
                Assertion assertion = (Assertion) obj;
                boolean isCaseSensitive = (assertion.getCaseSensitive() != null) ? assertion.getCaseSensitive() : false;
                if (isCaseSensitive) {
                    // If flag is set, resource and action should be kept as is. We should still lower the domain part in resource
                    String resourceWithLoweredDomain = ZMSUtils.lowerDomainInResource(assertion.getResource());
                    assertion.setResource(resourceWithLoweredDomain);
                } else {
                    assertion.setAction(assertion.getAction().toLowerCase());
                    assertion.setResource(assertion.getResource().toLowerCase());
                }
                assertion.setRole(assertion.getRole().toLowerCase());
            }
        },
        DEFAULT_ADMINS {
            @Override
            void convertToLowerCase(Object obj) {
                DefaultAdmins defaultAdmins = (DefaultAdmins) obj;
                LIST.convertToLowerCase(defaultAdmins.getAdmins());
            }
        },
        DOMAIN_TEMPLATE {
            @Override
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
            @Override
            void convertToLowerCase(Object obj) {
                DomainTemplateList templates = (DomainTemplateList) obj;
                if (templates != null) {
                    LIST.convertToLowerCase(templates.getTemplateNames());
                }
            }
        },
        ENTITY {
            @Override
            void convertToLowerCase(Object obj) {
                Entity entity = (Entity) obj;
                entity.setName(entity.getName().toLowerCase());
            }
        },
        GROUP {
            @Override
            void convertToLowerCase(Object obj) {
                Group group = (Group) obj;
                group.setName(group.getName().toLowerCase());
                GROUP_MEMBER.convertToLowerCase(group.getGroupMembers());
            }
        },
        GROUP_MEMBER {
            @Override
            void convertToLowerCase(Object obj) {
                @SuppressWarnings("unchecked")
                List<GroupMember> list = (List<GroupMember>) obj;
                if (list != null) {
                    ListIterator<GroupMember> iter = list.listIterator();
                    while (iter.hasNext()) {
                        GroupMember groupMember = iter.next();
                        if (groupMember.getMemberName() != null) {
                            iter.set(groupMember.setMemberName(groupMember.getMemberName().toLowerCase()));
                        }
                        if (groupMember.getGroupName() != null) {
                            iter.set(groupMember.setGroupName(groupMember.getGroupName().toLowerCase()));
                        }
                        if (groupMember.getDomainName() != null) {
                            iter.set(groupMember.setDomainName(groupMember.getDomainName().toLowerCase()));
                        }
                    }
                }
            }
        },
        GROUP_MEMBERSHIP {
            @Override
            void convertToLowerCase(Object obj) {
                GroupMembership membership = (GroupMembership) obj;
                membership.setMemberName(membership.getMemberName().toLowerCase());
                if (membership.getGroupName() != null) {
                    membership.setGroupName(membership.getGroupName().toLowerCase());
                }
            }
        },
        GROUP_META {
            @Override
            void convertToLowerCase(Object obj) {
                GroupMeta groupMeta = (GroupMeta) obj;
                if (groupMeta.getNotifyRoles() != null) {
                    groupMeta.setNotifyRoles(groupMeta.getNotifyRoles().toLowerCase());
                }
            }
        },
        LIST {
            @Override
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
            @Override
            void convertToLowerCase(Object obj) {
                Membership membership = (Membership) obj;
                membership.setMemberName(membership.getMemberName().toLowerCase());
                if (membership.getRoleName() != null) {
                    membership.setRoleName(membership.getRoleName().toLowerCase());
                }
            }
        },
        POLICY {
            @Override
            void convertToLowerCase(Object obj) {
                Policy policy = (Policy) obj;
                policy.setName(policy.getName().toLowerCase());
                if (policy.getAssertions() != null) {
                    boolean isCaseSensitive = (policy.getCaseSensitive() != null && policy.getCaseSensitive());
                    for (Assertion assertion : policy.getAssertions()) {
                        if (isCaseSensitive) {
                            // Only override assertion case-sensitivity if it is true (possible for a policy to have
                            // case-sensitive assertions along with case-insensitive assertions)
                            assertion.setCaseSensitive(true);
                        }
                        ASSERTION.convertToLowerCase(assertion);
                    }
                }
            }
        },
        PROVIDER_RESOURCE_GROUP_ROLES {
            @Override
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
            @Override
            void convertToLowerCase(Object obj) {
                PublicKeyEntry keyEntry = (PublicKeyEntry) obj;
                keyEntry.setId(keyEntry.getId().toLowerCase());
            }
        },
        ROLE {
            @Override
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
        ROLE_META {
            @Override
            void convertToLowerCase(Object obj) {
                RoleMeta roleMeta = (RoleMeta) obj;
                if (roleMeta.getNotifyRoles() != null) {
                    roleMeta.setNotifyRoles(roleMeta.getNotifyRoles().toLowerCase());
                }
                if (roleMeta.getSignAlgorithm() != null) {
                    roleMeta.setSignAlgorithm(roleMeta.getSignAlgorithm().toLowerCase());
                }
            }
        },
        ROLE_MEMBER {
            @Override
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
            @Override
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
            @Override
            void convertToLowerCase(Object obj) {
                SubDomain subdomain = (SubDomain) obj;
                subdomain.setName(subdomain.getName().toLowerCase());
                subdomain.setParent(subdomain.getParent().toLowerCase());
                if (subdomain.getSignAlgorithm() != null) {
                    subdomain.setSignAlgorithm(subdomain.getSignAlgorithm().toLowerCase());
                }
                LIST.convertToLowerCase(subdomain.getAdminUsers());
                DOMAIN_TEMPLATE_LIST.convertToLowerCase(subdomain.getTemplates());
            }
        },
        TENANCY {
            @Override
            void convertToLowerCase(Object obj) {
                Tenancy tenancy = (Tenancy) obj;
                tenancy.setDomain(tenancy.getDomain().toLowerCase());
                tenancy.setService(tenancy.getService().toLowerCase());
                LIST.convertToLowerCase(tenancy.getResourceGroups());
            }
        },
        TENANT_RESOURCE_GROUP_ROLES {
            @Override
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
            @Override
            void convertToLowerCase(Object obj) {
                TenantRoleAction roleAction = (TenantRoleAction) obj;
                roleAction.setAction(roleAction.getAction().toLowerCase());
                roleAction.setRole(roleAction.getRole().toLowerCase());
            }
        },
        TOP_LEVEL_DOMAIN {
            @Override
            void convertToLowerCase(Object obj) {
                TopLevelDomain domain = (TopLevelDomain) obj;
                domain.setName(domain.getName().toLowerCase());
                LIST.convertToLowerCase(domain.getAdminUsers());
                DOMAIN_TEMPLATE_LIST.convertToLowerCase(domain.getTemplates());
                if (domain.getOrg() != null) {
                    domain.setOrg(domain.getOrg().toLowerCase());
                }
                if (domain.getSignAlgorithm() != null) {
                    domain.setSignAlgorithm(domain.getSignAlgorithm().toLowerCase());
                }
            }
        },
        QUOTA {
            @Override
            void convertToLowerCase(Object obj) {
                Quota quota = (Quota) obj;
                quota.setName(quota.getName().toLowerCase());
            }
        },
        USER_DOMAIN {
            @Override
            void convertToLowerCase(Object obj) {
                UserDomain userDomain = (UserDomain) obj;
                userDomain.setName(userDomain.getName().toLowerCase());
                if (userDomain.getSignAlgorithm() != null) {
                    userDomain.setSignAlgorithm(userDomain.getSignAlgorithm().toLowerCase());
                }
                DOMAIN_TEMPLATE_LIST.convertToLowerCase(userDomain.getTemplates());
            }
        },
        DOMAIN_META {
            @Override
            void convertToLowerCase(Object obj) {
                DomainMeta domainMeta = (DomainMeta) obj;
                if (domainMeta.getCertDnsDomain() != null) {
                    domainMeta.setCertDnsDomain(domainMeta.getCertDnsDomain().toLowerCase());
                }
                if (domainMeta.getOrg() != null) {
                    domainMeta.setOrg(domainMeta.getOrg().toLowerCase());
                }
                if (domainMeta.getSignAlgorithm() != null) {
                    domainMeta.setSignAlgorithm(domainMeta.getSignAlgorithm().toLowerCase());
                }
            }
        },
        ASSERTION_CONDITIONS {
            @Override
            void convertToLowerCase(Object obj) {
                AssertionConditions assertionConditions = (AssertionConditions) obj;
                    for (AssertionCondition assertionCondition : assertionConditions.getConditionsList()) {
                        ASSERTION_CONDITION.convertToLowerCase(assertionCondition);
                    }
            }
        },
        ASSERTION_CONDITION {
            @Override
            void convertToLowerCase(Object obj) {
                AssertionCondition assertionCondition = (AssertionCondition) obj;
                // lower case key and value, assertion condition operator is an ENUM, hence left unchanged
                Map<String, AssertionConditionData> lowerCasedMap = new HashMap<>();
                for (Map.Entry<String, AssertionConditionData> assertionConditionDataEntry : assertionCondition.getConditionsMap().entrySet()) {
                    assertionConditionDataEntry.getValue().setValue(assertionConditionDataEntry.getValue().getValue().toLowerCase());
                    lowerCasedMap.put(assertionConditionDataEntry.getKey().toLowerCase(), assertionConditionDataEntry.getValue());
                }
                assertionCondition.setConditionsMap(lowerCasedMap);
            }
        },
        POLICY_OPTIONS {
            @Override
            void convertToLowerCase(Object obj) {
                PolicyOptions policyOptions = (PolicyOptions) obj;
                policyOptions.setVersion(policyOptions.getVersion().toLowerCase());
                if (!StringUtil.isEmpty(policyOptions.getFromVersion())) {
                    policyOptions.setFromVersion(policyOptions.getFromVersion().toLowerCase());
                }
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

        // create our json mapper

        loadJsonMapper();

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

        // load our domain meta store object

        loadDomainMetaStore();

        // check if we need to load any metric support for stats

        loadMetricObject();

        // load the Solution templates

        loadSolutionTemplates();

        // loud authentication history store

        loadAuthHistoryStore();

        // our object store - either mysql or file based

        loadObjectStore();

        // initialize our store with default domains
        // this should only happen when running ZMS in local/debug mode
        // otherwise the store should have been initialized by now

        initObjectStore();

        // load the list of authorized services

        loadAuthorizedServices();

        // retrieve our public keys

        loadServerPublicKeys();

        // make sure to set the keystore for any instance that requires it

        setAuthorityKeyStore();

        // Initialize Notification Manager

        setNotificationManager();

        //autoupdate templates

        autoApplyTemplates();

        // load the StatusChecker

        loadStatusChecker();

        // system disabled from UserAuthority

        initializePrincipalStateUpdater();

        // Initialize Service Provider Manager

        initializeServiceProviderManager();

        // load the DomainChangePublisher
        
        loadDomainChangePublisher();

    }

    void loadJsonMapper() {

        int maxNestingDepth = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_JSON_MAX_NESTING_DEPTH, "1000"));
        int maxNumberLength = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_JSON_MAX_NUMBER_LENGTH, "1000"));
        int maxStringLength = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_JSON_MAX_STRING_LENGTH, "200000000"));

        final StreamReadConstraints streamReadConstraints = StreamReadConstraints.builder()
                .maxNestingDepth(maxNestingDepth)
                .maxNumberLength(maxNumberLength)
                .maxStringLength(maxStringLength).build();
        StreamReadConstraints.overrideDefaultStreamReadConstraints(streamReadConstraints);

        jsonMapper = new ObjectMapper();
    }

    void loadDomainChangePublisher() {
        final String topicNames = System.getProperty(ZMS_PROP_DOMAIN_CHANGE_TOPIC_NAMES, "");
        for (String topic : topicNames.split(",")) {
            topic = topic.trim();
            if (!topic.isEmpty()) {
                ChangePublisher<DomainChangeMessage> publisher = createPublisher(topic);
                if (publisher != null) {
                    domainChangePublishers.add(publisher);
                }
            }
        }
    }

    private ChangePublisher<DomainChangeMessage> createPublisher(String topicName) {
        ChangePublisherFactory<DomainChangeMessage> publisherFactory;
        final String domainChangePublisherClassName = System.getProperty(ZMSConsts.ZMS_PROP_DOMAIN_CHANGE_PUBLISHER_FACTORY_CLASS,
            ZMSConsts.ZMS_PROP_DOMAIN_CHANGE_PUBLISHER_DEFAULT);
        try {
            publisherFactory = (ChangePublisherFactory<DomainChangeMessage>) Class.forName(domainChangePublisherClassName).getDeclaredConstructor().newInstance();
        } catch (Exception ex) {
            LOG.error("unable to initialize publisher factory for: {}", domainChangePublisherClassName, ex);
            return null;
        }
        try {
            return publisherFactory.create(keyStore, topicName);
        } catch (Exception ex) {
            LOG.error("unable to create a publisher for topic: {}", topicName, ex);
        }
        return null;
    }

    private void initializePrincipalStateUpdater() {
        if (Boolean.parseBoolean(System.getProperty(ZMSConsts.ZMS_PROP_ENABLE_PRINCIPAL_STATE_UPDATER, "false"))) {
            new PrincipalStateUpdater(this.dbService, this.userAuthority);
        }
    }

    private void initializeServiceProviderManager() {
        try {
            serviceProviderManager = ServiceProviderManager.getInstance(dbService, this);
            serviceProviderClient = new ServiceProviderClient(keyStore, homeDomainPrefix);
        } catch (KeyRefresherException | IOException | InterruptedException e) {
            throw new RuntimeException("Failed to initialize service provider manager: " + e.getMessage());
        }
    }

    private void setNotificationManager() {
        notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(userAuthority);
        ZMSNotificationTaskFactory zmsNotificationTaskFactory = new ZMSNotificationTaskFactory(dbService, userDomainPrefix, notificationToEmailConverterCommon);
        notificationManager = new NotificationManager(zmsNotificationTaskFactory.getNotificationTasks(), userAuthority);
    }

    void loadSystemProperties() {
        String propFile = System.getProperty(ZMSConsts.ZMS_PROP_FILE_NAME,
                getRootDir() + "/conf/zms_server/zms.properties");
        try {
            CONFIG_MANAGER.addConfigSource(ConfigProviderFile.PROVIDER_DESCRIPTION_PREFIX + propFile);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    void setAuthorityKeyStore() {
        for (Authority authority : authorities.getAuthorities()) {
            if (authority instanceof AuthorityKeyStore) {
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
        if (!StringUtil.isEmpty(userDomainAlias)) {
            userDomainAliasPrefix = userDomainAlias + ".";
        }

        headlessUserDomain = System.getProperty(ZMSConsts.ZMS_PROP_HEADLESS_USER_DOMAIN, userDomain);
        headlessUserDomainPrefix = headlessUserDomain + ".";

        final String addlUserCheckDomains = System.getProperty(ZMSConsts.ZMS_PROP_ADDL_USER_CHECK_DOMAINS);
        if (!StringUtil.isEmpty(addlUserCheckDomains)) {
            String[] checkDomains = addlUserCheckDomains.split(",");
            addlUserCheckDomainSet = new HashSet<>();
            addlUserCheckDomainPrefixList = new ArrayList<>();
            for (String checkDomain : checkDomains) {
                addlUserCheckDomainSet.add(checkDomain);
                addlUserCheckDomainPrefixList.add(checkDomain + ".");
            }
        }

        homeDomain = System.getProperty(ZMSConsts.ZMS_PROP_HOME_DOMAIN, userDomain);
        homeDomainPrefix = homeDomain + ".";

        // default token timeout for issued tokens

        userTokenTimeout = Integer.parseInt(
                System.getProperty(ZMSConsts.ZMS_PROP_TIMEOUT, "3600"));

        // check if we need to run in maintenance read only mode

        readOnlyMode = new DynamicConfigBoolean(CONFIG_MANAGER, ZMSConsts.ZMS_PROP_READ_ONLY_MODE, false);

        // check to see if we need to validate all user and service members
        // when adding them to roles

        validateServiceRoleMembers = new DynamicConfigBoolean(CONFIG_MANAGER, ZMSConsts.ZMS_PROP_VALIDATE_SERVICE_MEMBERS, false);
        validateUserRoleMembers = new DynamicConfigBoolean(CONFIG_MANAGER, ZMSConsts.ZMS_PROP_VALIDATE_USER_MEMBERS, false);
        validatePolicyAssertionRoles = new DynamicConfigBoolean(CONFIG_MANAGER, ZMSConsts.ZMS_PROP_VALIDATE_ASSERTION_ROLES, false);

        // there are going to be domains like our ci/cd dynamic project domain
        // where we can't verify the service role members so for those we're
        // going to skip specific domains from validation checks

        final String skipDomains = System.getProperty(
                ZMSConsts.ZMS_PROP_VALIDATE_SERVICE_MEMBERS_SKIP_DOMAINS, "");
        validateServiceMemberSkipDomains = Arrays.asList(skipDomains.split(","));
        allowUnderscoreInServiceNames = new DynamicConfigBoolean(CONFIG_MANAGER,
                ZMSConsts.ZMS_PROP_ALLOW_UNDERSCORE_IN_SERVICE_NAMES, Boolean.FALSE);

        // check to see if we need to support product ids as required
        // for top level domains

        productIdSupport = Boolean.parseBoolean(
                System.getProperty(ZMSConsts.ZMS_PROP_PRODUCT_ID_SUPPORT, "false"));

        // get the list of valid provider endpoints

        final String endPoints = System.getProperty(ZMSConsts.ZMS_PROP_PROVIDER_ENDPOINTS);
        if (!StringUtil.isEmpty(endPoints)) {
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

        useMasterCopyForSignedDomains = Boolean.parseBoolean(
                System.getProperty(ZMSConsts.ZMS_PROP_MASTER_COPY_FOR_SIGNED_DOMAINS, "false"));

        // get the maximum length allowed for a top level domain name

        domainNameMaxLen = Integer.parseInt(System.getProperty(
                ZMSConsts.ZMS_PROP_DOMAIN_NAME_MAX_SIZE, ZMSConsts.ZMS_DOMAIN_NAME_MAX_SIZE_DEFAULT));
        if (domainNameMaxLen < 10) { // 10 is arbitrary
            int domNameMaxDefault = Integer.parseInt(ZMSConsts.ZMS_DOMAIN_NAME_MAX_SIZE_DEFAULT);
            LOG.warn("init: Warning: maximum domain name length specified is too small: {} reverting to default: {}",
                    domainNameMaxLen, domNameMaxDefault);
            domainNameMaxLen = domNameMaxDefault;
        }
        LOG.info("init: using maximum domain name length: {}", domainNameMaxLen);

        // get the list of uris that we want to allow an-authenticated access

        final String uriList = System.getProperty(ZMSConsts.ZMS_PROP_NOAUTH_URI_LIST);
        if (!StringUtil.isEmpty(uriList)) {
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

        // get the list of allowed origin values for cors requests

        final String originList = System.getProperty(ZMSConsts.ZMS_PROP_CORS_ORIGIN_LIST);
        if (!StringUtil.isEmpty(originList)) {
            corsOriginList = new HashSet<>(Arrays.asList(originList.split(",")));
        }

        // get the list of allowed header names for cors requests

        final String headerList = System.getProperty(ZMSConsts.ZMS_PROP_CORS_HEADER_LIST,
                "*,Accept,Accept-Language,Content-Language,Content-Type,Authorization");
        corsRequestHeaderList = Arrays.stream(headerList.split(","))
                .map(String::toLowerCase).collect(Collectors.toSet());

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
        reservedSystemDomains.add(SYS_AUTH);
        reservedSystemDomains.add("sys.auth.audit");
        reservedSystemDomains.add("sys.auth.audit.org");
        reservedSystemDomains.add("sys.auth.audit.domain");
        reservedSystemDomains.add(userDomain);
        reservedSystemDomains.add(homeDomain);
        reservedSystemDomains.add(headlessUserDomain);

        // set up our reserved top level domain names. we will not allow any top level
        // domains to be created with these values

        reservedDomainNames = new DynamicConfigCsv(CONFIG_MANAGER, ZMSConsts.ZMS_PROP_RESERVED_DOMAIN_NAMES, null);

        // set up our health check file

        final String healthCheckPath = System.getProperty(ZMSConsts.ZMS_PROP_HEALTH_CHECK_PATH);
        if (!StringUtil.isEmpty(healthCheckPath)) {
            healthCheckFile = new File(healthCheckPath);
        }

        // get our domain contact types

        final String contactTypeList = System.getProperty(ZMSConsts.ZMS_PROP_DOMAIN_CONTACT_TYPES);
        if (!StringUtil.isEmpty(contactTypeList)) {
            domainContactTypes.addAll(Arrays.asList(contactTypeList.split(",")));
        }

        // get our domain classification values

        final String environments = System.getProperty(ZMSConsts.ZMS_PROP_DOMAIN_ENVIRONMENTS,
                ZMSConsts.ZMS_DEFAULT_DOMAIN_ENVIRONMENTS);
        domainEnvironments.addAll(Arrays.asList(environments.split(",")));

        // get server region

        serverRegion = System.getProperty(ZMSConsts.ZMS_PROP_SERVER_REGION);

        // fetch the list of system meta attributes that must be empty when a domain
        // is to be deleted

        final String metaAttributes = System.getProperty(ZMSConsts.ZMS_PROP_DOMAIN_DELETE_META_ATTRIBUTES);
        if (!StringUtil.isEmpty(metaAttributes)) {
            domainDeleteMetaAttributes.addAll(Arrays.asList(metaAttributes.split(",")));
        }
    }

    void loadObjectStore() {
        String objFactoryClass = System.getProperty(ZMSConsts.ZMS_PROP_OBJECT_STORE_FACTORY_CLASS,
                ZMSConsts.ZMS_OBJECT_STORE_FACTORY_CLASS);
        ObjectStoreFactory objFactory;
        try {
            objFactory = (ObjectStoreFactory) Class.forName(objFactoryClass).getDeclaredConstructor().newInstance();
        } catch (Exception ex) {
            LOG.error("Invalid ObjectStoreFactory class: {}", objFactoryClass, ex);
            throw new IllegalArgumentException("Invalid object store");
        }

        ZMSConfig zmsConfig = new ZMSConfig();
        zmsConfig.setUserDomain(userDomain);
        zmsConfig.setAddlUserCheckDomainPrefixList(addlUserCheckDomainPrefixList);
        zmsConfig.setUserDomainPrefix(userDomainPrefix);
        zmsConfig.setHeadlessUserDomainPrefix(headlessUserDomainPrefix);
        zmsConfig.setServerHostName(serverHostName);
        zmsConfig.setServerSolutionTemplates(serverSolutionTemplates);
        zmsConfig.setUserAuthority(userAuthority);
        zmsConfig.setValidator(validator);

        objectStore = objFactory.create(keyStore);
        dbService = new DBService(objectStore, auditLogger, zmsConfig, auditReferenceValidator, authHistoryStore);

        // create our group fetcher based on the db service

        groupMemberFetcher = new ZMSGroupMembersFetcher(dbService);
    }

    void loadAuthHistoryStore() {
        String authHistoryFactoryClass = System.getProperty(ZMSConsts.ZMS_PROP_AUTH_HISTORY_STORE_FACTORY_CLASS);
        if (StringUtil.isEmpty(authHistoryFactoryClass)) {
            LOG.info("Authentication History Store Disabled.");
            return;
        }

        AuthHistoryStoreFactory authHistoryStoreFactory;
        try {
            authHistoryStoreFactory = (AuthHistoryStoreFactory) Class.forName(authHistoryFactoryClass).getDeclaredConstructor().newInstance();
        } catch (Exception ex) {
            LOG.error("Invalid AuthHistoryStoreFactory class: {}", authHistoryFactoryClass, ex);
            throw new IllegalArgumentException("Invalid auth history store");
        }

        authHistoryStore = authHistoryStoreFactory.create(keyStore);
    }

    void loadMetricObject() {

        String metricFactoryClass = System.getProperty(ZMSConsts.ZMS_PROP_METRIC_FACTORY_CLASS,
                METRIC_DEFAULT_FACTORY_CLASS);
        MetricFactory metricFactory;
        try {
            metricFactory = (MetricFactory) Class.forName(metricFactoryClass).getDeclaredConstructor().newInstance();
        } catch (Exception ex) {
            LOG.error("Invalid MetricFactory class: {}", metricFactoryClass, ex);
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
            pkeyFactory = (PrivateKeyStoreFactory) Class.forName(pkeyFactoryClass).getDeclaredConstructor().newInstance();
        } catch (Exception ex) {
            LOG.error("Invalid PrivateKeyStoreFactory class: {}", pkeyFactoryClass, ex);
            throw new IllegalArgumentException("Invalid private key store");
        }

        // extract the private key and public keys for our service

        keyStore = pkeyFactory.create();

        privateECKey = keyStore.getPrivateKey(ZMSConsts.ZMS_SERVICE, serverHostName,
                serverRegion, ZMSConsts.EC);

        privateRSAKey = keyStore.getPrivateKey(ZMSConsts.ZMS_SERVICE, serverHostName,
                serverRegion, ZMSConsts.RSA);

        // if we don't have ec and rsa specific keys specified then we're going to fall
        // back and use the old private key api and use that for our private key
        // if both ec and rsa keys are provided, we use the ec key as preferred
        // when signing policy files

        if (privateECKey == null && privateRSAKey == null) {
            StringBuilder privKeyId = new StringBuilder(256);
            PrivateKey pkey = keyStore.getPrivateKey(ZMSConsts.ZMS_SERVICE, serverHostName, privKeyId);
            privateKey = new ServerPrivateKey(pkey, privKeyId.toString());
        } else {
            privateKey = Objects.requireNonNullElseGet(privateECKey, () -> privateRSAKey);
        }
    }

    void loadDomainMetaStore() {

        final String metaStoreFactoryClass = System.getProperty(ZMSConsts.ZMS_PROP_DOMAIN_META_STORE_FACTORY_CLASS,
                ZMSConsts.ZMS_DOMAIN_META_STORE_FACTORY_CLASS);
        DomainMetaStoreFactory metaStoreFactory;
        try {
            metaStoreFactory = (DomainMetaStoreFactory) Class.forName(metaStoreFactoryClass).getDeclaredConstructor().newInstance();
        } catch (Exception ex) {
            LOG.error("Invalid DomainMetaStoreFactory class: {}", metaStoreFactoryClass, ex);
            throw new IllegalArgumentException("Invalid metastore factory");
        }

        // get our meta store object

        domainMetaStore = metaStoreFactory.create(keyStore);
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
            }
            if (authorityClass.equals(userAuthorityClass)) {
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
            auditLogFactory = (AuditLoggerFactory) Class.forName(auditFactoryClass).getDeclaredConstructor().newInstance();
        } catch (Exception ex) {
            LOG.error("Invalid AuditLoggerFactory class: {}", auditFactoryClass, ex);
            throw new IllegalArgumentException("Invalid audit logger class");
        }

        // create our audit logger

        auditLogger = auditLogFactory.create();
    }

    void loadAuditRefValidator() {
        final String auditRefValidatorClass = System.getProperty(ZMSConsts.ZMS_PROP_AUDIT_REF_VALIDATOR_FACTORY_CLASS);
        AuditReferenceValidatorFactory auditReferenceValidatorFactory;

        if (!StringUtil.isEmpty(auditRefValidatorClass)) {

            try {
                auditReferenceValidatorFactory = (AuditReferenceValidatorFactory) Class.forName(auditRefValidatorClass).getDeclaredConstructor().newInstance();
            } catch (Exception ex) {
                LOG.error("Invalid AuditReferenceValidatorFactory class: {}", auditRefValidatorClass, ex);
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

        ServiceIdentity identity = dbService.getServiceIdentity(SYS_AUTH, ZMSConsts.ZMS_SERVICE, false);
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
            final String publicKey = Crypto.convertToPEMFormat(Crypto.extractPublicKey(privateKey.getKey()));
            serverPublicKeyMap.put(privateKey.getId(), Crypto.ybase64EncodeString(publicKey));
        }
    }

    void loadSolutionTemplates() {

        // get the configured path for the list of service templates

        String solutionTemplatesFname = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME,
                getRootDir() + "/conf/zms_server/solution_templates.json");

        Path path = Paths.get(solutionTemplatesFname);
        try {
            serverSolutionTemplates = JSON.fromBytes(Files.readAllBytes(path), SolutionTemplates.class);
        } catch (IOException ex) {
            LOG.error("Unable to parse solution templates file {}: {}",
                    solutionTemplatesFname, ex.getMessage());
        }

        if (serverSolutionTemplates == null) {
            LOG.error("Generating empty solution template list...");
            serverSolutionTemplates = new SolutionTemplates();
            serverSolutionTemplates.setTemplates(new HashMap<>());
            serverSolutionTemplateNames = Collections.emptyList();
        } else {
            serverSolutionTemplateNames = new ArrayList<>(serverSolutionTemplates.names());
            Collections.sort(serverSolutionTemplateNames);
        }
    }

    void autoApplyTemplates() {
        Map<String, Integer> eligibleTemplatesForAutoUpdate = new HashMap<>();
        for (String templateName : serverSolutionTemplates.getTemplates().keySet()) {
            Template template = serverSolutionTemplates.get(templateName);
            if (template != null && template.getMetadata() != null && template.getMetadata().getAutoUpdate() == Boolean.TRUE
                    && StringUtil.isEmpty(template.getMetadata().getKeywordsToReplace())) {
                eligibleTemplatesForAutoUpdate.put(templateName, template.getMetadata().getLatestVersion());
            }
        }
        if (Boolean.parseBoolean(System.getProperty(ZMSConsts.ZMS_AUTO_UPDATE_TEMPLATE_FEATURE_FLAG, "false"))
                && !eligibleTemplatesForAutoUpdate.isEmpty()) {
            ExecutorService executor = Executors.newSingleThreadExecutor();
            executor.execute(new AutoApplyTemplate(eligibleTemplatesForAutoUpdate));
            executor.shutdown();
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

    void loadStatusChecker() {
        final String statusCheckerFactoryClass = System.getProperty(ZMSConsts.ZMS_PROP_STATUS_CHECKER_FACTORY_CLASS);
        StatusCheckerFactory statusCheckerFactory;

        if (!StringUtil.isEmpty(statusCheckerFactoryClass)) {

            try {
                statusCheckerFactory = (StatusCheckerFactory) Class.forName(statusCheckerFactoryClass).getDeclaredConstructor().newInstance();
            } catch (Exception ex) {
                LOG.error("Invalid StatusCheckerFactory class: {}", statusCheckerFactoryClass, ex);
                throw new IllegalArgumentException("Invalid status checker factory class");
            }

            // create our status checker

            statusChecker = statusCheckerFactory.create();
        }
    }

    void initObjectStore() {

        final String caller = "initstore";

        List<String> domains = dbService.listDomains(null, 0, true);
        if (!domains.isEmpty() && domains.contains(SYS_AUTH)) {
            return;
        }

        final String adminUserList = System.getProperty(ZMSConsts.ZMS_PROP_DOMAIN_ADMIN);
        if (StringUtil.isEmpty(adminUserList)) {
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

        // create system required top level domains

        Domain domain = new Domain().setName(userDomain).setDescription("The reserved domain for user authentication")
                .setId(UUID.fromCurrentTime()).setModified(Timestamp.fromCurrentTime());
        createTopLevelDomain(null, domain, adminUsers, null, "System Setup");
        if (!ZMSConsts.USER_DOMAIN.equals(userDomain)) {
            domain = new Domain().setName(ZMSConsts.USER_DOMAIN).setDescription("The reserved domain for user authentication")
                    .setId(UUID.fromCurrentTime()).setModified(Timestamp.fromCurrentTime());
            createTopLevelDomain(null, domain, adminUsers, null, "System Setup");
        }
        if (!homeDomain.equals(userDomain)) {
            domain = new Domain().setName(homeDomain).setDescription("The reserved domain for personal user domains")
                    .setId(UUID.fromCurrentTime()).setModified(Timestamp.fromCurrentTime());
            createTopLevelDomain(null, domain, adminUsers, null, "System Setup");
        }
        if (!headlessUserDomain.equals(userDomain)) {
            domain = new Domain().setName(headlessUserDomain).setDescription("The reserved domain for headless users")
                    .setId(UUID.fromCurrentTime()).setModified(Timestamp.fromCurrentTime());
            createTopLevelDomain(null, domain, adminUsers, null, "System Setup");
        }
        domain = new Domain().setName("sys").setDescription("The reserved domain for system related information")
                .setId(UUID.fromCurrentTime()).setModified(Timestamp.fromCurrentTime());
        createTopLevelDomain(null, domain, adminUsers, null, "System Setup");

        // now create required subdomains in sys top level domain

        domain = new Domain().setName(SYS_AUTH).setDescription("The Athenz domain")
                .setId(UUID.fromCurrentTime()).setModified(Timestamp.fromCurrentTime());
        createSubDomain(null, domain, adminUsers, null, "System Setup", caller);

        domain = new Domain().setName("sys.auth.audit").setDescription("The Athenz audit domain")
                .setId(UUID.fromCurrentTime()).setModified(Timestamp.fromCurrentTime());
        createSubDomain(null, domain, adminUsers, null, "System Setup", caller);

        domain = new Domain().setName("sys.auth.audit.org").setDescription("The Athenz audit domain based on org name")
                .setId(UUID.fromCurrentTime()).setModified(Timestamp.fromCurrentTime());
        createSubDomain(null, domain, adminUsers, null, "System Setup", caller);

        domain = new Domain().setName("sys.auth.audit.domain").setDescription("The Athenz audit domain based on domain name")
                .setId(UUID.fromCurrentTime()).setModified(Timestamp.fromCurrentTime());
        createSubDomain(null, domain, adminUsers, null, "System Setup", caller);

        if (privateKey != null) {
            List<PublicKeyEntry> pubKeys = new ArrayList<>();
            final String publicKey = Crypto.convertToPEMFormat(Crypto.extractPublicKey(privateKey.getKey()));
            pubKeys.add(new PublicKeyEntry().setId(privateKey.getId()).setKey(Crypto.ybase64EncodeString(publicKey)));
            ServiceIdentity id = new ServiceIdentity().setName("sys.auth.zms").setPublicKeys(pubKeys);
            dbService.executePutServiceIdentity(null, SYS_AUTH, ZMSConsts.ZMS_SERVICE, id, null, caller, false);
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

    @Override
    public DomainList getDomainList(ResourceContext ctx, Integer limit, String skip, String prefix,
            Integer depth, String account, Integer productNumber, String roleMember, String roleName,
            String subscription, String project, String tagKey, String tagValue, String businessService,
            String productId, String modifiedSince) {

        final String caller = ctx.getApiName();

        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);

        if (LOG.isDebugEnabled()) {
            LOG.debug("getDomainList: limit: {}, skip: {}, prefix: {}, depth: {}, account: {}, productNumber: {}, " +
                    "roleMember: {}, roleName: {}, modifiedSince: {}, subscription: {}, project: {}, " +
                    "businessService: {}, productId: {}, tagKey: {}, tagValue: {}",
                    limit, skip, prefix, depth, account, productNumber, roleMember, roleName,
                    modifiedSince, subscription, project, businessService, productId, tagKey, tagValue);
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
        if (!StringUtil.isEmpty(tagKey)) {
            validate(tagKey, TYPE_TAG_KEY, caller);
        }
        if (!StringUtil.isEmpty(tagValue)) {
            validate(tagValue, TYPE_TAG_COMPOUND_VALUE, caller);
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
        if (!StringUtil.isEmpty(account)) {
            dlist = dbService.lookupDomainByAWSAccount(account);
        } else if (!StringUtil.isEmpty(subscription)) {
            dlist = dbService.lookupDomainByAzureSubscription(subscription);
        } else if (!StringUtil.isEmpty(project)) {
            dlist = dbService.lookupDomainByGcpProject(project);
        } else if (productNumber != null && productNumber != 0) {
            dlist = dbService.lookupDomainByProductId(productNumber);
        } else if (!StringUtil.isEmpty(productId)) {
            dlist = dbService.lookupDomainByProductId(productId);
        } else if (roleMember != null || roleName != null) {
            dlist = dbService.lookupDomainByRole(normalizeDomainAliasUser(roleMember), roleName);
        } else if (!StringUtil.isEmpty(tagKey)) {
            dlist = dbService.lookupDomainByTag(tagKey, tagValue);
        } else if (!StringUtil.isEmpty(businessService)) {
            dlist = dbService.lookupDomainByBusinessService(businessService);
        } else {
            dlist = listDomains(limit, skip, prefix, depth, modTime, false);
        }

        return dlist;
    }

    public Domain getDomain(ResourceContext ctx, String domainName) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        Domain domain = dbService.getDomain(domainName, false);
        if (domain == null) {
            throw ZMSUtils.notFoundError("getDomain: Domain not found: " + domainName, caller);
        }

        return domain;
    }

    @Override
    public Domain postTopLevelDomain(ResourceContext ctx, String auditRef, String resourceOwner, TopLevelDomain detail) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(detail, TYPE_TOP_LEVEL_DOMAIN, caller);

        String domainName = detail.getName();
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        // first verify that this is not a reserved domain name

        if (reservedDomainNames.hasItem(domainName)) {
            throw ZMSUtils.requestError("Domain name is reserved", caller);
        }

        // next check to make sure the domain does not contain an underscore
        // since it's not a valid character for our sanDNS hostname entry
        // in the service identity x.509 certificate, unless it's being
        // executed by a system admin

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
            if (detail.getYpmId() == null && StringUtil.isEmpty(detail.getProductId())) {
                throw ZMSUtils.requestError("Product Id is required when creating top level domain", caller);
            }
            // if we're given a ypm-id value then we need to make sure
            // it is not a negative number.
            if (detail.getYpmId() != null) {
                productId = detail.getYpmId();
                if (productId <= 0) {
                    throw ZMSUtils.requestError("Product Id must be a positive integer", caller);
                }
            }
        }

        // if we're provided a user authority filter then we need to
        // make sure it's valid

        validateUserAuthorityFilterAttribute(detail.getUserAuthorityFilter(), caller);

        // process our top level domain request

        Domain topLevelDomain = new Domain()
                .setName(domainName)
                .setAuditEnabled(detail.getAuditEnabled())
                .setDescription(detail.getDescription())
                .setOrg(detail.getOrg())
                .setId(UUID.fromCurrentTime())
                .setAccount(detail.getAccount())
                .setAzureSubscription(detail.getAzureSubscription())
                .setGcpProject(detail.getGcpProject())
                .setGcpProjectNumber(detail.getGcpProjectNumber())
                .setYpmId(productId)
                .setProductId(detail.getProductId())
                .setModified(Timestamp.fromCurrentTime())
                .setApplicationId(detail.getApplicationId())
                .setMemberExpiryDays(detail.getMemberExpiryDays())
                .setMemberPurgeExpiryDays(detail.getMemberPurgeExpiryDays())
                .setServiceExpiryDays(detail.getServiceExpiryDays())
                .setGroupExpiryDays(detail.getGroupExpiryDays())
                .setTokenExpiryMins(detail.getTokenExpiryMins())
                .setServiceCertExpiryMins(detail.getServiceCertExpiryMins())
                .setRoleCertExpiryMins(detail.getRoleCertExpiryMins())
                .setSignAlgorithm(detail.getSignAlgorithm())
                .setUserAuthorityFilter(detail.getUserAuthorityFilter())
                .setTags(detail.getTags())
                .setBusinessService(detail.getBusinessService())
                .setCertDnsDomain(detail.getCertDnsDomain())
                .setFeatureFlags(detail.getFeatureFlags())
                .setContacts(detail.getContacts())
                .setEnvironment(detail.getEnvironment());

        // before processing validate the fields

        validateDomainValues(topLevelDomain);

        List<String> adminUsers = normalizedAdminUsers(detail.getAdminUsers(), detail.getUserAuthorityFilter(), caller);
        return createTopLevelDomain(ctx, topLevelDomain, adminUsers, solutionTemplates, auditRef);
    }

    @Override
    public void deleteTopLevelDomain(ResourceContext ctx, String domainName, String auditRef, String resourceOwner) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        deleteDomain(ctx, auditRef, domainName, caller);
    }

    void deleteDomain(ResourceContext ctx, String auditRef, String domainName, String caller) {

        // make sure we're not deleting any of the reserved system domain

        if (reservedSystemDomains.contains(domainName)) {
            throw ZMSUtils.requestError("Cannot delete reserved system domain", caller);
        }

        DomainList subDomainList = listDomains(null, null, domainName + ".", null, 0, true);
        if (!subDomainList.getNames().isEmpty()) {
            throw ZMSUtils.requestError(caller + ": Cannot delete domain " +
                    domainName + ": " + subDomainList.getNames().size() + " subdomains of it exist", caller);
        }

        // we're going to make sure the domain does not have any
        // groups that are referenced in other domains. if that is the
        // case the group should be removed from all those domains
        // before the domain can be deleted

        AthenzDomain domain = getAthenzDomain(domainName, false);
        if (domain == null) {
            throw ZMSUtils.notFoundError("Domain not found: '" + domainName + "'", caller);
        }

        for (Group group : domain.getGroups()) {
            groupMemberConsistencyCheck(domainName, group.getName(), true, caller);
        }

        // consistency checks are ok. Now check if there are provider services dependent on the domain

        verifyNoServiceDependenciesOnDomain(domainName, caller);
        verifyServiceProvidersAuthorizeDelete(ctx, domainName, caller);
        verifyEmptyDomainMetaAttributes(domain.getDomain(), caller);

        // no service is dependent on the domain, we can go ahead and delete the domain

        dbService.executeDeleteDomain(ctx, domainName, auditRef, caller);
    }

    void verifyEmptyDomainMetaAttributes(Domain domain, final String caller) {

        for (String metaAttribute : domainDeleteMetaAttributes) {
            switch (metaAttribute) {
                case ZMSConsts.SYSTEM_META_ACCOUNT:
                    if (!StringUtil.isEmpty(domain.getAccount())) {
                        throw ZMSUtils.requestError("Domain has non-empty account attribute: "
                                + domain.getAccount(), caller);
                    }
                    break;
                case ZMSConsts.SYSTEM_META_GCP_PROJECT:
                    if (!StringUtil.isEmpty(domain.getGcpProject())) {
                        throw ZMSUtils.requestError("Domain has non-empty gcp-project attribute: "
                                + domain.getGcpProject(), caller);
                    }
                    break;
                case ZMSConsts.SYSTEM_META_AZURE_SUBSCRIPTION:
                    if (!StringUtil.isEmpty(domain.getAzureSubscription())) {
                        throw ZMSUtils.requestError("Domain has non-empty azure-subscription attribute: "
                                + domain.getAzureSubscription(), caller);
                    }
                    break;
            }
        }
    }

    private void verifyNoServiceDependenciesOnDomain(String domainName, String caller) {
        ServiceIdentityList serviceIdentityList = dbService.listServiceDependencies(domainName);
        if (serviceIdentityList.getNames() != null && !serviceIdentityList.getNames().isEmpty()) {
            final String msgBuilder = "Remove domain '" + domainName +
                    "' dependency from the following service(s):" +
                    String.join(", ", serviceIdentityList.getNames());
            throw ZMSUtils.forbiddenError(msgBuilder, caller);
        }
    }

    void verifyServiceProvidersAuthorizeDelete(ResourceContext ctx, String domainName, String caller) {
        // Concurrently contact all service providers with endpoints and verify that the domain can be deleted
        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        Map<String, ServiceProviderManager.DomainDependencyProvider> serviceProvidersWithEndpoints = serviceProviderManager.getServiceProvidersWithEndpoints();
        List<String> serviceDependenciesDenied = serviceProvidersWithEndpoints.values()
                .parallelStream()
                .map(domainDependencyProvider -> getErrorOnServiceProviderDeny(domainName, principal, domainDependencyProvider))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        if (!serviceDependenciesDenied.isEmpty()) {
            throw ZMSUtils.forbiddenError(String.join(", ", serviceDependenciesDenied), caller);
        }
    }

    private String getErrorOnServiceProviderDeny(String domainName, Principal principal, ServiceProviderManager.DomainDependencyProvider domainDependencyProvider) {
        DomainDependencyProviderResponse domainDependencyProviderResponse = serviceProviderClient.getDependencyStatus(domainDependencyProvider, domainName, principal.getFullName());
        if (domainDependencyProviderResponse.getStatus().equals(PROVIDER_RESPONSE_DENY)) {
            StringBuilder msgBuilder = new StringBuilder("Service '");
            msgBuilder.append(domainDependencyProvider.getProvider());
            msgBuilder.append("' is dependent on domain '");
            msgBuilder.append(domainName);
            msgBuilder.append("'");
            if (!StringUtil.isEmpty(domainDependencyProviderResponse.getMessage())) {
                msgBuilder.append(". Error: ");
                msgBuilder.append(domainDependencyProviderResponse.getMessage());
            }
            return msgBuilder.toString();
        }
        return null;
    }

    private void verifyNoDomainDependenciesOnService(String serviceName, String caller) {
        if (serviceProviderManager.isServiceProvider(serviceName)) {
            DomainList domainList = dbService.listDomainDependencies(serviceName);
            if (domainList.getNames() != null && !domainList.getNames().isEmpty()) {
                final String msgBuilder = "Remove service '" + serviceName +
                        "' dependency from the following domain(s):" +
                        String.join(", ", domainList.getNames());
                throw ZMSUtils.forbiddenError(msgBuilder, caller);
            }
        }
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

        DomainList dlist = listDomains(null, null, userDomainCheck, null, 0, true);
        if (dlist.getNames().size() < virtualDomainLimit) {
            return false;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("hasExceededVirtualSubDomainLimit: subdomains with prefix {}: {} while limit is: {}",
                    userDomainCheck, dlist.getNames().size(), virtualDomainLimit);
        }

        return true;
    }

    @Override
    public Domain postUserDomain(ResourceContext ctx, String name, String auditRef, String resourceOwner, UserDomain detail) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(detail, TYPE_USER_DOMAIN, caller);
        validate(name, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        name = name.toLowerCase();
        setRequestDomain(ctx, name);
        AthenzObject.USER_DOMAIN.convertToLowerCase(detail);

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

        final String userDomainAdmin = userDomainPrefix + principal.getName();
        validateRoleMemberPrincipal(userDomainAdmin, Principal.Type.USER.getValue(), null, null, null, true, caller);

        List<String> adminUsers = new ArrayList<>();
        adminUsers.add(userDomainAdmin);

        List<String> solutionTemplates = null;
        DomainTemplateList templates = detail.getTemplates();
        if (templates != null) {
            solutionTemplates = templates.getTemplateNames();
            validateSolutionTemplates(solutionTemplates, caller);
        }

        Domain subDomain = new Domain()
                .setName(homeDomain + "." + getUserDomainName(detail.getName()))
                .setAuditEnabled(detail.getAuditEnabled())
                .setDescription(detail.getDescription())
                .setId(UUID.fromCurrentTime())
                .setModified(Timestamp.fromCurrentTime())
                .setApplicationId(detail.getApplicationId())
                .setMemberExpiryDays(detail.getMemberExpiryDays())
                .setMemberPurgeExpiryDays(detail.getMemberPurgeExpiryDays())
                .setServiceExpiryDays(detail.getServiceExpiryDays())
                .setGroupExpiryDays(detail.getGroupExpiryDays())
                .setTokenExpiryMins(detail.getTokenExpiryMins())
                .setServiceCertExpiryMins(detail.getServiceCertExpiryMins())
                .setRoleCertExpiryMins(detail.getRoleCertExpiryMins())
                .setSignAlgorithm(detail.getSignAlgorithm())
                .setTags(detail.getTags())
                .setBusinessService(detail.getBusinessService())
                .setContacts(detail.getContacts())
                .setEnvironment(detail.getEnvironment());

        // before processing validate the fields

        validateDomainValues(subDomain);

        return createSubDomain(ctx, subDomain, adminUsers, solutionTemplates, auditRef, caller);
    }

    @Override
    public Domain postSubDomain(ResourceContext ctx, String parent, String auditRef, String resourceOwner, SubDomain detail) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(detail, TYPE_SUB_DOMAIN, caller);
        validate(parent, TYPE_DOMAIN_NAME, caller);
        validate(detail.getName(), TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        parent = parent.toLowerCase();
        setRequestDomain(ctx, parent);
        AthenzObject.SUB_DOMAIN.convertToLowerCase(detail);

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

        // verify that the parent domain exists

        AthenzDomain parentDomain = getAthenzDomain(parent, false);
        if (parentDomain == null || parentDomain.getDomain() == null) {
            throw ZMSUtils.notFoundError("Invalid parent domain: " + parent, caller);
        }

        // inherit audit_enabled flag, organization and user authority settings
        // from the parent domain

        detail.setAuditEnabled(parentDomain.getDomain().getAuditEnabled());
        detail.setOrg(parentDomain.getDomain().getOrg());
        detail.setUserAuthorityFilter(parentDomain.getDomain().getUserAuthorityFilter());

        // generate and verify admin users

        List<String> adminUsers = normalizedAdminUsers(detail.getAdminUsers(), detail.getUserAuthorityFilter(), caller);

        Domain subDomain = new Domain()
                .setName(detail.getParent() + "." + detail.getName())
                .setAuditEnabled(detail.getAuditEnabled())
                .setDescription(detail.getDescription())
                .setOrg(detail.getOrg())
                .setId(UUID.fromCurrentTime())
                .setModified(Timestamp.fromCurrentTime())
                .setApplicationId(detail.getApplicationId())
                .setMemberExpiryDays(detail.getMemberExpiryDays())
                .setMemberPurgeExpiryDays(detail.getMemberPurgeExpiryDays())
                .setServiceExpiryDays(detail.getServiceExpiryDays())
                .setGroupExpiryDays(detail.getGroupExpiryDays())
                .setTokenExpiryMins(detail.getTokenExpiryMins())
                .setServiceCertExpiryMins(detail.getServiceCertExpiryMins())
                .setRoleCertExpiryMins(detail.getRoleCertExpiryMins())
                .setSignAlgorithm(detail.getSignAlgorithm())
                .setTags(detail.getTags())
                .setBusinessService(detail.getBusinessService())
                .setContacts(detail.getContacts())
                .setEnvironment(detail.getEnvironment());

        // before processing validate the fields

        validateDomainValues(subDomain);

        return createSubDomain(ctx, subDomain, adminUsers, solutionTemplates, auditRef, caller);
    }

    boolean isSysAdminUser(Principal principal) {
        return isSysAdminUser(principal, true);
    }

    boolean isSysAdminUser(Principal principal, boolean prefixMustBeUserDomain) {

        // verify we're dealing with system administrator
        // authorize ("CREATE", "sys.auth:domain");

        if (prefixMustBeUserDomain) {
            if (!principal.getDomain().equals(userDomain)) {
                return false;
            }
        }

        AthenzDomain domain = getAthenzDomain(SYS_AUTH, true);

        // evaluate our domain's roles and policies to see if access
        // is allowed or not for the given operation and resource
        // our action are always converted to lowercase

        return hasAccess(domain, "create", SYS_AUTH + ":domain", principal, null) == AccessStatus.ALLOWED;
    }

    boolean authorizedForDomainDelete(Principal principal, final String domainName, final String caller) {

        // extract the domain object first

        AthenzDomain domain = getAthenzDomain(domainName, true);
        if (domain == null) {
            throw ZMSUtils.notFoundError("Domain not found: " + domainName, caller);
        }

        // carry out authorization check
        //     authorize ("delete", "{domainName}:domain");

        return hasAccess(domain, "delete", domainName + ":domain", principal, null) == AccessStatus.ALLOWED;
    }

    void authorizeSubDomainDeleteRequest(ResourceContext ctx, final String parentDomainName,
            final String subDomainName, final String caller) {

        // first check if the user has a delete privilege in the domain

        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        if (authorizedForDomainDelete(principal, subDomainName, caller)) {
            return;
        }

        // since the principal is not a domain admin, let's check if the
        // principal is an admin in the parent domain (original behavior)

        if (authorizedForDomainDelete(principal, parentDomainName, caller)) {
            return;
        }

        // the principal is not authorized to delete this domain

        throw ZMSUtils.forbiddenError("Principal is not authorized to delete domain: " + subDomainName, caller);
    }

    @Override
    public void deleteSubDomain(ResourceContext ctx, String parent, String name, String auditRef, String resourceOwner) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(parent, TYPE_DOMAIN_NAME, caller);
        validate(name, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        parent = parent.toLowerCase();
        name = name.toLowerCase();
        String domainName = parent + "." + name;
        setRequestDomain(ctx, parent);

        // carry out the authorization check for this request since the RDL
        // only defines authentication. The caller must be a domain admin either
        // in the domain itself or in the parent (original behavior)

        authorizeSubDomainDeleteRequest(ctx, parent, domainName, caller);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        deleteDomain(ctx, auditRef, domainName, caller);
    }

    @Override
    public void deleteUserDomain(ResourceContext ctx, String name, String auditRef, String resourceOwner) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(name, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        name = name.toLowerCase();
        setRequestDomain(ctx, name);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        String domainName = homeDomainPrefix + name;
        deleteDomain(ctx, auditRef, domainName, caller);
    }

    @Override
    public UserList getUserList(ResourceContext ctx, String domainName) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);

        // if we're not given an domain name then we'll
        // default to our system user domain otherwise
        // we'll validate the value and confirm it's one
        // of our configured user domains

        if (domainName != null) {
            validate(domainName, TYPE_DOMAIN_NAME, caller);
            domainName = domainName.toLowerCase();
            if (!domainName.equals(userDomain) &&
                    (addlUserCheckDomainSet == null || !addlUserCheckDomainSet.contains(domainName))) {
                throw ZMSUtils.requestError("Unknown user domain", caller);
            }
        } else {
            domainName = userDomain;
        }

        List<String> names = dbService.listPrincipals(domainName, true);
        return new UserList().setNames(names);
    }

    @Override
    public void deleteDomainRoleMember(ResourceContext ctx, String domainName, String memberName, String auditRef) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(memberName, TYPE_MEMBER_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        memberName = memberName.toLowerCase();

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        dbService.executeDeleteDomainRoleMember(ctx, domainName, memberName, auditRef, caller);
    }

    @Override
    public void deleteUser(ResourceContext ctx, String name, String auditRef) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validate(name, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        name = name.toLowerCase();
        setRequestDomain(ctx, name);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        String userName = userDomainPrefix + name;
        String domainName = homeDomainPrefix + getUserDomainName(name);

        // verify that we're not deleting one of the system admins. We'll
        // refuse those operations since the user must first be removed
        // from the sys.auth:role.admin role and then can be deleted

        if (isSysAdminRoleMember(userName)) {
            throw ZMSUtils.forbiddenError("system admin users cannot be deleted", caller);
        }

        dbService.executeDeleteUser(ctx, userName, domainName, auditRef, caller);
    }

    boolean isSysAdminRoleMember(final String roleMember) {
        Role role = dbService.getRole(SYS_AUTH, ADMIN_ROLE_NAME, false, true, false);
        if (role == null) {
            return false;
        }
        return isMemberOfRole(role, roleMember);
    }

    String getUserDomainName(String userName) {
        return (userAuthority == null) ? userName : userAuthority.getUserDomainName(userName);
    }

    @Override
    public void putDomainMeta(ResourceContext ctx, String domainName, String auditRef, String resourceOwner,
            DomainMeta meta) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);

        // validate meta values - validator will enforce any patters
        // defined in the schema and we need to validate the rest of the
        // integer and string values. for now we're making sure we're not
        // getting any negative values for our integer settings

        validate(meta, TYPE_DOMAIN_META, caller);
        validateDomainMetaValues(meta);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        AthenzObject.DOMAIN_META.convertToLowerCase(meta);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        if (LOG.isDebugEnabled()) {
            LOG.debug("putDomainMeta: name={}, meta={}", domainName, meta);
        }

        // first obtain our domain object

        Domain domain = dbService.getDomain(domainName, true);
        if (domain == null) {
            throw ZMSUtils.notFoundError("No such domain: " + domainName, caller);
        }

        // if any of our meta values has changed we need to validate
        // them against the meta store

        BitSet changedAttrs = validateDomainRegularMetaStoreValues(domain, meta);

        // process put domain meta request

        dbService.executePutDomainMeta(ctx, domain, meta, null, false, auditRef, caller);

        // since our operation was successful we need to see if we
        // need to update any of our values in the meta store

        updateExistingDomainMetaStoreDetails(domainName, meta, changedAttrs);
    }

    void validateDomainContacts(Map<String, String> contacts, final String caller) {

        if (contacts == null || contacts.isEmpty()) {
            return;
        }

        // verify the type is a registered type in the server and the value
        // is a valid principal according to the user authority

        for (Map.Entry<String, String> entry : contacts.entrySet()) {

            if (!domainContactTypes.contains(entry.getKey())) {
                throw ZMSUtils.requestError("invalid domain contact type: " + entry.getKey(), caller);
            }

            // empty value indicates that we want to delete the contact

            if (StringUtil.isEmpty(entry.getValue())) {
                continue;
            }

            // if we have a user authority defined, verify that the given contact
            // is a valid principal according to the user authority

            if (userAuthority != null && !userAuthority.isValidUser(entry.getValue())) {
                throw ZMSUtils.requestError("invalid domain contact: " + entry.getKey(), caller);
            }
        }
    }

    void validateString(final String value, final String type, final String caller) {
        if (value != null && !value.isEmpty()) {
            validate(value, type, caller);
        }
    }

    void validateIntegerValue(final Integer value, final String fieldName) {
        if (value != null && value < 0) {
            throw ZMSUtils.requestError(fieldName + " cannot be negative", "validateMetaFields");
        }
    }

    void validateDomainValues(Domain domain) {

        final String caller = "validateDomainValues";

        validateIntegerValue(domain.getServiceCertExpiryMins(), "serviceCertExpiryMins");
        validateIntegerValue(domain.getMemberExpiryDays(), "memberExpiryDays");
        validateIntegerValue(domain.getRoleCertExpiryMins(), "roleCertExpiryMins");
        validateIntegerValue(domain.getServiceExpiryDays(), "serviceExpiryDays");
        validateIntegerValue(domain.getGroupExpiryDays(), "groupExpiryDays");
        validateIntegerValue(domain.getTokenExpiryMins(), "tokenExpiryMins");
        validateIntegerValue(domain.getFeatureFlags(), "featureFlags");

        validateString(domain.getApplicationId(), TYPE_COMPOUND_NAME, caller);
        validateString(domain.getAccount(), TYPE_COMPOUND_NAME, caller);
        validateString(domain.getAzureSubscription(), TYPE_COMPOUND_NAME, caller);
        validateString(domain.getGcpProject(), TYPE_COMPOUND_NAME, caller);
        validateString(domain.getGcpProjectNumber(), TYPE_COMPOUND_NAME, caller);
        validateString(domain.getUserAuthorityFilter(), TYPE_AUTHORITY_KEYWORDS, caller);

        // we're going to check the meta values for our new domain
        // requests against our meta store

        if (!domainMetaStore.isValidBusinessService(domain.getName(), domain.getBusinessService())) {
            throw ZMSUtils.requestError("invalid business service name for domain", caller);
        }
        if (!domainMetaStore.isValidAWSAccount(domain.getName(), domain.getAccount())) {
            throw ZMSUtils.requestError("invalid aws account for domain", caller);
        }
        if (!domainMetaStore.isValidAzureSubscription(domain.getName(), domain.getAzureSubscription())) {
            throw ZMSUtils.requestError("invalid azure subscription for domain", caller);
        }
        if (!domainMetaStore.isValidGcpProject(domain.getName(), domain.getGcpProject())) {
            throw ZMSUtils.requestError("invalid gcp project for domain", caller);
        }
        // validate that gcp project details are specified correctly
        if (!validateGcpProjectDetails(domain.getGcpProject(), domain.getGcpProjectNumber())) {
            throw ZMSUtils.requestError("invalid gcp project details for domain, both id and number must be specified", caller);
        }
        if (!domainMetaStore.isValidProductId(domain.getName(), domain.getYpmId())) {
            throw ZMSUtils.requestError("invalid product id for domain", caller);
        }
        if (!domainMetaStore.isValidProductId(domain.getName(), domain.getProductId())) {
            throw ZMSUtils.requestError("invalid product id for domain", caller);
        }

        // validate the domain contacts types and names

        validateDomainContacts(domain.getContacts(), caller);

        // validate the domain environment if specified

        if (!StringUtil.isEmpty(domain.getEnvironment()) && !domainEnvironments.contains(domain.getEnvironment())) {
            throw ZMSUtils.requestError("invalid environment for domain", caller);
        }
    }

    boolean validateGcpProjectDetails(final String gcpProjectId, final String gcpProjectNumber) {
        // for gcp project we must have both project id and project number specified,
        // so we're going to check to make sure both are empty or have values
        boolean gcpIdEmpty = StringUtil.isEmpty(gcpProjectId);
        boolean gcpNumberEmpty = StringUtil.isEmpty(gcpProjectNumber);
        return (gcpIdEmpty && gcpNumberEmpty) || (!gcpIdEmpty && !gcpNumberEmpty);
    }

    BitSet validateDomainSystemMetaStoreValues(Domain domain, DomainMeta meta, final String attributeName) {

        final String caller = "validateDomainSystemMetaStoreValues";

        // we're going to check the meta values for our new domain
        // requests against our meta store.

        BitSet changedAttrs = new BitSet();
        switch (attributeName) {
            case ZMSConsts.SYSTEM_META_ACCOUNT:
                if (ZMSUtils.metaValueChanged(domain.getAccount(), meta.getAccount())) {
                    if (!domainMetaStore.isValidAWSAccount(domain.getName(), meta.getAccount())) {
                        throw ZMSUtils.requestError("invalid aws account for domain", caller);
                    }
                    changedAttrs.set(DomainMetaStore.META_ATTR_AWS_ACCOUNT);
                }
                break;
            case ZMSConsts.SYSTEM_META_AZURE_SUBSCRIPTION:
                if (ZMSUtils.metaValueChanged(domain.getAzureSubscription(), meta.getAzureSubscription())) {
                    if (!domainMetaStore.isValidAzureSubscription(domain.getName(), meta.getAzureSubscription())) {
                        throw ZMSUtils.requestError("invalid azure subscription for domain", caller);
                    }
                    changedAttrs.set(DomainMetaStore.META_ATTR_AZURE_SUBSCRIPTION);
                }
                break;
            case ZMSConsts.SYSTEM_META_GCP_PROJECT:
                if (!validateGcpProjectDetails(meta.getGcpProject(), meta.getGcpProjectNumber())) {
                    throw ZMSUtils.requestError("invalid gcp project details for domain, both id and number must be specified", caller);
                }
                if (ZMSUtils.metaValueChanged(domain.getGcpProject(), meta.getGcpProject()) ||
                        ZMSUtils.metaValueChanged(domain.getGcpProjectNumber(), meta.getGcpProjectNumber())) {
                    if (!domainMetaStore.isValidGcpProject(domain.getName(), meta.getGcpProject())) {
                        throw ZMSUtils.requestError("invalid gcp project for domain", caller);
                    }
                    changedAttrs.set(DomainMetaStore.META_ATTR_GCP_PROJECT);
                }
                break;
            case ZMSConsts.SYSTEM_META_PRODUCT_ID:
                if (ZMSUtils.metaValueChanged(domain.getYpmId(), meta.getYpmId())) {
                    if (!domainMetaStore.isValidProductId(domain.getName(), meta.getYpmId())) {
                        throw ZMSUtils.requestError("invalid product id for domain", caller);
                    }
                    changedAttrs.set(DomainMetaStore.META_ATTR_PRODUCT_NUMBER);
                }
                if (ZMSUtils.metaValueChanged(domain.getProductId(), meta.getProductId())) {
                    if (!domainMetaStore.isValidProductId(domain.getName(), meta.getProductId())) {
                        throw ZMSUtils.requestError("invalid product id for domain", caller);
                    }
                    changedAttrs.set(DomainMetaStore.META_ATTR_PRODUCT_ID);
                }
                break;
            case ZMSConsts.SYSTEM_META_BUSINESS_SERVICE:
                if (ZMSUtils.metaValueChanged(domain.getBusinessService(), meta.getBusinessService())) {
                    if (!domainMetaStore.isValidBusinessService(domain.getName(), meta.getBusinessService())) {
                        throw ZMSUtils.requestError("invalid business service for domain", caller);
                    }
                    changedAttrs.set(DomainMetaStore.META_ATTR_BUSINESS_SERVICE);
                }
                break;
        }

        return changedAttrs;
    }

    BitSet validateDomainRegularMetaStoreValues(Domain domain, DomainMeta meta) {

        final String caller = "validateDomainRegularMetaStoreValues";

        // we're going to check the meta values for our new domain
        // requests against our meta store - for now we only have
        // business service as a regular domain meta attribute

        BitSet changedAttrs = new BitSet();
        if (ZMSUtils.metaValueChanged(domain.getBusinessService(), meta.getBusinessService())) {
            if (!domainMetaStore.isValidBusinessService(domain.getName(), meta.getBusinessService())) {
                throw ZMSUtils.requestError("invalid business service name for domain", caller);
            }
            changedAttrs.set(DomainMetaStore.META_ATTR_BUSINESS_SERVICE);
        }

        return changedAttrs;
    }

    void validateDomainMetaValues(DomainMeta meta) {

        final String caller = "validateDomainMetaValues";

        validateIntegerValue(meta.getServiceCertExpiryMins(), "serviceCertExpiryMins");
        validateIntegerValue(meta.getMemberExpiryDays(), "memberExpiryDays");
        validateIntegerValue(meta.getRoleCertExpiryMins(), "roleCertExpiryMins");
        validateIntegerValue(meta.getServiceExpiryDays(), "serviceExpiryDays");
        validateIntegerValue(meta.getGroupExpiryDays(), "groupExpiryDays");
        validateIntegerValue(meta.getTokenExpiryMins(), "tokenExpiryMins");
        validateIntegerValue(meta.getYpmId(), "ypmId");
        validateIntegerValue(meta.getFeatureFlags(), "featureFlags");

        validateString(meta.getApplicationId(), TYPE_COMPOUND_NAME, caller);
        validateString(meta.getAccount(), TYPE_COMPOUND_NAME, caller);

        // validate the domain contacts types and names

        validateDomainContacts(meta.getContacts(), caller);

        // validate the domain environment if specified

        if (!StringUtil.isEmpty(meta.getEnvironment()) && !domainEnvironments.contains(meta.getEnvironment())) {
            throw ZMSUtils.requestError("invalid environment for domain", caller);
        }
    }

    void updateDomainMetaStoreAttributeDetails(final String domainName, int metaAttribute, final Object value) {

        // we are not going to fail our operation if any of these checks
        // fail. instead we're just going to log the failure and let the
        // administrator deal with them later. It is expected that there
        // some offline process that runs every day and verifies all the
        // data within athenz and the external meta store is in sync

        try {
            switch (metaAttribute) {
                case DomainMetaStore.META_ATTR_BUSINESS_SERVICE:
                    domainMetaStore.setBusinessServiceDomain(domainName, (String) value);
                    break;
                case DomainMetaStore.META_ATTR_AWS_ACCOUNT:
                    domainMetaStore.setAWSAccountDomain(domainName, (String) value);
                    break;
                case DomainMetaStore.META_ATTR_AZURE_SUBSCRIPTION:
                    domainMetaStore.setAzureSubscriptionDomain(domainName, (String) value);
                    break;
                case DomainMetaStore.META_ATTR_GCP_PROJECT:
                    domainMetaStore.setGcpProjectDomain(domainName, (String) value);
                    break;
                case DomainMetaStore.META_ATTR_PRODUCT_NUMBER:
                    domainMetaStore.setProductIdDomain(domainName, (Integer) value);
                    break;
                case DomainMetaStore.META_ATTR_PRODUCT_ID:
                    domainMetaStore.setProductIdDomain(domainName, (String) value);
                    break;
            }
        } catch (Exception ex) {
            LOG.error("Unable to update attribute {} with value {} for domain {}",
                    metaAttribute, value, domainName, ex);
        }
    }

    void updateNewDomainMetaStoreDetails(Domain domain) {

        if (!StringUtil.isEmpty(domain.getBusinessService())) {
            updateDomainMetaStoreAttributeDetails(domain.getName(), DomainMetaStore.META_ATTR_BUSINESS_SERVICE,
                    domain.getBusinessService());
        }
        if (!StringUtil.isEmpty(domain.getAccount())) {
            updateDomainMetaStoreAttributeDetails(domain.getName(), DomainMetaStore.META_ATTR_AWS_ACCOUNT,
                    domain.getAccount());
        }
        if (!StringUtil.isEmpty(domain.getAzureSubscription())) {
            updateDomainMetaStoreAttributeDetails(domain.getName(), DomainMetaStore.META_ATTR_AZURE_SUBSCRIPTION,
                    domain.getAzureSubscription());
        }
        if (!StringUtil.isEmpty(domain.getGcpProject())) {
            updateDomainMetaStoreAttributeDetails(domain.getName(), DomainMetaStore.META_ATTR_GCP_PROJECT,
                    domain.getGcpProject());
        }
        if (domain.getYpmId() != null) {
            updateDomainMetaStoreAttributeDetails(domain.getName(), DomainMetaStore.META_ATTR_PRODUCT_NUMBER,
                    domain.getYpmId());
        }
        if (domain.getProductId() != null) {
            updateDomainMetaStoreAttributeDetails(domain.getName(), DomainMetaStore.META_ATTR_PRODUCT_ID,
                    domain.getProductId());
        }
    }

    Object getDomainMetaAttribute(DomainMeta meta, int metaAttribute) {
        Object value = null;
        switch (metaAttribute) {
            case DomainMetaStore.META_ATTR_BUSINESS_SERVICE:
                value = meta.getBusinessService();
                break;
            case DomainMetaStore.META_ATTR_AWS_ACCOUNT:
                value = meta.getAccount();
                break;
            case DomainMetaStore.META_ATTR_AZURE_SUBSCRIPTION:
                value = meta.getAzureSubscription();
                break;
            case DomainMetaStore.META_ATTR_GCP_PROJECT:
                value = meta.getGcpProject();
                break;
            case DomainMetaStore.META_ATTR_PRODUCT_NUMBER:
                value = meta.getYpmId();
                break;
            case DomainMetaStore.META_ATTR_PRODUCT_ID:
                value = meta.getProductId();
                break;
        }
        return value;
    }

    void updateExistingDomainMetaStoreDetails(final String domainName, DomainMeta meta, BitSet changedAttrs) {

        for (int metaAttribute : changedAttrs.stream().toArray()) {
            updateDomainMetaStoreAttributeDetails(domainName, metaAttribute,
                    getDomainMetaAttribute(meta, metaAttribute));
        }
    }

    void validateRoleMetaValues(RoleMeta meta) {

        final String caller = "validateRoleMetaValues";

        validateIntegerValue(meta.getMemberExpiryDays(), "memberExpiryDays");
        validateIntegerValue(meta.getServiceExpiryDays(), "serviceExpiryDays");
        validateIntegerValue(meta.getGroupExpiryDays(), "groupExpiryDays");
        validateIntegerValue(meta.getTokenExpiryMins(), "tokenExpiryMins");
        validateIntegerValue(meta.getCertExpiryMins(), "certExpiryMins");
        validateIntegerValue(meta.getMemberReviewDays(), "memberReviewDays");
        validateIntegerValue(meta.getServiceReviewDays(), "serviceReviewDays");
        validateIntegerValue(meta.getGroupReviewDays(), "groupReviewDays");
        validateIntegerValue(meta.getMaxMembers(), "maxMembers");
        validateIntegerValue(meta.getSelfRenewMins(), "selfRenewMins");

        validateString(meta.getNotifyRoles(), TYPE_RESOURCE_NAMES, caller);
        validateString(meta.getUserAuthorityFilter(), TYPE_AUTHORITY_KEYWORDS, caller);
        validateString(meta.getUserAuthorityExpiration(), TYPE_AUTHORITY_KEYWORD, caller);
    }

    void validateRoleValues(Role role) {

        final String caller = "validateRoleValues";

        validateIntegerValue(role.getMemberExpiryDays(), "memberExpiryDays");
        validateIntegerValue(role.getServiceExpiryDays(), "serviceExpiryDays");
        validateIntegerValue(role.getGroupExpiryDays(), "groupExpiryDays");
        validateIntegerValue(role.getTokenExpiryMins(), "tokenExpiryMins");
        validateIntegerValue(role.getCertExpiryMins(), "certExpiryMins");
        validateIntegerValue(role.getMemberReviewDays(), "memberReviewDays");
        validateIntegerValue(role.getServiceReviewDays(), "serviceReviewDays");
        validateIntegerValue(role.getGroupReviewDays(), "groupReviewDays");
        validateIntegerValue(role.getMaxMembers(), "maxMembers");
        validateIntegerValue(role.getSelfRenewMins(), "selfRenewMins");

        validateString(role.getNotifyRoles(), TYPE_RESOURCE_NAMES, caller);
        validateString(role.getUserAuthorityFilter(), TYPE_AUTHORITY_KEYWORDS, caller);
        validateString(role.getUserAuthorityExpiration(), TYPE_AUTHORITY_KEYWORD, caller);
    }

    void validateGroupValues(Group group) {

        final String caller = "validateGroupValues";

        validateIntegerValue(group.getMemberExpiryDays(), "memberExpiryDays");
        validateIntegerValue(group.getServiceExpiryDays(), "serviceExpiryDays");
        validateIntegerValue(group.getMaxMembers(), "maxMembers");
        validateIntegerValue(group.getSelfRenewMins(), "selfRenewMins");

        validateString(group.getNotifyRoles(), TYPE_RESOURCE_NAMES, caller);
        validateString(group.getUserAuthorityFilter(), TYPE_AUTHORITY_KEYWORDS, caller);
        validateString(group.getUserAuthorityExpiration(), TYPE_AUTHORITY_KEYWORD, caller);
    }

    void validateGroupMetaValues(GroupMeta meta) {

        final String caller = "validateGroupMetaValues";

        validateIntegerValue(meta.getMemberExpiryDays(), "memberExpiryDays");
        validateIntegerValue(meta.getServiceExpiryDays(), "serviceExpiryDays");
        validateIntegerValue(meta.getMaxMembers(), "maxMembers");
        validateIntegerValue(meta.getSelfRenewMins(), "selfRenewMins");

        validateString(meta.getNotifyRoles(), TYPE_RESOURCE_NAMES, caller);
        validateString(meta.getUserAuthorityFilter(), TYPE_AUTHORITY_KEYWORDS, caller);
        validateString(meta.getUserAuthorityExpiration(), TYPE_AUTHORITY_KEYWORD, caller);
    }

    @Override
    public void putDomainSystemMeta(ResourceContext ctx, String domainName, String attribute,
            String auditRef, DomainMeta meta) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validate(attribute, TYPE_SIMPLE_NAME, caller);

        // validate meta values - validator will enforce any patters
        // defined in the schema and we need to validate the rest of the
        // integer and string values. for now we're making sure we're not
        // getting any negative values for our integer settings

        validate(meta, TYPE_DOMAIN_META, caller);
        validateDomainMetaValues(meta);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        attribute = attribute.toLowerCase();
        AthenzObject.DOMAIN_META.convertToLowerCase(meta);

        // verify that request is properly authenticated for this request

        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        verifyAuthorizedServiceOperation(principal.getAuthorizedService(), caller);

        if (LOG.isDebugEnabled()) {
            LOG.debug("putDomainSystemMeta: name={}, attribute={}, meta={}",
                    domainName, attribute, meta);
        }

        // first obtain our domain object

        Domain domain = dbService.getDomain(domainName, true);
        if (domain == null) {
            throw ZMSUtils.notFoundError("No such domain: " + domainName, caller);
        }

        // if this is just to update the timestamp then we will handle it separately

        if (ZMSConsts.SYSTEM_META_LAST_MOD_TIME.equals(attribute)) {
            dbService.updateDomainModTimestamp(domainName);
            return;
        }

        // if we are resetting the configured value then the caller
        // must also have a delete action available for the same resource

        boolean deleteAllowed = isAllowedSystemMetaDelete(principal, domainName, attribute, "domain");

        // if this productId is already used by any domain it will be
        // seen in dbService and exception thrown but we want to make
        // sure here if product id support is required then we must
        // have one specified for a top level domain.

        if (productIdSupport && meta.getYpmId() == null && StringUtil.isEmpty(meta.getProductId()) &&
                domainName.indexOf('.') == -1 && ZMSConsts.SYSTEM_META_PRODUCT_ID.equals(attribute)) {
             throw ZMSUtils.requestError("Unique Product Id must be specified for top level domain", caller);
        }

        // if we're provided a user authority filter then we need to
        // make sure it's valid

        validateUserAuthorityFilterAttribute(meta.getUserAuthorityFilter(), caller);

        // if any of our meta values has changed we need to validate
        // them against the meta store

        BitSet changedAttrs = validateDomainSystemMetaStoreValues(domain, meta, attribute);

        // process our put domain meta request

        dbService.executePutDomainMeta(ctx, domain, meta, attribute, deleteAllowed, auditRef, caller);

        // since our operation was successful we need to see if we
        // need to update any of our values in the meta store

        updateExistingDomainMetaStoreDetails(domainName, meta, changedAttrs);
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

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        return dbService.listDomainTemplates(domainName);
    }

    @Override
    public void putDomainTemplate(ResourceContext ctx, String domainName, String auditRef,
            DomainTemplate domainTemplate) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(domainTemplate, TYPE_DOMAIN_TEMPLATE, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        AthenzObject.DOMAIN_TEMPLATE.convertToLowerCase(domainTemplate);

        // verify that all template names are valid

        List<String> templateNames = domainTemplate.getTemplateNames();
        if (ZMSUtils.isCollectionEmpty(templateNames)) {
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
    }

    @Override
    public void putDomainTemplateExt(ResourceContext ctx, String domainName,
            String templateName, String auditRef, DomainTemplate domainTemplate) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(templateName, TYPE_SIMPLE_NAME, caller);
        validate(domainTemplate, TYPE_DOMAIN_TEMPLATE, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        templateName = templateName.toLowerCase();
        AthenzObject.DOMAIN_TEMPLATE.convertToLowerCase(domainTemplate);

        // verify that all template names are valid

        List<String> templateNames = domainTemplate.getTemplateNames();
        if (ZMSUtils.isCollectionEmpty(templateNames)) {
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
    }

    @Override
    public void deleteDomainTemplate(ResourceContext ctx, String domainName, String templateName, String auditRef) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(templateName, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        templateName = templateName.toLowerCase();

        if (LOG.isDebugEnabled()) {
            LOG.debug("deleteDomainTemplate: domain={}, template={}", domainName, templateName);
        }

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(),
                caller, "name", templateName);

        List<String> templateNames = new ArrayList<>();
        templateNames.add(templateName);
        validateSolutionTemplates(templateNames, caller);

        dbService.executeDeleteDomainTemplate(ctx, domainName, templateName, auditRef, caller);
    }

    @Override
    public DomainMetaStoreValidValuesList getDomainMetaStoreValidValuesList(ResourceContext ctx, String attributeName, String userName) {
        final String caller = ctx.getApiName();

        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);

        if (LOG.isDebugEnabled()) {
            LOG.debug("getDomainMetaStoreValidValuesList: user: {}, attribute: {}", userName, attributeName);
        }

        if (StringUtil.isEmpty(attributeName)) {
            throw ZMSUtils.requestError("attributeName is mandatory", caller);
        }

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        if (userName != null) {
            userName = userName.toLowerCase();
        }

        List<String> values;
        switch (attributeName) {
            case DomainMetaStore.META_ATTR_BUSINESS_SERVICE_NAME:
                values = domainMetaStore.getValidBusinessServices(userName);
                break;
            case DomainMetaStore.META_ATTR_AWS_ACCOUNT_NAME:
                values = domainMetaStore.getValidAWSAccounts(userName);
                break;
            case DomainMetaStore.META_ATTR_AZURE_SUBSCRIPTION_NAME:
                values = domainMetaStore.getValidAzureSubscriptions(userName);
                break;
            case DomainMetaStore.META_ATTR_GCP_PROJECT_NAME:
                values = domainMetaStore.getValidGcpProjects(userName);
                break;
            case DomainMetaStore.META_ATTR_PRODUCT_NUMBER_NAME:
            case DomainMetaStore.META_ATTR_PRODUCT_ID_NAME:
                values = domainMetaStore.getValidProductIds(userName);
                break;
            default:
                throw ZMSUtils.requestError("Invalid attribute: " + attributeName, caller);
        }
        DomainMetaStoreValidValuesList domainMetaStoreValidValuesList = new DomainMetaStoreValidValuesList();
        domainMetaStoreValidValuesList.setValidValues(values);
        return domainMetaStoreValidValuesList;
    }

    @Override
    public AuthHistoryDependencies getAuthHistoryDependencies(ResourceContext ctx, String domainName) {
        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        return dbService.getAuthHistory(domainName);
    }

    @Override
    public Response deleteExpiredMembers(ResourceContext ctx, Integer purgeResources, String auditRef, Boolean returnObj) {
        final String caller = ctx.getApiName();
        logPrincipal(ctx);
        validateRequest(ctx.request(), caller);

        if (purgeResources == null) {
            // it is not provided, all resources will be purged
            purgeResources = 3;
        }

        if (!List.of(0, 1, 2, 3).contains(purgeResources)) {
            throw ZMSUtils.requestError("Invalid purgeResources value, error: should be a number in [0-3]", caller);
        }

        EnumSet<PurgeResourcesEnum>  purgeResourcesEnumSet = PurgeResourcesEnum.getPurgeResourcesState(purgeResources);

        LOG.info("deleteExpiredMembers: purgeResources: {}", purgeResourcesEnumSet);

        ExpiredMembers expiredMembers = new ExpiredMembers();

        if (purgeResourcesEnumSet.contains(PurgeResourcesEnum.ROLES)) {
            List<ExpiryMember> expiredRoleMembers = dbService.executeDeleteAllExpiredRoleMemberships(ctx, auditRef, caller);
            expiredMembers.setExpiredRoleMembers(expiredRoleMembers);
        }

        if (purgeResourcesEnumSet.contains(PurgeResourcesEnum.GROUPS)) {
            List<ExpiryMember> expiredGroupMembers = dbService.executeDeleteAllExpiredGroupMemberships(ctx, auditRef, caller);
            expiredMembers.setExpiredGroupMembers(expiredGroupMembers);
        }

        return ZMSUtils.returnPutResponse(returnObj, expiredMembers);
    }

    @Override
    public void putResourceDomainOwnership(ResourceContext ctx, String domainName,
            String auditRef, ResourceDomainOwnership resourceOwnership) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validateResourceOwnership(resourceOwnership, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        dbService.executePutResourceDomainOwnership(ctx, domainName, resourceOwnership, auditRef, caller);
    }

    boolean validateRoleBasedAccessCheck(List<String> roles, final String trustDomain, final String domainName,
                                         final String principalName) {

        if (trustDomain != null) {
            LOG.error("validateRoleBasedAccessCheck: Cannot access cross-domain resources with role");
            return false;
        }

        // for Role tokens we don't have a name component in the principal
        // so the principal name should be the same as the domain value
        // thus it must match the domain name from the resource

        boolean bResourceDomainMatch = domainName.equalsIgnoreCase(principalName);

        // now we're going to go through all the roles specified and make
        // sure if it contains ':role.' separator then the domain must
        // our requested domain name. If the role does not have the separator
        // then the bResourceDomainMatch must be true

        final String prefix = domainName + AuthorityConsts.ROLE_SEP;
        for (String role : roles) {

            // if our role starts with the prefix then we're good

            if (role.startsWith(prefix)) {
                continue;
            }

            // otherwise if it has a role separator then it's an error
            // not to match the domain

            if (role.contains(AuthorityConsts.ROLE_SEP)) {
                LOG.error("validateRoleBasedAccessCheck: role {} does not start with resource domain {}",
                        role, domainName);
                return false;
            }

            // so at this point we don't have a separator so our
            // resource and principal domains must match

            if (!bResourceDomainMatch) {
                LOG.error("validateRoleBasedAccessCheck: resource domain {} does not match role domain {}",
                        domainName, principalName);
                return false;
            }
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
                LOG.debug("getAthenzDomain failure: {}", ex.getMessage());
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
            LOG.debug("retrieveAccessDomain: identity: {} domain: {}", principal.getFullName(), domainName);
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
            List<String> authenticatedRoles, String trustDomain, Principal principal) {

        // In ZMS, mTLS restricted certs cannot be used in APIs that require authorization

        if (principal.getMtlsRestricted()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("evaluateAccess: mTLS restricted, access denied");
            }
            return AccessStatus.DENIED;
        }

        AccessStatus accessStatus = AccessStatus.DENIED;

        List<Policy> policies = domain.getPolicies();
        List<Role> roles = domain.getRoles();

        for (Policy policy : policies) {

            if (LOG.isDebugEnabled()) {
                LOG.debug("evaluateAccess: processing policy name/version/active: {}/{}/{}",
                        policy.getName(), policy.getVersion(), policy.getActive());
            }

            // ignore any inactive/multi-version policies

            if (policy.getActive() == Boolean.FALSE) {
                continue;
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

        if (!resource.startsWith(USER_DOMAIN_PREFIX)) {
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

            final String userName = resource.substring(USER_DOMAIN_PREFIX.length(), idx);
            homeResource = homeDomainPrefix + getUserDomainName(userName) + resource.substring(idx);

        } else if (!homeDomain.equals(ZMSConsts.USER_DOMAIN)) {
            homeResource = homeDomainPrefix + resource.substring(USER_DOMAIN_PREFIX.length());
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
            LOG.debug("access:({}, {}, {}, {})", action, resource, principal, trustDomain);
        }

        // check to see if the authority is allowed to be processed in
        // authorization checks. If this value is false then the principal
        // must get a usertoken from ZMS first and the submit the request
        // with that token

        if (!AuthzHelper.authorityAuthorizationAllowed(principal)) {
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

        String domainName = AuthzHelper.retrieveResourceDomain(resource, action, trustDomain);
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

    AccessStatus hasAccess(AthenzDomain domain, String action, String resource,
            Principal principal, String trustDomain) {

        String identity = principal.getFullName();

        // if we're dealing with an access check based on a Role token then
        // make sure it's valid before processing it

        List<String> authenticatedRoles = principal.getRoles();
        if (authenticatedRoles != null && !validateRoleBasedAccessCheck(authenticatedRoles, trustDomain,
                domain.getName(), identity)) {
            return AccessStatus.DENIED_INVALID_ROLE_TOKEN;
        }

        // evaluate our domain's roles and policies to see if access
        // is allowed or not for the given operation and resource

        return evaluateAccess(domain, identity, action, resource, authenticatedRoles, trustDomain, principal);
    }

    public Access getAccessExt(ResourceContext ctx, String action, String resource,
            String trustDomain, String checkPrincipal) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(action, TYPE_COMPOUND_NAME, caller);

        return getAccessCheck(((RsrcCtxWrapper) ctx).principal(), action, resource,
                trustDomain, checkPrincipal, ctx);
    }

    public Access getAccess(ResourceContext ctx, String action, String resource,
            String trustDomain, String checkPrincipal) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(action, TYPE_COMPOUND_NAME, caller);
        validate(resource, TYPE_RESOURCE_NAME, caller);

        return getAccessCheck(((RsrcCtxWrapper) ctx).principal(), action, resource,
                trustDomain, checkPrincipal, ctx);
    }

    Access getAccessCheck(Principal principal, String action, String resource,
            String trustDomain, String checkPrincipal, ResourceContext ctx) {

        final String caller = "getaccess";

        if (LOG.isDebugEnabled()) {
            LOG.debug("getAccessCheck:({}, {}, {}, {}, {})", action, resource, principal, trustDomain, checkPrincipal);
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

        String domainName = AuthzHelper.retrieveResourceDomain(resource, action, trustDomain);
        setRequestDomain(ctx, domainName);
        if (domainName == null) {
            setRequestDomain(ctx, ZMSConsts.ZMS_INVALID_DOMAIN);
            throw ZMSUtils.notFoundError("getAccessCheck: Unable to extract resource domain", caller);
        }
        AthenzDomain domain = retrieveAccessDomain(domainName, principal);
        if (domain == null) {
            setRequestDomain(ctx, ZMSConsts.ZMS_UNKNOWN_DOMAIN);
            throw ZMSUtils.notFoundError("getAccessCheck: Resource Domain not found: '"
                    + domainName + "'", caller);
        }

        // if the domain is disabled then we're going to reject this
        // request right away

        if (domain.getDomain().getEnabled() == Boolean.FALSE) {
            throw ZMSUtils.forbiddenError("getAccessCheck: Disabled domain: '"
                    + domainName + "'", caller);
        }

        // if the check principal is given then we need to carry out the access
        // check against that principal

        if (checkPrincipal != null) {
            principal = ZMSUtils.createPrincipalForName(checkPrincipal, userDomain, userDomainAlias);
            if (principal == null) {
                throw ZMSUtils.unauthorizedError("getAccessCheck: Invalid check principal value specified", caller);
            }
        }

        boolean accessAllowed = false;
        AccessStatus accessStatus = hasAccess(domain, action, resource, principal, trustDomain);
        if (accessStatus == AccessStatus.ALLOWED) {
            accessAllowed = true;
        }
        return new Access().setGranted(accessAllowed);
    }

    void validateEntity(final String domainName, final String entityName, Entity entity) {

        final String caller = "validateentity";

        final String fullEntityName = ResourceUtils.entityResourceName(domainName, entityName);
        if (!fullEntityName.equals(entity.getName())) {
            throw ZMSUtils.requestError("validateEntity: Entity name mismatch: " + fullEntityName + " != " + entity.getName(), caller);
        }
        if (entity.getValue() == null) {
            throw ZMSUtils.requestError("validateEntity: Entity value is empty: " + entityName, caller);
        }
    }

    @Override
    public void putEntity(ResourceContext ctx, String domainName, String entityName, String auditRef, Entity resource) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(entityName, TYPE_ENTITY_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        entityName = entityName.toLowerCase();
        AthenzObject.ENTITY.convertToLowerCase(resource);
        validateEntity(domainName, entityName, resource);

        // if this happens to be an authorization details entity then
        // we need to validate the structure to make sure it is as expected

        validateAuthorizationDetailsEntity(entityName, resource, caller);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        dbService.executePutEntity(ctx, domainName, entityName, resource, auditRef, caller);
    }

    void validateAuthorizationDetailsEntity(final String entityName, Entity resource, final String caller) {

        if (!entityName.startsWith(AuthzDetailsEntity.ENTITY_NAME_PREFIX)) {
            return;
        }

        // convert our entity into the expected object

        AuthzDetailsEntity authzDetailsEntity;
        try {
            authzDetailsEntity = AuthzHelper.convertEntityToAuthzDetailsEntity(resource);
        } catch (Exception ex) {
            throw ZMSUtils.requestError("Invalid authorization details entity object provided", caller);
        }

        // make sure we have a type value present in the

        if (StringUtil.isEmpty(authzDetailsEntity.getType())) {
            throw ZMSUtils.requestError("Authorization details entity object missing type", caller);
        }
        List<AuthzDetailsField> roles = authzDetailsEntity.getRoles();
        if (roles == null || roles.isEmpty()) {
            throw ZMSUtils.requestError("Authorization details entity object missing roles", caller);
        }
        List<AuthzDetailsField> fields = authzDetailsEntity.getFields();
        if (fields == null || fields.isEmpty()) {
            throw ZMSUtils.requestError("Authorization details entity object missing fields", caller);
        }
    }

    @Override
    public EntityList getEntityList(ResourceContext ctx, String domainName) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        EntityList result = new EntityList();
        List<String> names = dbService.listEntities(domainName);
        result.setNames(names);

        return result;
    }

    public Entity getEntity(ResourceContext ctx, String domainName, String entityName) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(entityName, TYPE_ENTITY_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        entityName = entityName.toLowerCase();

        Entity entity = dbService.getEntity(domainName, entityName);
        if (entity == null) {
            throw ZMSUtils.notFoundError("getEntity: Entity not found: '" +
                    ResourceUtils.entityResourceName(domainName, entityName) + "'", caller);
        }

        return entity;
    }

    @Override
    public void deleteEntity(ResourceContext ctx, String domainName, String entityName, String auditRef) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(entityName, TYPE_ENTITY_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        entityName = entityName.toLowerCase();

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        dbService.executeDeleteEntity(ctx, domainName, entityName, auditRef, caller);
    }

    public ServerTemplateList getServerTemplateList(ResourceContext ctx) {

        final String caller = ctx.getApiName();

        logPrincipal(ctx);
        validateRequest(ctx.request(), caller);

        return new ServerTemplateList().setTemplateNames(serverSolutionTemplateNames);
    }

    public Template getTemplate(ResourceContext ctx, String templateName) {

        final String caller = ctx.getApiName();

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

        return template;
    }

    @Override
    public DomainTemplateDetailsList getDomainTemplateDetailsList(ResourceContext ctx, String domainName) {
        final String caller = ctx.getApiName();
        logPrincipal(ctx);
        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all domain into lower case

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        List<TemplateMetaData> templateDomainMapping = dbService.getDomainTemplates(domainName);
        DomainTemplateDetailsList domainTemplateDetailsList = null;
        if (templateDomainMapping != null) {
            domainTemplateDetailsList = new DomainTemplateDetailsList();
            for (TemplateMetaData metaData : templateDomainMapping) {
                Template template = serverSolutionTemplates.get(metaData.getTemplateName());
                // there is a possibility of a stale template coming back from DB over time(caused by template clean up)
                if (template != null) {
                    //Merging template metadata fields from solution-templates.json and template data from DB
                    metaData.setLatestVersion(template.getMetadata().getLatestVersion());
                    metaData.setAutoUpdate(template.getMetadata().getAutoUpdate());
                    metaData.setDescription(template.getMetadata().getDescription());
                    metaData.setKeywordsToReplace(template.metadata.getKeywordsToReplace());
                    metaData.setTimestamp(template.metadata.getTimestamp());
                }
            }
            domainTemplateDetailsList.setMetaData(templateDomainMapping);
        }
        return domainTemplateDetailsList;
    }

    @Override
    public DomainTemplateDetailsList getServerTemplateDetailsList(ResourceContext ctx) {
        final String caller = ctx.getApiName();

        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);

        List<TemplateMetaData> serverTemplateMetadataList = serverSolutionTemplates.getTemplates()
                .entrySet()
                .stream()
                .map(template -> {
                    TemplateMetaData metadata = template.getValue().getMetadata();
                    metadata.setTemplateName(template.getKey());
                    return metadata;
                })
                .collect(Collectors.toList());

        DomainTemplateDetailsList serverTemplateDetailsList = new DomainTemplateDetailsList();
        serverTemplateDetailsList.setMetaData(serverTemplateMetadataList);
        return serverTemplateDetailsList;
    }

    public RoleList getRoleList(ResourceContext ctx, String domainName, Integer limit, String skip) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        if (skip != null) {
            skip = skip.toLowerCase();
        }

        RoleList result = new RoleList();

        List<String> names = new ArrayList<>(dbService.listRoles(domainName));
        final String next = processListRequest(limit, skip, names);
        result.setNames(names);
        if (next != null) {
            result.setNext(next);
        }

        return result;
    }

    List<Role> setupRoleList(AthenzDomain domain, Boolean members, String tagKey, String tagValue) {

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
                        .setTrust(role.getTrust())
                        .setAuditEnabled(role.getAuditEnabled())
                        .setSelfServe(role.getSelfServe())
                        .setMemberExpiryDays(role.getMemberExpiryDays())
                        .setServiceExpiryDays(role.getServiceExpiryDays())
                        .setGroupExpiryDays(role.getGroupExpiryDays())
                        .setGroupReviewDays(role.getGroupReviewDays())
                        .setTokenExpiryMins(role.getTokenExpiryMins())
                        .setCertExpiryMins(role.getCertExpiryMins())
                        .setMemberReviewDays(role.getMemberReviewDays())
                        .setServiceReviewDays(role.getServiceReviewDays())
                        .setSignAlgorithm(role.getSignAlgorithm())
                        .setDescription(role.getDescription())
                        .setReviewEnabled(role.getReviewEnabled())
                        .setDeleteProtection(role.getDeleteProtection())
                        .setLastReviewedDate(role.getLastReviewedDate())
                        .setTags(role.getTags());
                roles.add(newRole);
            }
        }

        // filter roles by their tags
        if (tagKey != null) {
            roles = roles.stream()
                    .filter(role -> filterByTag(tagKey, tagValue, role, Role::getTags))
                    .collect(Collectors.toList());
        }

        return roles;
    }

    private <T> boolean filterByTag(String tagKey, String tagValue, T tagCollection, Function<T, Map<String, TagValueList>> tagsGetter) {
        Map<String, TagValueList> tags = tagsGetter.apply(tagCollection);
        boolean result = tags != null && tags.get(tagKey) != null;

        // if tagValue is present we should filter tag values
        if (result && tagValue != null) {
            List<String> tagValues = tags.get(tagKey).getList();
            result = tagValues != null && tagValues.contains(tagValue);
        }
        return result;
    }

    public Roles getRoles(ResourceContext ctx, String domainName, Boolean members, String tagKey, String tagValue) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        if (!StringUtil.isEmpty(tagKey)) {
            validate(tagKey, TYPE_TAG_KEY, caller);
        }
        if (!StringUtil.isEmpty(tagValue)) {
            validate(tagValue, TYPE_TAG_COMPOUND_VALUE, caller);
        }

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        Roles result = new Roles();

        AthenzDomain domain = getAthenzDomain(domainName, false);
        if (domain == null) {
            throw ZMSUtils.notFoundError("getRoles: Domain not found: '" + domainName + "'", caller);
        }

        result.setList(setupRoleList(domain, members, tagKey, tagValue));
        return result;
    }

    @Override
    public DomainRoleMembers getDomainRoleMembers(ResourceContext ctx, String domainName) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        return dbService.listDomainRoleMembers(domainName);
    }

    @Override
    public DomainRoleMember getPrincipalRoles(ResourceContext context, String principal, String domainName, Boolean expand) {
        final String caller = context.getApiName();
        logPrincipal(context);

        // If principal not specified, get roles for current user

        if (StringUtil.isEmpty(principal)) {
            principal = ((RsrcCtxWrapper) context).principal().getFullName();
        }
        validateRequest(context.request(), caller);
        validate(principal, TYPE_RESOURCE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        principal = principal.toLowerCase();

        if (!StringUtil.isEmpty(domainName)) {
            validate(domainName, TYPE_DOMAIN_NAME, caller);
            domainName = domainName.toLowerCase();
            setRequestDomain(context, domainName);
        }

        // if we're asked to expand all groups and delegated roles then
        // we're going to carry out an authorization check

        if (expand == Boolean.TRUE && !isAllowedExpandedRoleLookup(((RsrcCtxWrapper) context).principal(), principal, domainName)) {
            throw ZMSUtils.forbiddenError("principal is not authorized to request expanded role lookup", caller);
        }

        return dbService.getPrincipalRoles(principal, domainName, expand);
    }

    boolean isAllowedExpandedRoleLookup(Principal principal, final String checkPrincipal, final String domainName) {

        // Expanded role lookup requires one of these authorization checks
        // 1. authenticated principal is the same as the check principal
        // 2. system authorized ("access", "sys.auth:meta.role.lookup")
        // 3. service admin ("update", "{principal}")
        // 4. domain authorized ("access", "{domain}:meta.role.lookup") if domain is provided

        if (checkPrincipal.equals(principal.getFullName())) {
            return true;
        }

        // if the domain is provided then we're going to check to see if the principal
        // is authorized for role lookup access within the domain

        if (!StringUtil.isEmpty(domainName)) {
            AthenzDomain requestDomain = getAthenzDomain(domainName, true);
            if (requestDomain != null) {
                AccessStatus accessStatus = hasAccess(requestDomain, "access",
                        domainName + ":meta.role.lookup", principal, null);
                if (accessStatus == AccessStatus.ALLOWED) {
                    return true;
                }
            }
        }

        // if the check principal is another user, then this is not allowed
        // unless the principal is authorized at system level

        AthenzDomain domain = getAthenzDomain(SYS_AUTH, true);

        // evaluate our domain's roles and policies to see if access
        // is allowed or not for the given operation and resource
        // our action are always converted to lowercase


        AccessStatus accessStatus = hasAccess(domain, "access", "sys.auth:meta.role.lookup", principal, null);
        if (accessStatus == AccessStatus.ALLOWED) {
            return true;
        }

        // at this point one user cannot ask for another user

        if (ZMSUtils.isUserDomainPrincipal(checkPrincipal, userDomainPrefix, addlUserCheckDomainPrefixList)) {
            return false;
        }

        // for service accounts, the principal must have an update action
        // on the service identity object

        int idx = checkPrincipal.lastIndexOf('.');
        if (idx == -1) {
            LOG.debug("invalid check principal: {}", checkPrincipal);
            return false;
        }

        final String checkPrincipalDomain = checkPrincipal.substring(0, idx);
        final String checkResource = checkPrincipalDomain + ":service." + checkPrincipal.substring(idx + 1);

        domain = getAthenzDomain(checkPrincipalDomain, true);
        if (domain == null) {
            LOG.debug("invalid check principal domain: {}", checkPrincipal);
            return false;
        }

        accessStatus = hasAccess(domain, "update", checkResource, principal, null);
        return accessStatus == AccessStatus.ALLOWED;
    }

    @Override
    public Role getRole(ResourceContext ctx, String domainName, String roleName,
            Boolean auditLog, Boolean expand, Boolean pending) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        roleName = roleName.toLowerCase();

        Role role = dbService.getRole(domainName, roleName, auditLog, expand, pending);
        if (role == null) {
            throw ZMSUtils.notFoundError("getRole: Role not found: '" +
                    ResourceUtils.roleResourceName(domainName, roleName) + "'", caller);
        }

        return role;
    }

    List<String> normalizedAdminUsers(List<String> admins, final String domainUserAuthorityFilter, final String caller) {

        // let's use a set so we can strip out any duplicates

        Set<String> normalizedAdmins = new HashSet<>();
        for (String admin : admins) {
            normalizedAdmins.add(normalizeDomainAliasUser(admin));
        }

        // now go through the list and make sure they're all valid

        for (String admin : normalizedAdmins) {
            validateRoleMemberPrincipal(admin, principalType(admin), domainUserAuthorityFilter, null, null, true, caller);
        }

        return new ArrayList<>(normalizedAdmins);
    }

    int principalType(final String principalName) {
        return ZMSUtils.principalType(principalName, userDomainPrefix, addlUserCheckDomainPrefixList, headlessUserDomainPrefix).getValue();
    }

    String normalizeDomainAliasUser(String user) {
        if (user != null && userDomainAliasPrefix != null && user.startsWith(userDomainAliasPrefix)) {
            if (user.indexOf('.', userDomainAliasPrefix.length()) == -1) {
                return userDomainPrefix + user.substring(userDomainAliasPrefix.length());
            }
        }
        return user;
    }

    private boolean addNormalizedRoleMember(Map<String, RoleMember> normalizedMembers,
            RoleMember member) {

        member.setMemberName(normalizeDomainAliasUser(member.getMemberName()));

        // we'll automatically ignore any duplicates

        if (!normalizedMembers.containsKey(member.getMemberName())) {
            normalizedMembers.put(member.getMemberName(), member);
            return true;
        }
        return false;
    }

    void normalizeRoleMembers(Role role) {

        Map<String, RoleMember> normalizedMembers = new HashMap<>();

        // normalize getMembers() first

        List<String> members = role.getMembers();
        if (members != null) {
            LOG.error("DEPRECATED - Role {} provided with old members", role.getName());
            for (String memberOld : members) {
                RoleMember member = new RoleMember().setMemberName(memberOld);
                if (addNormalizedRoleMember(normalizedMembers, member)) {
                    member.setPrincipalType(principalType(member.getMemberName()));
                }
            }
        }

        // normalize getRoleMembers() now

        List<RoleMember> roleMembers = role.getRoleMembers();
        if (roleMembers != null) {
            for (RoleMember member : roleMembers) {
                if (addNormalizedRoleMember(normalizedMembers, member)) {
                    member.setPrincipalType(principalType(member.getMemberName()));
                }
            }
        }

        role.setRoleMembers(new ArrayList<>(normalizedMembers.values()));
        role.setMembers(null);
    }

    boolean isConsistentRoleName(final String domainName, final String roleName, Role role) {

        String resourceName = ResourceUtils.roleResourceName(domainName, roleName);

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
    public Response putRole(ResourceContext ctx, String domainName, String roleName, String auditRef,
            Boolean returnObj, String resourceOwner, Role role) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);
        validate(role, TYPE_ROLE, caller);
        validateRoleValues(role);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        roleName = roleName.toLowerCase();
        AthenzObject.ROLE.convertToLowerCase(role);

        // verify the role name in the URI and request are consistent

        if (!isConsistentRoleName(domainName, roleName, role)) {
            throw ZMSUtils.requestError("putRole: Inconsistent role names - expected: "
                    + ResourceUtils.roleResourceName(domainName, roleName) + ", actual: "
                    + role.getName(), caller);
        }

        // validate the user authority settings if they're provided

        validateUserAuthorityAttributes(role.getUserAuthorityFilter(), role.getUserAuthorityExpiration(), caller);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        Domain domain = dbService.getDomain(domainName, false);
        if (domain == null) {
            throw ZMSUtils.notFoundError("No such domain: " + domainName, caller);
        }

        // validate role and trust settings are as expected

        validateRoleStructure(role, domainName, caller);

        // normalize and remove duplicate members

        normalizeRoleMembers(role);

        // check to see if we need to validate user and service members
        // and possibly user authority filter restrictions. For the
        // admin role we're not going to allow any group members to
        // enforce the least privilege access where specific users must
        // be specified as members.

        boolean disallowGroups = ADMIN_ROLE_NAME.equals(roleName);
        validateRoleMemberPrincipals(role, domain.getUserAuthorityFilter(), disallowGroups, caller);

        // validate role review-enabled and/or audit-enabled flags

        validateRoleReviewAuditFlag(domain, role, caller);

        // update role expiry based on our configurations

        MemberDueDays memberExpiryDueDays = new MemberDueDays(domain, role, MemberDueDays.Type.EXPIRY);
        MemberDueDays memberReminderDueDays = new MemberDueDays(null, role, MemberDueDays.Type.REMINDER);

        updateRoleMemberExpiration(memberExpiryDueDays, role.getRoleMembers());

        // update role review based on our configurations

        updateRoleMemberReviewReminder(memberReminderDueDays, role.getRoleMembers());

        // update role expiry based on user authority expiry
        // if configured

        updateRoleMemberUserAuthorityExpiry(role, caller);

        // process our request

        Role dbRole = dbService.executePutRole(ctx, domainName, roleName, role, auditRef, caller, returnObj);
        return ZMSUtils.returnPutResponse(returnObj, dbRole);
    }

    void validateRoleReviewAuditFlag(final Domain domain, final Role role, final String caller) {

        // role cannot be requested to be audit-enabled if the domain is not audit enabled

        if (role.getAuditEnabled() == Boolean.TRUE && domain.getAuditEnabled() != Boolean.TRUE) {
            throw ZMSUtils.requestError("Role cannot be set as audit-enabled if the domain is not audit-enabled", caller);
        }

        // if the role is review and/or audit enabled then it cannot contain
        // role members as we want review and audit enabled roles
        // to be enabled as such and then add individual members

        if (!role.getRoleMembers().isEmpty()) {
            if (role.getReviewEnabled() == Boolean.TRUE) {
                throw ZMSUtils.requestError("Set review-enabled flag using role meta api", caller);
            }
            if (role.getAuditEnabled() == Boolean.TRUE) {
                throw ZMSUtils.requestError("Only system admins can set the role as audit-enabled if it has members", caller);
            }
        }
    }

    void validateRoleStructure(final Role role, final String domainName, final String caller) {

        if (!ZMSUtils.isCollectionEmpty(role.getMembers()) && !ZMSUtils.isCollectionEmpty(role.getRoleMembers())) {
            throw ZMSUtils.requestError("validateRoleMembers: Role cannot have both members and roleMembers set", caller);
        }

        // if this is a delegated role then validate that it's not
        // delegated back to itself and there are no members since
        // those 2 fields are mutually exclusive

        if (!StringUtil.isEmpty(role.getTrust())) {

            AthenzDomain athenzDomain = getAthenzDomain(role.getTrust(), true);
            if (athenzDomain == null) {
                throw ZMSUtils.requestError("Delegated role assigned to non existing domain", caller);
            }

            if (!ZMSUtils.isCollectionEmpty(role.getRoleMembers())) {
                throw ZMSUtils.requestError("validateRoleMembers: Role cannot have both roleMembers and delegated domain set", caller);
            }

            if (!ZMSUtils.isCollectionEmpty(role.getMembers())) {
                throw ZMSUtils.requestError("validateRoleMembers: Role cannot have both members and delegated domain set", caller);
            }

            if (domainName.equals(role.getTrust())) {
                throw ZMSUtils.requestError("validateRoleMembers: Role cannot be delegated to itself", caller);
            }
        }
    }

    void validateRoleMemberPrincipals(final Role role, final String domainUserAuthorityFilter, boolean disallowGroups,
                                      final String caller) {

        // extract the user authority filter for the role

        final String userAuthorityFilter = enforcedUserAuthorityFilter(role.getUserAuthorityFilter(),
                domainUserAuthorityFilter);

        for (RoleMember roleMember : role.getRoleMembers()) {
            validateRoleMemberPrincipal(roleMember.getMemberName(), roleMember.getPrincipalType(),
                    userAuthorityFilter, role.getUserAuthorityExpiration(), role.getAuditEnabled(),
                    disallowGroups, caller);
        }
    }

    void updateRoleMemberUserAuthorityExpiry(final Role role, final String caller) {

        // getUserAuthorityExpiryAttr also verifies that we have a valid
        // user authority configured in the server

        final String userAuthorityExpiry = getUserAuthorityExpiryAttr(role.getUserAuthorityExpiration());
        if (userAuthorityExpiry == null) {
            return;
        }

        for (RoleMember roleMember : role.getRoleMembers()) {

            // we only process users and automatically ignore services and groups
            // which are not handled by user authority

            if (roleMember.getPrincipalType() == Principal.Type.USER.getValue()) {

                // if we don't have an expiry specified for the user
                // then we're not going to allow this member

                Date expiry = userAuthority.getDateAttribute(roleMember.getMemberName(), userAuthorityExpiry);
                if (expiry == null) {
                    throw ZMSUtils.requestError("Invalid member: " + roleMember.getMemberName() +
                            ". No expiry date attribute specified in user authority", caller);
                }
                roleMember.setExpiration(Timestamp.fromDate(expiry));
            }
        }
    }

    void validateUserPrincipal(final String memberName, boolean validateUserMember, final String userAuthorityFilter,
                               final String caller) {

        if (userAuthority == null) {
            return;
        }

        if (validateUserMember) {
            if (!userAuthority.isValidUser(memberName)) {
                throw ZMSUtils.requestError("Principal " + memberName + " is not valid", caller);
            }
        }

        // once we know it's a valid principal and we have a user
        // authority filter configured, we'll check that as well
        // if we're already determined that the principal is not
        // valid there is no point of running this check

        if (!StringUtil.isEmpty(userAuthorityFilter)) {
            if (!ZMSUtils.isUserAuthorityFilterValid(userAuthority, userAuthorityFilter, memberName)) {
                throw ZMSUtils.requestError("Invalid member: " + memberName +
                        ". Required user authority filter not valid for the member", caller);
            }
        }
    }

    void validateServicePrincipal(final String memberName, final String caller) {

        int idx = memberName.lastIndexOf('.');
        if (idx == -1) {
            throw ZMSUtils.requestError("Principal " + memberName + " is not valid", caller);
        }

        final String domainName = memberName.substring(0, idx);
        final String serviceName = memberName.substring(idx + 1);

        // first we need to check if the domain is on the list of
        // our skip domains for service member validation. these
        // are typically domains (like for ci/cd) where services
        // are dynamic and do not need to be registered in Athenz

        for (String skipDomain : validateServiceMemberSkipDomains) {
            // first, we perform validation using wildcards
            if (skipDomain.endsWith("*")) {
                String skipDomainPrefix = skipDomain.substring(0, skipDomain.length() - 1);
                if (domainName.startsWith(skipDomainPrefix)) {
                    return;
                }
            } else if (skipDomain.equals(domainName)) {
                // if skipDomain doesn't have wildcard, we conduct a perfect match search
                return;
            }
        }
        // if it reaches here, check if the service exists
        if (dbService.getServiceIdentity(domainName, serviceName, true) == null) {
            throw ZMSUtils.requestError("Principal " + memberName + " is not a valid service", caller);
        }
    }

    void validateGroupPrincipal(final String memberName, final String userAuthorityFilter,
                                final String userAuthorityExpiration, Boolean auditEnabled, final String caller) {

        Group group = getGroup(memberName);
        if (group == null) {
            throw ZMSUtils.requestError("Principal " + memberName + " is not valid", caller);
        }

        if (ZMSUtils.userAuthorityAttrMissing(userAuthorityFilter, group.getUserAuthorityFilter())) {
            throw ZMSUtils.requestError("Group " + memberName + " does not have same user authority filter "
                    + userAuthorityFilter + " configured", caller);
        }

        if (ZMSUtils.userAuthorityAttrMissing(userAuthorityExpiration, group.getUserAuthorityExpiration())) {
            throw ZMSUtils.requestError("Group " + memberName + " does not have same user authority expiration "
                    + userAuthorityExpiration + " configured", caller);
        }

        // verify if role is audit enabled and we have a group member then
        // group must also have audit enabled flag

        if (auditEnabled == Boolean.TRUE && group.getAuditEnabled() != Boolean.TRUE) {
            throw ZMSUtils.requestError("Group " + memberName + " must be audit enabled", caller);
        }
    }

    void validateRoleMemberPrincipal(final String memberName, int principalType, final String userAuthorityFilter,
                                     final String userAuthorityExpiration, Boolean roleAuditEnabled,
                                     boolean disallowGroups, final String caller) {

        switch (Principal.Type.getType(principalType)) {

            case USER:
            case USER_HEADLESS:

                // if the account contains a wildcard then we're going
                // to let the user authority decide if it's valid or not

                validateUserPrincipal(memberName, validateUserRoleMembers.get(), userAuthorityFilter, caller);
                break;

            case SERVICE:

                if (validateServiceRoleMembers.get()) {

                    // if the account contains a wildcard character then
                    // we're going to assume it's valid

                    if (memberName.indexOf('*') == -1) {
                        validateServicePrincipal(memberName, caller);
                    }
                }

                break;

            case GROUP:

                if (disallowGroups) {
                    throw ZMSUtils.requestError("Group principals are not allowed in the role", caller);
                }

                validateGroupPrincipal(memberName, userAuthorityFilter, userAuthorityExpiration, roleAuditEnabled, caller);
                break;

            default:

                throw ZMSUtils.requestError("Principal " + memberName + " is not valid", caller);
        }
    }

    void validateGroupMemberPrincipal(final String memberName, int principalType, final String userAuthorityFilter,
                                      final String caller) {

        // we do not support any type of wildcards in group members

        if (memberName.indexOf('*') != -1) {
            throw ZMSUtils.requestError("Principal " + memberName + " is not valid", caller);
        }

        switch (Principal.Type.getType(principalType)) {

            case USER:
            case USER_HEADLESS:

                // for group members we always validate all members

                validateUserPrincipal(memberName, true, userAuthorityFilter, caller);
                break;

            case SERVICE:

                validateServicePrincipal(memberName, caller);
                break;

            default:

                throw ZMSUtils.requestError("Principal " + memberName + " is not valid", caller);
        }
    }

    @Override
    public void deleteRole(ResourceContext ctx, String domainName, String roleName, String auditRef, String resourceOwner) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        roleName = roleName.toLowerCase();

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        // we are not going to allow any user to delete
        // the admin role and policy since those are required
        // for standard domain operations */

        if (roleName.equalsIgnoreCase(ADMIN_ROLE_NAME)) {
            throw ZMSUtils.requestError("deleteRole: admin role cannot be deleted", caller);
        }

        // if enabled, we are not going to allow any user to delete a
        // role that is referenced in any assertion of any policy

        if (validatePolicyAssertionRoles.get() == Boolean.TRUE) {
            validateRoleNotAssociatedToPolicy(getPolicyList(domainName, caller), roleName, domainName, caller);
        }

        dbService.executeDeleteRole(ctx, domainName, roleName, auditRef, caller);
    }

    private List<Policy> getPolicyList(final String domainName, final String caller) {
        AthenzDomain domain = getAthenzDomain(domainName, false, true);
        if (domain == null) {
            throw ZMSUtils.notFoundError(caller + ": Domain not found: '" + domainName + "'", caller);
        }
        return setupPolicyList(domain, true, true, null, null);
    }

    void validateRoleNotAssociatedToPolicy(List<Policy> policies, final String roleName,
            final String domainName, final String caller) {

        final String fullRoleName = ResourceUtils.roleResourceName(domainName, roleName);
        for (Policy policy : policies) {
            if (policy.getAssertions() == null) {
                continue;
            }
            for (Assertion assertion : policy.getAssertions()) {
                if (assertion.getRole().equals(fullRoleName)) {
                    throw ZMSUtils.requestError("deleteRole: the role: " + roleName + " associated to policy: "
                            + policy.name + ", it cannot be deleted", caller);
                }
            }
        }
    }

    boolean isMemberOfRole(Role role, String member) {
        List<RoleMember> roleMembers = role.getRoleMembers();
        if (roleMembers == null) {
            return false;
        }
        return AuthzHelper.checkRoleMemberValidity(roleMembers, member, groupMemberFetcher);
    }

    @Override
    public Membership getMembership(ResourceContext ctx, String domainName,
            String roleName, String memberName, String expiration) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);
        validate(memberName, TYPE_MEMBER_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        roleName = roleName.toLowerCase();
        memberName = normalizeDomainAliasUser(memberName.toLowerCase());
        long expiryTimestamp = getModTimestamp(expiration);

        return dbService.getMembership(domainName, roleName, memberName, expiryTimestamp, false);
    }

    @Override
    public DomainRoleMembers getOverdueReview(ResourceContext ctx, String domainName) {
        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        return dbService.listOverdueReviewRoleMembers(domainName);
    }

    Timestamp getMemberDueDate(long cfgDueDateMillis, Timestamp memberDueDate) {
        if (memberDueDate == null) {
            return Timestamp.fromMillis(cfgDueDateMillis);
        } else if (memberDueDate.millis() > cfgDueDateMillis) {
            return Timestamp.fromMillis(cfgDueDateMillis);
        } else {
            return memberDueDate;
        }
    }

    void updateRoleMemberExpiration(MemberDueDays memberExpiryDueDays, List<RoleMember> roleMembers) {
        updateMemberDueDate(
                memberExpiryDueDays,
                roleMembers,
                RoleMember::getExpiration,
                RoleMember::setExpiration,
                RoleMember::getPrincipalType);
    }

    void updateRoleMemberReviewReminder(MemberDueDays memberReminderDueDays, List<RoleMember> roleMembers) {
        updateMemberDueDate(
                memberReminderDueDays,
                roleMembers,
                RoleMember::getReviewReminder,
                RoleMember::setReviewReminder,
                RoleMember::getPrincipalType);
    }

    private <T> void updateMemberDueDate(MemberDueDays memberDueDays,
                                         List<T> members,
                                         Function<T, Timestamp> dueDateGetter,
                                         BiConsumer<T, Timestamp> dueDateSetter,
                                         Function<T, Integer> principalTypeGetter) {

        long cfgUserMemberDueDateMillis = memberDueDays.getUserDueDateMillis();
        long cfgServiceMemberDueDateMillis = memberDueDays.getServiceDueDateMillis();
        long cfgGroupMemberDueDateMillis = memberDueDays.getGroupDueDateMillis();

        // if we have no value configured then we have nothing to
        // do so we'll just return right away

        if (cfgUserMemberDueDateMillis == 0 && cfgServiceMemberDueDateMillis == 0 && cfgGroupMemberDueDateMillis == 0) {
            return;
        }

        // go through the members and update due date as necessary

        for (T member : members) {

            Timestamp currentDueDate = dueDateGetter.apply(member);
            switch (Principal.Type.getType(principalTypeGetter.apply(member))) {
                case USER:
                    if (cfgUserMemberDueDateMillis != 0) {
                        Timestamp newDueDate = getMemberDueDate(cfgUserMemberDueDateMillis, currentDueDate);
                        dueDateSetter.accept(member, newDueDate);
                    }
                    break;
                case SERVICE:
                case USER_HEADLESS:
                    if (cfgServiceMemberDueDateMillis != 0) {
                        Timestamp newDueDate = getMemberDueDate(cfgServiceMemberDueDateMillis, currentDueDate);
                        dueDateSetter.accept(member, newDueDate);
                    }
                    break;
                case GROUP:
                    if (cfgGroupMemberDueDateMillis != 0) {
                        Timestamp newDueDate = getMemberDueDate(cfgGroupMemberDueDateMillis, currentDueDate);
                        dueDateSetter.accept(member, newDueDate);
                    }
                    break;
            }
        }
    }

    Timestamp memberDueDateTimestamp(Integer domainDueDateDays, Integer roleDueDateDays, Timestamp memberDueDate) {

        long cfgExpiryMillis = ZMSUtils.configuredDueDateMillis(domainDueDateDays, roleDueDateDays);

        // if we have no value configured then return
        // the membership expiration as is

        if (cfgExpiryMillis == 0) {
            return memberDueDate;
        }

        // otherwise compare the configured expiry days with the specified
        // membership value and choose the smallest expiration value

        return getMemberDueDate(cfgExpiryMillis, memberDueDate);
    }

    @Override
    public Response putMembership(ResourceContext ctx, String domainName, String roleName,
            String memberName, String auditRef, Boolean returnObj, String resourceOwner, Membership membership) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        setRequestDomain(ctx, domainName);
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

        final Principal principal = ((RsrcCtxWrapper) ctx).principal();

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceRoleOperation(principal.getAuthorizedService(), caller, roleName);

        // verify that the member name in the URI and object provided match

        if (!memberName.equals(membership.getMemberName())) {
            throw ZMSUtils.requestError("putMembership: Member name in URI and Membership object do not match", caller);
        }

        // role name is optional so we'll verify only if the value is present in the object

        if (membership.getRoleName() != null && !roleName.equals(membership.getRoleName())) {
            throw ZMSUtils.requestError("putMembership: Role name in URI and Membership object do not match", caller);
        }

        // extract our role object to get its attributes

        AthenzDomain domain = getAthenzDomain(domainName, false);
        Role role = getRoleFromDomain(roleName, domain);

        if (role == null) {
            throw ZMSUtils.requestError("Invalid role name specified", caller);
        }

        // create and normalize the role member object

        RoleMember roleMember = new RoleMember();
        roleMember.setMemberName(normalizeDomainAliasUser(memberName));
        roleMember.setPrincipalType(principalType(roleMember.getMemberName()));
        setRoleMemberExpiration(domain, role, roleMember, membership, caller);
        setRoleMemberReview(role, roleMember, membership);

        // check to see if we need to validate the principal

        final String userAuthorityFilter = enforcedUserAuthorityFilter(role.getUserAuthorityFilter(),
                domain.getDomain().getUserAuthorityFilter());
        boolean disallowGroups = ADMIN_ROLE_NAME.equals(roleName);
        validateRoleMemberPrincipal(roleMember.getMemberName(), roleMember.getPrincipalType(), userAuthorityFilter,
                role.getUserAuthorityExpiration(), role.getAuditEnabled(), disallowGroups, caller);

        // authorization check which also automatically updates
        // the active and approved flags for the request

        if (!isAllowedPutMembership(principal, domain, role, roleMember)) {
            throw ZMSUtils.forbiddenError("putMembership: principal is not authorized to add members", caller);
        }

        // add the member to the specified role

        Membership dbMembership = dbService.executePutMembership(ctx, domainName, roleName, roleMember, auditRef, caller, returnObj);

        // new role member with pending status. Notify approvers

        if (roleMember.getApproved() == Boolean.FALSE) {
            sendMembershipApprovalNotification(domainName, domain.getDomain().getOrg(), roleName,
                    roleMember.getMemberName(), auditRef, principal.getFullName(), role);
        }

        return ZMSUtils.returnPutResponse(returnObj, dbMembership);
    }

    String enforcedUserAuthorityFilter(final String roleUserAuthorityFilter, final String domainUserAuthorityFilter) {

        // for a filter to be enforced we need to make sure we have
        // a valid user authority object along with non-empty filter

        if (userAuthority == null) {
            return null;
        }

        return ZMSUtils.combineUserAuthorityFilters(roleUserAuthorityFilter, domainUserAuthorityFilter);
    }

    String getUserAuthorityExpiryAttr(final String userAuthorityExpiry) {

        // we must have a valid user authority and non-empty expiry setting

        return (userAuthority == null || StringUtil.isEmpty(userAuthorityExpiry)) ? null : userAuthorityExpiry;
    }

    Timestamp getUserAuthorityExpiry(final String userName, final String expiryAttrValue, final String caller) {

        // getUserAuthorityExpiryAttr also verifies that we have a valid
        // user authority configured in the server

        final String userAuthorityExpiry = getUserAuthorityExpiryAttr(expiryAttrValue);
        if (userAuthorityExpiry == null) {
            return null;
        }

        // if we don't get an expiry then we're going to throw an exception
        // since based on our config we must have an expiry specified

        Date expiry = userAuthority.getDateAttribute(userName, userAuthorityExpiry);
        if (expiry == null) {
            throw ZMSUtils.requestError("User does not have required user authority expiry configured", caller);
        }

        return Timestamp.fromDate(expiry);
    }

    void setRoleMemberExpiration(final AthenzDomain domain, final Role role, final RoleMember roleMember,
            final Membership membership, final String caller) {

        switch (Principal.Type.getType(roleMember.getPrincipalType())) {

            case USER:

                Timestamp userAuthorityExpiry = getUserAuthorityExpiry(roleMember.memberName, role.getUserAuthorityExpiration(), caller);
                if (userAuthorityExpiry != null) {
                    roleMember.setExpiration(userAuthorityExpiry);
                } else {
                    roleMember.setExpiration(memberDueDateTimestamp(domain.getDomain().getMemberExpiryDays(),
                            role.getMemberExpiryDays(), membership.getExpiration()));
                }
                break;

            case SERVICE:
            case USER_HEADLESS:

                roleMember.setExpiration(memberDueDateTimestamp(domain.getDomain().getServiceExpiryDays(),
                        role.getServiceExpiryDays(), membership.getExpiration()));
                break;

            case GROUP:

                roleMember.setExpiration(memberDueDateTimestamp(domain.getDomain().getGroupExpiryDays(),
                        role.getGroupExpiryDays(), membership.getExpiration()));
                break;
        }
    }

    void setRoleMemberReview(final Role role, final RoleMember roleMember,
                                 final Membership membership) {

        switch (Principal.Type.getType(roleMember.getPrincipalType())) {
            case USER:
                roleMember.setReviewReminder(memberDueDateTimestamp(null,
                        role.getMemberReviewDays(), membership.getReviewReminder()));
                break;

            case SERVICE:
            case USER_HEADLESS:
                roleMember.setReviewReminder(memberDueDateTimestamp(null,
                        role.getServiceReviewDays(), membership.getReviewReminder()));
                break;

            case GROUP:
                roleMember.setReviewReminder(memberDueDateTimestamp(null,
                        role.getGroupReviewDays(), membership.getReviewReminder()));
                break;
        }
    }

     void sendMembershipApprovalNotification(final String domain, final String org, final String roleName,
            final String member, final String auditRef, final String principal, final Role role) {
        Map<String, String> details = new HashMap<>();
        details.put(NOTIFICATION_DETAILS_DOMAIN, domain);
        details.put(NOTIFICATION_DETAILS_ROLE, roleName);
        details.put(NOTIFICATION_DETAILS_MEMBER, member);
        details.put(NOTIFICATION_DETAILS_REASON, auditRef);
        details.put(NOTIFICATION_DETAILS_REQUESTER, principal);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending Membership Approval notification after putMembership");
        }

        List<Notification> notifications = new PutRoleMembershipNotificationTask(domain, org, role, details, dbService, userDomainPrefix, notificationToEmailConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);
    }

    void sendGroupMembershipApprovalNotification(final String domain, final String org, final String groupName,
                                                 final String member, final String auditRef, final String principal,
                                                 final Group group) {
        Map<String, String> details = new HashMap<>();
        details.put(NOTIFICATION_DETAILS_DOMAIN, domain);
        details.put(NOTIFICATION_DETAILS_GROUP, groupName);
        details.put(NOTIFICATION_DETAILS_MEMBER, member);
        details.put(NOTIFICATION_DETAILS_REASON, auditRef);
        details.put(NOTIFICATION_DETAILS_REQUESTER, principal);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending Group Membership Approval notification after putGroupMembership");
        }

        List<Notification> notifications = new PutGroupMembershipNotificationTask(domain, org, group, details, dbService, userDomainPrefix, notificationToEmailConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);
    }

    @Override
    public void deletePendingMembership(ResourceContext ctx, String domainName, String roleName,
            String memberName, String auditRef) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);
        validate(memberName, TYPE_MEMBER_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        roleName = roleName.toLowerCase();
        memberName = normalizeDomainAliasUser(memberName.toLowerCase());

        // verify that request is properly authenticated for this request

        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        verifyAuthorizedServiceRoleOperation(principal.getAuthorizedService(), caller, roleName);

        // authorization check - there are two supported use cases
        // 1) the caller has authorization in the domain to update members in a role
        // 2) the caller is the original requestor for the pending request

        if (!isAllowedDeletePendingMembership(principal, domainName, roleName, memberName)) {
            throw ZMSUtils.forbiddenError("deletePendingMembership: principal is not authorized to delete pending members", caller);
        }

        // delete the member from the specified role

        dbService.executeDeletePendingMembership(ctx, domainName, roleName, memberName, auditRef, caller);
    }

    @Override
    public void deleteMembership(ResourceContext ctx, String domainName, String roleName,
            String memberName, String auditRef, String resourceOwner) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);
        validate(memberName, TYPE_MEMBER_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        roleName = roleName.toLowerCase();
        memberName = memberName.toLowerCase();

        final Principal principal = ((RsrcCtxWrapper) ctx).principal();

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceRoleOperation(principal.getAuthorizedService(), caller, roleName);

        // extract our role object to get its attributes

        AthenzDomain domain = getAthenzDomain(domainName, false);
        Role role = getRoleFromDomain(roleName, domain);

        if (role == null) {
            throw ZMSUtils.notFoundError("Invalid domain/role name specified", caller);
        }

        // authorization check since we have 2 actions: update and update_members
        // that allow access callers to manage members in a role plus we allow
        // delete operation if the principal matches membername

        final String normalizedMember = normalizeDomainAliasUser(memberName);
        if (!(principal.getFullName().equals(normalizedMember) || isAllowedPutMembershipAccess(principal, domain, role.getName()))) {
            throw ZMSUtils.forbiddenError("deleteMembership: principal is not authorized to delete members", caller);
        }

        // if this is the admin role then we need to make sure
        // the admin is not himself who happens to be the last
        // member in the role

        if (ZMSConsts.ADMIN_ROLE_NAME.equals(roleName)) {
            List<RoleMember> members = role.getRoleMembers();
            if (members.size() == 1 && members.get(0).getMemberName().equals(normalizedMember)) {
                throw ZMSUtils.forbiddenError("deleteMembership: Cannot delete last member of 'admin' role", caller);
            }
        }

        dbService.executeDeleteMembership(ctx, domainName, roleName, normalizedMember, auditRef, caller);
    }

    @Override
    public Stats getStats(ResourceContext ctx, String domainName) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        return dbService.getStats(domainName);
    }

    @Override
    public Stats getSystemStats(ResourceContext ctx) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        return dbService.getStats(null);
    }

    @Override
    public Quota getQuota(ResourceContext ctx, String domainName) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        return dbService.getQuota(domainName);
    }

    @Override
    public void putQuota(ResourceContext ctx, String domainName, String auditRef, Quota quota) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(quota, TYPE_QUOTA, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        AthenzObject.QUOTA.convertToLowerCase(quota);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(),
                caller);

        // verify that the domain name in the URI and object provided match

        if (!domainName.equals(quota.getName())) {
            throw ZMSUtils.requestError("putQuota: Domain name in URI and Quota object do not match", caller);
        }

        dbService.executePutQuota(ctx, domainName, quota, auditRef, caller);
    }

    @Override
    public void deleteQuota(ResourceContext ctx, String domainName, String auditRef) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        dbService.executeDeleteQuota(ctx, domainName, auditRef, caller);
    }

    boolean hasExceededListLimit(Integer limit, int count) {

        if (limit == null) {
            return false;
        }

        return limit > 0 && count > limit;
    }

    /**
     * Cut the list from a specific entry until limit is reached.
     * if the limit is specified and we have reached that limit then return
     * the name of the object that should be set at the next item for the
     * subsequent list operation.
     */
    String processListRequest(Integer limit, String skip, List<String> names) {
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

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        if (skip != null) {
            skip = skip.toLowerCase();
        }

        List<String> names = new ArrayList<>(dbService.listPolicies(domainName));
        final String next = processListRequest(limit, skip, names);
        PolicyList result = new PolicyList().setNames(names);
        if (next != null) {
            result.setNext(next);
        }

        return result;
    }

    @Override
    public PolicyList getPolicyVersionList(ResourceContext ctx, String domainName, String policyName) {
        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_ENTITY_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        policyName = policyName.toLowerCase();
        setRequestDomain(ctx, domainName);

        List<String> names = dbService.listPolicyVersions(domainName, policyName);

        return new PolicyList().setNames(names);
    }

    @Override
    public Policy getPolicyVersion(ResourceContext ctx, String domainName, String policyName, String version) {
        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_ENTITY_NAME, caller);
        validate(version, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        policyName = policyName.toLowerCase();
        version = version.toLowerCase();

        Policy policy = dbService.getPolicy(domainName, policyName, version);
        if (policy == null) {
            throw ZMSUtils.notFoundError(caller + ": Policy not found: '" +
                    ResourceUtils.policyResourceName(domainName, policyName) + "' with version: " + version, caller);
        }

        return policy;
    }

    @Override
    public Response putPolicyVersion(ResourceContext ctx, String domainName, String policyName,
            PolicyOptions policyOptions, String auditRef, Boolean returnObj, String resourceOwner) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_COMPOUND_NAME, caller);
        validate(policyOptions, TYPE_POLICY_OPTIONS, caller);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        policyName = policyName.toLowerCase();
        AthenzObject.POLICY_OPTIONS.convertToLowerCase(policyOptions);

        // we are not going to allow any user to update
        // the admin policy since that is required
        // for standard domain operations */

        if (policyName.equalsIgnoreCase(ADMIN_POLICY_NAME)) {
            throw ZMSUtils.requestError(caller + ": admin policy cannot be modified", caller);
        }

        Policy dbPolicy = dbService.executePutPolicyVersion(ctx, domainName, policyName, policyOptions.getVersion(), policyOptions.getFromVersion(), auditRef, caller, returnObj);

        return ZMSUtils.returnPutResponse(returnObj, dbPolicy);
    }

    @Override
    public void setActivePolicyVersion(ResourceContext ctx, String domainName, String policyName,
            PolicyOptions policyOptions, String auditRef, String resourceOwner) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_COMPOUND_NAME, caller);
        validate(policyOptions, TYPE_POLICY_OPTIONS, caller);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        policyName = policyName.toLowerCase();
        AthenzObject.POLICY_OPTIONS.convertToLowerCase(policyOptions);

        // we are not going to allow any user to update
        // the admin policy since that is required
        // for standard domain operations */

        if (policyName.equalsIgnoreCase(ADMIN_POLICY_NAME)) {
            throw ZMSUtils.requestError(caller + ": admin policy cannot be modified", caller);
        }

        dbService.executeSetActivePolicy(ctx, domainName, policyName, policyOptions.getVersion(), auditRef, caller);
    }

    @Override
    public void deletePolicyVersion(ResourceContext ctx, String domainName, String policyName, String version,
            String auditRef, String resourceOwner) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_ENTITY_NAME, caller);
        validate(version, TYPE_SIMPLE_NAME, caller);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        policyName = policyName.toLowerCase();
        version = version.toLowerCase();

        // we are not going to allow any user to delete
        // the admin role and policy since those are required
        // for standard domain operations */

        if (policyName.equalsIgnoreCase(ADMIN_POLICY_NAME)) {
            throw ZMSUtils.requestError(caller + ": admin policy version cannot be deleted", caller);
        }

        dbService.executeDeletePolicyVersion(ctx, domainName, policyName, version, auditRef, caller);
    }

    @Override
    public void putResourcePolicyOwnership(ResourceContext ctx, String domainName,
            String policyName, String auditRef, ResourcePolicyOwnership resourceOwnership) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_ENTITY_NAME, caller);
        validateResourceOwnership(resourceOwnership, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        policyName = policyName.toLowerCase();

        dbService.executePutResourcePolicyOwnership(ctx, domainName, policyName, resourceOwnership, auditRef, caller);
    }

    List<Policy> setupPolicyList(AthenzDomain domain, Boolean assertions, Boolean versions, String tagKey, String tagValue) {

        // if we're asked to return the assertions as well then we
        // just need to return the data as is without any modifications

        List<Policy> policies;
        if (assertions == Boolean.TRUE && versions == Boolean.TRUE) {
            policies = domain.getPolicies();
        } else {
            policies = new ArrayList<>();
            for (Policy policy : domain.getPolicies()) {

                // if we're only asked for active versions then skip
                // any multi-version policies

                if (versions != Boolean.TRUE && policy.getActive() == Boolean.FALSE) {
                    continue;
                }

                if (assertions == Boolean.TRUE) {
                    policies.add(policy);
                } else {
                    Policy newPolicy = new Policy()
                            .setName(policy.getName())
                            .setModified(policy.getModified())
                            .setVersion(policy.getVersion())
                            .setActive(policy.getActive())
                            .setTags(policy.getTags());
                    policies.add(newPolicy);
                }
            }
        }

        if (tagKey != null) {
            policies = policies.stream()
                    .filter(policy -> (filterByTag(tagKey, tagValue, policy, Policy::getTags)))
                    .collect(Collectors.toList());
        }

        return policies;
    }

    @Override
    public Policies getPolicies(ResourceContext ctx, String domainName, Boolean assertions, Boolean includeNonActive, String tagKey, String tagValue) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        Policies result = new Policies();

        AthenzDomain domain = getAthenzDomain(domainName, false);
        if (domain == null) {
            throw ZMSUtils.notFoundError(caller + ": Domain not found: '" + domainName + "'", caller);
        }

        result.setList(setupPolicyList(domain, assertions, includeNonActive, tagKey, tagValue));
        return result;
    }

    public Policy getPolicy(ResourceContext ctx, String domainName, String policyName) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_ENTITY_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        policyName = policyName.toLowerCase();

        Policy policy = dbService.getPolicy(domainName, policyName, null);
        if (policy == null) {
            throw ZMSUtils.notFoundError(caller + ": Policy not found: '" +
                    ResourceUtils.policyResourceName(domainName, policyName) + "'", caller);
        }

        return policy;
    }

    public Assertion getAssertion(ResourceContext ctx, String domainName, String policyName,
            Long assertionId) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_ENTITY_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        policyName = policyName.toLowerCase();

        Assertion assertion = dbService.getAssertion(domainName, policyName, assertionId);
        if (assertion == null) {
            throw ZMSUtils.notFoundError("getAssertion: Assertion not found: '" +
                    ResourceUtils.policyResourceName(domainName, policyName) + "' Assertion: '" +
                    assertionId + "'", caller);
        }

        return assertion;
    }

    @Override
    public Assertion putAssertion(ResourceContext ctx, String domainName, String policyName,
            String auditRef, String resourceOwner, Assertion assertion) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_COMPOUND_NAME, caller);
        validate(assertion, TYPE_ASSERTION, caller);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        policyName = policyName.toLowerCase();
        AthenzObject.ASSERTION.convertToLowerCase(assertion);

        // we are not going to allow any user to update
        // the admin policy since that is required
        // for standard domain operations */

        if (policyName.equalsIgnoreCase(ADMIN_POLICY_NAME)) {
            throw ZMSUtils.requestError("putAssertion: admin policy cannot be modified", caller);
        }

        // validate to make sure we have expected values for assertion fields
        // - and also to make sure that the associated role exists

        validatePolicyAssertion(assertion, domainName, new HashSet<>(), caller);

        dbService.executePutAssertion(ctx, domainName, policyName, null, assertion, auditRef, caller);
        return assertion;
    }

    @Override
    public Assertion putAssertionPolicyVersion(ResourceContext ctx, String domainName, String policyName, String version,
            String auditRef, String resourceOwner, Assertion assertion) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_COMPOUND_NAME, caller);
        validate(assertion, TYPE_ASSERTION, caller);
        validate(version, TYPE_SIMPLE_NAME, caller);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        policyName = policyName.toLowerCase();
        version = version.toLowerCase();
        AthenzObject.ASSERTION.convertToLowerCase(assertion);

        // we are not going to allow any user to update
        // the admin policy since that is required
        // for standard domain operations */

        if (policyName.equalsIgnoreCase(ADMIN_POLICY_NAME)) {
            throw ZMSUtils.requestError("putAssertionPolicyVersion: admin policy cannot be modified", caller);
        }

        // validate to make sure we have expected values for assertion fields
        // - and also to make sure that the associated role exists

        validatePolicyAssertion(assertion, domainName, new HashSet<>(), caller);

        dbService.executePutAssertion(ctx, domainName, policyName, version, assertion, auditRef, caller);
        return assertion;
    }

    void validateRoleAssociatedIsExist(Set<String> roleNames, String lookingForRole, String domainName, String caller) {

        String shortRoleName = ZMSUtils.removeDomainPrefix(lookingForRole, domainName, ROLE_PREFIX);
        if (!roleNames.contains(shortRoleName)) {
            throw ZMSUtils.requestError("The role: " + lookingForRole + " that associated to an assertion does not exist", caller);
        }
    }

    @Override
    public void deleteAssertion(ResourceContext ctx, String domainName, String policyName,
            Long assertionId, String auditRef, String resourceOwner) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_ENTITY_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        policyName = policyName.toLowerCase();

        // we are not going to allow any user to update
        // the admin policy since that is required
        // for standard domain operations */

        if (policyName.equalsIgnoreCase(ADMIN_POLICY_NAME)) {
            throw ZMSUtils.requestError("deleteAssertion: admin policy cannot be modified", caller);
        }

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        dbService.executeDeleteAssertion(ctx, domainName, policyName, null, assertionId, auditRef, caller);
    }

    @Override
    public void deleteAssertionPolicyVersion(ResourceContext ctx, String domainName, String policyName,
            String version, Long assertionId, String auditRef, String resourceOwner) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_ENTITY_NAME, caller);
        validate(version, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        policyName = policyName.toLowerCase();
        version = version.toLowerCase();

        // we are not going to allow any user to update
        // the admin policy since that is required
        // for standard domain operations */

        if (policyName.equalsIgnoreCase(ADMIN_POLICY_NAME)) {
            throw ZMSUtils.requestError("deleteAssertion: admin policy cannot be modified", caller);
        }

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        dbService.executeDeleteAssertion(ctx, domainName, policyName, version, assertionId, auditRef, caller);
    }

    void validatePolicyAssertions(List<Assertion> assertions, final String roleDomainName, final String caller) {

        if (assertions == null) {
            return;
        }

        // send this to func 'validatePolicyAssertion' since it doesn't need to
        // retrieve the roleList for every assertion

        Set<String> roleNamesCache = new HashSet<>();
        for (Assertion assertion : assertions) {
            validatePolicyAssertion(assertion, roleDomainName, roleNamesCache, caller);
        }
    }

    void validatePolicyAssertionConditions(List<Assertion> assertions, String caller) {
        if (assertions == null) {
            return;
        }
        for (Assertion a : assertions) {
            if (a.getConditions() != null) {
                validateAssertionConditions(a.getConditions(), caller);
            }
        }
    }

    void validatePolicyAssertion(Assertion assertion, final String roleDomainName, Set<String> roleNamesSet,
            final String caller) {

        // validate the overall structure of the assertion object

        ZMSUtils.validatePolicyAssertion(validator, assertion, false, caller);

        // if enabled, we are not going to allow any user to add/update
        // an assertion that the associated role does not exist
        // retrieve role list only if it hasn't been made for
        // another assertion in the same domain already

        if (validatePolicyAssertionRoles.get() == Boolean.TRUE) {

            if (roleNamesSet.isEmpty()) {
                roleNamesSet.addAll(dbService.listRoles(roleDomainName));
            }

            validateRoleAssociatedIsExist(roleNamesSet, assertion.getRole(), roleDomainName, caller);
        }
    }

    boolean isConsistentPolicyName(final String domainName, final String policyName, Policy policy) {

        String resourceName = ResourceUtils.policyResourceName(domainName, policyName);

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
    public Response putPolicy(ResourceContext ctx, String domainName, String policyName, String auditRef,
            Boolean returnObj, String resourceOwner, Policy policy) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_COMPOUND_NAME, caller);
        validate(policy, TYPE_POLICY, caller);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        policyName = policyName.toLowerCase();
        AthenzObject.POLICY.convertToLowerCase(policy);
        if (policy.getActive() == null) {
            policy.setActive(Boolean.TRUE);
        }

        // we are not going to allow any user to update
        // the admin policy since that is required
        // for standard domain operations */

        if (policyName.equalsIgnoreCase(ADMIN_POLICY_NAME)) {
            throw ZMSUtils.requestError("putPolicy: admin policy cannot be modified", caller);
        }

        // verify the policy name in the URI and request are consistent

        if (!isConsistentPolicyName(domainName, policyName, policy)) {
            throw ZMSUtils.requestError("putPolicy: Inconsistent policy names - expected: "
                    + ResourceUtils.policyResourceName(domainName, policyName) + ", actual: "
                    + policy.getName(), caller);
        }

        // validate to make sure we have expected values for assertion fields
        // also that all the roles that associates does exists

        validatePolicyAssertions(policy.getAssertions(), domainName, caller);

        validatePolicyAssertionConditions(policy.getAssertions(), caller);

        Policy dbPolicy = dbService.executePutPolicy(ctx, domainName, policyName, policy, auditRef, caller, returnObj);

        return ZMSUtils.returnPutResponse(returnObj, dbPolicy);
    }

    @Override
    public void deletePolicy(ResourceContext ctx, String domainName, String policyName, String auditRef,
            String resourceOwner) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_ENTITY_NAME, caller);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        policyName = policyName.toLowerCase();

        // we are not going to allow any user to delete
        // the admin role and policy since those are required
        // for standard domain operations */

        if (policyName.equalsIgnoreCase(ADMIN_POLICY_NAME)) {
            throw ZMSUtils.requestError("deletePolicy: admin policy cannot be deleted", caller);
        }

        dbService.executeDeletePolicy(ctx, domainName, policyName, auditRef, caller);
    }

    boolean delegatedTrust(String domainName, String roleName, String roleMember) {

        AthenzDomain domain = getAthenzDomain(domainName, true);
        if (domain == null) {
            return false;
        }

        for (Policy policy : domain.getPolicies()) {

            // ignore any inactive/multi-version policies

            if (policy.getActive() == Boolean.FALSE) {
                continue;
            }

            if (AuthzHelper.matchDelegatedTrustPolicy(policy, roleName, roleMember, domain.getRoles(), groupMemberFetcher)) {
                return true;
            }
        }

        return false;
    }

    boolean matchRole(String domain, List<Role> roles, String rolePattern, List<String> authenticatedRoles) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("matchRole domain: {} rolePattern: {}", domain, rolePattern);
        }

        String prefix = domain + AuthorityConsts.ROLE_SEP;
        int prefixLen = prefix.length();
        for (Role role : roles) {
            final String name = role.getName();
            if (!name.matches(rolePattern)) {
                continue;
            }

            // depending if the authority we either have the full role name
            // or only the short name (we have verified the prefix already)
            // so we're going to check both

            if (authenticatedRoles.contains(name) || authenticatedRoles.contains(name.substring(prefixLen))) {
                return true;
            }
        }
        return false;
    }

    boolean matchPrincipalInRole(Role role, String roleName, String fullUser, String trustDomain) {

        // if we have members in the role then we're going to check
        // against that list only

        if (role.getRoleMembers() != null) {
            return isMemberOfRole(role, fullUser);
        }

        // no members so let's check if this is a trust domain

        String trust = role.getTrust();
        if (!AuthzHelper.shouldRunDelegatedTrustCheck(trust, trustDomain)) {
            return false;
        }

        // delegate to another domain.

        if (LOG.isDebugEnabled()) {
            LOG.debug("matchPrincipal: [delegated trust. Checking with: {}]", trust);
        }

        return delegatedTrust(trust, roleName, fullUser);
    }

    boolean matchPrincipal(List<Role> roles, String rolePattern, String fullUser, String trustDomain) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("matchPrincipal - rolePattern: {} user: {} trust: {}", rolePattern, fullUser, trustDomain);
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

        String actionPattern = StringUtils.patternFromGlob(assertion.getAction().toLowerCase());
        if (LOG.isDebugEnabled()) {
            LOG.debug("assertionMatch: action '{}' pattern '{}'", action, actionPattern);
        }
        if (!action.matches(actionPattern)) {
            return false;
        }

        String rezPattern = StringUtils.patternFromGlob(assertion.getResource().toLowerCase());
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
            LOG.debug("assertionMatch: -> {} (effect: {})", matchResult, assertion.getEffect());
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
            LOG.debug("verifyProviderEndpoint: verifying endpoint: {}", providerEndpoint);
        }

        java.net.URI uri;
        try {
            uri = new java.net.URI(providerEndpoint);
        } catch (URISyntaxException ex) {
            return false;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("verifyProviderEndpoint: host:{} scheme: {}", uri.getHost(), uri.getScheme());
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
            Crypto.loadPublicKey(Crypto.ybase64DecodeString(key));
        } catch (Exception ex) {
            LOG.error("verifyServicePublicKey: Invalid Public Key: {}", ex.getMessage());
            return false;
        }
        return true;
    }

    boolean verifyServicePublicKeys(ServiceIdentity service) {

        // verify that the public keys specified are valid
        // It's okay to not specify any public keys

        List<PublicKeyEntry> publicKeyList = service.getPublicKeys();
        if (ZMSUtils.isCollectionEmpty(publicKeyList)) {
            return true;
        }

        for (PublicKeyEntry entry : publicKeyList) {
            if (!verifyServicePublicKey(entry.getKey())) {
                return false;
            }
        }
        return true;
    }

    public boolean isValidServiceName(final String domainName, final String serviceName, StringBuilder errorMessage) {

        // first check the list of configured reserved names

        if (reservedServiceNames != null && reservedServiceNames.contains(serviceName)) {
            errorMessage.append("reserved service name");
            return false;
        }

        // if we're not allowed to have underscores in service names then
        // we need to check if the service exists or not since we do not
        // want to block managing service accounts that were created before
        // the option was enforced or the domain is configured to allow
        // services with underscores

        if (allowUnderscoreInServiceNames.get() == Boolean.FALSE && serviceName.indexOf('_') != -1) {
            if ((!isDomainFeatureFlagEnabled(domainName, ZMSConsts.ZMS_FEATURE_ALLOW_SERVICE_UNDERSCORE)) &&
                    dbService.getServiceIdentity(domainName, serviceName, true) == null) {
                errorMessage.append("service name with underscore not allowed");
                return false;
            }
        }

        // finally, return result based on the configured minimum length of the service name

        if (serviceNameMinLength > 0 && serviceNameMinLength > serviceName.length()) {
            errorMessage.append("service name length too short");
            return false;
        }

        return true;
    }

    boolean isDomainFeatureFlagEnabled(final String domainName, int flag) {
        Domain domain = dbService.getDomain(domainName, false);
        Integer featureFlags = domain.getFeatureFlags();
        return featureFlags != null && (featureFlags & flag) != 0;
    }

    @Override
    public Response putServiceIdentity(ResourceContext ctx, String domainName, String serviceName,
            String auditRef, Boolean returnObj, String resourceOwner, ServiceIdentity service) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(serviceName, TYPE_SIMPLE_NAME, caller);
        validate(service, TYPE_SERVICE_IDENTITY, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        serviceName = serviceName.toLowerCase();
        AthenzObject.SERVICE_IDENTITY.convertToLowerCase(service);

        // validate that the service name is valid

        StringBuilder errorMessage = new StringBuilder(64);
        if (!isValidServiceName(domainName, serviceName, errorMessage)) {
            throw ZMSUtils.requestError("putServiceIdentity: " + errorMessage, caller);
        }

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        if (!ResourceUtils.serviceResourceName(domainName, serviceName).equals(service.getName())) {
            throw ZMSUtils.requestError("putServiceIdentity: Inconsistent service/domain names", caller);
        }

        if (!verifyServicePublicKeys(service)) {
            throw ZMSUtils.requestError("putServiceIdentity: Provided public key is invalid", caller);
        }

        if (!verifyProviderEndpoint(service.getProviderEndpoint())) {
            throw ZMSUtils.requestError("putServiceIdentity: Invalid endpoint: "
                + service.getProviderEndpoint() + " - must be http(s) and in configured domain", caller);
        }

        ServiceIdentity dbServiceIdentity = dbService.executePutServiceIdentity(ctx, domainName,
                serviceName, service, auditRef, caller, returnObj);

        return ZMSUtils.returnPutResponse(returnObj, dbServiceIdentity);
    }

    @Override
    public void putServiceIdentitySystemMeta(ResourceContext ctx, String domainName, String serviceName,
             String attribute, String auditRef, ServiceIdentitySystemMeta meta) {

        final String caller = "putservicesystemmeta";
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(serviceName, TYPE_SIMPLE_NAME, caller);
        validate(meta, TYPE_SERVICE_IDENTITY_SYSTEM_META, caller);
        validate(attribute, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        serviceName = serviceName.toLowerCase();
        attribute = attribute.toLowerCase();

        // verify that request is properly authenticated for this request

        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        verifyAuthorizedServiceOperation(principal.getAuthorizedService(), caller);

        if (LOG.isDebugEnabled()) {
            LOG.debug("putServiceIdentitySystemMeta: name={}, service={} attribute={}, meta={}",
                    domainName, serviceName, attribute, meta);
        }

        dbService.executePutServiceIdentitySystemMeta(ctx, domainName, serviceName, meta, attribute, auditRef, caller);
    }

    @Override
    public void putResourceServiceIdentityOwnership(ResourceContext ctx, String domainName,
            String serviceName, String auditRef, ResourceServiceIdentityOwnership resourceOwnership) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(serviceName, TYPE_SIMPLE_NAME, caller);
        validateResourceOwnership(resourceOwnership, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        serviceName = serviceName.toLowerCase();

        dbService.executePutResourceServiceOwnership(ctx, domainName, serviceName, resourceOwnership, auditRef, caller);
    }

    public ServiceIdentity getServiceIdentity(ResourceContext ctx, String domainName, String serviceName) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(serviceName, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        serviceName = serviceName.toLowerCase();

        ServiceIdentity service = dbService.getServiceIdentity(domainName, serviceName, false);
        if (service == null) {
            throw ZMSUtils.notFoundError("getServiceIdentity: Service not found: '" +
                    ResourceUtils.serviceResourceName(domainName, serviceName) + "'", caller);
        }

        return service;
    }

    @Override
    public void deleteServiceIdentity(ResourceContext ctx, String domainName, String serviceName,
            String auditRef, String resourceOwner) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(serviceName, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        serviceName = serviceName.toLowerCase();

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        // make sure no domain is dependent on the service

        verifyNoDomainDependenciesOnService(domainName + "." + serviceName, caller);

        dbService.executeDeleteServiceIdentity(ctx, domainName, serviceName, auditRef, caller);
    }

    List<ServiceIdentity> setupServiceIdentityList(AthenzDomain domain, Boolean publicKeys, Boolean hosts, String tagKey, String tagValue) {

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
                        .setDescription(service.getDescription())
                        .setModified(service.getModified())
                        .setExecutable(service.getExecutable())
                        .setGroup(service.getGroup())
                        .setUser(service.getUser())
                        .setProviderEndpoint(service.getProviderEndpoint())
                        .setTags(service.getTags());
                if (publicKeys == Boolean.TRUE) {
                    newService.setPublicKeys(service.getPublicKeys());
                } else if (hosts == Boolean.TRUE) {
                    newService.setHosts(service.getHosts());
                }
                services.add(newService);
            }
        }

        if (tagKey != null) {
            services = services.stream()
                    .filter(service -> filterByTag(tagKey, tagValue, service, ServiceIdentity::getTags))
                    .collect(Collectors.toList());
        }

        return services;
    }

    public ServiceIdentities getServiceIdentities(ResourceContext ctx, String domainName,
            Boolean publicKeys, Boolean hosts, String tagKey, String tagValue) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        if (!StringUtil.isEmpty(tagKey)) {
            validate(tagKey, TYPE_TAG_KEY, caller);
        }
        if (!StringUtil.isEmpty(tagValue)) {
            validate(tagValue, TYPE_TAG_COMPOUND_VALUE, caller);
        }

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        ServiceIdentities result = new ServiceIdentities();

        AthenzDomain domain = getAthenzDomain(domainName, false);
        if (domain == null) {
            throw ZMSUtils.notFoundError("getServiceIdentities: Domain not found: '"
                    + domainName + "'", caller);
        }

        result.setList(setupServiceIdentityList(domain, publicKeys, hosts, tagKey, tagValue));
        return result;
    }

    public ServiceIdentityList getServiceIdentityList(ResourceContext ctx, String domainName,
            Integer limit, String skip) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        if (skip != null) {
            skip = skip.toLowerCase();
        }

        List<String> names = new ArrayList<>(dbService.listServiceIdentities(domainName));
        final String next = processListRequest(limit, skip, names);
        ServiceIdentityList result = new ServiceIdentityList().setNames(names);
        if (next != null) {
            result.setNext(next);
        }

        return result;
    }

    public PublicKeyEntry getPublicKeyEntry(ResourceContext ctx, String domainName, String serviceName, String keyId) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(serviceName, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        serviceName = serviceName.toLowerCase();
        keyId = keyId.toLowerCase();

        PublicKeyEntry entry = dbService.getServicePublicKeyEntry(domainName, serviceName, keyId, false);
        if (entry == null) {
            throw ZMSUtils.notFoundError("getPublicKeyEntry: PublicKey " + keyId + " in service " +
                    ResourceUtils.serviceResourceName(domainName, serviceName) + " not found", caller);
        }

        return entry;
    }

    @Override
    public void deletePublicKeyEntry(ResourceContext ctx, String domainName, String serviceName,
            String keyId, String auditRef, String resourceOwner) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(serviceName, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        serviceName = serviceName.toLowerCase();
        keyId = keyId.toLowerCase();

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        dbService.executeDeletePublicKeyEntry(ctx, domainName, serviceName, keyId, auditRef, caller);
    }

    @Override
    public void putPublicKeyEntry(ResourceContext ctx, String domainName, String serviceName,
            String keyId, String auditRef, String resourceOwner, PublicKeyEntry keyEntry) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(serviceName, TYPE_SIMPLE_NAME, caller);
        validate(keyEntry, TYPE_PUBLIC_KEY_ENTRY, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        serviceName = serviceName.toLowerCase();
        keyId = keyId.toLowerCase();
        AthenzObject.PUBLIC_KEY_ENTRY.convertToLowerCase(keyEntry);

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
    }

    String removeQuotes(String value) {
        if (value.startsWith("\"")) {
            value = value.substring(1);
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

    SignedDomain createSignedDomain(String domainName, long modifiedTime, Boolean enabled) {
        SignedDomain signedDomain = new SignedDomain();
        DomainData domainData = new DomainData().setName(domainName);
        signedDomain.setDomain(domainData);
        domainData.setModified(Timestamp.fromMillis(modifiedTime));
        domainData.setEnabled(enabled);
        return signedDomain;
    }

    SignedDomain retrieveSignedDomainMeta(final Domain domain, final String metaAttr) {

        SignedDomain signedDomain = createSignedDomain(domain.getName(), domain.getModified().millis(),
                domain.getEnabled());
        if (metaAttr != null) {
            switch (metaAttr) {
                case ZMSConsts.SYSTEM_META_ACCOUNT:
                    final String account = domain.getAccount();
                    if (account == null) {
                        return null;
                    }
                    signedDomain.getDomain().setAccount(account);
                    break;
                case ZMSConsts.SYSTEM_META_AZURE_SUBSCRIPTION:
                    final String azureSubscription = domain.getAzureSubscription();
                    if (azureSubscription == null) {
                        return null;
                    }
                    signedDomain.getDomain().setAzureSubscription(azureSubscription);
                    break;
                case ZMSConsts.SYSTEM_META_GCP_PROJECT:
                    final String gcpProject = domain.getGcpProject();
                    if (gcpProject == null) {
                        return null;
                    }
                    signedDomain.getDomain().setGcpProject(gcpProject);
                    signedDomain.getDomain().setGcpProjectNumber(domain.getGcpProjectNumber());
                    break;
                case ZMSConsts.SYSTEM_META_YPM_ID:
                    final Integer ypmId = domain.getYpmId();
                    if (ypmId == null || ypmId == 0) {
                        return null;
                    }
                    signedDomain.getDomain().setYpmId(ypmId);
                    break;
                case ZMSConsts.SYSTEM_META_PRODUCT_ID:
                    final String productId = domain.getProductId();
                    if (productId == null) {
                        return null;
                    }
                    signedDomain.getDomain().setProductId(productId);
                    break;
                case ZMSConsts.SYSTEM_META_BUSINESS_SERVICE:
                    final String businessService = domain.getBusinessService();
                    if (businessService == null) {
                        return null;
                    }
                    signedDomain.getDomain().setBusinessService(businessService);
                    break;
                case ZMSConsts.SYSTEM_META_ATTR_ALL:
                    setDomainDataAttributes(signedDomain.getDomain(), domain);
                    break;
            }
        }
        return signedDomain;
    }

    void setDomainDataAttributes(DomainData domainData, Domain domain) {
        domainData.setDescription(domain.getDescription());
        domainData.setAccount(domain.getAccount());
        domainData.setAzureSubscription(domain.getAzureSubscription());
        domainData.setGcpProject(domain.getGcpProject());
        domainData.setGcpProjectNumber(domain.getGcpProjectNumber());
        domainData.setYpmId(domain.getYpmId());
        domainData.setProductId(domain.getProductId());
        domainData.setApplicationId(domain.getApplicationId());
        domainData.setMemberExpiryDays(domain.getMemberExpiryDays());
        domainData.setServiceExpiryDays(domain.getServiceExpiryDays());
        domainData.setGroupExpiryDays(domain.getGroupExpiryDays());
        domainData.setRoleCertExpiryMins(domain.getRoleCertExpiryMins());
        domainData.setServiceCertExpiryMins(domain.getServiceCertExpiryMins());
        domainData.setTokenExpiryMins(domain.getTokenExpiryMins());
        domainData.setOrg(domain.getOrg());
        domainData.setAuditEnabled(domain.getAuditEnabled());
        domainData.setTags(domain.getTags());
        domainData.setBusinessService(domain.getBusinessService());
        domainData.setSignAlgorithm(domain.getSignAlgorithm());
        domainData.setCertDnsDomain(domain.getCertDnsDomain());
        domainData.setMemberPurgeExpiryDays(domain.getMemberPurgeExpiryDays());
        domainData.setContacts(domain.getContacts());
    }

    SignedDomain retrieveSignedDomain(Domain domain, final String metaAttr, boolean setMetaDataOnly, boolean masterCopy, boolean includeConditions) {

        // check if we're asked to only return the meta data which
        // we already have - name and last modified time, so we can
        // add the domain to our return list and continue with the
        // next domain

        SignedDomain signedDomain;
        if (setMetaDataOnly) {
            signedDomain = retrieveSignedDomainMeta(domain, metaAttr);
        } else {
            signedDomain = retrieveSignedDomainData(domain, masterCopy, includeConditions);
        }
        return signedDomain;
    }

    SignedDomain retrieveSignedDomainData(Domain domain, boolean masterCopy, boolean includeConditions) {

        // generate our signed domain object

        final String domainName = domain.getName();
        SignedDomain signedDomain = createSignedDomain(domainName, domain.getModified().millis(),
                domain.getEnabled());

        // get the policies, roles, and service identities to create the
        // DomainData

        if (LOG.isDebugEnabled()) {
            LOG.debug("retrieveSignedDomain: retrieving domain {}", domainName);
        }

        AthenzDomain athenzDomain = getAthenzDomain(domainName, true, masterCopy);

        // it's possible that our domain was deleted by another
        // thread while we were processing this request so
        // we'll return null so the caller can skip this domain

        if (athenzDomain == null) {
            return null;
        }

        // set domain attributes - for enabled flag only set it
        // if it set to false

        DomainData domainData = signedDomain.getDomain();

        if (athenzDomain.getDomain().getEnabled() == Boolean.FALSE) {
            domainData.setEnabled(false);
        }
        if (athenzDomain.getDomain().getAuditEnabled() == Boolean.TRUE) {
            domainData.setAuditEnabled(true);
        }
        domainData.setAccount(athenzDomain.getDomain().getAccount());
        domainData.setAzureSubscription(athenzDomain.getDomain().getAzureSubscription());
        domainData.setYpmId(athenzDomain.getDomain().getYpmId());
        domainData.setProductId(athenzDomain.getDomain().getProductId());
        domainData.setApplicationId(athenzDomain.getDomain().getApplicationId());
        domainData.setSignAlgorithm(athenzDomain.getDomain().getSignAlgorithm());
        domainData.setBusinessService(athenzDomain.getDomain().getBusinessService());
        domainData.setDescription(athenzDomain.getDomain().getDescription());
        domainData.setCertDnsDomain(athenzDomain.getDomain().getCertDnsDomain());
        domainData.setOrg(athenzDomain.getDomain().getOrg());
        domainData.setUserAuthorityFilter(athenzDomain.getDomain().getUserAuthorityFilter());
        if (athenzDomain.getDomain().getServiceCertExpiryMins() != null) {
            domainData.setServiceCertExpiryMins(athenzDomain.getDomain().getServiceCertExpiryMins());
        }
        if (athenzDomain.getDomain().getRoleCertExpiryMins() != null) {
            domainData.setRoleCertExpiryMins(athenzDomain.getDomain().getRoleCertExpiryMins());
        }
        if (athenzDomain.getDomain().getTokenExpiryMins() != null) {
            domainData.setTokenExpiryMins(athenzDomain.getDomain().getTokenExpiryMins());
        }
        if (athenzDomain.getDomain().getMemberExpiryDays() != null) {
            domainData.setMemberExpiryDays(athenzDomain.getDomain().getMemberExpiryDays());
        }
        if (athenzDomain.getDomain().getGroupExpiryDays() != null) {
            domainData.setGroupExpiryDays(athenzDomain.getDomain().getGroupExpiryDays());
        }
        if (athenzDomain.getDomain().getServiceExpiryDays() != null) {
            domainData.setServiceExpiryDays(athenzDomain.getDomain().getServiceExpiryDays());
        }
        if (athenzDomain.getDomain().getMemberPurgeExpiryDays() != null) {
            domainData.setMemberPurgeExpiryDays(athenzDomain.getDomain().getMemberPurgeExpiryDays());
        }

        // set the domain tags and contacts

        domainData.setTags(athenzDomain.getDomain().getTags());
        domainData.setContacts(athenzDomain.getDomain().getContacts());

        // set the roles, services, groups and entities

        domainData.setRoles(athenzDomain.getRoles());
        domainData.setServices(athenzDomain.getServices());
        domainData.setGroups(athenzDomain.getGroups());
        domainData.setEntities(athenzDomain.getEntities());

        // generate the domain policy object that includes the domain
        // name and all policies. Then we'll sign this struct using
        // server's private key to get signed policy object

        DomainPolicies domainPolicies = new DomainPolicies().setDomain(domainName);
        domainPolicies.setPolicies(getDomainPolicyList(athenzDomain.getPolicies(), includeConditions));
        SignedPolicies signedPolicies = new SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        domainData.setPolicies(signedPolicies);

        String signature = Crypto.sign(
                SignUtils.asCanonicalString(signedPolicies.getContents()), privateKey.getKey());
        signedPolicies.setSignature(signature).setKeyId(privateKey.getId());

        // then sign the data and set the data and signature in a SignedDomain

        signature = Crypto.sign(SignUtils.asCanonicalString(domainData), privateKey.getKey());
        signedDomain.setSignature(signature).setKeyId(privateKey.getId());
        return signedDomain;
    }

    @Override
    public Response getSignedDomains(ResourceContext ctx, String domainName, String metaOnly,
            String metaAttr, Boolean master, Boolean conditions, String matchingTag) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        if (domainName != null) {
            domainName = domainName.toLowerCase();
            validate(domainName, TYPE_DOMAIN_NAME, caller);
            setRequestDomain(ctx, domainName);
        }
        if (metaAttr != null) {
            metaAttr = metaAttr.toLowerCase();
            validate(metaAttr, TYPE_SIMPLE_NAME, caller);
        }

        boolean setMetaDataOnly = ZMSUtils.parseBoolean(metaOnly, false);
        boolean includeConditions = Boolean.TRUE == conditions;
        long timestamp = getModTimestamp(matchingTag);

        // if this is one of our system principals then we're going
        // to use the master copy instead of read-only replicas
        // unless we're configured to always use read-only replicas
        // for all signed domain operations

        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        boolean masterCopy = (useMasterCopyForSignedDomains || master == Boolean.TRUE)
                && principal.getFullName().startsWith("sys.") && !readOnlyMode.get();

        // if we're given a specific domain then we don't need to
        // retrieve the list of modified domains

        List<SignedDomain> sdList = new ArrayList<>();
        Long youngestDomMod = -1L;

        if (domainName != null && !domainName.isEmpty()) {

            Domain domain = null;
            try {
                domain = dbService.getDomain(domainName, masterCopy);
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
                            .header("ETag", ENTITY_TAG_HEADER_DELEGATE.toString(eTag)).build();
                }

                // generate our signed domain object

                SignedDomain signedDomain = retrieveSignedDomain(domain, metaAttr, setMetaDataOnly,
                        masterCopy, includeConditions);

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

            if (!setMetaDataOnly && !masterCopy)  {
                return Response.status(ResourceException.BAD_REQUEST).build();
            }

            // we should get our matching tag before calling get modified list
            // in case we get a domain added/updated right after an empty domain list
            // was returned and before the matchingTag was set to a value

            if (matchingTag == null) {
                EntityTag eTag = new EntityTag(Timestamp.fromMillis(0).toString());
                matchingTag = ENTITY_TAG_HEADER_DELEGATE.toString(eTag);
            }

            // fetching the list of modified domains must always be carried out
            // against our master write database unless the server is running in
            // read-only mode in which case it indicates that our master write
            // db is not available thus we'll use the read replica

            DomainMetaList dmlist = dbService.listModifiedDomains(timestamp, !readOnlyMode.get());
            List<Domain> modlist = dmlist.getDomains();
            if (ZMSUtils.isCollectionEmpty(modlist)) {
                return Response.status(ResourceException.NOT_MODIFIED)
                        .header("ETag", matchingTag).build();
            }

            // now we can iterate through our list and retrieve each domain

            for (Domain dmod : modlist) {

                Long domModMillis = dmod.getModified().millis();
                if (domModMillis.compareTo(youngestDomMod) > 0) {
                    youngestDomMod = domModMillis;
                }

                // generate our signed domain object

                SignedDomain signedDomain = retrieveSignedDomain(dmod, metaAttr, setMetaDataOnly,
                        masterCopy, includeConditions);

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

        return Response.status(ResourceException.OK).entity(sdoms)
                .header("ETag", ENTITY_TAG_HEADER_DELEGATE.toString(eTag)).build();
    }

    @Override
    public Response getJWSDomain(ResourceContext ctx, String domainName, Boolean signatureP1363Format, String matchingTag) {

        final String caller = ctx.getApiName();

        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        long timestamp = getModTimestamp(matchingTag);

        AthenzDomain athenzDomain = getAthenzDomain(domainName, true, false);
        if (athenzDomain == null) {
            throw ZMSUtils.notFoundError("No such domain: " + domainName, caller);
        }

        long domainModTime = athenzDomain.getDomain().getModified().millis();
        EntityTag eTag = new EntityTag(athenzDomain.getDomain().getModified().toString());

        if (timestamp != 0 && domainModTime <= timestamp) {
            return Response
                    .status(ResourceException.NOT_MODIFIED)
                    .header("ETag", ENTITY_TAG_HEADER_DELEGATE.toString(eTag))
                    .build();
        }

        // generate our signed domain object and return in response

        return Response
                .status(ResourceException.OK)
                .entity(generateJWSDomain(athenzDomain, signatureP1363Format))
                .header("ETag", ENTITY_TAG_HEADER_DELEGATE.toString(eTag))
                .build();
    }

    JWSDomain generateJWSDomain(AthenzDomain athenzDomain, Boolean signatureP1363Format) {

        // set all domain attributes including roles and services

        final Domain domain = athenzDomain.getDomain();
        final String domainName = domain.getName();

        DomainData domainData = new DomainData()
                .setName(domainName)
                .setModified(domain.getModified())
                .setEnabled(domain.getEnabled());
        setDomainDataAttributes(domainData, domain);

        // set our roles/groups/entities

        domainData.setRoles(athenzDomain.getRoles());
        domainData.setGroups(athenzDomain.getGroups());
        domainData.setServices(athenzDomain.getServices());
        domainData.setEntities(athenzDomain.getEntities());

        // generate the domain policy object that includes the domain
        // name and all policies. However, for signature, we're going
        // generate one for the active policies only without any
        // conditions for backward compatibility reasons

        DomainPolicies domainPolicies = new DomainPolicies().setDomain(domainName);
        domainPolicies.setPolicies(getDomainPolicyList(athenzDomain.getPolicies(), false));
        final String signature = Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey.getKey());

        // reset the policy list to include all policies

        domainPolicies.setPolicies(athenzDomain.getPolicies());

        SignedPolicies signedPolicies = new SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(signature).setKeyId(privateKey.getId());

        domainData.setPolicies(signedPolicies);

        return signJwsDomain(domainData, signatureP1363Format);
    }

    JWSDomain signJwsDomain(DomainData domainData, Boolean signatureP1363Format) {

        // https://tools.ietf.org/html/rfc7515#section-7.2.2
        // first generate the json output of our object

        JWSDomain jwsDomain = null;
        try {
            // spec requires base64 url encoder without any padding

            final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

            // generate our domain data payload and encode it

            final byte[] jsonDomainData = jsonMapper.writeValueAsBytes(domainData);
            final byte[] encodedDomainData = encoder.encode(jsonDomainData);

            // generate our protected header - just includes the key id + algorithm

            final String protectedHeader = "{\"kid\":\"" + privateKey.getId() + "\",\"alg\":\"" + privateKey.getAlgorithm() + "\"}";
            final byte[] encodedProtectedHeader = encoder.encode(protectedHeader.getBytes(StandardCharsets.UTF_8));

            // combine protectedHeader . payload and sign the result

            byte[] signature = Crypto.sign(Bytes.concat(encodedProtectedHeader, PERIOD, encodedDomainData),
                    privateKey.getKey(), Crypto.SHA256);
            if (signatureP1363Format == Boolean.TRUE && privateKey.getAlgorithm() == SignatureAlgorithm.ES256) {
                signature = Crypto.convertSignatureFromDERToP1363Format(signature, Crypto.SHA256);
            }
            final byte[] encodedSignature = encoder.encode(signature);

            // our header contains a single entry with the kid

            final Map<String, String> headerMap = new HashMap<>();
            headerMap.put("kid", privateKey.getId());

            jwsDomain = new JWSDomain().setHeader(headerMap)
                    .setPayload(new String(encodedDomainData))
                    .setProtectedHeader(new String(encodedProtectedHeader))
                    .setSignature(new String(encodedSignature));

        } catch (Exception ex) {
            LOG.error("Unable to generate signed athenz domain object", ex);
        }
        return jwsDomain;
    }

    List<Policy> getDomainPolicyList(List<Policy> policies, boolean includeConditions) {

        if (policies == null) {
            return null;
        }

        // we are going to remove the assertion id from our assertions
        // since the data is signed and the clients don't need to be
        // updated due to this new attribute being returned

        List<Policy> policyList = new ArrayList<>();

        for (Policy policy : policies) {

            // ignore any inactive/multi-version policies

            if (policy.getActive() == Boolean.FALSE) {
                continue;
            }

            Policy newPolicy = new Policy()
                    .setModified(policy.getModified())
                    .setName(policy.getName());
            if (policy.getAssertions() != null) {
                List<Assertion> assertions = new ArrayList<>();
                for (Assertion assertion : policy.getAssertions()) {
                    Assertion newAssertion = new Assertion();
                    if (includeConditions) {
                        newAssertion.setId(assertion.getId());
                        if (assertion.getConditions() != null) {
                            AssertionConditions assertionConditionsCopy = new AssertionConditions();
                            assertionConditionsCopy.setConditionsList(assertion.getConditions().getConditionsList().stream()
                                    .map(c -> new AssertionCondition().setId(c.getId())
                                            .setConditionsMap(c.getConditionsMap().entrySet().stream()
                                                    .collect(Collectors.toMap(
                                                            Map.Entry::getKey,
                                                            e -> new AssertionConditionData().setValue(e.getValue().getValue())
                                                                    .setOperator(e.getValue().getOperator())
                                                            )

                                                    ))
                                    ).collect(Collectors.toList()));
                            newAssertion.setConditions(assertionConditionsCopy);
                        }
                    }
                    newAssertion.setAction(assertion.getAction())
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

        final String caller = ctx.getApiName();
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
            .expirationWindow(userTokenTimeout).keyId(privateKey.getId()).host(serverHostName)
            .ip(ServletRequestUtil.getRemoteAddress(ctx.request())).authorizedServices(services).build();

        token.sign(privateKey.getKey());
        UserToken userToken = new UserToken().setToken(token.getSignedToken());

        if (header == Boolean.TRUE && principalAuthority != null) {
            userToken.setHeader(principalAuthority.getHeader());
        }

        // set our standard CORS headers in our response if we're processing
        // a get user token for an authorized service

        if (services != null)  {
            setStandardCORSHeaders(ctx);
        }

        return userToken;
    }

    public UserToken optionsUserToken(ResourceContext ctx, String userName, String authorizedServices) {

        final String caller = ctx.getApiName();

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

        return null;
    }

    boolean isValidCORSOrigin(final String origin) {

        // first check for non-empty origin value

        if (origin == null || origin.isEmpty()) {
            return false;
        }

        // check if we have allow-list configured in which
        // case the value must be in our list

        if (corsOriginList != null && !corsOriginList.isEmpty()) {
            return corsOriginList.contains(origin);
        }

        // if we have no values configured then we're going
        // to validate the origin uri value

        return validateCORSOriginValue(origin);
    }

    boolean validateCORSOriginValue(final String origin) {

        // expected format: Origin: <scheme> "://" <hostname> [ ":" <port> ]

        URI uri;
        try {
            uri = new URI(origin);
        } catch (URISyntaxException ex) {
            LOG.error("validateCorsOriginValue: Unable to parse {}: {}", origin, ex.getMessage());
            return false;
        }

        // we only support either http or https scheme

        final String scheme = uri.getScheme();
        if (!(ZMSConsts.SCHEME_HTTPS.equals(scheme) || ZMSConsts.SCHEME_HTTP.equals(scheme))) {
            LOG.error("validateCorsOriginValue: Unsupported schema {}", origin);
            return false;
        }

        // host must be valid and present

        if (StringUtil.isEmpty(uri.getHost())) {
            LOG.error("validateCorsOriginValue: Missing hostname {}", origin);
            return false;
        }

        // it cannot have any query or path parameters

        if (!StringUtil.isEmpty(uri.getQuery()) || !StringUtil.isEmpty(uri.getPath())) {
            LOG.error("validateCorsOriginValue: Must not have query and/or path {}", origin);
            return false;
        }

        // verify the port number

        if (uri.getPort() > 65535) {
            LOG.error("validateCorsOriginValue: Invalid port number {}", origin);
            return false;
        }

        // we have a valid origin value

        return true;
    }

    void setStandardCORSHeaders(ResourceContext ctx) {

        // if we get an Origin header in our request then we're going to return
        // the same value in the Allow-Origin header

        final String origin = ctx.request().getHeader(ZMSConsts.HTTP_ORIGIN);
        if (isValidCORSOrigin(origin)) {
            ctx.response().addHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        }

        // we must allow credentials to be passed by the client

        ctx.response().addHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");

        // if the client is asking us to allow any headers then we're going
        // to return that set back as allowed if header names are validated

        final String allowHeaders = ctx.request().getHeader(ZMSConsts.HTTP_ACCESS_CONTROL_REQUEST_HEADERS);
        if (areValidRequestHeaders(allowHeaders)) {
            ctx.response().addHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_HEADERS, allowHeaders);
        }
    }

    boolean areValidRequestHeaders(final String allowHeaders) {

        // expected format: Access-Control-Request-Headers: <header-name>, <header-name>, ...

        if (StringUtil.isEmpty(allowHeaders) || corsRequestHeaderList == null) {
            return false;
        }

        for (String headerName : allowHeaders.split(",")) {
            if (!corsRequestHeaderList.contains(headerName.trim().toLowerCase())) {
                LOG.error("areValidRequestHeaders: header {} is not allowed", headerName);
                return false;
            }
        }

        // valid header values

        return true;
    }

    @Override
    public void putTenancy(ResourceContext ctx, String tenantDomain, String provider,
            String auditRef, Tenancy detail) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);

        validate(tenantDomain, TYPE_DOMAIN_NAME, caller);
        validate(provider, TYPE_SERVICE_NAME, caller); //the fully qualified service name to provision on

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        tenantDomain = tenantDomain.toLowerCase();
        setRequestDomain(ctx, tenantDomain);
        provider = provider.toLowerCase();
        AthenzObject.TENANCY.convertToLowerCase(detail);

        // validate our detail object against uri components

        if (!validateTenancyObject(detail, tenantDomain, provider)) {
            throw ZMSUtils.requestError("Invalid tenancy object", caller);
        }

        // verify that request is properly authenticated for this request

        String authorizedService = ((RsrcCtxWrapper) ctx).principal().getAuthorizedService();
        verifyAuthorizedServiceOperation(authorizedService, caller);

        String provSvcDomain = ZMSUtils.providerServiceDomain(provider); // provider service domain
        String provSvcName = ZMSUtils.providerServiceName(provider); // provider service name

        // we can't have the provider and tenant be in the same domain
        // as we don't allow delegation of roles onto themselves

        if (provSvcDomain.equals(tenantDomain)) {
            throw ZMSUtils.requestError("Provider and tenant domains cannot be the same", caller);
        }

        if (dbService.getServiceIdentity(provSvcDomain, provSvcName, true) == null) {
            throw ZMSUtils.notFoundError("Unable to retrieve service=" + provider, caller);
        }

        // we are going to allow the authorize service token owner to call
        // put tenancy on its own service

        boolean authzServiceTokenOperation = isAuthorizedProviderService(authorizedService,
                provSvcDomain, provSvcName, ((RsrcCtxWrapper) ctx).principal());

        if (authorizedService != null && !authzServiceTokenOperation) {
            throw ZMSUtils.requestError("Authorized service provider mismatch: "
                    + provider + "/" + authorizedService, caller);
        }

        if (!Boolean.FALSE.equals(detail.getCreateAdminRole())) {
            // set up our tenant admin policy so provider can check admin's access

            dbService.setupTenantAdminPolicy(ctx, tenantDomain, provSvcDomain,
                    provSvcName, auditRef, caller);
        }

        // if this is an authorized service token request then we're going to create
        // the corresponding admin role in the provider domain since that's been
        // authenticated already

        if (authzServiceTokenOperation) {
            setupTenantAdminPolicyInProvider(ctx, provSvcDomain, provSvcName, tenantDomain,
                    false, auditRef, caller);

            // If listed as service provider, register dependency between the provider service and the tenant domain (unless dependency exist
            // following creation of a previous resource group)

            tenancyRegisterDomainDependency(ctx, tenantDomain, provider, auditRef, caller);
        }
    }

    private void tenancyRegisterDomainDependency(ResourceContext ctx, String tenantDomain, String provider,
                                                 String auditRef, String caller) {
        if (serviceProviderManager.isServiceProvider(provider)) {
            DomainList domainList = dbService.listDomainDependencies(provider);
            if (!domainList.getNames().contains(tenantDomain)) {
                dbService.putDomainDependency(ctx, tenantDomain, provider, auditRef, caller);
            }
        }
    }

    private void tenancyDeregisterDomainDependency(ResourceContext ctx, String tenantDomain, String provSvcDomain,
                                                   String provSvcName, String auditRef, String caller) {
        final String serviceToDeregister = provSvcDomain + "." + provSvcName;
        if (serviceProviderManager.isServiceProvider(serviceToDeregister)) {
            boolean tenantDomainRolesExist = isTenantDomainRolesExist(tenantDomain, provSvcDomain, provSvcName);
            DomainList domainList = dbService.listDomainDependencies(serviceToDeregister);
            if (!tenantDomainRolesExist && domainList.getNames().contains(tenantDomain)) {
                dbService.deleteDomainDependency(ctx, tenantDomain, serviceToDeregister, auditRef, caller);
            }
        }
    }

    @Override
    public void deleteTenancy(ResourceContext ctx, String tenantDomain, String provider, String auditRef) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);

        validate(tenantDomain, TYPE_DOMAIN_NAME, caller);
        validate(provider, TYPE_SERVICE_NAME, caller); // fully qualified provider's service name

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        tenantDomain = tenantDomain.toLowerCase();
        setRequestDomain(ctx, tenantDomain);
        provider = provider.toLowerCase();

        // verify that request is properly authenticated for this request

        String authorizedService = ((RsrcCtxWrapper) ctx).principal().getAuthorizedService();
        verifyAuthorizedServiceOperation(authorizedService, caller);

        // make sure we have a valid provider service

        String provSvcDomain = ZMSUtils.providerServiceDomain(provider);
        String provSvcName   = ZMSUtils.providerServiceName(provider);

        if (dbService.getServiceIdentity(provSvcDomain, provSvcName, true) == null) {
            throw ZMSUtils.notFoundError("Unable to retrieve service: " + provider, caller);
        }

        // we are going to allow the authorize service token owner to call
        // delete tenancy on its own service without configuring a controller
        // end point

        boolean authzServiceTokenOperation = isAuthorizedProviderService(authorizedService,
            provSvcDomain, provSvcName, ((RsrcCtxWrapper) ctx).principal());

        if (authzServiceTokenOperation) {
            dbService.executeDeleteTenantRoles(ctx, provSvcDomain, provSvcName, tenantDomain, null,
                auditRef, caller);

            // If listed as service provider, check if there are remaining resource group roles. If not - de-register dependency between the provider service and the tenant domain

            tenancyDeregisterDomainDependency(ctx, tenantDomain, provSvcDomain, provSvcName, auditRef, caller);
        }

        // now clean-up local domain roles and policies for this tenant

        dbService.executeDeleteTenancy(ctx, tenantDomain, provSvcDomain, provSvcName,
                null, auditRef, caller);
    }

    @Override
    public void putTenant(ResourceContext ctx, String providerDomain, String providerService,
           String tenantDomain, String auditRef, Tenancy detail) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);

        validate(providerDomain, TYPE_DOMAIN_NAME, caller);
        validate(providerService, TYPE_SIMPLE_NAME, caller);
        validate(tenantDomain, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        providerDomain = providerDomain.toLowerCase();
        setRequestDomain(ctx, providerDomain);
        providerService = providerService.toLowerCase();
        tenantDomain = tenantDomain.toLowerCase();
        AthenzObject.TENANCY.convertToLowerCase(detail);

        // we can't have the provider and tenant be in the same domain
        // as we don't allow delegation of roles onto themselves

        if (providerDomain.equals(tenantDomain)) {
            throw ZMSUtils.requestError("Provider and tenant domains cannot be the same", caller);
        }

        // validate our detail object against uri components

        final String provider = providerDomain + "." + providerService;
        if (!validateTenancyObject(detail, tenantDomain, provider)) {
            throw ZMSUtils.requestError("Invalid tenancy object", caller);
        }

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        if (dbService.getServiceIdentity(providerDomain, providerService, true) == null) {
            throw ZMSUtils.notFoundError("Unable to retrieve service=" + providerService, caller);
        }

        setupTenantAdminPolicyInProvider(ctx, providerDomain, providerService, tenantDomain,
                false, auditRef, caller);

        // If listed as service provider, register dependency between the provider service and the tenant domain (unless dependency exist
        // following creation of a previous resource group)

        tenancyRegisterDomainDependency(ctx, tenantDomain, provider, auditRef, caller);
    }

    @Override
    public void deleteTenant(ResourceContext ctx, String providerDomain, String providerService,
            String tenantDomain, String auditRef) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);

        validate(providerDomain, TYPE_DOMAIN_NAME, caller);
        validate(providerService, TYPE_SIMPLE_NAME, caller);
        validate(tenantDomain, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        providerDomain = providerDomain.toLowerCase();
        setRequestDomain(ctx, providerDomain);
        providerService = providerService.toLowerCase();
        tenantDomain = tenantDomain.toLowerCase();

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        if (dbService.getServiceIdentity(providerDomain, providerService, true) == null) {
            throw ZMSUtils.notFoundError("Unable to retrieve service=" + providerService, caller);
        }

        dbService.executeDeleteTenantRoles(ctx, providerDomain, providerService, tenantDomain,
                null, auditRef, caller);

        // If listed as service provider, check if there are remaining resource group roles. If not - de-register dependency between the provider service and the tenant domain

        tenancyDeregisterDomainDependency(ctx, tenantDomain, providerDomain, providerService, auditRef, caller);
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

        return (!ZMSUtils.isCollectionEmpty(roles.getRoles()));
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

        return (!ZMSUtils.isCollectionEmpty(roles.getRoles()));
    }

    // put the trust roles into provider domain
    //
    @Override
    public TenantResourceGroupRoles putTenantResourceGroupRoles(ResourceContext ctx, String provSvcDomain,
            String provSvcName, String tenantDomain, String resourceGroup, String auditRef,
            TenantResourceGroupRoles detail) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
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
        setRequestDomain(ctx, provSvcDomain);
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

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        if (LOG.isInfoEnabled()) {
            LOG.info("putTenantResourceGroupRoles: ==== putTenantRoles(domain={}, service={}, tenant-domain={}, resource-group={}, detail={})",
                    provSvcDomain, provSvcName, tenantDomain, resourceGroup, detail);
        }

        // first setup the domain as a tenant in the provider domain

        setupTenantAdminPolicyInProvider(ctx, provSvcDomain, provSvcName, tenantDomain,
                true, auditRef, caller);

        // then setup the requested resource group roles

        dbService.executePutTenantRoles(ctx, provSvcDomain, provSvcName, tenantDomain,
                resourceGroup, detail.getRoles(), false, auditRef, caller);

        // If listed as service provider, register dependency between the provider service and the tenant domain (unless dependency exist
        // following creation of a previous resource group)

        final String provider = provSvcDomain + "." + provSvcName;
        tenancyRegisterDomainDependency(ctx, tenantDomain, provider, auditRef, caller);

        return detail;
    }

    public DomainDataCheck getDomainDataCheck(ResourceContext ctx, String domainName) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        if (LOG.isDebugEnabled()) {
            LOG.debug("getDomainDataCheck: domain={}", domainName);
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
                LOG.debug("getDomainDataCheck: processing role - {}", role.getName());
            }
            roleSet.add(role.getName());
            String roleName = ZMSUtils.removeDomainPrefix(role.getName(), domainName, ROLE_PREFIX);
            String trustDomain = role.getTrust();
            if (trustDomain != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("trust role for domain: {}", trustDomain);
                }
                trustRoleSet.add(trustDomain);
                Set<String> tset = trustRoleMap.computeIfAbsent(trustDomain, k -> new HashSet<>());
                tset.add(roleName);
            }
        }

        // look for dangling roles and policies
        //
        int assertionCount = 0;
        Set<String> usedRoleSet = new HashSet<>(); // keep track of roles used by policies
        Set<String> providerSet = new HashSet<>(); // keep track of providers from assume_role policies

        // assume_role resources are placed into the set per provider service domain

        Map<String, Set<String>> svcRoleMap = new HashMap<>();
        List<DanglingPolicy> danglingPolicies = new ArrayList<>();
        List<Policy> policies = domain.getPolicies();
        for (Policy policy : policies) {

            // ignore any inactive/multi-version policies

            if (policy.getActive() == Boolean.FALSE) {
                continue;
            }

            String pname = ZMSUtils.removeDomainPrefix(policy.getName(), domainName, POLICY_PREFIX);
            if (LOG.isDebugEnabled()) {
                LOG.debug("getDomainDataCheck: processing policy={} in domain={}", pname, domainName);
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
                if (roleSet.contains(roleName)) {
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
            LOG.debug("getDomainDataCheck: domain={} policy-count={} assertion-count={} dangling-policies={} dangling-roles={}",
                    domainName, policies.size(), assertionCount, danglingPolicies.size(), roleSet.size());
        }

        // Tenant Domain Check: does each provider fully support this tenant?
        // collect Service names (domain.service) for domains that don't contain
        // trust role
        List<String> provsWithoutTrust = new ArrayList<>();
        for (String provSvc : providerSet) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("getDomainDataCheck: domain={} provider-service={}", domainName, provSvc);
            }

            // 2 cases to resolve, one with resource group, one without
            // ex: iaas.stuff.storage.read
            // ex: iaas.stuff.storage.res_group.my_resource_group.read

            int idx = provSvc.indexOf(".res_group.");
            String provSvcDomain;
            if (idx == -1) {
                provSvcDomain = ZMSUtils.providerServiceDomain(provSvc);
            } else {
                provSvcDomain = ZMSUtils.providerServiceDomain(provSvc.substring(0, idx));
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
                LOG.debug("getDomainDataCheck: processing trust role: {}", trustRole);
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

                // ignore any inactive/multi-version policies
                if (policy.getActive() == Boolean.FALSE) {
                    continue;
                }

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

        return ddc;
    }

    @Override
    public void deleteProviderResourceGroupRoles(ResourceContext ctx, String tenantDomain,
             String provSvcDomain, String provSvcName, String resourceGroup, String auditRef) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
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
        setRequestDomain(ctx, provSvcDomain);
        provSvcName = provSvcName.toLowerCase();
        tenantDomain = tenantDomain.toLowerCase();
        resourceGroup = resourceGroup.toLowerCase();

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        // first clean-up local domain roles and policies for this tenant

        dbService.executeDeleteTenancy(ctx, tenantDomain, provSvcDomain, provSvcName,
             resourceGroup, auditRef, caller);

        // at this point the tenant side is complete. If the token was a chained
        // token signed by the provider service then we're going to process the
        // provider side as well thus complete the tenancy delete process

        String authorizedService = ((RsrcCtxWrapper) ctx).principal().getAuthorizedService();
        if (isAuthorizedProviderService(authorizedService, provSvcDomain, provSvcName, ((RsrcCtxWrapper) ctx).principal())) {

            dbService.executeDeleteTenantRoles(ctx, provSvcDomain, provSvcName, tenantDomain,
                resourceGroup, auditRef, caller);

            // If listed as service provider, check if there are remaining resource group roles.
            // If not - de-register dependency between the provider service and the tenant domain

            tenancyDeregisterDomainDependency(ctx, tenantDomain, provSvcDomain, provSvcName, auditRef, caller);
        }
    }

    private boolean isTenantDomainRolesExist(String tenantDomain, String provSvcDomain, String provSvcName) {
        final String provider = provSvcDomain + "." + provSvcName;
        List<String> dependentResourceGroups = getDependentServiceResourceGroupList(tenantDomain).getServiceAndResourceGroups().stream()
                .filter(dependency -> dependency.getDomain().equals(tenantDomain) && dependency.getService().equals(provider))
                .findAny()
                .map(DependentServiceResourceGroup::getResourceGroups)
                .orElse(new ArrayList<>());

        return !dependentResourceGroups.isEmpty();
    }

    public ProviderResourceGroupRoles getProviderResourceGroupRoles(ResourceContext ctx, String tenantDomain,
            String provSvcDomain, String provSvcName, String resourceGroup) {

        final String caller = ctx.getApiName();
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
        setRequestDomain(ctx, provSvcDomain);
        provSvcName = provSvcName.toLowerCase();
        tenantDomain = tenantDomain.toLowerCase();
        resourceGroup = resourceGroup.toLowerCase();

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

        return provRoles;
    }

    boolean isAuthorizedProviderService(String authorizedService, String provSvcDomain,
             String provSvcName, Principal principal) {

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
                 resource, null, null, principal);

        return accessStatus == AccessStatus.ALLOWED;
    }

    /**
     * This sets up the assume roles in the tenant. If the tenant's admin user
     * token has been authorized by the provider, the provider's domain will be
     * updated as well, thus completing the tenancy on-boarding in a single step.
    **/
    @Override
    public ProviderResourceGroupRoles putProviderResourceGroupRoles(ResourceContext ctx, String tenantDomain,
             String provSvcDomain, String provSvcName, String resourceGroup, String auditRef,
             ProviderResourceGroupRoles detail) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
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
        setRequestDomain(ctx, provSvcDomain);
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

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        if (LOG.isInfoEnabled()) {
            LOG.info("putProviderResourceGroupRoles: domain={}, service={}, tenant-domain={}, resource-group={}, detail={}",
                    provSvcDomain, provSvcName, tenantDomain, resourceGroup, detail);
        }

        if (!Boolean.FALSE.equals(detail.getCreateAdminRole())) {
            // set up our tenant admin policy so provider can check admin's access
            dbService.setupTenantAdminPolicy(ctx, tenantDomain, provSvcDomain, provSvcName, auditRef, caller);
        }

        // now we're going to set up our roles

        List<TenantRoleAction> roleActions = detail.getRoles();
        List<String> roles = new ArrayList<>();
        for (TenantRoleAction roleAction : roleActions) {
            roles.add(roleAction.getRole());
        }

        // we're going to create a separate role for each one of tenant roles returned
        // based on its action and set the caller as a member in each role

        dbService.executePutProviderRoles(ctx, tenantDomain, provSvcDomain, provSvcName, resourceGroup,
            roles, detail.getSkipPrincipalMember(), auditRef, caller);

        // at this point the tenant side is complete. If the token was a chained
        // token signed by the provider service then we're going to process the
        // provider side as well thus complete the tenancy on-boarding process

        String authorizedService = ((RsrcCtxWrapper) ctx).principal().getAuthorizedService();
        if (isAuthorizedProviderService(authorizedService, provSvcDomain, provSvcName, ((RsrcCtxWrapper) ctx).principal())) {

            // first we need to set up the admin roles in case this
            // happens to be the first resource group

            setupTenantAdminPolicyInProvider(ctx, provSvcDomain, provSvcName, tenantDomain,
                    true, auditRef, caller);

            // now onboard the requested resource group

            dbService.executePutTenantRoles(ctx, provSvcDomain, provSvcName, tenantDomain,
                    resourceGroup, roleActions, false, auditRef, caller);

            // If listed as service provider, register dependency between the provider service and the tenant domain (unless dependency exist
            // following creation of a previous resource group)

            tenancyRegisterDomainDependency(ctx, tenantDomain, authorizedService, auditRef, caller);
        }

        return detail;
    }

    void setupTenantAdminPolicyInProvider(ResourceContext ctx, final String provSvcDomain,
            final String provSvcName, final String tenantDomain, boolean resourceGroupComp,
            final String auditRef, final String caller) {

        List<TenantRoleAction> roles = new ArrayList<>();
        TenantRoleAction roleAction = new TenantRoleAction().setAction("*").setRole(ADMIN_ROLE_NAME);
        roles.add(roleAction);

        // if we want the admin policy with a resource group component then we'll
        // pass an empty string for the resource group which indicate that tenancy
        // is based on resource groups otherwise null

        dbService.executePutTenantRoles(ctx, provSvcDomain, provSvcName, tenantDomain,
                resourceGroupComp ? "" : null, roles, true, auditRef, caller);
    }

    String getProviderRoleAction(String provSvcDomain, String roleName) {

        // if no match then we're going to default action of empty string

        Policy policy = dbService.getPolicy(provSvcDomain, roleName, null); // policy has same name
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

        final String caller = ctx.getApiName();
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
        setRequestDomain(ctx, provSvcDomain);
        provSvcName = provSvcName.toLowerCase();
        tenantDomain = tenantDomain.toLowerCase();
        resourceGroup = resourceGroup.toLowerCase();

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
        return troles;
    }

    @Override
    public void deleteTenantResourceGroupRoles(ResourceContext ctx, String provSvcDomain,
            String provSvcName, String tenantDomain, String resourceGroup, String auditRef) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
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
        setRequestDomain(ctx, provSvcDomain);
        provSvcName = provSvcName.toLowerCase();
        tenantDomain = tenantDomain.toLowerCase();
        resourceGroup = resourceGroup.toLowerCase();

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        dbService.executeDeleteTenantRoles(ctx, provSvcDomain, provSvcName, tenantDomain,
                resourceGroup, auditRef, caller);

        // If listed as service provider, check if there are remaining resource group roles.
        // If not - de-register dependency between the provider service and the tenant domain

        tenancyDeregisterDomainDependency(ctx, tenantDomain, provSvcDomain, provSvcName, auditRef, caller);
    }

    void validateRequest(HttpServletRequest request, String caller) {
        validateRequest(request, caller, false);
    }

    void validateResourceOwner(final String resourceOwner, final String caller) {
        if (!StringUtil.isEmpty(resourceOwner)) {
            validate(resourceOwner, TYPE_SIMPLE_NAME, caller);
            if (resourceOwner.length() > 32) {
                throw ZMSUtils.requestError("Invalid resource owner: " + resourceOwner +
                        " : name length cannot exceed 32 characters", caller);
            }
        }
    }

    void validateResourceOwnership(ResourceDomainOwnership resourceOwnership, final String caller) {
        if (resourceOwnership == null) {
            throw ZMSUtils.requestError("Invalid resource domain ownership: null", caller);
        }
        validateResourceOwner(resourceOwnership.getObjectOwner(), caller);
        validateResourceOwner(resourceOwnership.getMetaOwner(), caller);
    }

    void validateResourceOwnership(ResourceRoleOwnership resourceOwnership, final String caller) {
        if (resourceOwnership == null) {
            throw ZMSUtils.requestError("Invalid resource role ownership: null", caller);
        }
        validateResourceOwner(resourceOwnership.getObjectOwner(), caller);
        validateResourceOwner(resourceOwnership.getMetaOwner(), caller);
        validateResourceOwner(resourceOwnership.getMembersOwner(), caller);
    }

    void validateResourceOwnership(ResourceGroupOwnership resourceOwnership, final String caller) {
        if (resourceOwnership == null) {
            throw ZMSUtils.requestError("Invalid resource group ownership: null", caller);
        }
        validateResourceOwner(resourceOwnership.getObjectOwner(), caller);
        validateResourceOwner(resourceOwnership.getMetaOwner(), caller);
        validateResourceOwner(resourceOwnership.getMembersOwner(), caller);
    }

    void validateResourceOwnership(ResourcePolicyOwnership resourceOwnership, final String caller) {
        if (resourceOwnership == null) {
            throw ZMSUtils.requestError("Invalid resource policy ownership: null", caller);
        }
        validateResourceOwner(resourceOwnership.getObjectOwner(), caller);
        validateResourceOwner(resourceOwnership.getAssertionsOwner(), caller);
    }

    void validateResourceOwnership(ResourceServiceIdentityOwnership resourceOwnership, final String caller) {
        if (resourceOwnership == null) {
            throw ZMSUtils.requestError("Invalid resource service ownership: null", caller);
        }
        validateResourceOwner(resourceOwnership.getObjectOwner(), caller);
        validateResourceOwner(resourceOwnership.getPublicKeysOwner(), caller);
        validateResourceOwner(resourceOwnership.getHostsOwner(), caller);
    }

    void validateRequest(HttpServletRequest request, String caller, boolean statusRequest) {

        // first validate if we're required process this over TLS only

        if (secureRequestsOnly && !request.isSecure()) {
            throw ZMSUtils.requestError(caller + " request must be over TLS", caller);
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
        ZMSUtils.validateObject(validator, val, type, caller);
    }

    List<String> validatedAdminUsers(List<String> lst) {

        final String caller = "validatedadminusers";

        if (ZMSUtils.isCollectionEmpty(lst)) {
            throw ZMSUtils.requestError("validatedAdminUsers: Missing adminUsers", caller);
        }
        Set<String> users = new HashSet<>();
        for (String user : lst) {
            validate(user, TYPE_RESOURCE_NAME, caller);
            users.add(user);
        }
        return new ArrayList<>(users);
    }

    Domain createTopLevelDomain(ResourceContext ctx, Domain domain, List<String> adminUsers,
                List<String> solutionTemplates, String auditRef) {
        List<String> users = validatedAdminUsers(adminUsers);
        Domain newDomain = dbService.makeDomain(ctx, domain, users, solutionTemplates, auditRef);

        // since the domain was successfully created we need to update
        // the meta attributes in the meta store if required

        updateNewDomainMetaStoreDetails(domain);
        return newDomain;
    }

    Domain createSubDomain(ResourceContext ctx, Domain domain, List<String> adminUsers,
                List<String> solutionTemplates, String auditRef, String caller) {

        // verify length of full sub domain name

        if (domain.getName().length() > domainNameMaxLen) {
            throw ZMSUtils.requestError("Invalid SubDomain name: " + domain.getName()
                    + " : name length cannot exceed: " + domainNameMaxLen, caller);
        }

        List<String> users = validatedAdminUsers(adminUsers);
        Domain newDomain = dbService.makeDomain(ctx, domain, users, solutionTemplates, auditRef);

        // since the domain was successfully created we need to update
        // the meta attributes in the meta store if required

        updateNewDomainMetaStoreDetails(domain);
        return newDomain;
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

    DomainList listDomains(Integer limit, String skip, String prefix, Integer depth, long modTime, boolean masterCopy) {

        //note: we don't use the store's options, because we also need to filter on depth

        List<String> allDomains = dbService.listDomains(prefix, modTime, masterCopy);
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
            LOG.debug("getPublicKey: service={}.{} key-id={}", domain, service, keyId);
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
                    LOG.debug("getPublicKey: unable to get public key: {}", ex.getMessage());
                }
                return null;
            }
        }

        if (pubKey == null) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("getPublicKey: service={}.{} has no public key registered", domain, service);
            }
            return null;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("getPublicKey: service public key: {}", pubKey);
        }

        return Crypto.ybase64DecodeString(pubKey);
    }

    @Override
    public void putDefaultAdmins(ResourceContext ctx, String domainName, String auditRef,
            DefaultAdmins defaultAdmins) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (LOG.isDebugEnabled()) {
            LOG.debug("putDefaultAdmins: domain={}", domainName);
        }

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        AthenzDomain domain = getAthenzDomain(domainName, false);
        if (domain == null) {
            throw ZMSUtils.notFoundError("putDefaultAdmins: Domain not found: '" + domainName + "'", caller);
        }

        // normalize and validate requested admin users

        AthenzObject.DEFAULT_ADMINS.convertToLowerCase(defaultAdmins);
        defaultAdmins.setAdmins(normalizedAdminUsers(defaultAdmins.getAdmins(), domain.getDomain().getUserAuthorityFilter(), caller));

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
                LOG.info("putDefaultAdmins: Adding domain admin role because no domain admin role was found for domain: {}", domainName);
            }
            adminRole = ZMSUtils.makeAdminRole(domainName, new ArrayList<>());
            dbService.executePutRole(ctx, domainName, ADMIN_ROLE_NAME, adminRole, auditRef, caller, false);
        }

        Policy adminPolicy = null;
        for (Policy policy : domain.getPolicies()) {

            // ignore any inactive/multi-version policies
            if (policy.getActive() == Boolean.FALSE) {
                continue;
            }

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
                LOG.info("putDefaultAdmins: Adding domain admin policy  because no domain admin policy  was found for domain: {}", domainName);
            }
            //Create and add the admin policy
            adminPolicy = ZMSUtils.makeAdminPolicy(domainName, adminRole);
            dbService.executePutPolicy(ctx, domainName, ADMIN_POLICY_NAME, adminPolicy, auditRef, caller, false);
        }

        addDefaultAdminAssertion(ctx, domainName, adminPolicy, auditRef, caller);

        removeAdminDenyAssertions(ctx, domainName, domain.getPolicies(), domain.getRoles(), adminRole,
                defaultAdmins, auditRef);

        addDefaultAdminMembers(ctx, domainName, adminRole, defaultAdmins, auditRef, caller);
    }

    void addDefaultAdminAssertion(ResourceContext ctx, String domainName, Policy adminPolicy,
            String auditRef, String caller) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("addDefaultAdminAssertion");
        }

        String domainAllResources = domainName + ":*";
        String domainAdminRole = ResourceUtils.roleResourceName(domainName, ADMIN_ROLE_NAME);

        boolean invalidAssertions = false;
        List<Assertion> assertions = adminPolicy.getAssertions();
        if (assertions != null) {

            for (Assertion assertion : assertions) {
                String resource = assertion.getResource();
                if (resource == null) {
                    invalidAssertions = true;
                    continue;
                }

                String action = assertion.getAction();
                if (action == null) {
                    invalidAssertions = true;
                    continue;
                }

                String role = assertion.getRole();
                if (role == null) {
                    invalidAssertions = true;
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
            LOG.info("Adding default admin assertion to admin policy because no default admin assertion was found for admin policy for domain: {}", domainName);
        }

        // if we had invalid assertions then we're going to
        // reset the assertion list otherwise we can't update

        if (invalidAssertions) {
            adminPolicy.setAssertions(new ArrayList<>());
        }
        ZMSUtils.addAssertion(adminPolicy, domainAllResources, "*", domainAdminRole, AssertionEffect.ALLOW);
        dbService.executePutPolicy(ctx, domainName, ADMIN_POLICY_NAME, adminPolicy, auditRef, caller, false);
    }

    void removeAdminDenyAssertions(ResourceContext ctx, final String domainName, List<Policy> policies,
            List<Role> roles, Role adminRole, DefaultAdmins defaultAdmins, final String auditRef) {

        final String caller = "putdefaultadmins";

        if (LOG.isDebugEnabled()) {
            LOG.debug("removeAdminDenyAssertions");
        }

        for (Policy policy : policies) {

            if (LOG.isDebugEnabled()) {
                LOG.debug("access: processing policy: {}", policy.getName());
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
                if (effect != AssertionEffect.DENY) {
                    continue;
                }

                // If there is no role in the assertion then admin is not being denied
                String assertionRole = assertion.getRole();
                if (assertionRole == null) {
                    continue;
                }

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Found DENY assertion for role {}", assertionRole);
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
                LOG.info("Removing assertion from policy:{} because it was for the domain admin role.", policy.getName());
            }

            for (Assertion assertion : assertionsToDelete) {
                assertions.remove(assertion);
            }

            String policyName = ZMSUtils.removeDomainPrefix(policy.getName(), domainName, POLICY_PREFIX);
            dbService.executePutPolicy(ctx, domainName, policyName, policy, auditRef, caller, false);
        }
    }

    void removeAdminMembers(ResourceContext ctx, String domainName, List<Role> roles,
            String assertionRole, DefaultAdmins defaultAdmins, String auditRef, String caller) {

        for (Role role : roles) {

            if (LOG.isDebugEnabled()) {
                LOG.debug("removeAdminMembers: Removing admin members from role: {}", role.getName());
            }

            if (!assertionRole.equals(role.getName())) {
                continue;
            }

            String roleName = ZMSUtils.removeDomainPrefix(role.getName(), domainName, ROLE_PREFIX);
            for (String adminName : defaultAdmins.getAdmins()) {
                if (isMemberOfRole(role, adminName)) {
                    if (LOG.isInfoEnabled()) {
                        LOG.info("removeAdminMembers: removing member: {} from role: {} because there is a DENY assertion for this role in this domain.",
                                adminName, roleName);
                    }

                    // we're going to ignore any exceptions and just log the errors

                    try {
                        dbService.executeDeleteMembership(ctx, domainName, roleName, adminName, auditRef, caller);
                    } catch (Exception ex) {
                        LOG.error("removeAdminMembers: unable to remove member: {} from role: {}, error: {}",
                                adminName, roleName, ex.getMessage());
                    }
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
                    LOG.info("Adding member: {} to admin role for domain: {}", adminName, domainName);
                }
                RoleMember roleMember = new RoleMember().setMemberName(adminName);
                dbService.executePutMembership(ctx, domainName, ADMIN_ROLE_NAME,
                        roleMember, auditRef, caller, false);
            }
        }
    }

    public ServicePrincipal getServicePrincipal(ResourceContext ctx) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);

        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        final String principalDomain = principal.getDomain();
        setRequestDomain(ctx, principalDomain);

        Authority authority = principal.getAuthority();

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
                .ip(sdToken.getIP()).keyId(privateKey.getId()).host(serverHostName)
                .keyService(ZMSConsts.ZMS_SERVICE).build();
            zmsToken.sign(privateKey.getKey());

            servicePrincipal.setToken(zmsToken.getSignedToken());

        } else {
            servicePrincipal.setToken(principal.getCredentials());
        }

        return servicePrincipal;
    }

    ArrayList<AllowedOperation> getAuthorizedServiceOperations(final String authorizedService, final String operationName) {

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

        return ops;
    }

    void verifyAuthorizedServiceOperation(final String authorizedService, final String operationName) {
        verifyAuthorizedServiceOperation(authorizedService, operationName, null, null);
    }

    void verifyAuthorizedServiceRoleOperation(final String authorizedService, final String operationName,
            final String roleName) {

        // only process this request if we have an authorized service specified

        if (authorizedService == null) {
            return;
        }

        // lookup the authorized services struct and see if we have the
        // service specified in the allowed list

        ArrayList<AllowedOperation> ops = getAuthorizedServiceOperations(authorizedService, operationName);

        // otherwise make sure the operation is allowed for this service

        boolean opAllowed = false;
        for (AllowedOperation op : ops) {
            if (!op.getName().equalsIgnoreCase(operationName)) {
                continue;
            }

            opAllowed = op.isOperationAllowedOn("role", roleName, AllowedOperation.MatchType.EQUALS) ||
                    op.isOperationAllowedOn("role-prefix", roleName, AllowedOperation.MatchType.STARTS_WITH);
            break;
        }

        if (!opAllowed) {
            throw ZMSUtils.forbiddenError("Unauthorized Operation (" + operationName
                            + ") for Service " + authorizedService
                            + " on role " + roleName, operationName);
        }
    }

    void verifyAuthorizedServiceGroupOperation(final String authorizedService, final String operationName,
                                              final String groupName) {

        // only process this request if we have an authorized service specified

        if (authorizedService == null) {
            return;
        }

        // lookup the authorized services struct and see if we have the
        // service specified in the allowed list

        ArrayList<AllowedOperation> ops = getAuthorizedServiceOperations(authorizedService, operationName);

        // otherwise make sure the operation is allowed for this service

        boolean opAllowed = false;
        for (AllowedOperation op : ops) {
            if (!op.getName().equalsIgnoreCase(operationName)) {
                continue;
            }

            opAllowed = op.isOperationAllowedOn("group", groupName, AllowedOperation.MatchType.EQUALS) ||
                    op.isOperationAllowedOn("group-prefix", groupName, AllowedOperation.MatchType.STARTS_WITH);
            break;
        }

        if (!opAllowed) {
            throw ZMSUtils.forbiddenError("Unauthorized Operation (" + operationName
                    + ") for Service " + authorizedService
                    + " on group " + groupName, operationName);
        }
    }

    /**
     * If opItemType and value are not defined in the authorized_services JSON file,
     * you can simply pass NULL for these two values.
     */
    void verifyAuthorizedServiceOperation(final String authorizedService, final String operationName,
            final String opItemType, final String opItemVal) {

        // only process this request if we have an authorized service specified

        if (authorizedService == null) {
            return;
        }

        // lookup the authorized services struct and see if we have the
        // service specified in the allowed list

        ArrayList<AllowedOperation> ops = getAuthorizedServiceOperations(authorizedService, operationName);

        // otherwise make sure the operation is allowed for this service

        boolean opAllowed = false;
        for (AllowedOperation op : ops) {
            if (!op.getName().equalsIgnoreCase(operationName)) {
                continue;
            }

            opAllowed = op.isOperationAllowedOn(opItemType, opItemVal, AllowedOperation.MatchType.EQUALS);
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

        final String caller = ctx.getApiName();
        logPrincipal(ctx);
        validateRequest(ctx.request(), caller);

        if (StringUtil.isEmpty(principal)) {
            throw ZMSUtils.requestError("principal is required for resource access list", caller);
        }

        Principal ctxPrincipal = ((RsrcCtxWrapper) ctx).principal();
        if (LOG.isDebugEnabled()) {
            LOG.debug("getResourceAccessList:({}, {}, {})", ctxPrincipal, principal, action);
        }

        validate(principal, TYPE_RESOURCE_NAME, caller);
        principal = normalizeDomainAliasUser(principal.toLowerCase());

        if (action != null) {
            validate(action, TYPE_COMPOUND_NAME, caller);
            action = action.toLowerCase();
        }

        return dbService.getResourceAccessList(principal, action);
    }

    @Override
    public Info getInfo(ResourceContext ctx) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);
        validateRequest(ctx.request(), caller);

        if (serverInfo == null) {
            fetchInfoFromManifest(ctx.servletContext());
        }

        return serverInfo;
    }

    synchronized void fetchInfoFromManifest(ServletContext servletContext) {

        if (serverInfo != null) {
            return;
        }
        Info info = new Info();
        Properties prop = new Properties();
        try {
            prop.load(servletContext.getResourceAsStream("/META-INF/MANIFEST.MF"));
            info.setBuildJdkSpec(prop.getProperty("Build-Jdk-Spec"));
            info.setImplementationTitle(prop.getProperty("Implementation-Title"));
            info.setImplementationVendor(prop.getProperty("Implementation-Vendor"));
            info.setImplementationVersion(prop.getProperty("Implementation-Version"));
        } catch (Exception ex) {
            LOG.error("Unable to read war /META-INF/MANIFEST.MF", ex);
        }
        serverInfo = info;
    }

    @Override
    public Status getStatus(ResourceContext ctx) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        // validate our request as status request

        validateRequest(ctx.request(), caller, true);

        // we're going to verify our database connectivity
        // by listing our system domains. In case of failure
        // we're going to return not found

        if (dbService.listDomains(SYS_AUTH, 0, false).isEmpty()) {
            throw ZMSUtils.notFoundError("Error - no domains available", caller);
        }

        // check if we're configured to check for the status file

        if (healthCheckFile != null && !healthCheckFile.exists()) {
            throw ZMSUtils.notFoundError("Error - no status available", caller);
        }

        // if the StatusChecker is set, check the server status

        if (statusChecker != null) {
            try {
                statusChecker.check();
            } catch (StatusCheckException e) {
                throw ZMSUtils.error(e.getCode(), e.getMsg(), caller);
            }
        }

        return successServerStatus;
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

    void logPrincipal(ResourceContext ctx) {

        // we are going to log our principal and validate that it
        // contains expected data

        final String principalName = ((RsrcCtxWrapper) ctx).logPrincipal();
        if (principalName != null) {
            validate(principalName, TYPE_SERVICE_NAME, "logPrincipal");
        }
    }

    public ResourceContext newResourceContext(ServletContext servletContext, HttpServletRequest request,
            HttpServletResponse response, String apiName) {

        Object timerMetric = metric.startTiming("zms_api_latency", null, null, request.getMethod(), apiName.toLowerCase());

        // check to see if we want to allow this URI to be available
        // with optional authentication support

        boolean optionalAuth = StringUtils.requestUriMatch(request.getRequestURI(),
                authFreeUriSet, authFreeUriList);
        boolean eventPublishersEnabled = !domainChangePublishers.isEmpty();
        return new RsrcCtxWrapper(servletContext, request, response, authorities, optionalAuth, this,
                timerMetric, apiName, eventPublishersEnabled);
    }

    @Override
    public Schema getRdlSchema(ResourceContext context) {
        return schema;
    }

    static String getServerHostName() {

        String serverHostName = System.getProperty(ZMSConsts.ZMS_PROP_HOSTNAME);
        if (StringUtil.isEmpty(serverHostName)) {
            try {
                InetAddress localhost = java.net.InetAddress.getLocalHost();
                serverHostName = localhost.getCanonicalHostName();
            } catch (java.net.UnknownHostException e) {
                LOG.info("Unable to determine local hostname: {}", e.getMessage());
                serverHostName = "localhost";
            }
        }

        return serverHostName;
    }

    Authority getAuthority(String className) {

        LOG.debug("Loading authority {}...", className);

        Authority authority;
        try {
            authority = (Authority) Class.forName(className).getDeclaredConstructor().newInstance();
        } catch (Exception ex) {
            LOG.error("Invalid Authority class: {}", className, ex);
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

    boolean isAllowedSystemMetaDelete(Principal principal, final String reqDomain, final String attribute,
            final String objectType) {

        // the authorization policy resides in official sys.auth domain

        AthenzDomain domain = getAthenzDomain(SYS_AUTH, true);

        // evaluate our domain's roles and policies to see if access
        // is allowed or not for the given operation and resource
        // our action are always converted to lowercase

        String resource = SYS_AUTH + ":meta." + objectType + "." + attribute + "." + reqDomain;
        AccessStatus accessStatus = hasAccess(domain, "delete", resource, principal, null);

        return accessStatus == AccessStatus.ALLOWED;
    }

    @Override
    public void putRoleSystemMeta(ResourceContext ctx, String domainName, String roleName, String attribute,
            String auditRef, RoleSystemMeta meta) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);
        validate(meta, TYPE_ROLE_SYSTEM_META, caller);
        validate(attribute, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        roleName = roleName.toLowerCase();
        attribute = attribute.toLowerCase();

        // verify that request is properly authenticated for this request

        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        verifyAuthorizedServiceOperation(principal.getAuthorizedService(), caller);

        if (LOG.isDebugEnabled()) {
            LOG.debug("putRoleSystemMeta: name={}, role={} attribute={}, meta={}",
                    domainName, roleName, attribute, meta);
        }

        dbService.executePutRoleSystemMeta(ctx, domainName, roleName, meta, attribute, auditRef, caller);
    }

    @Override
    public void putRoleMeta(ResourceContext ctx, String domainName, String roleName, String auditRef,
            String resourceOwner, RoleMeta meta) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);

        // validate meta values - validator will enforce any patters
        // defined in the schema and we need to validate the rest of the
        // integer and string values. for now we're making sure we're not
        // getting any negative values for our integer settings

        validate(meta, TYPE_ROLE_META, caller);
        validateRoleMetaValues(meta);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        roleName = roleName.toLowerCase();
        AthenzObject.ROLE_META.convertToLowerCase(meta);

        // validate the user authority settings if they're provided

        validateUserAuthorityAttributes(meta.getUserAuthorityFilter(), meta.getUserAuthorityExpiration(), caller);

        // verify that request is properly authenticated for this request

        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        verifyAuthorizedServiceOperation(principal.getAuthorizedService(), caller);

        // make sure to fetch our domain and role objects

        AthenzDomain domain = getAthenzDomain(domainName, false);
        Role role = getRoleFromDomain(roleName, domain);

        if (role == null) {
            throw ZMSUtils.notFoundError("Invalid domain/role name specified", caller);
        }

        // validate audit enabled flag for the given role

        validateRoleMetaAuditEnabledFlag(meta, role, domain.getDomain(), caller);

        // authorization check since we have 2 actions: update and update_meta
        // that allow access callers to manage metadata in a role

        if (!isAllowedPutRoleMetaAccess(principal, domain, role.getName())) {
            throw ZMSUtils.forbiddenError("putRoleMeta: principal is not authorized to update metadata", caller);
        }

        // we need to validate that if the role contains groups then the
        // group members must have the same filters otherwise we will not
        // allow the filter to be set

        validateGroupMemberAuthorityAttributes(role, meta.getUserAuthorityFilter(),
                meta.getUserAuthorityExpiration(), caller);

        if (LOG.isDebugEnabled()) {
            LOG.debug("putRoleMeta: name={}, role={} meta={}", domainName, roleName, meta);
        }

        dbService.executePutRoleMeta(ctx, domainName, roleName, role, meta, auditRef, caller);
    }

    void validateRoleMetaAuditEnabledFlag(RoleMeta meta, Role role, Domain domain, final String caller) {

        if (meta.getAuditEnabled() == Boolean.TRUE) {
            if (domain.getAuditEnabled() != Boolean.TRUE) {
                throw ZMSUtils.requestError("Role cannot be set as audit-enabled if the domain is not audit-enabled", caller);
            }
            if (role.getAuditEnabled() != Boolean.TRUE && role.getRoleMembers() != null && !role.getRoleMembers().isEmpty()) {
                throw ZMSUtils.requestError("Only system admins can set the role as audit-enabled if it already has members", caller);
            }
        } else {
            meta.setAuditEnabled(role.getAuditEnabled());
        }
    }

    void validateGroupMemberAuthorityAttributes(Role role, final String userAuthorityFilter,
                                                final String userAuthorityExpiration, final String caller) {

        // if both filters are empty then we have nothing to check for

        if (StringUtil.isEmpty(userAuthorityFilter) && StringUtil.isEmpty(userAuthorityExpiration)) {
            return;
        }

        // go through all role members and if we have any groups validate
        // that the group has the requested filters set

        for (RoleMember roleMember : ZMSUtils.emptyIfNull(role.getRoleMembers())) {

            final String memberName = roleMember.getMemberName();
            if (ZMSUtils.principalType(memberName, userDomainPrefix, addlUserCheckDomainPrefixList,
                    headlessUserDomainPrefix) != Principal.Type.GROUP) {
                continue;
            }

            // get the group details - any invalid member will cause failure
            // in the operation so the caller can fix the issue

            Group group = getGroup(memberName);
            if (group == null) {
                throw ZMSUtils.requestError("Invalid group member " + memberName + " in the role", caller);
            }

            if (ZMSUtils.userAuthorityAttrMissing(userAuthorityFilter, group.getUserAuthorityFilter())) {
                throw ZMSUtils.requestError("Group " + memberName + " does not have same user authority filter "
                        + userAuthorityFilter + " configured", caller);
            }

            if (ZMSUtils.userAuthorityAttrMissing(userAuthorityExpiration, group.getUserAuthorityExpiration())) {
                throw ZMSUtils.requestError("Group " + memberName + " does not have same user authority expiration "
                        + userAuthorityExpiration + " configured", caller);
            }
        }
    }

    Group getGroup(final String groupFullName) {
        int idx = groupFullName.indexOf(AuthorityConsts.GROUP_SEP);
        final String domainName = groupFullName.substring(0, idx);
        final String groupName = groupFullName.substring(idx + AuthorityConsts.GROUP_SEP.length());
        return dbService.getGroup(domainName, groupName, false, false);
    }

    @Override
    public void putMembershipDecision(ResourceContext ctx, String domainName, String roleName,
            String memberName, String auditRef, Membership membership) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
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
        setRequestDomain(ctx, domainName);
        roleName = roleName.toLowerCase();
        memberName = memberName.toLowerCase();
        AthenzObject.MEMBERSHIP.convertToLowerCase(membership);

        final Principal principal = ((RsrcCtxWrapper) ctx).principal();

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceRoleOperation(principal.getAuthorizedService(), caller, roleName);

        // verify that the member name in the URI and object provided match

        if (!memberName.equals(membership.getMemberName())) {
            throw ZMSUtils.requestError("putMembershipDecision: Member name in URI and Membership object do not match", caller);
        }

        // role name is optional so we'll verify only if the value is present in the object

        if (membership.getRoleName() != null && !roleName.equals(membership.getRoleName())) {
            throw ZMSUtils.requestError("putMembershipDecision: Role name in URI and Membership object do not match", caller);
        }

        AthenzDomain domain = getAthenzDomain(domainName, false);
        Role role = getRoleFromDomain(roleName, domain);
        if (role == null) {
            throw ZMSUtils.requestError("Invalid rolename specified", caller);
        }

        // initially create the role member and only set the
        // user name which is all we need in case we need to
        // lookup the pending entry for review approval
        // we'll set the state and expiration after the
        // authorization check is successful

        RoleMember roleMember = new RoleMember();
        roleMember.setMemberName(normalizeDomainAliasUser(memberName));
        roleMember.setPrincipalType(principalType(roleMember.getMemberName()));

        // authorization check

        validatePutMembershipDecisionAuthorization(principal, domain, role, roleMember);

        roleMember.setApproved(membership.getApproved());
        roleMember.setActive(membership.getActive());

        // set the user state, expiration and review date values
        // no need to update the review/expiration dates if the
        // request is going to be rejected

        if (roleMember.getApproved() == Boolean.TRUE) {

            setRoleMemberExpiration(domain, role, roleMember, membership, caller);
            setRoleMemberReview(role, roleMember, membership);

            // check to see if we need to validate the principal
            // but only if the decision is to approve. We don't
            // want to block removal of rejected user requests

            final String userAuthorityFilter = enforcedUserAuthorityFilter(role.getUserAuthorityFilter(),
                    domain.getDomain().getUserAuthorityFilter());
            boolean disallowGroups = ADMIN_ROLE_NAME.equals(roleName);
            validateRoleMemberPrincipal(roleMember.getMemberName(), roleMember.getPrincipalType(),
                    userAuthorityFilter, role.getUserAuthorityExpiration(), role.getAuditEnabled(),
                    disallowGroups, caller);
        }

        dbService.executePutMembershipDecision(ctx, domainName, roleName, roleMember, auditRef, caller);
    }

    private void validatePutMembershipDecisionAuthorization(final Principal principal, final AthenzDomain domain,
            final Role role, final RoleMember roleMember) {

        final String caller = "putmembershipdecision";

        // if this is an audit enabled domain then we're going to carry
        // out the authorization in the sys.auth.audit domains

        if (role.getAuditEnabled() == Boolean.TRUE) {
            if (!isAllowedAuditRoleMembershipApproval(principal, domain)) {
                throw ZMSUtils.forbiddenError("principal " + principal.getFullName()
                        + " is not authorized to approve / reject members", caller);
            }
            return;
        }

        // otherwise, we're going to do a standard check if the principal
        // is authorized to update the domain role membership

        if (!isAllowedPutMembershipAccess(principal, domain, role.getName())) {
            throw ZMSUtils.forbiddenError("principal " + principal.getFullName()
                    + " is not authorized to approve / reject members", caller);
        }

        // if the user is allowed to make changes in the domain but
        // the role is review enabled then we need to make sure
        // the approver cannot be the same as the requester

        if (role.getReviewEnabled() == Boolean.TRUE) {

            Membership pendingMember = dbService.getMembership(domain.getName(),
                    ZMSUtils.extractRoleName(domain.getName(), role.getName()),
                    roleMember.getMemberName(), 0, true);

            if (principal.getFullName().equalsIgnoreCase(pendingMember.getRequestPrincipal())) {
                throw ZMSUtils.forbiddenError("principal " + principal.getFullName()
                        + " cannot approve his/her own request", caller);
            }
        }
    }

    private void validatePutGroupMembershipDecisionAuthorization(final Principal principal, final AthenzDomain domain,
                                                                 final Group group, final GroupMember groupMember) {

        final String caller = "putgroupmembershipdecision";

        // if this is an audit enabled domain then we're going to carry
        // out the authorization in the sys.auth.audit domains

        if (group.getAuditEnabled() == Boolean.TRUE) {
            if (!isAllowedAuditRoleMembershipApproval(principal, domain)) {
                throw ZMSUtils.forbiddenError("principal " + principal.getFullName()
                        + " is not authorized to approve / reject members", caller);
            }
            return;
        }

        // otherwise, we're going to do a standard check if the principal
        // is authorized to update the domain group membership

        if (!isAllowedPutMembershipAccess(principal, domain, group.getName())) {
            throw ZMSUtils.forbiddenError("principal " + principal.getFullName()
                    + " is not authorized to approve / reject members", caller);
        }

        // if the user is allowed to make changes in the domain but
        // the role is review enabled then we need to make sure
        // the approver cannot be the same as the requester

        if (group.getReviewEnabled() == Boolean.TRUE) {

            GroupMembership pendingMember = dbService.getGroupMembership(domain.getName(),
                    ZMSUtils.extractGroupName(domain.getName(), group.getName()),
                    groupMember.getMemberName(), 0, true);

            if (principal.getFullName().equalsIgnoreCase(pendingMember.getRequestPrincipal())) {
                throw ZMSUtils.forbiddenError("principal " + principal.getFullName()
                        + " cannot approve his/her own request", caller);
            }
        }
    }

    boolean isAllowedAuditRoleMembershipApproval(Principal principal, final AthenzDomain reqDomain) {

        // the authorization policy resides in official sys.auth.audit domains
        // first we're going to check the per domain one and then we'll
        // follow up with per org domain

        AthenzDomain authDomain = getAthenzDomain(ZMSConsts.SYS_AUTH_AUDIT_BY_DOMAIN, true);

        // evaluate our domain's roles and policies to see if access
        // is allowed or not for the given operation and resource
        // our action are always converted to lowercase

        String resource = ZMSConsts.SYS_AUTH_AUDIT_BY_DOMAIN + ":audit." + reqDomain.getDomain().getName();
        AccessStatus accessStatus = hasAccess(authDomain, "update", resource, principal, null);
        if (accessStatus == AccessStatus.ALLOWED) {
            return true;
        }

        // if we didn't find any authorization for the per-domain setup
        // we're going to look at the per-org setup

        authDomain = getAthenzDomain(ZMSConsts.SYS_AUTH_AUDIT_BY_ORG, true);
        resource = ZMSConsts.SYS_AUTH_AUDIT_BY_ORG + ":audit." + reqDomain.getDomain().getOrg();
        accessStatus = hasAccess(authDomain, "update", resource, principal, null);

        return accessStatus == AccessStatus.ALLOWED;
    }

    Role getRoleFromDomain(final String roleName, AthenzDomain domain) {
        if (domain != null && domain.getRoles() != null) {
            for (Role role : domain.getRoles()) {
                if (role.getName().equalsIgnoreCase(ResourceUtils.roleResourceName(domain.getName(), roleName))) {
                    return role;
                }
            }
        }
        return null;
    }

    Group getGroupFromDomain(final String groupName, AthenzDomain domain) {
        if (domain != null && domain.getGroups() != null) {
            for (Group group : domain.getGroups()) {
                if (group.getName().equalsIgnoreCase(ResourceUtils.groupResourceName(domain.getName(), groupName))) {
                    return group;
                }
            }
        }
        return null;
    }

    boolean isAllowedPutMembershipAccess(Principal principal, final AthenzDomain domain, final String resourceName) {

        // evaluate our domain's roles and policies to see if either update or update_members
        // action is allowed for the given role (update allows access to manage both members
        // and metadata while update_members only allows access to manage members).

        return isAllowedActionOnResource(principal, domain, resourceName, "update", "update_members");
    }

    boolean isAllowedPutRoleMetaAccess(Principal principal, final AthenzDomain domain, final String roleName) {

        // evaluate our domain's roles and policies to see if either update or update_meta
        // action is allowed for the given role (update allows access to manage both members
        // and metadata while update_meta only allows access to manage metadata).

        return isAllowedActionOnResource(principal, domain, roleName, "update", "update_meta");
    }

    private boolean isAllowedActionOnResource(Principal principal, final AthenzDomain domain,
            final String resourceName, String... actions) {

        // evaluate our domain's roles and policies to see if one of the actions specified
        // is allowed for the given resource (role or group):
        // update - allows access to manage both members and metadata
        // update_members - only allows access to manage members
        // update_meta - only allows access to manage metadata

        for (String action : actions) {
            if (hasAccess(domain, action, resourceName, principal, null) == AccessStatus.ALLOWED) {
                return true;
            }
        }

        return false;
    }

    boolean isAllowedPutMembership(Principal principal, final AthenzDomain domain, final Role role,
            final RoleMember member) {

        // first lets check if the principal has update access on the role

        if (isAllowedPutMembershipAccess(principal, domain, role.getName())) {

            // even with update access, if the role is audit/review enabled, member status
            // can not be set to active/approved. It has to be approved by audit/review admins.
            // for all other roles, set member status to active/approved immediately

            updateRoleMemberActiveState(member, role);
            return true;

        } else if (isRoleSelfRenewAllowed(role, principal, member)) {

            // even with update access, if the role is audit/review enabled, member status
            // can not be set to active/approved. It has to be approved by audit/review admins.
            // for all other roles, set member status to active/approved immediately

            updateRoleMemberActiveState(member, role);

            // we need to update the expiration before returning

            updateRoleMemberSelfRenewExpiration(member, role.getSelfRenewMins());
            return true;

        } else if (role.getSelfServe() == Boolean.TRUE) {

            // if the role is self-serve then users are allowed to add anyone
            // since the request must be approved by someone else so we'll allow it
            // but with member status set to inactive.

            member.setActive(false);
            member.setApproved(false);
            return true;
        }

        return false;
    }

    void updateRoleMemberActiveState(RoleMember member, Role role) {

        // even with update access, if the role is audit/review enabled, member status
        // can not be set to active/approved. It has to be approved by audit/review admins.
        // for all other roles, set member status to active/approved immediately

        boolean auditEnabled = (role.getAuditEnabled() == Boolean.TRUE || role.getReviewEnabled() == Boolean.TRUE);
        member.setActive(!auditEnabled);
        member.setApproved(!auditEnabled);
    }

    void updateRoleMemberSelfRenewExpiration(RoleMember member, int expiryMins) {

        // only set the expiry based on the self-renew minutes if the
        // member either does not have one set or it's set to a value
        // that is longer than what's configured by the self-renew mins

        long selfRenewExpiry = System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(expiryMins, TimeUnit.MINUTES);
        Timestamp memberExpiry = member.getExpiration();
        if (memberExpiry == null || memberExpiry.millis() > selfRenewExpiry) {
            member.setExpiration(Timestamp.fromMillis(selfRenewExpiry));
        }
    }

    boolean isRoleSelfRenewAllowed(Role role, Principal principal, RoleMember member) {

        // to allow self renew the following conditions must be met
        // 1. role self-renew option is enabled
        // 2. role self-renew-mins has valid number of minutes
        // 3. the principal is the same as the member name
        // 4. the member is an existing role member (regardless expired or not)

        if (role.getSelfRenew() != Boolean.TRUE) {
            return false;
        }

        if (role.getSelfRenewMins() == null || role.getSelfRenewMins() <= 0) {
            return false;
        }

        if (!principal.getFullName().equals(member.getMemberName())) {
            return false;
        }

        if (role.getRoleMembers() == null) {
            return false;
        }

        for (RoleMember roleMember : role.getRoleMembers()) {
            if (roleMember.getMemberName().equals(member.getMemberName())) {
                return true;
            }
        }

        return false;
    }

    boolean isAllowedDeletePendingMembership(Principal principal, final String domainName,
            final String roleName, final String memberName) {

        // first lets check if the principal has update access on the role

        AthenzDomain domain = getAthenzDomain(domainName, false);
        if (domain == null) {
            throw ZMSUtils.notFoundError("Domain not found: " + domainName, "deletePendingMembership");
        }
        if (isAllowedPutMembershipAccess(principal, domain, ResourceUtils.roleResourceName(domainName, roleName))) {
            return true;
        }

        // check of the requestor of the pending request is the principal

        Membership pendingMember = dbService.getMembership(domainName, roleName, memberName, 0, true);
        return pendingMember != null && principal.getFullName().equals(pendingMember.getRequestPrincipal());
    }

    @Override
    public DomainRoleMembership getPendingDomainRoleMembersList(ResourceContext ctx, String principal, String domainName) {

        final String caller = ctx.getApiName();

        final Principal ctxPrincipal = ((RsrcCtxWrapper) ctx).principal();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);

        // validate domain if not null/empty or * (for all domains)
        String checkDomainName = null;
        if (!StringUtil.isEmpty(domainName)) {
            if (!("*".equals(domainName))) {
                validate(domainName, TYPE_DOMAIN_NAME, caller);
            }
            checkDomainName = domainName.toLowerCase();
        }

        // validate principal if not null/empty
        // get principal from certificate if domain and principal is null

        String checkPrincipal = null;
        if (!StringUtil.isEmpty(principal)) {
            validate(principal, TYPE_ENTITY_NAME, caller);
            checkPrincipal = normalizeDomainAliasUser(principal.toLowerCase());
        } else if (StringUtil.isEmpty(checkDomainName)) {
            checkPrincipal = ctxPrincipal.getFullName();
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("getpendingdomainrolememberslist principal: ({}), domainName: ({})", checkPrincipal, checkDomainName);
        }

        return dbService.getPendingDomainRoleMembers(checkPrincipal, checkDomainName);
    }

    @Override
    public UserAuthorityAttributeMap getUserAuthorityAttributeMap(ResourceContext ctx) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);
        validateRequest(ctx.request(), caller);

        Map<String, UserAuthorityAttributes> attributeMap = new HashMap<>();
        if (userAuthority != null) {
            attributeMap.put("bool", new UserAuthorityAttributes().setValues(new ArrayList<>(userAuthority.booleanAttributesSupported())));
            attributeMap.put("date", new UserAuthorityAttributes().setValues(new ArrayList<>(userAuthority.dateAttributesSupported())));
        }
        UserAuthorityAttributeMap userAuthorityAttributeMap = new UserAuthorityAttributeMap();
        userAuthorityAttributeMap.setAttributes(attributeMap);
        return userAuthorityAttributeMap;
    }

    @Override
    public Response putRoleReview(ResourceContext ctx, String domainName, String roleName, String auditRef,
            Boolean returnObj, String resourceOwner, Role role) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);
        validate(role, TYPE_ROLE, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        roleName = roleName.toLowerCase();
        AthenzObject.ROLE.convertToLowerCase(role);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        // verify the role name in the URI and request are consistent

        if (!isConsistentRoleName(domainName, roleName, role)) {
            throw ZMSUtils.requestError(caller + ": Inconsistent role names - expected: "
                    + ResourceUtils.roleResourceName(domainName, roleName) + ", actual: "
                    + role.getName(), caller);
        }

        AthenzDomain domain = getAthenzDomain(domainName, false);
        if (domain == null) {
            throw ZMSUtils.notFoundError("No such domain: " + domainName, caller);
        }

        Role dbRole = getRoleFromDomain(roleName, domain);

        // normalize and remove duplicate members

        normalizeRoleMembers(role);

        // validate all members specified in the review request

        validateRoleMemberPrincipals(role, domain.getDomain().getUserAuthorityFilter(), false, caller);

        // update role expiry based on our configurations

        MemberDueDays memberExpiryDueDays = new MemberDueDays(domain.getDomain(), dbRole, MemberDueDays.Type.EXPIRY);
        MemberDueDays memberReminderDueDays = new MemberDueDays(null, dbRole, MemberDueDays.Type.REMINDER);

        updateRoleMemberExpiration(memberExpiryDueDays, role.getRoleMembers());

        // update role review based on our configurations

        updateRoleMemberReviewReminder(memberReminderDueDays, role.getRoleMembers());

        // process our request

        Role updatedRole = dbService.executePutRoleReview(ctx, domainName, roleName, role, memberExpiryDueDays,
                memberReminderDueDays, auditRef, caller, returnObj);

        return ZMSUtils.returnPutResponse(returnObj, updatedRole);
    }

    @Override
    public void putResourceRoleOwnership(ResourceContext ctx, String domainName, String roleName,
            String auditRef, ResourceRoleOwnership resourceOwnership) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);
        validateResourceOwnership(resourceOwnership, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        roleName = roleName.toLowerCase();

        dbService.executePutResourceRoleOwnership(ctx, domainName, roleName, resourceOwnership, auditRef, caller);
    }

    List<Group> setupGroupList(AthenzDomain domain, Boolean members, String tagKey, String tagValue) {

        // if we're asked to return the members as well then we
        // just need to return the data as is without any modifications

        List<Group> groups;
        if (members == Boolean.TRUE) {
            groups = domain.getGroups();
        } else {
            groups = new ArrayList<>();
            for (Group group : domain.getGroups()) {
                Group newGroup = new Group()
                        .setName(group.getName())
                        .setModified(group.getModified())
                        .setAuditEnabled(group.getAuditEnabled())
                        .setSelfServe(group.getSelfServe())
                        .setMemberExpiryDays(group.getMemberExpiryDays())
                        .setServiceExpiryDays(group.getServiceExpiryDays())
                        .setReviewEnabled(group.getReviewEnabled())
                        .setLastReviewedDate(group.getLastReviewedDate())
                        .setTags(group.getTags());
                groups.add(newGroup);
            }
        }

        // filter groups by their tags
        if (tagKey != null) {
            groups = groups.stream()
                    .filter(group -> filterByTag(tagKey, tagValue, group, Group::getTags))
                    .collect(Collectors.toList());
        }

        return groups;
    }

    @Override
    public Groups getGroups(ResourceContext ctx, String domainName, Boolean members, String tagKey, String tagValue) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        if (!StringUtil.isEmpty(tagKey)) {
            validate(tagKey, TYPE_TAG_KEY, caller);
        }
        if (!StringUtil.isEmpty(tagValue)) {
            validate(tagValue, TYPE_TAG_COMPOUND_VALUE, caller);
        }

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        Groups result = new Groups();

        AthenzDomain domain = getAthenzDomain(domainName, false);
        if (domain == null) {
            throw ZMSUtils.notFoundError("Domain not found: '" + domainName + "'", caller);
        }

        result.setList(setupGroupList(domain, members, tagKey, tagValue));
        return result;
    }

    @Override
    public Group getGroup(ResourceContext ctx, String domainName, String groupName, Boolean auditLog, Boolean pending) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(groupName, TYPE_ENTITY_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        groupName = groupName.toLowerCase();

        Group group = dbService.getGroup(domainName, groupName, auditLog, pending);
        if (group == null) {
            throw ZMSUtils.notFoundError("getGroup: Group not found: '" +
                    ResourceUtils.groupResourceName(domainName, groupName) + "'", caller);
        }

        return group;
    }

    boolean isConsistentGroupName(final String domainName, final String groupName, Group group) {

        String resourceName = ResourceUtils.groupResourceName(domainName, groupName);

        // first lets assume we have the expected name specified in the group

        if (resourceName.equals(group.getName())) {
            return true;
        }

        // if not check to see if the group contains the relative local name
        // part only instead of the expected resourceName and update accordingly

        if (groupName.equals(group.getName())) {
            group.setName(resourceName);
            return true;
        }

        // we have a mismatch

        return false;
    }

    private boolean addNormalizedGroupMember(Map<String, GroupMember> normalizedMembers, GroupMember member) {

        member.setMemberName(normalizeDomainAliasUser(member.getMemberName()));

        // we'll automatically ignore any duplicates

        if (!normalizedMembers.containsKey(member.getMemberName())) {
            normalizedMembers.put(member.getMemberName(), member);
            return true;
        }
        return false;
    }

    void normalizeGroupMembers(Group group) {

        Map<String, GroupMember> normalizedMembers = new HashMap<>();

        List<GroupMember> groupMembers = group.getGroupMembers();
        if (groupMembers != null) {
            for (GroupMember member : groupMembers) {

                // if our member was added to the normalized map then we
                // also need to set the principal type

                if (addNormalizedGroupMember(normalizedMembers, member)) {
                    member.setPrincipalType(principalType(member.getMemberName()));
                }
            }
        }

        group.setGroupMembers(new ArrayList<>(normalizedMembers.values()));
    }

    void validateGroupMemberPrincipals(final Group group, final String domainUserAuthorityFilter, final String caller) {

        // make sure we have either one of the options enabled for verification

        final String userAuthorityFilter = enforcedUserAuthorityFilter(group.getUserAuthorityFilter(),
                domainUserAuthorityFilter);

        for (GroupMember groupMember : group.getGroupMembers()) {
            validateGroupMemberPrincipal(groupMember.getMemberName(), groupMember.getPrincipalType(),
                    userAuthorityFilter, caller);
        }
    }

    void updateGroupMemberUserAuthorityExpiry(final Group group, final String caller) {

        // getUserAuthorityExpiryAttr also verifies that we have a valid
        // user authority configured in the server

        final String userAuthorityExpiry = getUserAuthorityExpiryAttr(group.getUserAuthorityExpiration());
        if (userAuthorityExpiry == null) {
            return;
        }

        for (GroupMember groupMember : group.getGroupMembers()) {

            // we only process users and automatically ignore services which
            // are not handled by user authority

            if (ZMSUtils.isUserDomainPrincipal(groupMember.getMemberName(), userDomainPrefix,
                    addlUserCheckDomainPrefixList)) {

                // if we don't have an expiry specified for the user
                // then we're not going to allow this member

                Date expiry = userAuthority.getDateAttribute(groupMember.getMemberName(), userAuthorityExpiry);
                if (expiry == null) {
                    throw ZMSUtils.requestError("Invalid member: " + groupMember.getMemberName() +
                            ". No expiry date attribute specified in user authority", caller);
                }
                groupMember.setExpiration(Timestamp.fromDate(expiry));
            }
        }
    }

    @Override
    public Response putGroup(ResourceContext ctx, String domainName, String groupName, String auditRef,
            Boolean returnObj, String resourceOwner, Group group) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(groupName, TYPE_ENTITY_NAME, caller);
        validate(group, TYPE_GROUP, caller);
        validateGroupValues(group);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        groupName = groupName.toLowerCase();
        AthenzObject.GROUP.convertToLowerCase(group);

        // validate the user authority settings if they're provided

        validateUserAuthorityAttributes(group.getUserAuthorityFilter(), group.getUserAuthorityExpiration(), caller);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        // verify the group name in the URI and request are consistent

        if (!isConsistentGroupName(domainName, groupName, group)) {
            throw ZMSUtils.requestError("putGroup: Inconsistent group names - expected: "
                    + ResourceUtils.groupResourceName(domainName, groupName) + ", actual: "
                    + group.getName(), caller);
        }

        Domain domain = dbService.getDomain(domainName, false);
        if (domain == null) {
            throw ZMSUtils.notFoundError("No such domain: " + domainName, caller);
        }

        // normalize and remove duplicate members

        normalizeGroupMembers(group);

        // check to see if we need to validate user and service members
        // and possibly user authority filter restrictions

        validateGroupMemberPrincipals(group, domain.getUserAuthorityFilter(), caller);

        // validate group review-enabled and/or audit-enabled flags

        validateGroupReviewAuditFlag(domain, group, caller);

        // update group expiry based on our configurations

        MemberDueDays memberExpiryDueDays = new MemberDueDays(domain, group);
        updateGroupMemberExpiration(memberExpiryDueDays, group.getGroupMembers());

        // update group expiry based on user authority expiry if configured

        updateGroupMemberUserAuthorityExpiry(group, caller);

        // process our request

        Group dbGroup = dbService.executePutGroup(ctx, domainName, groupName, group, auditRef, returnObj);

        return ZMSUtils.returnPutResponse(returnObj, dbGroup);
    }

    void validateGroupReviewAuditFlag(final Domain domain, final Group group, final String caller) {

        // group cannot be requested to be audit-enabled if the domain is not audit enabled

        if (group.getAuditEnabled() == Boolean.TRUE && domain.getAuditEnabled() != Boolean.TRUE) {
            throw ZMSUtils.requestError("Group cannot be set as audit-enabled if the domain is not audit-enabled", caller);
        }

        // if the group is review and/or audit enabled then it cannot contain
        // group members as we want review and audit enabled roles
        // to be enabled as such and then add individual members

        if (!group.getGroupMembers().isEmpty()) {
            if (group.getReviewEnabled() == Boolean.TRUE) {
                throw ZMSUtils.requestError("Set review-enabled flag using group meta api", caller);
            }
            if (group.getAuditEnabled() == Boolean.TRUE) {
                throw ZMSUtils.requestError("Only system admins can set the group as audit-enabled if it has members", caller);
            }
        }
    }

    void updateGroupMemberExpiration(MemberDueDays memberExpiryDueDays,
                                    List<GroupMember> groupMembers) {

        updateGroupMemberDueDate(
                memberExpiryDueDays,
                groupMembers,
                GroupMember::getExpiration,
                GroupMember::setExpiration);
    }

    private void updateGroupMemberDueDate(MemberDueDays memberExpiryDueDays,
                                          List<GroupMember> groupMembers,
                                          Function<GroupMember, Timestamp> dueDateGetter,
                                          BiConsumer<GroupMember, Timestamp> dueDateSetter) {

        updateMemberDueDate(
                memberExpiryDueDays,
                groupMembers,
                dueDateGetter,
                dueDateSetter,
                GroupMember::getPrincipalType);
    }

    @Override
    public void deleteGroup(ResourceContext ctx, String domainName, String groupName, String auditRef,
            String resourceOwner) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(groupName, TYPE_ENTITY_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        groupName = groupName.toLowerCase();

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        // before deleting a group make sure the group is not included
        // in any roles in which case those need to be removed first
        // to maintain good consistency (we're going t ignore any
        // exceptions - we get 404s if the principal is not part of
        // any roles, for example

        groupMemberConsistencyCheck(domainName, ResourceUtils.groupResourceName(domainName, groupName), false, caller);

        // everything is ok, so we should go ahead and delete the group

        dbService.executeDeleteGroup(ctx, domainName, groupName, auditRef);
    }

    void groupMemberConsistencyCheck(final String domainName, final String groupResourceName, boolean skipOwnerDomain, final String caller) {

        DomainRoleMember drm = null;
        try {
            drm = dbService.getPrincipalRoles(groupResourceName, null, null);
        } catch (ResourceException ignored) {
        }

        if (drm == null || drm.getMemberRoles().isEmpty()) {
            return;
        }

        // if we have the skip owner domain option enabled then we need
        // to make sure we have roles that are not in the same owner domain

        boolean consistencyCheckFailure = false;
        if (skipOwnerDomain) {
            for (MemberRole memberRole : drm.getMemberRoles()) {
                if (!domainName.equals(memberRole.getDomainName())) {
                    consistencyCheckFailure = true;
                    break;
                }
            }
        } else {
            consistencyCheckFailure = true;
        }

        // if we have no failures then we'll return right away

        if (!consistencyCheckFailure) {
            return;
        }

        StringBuilder msgBuilder = new StringBuilder("Remove group '");
        msgBuilder.append(groupResourceName);
        msgBuilder.append("' membership from the following role(s):");
        for (MemberRole memberRole : drm.getMemberRoles()) {
            if (skipOwnerDomain && domainName.equals(memberRole.getDomainName())) {
                continue;
            }
            msgBuilder.append(' ');
            msgBuilder.append(ResourceUtils.roleResourceName(memberRole.getDomainName(), memberRole.getRoleName()));
        }
        throw ZMSUtils.requestError(msgBuilder.toString(), caller);
    }

    @Override
    public GroupMembership getGroupMembership(ResourceContext ctx, String domainName, String groupName, String memberName, String expiration) {
        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(groupName, TYPE_ENTITY_NAME, caller);
        validate(memberName, TYPE_MEMBER_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        groupName = groupName.toLowerCase();
        memberName = normalizeDomainAliasUser(memberName.toLowerCase());
        long expiryTimestamp = getModTimestamp(expiration);

        return dbService.getGroupMembership(domainName, groupName, memberName, expiryTimestamp, false);
    }

    void setGroupMemberExpiration(final AthenzDomain domain, final Group group, final GroupMember groupMember,
                                  final GroupMembership membership, final String caller) {

        switch (Principal.Type.getType(groupMember.getPrincipalType())) {

            case USER:

                Timestamp userAuthorityExpiry = getUserAuthorityExpiry(groupMember.memberName, group.getUserAuthorityExpiration(), caller);
                if (userAuthorityExpiry != null) {
                    groupMember.setExpiration(userAuthorityExpiry);
                } else {
                    groupMember.setExpiration(memberDueDateTimestamp(domain.getDomain().getMemberExpiryDays(),
                            group.getMemberExpiryDays(), membership.getExpiration()));
                }
                break;

            case SERVICE:
            case USER_HEADLESS:

                groupMember.setExpiration(memberDueDateTimestamp(domain.getDomain().getServiceExpiryDays(),
                        group.getServiceExpiryDays(), membership.getExpiration()));
                break;

            case GROUP:
                throw ZMSUtils.requestError("Group member can't be of type group", caller);
        }
    }

    boolean isAllowedPutGroupMembership(Principal principal, final AthenzDomain domain, final Group group,
                                   final GroupMember groupMember) {

        // first lets check if the principal has update access on the group

        if (isAllowedPutMembershipAccess(principal, domain, group.getName())) {

            // even with update access, if the group is audit/review enabled, member status
            // can not be set to active/approved. It has to be approved by audit/review admins.
            // for all other groups, set member status to active/approved immediately

            updateGroupMemberActiveState(groupMember, group);
            return true;

        } else if (isGroupSelfRenewAllowed(group, principal, groupMember)) {

            // even with update access, if the group is audit/review enabled, member status
            // can not be set to active/approved. It has to be approved by audit/review admins.
            // for all other groups, set member status to active/approved immediately

            updateGroupMemberActiveState(groupMember, group);

            // we need to update the expiration before returning

            updateGroupMemberSelfRenewExpiration(groupMember, group.getSelfRenewMins());
            return true;

        } else if (group.getSelfServe() == Boolean.TRUE) {

            // if the group is self-serve then users are allowed to add anyone
            // since the request must be approved by someone else so we'll allow it
            // but with member status set to inactive.

            groupMember.setActive(false);
            groupMember.setApproved(false);
            return true;
        }

        return false;
    }

    void updateGroupMemberActiveState(GroupMember member, Group group) {

        // even with update access, if the group is audit/review enabled, member status
        // can not be set to active/approved. It has to be approved by audit/review admins.
        // for all other groups, set member status to active/approved immediately

        boolean auditEnabled = (group.getAuditEnabled() == Boolean.TRUE || group.getReviewEnabled() == Boolean.TRUE);
        member.setActive(!auditEnabled);
        member.setApproved(!auditEnabled);
    }

    void updateGroupMemberSelfRenewExpiration(GroupMember member, int expiryMins) {

        // only set the expiry based on the self-renew minutes if the
        // member either does not have one set or it's set to a value
        // that is longer than what's configured by the self-renew mins

        long selfRenewExpiry = System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(expiryMins, TimeUnit.MINUTES);
        Timestamp memberExpiry = member.getExpiration();
        if (memberExpiry == null || memberExpiry.millis() > selfRenewExpiry) {
            member.setExpiration(Timestamp.fromMillis(selfRenewExpiry));
        }
    }

    boolean isGroupSelfRenewAllowed(Group group, Principal principal, GroupMember member) {

        // to allow self renew the following conditions must be met
        // 1. group self-renew option is enabled
        // 2. group self-renew-mins has valid number of minutes
        // 3. the principal is the same as the member name
        // 4. the member is an existing group member (regardless expired or not)

        if (group.getSelfRenew() != Boolean.TRUE) {
            return false;
        }

        if (group.getSelfRenewMins() == null || group.getSelfRenewMins() <= 0) {
            return false;
        }

        if (!principal.getFullName().equals(member.getMemberName())) {
            return false;
        }

        if (group.getGroupMembers() == null) {
            return false;
        }

        for (GroupMember groupMember : group.getGroupMembers()) {
            if (groupMember.getMemberName().equals(member.getMemberName())) {
                return true;
            }
        }

        return false;
    }

    @Override
    public Response putGroupMembership(ResourceContext ctx, String domainName, String groupName, String memberName,
            String auditRef, Boolean returnObj, String resourceOwner, GroupMembership membership) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        setRequestDomain(ctx, domainName);
        validate(groupName, TYPE_ENTITY_NAME, caller);
        validate(memberName, TYPE_MEMBER_NAME, caller);
        validate(membership, TYPE_GROUP_MEMBERSHIP, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        groupName = groupName.toLowerCase();
        memberName = memberName.toLowerCase();
        AthenzObject.GROUP_MEMBERSHIP.convertToLowerCase(membership);

        final Principal principal = ((RsrcCtxWrapper) ctx).principal();

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceGroupOperation(principal.getAuthorizedService(), caller, groupName);

        // verify that the member name in the URI and object provided match

        if (!memberName.equals(membership.getMemberName())) {
            throw ZMSUtils.requestError("putGroupMembership: Member name in URI and GroupMembership object do not match", caller);
        }

        // group name is optional so we'll verify only if the value is present in the object

        if (membership.getGroupName() != null && !groupName.equals(membership.getGroupName())) {
            throw ZMSUtils.requestError("putGroupMembership: Group name in URI and GroupMembership object do not match", caller);
        }

        // extract our group object to get its attributes

        AthenzDomain domain = getAthenzDomain(domainName, false);
        Group group = getGroupFromDomain(groupName, domain);

        if (group == null) {
            throw ZMSUtils.requestError("Invalid groupname specified", caller);
        }

        // create and normalize the role member object

        GroupMember groupMember = new GroupMember();
        groupMember.setMemberName(normalizeDomainAliasUser(memberName));
        groupMember.setPrincipalType(principalType(groupMember.getMemberName()));
        setGroupMemberExpiration(domain, group, groupMember, membership, caller);

        // check to see if we need to validate the principal

        final String userAuthorityFilter = enforcedUserAuthorityFilter(group.getUserAuthorityFilter(),
                domain.getDomain().getUserAuthorityFilter());
        validateGroupMemberPrincipal(groupMember.getMemberName(), groupMember.getPrincipalType(), userAuthorityFilter, caller);

        // authorization check which also automatically updates
        // the active and approved flags for the request

        if (!isAllowedPutGroupMembership(principal, domain, group, groupMember)) {
            throw ZMSUtils.forbiddenError("putGroupMembership: principal is not authorized to add members", caller);
        }

        // add the member to the specified role

       GroupMembership dbGroup = dbService.executePutGroupMembership(ctx, domainName, group, groupMember, auditRef, returnObj);

        // new group member with pending status. Notify approvers

        if (groupMember.getApproved() == Boolean.FALSE) {
            sendGroupMembershipApprovalNotification(domainName, domain.getDomain().getOrg(), groupName,
                    groupMember.getMemberName(), auditRef, principal.getFullName(), group);
        }

        return ZMSUtils.returnPutResponse(returnObj, dbGroup);
    }

    @Override
    public void deleteGroupMembership(ResourceContext ctx, String domainName, String groupName, String memberName,
            String auditRef, String resourceOwner) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(groupName, TYPE_ENTITY_NAME, caller);
        validate(memberName, TYPE_MEMBER_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        groupName = groupName.toLowerCase();
        memberName = memberName.toLowerCase();

        final Principal principal = ((RsrcCtxWrapper) ctx).principal();

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceGroupOperation(principal.getAuthorizedService(), caller, groupName);

        // extract our role object to get its attributes

        AthenzDomain domain = getAthenzDomain(domainName, false);
        Group group = getGroupFromDomain(groupName, domain);

        if (group == null) {
            throw ZMSUtils.notFoundError("Invalid domain/group name specified", caller);
        }

        // authorization check since we have 2 actions: update and update_members
        // that allow access callers to manage members in a group plus we allow
        // delete operation if the principal matches membername

        final String normalizedMember = normalizeDomainAliasUser(memberName);
        if (!(principal.getFullName().equals(normalizedMember) || isAllowedPutMembershipAccess(principal, domain, group.getName()))) {
            throw ZMSUtils.forbiddenError("deleteGroupMembership: principal is not authorized to delete members", caller);
        }

        dbService.executeDeleteGroupMembership(ctx, domainName, groupName, normalizedMember, auditRef);
    }

    boolean isAllowedDeletePendingGroupMembership(Principal principal, final String domainName,
                                                  final String groupName, final String memberName) {

        // first lets check if the principal has update access on the group

        AthenzDomain domain = getAthenzDomain(domainName, false);
        if (domain == null) {
            throw ZMSUtils.notFoundError("Domain not found: " + domainName, "deletePendingGroupMembership");
        }
        if (isAllowedPutMembershipAccess(principal, domain, ResourceUtils.groupResourceName(domainName, groupName))) {
            return true;
        }

        // check of the requestor of the pending request is the principal

        GroupMembership pendingGroupMember = dbService.getGroupMembership(domainName, groupName, memberName, 0, true);
        return pendingGroupMember != null && principal.getFullName().equals(pendingGroupMember.getRequestPrincipal());
    }

    @Override
    public void deletePendingGroupMembership(ResourceContext ctx, String domainName, String groupName, String memberName, String auditRef) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(groupName, TYPE_ENTITY_NAME, caller);
        validate(memberName, TYPE_MEMBER_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        groupName = groupName.toLowerCase();
        memberName = normalizeDomainAliasUser(memberName.toLowerCase());

        // verify that request is properly authenticated for this request

        Principal principal = ((RsrcCtxWrapper) ctx).principal();

        verifyAuthorizedServiceGroupOperation(principal.getAuthorizedService(), caller, groupName);

        // authorization check - there are two supported use cases
        // 1) the caller has authorization in the domain to update members in a group
        // 2) the caller is the original requestor for the pending request

        if (!isAllowedDeletePendingGroupMembership(principal, domainName, groupName, memberName)) {
            throw ZMSUtils.forbiddenError("deletePendingGroupMembership: principal is not authorized to delete pending members", caller);
        }

        // delete the member from the specified group

        dbService.executeDeletePendingGroupMembership(ctx, domainName, groupName, memberName, auditRef);
    }

    @Override
    public DomainGroupMember getPrincipalGroups(ResourceContext ctx, String principal, String domainName) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (StringUtil.isEmpty(principal)) {
            // If principal not specified, get roles for current user
            principal = ((RsrcCtxWrapper) ctx).principal().getFullName();
        }
        validateRequest(ctx.request(), caller);
        validate(principal, TYPE_ENTITY_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        principal = principal.toLowerCase();

        if (!StringUtil.isEmpty(domainName)) {
            validate(domainName, TYPE_DOMAIN_NAME, caller);
            domainName = domainName.toLowerCase();
            setRequestDomain(ctx, domainName);
        }

        return dbService.getPrincipalGroups(principal, domainName);
    }

    @Override
    public void putGroupSystemMeta(ResourceContext ctx, String domainName, String groupName, String attribute,
                                   String auditRef, GroupSystemMeta meta) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(groupName, TYPE_ENTITY_NAME, caller);
        validate(meta, TYPE_GROUP_SYSTEM_META, caller);
        validate(attribute, TYPE_SIMPLE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        groupName = groupName.toLowerCase();
        attribute = attribute.toLowerCase();

        // verify that request is properly authenticated for this request

        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        verifyAuthorizedServiceOperation(principal.getAuthorizedService(), caller);

        if (LOG.isDebugEnabled()) {
            LOG.debug("putGroupSystemMeta: name={}, group={} attribute={}, meta={}",
                    domainName, groupName, attribute, meta);
        }

        dbService.executePutGroupSystemMeta(ctx, domainName, groupName, meta, attribute, auditRef);
    }

    @Override
    public void putGroupMeta(ResourceContext ctx, String domainName, String groupName, String auditRef,
            String resourceOwner, GroupMeta meta) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(groupName, TYPE_ENTITY_NAME, caller);

        // validate meta values - validator will enforce any patters
        // defined in the schema and we need to validate the rest of the
        // integer and string values. for now we're making sure we're not
        // getting any negative values for our integer settings

        validate(meta, TYPE_GROUP_META, caller);
        validateGroupMetaValues(meta);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        groupName = groupName.toLowerCase();
        AthenzObject.GROUP_META.convertToLowerCase(meta);

        // validate the user authority settings if they're provided

        validateUserAuthorityAttributes(meta.getUserAuthorityFilter(), meta.getUserAuthorityExpiration(), caller);

        // verify that request is properly authenticated for this request

        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        verifyAuthorizedServiceOperation(principal.getAuthorizedService(), caller);

        // make sure to fetch our domain and role objects

        AthenzDomain domain = getAthenzDomain(domainName, false);
        Group group = getGroupFromDomain(groupName, domain);

        if (group == null) {
            throw ZMSUtils.notFoundError("Invalid domain/group name specified", caller);
        }

        // validate audit enabled flag for the given role

        validateGroupMetaAuditEnabledFlag(meta, group, domain.getDomain(), caller);

        if (LOG.isDebugEnabled()) {
            LOG.debug("putGroupMeta: name={}, role={} meta={}", domainName, groupName, meta);
        }

        dbService.executePutGroupMeta(ctx, domainName, groupName, group, meta, auditRef);
    }

    void validateGroupMetaAuditEnabledFlag(GroupMeta meta, Group group, Domain domain, final String caller) {

        if (meta.getAuditEnabled() == Boolean.TRUE) {
            if (domain.getAuditEnabled() != Boolean.TRUE) {
                throw ZMSUtils.requestError("Group cannot be set as audit-enabled if the domain is not audit-enabled", caller);
            }
            if (group.getAuditEnabled() != Boolean.TRUE && group.getGroupMembers() != null && !group.getGroupMembers().isEmpty()) {
                throw ZMSUtils.requestError("Only system admins can set the group as audit-enabled if it already has members", caller);
            }
        } else {
            meta.setAuditEnabled(group.getAuditEnabled());
        }
    }

    @Override
    public void putGroupMembershipDecision(ResourceContext ctx, String domainName, String groupName, String memberName,
                                           String auditRef, GroupMembership membership) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(groupName, TYPE_ENTITY_NAME, caller);
        validate(memberName, TYPE_MEMBER_NAME, caller);
        validate(membership, TYPE_GROUP_MEMBERSHIP, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        groupName = groupName.toLowerCase();
        memberName = memberName.toLowerCase();
        AthenzObject.GROUP_MEMBERSHIP.convertToLowerCase(membership);

        final Principal principal = ((RsrcCtxWrapper) ctx).principal();

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceGroupOperation(principal.getAuthorizedService(), caller, groupName);

        // verify that the member name in the URI and object provided match

        if (!memberName.equals(membership.getMemberName())) {
            throw ZMSUtils.requestError("putGroupMembershipDecision: Member name in URI and GroupMembership object do not match", caller);
        }

        // group name is optional so we'll verify only if the value is present in the object

        if (membership.getGroupName() != null && !groupName.equals(membership.getGroupName())) {
            throw ZMSUtils.requestError("putGroupMembershipDecision: Group name in URI and GroupMembership object do not match", caller);
        }

        AthenzDomain domain = getAthenzDomain(domainName, false);
        Group group = getGroupFromDomain(groupName, domain);
        if (group == null) {
            throw ZMSUtils.requestError("Invalid groupname specified", caller);
        }

        // initially create the group member and only set the
        // user name which is all we need in case we need to
        // lookup the pending entry for review approval
        // we'll set the state and expiration after the
        // authorization check is successful

        GroupMember groupMember = new GroupMember();
        groupMember.setMemberName(normalizeDomainAliasUser(memberName));
        groupMember.setPrincipalType(principalType(groupMember.getMemberName()));

        // authorization check

        validatePutGroupMembershipDecisionAuthorization(principal, domain, group, groupMember);

        groupMember.setApproved(membership.getApproved());
        groupMember.setActive(membership.getActive());

        // set the user state, expiration and review date values
        // no need to update the review/expiration dates if the
        // request is going to be rejected

        if (groupMember.getApproved() == Boolean.TRUE) {

            setGroupMemberExpiration(domain, group, groupMember, membership, caller);

            // check to see if we need to validate the principal
            // but only if the decision is to approve. We don't
            // want to block removal of rejected user requests

            final String userAuthorityFilter = enforcedUserAuthorityFilter(group.getUserAuthorityFilter(),
                    domain.getDomain().getUserAuthorityFilter());
             validateGroupMemberPrincipal(groupMember.getMemberName(), groupMember.getPrincipalType(),
                     userAuthorityFilter, caller);
        }

        dbService.executePutGroupMembershipDecision(ctx, domainName, group, groupMember, auditRef);
    }

    @Override
    public Response putGroupReview(ResourceContext ctx, String domainName, String groupName, String auditRef,
            Boolean returnObj, String resourceOwner, Group group) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(groupName, TYPE_ENTITY_NAME, caller);
        validate(group, TYPE_GROUP, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        groupName = groupName.toLowerCase();
        AthenzObject.GROUP.convertToLowerCase(group);

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        // verify the group name in the URI and request are consistent

        if (!isConsistentGroupName(domainName, groupName, group)) {
            throw ZMSUtils.requestError(caller + ": Inconsistent group names - expected: "
                    + ResourceUtils.groupResourceName(domainName, groupName) + ", actual: "
                    + group.getName(), caller);
        }

        AthenzDomain domain = getAthenzDomain(domainName, false);
        if (domain == null) {
            throw ZMSUtils.notFoundError("No such domain: " + domainName, caller);
        }

        Group dbGroup = getGroupFromDomain(groupName, domain);

        // normalize and remove duplicate members

        normalizeGroupMembers(group);

        // validate all members specified in the review request

        validateGroupMemberPrincipals(group, domain.getDomain().getUserAuthorityFilter(), caller);

        // update group expiry based on our configurations

        MemberDueDays memberExpiryDueDays = new MemberDueDays(domain.getDomain(), dbGroup);
        updateGroupMemberExpiration(memberExpiryDueDays, group.getGroupMembers());

        // process our request

        Group updatedGroup = dbService.executePutGroupReview(ctx, domainName, groupName, group, memberExpiryDueDays, auditRef, returnObj);

        return ZMSUtils.returnPutResponse(returnObj, updatedGroup);
    }

    @Override
    public DomainGroupMembership getPendingDomainGroupMembersList(ResourceContext ctx, String principal, String domainName) {
        final String caller = ctx.getApiName();

        final Principal ctxPrincipal = ((RsrcCtxWrapper) ctx).principal();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);

        // validate domain if not null/empty or * (for all domains)
        String checkDomainName = null;
        if (!StringUtil.isEmpty(domainName)) {
            if (!("*".equals(domainName))) {
                validate(domainName, TYPE_DOMAIN_NAME, caller);
            }
            checkDomainName = domainName.toLowerCase();
        }

        // validate principal if not null/empty
        // get principal from certificate if domain and principal is null

        String checkPrincipal = null;
        if (!StringUtil.isEmpty(principal)) {
            validate(principal, TYPE_ENTITY_NAME, caller);
            checkPrincipal = normalizeDomainAliasUser(principal.toLowerCase());
        } else if (StringUtil.isEmpty(checkDomainName)) {
            checkPrincipal = ctxPrincipal.getFullName();
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("getpendingdomaingroupmemberslist principal: ({}), domainName: ({})", checkPrincipal, checkDomainName);
        }

        return dbService.getPendingDomainGroupMembers(checkPrincipal, checkDomainName);
    }

    @Override
    public void putResourceGroupOwnership(ResourceContext ctx, String domainName,
            String groupName, String auditRef, ResourceGroupOwnership resourceOwnership) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(groupName, TYPE_ENTITY_NAME, caller);
        validateResourceOwnership(resourceOwnership, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        groupName = groupName.toLowerCase();

        dbService.executePutResourceGroupOwnership(ctx, domainName, groupName, resourceOwnership, auditRef, caller);
    }

    void validateUserAuthorityFilterAttribute(final String authorityFilter, final String caller)  {

        if (!StringUtil.isEmpty(authorityFilter)) {
            if (userAuthority == null) {
                throw ZMSUtils.requestError("User Authority filter specified without a valid user authority", caller);
            }

            Set<String> attrSet = userAuthority.booleanAttributesSupported();
            for (String attr : authorityFilter.split(","))  {
                if (!attrSet.contains(attr)) {
                    throw ZMSUtils.requestError(attr + " is not a valid user authority attribute", caller);
                }
            }
        }
    }

    /**
     * All AssertionCondition objects part of AssertionConditions will share the same condition id.
     * Since a logical condition can have multiple assertion conditions which are realized using
     * AND operation. e.g. AssertionConditions has a list of AssertionCondition
     * containing 3 conditions, A=1, B=2, C=3 then all these will go in to DB against the same
     * condition id and will be evaluated as (A=1 AND B=2 AND C=3)
     * If an assertion is required to have multiple of such tuples, this api call needs to be repeated for each.
     */
    @Override
    public AssertionConditions putAssertionConditions(ResourceContext ctx, String domainName, String policyName,
            Long assertionId, String auditRef, String resourceOwner, AssertionConditions assertionConditions) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_COMPOUND_NAME, caller);
        validate(assertionConditions, TYPE_ASSERTION_CONDITIONS, caller);

        // we are not going to allow any user to update
        // the admin policy since that is required
        // for standard domain operations */

        if (policyName.equalsIgnoreCase(ADMIN_POLICY_NAME)) {
            throw ZMSUtils.requestError("putAssertionConditions: admin policy cannot have conditions", caller);
        }

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        policyName = policyName.toLowerCase();
        AthenzObject.ASSERTION_CONDITIONS.convertToLowerCase(assertionConditions);

        // validate to make sure we have expected values for assertion fields

        validateAssertionConditions(assertionConditions, caller);

        dbService.executePutAssertionConditions(ctx, domainName, policyName, assertionId, assertionConditions, auditRef, caller);
        return assertionConditions;
    }

    @Override
    public AssertionCondition putAssertionCondition(ResourceContext ctx, String domainName, String policyName,
            Long assertionId, String auditRef, String resourceOwner, AssertionCondition assertionCondition) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_COMPOUND_NAME, caller);
        validate(assertionCondition, TYPE_ASSERTION_CONDITION, caller);

        // we are not going to allow any user to update
        // the admin policy since that is required
        // for standard domain operations */

        if (policyName.equalsIgnoreCase(ADMIN_POLICY_NAME)) {
            throw ZMSUtils.requestError("deleteAssertionCondition: admin policy cannot be modified", caller);
        }

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        policyName = policyName.toLowerCase();
        AthenzObject.ASSERTION_CONDITION.convertToLowerCase(assertionCondition);

        // validate to make sure we have expected values for assertion fields

        validateAssertionCondition(assertionCondition, caller);

        dbService.executePutAssertionCondition(ctx, domainName, policyName, assertionId, assertionCondition, auditRef, caller);
        return assertionCondition;
    }

    @Override
    public void deleteAssertionConditions(ResourceContext ctx, String domainName, String policyName,
            Long assertionId, String auditRef, String resourceOwner) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_ENTITY_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        policyName = policyName.toLowerCase();

        // we are not going to allow any user to update
        // the admin policy since that is required
        // for standard domain operations */

        if (policyName.equalsIgnoreCase(ADMIN_POLICY_NAME)) {
            throw ZMSUtils.requestError("deleteAssertionConditions: admin policy cannot be modified", caller);
        }

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        dbService.executeDeleteAssertionConditions(ctx, domainName, policyName, assertionId, auditRef, caller);
    }

    @Override
    public void deleteAssertionCondition(ResourceContext ctx, String domainName, String policyName,
            Long assertionId, Integer conditionId, String auditRef, String resourceOwner) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        validateRequest(ctx.request(), caller);
        validateResourceOwner(resourceOwner, caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(policyName, TYPE_ENTITY_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        policyName = policyName.toLowerCase();

        // we are not going to allow any user to update
        // the admin policy since that is required
        // for standard domain operations */

        if (policyName.equalsIgnoreCase(ADMIN_POLICY_NAME)) {
            throw ZMSUtils.requestError("deleteAssertionCondition: admin policy cannot be modified", caller);
        }

        // verify that request is properly authenticated for this request

        verifyAuthorizedServiceOperation(((RsrcCtxWrapper) ctx).principal().getAuthorizedService(), caller);

        dbService.executeDeleteAssertionCondition(ctx, domainName, policyName, assertionId, conditionId, auditRef, caller);
    }

    @Override
    public void putDomainDependency(ResourceContext ctx, String domainName, String auditRef, DependentService dependentService) {
        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        String service = (dependentService != null) ? dependentService.getService() : null;
        service = getAuthorizedProviderService((RsrcCtxWrapper) ctx, service, caller);

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(service, TYPE_SERVICE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        service = service.toLowerCase();

        dbService.putDomainDependency(ctx, domainName, service, auditRef, caller);
    }

    @Override
    public void deleteDomainDependency(ResourceContext ctx, String domainName, String service, String auditRef) {
        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        if (readOnlyMode.get()) {
            throw ZMSUtils.requestError(SERVER_READ_ONLY_MESSAGE, caller);
        }

        service = getAuthorizedProviderService((RsrcCtxWrapper) ctx, service, caller);

        validateRequest(ctx.request(), caller);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(service, TYPE_SERVICE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);
        service = service.toLowerCase();

        dbService.deleteDomainDependency(ctx, domainName, service, auditRef, caller);
    }

    String getAuthorizedProviderService(RsrcCtxWrapper ctx, String service, String caller) {

        // If system administrator - service is mandatory
        // Otherwise ignore it and use the principal as dependent service

        Principal principal = ctx.principal();
        boolean isSysAdminUser = isSysAdminUser(principal, false);
        if (isSysAdminUser) {
            if (StringUtil.isEmpty(service)) {
                throw ZMSUtils.requestError("service is mandatory", caller);
            }
        } else {
            service = principal.getFullName();
        }
        service = service.toLowerCase();

        if (!serviceProviderManager.isServiceProvider(service)) {
            throw ZMSUtils.unauthorizedError(service + " is not an authorized service provider", caller);
        }
        return service;
    }

    @Override
    public ServiceIdentityList getDependentServiceList(ResourceContext ctx, String domainName) {
        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        return dbService.listServiceDependencies(domainName);
    }

    @Override
    public DependentServiceResourceGroupList getDependentServiceResourceGroupList(ResourceContext ctx, String domainName) {
        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(domainName, TYPE_DOMAIN_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domainName = domainName.toLowerCase();
        setRequestDomain(ctx, domainName);

        return getDependentServiceResourceGroupList(domainName);
    }

    private DependentServiceResourceGroupList getDependentServiceResourceGroupList(String domainName) {
        ServiceIdentityList serviceIdentityList = dbService.listServiceDependencies(domainName);
        final String finalDomainName = domainName;
        List<DependentServiceResourceGroup> dependentServiceResourceGroups = serviceIdentityList.getNames().stream().map(service -> {
            DependentServiceResourceGroup dependentServiceResourceGroup = new DependentServiceResourceGroup();
            dependentServiceResourceGroup.setService(service);
            dependentServiceResourceGroup.setDomain(finalDomainName);
            dependentServiceResourceGroup.setResourceGroups(getResourceGroupsForProviderServiceTenantDomain(service, finalDomainName));
            return dependentServiceResourceGroup;
        }).collect(Collectors.toList());
        return new DependentServiceResourceGroupList().setServiceAndResourceGroups(dependentServiceResourceGroups);
    }

    private List<String> getResourceGroupsForProviderServiceTenantDomain(final String service, final String tenantDomain) {
        final String provSvcName = ZMSUtils.providerServiceName(service);
        final String provSvcDomain = ZMSUtils.providerServiceDomain(service);
        final String rolePrefix = ZMSUtils.getTenantResourceGroupRolePrefix(provSvcName, tenantDomain, "");
        final List<String> tenantDomainRoles = dbService.listRoles(provSvcDomain);
        return tenantDomainRoles.stream()
                .filter(role -> role.startsWith(rolePrefix))
                .collect(Collectors.toList());
    }

    @Override
    public DomainList getDependentDomainList(ResourceContext ctx, String service) {
        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        validateRequest(ctx.request(), caller);
        validate(service, TYPE_SERVICE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        service = service.toLowerCase();

        if (serviceProviderManager.isServiceProvider(service)) {
            return dbService.listDomainDependencies(service);
        } else {
            throw ZMSUtils.requestError(service + " is not a registered service provider", caller);
        }
    }

    void validateAssertionConditions(AssertionConditions assertionConditions, String caller) {
        // TODO
    }

    void validateAssertionCondition(AssertionCondition assertionCondition, String caller) {
        // TODO
    }

    void validateUserAuthorityDateAttribute(final String authorityExpiration, final String caller) {

        if (!StringUtil.isEmpty(authorityExpiration)) {
            if (userAuthority == null) {
                throw ZMSUtils.requestError("User Authority expiry specified without a valid user authority", caller);
            }

            Set<String> attrSet = userAuthority.dateAttributesSupported();
            if (!attrSet.contains(authorityExpiration)) {
                throw ZMSUtils.requestError(authorityExpiration + " is not a valid user authority date attribute", caller);
            }
        }
    }

    void validateUserAuthorityAttributes(final String authorityFilter, final String authorityExpiration, final String caller) {
        validateUserAuthorityFilterAttribute(authorityFilter, caller);
        validateUserAuthorityDateAttribute(authorityExpiration, caller);
    }

    class AutoApplyTemplate implements Runnable {
        Map<String, Integer> eligibleTemplatesForAutoUpdate;

        public AutoApplyTemplate(Map<String, Integer> eligibleTemplatesForAutoUpdate) {
            this.eligibleTemplatesForAutoUpdate = eligibleTemplatesForAutoUpdate;
        }

        @Override
        public void run() {
            if (LOG.isInfoEnabled()) {
                LOG.info("List of eligible templates with version to apply .. {}", eligibleTemplatesForAutoUpdate);
            }
            Map<String, List<String>> domainTemplateUpdateMapping = dbService.applyTemplatesForListOfDomains(eligibleTemplatesForAutoUpdate);
            if (LOG.isInfoEnabled()) {
                for (String domainName : domainTemplateUpdateMapping.keySet()) {
                    LOG.info("List of templates applied against domain {} {}", domainName, domainTemplateUpdateMapping.get(domainName));
                }
            }
        }
    }

    @Override
    public void recordMetrics(ResourceContext ctx, int httpStatus) {
        try {
            final String principalDomainName = getPrincipalDomain(ctx);
            final String domainName = getRequestDomainName(ctx);
            final Object timerMetric = getTimerMetric(ctx);
            final String httpMethod = (ctx != null) ? ctx.getHttpMethod() : null;
            final String apiName = (ctx != null) ? ctx.getApiName() : null;
            final String timerName = (apiName != null) ? apiName + "_timing" : null;
            metric.increment("zms_api", domainName, principalDomainName, httpMethod, httpStatus, apiName);
            metric.stopTiming(timerMetric, domainName, principalDomainName, httpMethod, httpStatus, timerName);
        } catch (Exception ex) {
            LOG.error("Got exception during recordMetrics", ex);
        }
    }

    @Override
    public void publishChangeMessage(ResourceContext ctx, int httpStatus) {
        if (domainChangePublishers == null || ctx.getDomainChangeMessages() == null) {
            return;
        }
        if (httpStatus >= 200 && httpStatus <= 299) {
            for (DomainChangeMessage changeMessage : ctx.getDomainChangeMessages()) {
                for (ChangePublisher<DomainChangeMessage> publisher : domainChangePublishers) {
                    try {
                        publisher.publish(changeMessage);
                    } catch (Exception ex) {
                        LOG.error("Got exception during publishChangeMessage", ex);
                    }
                }
            }
        }
    }
    
    public static class ZMSGroupMembersFetcher implements AuthzHelper.GroupMembersFetcher {

        DBService dbService;
        ZMSGroupMembersFetcher(DBService dbService) {
            this.dbService = dbService;
        }

        @Override
        public List<GroupMember> getGroupMembers(String groupName) {
            int idx = groupName.indexOf(AuthorityConsts.GROUP_SEP);
            final String domName = groupName.substring(0, idx);
            final String grpName = groupName.substring(idx + AuthorityConsts.GROUP_SEP.length());
            Group group = dbService.getGroup(domName, grpName, false, false);
            if (group == null) {
                return null;
            }
            return group.getGroupMembers();
        }
    }

    @Override
    public ReviewObjects getRolesForReview(ResourceContext ctx, String principal) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        // If principal not specified, get roles for current user

        if (StringUtil.isEmpty(principal)) {
            principal = ((RsrcCtxWrapper) ctx).principal().getFullName();
        }
        validateRequest(ctx.request(), caller);
        validate(principal, TYPE_RESOURCE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case

        principal = principal.toLowerCase();

        if (!isAllowedObjectReviewLookup(((RsrcCtxWrapper) ctx).principal(), principal)) {
            throw ZMSUtils.forbiddenError("principal is not authorized to request role review list", caller);
        }

        return dbService.getRolesForReview(principal);
    }

    @Override
    public ReviewObjects getGroupsForReview(ResourceContext ctx, String principal) {

        final String caller = ctx.getApiName();
        logPrincipal(ctx);

        // If principal not specified, get groups for current user

        if (StringUtil.isEmpty(principal)) {
            principal = ((RsrcCtxWrapper) ctx).principal().getFullName();
        }
        validateRequest(ctx.request(), caller);
        validate(principal, TYPE_RESOURCE_NAME, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case

        principal = principal.toLowerCase();

        if (!isAllowedObjectReviewLookup(((RsrcCtxWrapper) ctx).principal(), principal)) {
            throw ZMSUtils.forbiddenError("principal is not authorized to request group review list", caller);
        }

        return dbService.getGroupsForReview(principal);
    }

    boolean isAllowedObjectReviewLookup(Principal principal, final String checkPrincipal) {

        // Role/Group Review list lookup requires one of these authorization checks
        // 1. authenticated principal is the same as the check principal
        // 2. system authorized ("access", "sys.auth:meta.review.lookup")

        if (checkPrincipal.equals(principal.getFullName())) {
            return true;
        }

        // if the check principal is another user, then this is not allowed
        // unless the principal is authorized at system level

        AthenzDomain domain = getAthenzDomain(SYS_AUTH, true);

        // evaluate our domain's roles and policies to see if access
        // is allowed or not for the given operation and resource
        // our action are always converted to lowercase

        AccessStatus accessStatus = hasAccess(domain, "access", "sys.auth:meta.review.lookup", principal, null);
        return accessStatus == AccessStatus.ALLOWED;
    }
}
