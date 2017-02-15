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

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.EntityTag;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.CertificateAuthority;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.log.AthenzRequestLog;
import com.yahoo.athenz.common.server.log.AuditLogFactory;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.rest.Http;
import com.yahoo.athenz.common.server.util.ServletRequestUtil;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.cert.CertSigner;
import com.yahoo.athenz.zts.cert.InstanceIdentityStore;
import com.yahoo.athenz.zts.store.CloudStore;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.athenz.zts.utils.ZTSUtils;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.Validator;
import com.yahoo.rdl.Validator.Result;

/**
 * An implementation of ZTS.
 */
public class ZTSImpl implements KeyStore, ZTSHandler {

    protected DataStore dataStore;
    protected CloudStore cloudStore;
    protected InstanceIdentityStore instanceIdentityStore;
    protected Metric metric;
    protected Schema schema;
    protected PrivateKey privateKey;
    protected String privateKeyId = "0";
    protected int roleTokenDefaultTimeout;
    protected int roleTokenMaxTimeout;
    protected long serviceTokenTimeOffset;
    protected long bootTimeOffset;
    protected boolean traceAccess = true;
    protected long signedPolicyTimeout;
    protected String serverHostName = null;
    protected AuditLogger auditLogger = null;
    protected String auditLoggerMsgBldrClass = null;
    protected String serverHttpsPort = null;
    protected String serverHttpPort  = null;
    protected String userDomain = "user";
    protected boolean leastPrivilegePrincipal = false;
    protected Set<String> authorizedProxyUsers = null;
    
    private static final String ATTR_ACCOUNT_ID = "accountId";
    private static final String ATTR_PENDING_TIME = "pendingTime";

    private static final String TYPE_DOMAIN_NAME = "DomainName";
    private static final String TYPE_SIMPLE_NAME = "SimpleName";
    private static final String TYPE_ENTITY_NAME = "EntityName";
    private static final String TYPE_SERVICE_NAME = "ServiceName";
    private static final String TYPE_INSTANCE_INFO = "InstanceInformation";
    private static final String TYPE_AWS_INSTANCE_INFO = "AWSInstanceInformation";
    private static final String TYPE_AWS_CERT_REQUEST = "AWSCertificateRequest";
    private static final String TYPE_INSTANCE_REFRESH_REQUEST = "InstanceRefreshRequest";
    private static final String TYPE_DOMAIN_METRICS = "DomainMetrics";
    private static final String TYPE_ROLE_CERTIFICATE_REQUEST = "RoleCertificateRequest";
    
    private static final String ZTS_ROLE_TOKEN_VERSION = "Z1";
    
    private static final long ZTS_NTOKEN_DEFAULT_EXPIRY = TimeUnit.SECONDS.convert(2, TimeUnit.HOURS);
    private static final long ZTS_NTOKEN_MAX_EXPIRY = TimeUnit.SECONDS.convert(7, TimeUnit.DAYS);
    private static final long ZTS_ROLE_CERT_EXPIRY = TimeUnit.SECONDS.convert(30, TimeUnit.DAYS);
    
    // HTTP operation types used in metrics
    private static final String HTTP_GET  = "GET";
    private static final String HTTP_POST = "POST";
    private static final String HTTP_REQUEST = "REQUEST";

    // domain metrics prefix
    private static final String DOM_METRIX_PREFIX = "dom_metric_";

    private static final Logger LOGGER = LoggerFactory.getLogger(ZTSImpl.class);
    
    protected Http.AuthorityList authorities = null;
    private final ZTSAuthorizer authorizer;
    protected static Validator validator;
    
    public ZTSImpl(String serverHostName, DataStore dataStore, CloudStore cloudStore,
            InstanceIdentityStore instanceIdentityStore, Metric metric, PrivateKey privateKey,
            String privateKeyId, AuditLogger auditLog, String auditLogMsgBldrClass) {

        this.schema = ZTSSchema.instance();
        validator = new Validator(schema);

        this.dataStore = dataStore;
        this.cloudStore = cloudStore;
        this.instanceIdentityStore = instanceIdentityStore;
        this.metric = metric;
        this.privateKey = privateKey;
        this.privateKeyId = privateKeyId;
        this.serverHostName = serverHostName;
        this.userDomain = System.getProperty(ZTSConsts.ZTS_PROP_USER_DOMAIN, "user");
        
        auditLogger = auditLog;
        auditLoggerMsgBldrClass = auditLogMsgBldrClass;
        
        // check to see if we want to disable allowing clients to ask for role
        // tokens without role name thus violating the least privilege principle
        
        leastPrivilegePrincipal = Boolean.parseBoolean(System.getProperty(ZTSConsts.ZTS_PROP_LEAST_PRIVILEGE_PRINCIPLE, "false"));
        
        // Default Role Token timeout is 2 hours. If the client asks for role tokens
        // with a min expiry time of 1 hour, the setting of 2 hours allows the client
        // to at least cache the tokens for 1 hour. We're going to set the ZTS client's
        // min default value to 15 mins so that we can by default cache tokens for
        // an hour and 45 minutes.
        
        long timeout = TimeUnit.SECONDS.convert(2, TimeUnit.HOURS);
        this.roleTokenDefaultTimeout = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT, Long.toString(timeout)));
        
        // Max Timeout - 30 days
        
        timeout = TimeUnit.SECONDS.convert(30, TimeUnit.DAYS);
        this.roleTokenMaxTimeout = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT, Long.toString(timeout)));
        
        // signedPolicyTimeout is in milliseconds but the config setting should be in seconds
        // to be consistent with other configuration properties
        
        timeout = TimeUnit.SECONDS.convert(7, TimeUnit.DAYS);
        this.signedPolicyTimeout = 1000 * Long.parseLong(System.getProperty(ZTSConsts.ZTS_PROP_SIGNED_POLICY_TIMEOUT, Long.toString(timeout)));

        // bootTimeOffset is in milliseconds but the config setting should be in seconds
        // to be consistent with other configuration properties
        
        timeout = TimeUnit.SECONDS.convert(5, TimeUnit.MINUTES);
        this.bootTimeOffset = 1000 * Long.parseLong(System.getProperty(ZTSConsts.ZTS_PROP_AWS_BOOT_TIME_OFFSET, Long.toString(timeout)));
        
        // when requesting service tokens on behalf of tenants, the provisioner's
        // token must be fresh and generated with specified number of seconds
        
        timeout = TimeUnit.SECONDS.convert(5, TimeUnit.MINUTES);
        this.serviceTokenTimeOffset = Long.parseLong(System.getProperty(ZTSConsts.ZTS_PROP_SERVICE_TOKEN_TIME_OFFSET, Long.toString(timeout)));
        
        serverHttpsPort = System.getProperty(ZTSConsts.ZTS_PROP_HTTPS_PORT, Integer.toString(ZTSConsts.ZTS_HTTPS_PORT_DEFAULT));
        serverHttpPort  = System.getProperty(ZTSConsts.ZTS_PROP_HTTP_PORT, Integer.toString(ZTSConsts.ZTS_HTTP_PORT_DEFAULT));
        
        // retrieve the list of our authorized proxy users
        
        String authorizedProxyUserList = System.getProperty(ZTSConsts.ZTS_PROP_AUTHORIZED_PROXY_USERS);
        if (authorizedProxyUserList != null) {
            authorizedProxyUsers = new HashSet<>(Arrays.asList(authorizedProxyUserList.split(",")));
        }
        
        this.authorizer = new ZTSAuthorizer(dataStore, cloudStore);
    }

    public void putAuthorityList(Http.AuthorityList authList) {
        authorities = authList;
    }

    AuditLogMsgBuilder getAuditLogMsgBuilder(ResourceContext ctx, String domainName, String caller, String method) {
        AuditLogMsgBuilder msgBldr;
        try {
            msgBldr = AuditLogFactory.getMsgBuilder(auditLoggerMsgBldrClass);
        } catch (Exception exc) {
            LOGGER.error("getAuditLogMsgBuilder: failed to get an AuditLogMsgBuilder. Get the default instead: "
                    + exc.getMessage());
            msgBldr = AuditLogFactory.getMsgBuilder();
        }

        // get the where - which means where this server is running
        msgBldr.whereIp(serverHostName).whereHttpsPort(serverHttpsPort).whereHttpPort(serverHttpPort);

        msgBldr.whatDomain(domainName).whatApi(caller).whatMethod(method);

        // get the 'who' and set it
        //
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
            //
            msgBldr.clientIp(ServletRequestUtil.getRemoteAddress(ctx.request()));
        }

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
    
    /**
     * @return the ZTS Schema object, describing its API and types.
     */
    public Schema schema() {
        return schema;
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
        StringBuilder str = new StringBuilder(256);
        str.append(domain);
        str.append(".");
        str.append(service);
        return str.toString();
    }
    
    ServiceIdentity lookupServiceIdentity(DomainData domainData, String serviceName) {
        
        List<com.yahoo.athenz.zms.ServiceIdentity> services = domainData.getServices();
        if (services == null) {
            return null;
        }
        
        for (com.yahoo.athenz.zms.ServiceIdentity service : services) {
            if (service.getName().equalsIgnoreCase(serviceName)) {
                ServiceIdentity ztsService = generateZTSServiceIdentity(service);
                return ztsService;
            }
        }
        
        return null;
    }
    
    // ----------------- the ServiceIdentity interface

    public ServiceIdentity getServiceIdentity(ResourceContext ctx, String domainName, String serviceName) {
        
        final String caller = "getserviceidentity";
        final String callerTiming = "getserviceidentity_timing";
        metric.increment(HTTP_GET);
        logPrincipal(ctx);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(serviceName, TYPE_SIMPLE_NAME, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case
        
        domainName = domainName.toLowerCase();
        serviceName = serviceName.toLowerCase();
        
        Object timerMetric = metric.startTiming(callerTiming, domainName);
        DomainData domainData = dataStore.getDomainData(domainName);
        if (domainData == null) {
            metric.increment(HTTP_REQUEST, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            metric.increment(caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            throw notFoundError("Domain not found: '" + domainName + "'", caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
        }
        
        // update our metric with dimension. we're moving the metric here
        // after the domain name has been confirmed as valid since with
        // dimensions we get stuck with persistent indexes so we only want
        // to create them for valid domain names

        metric.increment(HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        
        String cnService = generateServiceIdentityName(domainName, serviceName);
        ServiceIdentity ztsService = lookupServiceIdentity(domainData, cnService);

        if (ztsService == null) {
            throw notFoundError("Service not found: '" + cnService + "'", caller, domainName);
        }
        
        metric.stopTiming(timerMetric);
        return ztsService;
    }

    public PublicKeyEntry getPublicKeyEntry(ResourceContext ctx, String domainName, String serviceName, String keyId) {
        
        final String caller = "getpublickeyentry";
        final String callerTiming = "getpublickeyentry_timing";
        metric.increment(HTTP_GET);
        logPrincipal(ctx);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(serviceName, TYPE_SIMPLE_NAME, caller);

        if (keyId == null) {
            throw requestError("Invalid Public Key Id specified", caller, domainName);
        }
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domainName = domainName.toLowerCase();
        serviceName = serviceName.toLowerCase();
        keyId = keyId.toLowerCase();

        Object timerMetric = metric.startTiming(callerTiming, domainName);
        metric.increment(HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        String publicKey = dataStore.getPublicKey(domainName, serviceName, keyId);
        if (publicKey == null) {
            throw notFoundError("Public Key not found", caller, domainName);
        }

        PublicKeyEntry entry = new PublicKeyEntry().setId(keyId)
                .setKey(Crypto.ybase64(publicKey.getBytes(StandardCharsets.UTF_8)));
        metric.stopTiming(timerMetric);
        return entry;
    }
    
    void addServiceNameToList(String fullName, String prefix, List<String> names) {
        
        if (!fullName.startsWith(prefix)) {
            return;
        }
        
        names.add(fullName.substring(prefix.length()));
    }
    
    public ServiceIdentityList getServiceIdentityList(ResourceContext ctx, String domainName) {
        
        final String caller = "getserviceidentitylist";
        final String callerTiming = "getserviceidentitylist_timing";
        metric.increment(HTTP_GET);
        logPrincipal(ctx);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case
        
        domainName = domainName.toLowerCase();
        Object timerMetric = metric.startTiming(callerTiming, domainName);

        DomainData domainData = dataStore.getDomainData(domainName);
        if (domainData == null) {
            metric.increment(HTTP_REQUEST, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            metric.increment(caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            throw notFoundError("Domain not found: '" + domainName + "'", caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
        }
        
        // update our metric with dimension. we're moving the metric here
        // after the domain name has been confirmed as valid since with
        // dimensions we get stuck with persistent indexes so we only want
        // to create them for valid domain names

        metric.increment(HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        
        List<String> names = new ArrayList<String>();
        String prefix = domainName + ".";
        
        ServiceIdentityList result = new ServiceIdentityList();
        List<com.yahoo.athenz.zms.ServiceIdentity> services = domainData.getServices();
        if (services != null) {
            for (com.yahoo.athenz.zms.ServiceIdentity service : services) {
                addServiceNameToList(service.getName(), prefix, names);
            }
            result.setNames(names);
        }
        
        metric.stopTiming(timerMetric);
        return result;
    }

    public HostServices getHostServices(ResourceContext ctx, String host) {
        
        final String caller = "gethostservices";
        final String callerTiming = "gethostservices_timing";
        metric.increment(HTTP_GET);
        metric.increment(HTTP_REQUEST);
        metric.increment(caller);
        Object timerMetric = metric.startTiming(callerTiming, null);
        logPrincipal(ctx);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case
        
        host = host.toLowerCase();
        HostServices result = dataStore.getHostServices(host);
        
        metric.stopTiming(timerMetric);
        return result;
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
                            .setRole(zmsAssertion.getRole());

                    if (zmsAssertion.getEffect() != null
                            && zmsAssertion.getEffect() == com.yahoo.athenz.zms.AssertionEffect.DENY) {
                        ztsAssertion.setEffect(AssertionEffect.DENY);
                    } else {
                        ztsAssertion.setEffect(AssertionEffect.ALLOW);
                    }
                    ztsAssertions.add(ztsAssertion);
                }
                ztsPolicy.setAssertions(ztsAssertions);
            }
            ztsPolicies.add(ztsPolicy);
        }
        
        return ztsPolicies;
    }
    
    public void getDomainSignedPolicyData(ResourceContext ctx, String domainName,
            String matchingTag, GetDomainSignedPolicyDataResult signedPoliciesResult) {
        
        final String caller = "getdomainsignedpolicydata";
        final String callerTiming = "getdomainsignedpolicydata_timing";
        metric.increment(HTTP_GET);
        logPrincipal(ctx);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case
        
        domainName = domainName.toLowerCase();
        Object timerMetric = metric.startTiming(callerTiming, domainName);

        DomainData domainData = dataStore.getDomainData(domainName);
        if (domainData == null) {
            metric.increment(HTTP_REQUEST, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            metric.increment(caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            throw notFoundError("Domain not found: '" + domainName + "'", caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
        }
        
        // update our metric with dimension. we're moving the metric here
        // after the domain name has been confirmed as valid since with
        // dimensions we get stuck with persistent indexes so we only want
        // to create them for valid domain names

        metric.increment(HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        
        Timestamp modified = domainData.getModified();
        EntityTag eTag = new EntityTag(modified.toString());
        String tag = eTag.toString();
        
        // Set timestamp for domain rather than youngest policy.
        // Since a policy could have been deleted, and can only be detected
        // via the domain modified timestamp.
        
        if (matchingTag != null && matchingTag.equals(tag)) {
            signedPoliciesResult.done(304, matchingTag);
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

        String signature = Crypto.sign(SignUtils.asCanonicalString(signedPolicyData), privateKey);
        DomainSignedPolicyData result = new DomainSignedPolicyData()
            .setSignedPolicyData(signedPolicyData)
            .setSignature(signature)
            .setKeyId(privateKeyId);
        
        metric.stopTiming(timerMetric);
        signedPoliciesResult.done(200, result, tag);
    }

    String convertEmptyStringToNull(String value) {
        
        if (value != null && value.length() == 0) {
            return null;
        } else {
            return value;
        }
    }
    
    long determineTokenTimeout(Integer minExpiryTime, Integer maxExpiryTime) {
        
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
        
        return tokenTimeout;
    }

    public TenantDomains getTenantDomains(ResourceContext ctx, String providerDomainName,
            String userName, String roleName, String serviceName) {
        
        final String caller = "gettenantdomains";
        final String callerTiming = "gettenantdomains_timing";
        metric.increment(HTTP_GET);
        logPrincipal(ctx);

        validate(providerDomainName, TYPE_DOMAIN_NAME, caller);
        validate(userName, TYPE_ENTITY_NAME, caller);
        if (roleName != null) {
            validate(roleName, TYPE_ENTITY_NAME, caller);
        }
        if (serviceName != null) {
            validate(serviceName, TYPE_SERVICE_NAME, caller);
        }
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case
        
        providerDomainName = providerDomainName.toLowerCase();
        userName = userName.toLowerCase();
        if (roleName != null) {
            roleName = roleName.toLowerCase();
        }
        if (serviceName != null) {
            serviceName = serviceName.toLowerCase();
        }
        
        // first retrieve our domain data object from the cache

        Object timerMetric = metric.startTiming(callerTiming, providerDomainName);
        DataCache data = dataStore.getDataCache(providerDomainName);
        if (data == null) {
            // just increment the request counter without any dimension
            // we don't want to get persistent indexes for invalid domains

            metric.increment(HTTP_REQUEST, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            metric.increment(caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            LOGGER.error("getTenantDomains: Unknown provider domain: " + providerDomainName);
            throw notFoundError("getTenantDomains: No such provider domain: " + providerDomainName,
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
        }
        
        // update our metric with dimension. we're moving the metric here
        // after the domain name has been confirmed as valid since with
        // dimensions we get stuck with persistent indexes so we only want
        // to create them for valid domain names

        metric.increment(HTTP_REQUEST, providerDomainName);
        metric.increment(caller, providerDomainName);
        
        // process our request and retrieve the roles for the principal
        
        ArrayList<String> roles = new ArrayList<>();
        
        // if the username does not contain a domain then we'll assume
        // user domain and handle accordingly
        
        if (userName.indexOf('.') == -1) {
            userName = this.userDomain + "." + userName;
        }
        
        dataStore.getAccessibleRoles(data, providerDomainName, userName,
                roleName, roles, false);
        
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
        tenantDomains.setTenantDomainNames(new ArrayList<String>(domainNames));

        metric.stopTiming(timerMetric);
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
        StringBuffer domainNameBuf = new StringBuffer(512).append(comps[2]);
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
    
    // Token interface
    public RoleToken getRoleToken(ResourceContext ctx, String domainName, String roleName,
            Integer minExpiryTime, Integer maxExpiryTime, String proxyForPrincipal) {
        
        final String caller = "getroletoken";
        final String callerTiming = "getroletoken_timing";
        metric.increment(HTTP_GET);
        logPrincipal(ctx);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        if (roleName != null && !roleName.isEmpty()) {
            validate(roleName, TYPE_ENTITY_NAME, caller);
        }
        if (proxyForPrincipal != null && !proxyForPrincipal.isEmpty()) {
            validate(proxyForPrincipal, TYPE_ENTITY_NAME, caller);
        }
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case
        
        domainName = domainName.toLowerCase();
        if (roleName != null) {
            roleName = roleName.toLowerCase();
        }
        
        Object timerMetric = metric.startTiming(callerTiming, domainName);
        
        // get our principal's name
        
        String principal = ((RsrcCtxWrapper) ctx).principal().getFullName();
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("getRoleToken(domain: " + domainName + ", principal: " + principal +
                    ", role-name: " + roleName + ", proxy-for: " + proxyForPrincipal + ")");
        }
        
        // do not allow empty (not null) values for role
        
        roleName = convertEmptyStringToNull(roleName);
        proxyForPrincipal = convertEmptyStringToNull(proxyForPrincipal);

        if (leastPrivilegePrincipal && roleName == null) {
            LOGGER.error("getRoleToken: Principal: " + principal +
                    " requested a role token without the required roleName");
            throw requestError("getRoleToken: Client must specify a roleName to request a token for",
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
        }
        
        // we can only have a proxy for principal request if the original
        // caller is authorized for such operations
        
        if (proxyForPrincipal != null && !isAuthorizedProxyUser(authorizedProxyUsers, principal)) {
            LOGGER.error("getRoleToken: Principal: " + principal +
                    " not authorized for proxy role token request");
            throw forbiddenError("getRoleToken: Principal: " + principal
                    + " not authorized for proxy role token request", caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
        }
        
        StringBuilder auditLogDetails = new StringBuilder(512);
        auditLogDetails.append("RoleName=").append(roleName);
        AuditLogMsgBuilder msgBldr = getAuditLogMsgBuilder(ctx, domainName, caller, HTTP_GET);
        msgBldr.when(Timestamp.fromCurrentTime().toString()).
                whatEntity("RoleToken").why("zts-audit");

        // first retrieve our domain data object from the cache

        DataCache data = dataStore.getDataCache(domainName);
        if (data == null) {
            // just increment the request counter without any dimension
            // we don't want to get persistent indexes for invalid domains

            metric.increment(HTTP_REQUEST, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            metric.increment(caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            
            // create our audit log entry
            
            auditLogDetails.append(",ERROR=(No Such Domain)");
            msgBldr.whatDetails(auditLogDetails.toString());
            if (auditLogger != null) {
                auditLogger.log(msgBldr);
            } else {
                LOGGER.error(msgBldr.toString());
            }
            LOGGER.error("getRoleToken: Principal: " + principal +
                    " requested a role token for an unknown domain: " + domainName);
            throw notFoundError("getRoleToken: No such domain: " + domainName, caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
        }
        
        // update our metric with dimension. we're moving the metric here
        // after the domain name has been confirmed as valid since with
        // dimensions we get stuck with persistent indexes so we only want
        // to create them for valid domain names

        metric.increment(HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        
        // process our request and retrieve the roles for the principal
        
        ArrayList<String> roles = new ArrayList<>();
        dataStore.getAccessibleRoles(data, domainName, principal, roleName,
                roles, false);
        
        if (roles.isEmpty()) {
            auditLogDetails.append(",ERROR=(Principal Has No Access to Domain)");
            msgBldr.whatDetails(auditLogDetails.toString());
            if (auditLogger != null) {
                auditLogger.log(msgBldr);
            } else {
                LOGGER.error(msgBldr.toString());
            }
            LOGGER.error("getRoleToken: Principal: " + principal +
                    " has no acccess to any roles in domain: " + domainName);
            throw forbiddenError("getRoleToken: No access to any roles in domain: " + domainName,
                    caller, domainName);
        }
        
        // if this is proxy for operation then we want to make sure that
        // both principals have access to the same set of roles otherwise
        // we're not going to issue a roletoken with an updated principal
        // field
        
        String proxyUser = null;
        if (proxyForPrincipal != null) {
            ArrayList<String> rolesForProxy = new ArrayList<>();
            dataStore.getAccessibleRoles(data, domainName, proxyForPrincipal, roleName, rolesForProxy, false);
            if (!compareRoleLists(roles, rolesForProxy)) {
                throw forbiddenError("getRoleToken: Principal does not have access to the same set of roles as proxy principal",
                        caller, domainName);
            }
            
            // we need to switch our principal and proxy for user
            
            proxyUser = principal;
            principal = proxyForPrincipal;
        }

        long tokenTimeout = determineTokenTimeout(minExpiryTime, maxExpiryTime);
        com.yahoo.athenz.auth.token.RoleToken token =
                new com.yahoo.athenz.auth.token.RoleToken.Builder(ZTS_ROLE_TOKEN_VERSION, domainName, roles)
                    .expirationWindow(tokenTimeout).host(serverHostName).keyId(privateKeyId)
                    .principal(principal).ip(ServletRequestUtil.getRemoteAddress(ctx.request()))
                    .proxyUser(proxyUser).domainCompleteRoleSet(roleName == null).build();
        token.sign(privateKey);

        RoleToken roleToken = new RoleToken();
        roleToken.setToken(token.getSignedToken());
        roleToken.setExpiryTime(token.getExpiryTime());
        
        auditLogDetails.append(",SUCCESS ROLETOKEN=(").append(token.getUnsignedToken()).append(")"); 
        msgBldr.whatDetails(auditLogDetails.toString());
        if (auditLogger != null) {
            auditLogger.log(msgBldr);
        } else {
            LOGGER.error(msgBldr.toString());
        }

        metric.stopTiming(timerMetric);
        return roleToken;
    }

    boolean compareRoleLists(List<String> list1, List<String> list2) {

        if (list1.size() != list2.size()) {
            LOGGER.error("Role lists do not have the same size: " + list1.size() + " vs. " + list2.size());
            return false;
        }

        Set<String> set2 = new HashSet<>(list2);
        for (String item : list1) {
            if (!set2.contains(item)) {
                return false;
            }
        }

        return true;
    }

    public RoleAccess getRoleAccess(ResourceContext ctx, String domainName, String principal) {
        
        final String caller = "getroleaccess";
        final String callerTiming = "getroleaccess_timing";
        metric.increment(HTTP_GET);
        logPrincipal(ctx);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(principal, TYPE_ENTITY_NAME, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case
        
        domainName = domainName.toLowerCase();
        principal = principal.toLowerCase();
        
        Object timerMetric = metric.startTiming(callerTiming, domainName);
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("getRoleAccess(domain: " + domainName + ", principal: " + principal + ")");
        }
        
        // first retrieve our domain data object from the cache

        DataCache data = dataStore.getDataCache(domainName);
        if (data == null) {
            // just increment the request counter without any dimension
            // we don't want to get persistent indexes for invalid domains

            metric.increment(HTTP_REQUEST, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            metric.increment(caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            
            LOGGER.error("getRoleAccess: Principal: " + principal +
                    " requested role access for an unknown domain: " + domainName);
            throw notFoundError("getRoleAccess: No such domain: " + domainName,
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
        }
        
        // update our metric with dimension. we're moving the metric here
        // after the domain name has been confirmed as valid since with
        // dimensions we get stuck with persistent indexes so we only want
        // to create them for valid domain names

        metric.increment(HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        
        // process our request and retrieve the roles for the principal
        
        ArrayList<String> roles = new ArrayList<>();
        dataStore.getAccessibleRoles(data, domainName, principal, null,
                roles, false);
        
        RoleAccess roleAccess = new RoleAccess().setRoles(roles);
        metric.stopTiming(timerMetric);
        return roleAccess;
    }
    
    @Override
    public RoleToken postRoleCertificateRequest(ResourceContext ctx, String domainName, String roleName,
            RoleCertificateRequest req) {
        
        final String caller = "postrolecertificaterequest";
        final String callerTiming = "postrolecertificaterequest_timing";
        metric.increment(HTTP_POST);
        logPrincipal(ctx);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);
        validate(req, TYPE_ROLE_CERTIFICATE_REQUEST, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case
        
        domainName = domainName.toLowerCase();
        roleName = roleName.toLowerCase();
        
        Object timerMetric = metric.startTiming(callerTiming, domainName);

        // get our principal's name
        
        String principal = ((RsrcCtxWrapper) ctx).principal().getFullName();
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("postRoleCertificateRequest(domain: " + domainName + ", principal: "
                    + principal + ", role: " + roleName + ")");
        }
        
        StringBuilder auditLogDetails = new StringBuilder(512);
        AuditLogMsgBuilder msgBldr = getAuditLogMsgBuilder(ctx, domainName, caller, HTTP_GET);
        msgBldr.when(Timestamp.fromCurrentTime().toString()).
                whatEntity("RoleCertificate").why("zts-audit");

        // first retrieve our domain data object from the cache

        DataCache data = dataStore.getDataCache(domainName);
        if (data == null) {
            // just increment the request counter without any dimension
            // we don't want to get persistent indexes for invalid domains

            metric.increment(HTTP_REQUEST, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            metric.increment(caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            
            // create our audit log entry
            
            auditLogDetails.append(",ERROR=(No Such Domain)");
            msgBldr.whatDetails(auditLogDetails.toString());
            if (auditLogger != null) {
                auditLogger.log(msgBldr);
            } else {
                LOGGER.error(msgBldr.toString());
            }
            LOGGER.error("postRoleCertificateRequest: Principal: " + principal +
                    " requested a role certificate for an unknown domain: " + domainName);
            throw notFoundError("postRoleCertificateRequest: No such domain: " + domainName,
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
        }
        
        // update our metric with dimension. we're moving the metric here
        // after the domain name has been confirmed as valid since with
        // dimensions we get stuck with persistent indexes so we only want
        // to create them for valid domain names

        metric.increment(HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        
        // process our request and retrieve the roles for the principal
        
        ArrayList<String> roles = new ArrayList<>();
        dataStore.getAccessibleRoles(data, domainName, principal, roleName,
                roles, false);
        
        if (roles.isEmpty()) {
            auditLogDetails.append(",ERROR=(Principal Has No Access to Domain)");
            msgBldr.whatDetails(auditLogDetails.toString());
            if (auditLogger != null) {
                auditLogger.log(msgBldr);
            } else {
                LOGGER.error(msgBldr.toString());
            }
            LOGGER.error("postRoleCertificateRequest: Principal: " + principal +
                    " has no acccess to any roles in domain: " + domainName);
            throw forbiddenError("postRoleCertificateRequest: No access to any roles in domain: "
                    + domainName, caller, domainName);
        }
        
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(req.getCsr());
        if (certReq == null) {
            LOGGER.error("postRoleCertificateRequest: unable to parse cert request");
            throw requestError("postRoleCertificateRequest: Unable to parse cert request",
                    caller, domainName);
        }

        if (!validateRoleCertificateRequest(certReq, domainName, roles, principal)) {
            LOGGER.error("postRoleCertificateRequest: unable to validate certificate request");
            throw requestError("postRoleCertificateRequest: Unable to validate cert request",
                    caller, domainName);
        }
        
        CertSigner certSigner = this.cloudStore.getCertSigner();
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Cert signer: {} ", certSigner);
        }
        String x509Cert = certSigner.generateX509Certificate(req.getCsr());
        if (null == x509Cert || x509Cert.isEmpty()) {
            LOGGER.error("Unable to create certificate from the cert signer");
            throw serverError("postRoleCertificateRequest: Unable to create certificate from the cert signer",
                    caller, domainName);
        }
        RoleToken roleToken = new RoleToken().setToken(x509Cert).setExpiryTime(ZTS_ROLE_CERT_EXPIRY);
        
        auditLogDetails.append(",SUCCESS ROLE-CERTIFICATE");
        msgBldr.whatDetails(auditLogDetails.toString());
        if (auditLogger != null) {
            auditLogger.log(msgBldr);
        } else {
            LOGGER.error(msgBldr.toString());
        }

        metric.stopTiming(timerMetric);
        return roleToken;
    }

    boolean validateRoleCertificateRequest(PKCS10CertificationRequest certReq,
            String domainName, List<String> roles, String principal) {
        
        String cnCertReq = null;
        try {
            cnCertReq = Crypto.extractX509CSRCommonName(certReq);
        } catch (Exception ex) {
            
            // we want to catch all the exceptions here as we want to
            // handle all the errors and not let container to return
            // standard server error
            
            LOGGER.error("validateRoleCertificateRequest: unable to extract csr cn: "
                    + ex.getMessage());
        }
        
        if (cnCertReq == null) {
            return false;
        }
        
        // we must have only a single value in our list since we specified
        // what role we're looking for but we'll iterate through the list
        // anyway
        
        boolean roleNameValidated = false;
        for (String role : roles) {
            final String roleName = domainName + ":role." + role;
            if (cnCertReq.equals(roleName)) {
                roleNameValidated = true;
                break;
            }
        }
        
        if (!roleNameValidated) {
            return false;
        }
        
        // now let's check if we have an rfc822 field specified in the
        // request. if we have, then it must be of the following format:
        // principal@[cloud].yahoo.cloud
        
        String email = null;
        try {
            email = Crypto.extractX509CSREmail(certReq);
        } catch (Exception ex) {
            
            // we want to catch all the exceptions here as we want to
            // handle all the errors and not let container to return
            // standard server error
            
            LOGGER.error("validateRoleCertificateRequest: unable to extract csr email: "
                    + ex.getMessage());
        }
        
        if (email != null) {
            String emailPrefix = principal + "@";
            if (!email.startsWith(emailPrefix) || !email.endsWith(".yahoo.cloud")) {
                return false;
            }
        }
        
        return true;
    }
    public AWSTemporaryCredentials getAWSTemporaryCredentials(ResourceContext ctx, String domainName,
            String roleName) {

        final String caller = "getawstemporarycredentials";
        final String callerTiming = "getawstemporarycredentials_timing";
        metric.increment(HTTP_GET);
        logPrincipal(ctx);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case
        
        domainName = domainName.toLowerCase();
        roleName = roleName.toLowerCase();
        
        Object timerMetric = metric.startTiming(callerTiming, domainName);
        metric.increment(HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("getAWSTemporaryCredentials(domain: " + domainName + ", role: " + roleName + ")");
        }
        
        if (!cloudStore.isAwsEnabled()) {
            throw requestError("getAWSTemporaryCredentials: AWS support is not available",
                    caller, domainName);
        }
        
        // get our principal's name
        
        String principal = ((RsrcCtxWrapper) ctx).principal().getFullName();
        
        String roleResource = domainName + ":" + roleName;
        
        // we need to first verify that our principal is indeed configured
        // with aws assume role assertion for the specified role and domain
        
        if (!verifyAWSAssumeRole(domainName, roleResource, principal)) {
            throw forbiddenError("getAWSTemporaryCredentials: Forbidden (ASSUME_AWS_ROLE on "
                    + roleResource + " for " + principal + ")", caller, domainName);
        }
        
        // now need to get the associated AWS account for the domain name
        
        String account = cloudStore.getAWSAccount(domainName);
        if (account == null) {
            throw requestError("getAWSTemporaryCredentials: unable to retrieve AWS account for: "
                    + domainName, caller, domainName);
        }
        
        // obtain the credentials from the cloud store
        
        AWSTemporaryCredentials creds = cloudStore.assumeAWSRole(account, roleName, principal);
        if (creds == null) {
            throw requestError("getAWSTemporaryCredentials: unable to assume role " + roleName
                    + " in domain " + domainName + " for principal " + principal, caller, domainName);
        }
        
        metric.stopTiming(timerMetric);
        return creds;
    }

    boolean verifyAWSAssumeRole(String domainName, String roleResource, String principal) {
        
        // first retrieve our domain data object from the cache
        
        DataCache data = dataStore.getDataCache(domainName);
        if (data == null) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("verifyAWSAssumeRole: unknown domain: " + domainName);
            }
            return false;
        }
        
        // retrieve the roles for the principal
        
        ArrayList<String> roles = new ArrayList<>();
        dataStore.getAccessibleRoles(data, domainName, principal, null, roles, true);
        
        if (roles.isEmpty()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("verifyAWSAssumeRole: Principal: " + principal +
                    " has no acccess to any roles in domain: " + domainName);
            }
            return false;
        }

        // check to see if any of the roles give access to the specified resource
        
        Set<String> awsResourceSet = null;
        for (String role : roles) {
            awsResourceSet = data.getAWSResourceRoleSet(role);
            if (awsResourceSet != null && awsResourceSet.contains(roleResource)) {
                return true;
            }
        }
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("verifyAWSAssumeRole: Principal: " + principal +
                " has no acccess to resource: " + roleResource + " in domain: " + domainName);
        }
        
        return false;
    }

    @Override
    public Identity postAWSInstanceInformation(ResourceContext ctx, AWSInstanceInformation info) {
        
        final String caller = "postawsinstanceinformation";
        final String callerTiming = "postawsinstanceinformation_timing";
        metric.increment(HTTP_POST);
        logPrincipal(ctx);

        validate(info, TYPE_AWS_INSTANCE_INFO, caller);
        
        Object timerMetric = metric.startTiming(callerTiming, info.getDomain());
        metric.increment(HTTP_REQUEST, info.getDomain());
        metric.increment(caller, info.getDomain());
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("postAWSInstanceInformation: " + info);
        }
        
        if (!cloudStore.isAwsEnabled()) {
            throw requestError("postAWSInstanceInformation: AWS support is not available",
                    caller, info.getDomain());
        }
        
        // verify we have a valid aws enabled domain
        
        String account = cloudStore.getAWSAccount(info.getDomain());
        if (account == null) {
            throw requestError("postAWSInstanceInformation: unable to retrieve AWS account for: "
                    + info.getDomain(), caller, info.getDomain());
        }
        
        // verify the domain account and the account in the info
        // object do match
        
        if (!account.equalsIgnoreCase(info.getAccount())) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("postAWSInstanceInformation: ZTS domain account lookup: " + account);
                LOGGER.debug("postAWSInstanceInformation: Instance Information account: " + info.getAccount());
            }
            throw requestError("postAWSInstanceInformation: mismatch between account values: "
                    + " domain lookup: " + account + " vs. instance info: " + info.getAccount(),
                    caller, info.getDomain());
        }
        
        // we need to validate the instance document
        
        if (!cloudStore.validateInstanceDocument(info.getDocument(), info.getSignature())) {
            throw requestError("postAWSInstanceInformation: unable to validate instance document",
                    caller, info.getDomain());
        }
        
        // convert our document into a struct that we can extract data
        
        Struct instanceDocument = null;
        try {
            instanceDocument = JSON.fromString(info.getDocument(), Struct.class);
        } catch (Exception ex) {
            LOGGER.error("postAWSInstanceInformation: failed to parse: " + info.getDocument()
                + " error: " + ex.getMessage());
        }
        
        if (instanceDocument == null) {
            throw requestError("postAWSInstanceInformation: unable to parse instance document",
                    caller, info.getDomain());
        }
        
        // verify that the account lookup and the account in the document match
        
        String docAccount = instanceDocument.getString(ATTR_ACCOUNT_ID);
        if (!account.equalsIgnoreCase(docAccount)) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("postAWSInstanceInformation: ZTS domain account lookup: " + account);
                LOGGER.debug("postAWSInstanceInformation: Instance document account: " + docAccount);
            }
            throw requestError("postAWSInstanceInformation: mismatch between account values: "
                    + " domain lookup: " + account + " vs. instance document: " + docAccount,
                    caller, info.getDomain());
        }
        
        // verify that the boot up time for the instance is now

        Timestamp bootTime = instanceDocument.getTimestamp(ATTR_PENDING_TIME);
        if (bootTime.millis() < System.currentTimeMillis() - bootTimeOffset) {
            throw forbiddenError("postAWSInstanceInformation: instance boot time is not recent enough",
                    caller, info.getDomain());
        }
        
        // verify that the temporary credentials specified in the request
        // can be used to assume the given role thus verifying the
        // instance identity
        
        if (!cloudStore.verifyInstanceIdentity(info)) {
            throw requestError("postAWSInstanceInformation: unable to verify instance identity",
                    caller, info.getDomain());
        }
        
        // now let's validate the csr given to us by the client
        // and generate certificate for the instance
        
        Identity identity = cloudStore.generateIdentity(info.getCsr(), info.getName());
        if (identity == null) {
            throw requestError("postAWSInstanceInformation: unable to generate identity",
                    caller, info.getDomain());
        }
        
        metric.stopTiming(timerMetric);
        return identity;
    }
     
    @Override
    public Identity postInstanceRefreshRequest(ResourceContext ctx, String domain,
            String service, InstanceRefreshRequest req) {

        final String caller = "postinstancerefreshrequest";
        final String callerTiming = "postinstancerefreshrequest_timing";
        metric.increment(HTTP_POST);
        logPrincipal(ctx);

        validate(domain, TYPE_DOMAIN_NAME, caller);
        validate(service, TYPE_SIMPLE_NAME, caller);
        validate(req, TYPE_INSTANCE_REFRESH_REQUEST, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domain = domain.toLowerCase();
        service = service.toLowerCase();
        
        Object timerMetric = metric.startTiming(callerTiming, domain);
        metric.increment(HTTP_REQUEST, domain);
        metric.increment(caller, domain);

        // make sure the credentials match to whatever the request is

        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        String principalName = domain + "." + service;
        if (!principalName.equals(principal.getFullName())) {
            throw requestError("postInstanceRefreshRequest: Principal mismatch: "
                    + principalName + " vs. " + principal.getFullName(), caller, domain);
        }

        Authority authority = principal.getAuthority();
        
        // currently we only support ServiceTokens being refreshed to
        // certificates and services that already have certificates
        
        if (!(authority instanceof CertificateAuthority || authority instanceof PrincipalAuthority)) {
            throw requestError("postInstanceRefreshRequest: Unsupported authority for TLS Certs: " +
                    authority.toString(), caller, domain);
        }
         
        // if we're converting NTokens into TLS Certs, then we have two
        // additional checks - need to verify it's not a user and the
        // public key for the NToken must match what's in the CSR
        
        String publicKey = null;
        if (authority instanceof PrincipalAuthority) {
            
            // if the authority is a principal authority, make sure it's not
            // a personal domain user token as users should not get personal
            // TLS certificates from ZTS
            
            if (userDomain.equalsIgnoreCase(principal.getDomain())) {
                throw requestError("postInstanceRefreshRequest: TLS Certificates require ServiceTokens: " +
                        principalName, caller, domain);
            }

            // retrieve the public key for the principal
            
            publicKey = getPublicKey(domain, service, principal.getKeyId());
            if (publicKey == null) {
                throw requestError("postInstanceRefreshRequest: Unable to retrieve public key for " +
                        principalName + " with key id: " + principal.getKeyId(), caller, domain);
            }
        }
        
        // validate that the cn and public key (if required) match to
        // the provided details
        
        if (!instanceIdentityStore.verifyCertificateRequest(req.getCsr(), principalName, publicKey)) {
            throw requestError("postInstanceRefreshRequest: invalid CSR - cn or public key mismatch",
                    caller, domain);
        }
        
        // generate identity with the certificate
        
        Identity identity = instanceIdentityStore.generateIdentity(req.getCsr(), principalName);
        if (identity == null) {
            throw requestError("postInstanceRefreshRequest: unable to generate identity",
                    caller, domain);
        }
        
        metric.stopTiming(timerMetric);
        return identity;
    }

    @Override
    public Identity postInstanceInformation(ResourceContext ctx, InstanceInformation info) {

        final String caller = "postinstanceinformation";
        final String callerTiming = "postinstanceinformation_timing";
        metric.increment(HTTP_POST);
        logPrincipal(ctx);

        String domain = info.getDomain();
        String service = info.getService();

        Object timerMetric = metric.startTiming(callerTiming, domain);
        metric.increment(HTTP_REQUEST, domain);
        metric.increment(caller, domain);

        validate(info, TYPE_INSTANCE_INFO, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)

        domain = domain.toLowerCase();
        service = service.toLowerCase();
        final String cn = domain + "." + service;
        
        // now let's validate the request, and the csr, given to us by the client

        if (!instanceIdentityStore.verifyInstanceIdentity(info)) {
            throw requestError("postInstanceInformation: unable to generate identity, invalid request",
                    caller, domain);
        }

        // validate the CSR
        
        if (!instanceIdentityStore.verifyCertificateRequest(info.getCsr(), cn, null)) {
            throw requestError("postInstanceInformation: unable to generate identity, invalid csr",
                    caller, domain);
        }
        
        // generate certificate for the instance

        Identity identity = instanceIdentityStore.generateIdentity(info.getCsr(), cn);
        if (identity == null) {
            throw requestError("postInstanceInformation: unable to generate identity",
                    caller, domain);
        }

        metric.stopTiming(timerMetric);
        return identity;
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
    
    @Override
    public Identity postAWSCertificateRequest(ResourceContext ctx, String domain, String service,
            AWSCertificateRequest req) {
        
        final String caller = "postawscertificaterequest";
        final String callerTiming = "postawscertificaterequest_timing";
        metric.increment(HTTP_POST);
        logPrincipal(ctx);

        validate(domain, TYPE_DOMAIN_NAME, caller);
        validate(service, TYPE_SIMPLE_NAME, caller);
        validate(req, TYPE_AWS_CERT_REQUEST, caller);

        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        domain = domain.toLowerCase();
        service = service.toLowerCase();
        
        Object timerMetric = metric.startTiming(callerTiming, domain);
        metric.increment(HTTP_REQUEST, domain);
        metric.increment(caller, domain);
        
        // get our principal's name
        
        // make sure this was authenticated by the
        // Certificate authority and not by anyone else
        
        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        Authority authority = principal.getAuthority();
        
        if (!(authority instanceof com.yahoo.athenz.auth.impl.CertificateAuthority)) {
            throw forbiddenError("postAWSCertificateRequest: Not authenticated by Certificate Authority",
                    caller, domain);
        }
        
        String principalName = principal.getFullName();

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("postAWSCertificateRequest: " + req + " for principal: " + principal);
        }
        
        if (!cloudStore.isAwsEnabled()) {
            throw requestError("postAWSCertificateRequest: AWS support is not available",
                    caller, domain);
        }
        
        // verify we have a valid aws enabled domain
        
        String account = cloudStore.getAWSAccount(domain);
        if (account == null) {
            throw requestError("postAWSCertificateRequest: unable to retrieve AWS account for: "
                    + domain, caller, domain);
        }
        
        // now let's validate the csr given to us by the client
        // and generate certificate for the instance
        
        Identity identity = cloudStore.generateIdentity(req.getCsr(), principalName);
        if (identity == null) {
            throw requestError("postAWSCertificateRequest: unable to generate identity",
                    caller, domain);
        }
        
        metric.stopTiming(timerMetric);
        return identity;
    }
    
    @Override
    public Access getAccess(ResourceContext ctx, String domainName, String roleName,
            String principal) {
        
        final String caller = "getaccess";
        final String callerTiming = "getaccess_timing";
        metric.increment(HTTP_GET);
        logPrincipal(ctx);
        
        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(roleName, TYPE_ENTITY_NAME, caller);
        validate(principal, TYPE_ENTITY_NAME, caller);
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case since ZMS Server
        // saves all of its object names in lower case
        
        domainName = domainName.toLowerCase();
        roleName = roleName.toLowerCase();
        principal = principal.toLowerCase();
        
        Object timerMetric = metric.startTiming(callerTiming, domainName);
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("getAccess(domain: " + domainName + ", principal: " + principal +
                    ", role: " + roleName + ")");
        }
        
        // first retrieve our domain data object from the cache

        DataCache data = dataStore.getDataCache(domainName);
        if (data == null) {
            // just increment the request counter without any dimension
            // we don't want to get persistent indexes for invalid domains

            metric.increment(HTTP_REQUEST, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            metric.increment(caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            
            LOGGER.error("getAccess(principal: " + principal + ", role: " + roleName
                    + ") unknown domain: " + domainName);
            throw notFoundError("getAccess: No such domain: " + domainName, caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
        }
        
        // update our metric with dimension. we're moving the metric here
        // after the domain name has been confirmed as valid since with
        // dimensions we get stuck with persistent indexes so we only want
        // to create them for valid domain names

        metric.increment(HTTP_REQUEST, domainName);
        metric.increment(caller, domainName);
        
        // process our request and retrieve the roles for the principal
        
        ArrayList<String> roles = new ArrayList<>();
        dataStore.getAccessibleRoles(data, domainName, principal, null,
                roles, false);
        
        // create our response object and set the flag whether
        // or not the principal has access to the role
        
        Access access = new Access();
        access.setGranted(roles.contains(roleName));
        
        metric.stopTiming(timerMetric);
        return access;
    }
    
    /*
     * /metrics/{domainName}
     */
    @Override
    public DomainMetrics postDomainMetrics(ResourceContext ctx, String domainName,
            DomainMetrics req) {

        final String caller = "postdomainmetrics";
        final String callerTiming = "postdomainmetrics_timing";
        metric.increment(HTTP_POST);
        logPrincipal(ctx);

        validate(domainName, TYPE_DOMAIN_NAME, caller);
        validate(req, TYPE_DOMAIN_METRICS, caller);
        domainName = domainName.toLowerCase();
 
        Object timerMetric = metric.startTiming(callerTiming, domainName);

        // verify valid domain specified
        DataCache data = dataStore.getDataCache(domainName);
        if (data == null) {
            metric.increment(HTTP_REQUEST, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            metric.increment(caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            LOGGER.error("postDomainMetrics: request for unknown domain: " + domainName);
            throw notFoundError("postDomainMetrics: No such domain: " + domainName,
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
        }

        // verify domain name matches domain name in request object
        String metricDomain = req.getDomainName();
        if (metricDomain == null) {
            String errMsg = "postDomainMetrics: metrics request missing domain name: "
                    + domainName;
            LOGGER.error(errMsg);
            throw requestError(errMsg, caller, domainName);
        } else if (metricDomain != null) {
            metricDomain = metricDomain.toLowerCase();
            if (!metricDomain.equals(domainName)) {
                String errMsg = "postDomainMetrics: mismatched domain names: uri domain: "
            + domainName + " : metric domain: " + metricDomain;
                LOGGER.error(errMsg);
                throw requestError(errMsg, caller, domainName);
            }
        }

        List<DomainMetric> dmList = req.getMetricList();
        if (dmList == null || dmList.size() == 0) {
            // no metrics were sent - log error
            String errMsg = "postDomainMetrics: received no metrics for domain: " + domainName;
            LOGGER.error(errMsg);
            throw requestError(errMsg, caller, domainName);
        }

        // process the DomainMetrics request in order to increment each of its attrs
        for (DomainMetric dm: dmList) {
            DomainMetricType dmType = dm.getMetricType();
            if (dmType == null) {
                LOGGER.warn("postDomainMetrics: ignore missing metric received for domain: {}", domainName);
                continue;
            }

            String dmt    = dmType.toString().toLowerCase();
            Integer count = dm.getMetricVal();
            if (count == null || count.intValue() < 0) {
                if (LOGGER.isWarnEnabled()) {
                    LOGGER.warn("postDomainMetrics: ignore metric: " + dmt + 
                        " : invalid counter: " + count + " : received for domain: " + domainName);
                }
                continue;
            }
            String metricName = DOM_METRIX_PREFIX + dmt;
            metric.increment(metricName, domainName, count);
        }

        metric.stopTiming(timerMetric);
        return req;
    }
    
    @Override
    public Schema getRdlSchema(ResourceContext context) {
        return schema;
    }
    
    protected String formatValidationError(String msg, Struct v) {
        return msg + ": " + v.getString("error") + " [" + v.getString("context") + "]";
    }

    void validate(Object val, String type, String caller) {
        if (val == null) {
            throw requestError("Missing or malformed " + type, caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
        }
        
        Result result = validator.validate(val, type);
        if (!result.valid) {
            throw requestError("Invalid " + type  + " error: " + result.error, caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN);
        }
    }

    void logPrincipal(ResourceContext ctx) {
        final Principal principal = ((RsrcCtxWrapper) ctx).principal();
        if (principal != null) {
            ctx.request().setAttribute(AthenzRequestLog.REQUEST_PRINCIPAL, principal.getFullName());
        }
    }
    
    protected RuntimeException error(int code, String msg, String caller, String domainName) {
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(msg);
        }
        
        // If caller is null, we do not want to emit any error metrics.
        // Otherwise, the caller name should be from the method that threw
        // the specific runtime exception.
        
        if (caller != null && !ZTSUtils.emitMonmetricError(code, caller, domainName, this.metric)) {
            LOGGER.error("ZTS Error: unable to emit error metric for caller: " + caller +
                    " with message: " + msg);
        }
        return new ResourceException(code, new ResourceError().code(code).message(msg));
    }

    protected RuntimeException requestError(String msg, String caller, String domainName) {
        return error(ResourceException.BAD_REQUEST, msg, caller, domainName);
    }

    protected RuntimeException forbiddenError(String msg, String caller, String domainName) {
        return error(ResourceException.FORBIDDEN, msg, caller, domainName);
    }

    protected RuntimeException notFoundError(String msg, String caller, String domainName) {
        return error(ResourceException.NOT_FOUND, msg, caller, domainName);
    }

    protected RuntimeException serverError(String msg, String caller, String domainName) {
        return error(ResourceException.INTERNAL_SERVER_ERROR, msg, caller, domainName);
    }

    public ResourceContext newResourceContext(HttpServletRequest request, HttpServletResponse response) {
        return new RsrcCtxWrapper(request, response, authorities, authorizer);
    }

    public Authorizer getAuthorizer() {
        return authorizer;
    }
}
