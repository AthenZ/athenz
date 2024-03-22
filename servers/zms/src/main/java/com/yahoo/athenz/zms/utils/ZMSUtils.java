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
package com.yahoo.athenz.zms.utils;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.StringUtils;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.common.server.util.ServletRequestUtil;
import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.Validator;
import jakarta.ws.rs.core.Response;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.TimeUnit;

public class ZMSUtils {

    private static final Logger LOG = LoggerFactory.getLogger(ZMSUtils.class);

    public static void addAssertion(Policy policy, String resource, String action, String role,
            AssertionEffect effect) {
        
        List<Assertion> assertions = policy.getAssertions();
        if (assertions == null) {
            assertions = new ArrayList<>();
            policy.setAssertions(assertions);
        }
        Assertion assertion = new Assertion()
                .setAction(action)
                .setResource(resource)
                .setRole(role);
        if (effect != AssertionEffect.ALLOW) {
            assertion.setEffect(effect);
        }
        assertions.add(assertion);
    }
    
    public static Role makeAdminRole(String domainName, List<String> adminUsers) {
        List<RoleMember> roleMembers = new ArrayList<>();
        for (String admin: adminUsers) {
            RoleMember roleMember = new RoleMember();
            roleMember.setMemberName(admin);
            roleMember.setActive(true);
            roleMember.setApproved(true);
            roleMembers.add(roleMember);
        }
        return new Role()
                .setName(ResourceUtils.roleResourceName(domainName, ZMSConsts.ADMIN_ROLE_NAME))
                .setRoleMembers(roleMembers);
    }
    
    public static Policy makeAdminPolicy(String domainName, Role adminsRole) {
        
        Policy policy = new Policy()
                .setName(ResourceUtils.policyResourceName(domainName, ZMSConsts.ADMIN_POLICY_NAME));
        
        addAssertion(policy, domainName + ":*", "*", adminsRole.getName(), AssertionEffect.ALLOW);
        return policy;
    }
    
    public static String removeDomainPrefix(String objectName, String domainName, String objectPrefix) {
        String valPrefix = domainName + ":" + objectPrefix;
        if (objectName.startsWith(valPrefix)) {
            objectName = objectName.substring(valPrefix.length());
        }
        return objectName;
    }
    
    public static String removeDomainPrefixForService(String serviceName, String domainName) {
        final String valPrefix = domainName + ".";
        if (serviceName.startsWith(valPrefix)) {
            serviceName = serviceName.substring(valPrefix.length());
        }
        return serviceName;
    }
    
    public static String getTenantResourceGroupRolePrefix(String provSvcName, String tenantDomain, String resourceGroup) {
        
        StringBuilder rolePrefix = new StringBuilder(256);
        rolePrefix.append(provSvcName).append(".tenant.").append(tenantDomain).append('.');
        if (resourceGroup != null) {
            rolePrefix.append("res_group.");
            if (!resourceGroup.isEmpty()) {
                rolePrefix.append(resourceGroup).append('.');
            }
        }
        return rolePrefix.toString();
    }
    
    public static String getProviderResourceGroupRolePrefix(String provSvcDomain, String provSvcName, String resourceGroup) {
        
        StringBuilder rolePrefix = new StringBuilder(256);
        rolePrefix.append(provSvcDomain).append('.').append(provSvcName).append('.');
        if (!StringUtil.isEmpty(resourceGroup)) {
            rolePrefix.append("res_group.").append(resourceGroup).append('.');
        }
        return rolePrefix.toString();
    }
    
    public static String getTrustedResourceGroupRolePrefix(String provSvcDomain, String provSvcName,
            String tenantDomain, String resourceGroup) {
        
        StringBuilder trustedRole = new StringBuilder(256);
        trustedRole.append(provSvcDomain).append(AuthorityConsts.ROLE_SEP).append(provSvcName)
                .append(".tenant.").append(tenantDomain).append('.');
        if (!StringUtil.isEmpty(resourceGroup)) {
            trustedRole.append("res_group.").append(resourceGroup).append('.');
        }
        return trustedRole.toString();
    }
    
    /**
     * Set up a new AuditLogMsgBuilder object with common values.
     * @param ctx resource context object
     * @param auditLogger audit logger object
     * @param domainName domain name
     * @param auditRef audit reference value provided in the request
     * @param caller api name
     * @param method http method name
     * @return audit log message builder object
    **/
    public static AuditLogMsgBuilder getAuditLogMsgBuilder(ResourceContext ctx,
            AuditLogger auditLogger, String domainName, String auditRef, String caller,
            String method) {
        
        AuditLogMsgBuilder msgBldr = auditLogger.getMsgBuilder();

        // get the where - which means where this server is running
        
        msgBldr.where(ZMSImpl.serverHostName);
        msgBldr.whatDomain(domainName).why(auditRef).whatApi(caller).whatMethod(method);

        // get the 'who' and set it
        
        if (ctx != null) {
            Principal princ = ((RsrcCtxWrapper) ctx).principal();
            if (princ != null) {
                String fullName = princ.getFullName();
                String unsignedCreds = princ.getUnsignedCredentials();
                if (unsignedCreds == null) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("who-name=").append(princ.getName());
                    sb.append(",who-domain=").append(princ.getDomain());
                    sb.append(",who-fullname=").append(fullName);
                    List<String> roles = princ.getRoles();
                    if (roles != null && !roles.isEmpty()) {
                        sb.append(",who-roles=").append(roles);
                    }
                    unsignedCreds = sb.toString();
                }
                msgBldr.who(unsignedCreds);
                msgBldr.whoFullName(fullName);
            }

            // get the client IP
            
            msgBldr.clientIp(ServletRequestUtil.getRemoteAddress(ctx.request()));
        }

        return msgBldr;
    }
    
    public static RuntimeException error(int code, String msg, String caller) {

        LOG.error("Error: {} code: {} message: {}", caller, code, msg);
        
        // emit our metrics if configured. the method will automatically
        // return from the caller if caller is null
        
        emitMonmetricError(code, caller);
        return new ResourceException(code, new ResourceError().code(code).message(msg));
    }

    public static RuntimeException requestError(String msg, String caller) {
        return error(ResourceException.BAD_REQUEST, msg, caller);
    }

    public static RuntimeException unauthorizedError(String msg, String caller) {
        return error(ResourceException.UNAUTHORIZED, msg, caller);
    }

    public static RuntimeException forbiddenError(String msg, String caller) {
        return error(ResourceException.FORBIDDEN, msg, caller);
    }

    public static RuntimeException notFoundError(String msg, String caller) {
        return error(ResourceException.NOT_FOUND, msg, caller);
    }
    
    public static RuntimeException internalServerError(String msg, String caller) {
        return error(ResourceException.INTERNAL_SERVER_ERROR, msg, caller);
    }
    
    public static RuntimeException quotaLimitError(String msg, String caller) {
        return error(ResourceException.TOO_MANY_REQUESTS, msg, caller);
    }
    
    public static boolean emitMonmetricError(int errorCode, String caller) {
        if (errorCode < 1) {
            return false;
        }
        if (caller == null || caller.isEmpty()) {
            return false;
        }
        
        if (ZMSImpl.metric == null) {
            return false;
        }
        // Set 3 scoreboard error metrics:
        // (1) cumulative "ERROR" (of all zms request and error types)
        // (2) cumulative granular zms request and error type (eg- "getdomainlist_error_400")
        // (3) cumulative error type (of all zms requests) (eg- "error_404")
        String errCode = Integer.toString(errorCode);
        ZMSImpl.metric.increment("ERROR");
        ZMSImpl.metric.increment(caller.toLowerCase() + "_error_" + errCode);
        ZMSImpl.metric.increment("error_" + errCode);
        
        return true;
    }

    public static void threadSleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException ignored) {
        }
    }

    public static boolean parseBoolean(final String value, boolean defaultValue) {
        boolean boolVal = defaultValue;
        if (value != null && !value.isEmpty()) {
            boolVal = Boolean.parseBoolean(value.trim());
        }
        return boolVal;
    }

    public static Principal.Type principalType(final String memberName, final String userDomainPrefix,
            final List<String> addlUserCheckDomainPrefixList, final String headlessUserDomainPrefix) {

        if (ZMSUtils.isUserDomainPrincipal(memberName, userDomainPrefix, addlUserCheckDomainPrefixList)) {
            return Principal.Type.USER;
        } else if (ZMSUtils.isHeadlessUserDomainPrincipal(memberName, headlessUserDomainPrefix)) {
            return Principal.Type.USER_HEADLESS;
        } else if (memberName.contains(AuthorityConsts.GROUP_SEP)) {
            return Principal.Type.GROUP;
        } else {
            return Principal.Type.SERVICE;
        }
    }

    public static boolean isUserDomainPrincipal(final String memberName, final String userDomainPrefix,
            final List<String> addlUserCheckDomainPrefixList) {

        if (memberName.startsWith(userDomainPrefix) && StringUtils.countMatches(memberName, '.') == 1) {
            return true;
        }

        if (addlUserCheckDomainPrefixList != null) {
            for (String prefix : addlUserCheckDomainPrefixList) {
                if (memberName.startsWith(prefix) && StringUtils.countMatches(memberName, '.') == 1) {
                    return true;
                }
            }
        }

        return false;
    }
    
    public static boolean isHeadlessUserDomainPrincipal(final String memberName, final String headlessUserDomainPrefix) {
        return memberName.startsWith(headlessUserDomainPrefix) && StringUtils.countMatches(memberName, '.') == 1;
    }

    public static String extractObjectName(String domainName, String fullName, String objType) {

        // generate prefix to compare with

        final String prefix = domainName + objType;
        if (!fullName.startsWith(prefix)) {
            return null;
        }
        return fullName.substring(prefix.length());
    }

    public static String extractRoleName(String domainName, String fullRoleName) {
        return extractObjectName(domainName, fullRoleName, AuthorityConsts.ROLE_SEP);
    }

    public static String extractGroupName(String domainName, String fullGroupName) {
        return extractObjectName(domainName, fullGroupName, AuthorityConsts.GROUP_SEP);
    }

    public static String extractPolicyName(String domainName, String fullPolicyName) {
        return extractObjectName(domainName, fullPolicyName, AuthorityConsts.POLICY_SEP);
    }

    public static String extractEntityName(String domainName, String fullEntityName) {
        return extractObjectName(domainName, fullEntityName, AuthorityConsts.ENTITY_SEP);
    }

    public static String extractServiceName(String domainName, String fullServiceName) {
        return extractObjectName(domainName, fullServiceName, ".");
    }

    public static boolean isUserAuthorityFilterValid(Authority userAuthority, final String filterList, final String memberName) {

        // in most cases we're going to have a single filter configured,
        // so we'll optimize for that case and not create an array

        if (filterList.indexOf(',') == -1) {
            if (!userAuthority.isAttributeSet(memberName, filterList)) {
                LOG.error("Principal {} does not satisfy user authority {} filter", memberName, filterList);
                return false;
            }
        } else {
            final String[] filterItems = filterList.split(",");
            for (String filterItem : filterItems) {
                if (!userAuthority.isAttributeSet(memberName, filterItem)) {
                    LOG.error("Principal {} does not satisfy user authority {} filter", memberName, filterItem);
                    return false;
                }
            }
        }
        return true;
    }

    public static String combineUserAuthorityFilters(final String roleUserAuthorityFilter, final String domainUserAuthorityFilter) {

        String authorityFilter = null;
        if (roleUserAuthorityFilter != null && !roleUserAuthorityFilter.isEmpty()) {
            authorityFilter = roleUserAuthorityFilter;
        }

        if (domainUserAuthorityFilter != null && !domainUserAuthorityFilter.isEmpty()) {
            if (authorityFilter == null) {
                authorityFilter = domainUserAuthorityFilter;
            } else {
                // no need for extra work to remove duplicates
                authorityFilter += "," + domainUserAuthorityFilter;
            }
        }

        return authorityFilter;
    }

    public static String lowerDomainInResource(String resource) {
        if (resource == null) {
            return null;
        }

        int delimiterIndex = resource.indexOf(":");
        if (delimiterIndex == -1) {
            return resource;
        }

        String lowerCasedDomain = resource.substring(0, delimiterIndex).toLowerCase();
        return lowerCasedDomain + resource.substring(delimiterIndex);
    }

    public static boolean userAuthorityAttrMissing(final String origAttrList, final String checkAttrList) {

        // if the original attr list is empty then there is nothing to check

        if (StringUtil.isEmpty(origAttrList)) {
            return false;
        }

        // if the check attribute list is empty then it's a failure
        // since we know that our original attr is not empty

        if (StringUtil.isEmpty(checkAttrList)) {
            return true;
        }

        // we'll just compare the values as is in case there
        // is a match and no further processing is necessary

        if (origAttrList.equals(checkAttrList)) {
            return false;
        }

        // we need to tokenize our attr values and compare. we want to
        // make sure all original attribute values are present in the checklist

        Set<String> checkValues = new HashSet<>(Arrays.asList(checkAttrList.split(",")));
        for (String attr : origAttrList.split(",")) {
            if (!checkValues.contains(attr)) {
                return true;
            }
        }

        return false;
    }

    public static Principal createPrincipalForName(String principalName, String userDomain, String userDomainAlias) {

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

    public static boolean metaValueChanged(Object domainValue, Object metaValue) {
        return metaValue != null && !metaValue.equals(domainValue);
    }

    public static long configuredDueDateMillis(Integer domainDueDateDays, Integer roleDueDateDays) {

        // the role expiry days settings overrides the domain one if one configured

        int expiryDays = 0;
        if (roleDueDateDays != null && roleDueDateDays > 0) {
            expiryDays = roleDueDateDays;
        } else if (domainDueDateDays != null && domainDueDateDays > 0) {
            expiryDays = domainDueDateDays;
        }
        return expiryDays == 0 ? 0 : System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(expiryDays, TimeUnit.DAYS);
    }

    public static String providerServiceDomain(String provider) {
        int n = provider.lastIndexOf('.');
        if (n <= 0 || n == provider.length() - 1) {
            return null;
        }
        return provider.substring(0, n);
    }

    public static String providerServiceName(String provider) {
        int n = provider.lastIndexOf('.');
        if (n <= 0 || n == provider.length() - 1) {
            return null;
        }
        return provider.substring(n + 1);
    }

    public static <T> Response returnPutResponse(Boolean flag, T returnObj) {
        return (flag == Boolean.TRUE)
                ? Response.status(ResourceException.OK).entity(returnObj).build()
                : Response.status(ResourceException.NO_CONTENT).build();
    }

    public static boolean isCollectionEmpty(Collection<?> collection) {
        return collection == null || collection.isEmpty();
    }

    public static <T> List<T> emptyIfNull(final List<T> c) {
        return c == null ? Collections.emptyList() : c;
    }

    public static void validateObject(Validator validator, Object val, String type, String caller) {
        if (val == null) {
            throw requestError("Missing or malformed " + type, caller);
        }

        try {
            Validator.Result result = validator.validate(val, type);
            if (!result.valid) {
                throw requestError("Invalid " + type + " error: " + result.error, caller);
            }
        } catch (Exception ex) {
            LOG.error("Object validation exception", ex);
            throw requestError("Invalid " + type + " error: " + ex.getMessage(), caller);
        }
    }

    public static void validatePolicyAssertion(Validator validator, Assertion assertion,
            boolean validateRoleName, final String caller) {

        // extract the domain name from the resource

        final String resource = assertion.getResource();
        int idx = resource.indexOf(':');
        if (idx == -1) {
            throw ZMSUtils.requestError("Missing domain name from assertion resource: "
                    + resource, caller);
        }

        // we need to validate our domain name with special
        // case of * that is allowed to match any domain

        final String domainName = resource.substring(0, idx);
        if (!domainName.equals("*")) {
            validateObject(validator, domainName, ZMSConsts.TYPE_DOMAIN_NAME, caller);
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

        // validate role name to be a compound type if requested

        if (validateRoleName) {
            validateObject(validator, assertion.getRole(), ZMSConsts.TYPE_RESOURCE_NAME, caller);
        }
    }

}
