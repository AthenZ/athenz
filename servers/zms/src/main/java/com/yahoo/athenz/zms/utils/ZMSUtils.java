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
package com.yahoo.athenz.zms.utils;

import java.util.ArrayList;
import java.util.List;

import com.yahoo.athenz.auth.Authority;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.util.ServletRequestUtil;
import com.yahoo.athenz.common.server.util.StringUtils;
import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.AssertionEffect;
import com.yahoo.athenz.zms.Policy;
import com.yahoo.athenz.zms.ResourceContext;
import com.yahoo.athenz.zms.ResourceError;
import com.yahoo.athenz.zms.ResourceException;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zms.RsrcCtxWrapper;
import com.yahoo.athenz.zms.ZMSConsts;
import com.yahoo.athenz.zms.ZMSImpl;

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
                .setName(roleResourceName(domainName, ZMSConsts.ADMIN_ROLE_NAME))
                .setRoleMembers(roleMembers);
    }
    
    public static Policy makeAdminPolicy(String domainName, Role adminsRole) {
        
        Policy policy = new Policy()
                .setName(policyResourceName(domainName, ZMSConsts.ADMIN_POLICY_NAME));
        
        addAssertion(policy, domainName + ":*", "*", adminsRole.getName(), AssertionEffect.ALLOW);
        return policy;
    }
    
    private static String generateResourceName(String domainName, String resName, String resType) {
        if (resType.isEmpty()) {
            return domainName + "." + resName;
        } else {
            return domainName + ":" + resType + "." + resName;
        }
    }
    
    public static String roleResourceName(String domainName, String roleName) {
        return generateResourceName(domainName, roleName, ZMSConsts.OBJECT_ROLE);
    }

    public static String policyResourceName(String domainName, String policyName) {
        return generateResourceName(domainName, policyName, ZMSConsts.OBJECT_POLICY);
    }
    
    public static String serviceResourceName(String domainName, String serviceName) {
        return generateResourceName(domainName, serviceName, "");
    }

    public static String entityResourceName(String domainName, String serviceName) {
        return generateResourceName(domainName, serviceName, "");
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
            rolePrefix.append("res_group.").append(resourceGroup).append('.');
        }
        return rolePrefix.toString();
    }
    
    public static String getProviderResourceGroupRolePrefix(String provSvcDomain, String provSvcName, String resourceGroup) {
        
        StringBuilder rolePrefix = new StringBuilder(256);
        rolePrefix.append(provSvcDomain).append('.').append(provSvcName).append('.');
        if (resourceGroup != null) {
            rolePrefix.append("res_group.").append(resourceGroup).append('.');
        }
        return rolePrefix.toString();
    }
    
    public static String getTrustedResourceGroupRolePrefix(String provSvcDomain, String provSvcName,
            String tenantDomain, String resourceGroup) {
        
        StringBuilder trustedRole = new StringBuilder(256);
        trustedRole.append(provSvcDomain).append(AuthorityConsts.ROLE_SEP).append(provSvcName)
                .append(".tenant.").append(tenantDomain).append('.');
        if (resourceGroup != null) {
            trustedRole.append("res_group.").append(resourceGroup).append('.');
        }
        return trustedRole.toString();
    }
    
    public static boolean assumeRoleResourceMatch(String roleName, Assertion assertion) {
        
        if (!ZMSConsts.ACTION_ASSUME_ROLE.equalsIgnoreCase(assertion.getAction())) {
            return false;
        }
        
        String rezPattern = StringUtils.patternFromGlob(assertion.getResource());
        return roleName.matches(rezPattern);
    }
    
    public static void removeMembers(List<RoleMember> originalRoleMembers, List<RoleMember> removeRoleMembers) {
        if (removeRoleMembers == null || originalRoleMembers == null) {
            return;
        }
        for (RoleMember removeMember : removeRoleMembers) {
            String removeName = removeMember.getMemberName();
            for (int j = 0; j < originalRoleMembers.size(); j++) {
                if (removeName.equalsIgnoreCase(originalRoleMembers.get(j).getMemberName())) {
                    originalRoleMembers.remove(j);
                    break;
                }
            }
        }
    }
    
    public static List<String> convertRoleMembersToMembers(List<RoleMember> members) {
        List<String> memberList = new ArrayList<>();
        if (members == null) {
            return memberList;
        }
        for (RoleMember member: members) {
            // only add active members to membername list. Active flag is optional for default value
            if (member.getActive() != Boolean.FALSE) {
                memberList.add(member.getMemberName());
            }
        }
        return memberList;
    }
    
    public static List<RoleMember> convertMembersToRoleMembers(List<String> members) {
        List<RoleMember> roleMemberList = new ArrayList<>();
        if (members == null) {
            return roleMemberList;
        }
        for (String member: members) {
            roleMemberList.add(new RoleMember().setMemberName(member));
        }
        return roleMemberList;
    }
    
    /**
     * Setup a new AuditLogMsgBuilder object with common values.
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
                    if (roles != null && roles.size() > 0) {
                        sb.append(",who-roles=").append(roles.toString());
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

    public static boolean isUserDomainPrincipal(final String memberName, final String userDomainPrefix,
            final List<String> addlUserCheckDomainPrefixList) {

        if (memberName.startsWith(userDomainPrefix)) {
            return true;
        }

        if (addlUserCheckDomainPrefixList != null) {
            for (String prefix : addlUserCheckDomainPrefixList) {
                if (memberName.startsWith(prefix)) {
                    return true;
                }
            }
        }

        return false;
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

    public static String extractPolicyName(String domainName, String fullPolicyName) {
        return extractObjectName(domainName, fullPolicyName, ":policy.");
    }

    public static String extractServiceName(String domainName, String fullServiceName) {
        return extractObjectName(domainName, fullServiceName, ".");
    }

    public static boolean isUserAuthorityFilterValid(Authority userAuthority, final String filterList, final String memberName) {

        // in most cases we're going to have a single filter configured
        // so we'll optimize for that case and not create an array

        if (filterList.indexOf(',') == -1) {
            if (!userAuthority.isAttributeSet(memberName, filterList)) {
                LOG.error("Principal {} does not satisfy user authority {} filter", memberName, filterList);
                return false;
            }
            return true;
        } else {
            final String[] filterItems = filterList.split(",");
            for (String filterItem : filterItems) {
                if (!userAuthority.isAttributeSet(memberName, filterItem)) {
                    LOG.error("Principal {} does not satisfy user authority {} filter", memberName, filterItem);
                    return false;
                }
            }
            return true;
        }
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
}
