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
package com.yahoo.athenz.zms.utils;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.common.server.util.StringUtils;
import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.AssertionEffect;
import com.yahoo.athenz.zms.Policy;
import com.yahoo.athenz.zms.ResourceError;
import com.yahoo.athenz.zms.ResourceException;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
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
        assertions.add(assertion);
    }
    
    public static Role makeAdminRole(String domainName, List<String> adminUsers) {
        List<RoleMember> roleMembers = new ArrayList<>();
        for (String admin: adminUsers) {
            RoleMember roleMember = new RoleMember();
            roleMember.setMemberName(admin);
            roleMembers.add(roleMember);
        }
        Role role = new Role()
                .setName(roleResourceName(domainName, ZMSConsts.ADMIN_ROLE_NAME))
                .setRoleMembers(roleMembers);
        return role;
    }
    
    public static Policy makeAdminPolicy(String domainName, Role adminsRole) {
        
        Policy policy = new Policy()
                .setName(policyResourceName(domainName, ZMSConsts.ADMIN_POLICY_NAME));
        
        addAssertion(policy, domainName + ":*", "*", adminsRole.getName(), AssertionEffect.ALLOW);
        return policy;
    }
    
    static String generateResourceName(String domainName, String resName, String resType) {
        StringBuilder name = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT).append(domainName);
        if (!resType.isEmpty()) {
            name.append(':');
            name.append(resType);
        }
        name.append('.');
        name.append(resName);
        return name.toString();
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
    
    public static String getTenantResourceGroupRolePrefix(String provSvcName, String tenantDomain, String resourceGroup) {
        
        StringBuilder rolePrefix = new StringBuilder(256);
        rolePrefix.append(provSvcName).append(".tenant.").append(tenantDomain).append(".");
        if (resourceGroup != null) {
            rolePrefix.append("res_group.").append(resourceGroup).append(".");
        }
        return rolePrefix.toString();
    }
    
    public static String getProviderResourceGroupRolePrefix(String provSvcDomain, String provSvcName, String resourceGroup) {
        
        StringBuilder rolePrefix = new StringBuilder(256);
        rolePrefix.append(provSvcDomain).append(".").append(provSvcName).append(".");
        if (resourceGroup != null) {
            rolePrefix.append("res_group.").append(resourceGroup).append(".");
        }
        return rolePrefix.toString();
    }
    
    public static String getTrustedResourceGroupRolePrefix(String provSvcDomain, String provSvcName,
            String tenantDomain, String resourceGroup) {
        
        StringBuilder trustedRole = new StringBuilder(256);
        trustedRole.append(provSvcDomain).append(":role.").append(provSvcName)
                .append(".tenant.").append(tenantDomain).append(".");
        if (resourceGroup != null) {
            trustedRole.append("res_group.").append(resourceGroup).append(".");
        }
        return trustedRole.toString();
    }
    
    public static boolean assumeRoleResourceMatch(String roleName, Assertion assertion) {
        
        if (!ZMSConsts.ACTION_ASSUME_ROLE.equalsIgnoreCase(assertion.getAction())) {
            return false;
        }
        
        String rezPattern = StringUtils.patternFromGlob(assertion.getResource());
        if (!roleName.matches(rezPattern)) {
            return false;
        }
        
        return true;
    }
    
    public static final void validateRoleMembers(final Role role, final String caller,
            final String domainName) {
        
        if ((role.getMembers() != null && !role.getMembers().isEmpty()) 
                && (role.getRoleMembers() != null && !role.getRoleMembers().isEmpty())) {
            throw ZMSUtils.requestError("validateRoleMembers: Role cannot have both members and roleMembers set", caller);
        }
        
        // if this is a delegated role then validate that it's not
        // delegated back to itself and there are no members since
        // those 2 fields are mutually exclusive
        
        if (role.getTrust() != null && !role.getTrust().isEmpty()) {
            
            if (role.getRoleMembers() != null && !role.getRoleMembers().isEmpty()) {
                throw ZMSUtils.requestError("validateRoleMembers: Role cannot have both roleMembers and delegated domain set", caller);
            }
            
            if (role.getMembers() != null && !role.getMembers().isEmpty()) {
                throw ZMSUtils.requestError("validateRoleMembers: Role cannot have both members and delegated domain set", caller);
            }
            
            if (domainName.equals(role.getTrust())) {
                throw ZMSUtils.requestError("validateRoleMembers: Role cannot be delegated to itself", caller);
            }
        }
    }
    
    public static final void removeMembers(List<RoleMember> orginalRoleMembers,
            List<RoleMember> removeRoleMembers) {
        for (int i = 0; i < removeRoleMembers.size(); i ++) {
            String removeName = removeRoleMembers.get(i).getMemberName();
            for (int j = 0; j < orginalRoleMembers.size(); j ++) {
                if (removeName.equalsIgnoreCase(orginalRoleMembers.get(j).getMemberName())) {
                    orginalRoleMembers.remove(j);
                }
            }
        }
    }
    
    public static final List<String> convertRoleMembersToMembers(List<RoleMember> members) {
        List<String> memberList = new ArrayList<String>();
        if (members == null) {
            return memberList;
        }
        for (RoleMember member: members) {
            memberList.add(member.getMemberName());
        }
        return memberList;
    }
    
    public static final List<RoleMember> convertMembersToRoleMembers(List<String> members) {
        List<RoleMember> roleMemberList = new ArrayList<RoleMember>();
        if (members == null) {
            return roleMemberList;
        }
        for (String member: members) {
            roleMemberList.add(new RoleMember().setMemberName(member));
        }
        return roleMemberList;
    }
    
    public static RuntimeException error(int code, String msg, String caller) {
        
        if (LOG.isDebugEnabled()) {
            LOG.debug(msg);
        }
        
        // If caller is null, we do not want to emit any error metrics.
        // Otherwise, the caller name should be from the method that threw
        // the specific runtime exception.
        
        if (caller != null && !emitMonmetricError(code, caller)) {
            LOG.error("Unable to emit error metric for caller: " + caller +
                    " with message: " + msg);
        }
        return new ResourceException(code, new ResourceError().code(code).message(msg));
    }

    public static RuntimeException requestError(String msg, String caller) {
        return error(ResourceException.BAD_REQUEST, msg, caller);
    }

    public static RuntimeException redirectError(String msg, String caller) {
        return error(ResourceException.FOUND, msg, caller);
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
    
    public static boolean emitMonmetricError(int errorCode, String caller) {
        if (errorCode < 1) {
            return false;
        }
        if (caller == null || caller.length() == 0) {
            return false;
        }
        caller = caller.trim();
        String alphanum = "^[a-zA-Z0-9]*$";
        if (!caller.matches(alphanum)) {
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
}
