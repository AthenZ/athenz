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

package com.yahoo.athenz.common.server.util;

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import com.yahoo.athenz.zms.*;
import org.eclipse.jetty.util.StringUtil;

import static com.yahoo.athenz.common.server.util.config.ConfigManagerSingleton.CONFIG_MANAGER;

public class ResourceOwnership {

    public static final String ZMS_PROP_RESOURCE_OWNER_IGNORE_VALUE  = "athenz.zms.resource_owner_ignore_value";
    public static final String ZMS_PROP_ENFORCE_RESOURCE_OWNERSHIP   = "athenz.zms.enforce_resource_ownership";
    public static final String ZMS_PROP_RESOURCE_OWNER_FORCE_SUFFIX  = "athenz.zms.resource_owner_force_suffix";
    
    public static final String RESOURCE_OWNER_IGNORE =
            System.getProperty(ZMS_PROP_RESOURCE_OWNER_IGNORE_VALUE, "ignore");

    public static final String RESOURCE_OWNER_FORCE_SUFFIX =
            System.getProperty(ZMS_PROP_RESOURCE_OWNER_FORCE_SUFFIX, ":force");

    protected static DynamicConfigBoolean ENFORCE_RESOURCE_OWNERSHIP = new DynamicConfigBoolean(CONFIG_MANAGER,
            ZMS_PROP_ENFORCE_RESOURCE_OWNERSHIP, Boolean.TRUE);

    static void addResourceOwnerComp(final String compName, final String compValue, StringBuilder resourceOwner) {
        if (StringUtil.isEmpty(compValue)) {
            return;
        }
        if (resourceOwner.length() > 0) {
            resourceOwner.append(",");
        }
        resourceOwner.append(compName).append(":").append(compValue);
    }

    public static String generateResourceOwnerString(ResourceDomainOwnership resourceOwner) {
        StringBuilder resourceOwnerString = new StringBuilder();
        addResourceOwnerComp("object", resourceOwner.getObjectOwner(), resourceOwnerString);
        addResourceOwnerComp("meta", resourceOwner.getMetaOwner(), resourceOwnerString);
        return resourceOwnerString.toString();
    }

    public static String generateResourceOwnerString(ResourceServiceIdentityOwnership resourceOwner) {
        StringBuilder resourceOwnerString = new StringBuilder();
        addResourceOwnerComp("object", resourceOwner.getObjectOwner(), resourceOwnerString);
        addResourceOwnerComp("publickeys", resourceOwner.getPublicKeysOwner(), resourceOwnerString);
        addResourceOwnerComp("hosts", resourceOwner.getHostsOwner(), resourceOwnerString);
        return resourceOwnerString.toString();
    }

    public static String generateResourceOwnerString(ResourcePolicyOwnership resourceOwner) {
        StringBuilder resourceOwnerString = new StringBuilder();
        addResourceOwnerComp("object", resourceOwner.getObjectOwner(), resourceOwnerString);
        addResourceOwnerComp("assertions", resourceOwner.getAssertionsOwner(), resourceOwnerString);
        return resourceOwnerString.toString();
    }

    public static String generateResourceOwnerString(ResourceGroupOwnership resourceOwner) {
        StringBuilder resourceOwnerString = new StringBuilder();
        addResourceOwnerComp("object", resourceOwner.getObjectOwner(), resourceOwnerString);
        addResourceOwnerComp("meta", resourceOwner.getMetaOwner(), resourceOwnerString);
        addResourceOwnerComp("members", resourceOwner.getMembersOwner(), resourceOwnerString);
        return resourceOwnerString.toString();
    }

    public static String generateResourceOwnerString(ResourceRoleOwnership resourceOwner) {
        StringBuilder resourceOwnerString = new StringBuilder();
        addResourceOwnerComp("object", resourceOwner.getObjectOwner(), resourceOwnerString);
        addResourceOwnerComp("meta", resourceOwner.getMetaOwner(), resourceOwnerString);
        addResourceOwnerComp("members", resourceOwner.getMembersOwner(), resourceOwnerString);
        return resourceOwnerString.toString();
    }

    public static ResourceRoleOwnership getResourceRoleOwnership(final String resourceOwner) {
        if (StringUtil.isEmpty(resourceOwner)) {
            return null;
        }
        ResourceRoleOwnership resourceOwnership = new ResourceRoleOwnership();
        for (String item : resourceOwner.split(",")) {
            if (item.startsWith("object:")) {
                resourceOwnership.setObjectOwner(item.substring(7));
            } else if (item.startsWith("meta:")) {
                resourceOwnership.setMetaOwner(item.substring(5));
            } else if (item.startsWith("members:")) {
                resourceOwnership.setMembersOwner(item.substring(8));
            }
        }
        return resourceOwnership;
    }

    public static ResourceGroupOwnership getResourceGroupOwnership(final String resourceOwner) {
        if (StringUtil.isEmpty(resourceOwner)) {
            return null;
        }
        ResourceGroupOwnership resourceOwnership = new ResourceGroupOwnership();
        for (String item : resourceOwner.split(",")) {
            if (item.startsWith("object:")) {
                resourceOwnership.setObjectOwner(item.substring(7));
            } else if (item.startsWith("meta:")) {
                resourceOwnership.setMetaOwner(item.substring(5));
            } else if (item.startsWith("members:")) {
                resourceOwnership.setMembersOwner(item.substring(8));
            }
        }
        return resourceOwnership;
    }

    public static ResourcePolicyOwnership getResourcePolicyOwnership(final String resourceOwner) {
        if (StringUtil.isEmpty(resourceOwner)) {
            return null;
        }
        ResourcePolicyOwnership resourceOwnership = new ResourcePolicyOwnership();
        for (String item : resourceOwner.split(",")) {
            if (item.startsWith("object:")) {
                resourceOwnership.setObjectOwner(item.substring(7));
            } else if (item.startsWith("assertions:")) {
                resourceOwnership.setAssertionsOwner(item.substring(11));
            }
        }
        return resourceOwnership;
    }

    public static ResourceServiceIdentityOwnership getResourceServiceOwnership(final String resourceOwner) {
        if (StringUtil.isEmpty(resourceOwner)) {
            return null;
        }
        ResourceServiceIdentityOwnership resourceOwnership = new ResourceServiceIdentityOwnership();
        for (String item : resourceOwner.split(",")) {
            if (item.startsWith("object:")) {
                resourceOwnership.setObjectOwner(item.substring(7));
            } else if (item.startsWith("publickeys:")) {
                resourceOwnership.setPublicKeysOwner(item.substring(11));
            } else if (item.startsWith("hosts:")) {
                resourceOwnership.setHostsOwner(item.substring(6));
            }
        }
        return resourceOwnership;
    }

    public static ResourceDomainOwnership getResourceDomainOwnership(final String resourceOwner) {
        if (StringUtil.isEmpty(resourceOwner)) {
            return null;
        }
        ResourceDomainOwnership resourceOwnership = new ResourceDomainOwnership();
        for (String item : resourceOwner.split(",")) {
            if (item.startsWith("object:")) {
                resourceOwnership.setObjectOwner(item.substring(7));
            } else if (item.startsWith("meta:")) {
                resourceOwnership.setMetaOwner(item.substring(5));
            }
        }
        return resourceOwnership;
    }

    public static void verifyDomainDeleteResourceOwnership(Domain domain, final String resourceOwner,
            final String caller) throws ServerResourceException {

        // if the object has no owner then we're good for the enforcement check

        ResourceDomainOwnership resourceOwnership = domain.getResourceOwnership();
        if (resourceOwnership == null || resourceOwnership.getObjectOwner() == null) {
            return;
        }

        verifyDeleteResourceOwnership(resourceOwner, resourceOwnership.getObjectOwner(), caller);
    }

    public static ResourceDomainOwnership verifyDomainMetaResourceOwnership(Domain domain, final String resourceOwner,
            final String caller) throws ServerResourceException {

        // first check if we're explicitly asked to ignore the check
        // by either using the ignore value or the feature being disabled

        if (skipEnforceResourceOwnership(resourceOwner)) {
            return null;
        }

        boolean bOwnerSpecified = !StringUtil.isEmpty(resourceOwner);
        String resourceOwnerWithoutForceSuffix = getResourceOwnershipWithoutForceSuffix(resourceOwner, bOwnerSpecified);
        ResourceDomainOwnership requestOwnership = bOwnerSpecified ?
                new ResourceDomainOwnership().setMetaOwner(resourceOwnerWithoutForceSuffix) : null;

        // if the object has no owner then we're good for the enforcement
        // part, but we need to return the request ownership object (in case
        // it was specified) so the resource is updated accordingly

        ResourceDomainOwnership resourceOwnership = domain.getResourceOwnership();
        if (resourceOwnership == null) {
            return requestOwnership;
        }

        final String metaOwner = resourceOwnership.getMetaOwner();
        if (!bOwnerSpecified && StringUtil.isEmpty(metaOwner)) {
            // if both values are not present then no changes are necessary
            return null;
        } else if (!bOwnerSpecified) {
            // if the object has meta owner then we reject the request
            throw Utils.conflictError("Domain has a resource owner: " + metaOwner, caller);
        } else if (StringUtil.isEmpty(metaOwner) || isResourceOwnershipOverrideAllowed(resourceOwner, metaOwner)) {
            // if the object has no meta owner then we need to set it
            requestOwnership.setObjectOwner(resourceOwnership.getObjectOwner());
            return requestOwnership;
        } else if (!resourceOwnerWithoutForceSuffix.equalsIgnoreCase(metaOwner)) {
            throw Utils.conflictError("Invalid resource owner for domain: " + domain.getName()
                    + ", " + metaOwner + " vs. " + resourceOwnerWithoutForceSuffix, caller);
        } else {
            // no changes needed
            return null;
        }
    }

    public static ResourceRoleOwnership verifyRoleResourceOwnership(Role role, boolean roleMembersPresent,
            final String resourceOwner, final String caller) throws ServerResourceException {

        // first check if we're explicitly asked to ignore the check
        // by either using the ignore value or the feature being disabled

        if (skipEnforceResourceOwnership(resourceOwner)) {
            return null;
        }

        boolean bOwnerSpecified = !StringUtil.isEmpty(resourceOwner);
        String resourceOwnerWithoutForceSuffix = getResourceOwnershipWithoutForceSuffix(resourceOwner, bOwnerSpecified);

        ResourceRoleOwnership requestOwnership = bOwnerSpecified ?
                new ResourceRoleOwnership().setObjectOwner(resourceOwnerWithoutForceSuffix).setMetaOwner(resourceOwnerWithoutForceSuffix)
                        .setMembersOwner(resourceOwnerWithoutForceSuffix) : null;

        // if the original object is null then we need to update ownership
        // set accordingly - if the roleMembersPresent is false, we won't set
        // membership ownership since it's not present in the original object

        if (role == null || role.getResourceOwnership() == null) {
            if (!bOwnerSpecified) {
                return null;
            }
            if (!roleMembersPresent) {
                requestOwnership.setMembersOwner(null);
            }
            return requestOwnership;
        }

        // we need to verify all components in the resource ownership

        ResourceRoleOwnership resourceOwnership = role.getResourceOwnership();
        boolean bUpdateRequired = false;
        if (resourceOwnership.getObjectOwner() == null || isResourceOwnershipOverrideAllowed(resourceOwner, resourceOwnership.getObjectOwner())) {
            bUpdateRequired = true;
        } else if (ownershipCheckFailure(bOwnerSpecified, resourceOwnerWithoutForceSuffix, resourceOwnership.getObjectOwner())) {
            throw Utils.conflictError("Invalid resource owner for role: " + role.getName()
                    + ", " +  resourceOwnership.getObjectOwner() + " vs. " + resourceOwnerWithoutForceSuffix, caller);
        }

        if (resourceOwnership.getMembersOwner() == null || isResourceOwnershipOverrideAllowed(resourceOwner, resourceOwnership.getMembersOwner())) {
            bUpdateRequired = true;
        } else if (ownershipCheckFailure(bOwnerSpecified, resourceOwnerWithoutForceSuffix, resourceOwnership.getMembersOwner())) {
            throw Utils.conflictError("Invalid members owner for role: " + role.getName()
                    + ", " +  resourceOwnership.getMembersOwner() + " vs. " + resourceOwnerWithoutForceSuffix, caller);
        }

        if (resourceOwnership.getMetaOwner() == null || isResourceOwnershipOverrideAllowed(resourceOwner, resourceOwnership.getMetaOwner())) {
            bUpdateRequired = true;
        } else if (ownershipCheckFailure(bOwnerSpecified, resourceOwnerWithoutForceSuffix, resourceOwnership.getMetaOwner())) {
            throw Utils.conflictError("Invalid meta owner for role: " + role.getName()
                    + ", " +  resourceOwnership.getMetaOwner() + " vs. " + resourceOwnerWithoutForceSuffix, caller);
        }

        return bUpdateRequired ? requestOwnership : null;
    }

    public static void verifyRoleDeleteResourceOwnership(Role role, final String resourceOwner,
            final String caller) throws ServerResourceException {

        // if the object has no owner then we're good for the enforcement check

        ResourceRoleOwnership resourceOwnership = role.getResourceOwnership();
        if (resourceOwnership == null || resourceOwnership.getObjectOwner() == null) {
            return;
        }

        verifyDeleteResourceOwnership(resourceOwner, resourceOwnership.getObjectOwner(), caller);
    }

    public static void verifyRoleMembersDeleteResourceOwnership(Role role, final String resourceOwner,
            final String caller) throws ServerResourceException {

        // if the role member has no owner then we're good for the enforcement check
        ResourceRoleOwnership resourceOwnership = role.getResourceOwnership();
        if (resourceOwnership == null || resourceOwnership.getMembersOwner() == null) {
            return;
        }

        verifyDeleteResourceOwnership(resourceOwner, resourceOwnership.getMembersOwner(), caller);
    }

    public static ResourceRoleOwnership verifyRoleMetaResourceOwnership(Role role, final String resourceOwner,
            final String caller) throws ServerResourceException {

        // first check if we're explicitly asked to ignore the check
        // by either using the ignore value or the feature being disabled

        if (skipEnforceResourceOwnership(resourceOwner)) {
            return null;
        }

        boolean bOwnerSpecified = !StringUtil.isEmpty(resourceOwner);
        String resourceOwnerWithoutForceSuffix = getResourceOwnershipWithoutForceSuffix(resourceOwner, bOwnerSpecified);
        ResourceRoleOwnership requestOwnership = bOwnerSpecified ?
                new ResourceRoleOwnership().setMetaOwner(resourceOwnerWithoutForceSuffix) : null;

        // if the object has no owner then we're good for the enforcement
        // part, but we need to return the request ownership object (in case
        // it was specified) so the resource is updated accordingly

        ResourceRoleOwnership resourceOwnership = role.getResourceOwnership();
        if (resourceOwnership == null) {
            return requestOwnership;
        }

        final String metaOwner = resourceOwnership.getMetaOwner();
        if (!bOwnerSpecified && StringUtil.isEmpty(metaOwner)) {
            // if both values are not present then no changes are necessary
            return null;
        } else if (!bOwnerSpecified) {
            // if the object has meta owner then we reject the request
            throw Utils.conflictError("Role has a resource owner: " + metaOwner, caller);
        } else if (StringUtil.isEmpty(metaOwner) || isResourceOwnershipOverrideAllowed(resourceOwner, metaOwner)) {
            // if the object has no meta owner then we need to set it
            requestOwnership.setObjectOwner(resourceOwnership.getObjectOwner());
            requestOwnership.setMembersOwner(resourceOwnership.getMembersOwner());
            return requestOwnership;
        } else if (!resourceOwnerWithoutForceSuffix.equalsIgnoreCase(metaOwner)) {
            throw Utils.conflictError("Invalid resource meta owner for role: " + role.getName()
                    + ", " + metaOwner + " vs. " + resourceOwnerWithoutForceSuffix, caller);
        } else {
            // no changes needed
            return null;
        }
    }

    public static ResourceRoleOwnership verifyRoleMembersResourceOwnership(Role role, final String resourceOwner,
            final String caller) throws ServerResourceException {

        // first check if we're explicitly asked to ignore the check
        // by either using the ignore value or the feature being disabled

        if (skipEnforceResourceOwnership(resourceOwner)) {
            return null;
        }

        boolean bOwnerSpecified = !StringUtil.isEmpty(resourceOwner);
        String resourceOwnerWithoutForceSuffix = getResourceOwnershipWithoutForceSuffix(resourceOwner, bOwnerSpecified);
        ResourceRoleOwnership requestOwnership = bOwnerSpecified ?
                new ResourceRoleOwnership().setMembersOwner(resourceOwnerWithoutForceSuffix) : null;

        // if the object has no owner then we're good for the enforcement
        // part, but we need to return the request ownership object (in case
        // it was specified) so the resource is updated accordingly

        ResourceRoleOwnership resourceOwnership = role.getResourceOwnership();
        if (resourceOwnership == null) {
            return requestOwnership;
        }

        final String membersOwner = resourceOwnership.getMembersOwner();
        if (!bOwnerSpecified && StringUtil.isEmpty(membersOwner)) {
            // if both values are not present then no changes are necessary
            return null;
        } else if (!bOwnerSpecified) {
            // if the object has members owner then we reject the request
            throw Utils.conflictError("Role has a resource owner: " + membersOwner, caller);
        } else if (StringUtil.isEmpty(membersOwner) || isResourceOwnershipOverrideAllowed(resourceOwner, membersOwner)) {
            // if the object has no members owner / request is asking for a force override then we need to set it
            requestOwnership.setObjectOwner(resourceOwnership.getObjectOwner());
            requestOwnership.setMetaOwner(resourceOwnership.getMetaOwner());
            return requestOwnership;
        } else if (!resourceOwnerWithoutForceSuffix.equalsIgnoreCase(membersOwner)) {
            throw Utils.conflictError("Invalid resource member owner for role: " + role.getName()
                    + ", " + membersOwner + " vs. " + resourceOwnerWithoutForceSuffix, caller);
        } else {
            // no changes needed
            return null;
        }
    }

    public static ResourceGroupOwnership verifyGroupResourceOwnership(Group group, boolean groupMembersPresent,
            final String resourceOwner, final String caller) throws ServerResourceException {

        // first check if we're explicitly asked to ignore the check
        // by either using the ignore value or the feature being disabled

        if (skipEnforceResourceOwnership(resourceOwner)) {
            return null;
        }

        boolean bOwnerSpecified = !StringUtil.isEmpty(resourceOwner);
        String resourceOwnerWithoutForceSuffix = getResourceOwnershipWithoutForceSuffix(resourceOwner, bOwnerSpecified);
        ResourceGroupOwnership requestOwnership = bOwnerSpecified ?
                new ResourceGroupOwnership().setObjectOwner(resourceOwnerWithoutForceSuffix).setMetaOwner(resourceOwnerWithoutForceSuffix)
                        .setMembersOwner(resourceOwnerWithoutForceSuffix) : null;

        // if the original object is null then we need to update ownership
        // set accordingly - if the groupMembersPresent is false, we won't set
        // membership ownership since it's not present in the original object

        if (group == null || group.getResourceOwnership() == null) {
            if (!bOwnerSpecified) {
                return null;
            }
            if (!groupMembersPresent) {
                requestOwnership.setMembersOwner(null);
            }
            return requestOwnership;
        }

        // we need to verify all components in the resource ownership

        ResourceGroupOwnership resourceOwnership = group.getResourceOwnership();
        boolean bUpdateRequired = false;
        if (resourceOwnership.getObjectOwner() == null || isResourceOwnershipOverrideAllowed(resourceOwner, resourceOwnership.getObjectOwner())) {
            bUpdateRequired = true;
        } else if (ownershipCheckFailure(bOwnerSpecified, resourceOwnerWithoutForceSuffix, resourceOwnership.getObjectOwner())) {
            throw Utils.conflictError("Invalid resource owner for group: " + group.getName()
                    + ", " +  resourceOwnership.getObjectOwner() + " vs. " + resourceOwner, caller);
        }

        if (resourceOwnership.getMembersOwner() == null || isResourceOwnershipOverrideAllowed(resourceOwner, resourceOwnership.getMembersOwner())) {
            bUpdateRequired = true;
        } else if (ownershipCheckFailure(bOwnerSpecified, resourceOwnerWithoutForceSuffix, resourceOwnership.getMembersOwner())) {
            throw Utils.conflictError("Invalid members owner for group: " + group.getName()
                    + ", " +  resourceOwnership.getMembersOwner() + " vs. " + resourceOwner, caller);
        }

        if (resourceOwnership.getMetaOwner() == null || isResourceOwnershipOverrideAllowed(resourceOwner, resourceOwnership.getMetaOwner())) {
            bUpdateRequired = true;
        } else if (ownershipCheckFailure(bOwnerSpecified, resourceOwnerWithoutForceSuffix, resourceOwnership.getMetaOwner())) {
            throw Utils.conflictError("Invalid meta owner for group: " + group.getName()
                    + ", " +  resourceOwnership.getMetaOwner() + " vs. " + resourceOwnerWithoutForceSuffix, caller);
        }

        return bUpdateRequired ? requestOwnership : null;
    }

    public static void verifyGroupDeleteResourceOwnership(Group group, final String resourceOwner,
            final String caller) throws ServerResourceException {

        // if the object has no owner then we're good for the enforcement check

        ResourceGroupOwnership resourceOwnership = group.getResourceOwnership();
        if (resourceOwnership == null || resourceOwnership.getObjectOwner() == null) {
            return;
        }

        verifyDeleteResourceOwnership(resourceOwner, resourceOwnership.getObjectOwner(), caller);
    }

    public static ResourceGroupOwnership verifyGroupMetaResourceOwnership(Group group, final String resourceOwner,
            final String caller) throws ServerResourceException {

        // first check if we're explicitly asked to ignore the check
        // by either using the ignore value or the feature being disabled

        if (skipEnforceResourceOwnership(resourceOwner)) {
            return null;
        }

        boolean bOwnerSpecified = !StringUtil.isEmpty(resourceOwner);
        String resourceOwnerWithoutForceSuffix = getResourceOwnershipWithoutForceSuffix(resourceOwner, bOwnerSpecified);
        ResourceGroupOwnership requestOwnership = bOwnerSpecified ?
                new ResourceGroupOwnership().setMetaOwner(resourceOwnerWithoutForceSuffix) : null;

        // if the object has no owner then we're good for the enforcement
        // part, but we need to return the request ownership object (in case
        // it was specified) so the resource is updated accordingly

        ResourceGroupOwnership resourceOwnership = group.getResourceOwnership();
        if (resourceOwnership == null) {
            return requestOwnership;
        }

        // if the current object has no meta owner then we need to update
        // the resource ownership to set it to the caller

        final String metaOwner = resourceOwnership.getMetaOwner();
        if (!bOwnerSpecified && StringUtil.isEmpty(metaOwner)) {
            // if both values are not present then no changes are necessary
            return null;
        } else if (!bOwnerSpecified) {
            // if the object has members owner then we reject the request
            throw Utils.conflictError("Group has a resource owner: " + metaOwner, caller);
        } else if (StringUtil.isEmpty(metaOwner) || isResourceOwnershipOverrideAllowed(resourceOwner, metaOwner)) {
            // if the object has no meta owner then we need to set it
            requestOwnership.setObjectOwner(resourceOwnership.getObjectOwner());
            requestOwnership.setMembersOwner(resourceOwnership.getMembersOwner());
            return requestOwnership;
        } else if (!resourceOwnerWithoutForceSuffix.equalsIgnoreCase(metaOwner)) {
            throw Utils.conflictError("Invalid resource meta owner for group: " + group.getName()
                    + ", " + metaOwner + " vs. " + resourceOwnerWithoutForceSuffix, caller);
        } else {
            // no changes needed
            return null;
        }
    }

    public static ResourceGroupOwnership verifyGroupMembersResourceOwnership(Group group, final String resourceOwner,
            final String caller) throws ServerResourceException {

        // first check if we're explicitly asked to ignore the check
        // by either using the ignore value or the feature being disabled

        if (skipEnforceResourceOwnership(resourceOwner)) {
            return null;
        }

        boolean bOwnerSpecified = !StringUtil.isEmpty(resourceOwner);
        String resourceOwnerWithoutForceSuffix = getResourceOwnershipWithoutForceSuffix(resourceOwner, bOwnerSpecified);
        ResourceGroupOwnership requestOwnership = bOwnerSpecified ?
                new ResourceGroupOwnership().setMembersOwner(resourceOwnerWithoutForceSuffix) : null;

        // if the object has no owner then we're good for the enforcement
        // part, but we need to return the request ownership object (in case
        // it was specified) so the resource is updated accordingly

        ResourceGroupOwnership resourceOwnership = group.getResourceOwnership();
        if (resourceOwnership == null) {
            return requestOwnership;
        }

        final String membersOwner = resourceOwnership.getMembersOwner();
        if (!bOwnerSpecified && StringUtil.isEmpty(membersOwner)) {
            // if both values are not present then no changes are necessary
            return null;
        } else if (!bOwnerSpecified) {
            // if the object has members owner then we reject the request
            throw Utils.conflictError("Group has a resource owner: " + membersOwner, caller);
        } else if (StringUtil.isEmpty(membersOwner) || isResourceOwnershipOverrideAllowed(resourceOwner, membersOwner)) {
            // if the object has no members owner then we need to set it
            requestOwnership.setObjectOwner(resourceOwnership.getObjectOwner());
            requestOwnership.setMetaOwner(resourceOwnership.getMetaOwner());
            return requestOwnership;
        } else if (!resourceOwnerWithoutForceSuffix.equalsIgnoreCase(membersOwner)) {
            throw Utils.conflictError("Invalid resource member owner for group: " + group.getName()
                    + ", " + membersOwner + " vs. " + resourceOwnerWithoutForceSuffix, caller);
        } else {
            // no changes needed
            return null;
        }
    }

    public static ResourcePolicyOwnership verifyPolicyResourceOwnership(Policy policy, boolean assertionsPresent,
            final String resourceOwner, final String caller) throws ServerResourceException {

        // first check if we're explicitly asked to ignore the check
        // by either using the ignore value or the feature being disabled

        if (skipEnforceResourceOwnership(resourceOwner)) {
            return null;
        }

        boolean bOwnerSpecified = !StringUtil.isEmpty(resourceOwner);
        String resourceOwnerWithoutForceSuffix = getResourceOwnershipWithoutForceSuffix(resourceOwner, bOwnerSpecified);
        ResourcePolicyOwnership requestOwnership = bOwnerSpecified ?
                new ResourcePolicyOwnership().setObjectOwner(resourceOwnerWithoutForceSuffix).setAssertionsOwner(resourceOwnerWithoutForceSuffix) : null;

        // if the original object is null then we need to update ownership
        // set accordingly - if the assertionsPresent is false, we won't set
        // assertions ownership since it's not present in the original object

        if (policy == null || policy.getResourceOwnership() == null) {
            if (!bOwnerSpecified) {
                return null;
            }
            if (!assertionsPresent) {
                requestOwnership.setAssertionsOwner(null);
            }
            return requestOwnership;
        }

        // we need to verify all components in the resource ownership

        ResourcePolicyOwnership resourceOwnership = policy.getResourceOwnership();
        boolean bUpdateRequired = false;
        if (resourceOwnership.getObjectOwner() == null || isResourceOwnershipOverrideAllowed(resourceOwner, resourceOwnership.getObjectOwner())) {
            bUpdateRequired = true;
        } else if (ownershipCheckFailure(bOwnerSpecified, resourceOwnerWithoutForceSuffix, resourceOwnership.getObjectOwner())) {
            throw Utils.conflictError("Invalid resource owner for policy: " + policy.getName()
                    + ", " +  resourceOwnership.getObjectOwner() + " vs. " + resourceOwnerWithoutForceSuffix, caller);
        }

        if (resourceOwnership.getAssertionsOwner() == null || isResourceOwnershipOverrideAllowed(resourceOwner, resourceOwnership.getAssertionsOwner())) {
            bUpdateRequired = true;
        } else if (ownershipCheckFailure(bOwnerSpecified, resourceOwnerWithoutForceSuffix, resourceOwnership.getAssertionsOwner())) {
            throw Utils.conflictError("Invalid assertions owner for policy: " + policy.getName()
                    + ", " +  resourceOwnership.getAssertionsOwner() + " vs. " + resourceOwnerWithoutForceSuffix, caller);
        }

        return bUpdateRequired ? requestOwnership : null;
    }

    private static String getResourceOwnershipWithoutForceSuffix(String resourceOwner, boolean bOwnerSpecified) {
        String resourceOwnerWithoutForceSuffix = resourceOwner;
        if (bOwnerSpecified && resourceOwner.endsWith(RESOURCE_OWNER_FORCE_SUFFIX)) {
            resourceOwnerWithoutForceSuffix = resourceOwner.substring(0, resourceOwner.length() - RESOURCE_OWNER_FORCE_SUFFIX.length());
        }
        return resourceOwnerWithoutForceSuffix;
    }

    public static void verifyPolicyDeleteResourceOwnership(Policy policy, final String resourceOwner,
            final String caller) throws ServerResourceException {

        // if the object has no owner then we're good for the enforcement check

        ResourcePolicyOwnership resourceOwnership = policy.getResourceOwnership();
        if (resourceOwnership == null || resourceOwnership.getObjectOwner() == null) {
            return;
        }

        verifyDeleteResourceOwnership(resourceOwner, resourceOwnership.getObjectOwner(), caller);
    }

    public static ResourcePolicyOwnership verifyPolicyAssertionsResourceOwnership(Policy policy, final String resourceOwner,
            final String caller) throws ServerResourceException {

        // first check if we're explicitly asked to ignore the check
        // by either using the ignore value or the feature being disabled

        if (skipEnforceResourceOwnership(resourceOwner)) {
            return null;
        }

        boolean bOwnerSpecified = !StringUtil.isEmpty(resourceOwner);
        String resourceOwnerWithoutForceSuffix = getResourceOwnershipWithoutForceSuffix(resourceOwner, bOwnerSpecified);
        ResourcePolicyOwnership requestOwnership = bOwnerSpecified ?
                new ResourcePolicyOwnership().setAssertionsOwner(resourceOwnerWithoutForceSuffix) : null;

        // if the object has no owner then we're good for the enforcement
        // part, but we need to return the request ownership object (in case
        // it was specified) so the resource is updated accordingly

        ResourcePolicyOwnership resourceOwnership = policy.getResourceOwnership();
        if (resourceOwnership == null) {
            return requestOwnership;
        }

        final String assertionsOwner = resourceOwnership.getAssertionsOwner();
        if (!bOwnerSpecified && StringUtil.isEmpty(assertionsOwner)) {
            // if both values are not present then no changes are necessary
            return null;
        } else if (!bOwnerSpecified) {
            // if the object has assertions owner then we reject the request
            throw Utils.conflictError("Policy has a resource owner: " + assertionsOwner, caller);
        } else if (StringUtil.isEmpty(assertionsOwner) || isResourceOwnershipOverrideAllowed(resourceOwner, assertionsOwner)) {
            // if the object has no assertions owner then we need to set it
            requestOwnership.setObjectOwner(resourceOwnership.getObjectOwner());
            return requestOwnership;
        } else if (!resourceOwnerWithoutForceSuffix.equalsIgnoreCase(assertionsOwner)) {
            throw Utils.conflictError("Invalid resource member owner for policy: " + policy.getName()
                    + ", " + assertionsOwner + " vs. " + resourceOwnerWithoutForceSuffix, caller);
        } else {
            // no changes needed
            return null;
        }
    }

    public static ResourceServiceIdentityOwnership verifyServiceResourceOwnership(ServiceIdentity service,
            boolean publicKeysPresent, boolean hostsPresent, final String resourceOwner, final String caller)
            throws ServerResourceException {

        // first check if we're explicitly asked to ignore the check
        // by either using the ignore value or the feature being disabled

        if (skipEnforceResourceOwnership(resourceOwner)) {
            return null;
        }

        boolean bOwnerSpecified = !StringUtil.isEmpty(resourceOwner);
        String resourceOwnerWithoutForceSuffix = getResourceOwnershipWithoutForceSuffix(resourceOwner, bOwnerSpecified);
        ResourceServiceIdentityOwnership requestOwnership = bOwnerSpecified ?
                new ResourceServiceIdentityOwnership().setObjectOwner(resourceOwnerWithoutForceSuffix)
                        .setPublicKeysOwner(resourceOwnerWithoutForceSuffix).setHostsOwner(resourceOwnerWithoutForceSuffix) : null;

        // if the original object is null then we need to update ownership
        // set accordingly - if the publicKeysPresent or  hostsPresent is false,
        // we won't set the corresponding ownership since it's not present in the original object

        if (service == null || service.getResourceOwnership() == null) {
            if (!bOwnerSpecified) {
                return null;
            }
            if (!publicKeysPresent) {
                requestOwnership.setPublicKeysOwner(null);
            }
            if (!hostsPresent) {
                requestOwnership.setHostsOwner(null);
            }
            return requestOwnership;
        }

        // we need to verify all components in the resource ownership

        ResourceServiceIdentityOwnership resourceOwnership = service.getResourceOwnership();
        boolean bUpdateRequired = false;
        if (resourceOwnership.getObjectOwner() == null || isResourceOwnershipOverrideAllowed(resourceOwner, resourceOwnership.getObjectOwner())) {
            bUpdateRequired = true;
        } else if (ownershipCheckFailure(bOwnerSpecified, resourceOwnerWithoutForceSuffix, resourceOwnership.getObjectOwner())) {
            throw Utils.conflictError("Invalid resource owner for service: " + service.getName()
                    + ", " +  resourceOwnership.getObjectOwner() + " vs. " + resourceOwner, caller);
        }

        if (resourceOwnership.getPublicKeysOwner() == null || isResourceOwnershipOverrideAllowed(resourceOwner, resourceOwnership.getPublicKeysOwner())) {
            bUpdateRequired = true;
        } else if (ownershipCheckFailure(bOwnerSpecified, resourceOwnerWithoutForceSuffix, resourceOwnership.getPublicKeysOwner())) {
            throw Utils.conflictError("Invalid public-keys owner for service: " + service.getName()
                    + ", " +  resourceOwnership.getPublicKeysOwner() + " vs. " + resourceOwner, caller);
        }

        if (resourceOwnership.getHostsOwner() == null || isResourceOwnershipOverrideAllowed(resourceOwner, resourceOwnership.getHostsOwner())) {
            bUpdateRequired = true;
        } else if (ownershipCheckFailure(bOwnerSpecified, resourceOwnerWithoutForceSuffix, resourceOwnership.getHostsOwner())) {
            throw Utils.conflictError("Invalid hosts owner for service: " + service.getName()
                    + ", " +  resourceOwnership.getHostsOwner() + " vs. " + resourceOwner, caller);
        }

        return bUpdateRequired ? requestOwnership : null;
    }

    public static void verifyServiceDeleteResourceOwnership(ServiceIdentity service, final String resourceOwner,
            final String caller) throws ServerResourceException {

        // if the object has no owner then we're good for the enforcement check

        ResourceServiceIdentityOwnership resourceOwnership = service.getResourceOwnership();
        if (resourceOwnership == null || resourceOwnership.getObjectOwner() == null) {
            return;
        }

        verifyDeleteResourceOwnership(resourceOwner, resourceOwnership.getObjectOwner(), caller);
    }

    public static ResourceServiceIdentityOwnership verifyServicePublicKeysResourceOwnership(ServiceIdentity service,
            final String resourceOwner, final String caller) throws ServerResourceException {

        // first check if we're explicitly asked to ignore the check
        // by either using the ignore value or the feature being disabled

        if (skipEnforceResourceOwnership(resourceOwner)) {
            return null;
        }

        boolean bOwnerSpecified = !StringUtil.isEmpty(resourceOwner);
        String resourceOwnerWithoutForceSuffix = getResourceOwnershipWithoutForceSuffix(resourceOwner, bOwnerSpecified);
        ResourceServiceIdentityOwnership requestOwnership = bOwnerSpecified ?
                new ResourceServiceIdentityOwnership().setPublicKeysOwner(resourceOwnerWithoutForceSuffix) : null;

        // if the object has no owner then we're good for the enforcement
        // part, but we need to return the request ownership object (in case
        // it was specified) so the resource is updated accordingly

        ResourceServiceIdentityOwnership resourceOwnership = service.getResourceOwnership();
        if (resourceOwnership == null) {
            return requestOwnership;
        }

        final String publicKeysOwner = resourceOwnership.getPublicKeysOwner();
        if (!bOwnerSpecified && StringUtil.isEmpty(publicKeysOwner)) {
            // if both values are not present then no changes are necessary
            return null;
        } else if (!bOwnerSpecified) {
            // if the object has public keys owner then we reject the request
            throw Utils.conflictError("Service has a resource owner: " + publicKeysOwner, caller);
        } else if (StringUtil.isEmpty(publicKeysOwner) || isResourceOwnershipOverrideAllowed(resourceOwner, publicKeysOwner)) {
            // if the object has no public keys owner then we need to set it
            requestOwnership.setObjectOwner(resourceOwnership.getObjectOwner());
            requestOwnership.setHostsOwner(resourceOwnership.getHostsOwner());
            return requestOwnership;
        } else if (!resourceOwnerWithoutForceSuffix.equalsIgnoreCase(publicKeysOwner)) {
            throw Utils.conflictError("Invalid resource member owner for service: " + service.getName()
                    + ", " + publicKeysOwner + " vs. " + resourceOwnerWithoutForceSuffix, caller);
        } else {
            // no changes needed
            return null;
        }
    }

    public static boolean ownershipCheckFailure(boolean bOwnerSpecified, final String resourceOwner,
            final String objectOwner) {
        return ((bOwnerSpecified && !resourceOwner.equalsIgnoreCase(objectOwner)) ||
            (!bOwnerSpecified && !StringUtil.isEmpty(objectOwner)));
    }

    public static void verifyPolicyAssertionsDeleteResourceOwnership(Policy policy, final String resourceOwner,
            final String caller) throws ServerResourceException {

        // if the object has no owner then we're good for the enforcement check

        ResourcePolicyOwnership resourceOwnership = policy.getResourceOwnership();
        if (resourceOwnership == null || resourceOwnership.getAssertionsOwner() == null) {
            return;
        }

        verifyDeleteResourceOwnership(resourceOwner, resourceOwnership.getAssertionsOwner(), caller);
    }

    public static void verifyGroupMembersDeleteResourceOwnership(Group group, final String resourceOwner,
            final String caller) throws ServerResourceException {

        // if the group member has no owner then we're good for the enforcement check

        ResourceGroupOwnership resourceOwnership = group.getResourceOwnership();
        if (resourceOwnership == null || resourceOwnership.getMembersOwner() == null) {
            return;
        }

        verifyDeleteResourceOwnership(resourceOwner, resourceOwnership.getMembersOwner(), caller);
    }

    public static void verifyDeleteResourceOwnership(String resourceOwner, final String objectOwner,
            final String caller) throws ServerResourceException {

        // first check if we're explicitly asked to ignore the check
        // by either using the ignore value or the feature being disabled

        if (skipEnforceResourceOwnership(resourceOwner)) {
            return;
        }

        // if the current resource owner includes the force suffix then we need to drop it and
        // then do the match
        resourceOwner = getResourceOwnershipWithoutForceSuffix(resourceOwner, !StringUtil.isEmpty(resourceOwner));

        // at this point we have an object owner so the value must match
        // otherwise we'll throw a conflict error exception

        if (!objectOwner.equalsIgnoreCase(resourceOwner)) {
            throw Utils.conflictError("Invalid resource owner for object: " +
                    objectOwner + " vs. " + resourceOwner, caller);
        }
    }

    public static boolean skipEnforceResourceOwnership(final String resourceOwner) {
        return ENFORCE_RESOURCE_OWNERSHIP.get() == Boolean.FALSE || RESOURCE_OWNER_IGNORE.equalsIgnoreCase(resourceOwner);
    }

    public static boolean isResourceOwnershipOverrideAllowed(final String resourceOwner, final String objectOwner) {
        if (resourceOwner != null && resourceOwner.endsWith(RESOURCE_OWNER_FORCE_SUFFIX)) {
            return !objectOwner.concat(RESOURCE_OWNER_FORCE_SUFFIX).equals(resourceOwner);
        }
        return false;
    }
}
