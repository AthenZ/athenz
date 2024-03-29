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

import com.yahoo.athenz.zms.*;
import org.eclipse.jetty.util.StringUtil;

public class ResourceOwnership {

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
}
