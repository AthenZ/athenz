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

import com.yahoo.athenz.common.ServerCommonConsts;

public class ResourceUtils {
    private static String generateResourceName(String domainName, String resName, String resType) {
        if (resType.isEmpty()) {
            return domainName + "." + resName;
        } else {
            return domainName + ":" + resType + "." + resName;
        }
    }

    public static String roleResourceName(String domainName, String roleName) {
        return generateResourceName(domainName, roleName, ServerCommonConsts.OBJECT_ROLE);
    }

    public static String groupResourceName(String domainName, String groupName) {
        return generateResourceName(domainName, groupName, ServerCommonConsts.OBJECT_GROUP);
    }

    public static String serviceResourceName(String domainName, String serviceName) {
        return generateResourceName(domainName, serviceName, "");
    }

    public static String policyResourceName(String domainName, String policyName) {
        return generateResourceName(domainName, policyName, ServerCommonConsts.OBJECT_POLICY);
    }

    public static String entityResourceName(String domainName, String entityName) {
        return generateResourceName(domainName, entityName, ServerCommonConsts.OBJECT_ENTITY);
    }
}
