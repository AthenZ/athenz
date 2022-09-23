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
package com.yahoo.athenz.zts;

public class ZTSClientServiceProvider implements ZTSClientService {

    static RoleToken roleToken;
    static String domainName;
    static String roleName;
    static String trustDomain;
    static String proxyForPrincipal;

    @Override
    public RoleToken fetchToken(String domain, String seervice, String domName,
            String rName, Integer minExpiryTime, Integer maxExpiryTime, String proxy) {

        System.out.println("ZTSClientServiceProvider:fetchToken: domain=" + domName +
            " role=" + roleName + " proxy=" + proxy);

        if (domainName == null || !domainName.equals(domName)) {
            return null;
        }
        
        if (roleName != null && !roleName.equals(rName)) {
            return null;
        }

        if (proxyForPrincipal != null && !proxyForPrincipal.equals(proxy)) {
            return null;
        }

        System.out.println("ZTSClientServiceProvider:fetchToken: return token for domain=" + domName +
            " role=" + rName + " proxy=" + proxy);
        return roleToken;
    }

    public static void setToken(RoleToken rToken, String domName, String rName, String proxy) {

        roleToken = rToken;
        domainName = domName;
        roleName  = rName;
        proxyForPrincipal = proxy;
    }
}

