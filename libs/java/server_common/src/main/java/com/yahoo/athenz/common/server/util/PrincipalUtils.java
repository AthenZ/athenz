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

import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.StringUtils;

import java.util.List;

public class PrincipalUtils {

    public static Principal.Type principalType(final String memberName, final String userDomainPrefix,
            final List<String> addlUserCheckDomainPrefixList, final String headlessUserDomainPrefix) {

        if (isUserDomainPrincipal(memberName, userDomainPrefix, addlUserCheckDomainPrefixList)) {
            return Principal.Type.USER;
        } else if (isHeadlessUserDomainPrincipal(memberName, headlessUserDomainPrefix)) {
            return Principal.Type.USER_HEADLESS;
        }

        int sepIdx = memberName.indexOf(AuthorityConsts.ATHENZ_PRINCIPAL_ENTITY_CHAR);
        if (sepIdx != -1) {
            if (memberName.regionMatches(sepIdx, AuthorityConsts.GROUP_SEP, 0, AuthorityConsts.GROUP_SEP.length())) {
                return Principal.Type.GROUP;
            } else if (memberName.regionMatches(sepIdx, AuthorityConsts.EXT_SEP, 0, AuthorityConsts.EXT_SEP.length())) {
                return Principal.Type.EXTERNAL;
            }
        }

        return Principal.Type.SERVICE;
    }

    public static boolean isUserDomainPrincipal(final String memberName, final String userDomainPrefix,
            final List<String> addlUserCheckDomainPrefixList) {

        // we must have a single separator in the principal name

        if (StringUtils.countMatches(memberName, '.') != 1) {
            return false;
        }

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

    public static boolean isHeadlessUserDomainPrincipal(final String memberName, final String headlessUserDomainPrefix) {
        return memberName.startsWith(headlessUserDomainPrefix) && StringUtils.countMatches(memberName, '.') == 1;
    }

    /**
     * Create a Principal for the given principal name. If the principal name is a group principal
     * then we're going to return null. For external members we'll generate a princpial object
     * with the domain and full name attributes. For user/service principals we'll generate a 
     * principal object with the domain and name attributes.
     * @param principalName Principal name to create a Principal for
     * @param userDomain User domain to use if the principal name is a user principal without the domain component
     * @param userDomainAlias if the principal is a user principal with the domain alias then use use the userDomain argument
     * @return A Principal for the given principal name
     */
    public static Principal createPrincipalForName(final String principalName, final String userDomain,
            final String userDomainAlias) {

        String domain;
        String name;

        // make sure we're not dealing with group principals and for
        // external members we're going to return a principal object
        // with the domain and name

        int idx = principalName.indexOf(AuthorityConsts.ATHENZ_PRINCIPAL_ENTITY_CHAR);
        if (idx != -1) {
            if (principalName.regionMatches(idx, AuthorityConsts.GROUP_SEP, 0, AuthorityConsts.GROUP_SEP.length())) {
                return null;
            } else if (principalName.regionMatches(idx, AuthorityConsts.EXT_SEP, 0, AuthorityConsts.EXT_SEP.length())) {
                return SimplePrincipal.create(principalName.substring(0, idx), principalName);
            }
        }

        // so at this point we're dealing with a service principal
        // if we have no . in the principal name we're going to default
        // to our configured user domain

        idx = principalName.lastIndexOf('.');
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
}
