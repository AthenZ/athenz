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
import com.yahoo.athenz.auth.util.StringUtils;

import java.util.List;

public class PrincipalUtils {

    public static Principal.Type principalType(final String memberName, final String userDomainPrefix,
            final List<String> addlUserCheckDomainPrefixList, final String headlessUserDomainPrefix) {

        if (isUserDomainPrincipal(memberName, userDomainPrefix, addlUserCheckDomainPrefixList)) {
            return Principal.Type.USER;
        } else if (isHeadlessUserDomainPrincipal(memberName, headlessUserDomainPrefix)) {
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
}
