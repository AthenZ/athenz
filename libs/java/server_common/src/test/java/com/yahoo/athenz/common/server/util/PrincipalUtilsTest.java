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

import com.yahoo.athenz.auth.Principal;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.List;

import static org.testng.Assert.assertEquals;

public class PrincipalUtilsTest {

    @Test
    public void testPrincipalType() {
        // Set different strings between user and home domain
        String userDomain = "user";
        String userDomain2 = "user2";
        String homeDomain = "home";
        String headlessDomain = "headless";
        String topLevelDomain = "athenz";
        String groupSep = ":group";
        List<String> addlUserCheckDomainPrefixList = Arrays.asList(userDomain2);

        // GROUP
        assertEquals(PrincipalUtils.principalType(homeDomain + ".joe" + groupSep + ".test-group", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.GROUP);
        assertEquals(PrincipalUtils.principalType(topLevelDomain + groupSep + ".test-group", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.GROUP);
        // USER
        assertEquals(PrincipalUtils.principalType(userDomain + ".joe", userDomain, addlUserCheckDomainPrefixList,
                headlessDomain), Principal.Type.USER);
        assertEquals(PrincipalUtils.principalType(userDomain2 + ".joe", userDomain, addlUserCheckDomainPrefixList,
                headlessDomain), Principal.Type.USER);
        // USER_HEADLESS
        assertEquals(PrincipalUtils.principalType(headlessDomain + ".joe", userDomain, addlUserCheckDomainPrefixList,
                headlessDomain), Principal.Type.USER_HEADLESS);
        // SERVICE
        assertEquals(PrincipalUtils.principalType(topLevelDomain + ".test-service", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.SERVICE);
        assertEquals(PrincipalUtils.principalType(homeDomain + ".joe" + ".test-service", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.SERVICE);

        // Set same strings between user and home domain.
        userDomain = "personal";
        homeDomain = userDomain;

        // GROUP
        assertEquals(PrincipalUtils.principalType(homeDomain + ".joe" + groupSep + ".test-group", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.GROUP);
        assertEquals(PrincipalUtils.principalType(topLevelDomain + groupSep + ".test-group", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.GROUP);
        // USER
        assertEquals(PrincipalUtils.principalType(userDomain + ".joe", userDomain, addlUserCheckDomainPrefixList,
                headlessDomain), Principal.Type.USER);
        assertEquals(PrincipalUtils.principalType(userDomain2 + ".joe", userDomain, addlUserCheckDomainPrefixList,
                headlessDomain), Principal.Type.USER);
        // USER_HEADLESS
        assertEquals(PrincipalUtils.principalType(headlessDomain + ".joe", userDomain, addlUserCheckDomainPrefixList,
                headlessDomain), Principal.Type.USER_HEADLESS);
        // SERVICE
        assertEquals(PrincipalUtils.principalType(topLevelDomain + ".test-service", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.SERVICE);
        assertEquals(PrincipalUtils.principalType(homeDomain + ".joe" + ".test-service", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.SERVICE);
    }
}
