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
package com.yahoo.athenz.auth.oauth.token;

import static org.testng.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class OAuthJwtAccessTokenTest {

    @Test(dataProvider = "instances")
    public void testGetScopes(OAuthJwtAccessToken instance, List<String> expected) {
        assertEquals(instance.getScopes(), expected);
    }
    @DataProvider(name = "instances")
    public static Object[][] instances() {
        List<Object[]> testCases = new ArrayList<>();

        // null scope
        testCases.add(new Object[]{
            new OAuthJwtAccessToken() {
                public String getScope() { return null; }
                public String getSubject() { return null; }
                public String getIssuer() { return null; }
                public String getAudience() { return null; }
                public List<String>  getAudiences() { return null; }
                public String getClientId() { return null; }
                public String getCertificateThumbprint() { return null; }
                public long getIssuedAt() { return 0L; }
                public long getExpiration() { return 0L; }
                public String getSignature() { return null; }
            },
            null
        });
        // empty scope
        testCases.add(new Object[]{
            new OAuthJwtAccessToken() {
                public String getScope() { return ""; }
                public String getSubject() { return null; }
                public String getIssuer() { return null; }
                public String getAudience() { return null; }
                public List<String>  getAudiences() { return null; }
                public String getClientId() { return null; }
                public String getCertificateThumbprint() { return null; }
                public long getIssuedAt() { return 0L; }
                public long getExpiration() { return 0L; }
                public String getSignature() { return null; }
            },
            Arrays.asList("")
        });
        // 2 scopes
        testCases.add(new Object[]{
            new OAuthJwtAccessToken() {
                public String getScope() { return "scope_1 scope_2"; }
                public String getSubject() { return null; }
                public String getIssuer() { return null; }
                public String getAudience() { return null; }
                public List<String>  getAudiences() { return null; }
                public String getClientId() { return null; }
                public String getCertificateThumbprint() { return null; }
                public long getIssuedAt() { return 0L; }
                public long getExpiration() { return 0L; }
                public String getSignature() { return null; }
            },
            Arrays.asList("scope_1", "scope_2")
        });
        // trailing delimiter
        testCases.add(new Object[]{
            new OAuthJwtAccessToken() {
                public String getScope() { return "scope_3 scope_4 "; }
                public String getSubject() { return null; }
                public String getIssuer() { return null; }
                public String getAudience() { return null; }
                public List<String>  getAudiences() { return null; }
                public String getClientId() { return null; }
                public String getCertificateThumbprint() { return null; }
                public long getIssuedAt() { return 0L; }
                public long getExpiration() { return 0L; }
                public String getSignature() { return null; }
            },
            Arrays.asList("scope_3", "scope_4")
        });

        return testCases.toArray(new Object[testCases.size()][]);
    }

}
