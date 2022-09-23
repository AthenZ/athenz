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

import org.testng.annotations.Test;

import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.*;

public class SignedPolicyRequestTest {

    @Test
    public void testSignedPolicyRequest() {

        Map<String, String> policyVersions = new HashMap<>();
        SignedPolicyRequest request1 = new SignedPolicyRequest().setPolicyVersions(policyVersions)
                        .setSignatureP1363Format(true);

        assertEquals(request1.getPolicyVersions(), policyVersions);
        assertTrue(request1.getSignatureP1363Format());

        SignedPolicyRequest request2 = new SignedPolicyRequest().setPolicyVersions(policyVersions)
                        .setSignatureP1363Format(true);
        assertTrue(request2.equals(request1));
        assertTrue(request2.equals(request2));
        assertFalse(request2.equals(null));

        Map<String, String> policyVersions2 = new HashMap<>();
        policyVersions2.put("policy1", "0");
        request2.setPolicyVersions(policyVersions2);
        assertFalse(request2.equals(request1));
        request2.setPolicyVersions(null);
        assertFalse(request2.equals(request1));
        request2.setPolicyVersions(policyVersions);
        assertTrue(request2.equals(request1));

        request2.setSignatureP1363Format(false);
        assertFalse(request2.equals(request1));
        request2.setSignatureP1363Format(true);
        assertTrue(request2.equals(request1));
    }
}
