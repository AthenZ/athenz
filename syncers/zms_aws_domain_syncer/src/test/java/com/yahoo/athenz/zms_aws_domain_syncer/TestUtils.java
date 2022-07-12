/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.zms_aws_domain_syncer;

import com.google.common.primitives.Bytes;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Timestamp;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.*;

public class TestUtils {

    public final static String TESTROOT = "src/test/resources";

    private static final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private static final byte[] PERIOD = { 46 };

    public static JWSDomain createJWSDomain(final String domainName, Timestamp modifiedTimeStamp) {

        final String adminRole = domainName + ":role.admin";
        final String adminPolicy = domainName + ":policy.admin";

        List<Role> roles = new ArrayList<>();
        Role role = new Role().setName(adminRole).setModified(modifiedTimeStamp);
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.john"));
        roleMembers.add(new RoleMember().setMemberName("unix.zms_test_admin"));
        role.setRoleMembers(roleMembers);
        roles.add(role);

        List<Policy> policies = new ArrayList<>();
        Policy policy = new Policy().setName(adminPolicy);
        List<Assertion> assertions = new ArrayList<>();
        assertions.add(new Assertion().setResource("iaas:*").setAction("*").setRole(adminRole)
                .setEffect(AssertionEffect.ALLOW));
        policy.setAssertions(assertions);
        policies.add(policy);

        DomainPolicies domainPolicies = new DomainPolicies();
        domainPolicies.setDomain(domainName);
        domainPolicies.setPolicies(policies);

        SignedPolicies signedPolicies = new SignedPolicies();
        signedPolicies.setKeyId("zms.dev.0");
        signedPolicies.setSignature("MEQCIBUt9skEPl-AGE7qZdJHkHMQApXKPnM66Qc0EzKKJpOlAiBZguWu-l4-ND2bi7Jbt6vwlwLw0H3TI63cZrKxneBPjg");
        signedPolicies.setContents(domainPolicies);

        DomainData domainData = new DomainData();
        domainData.setName(domainName);
        domainData.setModified(modifiedTimeStamp);
        domainData.setRoles(roles);
        domainData.setPolicies(signedPolicies);

        File privKeyFile = new File("src/test/resources/zms_private.pem");
        final String privKey = Crypto.encodedFile(privKeyFile);
        java.security.PrivateKey privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));

        return signJWSDomain(domainData, privateKey, "1");
    }

    public static JWSDomain signJWSDomain(DomainData domainData, PrivateKey privateKey, final String keyId) {

        // https://tools.ietf.org/html/rfc7515#section-7.2.2
        // first generate the json output of our object

        JWSDomain jwsDomain = null;
        try {
            // generate our domain data payload and encode it

            final byte[] jsonDomain = JSON.bytes(domainData);
            final byte[] encodedDomain = encoder.encode(jsonDomain);

            // generate our protected header - just includes the key id + algorithm

            final String protectedHeader = "{\"kid\":\"" + keyId + "\",\"alg\":\"RS256\"}";
            final byte[] encodedHeader = encoder.encode(protectedHeader.getBytes(StandardCharsets.UTF_8));

            // combine protectedHeader . payload and sign the result

            final byte[] signature = encoder.encode(Crypto.sign(
                    Bytes.concat(encodedHeader, PERIOD, encodedDomain), privateKey, Crypto.SHA256));

            // our header contains a single entry with the keyid

            final Map<String, String> headerMap = new HashMap<>();
            headerMap.put("keyid", "1");

            jwsDomain = new JWSDomain().setHeader(headerMap)
                    .setPayload(new String(encodedDomain))
                    .setProtectedHeader(new String(encodedHeader))
                    .setSignature(new String(signature));

        } catch (Exception ignored) {
        }
        return jwsDomain;
    }
}
