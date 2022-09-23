/**
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
package com.yahoo.athenz.zpe_policy_updater;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.yahoo.rdl.Timestamp;
import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zts.Assertion;
import com.yahoo.athenz.zts.AssertionEffect;
import com.yahoo.athenz.zts.DomainSignedPolicyData;
import com.yahoo.athenz.zts.Policy;
import com.yahoo.athenz.zts.PolicyData;
import com.yahoo.athenz.zts.PublicKeyEntry;
import com.yahoo.athenz.zts.RoleToken;
import com.yahoo.athenz.zts.ServiceIdentity;
import com.yahoo.athenz.zts.ServiceIdentityList;
import com.yahoo.athenz.zts.SignedPolicyData;
import com.yahoo.athenz.zts.ZTSClientException;
import com.yahoo.athenz.zts.ZTSRDLGeneratedClient;

public class ZTSMock extends ZTSRDLGeneratedClient {
    private PrivateKey ztsPrivateKeyK0 = null;
    private PrivateKey ztsPrivateKeyK1 = null;
    private PrivateKey zmsPrivateKeyK0 = null;
    private String keyId = "0";

    public ZTSMock() throws IOException {
        super("http://localhost:10080");
        loadKeys();
    }

    private void loadKeys() throws IOException {
        Path path = Paths.get("./src/test/resources/unit_test_zts_private_k0.pem");
        ztsPrivateKeyK0 = Crypto.loadPrivateKey(new String(Files.readAllBytes(path)));

        path = Paths.get("./src/test/resources/unit_test_zts_private_k1.pem");
        ztsPrivateKeyK1 = Crypto.loadPrivateKey(new String(Files.readAllBytes(path)));

        path = Paths.get("./src/test/resources/unit_test_zms_private_k0.pem");
        zmsPrivateKeyK0 = Crypto.loadPrivateKey(new String(Files.readAllBytes(path)));
    }

    void setPublicKeyId(String keyId) {
        this.keyId = keyId;
    }
    
    @Override
    public DomainSignedPolicyData getDomainSignedPolicyData(String domainName,
            String matchingTag, Map<String, List<String>> responseHeaders) {

        DomainSignedPolicyData result = null;
        if (!domainName.equals("sports") && 
            !domainName.equals("sys.auth") &&
            !domainName.equals("expiredDomain")) {
            return result;
        }

        SignedPolicyData signedPolicyData = new SignedPolicyData();

        Timestamp expires;
        if (domainName.equals("expiredDomain")) {
            expires = Timestamp.fromMillis(System.currentTimeMillis()
                - (1000L * 60));
        } else {
            expires = Timestamp.fromMillis(System.currentTimeMillis()
                + (1000L * 60 * 60 * 24 * 7));
        }
        signedPolicyData.setExpires(expires);

        Timestamp modified = Timestamp.fromMillis(System.currentTimeMillis());
        signedPolicyData.setModified(modified);

        String policyName = domainName + ":policy." + "admin";
        Policy policy = new Policy();
        policy.setName(policyName);

        Assertion assertion = new Assertion();
        assertion.setAction("*");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*");

        String roleName = domainName + AuthorityConsts.ROLE_SEP + "admin";
        assertion.setRole(roleName);

        List<Assertion> assertList = new ArrayList<Assertion>();
        assertList.add(assertion);

        assertion = new Assertion();
        assertion.setAction("*");
        assertion.setEffect(AssertionEffect.DENY);
        assertion.setResource("*");

        roleName = domainName + AuthorityConsts.ROLE_SEP + "non-admin";
        assertion.setRole(roleName);
        assertList.add(assertion);

        policy.setAssertions(assertList);

        List<Policy> listOfPolicies = new ArrayList<Policy>();
        listOfPolicies.add(policy);
        
        PolicyData policyData = new PolicyData();
        policyData.setPolicies(listOfPolicies);
        policyData.setDomain(domainName);
        
        signedPolicyData.setPolicyData(policyData);
        signedPolicyData.setZmsKeyId("0");
        signedPolicyData.setZmsSignature(Crypto.sign(SignUtils.asCanonicalString(policyData), zmsPrivateKeyK0));
        
        DomainSignedPolicyData domainSignedPolicyData = new DomainSignedPolicyData();
        domainSignedPolicyData.setSignedPolicyData(signedPolicyData);

        PrivateKey ztsKey = null;
        if ("0".equals(keyId)) {
            ztsKey = ztsPrivateKeyK0;
        } else if ("1".equals(keyId)) {
            ztsKey = ztsPrivateKeyK1;
        }

        String signature = Crypto.sign(SignUtils.asCanonicalString(signedPolicyData), ztsKey);
        domainSignedPolicyData.setKeyId(keyId);
        domainSignedPolicyData.setSignature(signature);

        return domainSignedPolicyData;
    }

    @Override
    public RoleToken getRoleToken(String domainName, String role,
            Integer minExpiryTime, Integer maxExpiryTime, String proxyForPrincipal) {
        return null;
    }

    @Override
    public ServiceIdentity getServiceIdentity(String domainName, String serviceName) {
        return null;
    }

    @Override
    public ServiceIdentityList getServiceIdentityList(String domainName) {
        return null;
    }

    @Override
    public PublicKeyEntry getPublicKeyEntry(String domainName, String serviceName,
            String keyId) {
        PublicKeyEntry keyEntry = null;
        if ("2".equals(keyId)) {
            keyEntry = new PublicKeyEntry();
            Path path = Paths.get("./src/test/resources/zts_public_k1.pem");
            keyEntry.setId(keyId);
            try {
                keyEntry.setKey(Crypto.ybase64(Files.readAllBytes(path)));
            } catch (IOException e) {
            }
        }
        if (keyEntry == null) {
            throw new ZTSClientException(404, "Unknown ZTS Public Key");
        } else {
            return keyEntry;
        }
    }
}
