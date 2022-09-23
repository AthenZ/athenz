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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zts.DomainSignedPolicyData;
import com.yahoo.athenz.zts.PolicyData;
import com.yahoo.athenz.zts.SignedPolicyData;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Timestamp;

/**
 * Sign policy files
 *
 */
public class SignPoliciesUtility
{
    private static void usage() {
        System.out.println("usage: java -cp <your classpath> <zts private key file> <zms private key file> <policy file to sign> <path to the signed policy file>");
        System.exit(-1);
    }

    static String signPolicies(String ztsPrivateKeyPath, String zmsPrivateKeyPath, String signedPolicyFile,
            String newPolicyFile) {

        String etag = null;
        try {
            Path path = Paths.get(ztsPrivateKeyPath);
            PrivateKey ztsPrivateKey = Crypto.loadPrivateKey(new String((Files.readAllBytes(path))));

            path = Paths.get(zmsPrivateKeyPath);
            PrivateKey zmsPrivateKey = Crypto.loadPrivateKey(new String((Files.readAllBytes(path))));

            path = Paths.get(signedPolicyFile);
            DomainSignedPolicyData domainSignedPolicyData = JSON.fromBytes(Files.readAllBytes(path),
                    DomainSignedPolicyData.class);
            SignedPolicyData signedPolicyData = domainSignedPolicyData.getSignedPolicyData();
            
            PolicyData policyData = signedPolicyData.getPolicyData();
            signedPolicyData.setZmsSignature(Crypto.sign(SignUtils.asCanonicalString(policyData), zmsPrivateKey));
            signedPolicyData.setZmsKeyId("0");
            
            long curTime = System.currentTimeMillis();
            Timestamp modified = Timestamp.fromMillis(curTime);
            signedPolicyData.setModified(modified);

            Timestamp expires = Timestamp.fromMillis(curTime + (1000L * 60 * 60 * 24 * 7));
            signedPolicyData.setExpires(expires);
            
            String signature = Crypto.sign(SignUtils.asCanonicalString(signedPolicyData), ztsPrivateKey);
            domainSignedPolicyData.setSignature(signature).setKeyId("0");
            File file = new File(newPolicyFile);
            file.createNewFile();
            Files.write(file.toPath(), JSON.bytes(domainSignedPolicyData));

            etag = "\"" + modified.toString() + "\"";
        } catch (IOException e) {
            System.out.println("Exception: " + e.getMessage());
            System.exit(-1);
        }

        System.out.println("Signed " + newPolicyFile + " policy file");
        return etag;
    }

    public static void main(String[] args) {
        if (args.length != 4) {
            usage();
        }

        signPolicies(args[0], args[1], args[2], args[3]);
    }
}
