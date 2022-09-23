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
package com.yahoo.athenz.instance.provider.impl;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class InstanceAWSUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceAWSUtils.class);

    static final String AWS_PROP_PUBLIC_CERT      = "athenz.zts.aws_public_cert";

    PublicKey awsPublicKey = null;           // AWS public key for validating instance documents

    public InstanceAWSUtils() {
        final String awsCertFileName = System.getProperty(AWS_PROP_PUBLIC_CERT, "");
        if (!awsCertFileName.isEmpty()) {
            File awsCertFile = new File(awsCertFileName);
            X509Certificate awsCert = Crypto.loadX509Certificate(awsCertFile);
            awsPublicKey = awsCert.getPublicKey();
        }

        if (awsPublicKey == null) {
            LOGGER.error("AWS Public Key not specified - no instance requests will be authorized");
        }
    }

    public boolean validateAWSSignature(final String document, final String signature, StringBuilder errMsg) {

        if (signature == null || signature.isEmpty()) {
            errMsg.append("AWS instance document signature is empty");
            return false;
        }

        if (awsPublicKey == null) {
            errMsg.append("AWS Public key is not available");
            return false;
        }

        boolean valid = false;
        try {
            valid = Crypto.validatePKCS7Signature(document, signature, awsPublicKey);
        } catch (CryptoException ex) {
            errMsg.append("verifyInstanceDocument: unable to verify AWS instance document: ");
            errMsg.append(ex.getMessage());
        }

        return valid;
    }
}
