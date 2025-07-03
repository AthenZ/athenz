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
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class InstanceAWSUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceAWSUtils.class);

    static final String AWS_PROP_PUBLIC_CERT            = "athenz.zts.aws_public_cert";
    static final String AWS_PROP_PUBLIC_CERT_PER_REGION = "athenz.zts.aws_public_cert_per_region";

    // AWS public key for validating instance documents
    PublicKey awsPublicKey = null;
    // AWS public keys for validating instance documents per region
    Map<String, PublicKey> awsPublicKeyRegionMap = new HashMap<>();

    public InstanceAWSUtils() {

        // the default AWS public cert file is specified for backward compatibility
        // the preference would be to use the new per-region certs

        final String awsCertFileName = System.getProperty(AWS_PROP_PUBLIC_CERT, "");
        awsPublicKey = loadPublicKey(awsCertFileName);

        // the format for the region cert files is <region>:<filename>[,<region>:<filename>...]
        // e.g. us-east-1:/path/to/us-east-1.pem,us-west-2:/path/to/us-west-2.pem

        final String awsPerRegionCertFiles = System.getProperty(AWS_PROP_PUBLIC_CERT_PER_REGION, "");
        if (!awsPerRegionCertFiles.isEmpty()) {
            String[] regionCertFiles = awsPerRegionCertFiles.split(",");
            for (String regionCertFile : regionCertFiles) {
                String[] parts = regionCertFile.split(":");
                if (parts.length != 2) {
                    LOGGER.error("Invalid AWS public cert per region format: {}", regionCertFile);
                    continue;
                }
                PublicKey publicKey = loadPublicKey(parts[1].trim());
                if (publicKey != null) {
                    awsPublicKeyRegionMap.put(parts[0].trim(), publicKey);
                }
            }
        }

        if (awsPublicKey == null && awsPublicKeyRegionMap.isEmpty()) {
            LOGGER.error("AWS Public Key not specified - no instance requests will be authorized");
        }
    }

    /**
     * Load the AWS public key from the specified certificate file.
     *
     * @param certFileName the name of the certificate file
     * @return the PublicKey object, or null if unable to load
     */
    PublicKey loadPublicKey(final String certFileName) {
        if (certFileName.isEmpty()) {
            return null;
        }
        try {
            File certFile = new File(certFileName);
            X509Certificate awsCert = Crypto.loadX509Certificate(certFile);
            return awsCert.getPublicKey();
        } catch (Exception ex) {
            LOGGER.error("Unable to load AWS public cert from filename: {}, error: {}", certFileName, ex.getMessage());
        }
        return null;
    }

    /**
     * Validate the AWS instance document signature.
     *
     * @param document  the instance document
     * @param signature the signature to validate
     * @param region    the AWS region of the instance
     * @param errMsg    StringBuilder to append error messages
     * @return true if the signature is valid, false otherwise
     */
    public boolean validateAWSSignature(final String document, final String signature, final String region, StringBuilder errMsg) {

        if (signature == null || signature.isEmpty()) {
            errMsg.append("AWS instance document signature is empty");
            return false;
        }

        // first we need to check if we have a public key for
        // the specified region, if not then we use the default key

        PublicKey publicKey = getAwsPublicKey(region);
        if (publicKey == null) {
            errMsg.append("AWS Public key is not available");
            return false;
        }

        boolean valid = false;
        try {
            valid = Crypto.validatePKCS7Signature(document, signature, publicKey);
        } catch (CryptoException ex) {
            errMsg.append("verifyInstanceDocument: unable to verify AWS instance document: ");
            errMsg.append(ex.getMessage());
        }

        return valid;
    }

    PublicKey getAwsPublicKey(final String region) {
        PublicKey publicKey = null;
        if (!StringUtil.isEmpty(region)) {
            publicKey = awsPublicKeyRegionMap.get(region);
        }
        if (publicKey == null) {
            publicKey = awsPublicKey;
        }
        return publicKey;
    }
}
