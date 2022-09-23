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
import java.nio.file.StandardCopyOption;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Timestamp;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zts.DomainSignedPolicyData;
import com.yahoo.athenz.zts.PolicyData;
import com.yahoo.athenz.zts.SignedPolicyData;
import com.yahoo.athenz.zts.ZTSClient;

public class PolicyUpdater {

    private static final Logger LOG = LoggerFactory.getLogger(PolicyUpdater.class);

    private static final String POLICY_FILE_EXTENSION = ".pol";
    private static final String TEMP_FILE_EXTENSION = ".tmp";

    private enum ZPUExitCode {
        SUCCESS(0),
        CONFIG_CREATE_FAILURE(1),
        CONFIG_INIT_FAILURE(2),
        MAX_INSTANCE_FAILURE(3),
        POLICY_UPDATE_FAILURE(4);

        private int code;
        ZPUExitCode(int code) {
            this.code = code;
        }
        int getCode() {
            return code;
        }
    }

    public static void main(String[] args) throws InterruptedException {

        PolicyUpdaterConfiguration configuration = null;
        try {
            configuration = new PolicyUpdaterConfiguration();
        } catch (Exception ex) {
            LOG.error("Unable to create configuration object: {}", ex.getMessage());
            System.exit(ZPUExitCode.CONFIG_CREATE_FAILURE.getCode());
        }

        Random randomGenerator = new Random();

        if (configuration.getStartupDelayIntervalInSecs() > 0) {
            int randomSleepInterval = randomGenerator.nextInt(configuration.getStartupDelayIntervalInSecs());
            LOG.info("Launching zpe_policy_updater in {} seconds...", randomSleepInterval);
            for (int i = 0; i < randomSleepInterval; i++) {
                Thread.sleep(1000);
            }
        } else {
            LOG.info("Launching zpe_policy_updater with no delay...");
        }
        
        ZPUExitCode exitCode = ZPUExitCode.SUCCESS;
        try {
            try {
                configuration.init(null, null);
            } catch (Exception ex) {
                LOG.error("Unable to initialize configuration object: {}", ex.getMessage());
                exitCode = ZPUExitCode.CONFIG_INIT_FAILURE;
                throw ex;
            }

            try {
                PolicyUpdater.policyUpdater(configuration, new ZTSClientFactoryImpl());
            } catch (Exception ex) {
                LOG.error("PolicyUpdater: Unable to update policy data: {}", ex.getMessage());
                exitCode = ZPUExitCode.POLICY_UPDATE_FAILURE;
                throw ex;
            }
        } catch (Exception exc) {
            LOG.error("PolicyUpdater: Exiting upon error: {}", exc.getMessage());
        } finally {
            System.exit(exitCode.getCode());
        }
    }
    
    static void policyUpdater(PolicyUpdaterConfiguration configuration, ZTSClientFactory ztsFactory)
            throws Exception {

        try (ZTSClient zts = ztsFactory.create()) {

            List<String> domainList = configuration.getDomainList();
            LOG.info("policyUpdater: Number of domains to process: {}", domainList == null ? 0 : domainList.size());
            if (domainList == null) {
                LOG.error("policyUpdater: no domain list to process from configuration");
                throw new Exception("no configured domains to process");
            }
            
            for (String domain : domainList) {

                LOG.info("Fetching signed policies for domain: {}", domain);
                
                String matchingTag = getEtagForExistingPolicy(zts, configuration, domain);
                
                Map<String, List<String>> responseHeaders = null;
                DomainSignedPolicyData domainSignedPolicyData;
                try {
                    domainSignedPolicyData = zts.getDomainSignedPolicyData(domain, matchingTag,
                            responseHeaders);
                } catch (Exception exc) {
                    domainSignedPolicyData = null;
                    LOG.error("PolicyUpdater: Unable to retrieve policies from zts for domain={}", domain, exc);
                }
                if (domainSignedPolicyData == null) {
                    if (matchingTag != null && !matchingTag.isEmpty()) {
                        LOG.info("PolicyUpdater: Policies not updated since last fetch time");
                    }
                } else if (validateSignedPolicies(zts, configuration, domainSignedPolicyData, domain)) {
                    writePolicies(configuration, domain, domainSignedPolicyData);
                }
            }
        }
    }

    static boolean validateSignedPolicies(ZTSClient zts, PolicyUpdaterConfiguration configuration,
            DomainSignedPolicyData domainSignedPolicyData, String domain) {
        
        if (domainSignedPolicyData == null || domain == null) {
            throw new IllegalArgumentException("null parameters are not valid arguments");
        }
        
        LOG.info("Checking expiration time for: {}", domain);

        Timestamp expires = domainSignedPolicyData.getSignedPolicyData().getExpires();
        if (System.currentTimeMillis() > expires.millis()) {
            LOG.error("Signed policy for domain:{} was expired.", domain);
            return false;
        }

        // first we're going to verify the ZTS signature for the data
        
        LOG.info("Verifying ZTS signature for: {}", domain);
        SignedPolicyData signedPolicyData = domainSignedPolicyData.getSignedPolicyData();
        
        LOG.debug("Policies retrieved from the ZTS server: {}", signedPolicyData);

        String signature = domainSignedPolicyData.getSignature();
        String keyId     = domainSignedPolicyData.getKeyId();
        LOG.debug("validateSignedPolicies: domain={} zts key id={} Digital ZTS signature={}", domain, keyId, signature);

        PublicKey ztsPublicKey = configuration.getZtsPublicKey(zts, keyId);
        if (ztsPublicKey == null) {
            LOG.error("validateSignedPolicies: Missing ZTS Public key for id: {}", keyId);
            return false;
        }
        
        boolean verified = Crypto.verify(SignUtils.asCanonicalString(signedPolicyData), ztsPublicKey, signature);
        if (!verified) {
            LOG.error("Signed policy for domain:{}} failed ZTS signature verification.", domain);
            LOG.error("ZTS Signature: {}. Policies data returned from ZTS: {}", signature, signedPolicyData);
            return false;
        }
        
        // then we're going to verify the ZMS signature for the policy data
        
        LOG.info("Verifying ZMS signature for: {}", domain);
        PolicyData policyData = signedPolicyData.getPolicyData();
       
        signature = signedPolicyData.getZmsSignature();
        LOG.debug("Digital ZMS signature: {}", signature);
        keyId = signedPolicyData.getZmsKeyId();
        LOG.debug("Digital ZMS signature key Id: {}", keyId);
        
        PublicKey zmsPublicKey = configuration.getZmsPublicKey(zts, keyId);
        if (zmsPublicKey == null) {
            LOG.error("Missing ZMS Public key with id: {}", keyId);
            return false;
        }
        
        verified = Crypto.verify(SignUtils.asCanonicalString(policyData), zmsPublicKey, signature);
        if (!verified) {
            LOG.error("Signed policy for domain:{}} failed ZMS signature verification.", domain);
            LOG.error("ZMS Signature: {}. Policies data returned from ZTS: {}", signature, policyData);
        }
        
        return verified;
    }

    static void verifyTmpDirSetup(PolicyUpdaterConfiguration configuration) throws IOException {
        // ensure tmp dir exists
        String policyTmpDir = configuration.getPolicyFileTmpDir();
        Path tmpDir = Paths.get(policyTmpDir);
        if (java.nio.file.Files.exists(tmpDir)) {
            return;
        }

        LOG.warn("The temp dir doesnt exist so will create it: {}", tmpDir);
        java.nio.file.Files.createDirectory(tmpDir);

        // get the user from config file to perform chown aginst the tmp dir
        // chown -R $zpu_user $ROOT/tmp/zpe
        String user = configuration.getZpuDirOwner();
        if (user == null) {
            LOG.warn("Cannot chown of the temp dir: {} : no configured user", tmpDir);
            return;
        }

        try {
            java.nio.file.attribute.UserPrincipalLookupService lookupSvc =
                java.nio.file.FileSystems.getDefault().getUserPrincipalLookupService();
            java.nio.file.attribute.UserPrincipal uprinc = lookupSvc.lookupPrincipalByName(user);
            Files.setOwner(tmpDir, uprinc);
        } catch (Exception exc) {
            LOG.warn("Failed to chown of the temp dir: {}, user: {}, exc: {}", tmpDir, user, exc.getMessage());
        }
    }

    static void writePolicies(PolicyUpdaterConfiguration configuration, String domain,
            DomainSignedPolicyData domainSignedPolicyData) throws IOException {

        if (configuration == null) {
            throw new IllegalArgumentException("null configuration");
        }
        String policyTmpDir = configuration.getPolicyFileTmpDir();
        String policyDir    = configuration.getPolicyFileDir();
        if (policyTmpDir == null || policyDir == null || domain == null || domainSignedPolicyData == null) {
            throw new IllegalArgumentException("null parameters are not valid arguments");
        }
        
        String pathToTempFile   = policyTmpDir + File.separator + domain + TEMP_FILE_EXTENSION;
        String pathToPolicyFile = policyDir + File.separator + domain + POLICY_FILE_EXTENSION;

        // ensure tmp dir exists
        verifyTmpDirSetup(configuration);

        LOG.info("Writing temp policy file: {}", pathToTempFile);
        // Make a file object from the path name
        File file = new File(pathToTempFile);
        file.createNewFile();
        Files.write(file.toPath(), JSON.bytes(domainSignedPolicyData));

        Path sourceFile = Paths.get(pathToTempFile);
        Path destinationFile = Paths.get(pathToPolicyFile);
        try {
            LOG.info("Moving temp file : {} to destination: {}", sourceFile, destinationFile);
            Files.copy(sourceFile, destinationFile, StandardCopyOption.REPLACE_EXISTING);
            Files.deleteIfExists(sourceFile);
        } catch (IOException exc) {
            LOG.error("PolicyUpdater: Moving temp file failure. source: {} : destination: {} : exc: {}",
                    sourceFile, destinationFile, exc);
        }
    }

    static String getEtagForExistingPolicy(ZTSClient zts, PolicyUpdaterConfiguration configuration,
            String domain) {
        
        if (domain == null) {
            throw new IllegalArgumentException("getEtagForExistingPolicy: null parameters are not valid arguments");
        }

        String policyDir = configuration.getPolicyFileDir();
        if (policyDir == null) {
            throw new IllegalArgumentException("getEtagForExistingPolicy: Invalid configuration: no policy directory path");
        }
        
        String policyDirPath;
        if (policyDir.length() - 1 != policyDir.lastIndexOf(File.separator)) {
            policyDirPath = policyDir + File.separator;
        } else {
            policyDirPath = policyDir;
        }
        
        String policyFile = policyDirPath + domain + POLICY_FILE_EXTENSION;

        LOG.info("Decoding {} to retrieve eTag from policy file.", policyFile);
        File file = new File(policyFile);

        if (!file.exists()) {
            LOG.info("Policy file not found.");
            return null;
        }

        DomainSignedPolicyData domainSignedPolicyData;
        try {
            domainSignedPolicyData = JSON.fromBytes(Files.readAllBytes(file.toPath()),
                    DomainSignedPolicyData.class);
        } catch (Exception ex) {
            LOG.info("Unable to parse domain signed policy file: {}", policyFile);
            return null;
        }
        
        // validate the signature before checking for expiration
        
        if (validateSignedPolicies(zts, configuration, domainSignedPolicyData, domain) == false) {
            LOG.info("Unable to validate domain signed policy file: {}", policyFile);
            return null;
        }
        
        // Check expiration of policies and if its less than the configured interval defined by user
        // to get updated policy then return null so that the policies are updated
        
        LOG.info("Checking expiration time for: {}", domain);
        long now = System.currentTimeMillis() / 1000;

        Timestamp expires = domainSignedPolicyData.getSignedPolicyData().getExpires();
 
        long startupDelayInterval = configuration.getStartupDelayIntervalInSecs();
        
        LOG.info("Expiration time for {} is: {}", domain, (expires.millis() / 1000));
        LOG.info("Startup delay: {}", startupDelayInterval);
        LOG.info("Current time: {}", now);

        if (((expires.millis() / 1000) - now) <  (startupDelayInterval)) {
            LOG.info("Signed policies for domain:{} are expired, returning null.", domain);
            return null;
        }

        String etag = null;
        if (domainSignedPolicyData.getSignedPolicyData().getModified() != null) {
            
            // ETags are quoted-strings based on the HTTP RFC
            // http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.11
            // so we're going to quote our modified timestamp
            
            etag = "\"" + domainSignedPolicyData.getSignedPolicyData().getModified().toString() + "\"";
            LOG.info("ETag: {}", etag);
        } else {
            LOG.info("No ETag found.");
        }

        return etag;
    }
}
