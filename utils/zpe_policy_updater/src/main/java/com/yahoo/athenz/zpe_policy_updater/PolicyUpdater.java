/**
 * Copyright 2016 Yahoo Inc.
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
import com.yahoo.athenz.zts.DomainMetrics;
import com.yahoo.athenz.zts.DomainSignedPolicyData;
import com.yahoo.athenz.zts.PolicyData;
import com.yahoo.athenz.zts.SignedPolicyData;
import com.yahoo.athenz.zts.ZTSClient;
import com.yahoo.athenz.zts.ZTSClientException;

public class PolicyUpdater {

    private static final Logger LOG = LoggerFactory.getLogger(PolicyUpdater.class);

    private static final String POLICY_FILE_EXTENSION = ".pol";
    private static final String TEMP_FILE_EXTENSION = ".tmp";

    public static final String ZPE_METRIC_FILE_PATH = "/var/zpe_stat/";
    public static final String ZPE_PROP_METRIC_FILE_PATH = "athenz.zpe.metric_file_path";
    
    static final String METRIC_GENERAL_FAILURE = "zpu_general_fail_sum";
    static final String METRIC_PROCESS_SUM     = "zpu_process_sum";
    static final String METRIC_DOMAIN_FAILURE  = "domain_fail_sum";
    static final String METRIC_DOMAIN_SUCCESS  = "domain_good_sum";
    static final String METRIC_DOMAIN_FAIL     = "domain_fail";
    static final String METRIC_DOMAIN_GOOD     = "domain_good";
    
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
    };

    public static void main(String[] args) throws IOException, InterruptedException {

        PolicyUpdaterConfiguration configuration = null;
        try {
            configuration = new PolicyUpdaterConfiguration();
        } catch (Exception ex) {
            LOG.error("Unable to create configuration object: " + ex.getMessage());
            System.exit(ZPUExitCode.CONFIG_CREATE_FAILURE.getCode());
        }

        Random randomGenerator = new Random();
        int randmonSleepInterval = 0;

        if (configuration.getStartupDelayIntervalInSecs() > 0) {
            randmonSleepInterval = randomGenerator.nextInt(configuration.getStartupDelayIntervalInSecs());
            LOG.info("Launching zpe_policy_updater in " + randmonSleepInterval + " seconds...");
            for (int i = 0; i < randmonSleepInterval; i++) {
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
                LOG.error("Unable to initialize configuration object: " + ex.getMessage());
                exitCode = ZPUExitCode.CONFIG_INIT_FAILURE;
                throw ex;
            }

            try {
                PolicyUpdater.policyUpdater(configuration, new ZTSClientFactoryImpl());
            } catch (Exception ex) {
                LOG.error("PolicyUpdater: Unable to update policy data: " + ex.getMessage());
                exitCode = ZPUExitCode.POLICY_UPDATE_FAILURE;
                throw ex;
            }
        } catch (Exception exc) {
            LOG.error("PolicyUpdater: Exiting upon error: " + exc.getMessage());
        } finally {
            System.exit(exitCode.getCode());
        }
    }
    
    static void policyUpdater(PolicyUpdaterConfiguration configuration, ZTSClientFactory ztsFactory)
            throws Exception {

        try (ZTSClient zts = ztsFactory.create()) {

            List<String> domainList = configuration.getDomainList();
            LOG.info("policyUpdater: Number of domains to process:"
                    + (domainList == null ? 0 : domainList.size()));
            if (domainList == null) {
                LOG.error("policyUpdater: no domain list to process from configuration");
                throw new Exception("no configured domains to process");
            }
            
            for (String domain : domainList) {

                LOG.info("Fetching signed policies for domain:" + domain);
                
                String matchingTag = getEtagForExistingPolicy(zts, configuration, domain);
                
                Map<String, List<String>> responseHeaders = null;
                DomainSignedPolicyData domainSignedPolicyData = null;
                try {
                    domainSignedPolicyData = zts.getDomainSignedPolicyData(domain, matchingTag,
                            responseHeaders);
                } catch (Exception exc) {
                    domainSignedPolicyData = null;
                    LOG.error("PolicyUpdater: Unable to retrieve policies from zts for domain="
                            + domain, exc);
                }
                if (domainSignedPolicyData == null) {
                    if (matchingTag != null && !matchingTag.isEmpty()) {
                        LOG.info("PolicyUpdater: Policies not updated since last fetch time");
                    }
                } else if (validateSignedPolicies(zts, configuration, domainSignedPolicyData, domain)) {
                    writePolicies(configuration, domain, domainSignedPolicyData);
                }
            }
            
            // now push the domain metrics files
            
            postDomainMetrics(zts);
        }
    }

    static boolean validateSignedPolicies(ZTSClient zts, PolicyUpdaterConfiguration configuration,
            DomainSignedPolicyData domainSignedPolicyData, String domain) {
        
        if (domainSignedPolicyData == null || domain == null) {
            throw new IllegalArgumentException("null parameters are not valid arguments");
        }
        
        LOG.info("Checking expiration time for:" + domain);

        Timestamp expires = domainSignedPolicyData.getSignedPolicyData().getExpires();
        if (System.currentTimeMillis() > expires.millis()) {
            LOG.error("Signed policy for domain:" + domain + " was expired.");
            return false;
        }

        // first we're going to verify the ZTS signature for the data
        
        LOG.info("Verifying ZTS signature for: " + domain);
        SignedPolicyData signedPolicyData = domainSignedPolicyData.getSignedPolicyData();
        
        LOG.debug("Policies retrieved from the ZTS server: " + signedPolicyData);

        String signature = domainSignedPolicyData.getSignature();
        String keyId     = domainSignedPolicyData.getKeyId();
        LOG.debug("validateSignedPolicies: domain=" + domain + " zts key id=" + keyId + " Digital ZTS signature=" + signature);

        PublicKey ztsPublicKey = configuration.getZtsPublicKey(zts, keyId);
        if (ztsPublicKey == null) {
            LOG.error("validateSignedPolicies: Missing ZTS Public key for id: " + keyId);
            return false;
        }
        
        boolean verified = Crypto.verify(SignUtils.asCanonicalString(signedPolicyData), ztsPublicKey, signature);
        if (verified == false) {
            LOG.error("Signed policy for domain:" + domain + " failed ZTS signature verification.");
            LOG.error("ZTS Signature: " + signature + ". Policies data returned from ZTS: " + signedPolicyData);
            return false;
        }
        
        // then we're going to verify the ZMS signature for the policy data
        
        LOG.info("Verifying ZMS signature for: " + domain);
        PolicyData policyData = signedPolicyData.getPolicyData();
       
        signature = signedPolicyData.getZmsSignature();
        LOG.debug("Digital ZMS signature: " + signature);
        keyId = signedPolicyData.getZmsKeyId();
        LOG.debug("Digital ZMS signature key Id: " + keyId);
        
        PublicKey zmsPublicKey = configuration.getZmsPublicKey(zts, keyId);
        if (zmsPublicKey == null) {
            LOG.error("Missing ZMS Public key with id: " + keyId);
            return false;
        }
        
        verified = Crypto.verify(SignUtils.asCanonicalString(policyData), zmsPublicKey, signature);
        if (verified == false) {
            LOG.error("Signed policy for domain:" + domain + " failed ZMS signature verification.");
            LOG.error("ZMS Signature: " + signature + ". Policies data returned from ZTS: " + policyData);
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

        LOG.warn("The temp dir doesnt exist so will create it: " + tmpDir);
        java.nio.file.Files.createDirectory(tmpDir);

        // get the user from config file to perform chown aginst the tmp dir
        // chown -R $zpu_user $ROOT/tmp/zpe
        String user = configuration.getZpuDirOwner();
        if (user == null) {
            LOG.warn("Cannot chown of the temp dir: " + tmpDir + " : no configured user");
            return;
        }

        try {
            java.nio.file.attribute.UserPrincipalLookupService lookupSvc =
                java.nio.file.FileSystems.getDefault().getUserPrincipalLookupService();
            java.nio.file.attribute.UserPrincipal uprinc = lookupSvc.lookupPrincipalByName(user);
            Files.setOwner(tmpDir, uprinc);
        } catch (Exception exc) {
            LOG.warn("Failed to chown of the temp dir: " + tmpDir
                    + ", user: " + user + ", exc: " + exc.getMessage());
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

        LOG.info("Writing temp policy file: " + pathToTempFile);
        // Make a file object from the path name
        File file = new File(pathToTempFile);
        file.createNewFile();
        Files.write(file.toPath(), JSON.bytes(domainSignedPolicyData));

        Path sourceFile = Paths.get(pathToTempFile);
        Path destinationFile = Paths.get(pathToPolicyFile);
        try {
            LOG.info("Moving temp file : " + sourceFile + " to destination: " + destinationFile);
            Files.copy(sourceFile, destinationFile, StandardCopyOption.REPLACE_EXISTING);
            Files.deleteIfExists(sourceFile);
        } catch (IOException exc) {
            LOG.error("PolicyUpdater: Moving temp file failure. source: " + sourceFile
                    + " : destination: " + destinationFile + " : exc: " + exc);
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
        
        String etag = null;
        String policyFile = policyDirPath + domain + POLICY_FILE_EXTENSION;

        LOG.info("Decoding " + policyFile + " to retrieve eTag from policy file.");
        File file = new File(policyFile);

        if (file.exists() == false) {
            LOG.info("Policy file not found.");
            return etag;
        }

        DomainSignedPolicyData domainSignedPolicyData = null;
        try {
            domainSignedPolicyData = JSON.fromBytes(Files.readAllBytes(file.toPath()),
                    DomainSignedPolicyData.class);
        } catch (Exception ex) {
            LOG.info("Unable to parse domain signed policy file: " + policyFile);
            return etag;
        }
        
        // validate the signature before checking for expiration
        
        if (validateSignedPolicies(zts, configuration, domainSignedPolicyData, domain) == false) {
            LOG.info("Unable to validate domain signed policy file: " + policyFile);
            return etag;
        }
        
        // Check expiration of policies and if its less than the configured interval defined by user
        // to get updated policy then return null so that the policies are updated
        
        LOG.info("Checking expiration time for: " + domain);
        long now = System.currentTimeMillis() / 1000;

        Timestamp expires = domainSignedPolicyData.getSignedPolicyData().getExpires();
 
        long startupDelayInterval = configuration.getStartupDelayIntervalInSecs();
        
        LOG.info("Expiration time for " + domain + " is: " + (expires.millis() / 1000));
        LOG.info("Startup delay: " + startupDelayInterval);
        LOG.info("Current time: " + now);

        if (((expires.millis() / 1000) - now) <  (startupDelayInterval)) {
            LOG.info("Signed policies for domain:" + domain + " are expired, returning null.");
            return null;
        }

        if (domainSignedPolicyData.getSignedPolicyData().getModified() != null) {
            
            // ETags are quoted-strings based on the HTTP RFC
            // http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.11
            // so we're going to quote our modified timestamp
            
            etag = "\"" + domainSignedPolicyData.getSignedPolicyData().getModified().toString() + "\"";
            LOG.info("ETag: " + etag);
        } else {
            LOG.info("No ETag found.");
        }

        return etag;
    }
    
    static String getFilePath() {
        String rootDir = System.getenv("ROOT");
        if (rootDir == null) {
            rootDir = "/home/athenz";
        }
        final String defaultPath = rootDir + ZPE_METRIC_FILE_PATH;
        String filePath = System.getProperty(ZPE_PROP_METRIC_FILE_PATH, defaultPath);
        
        // verify it ends with the separator and handle accordingly
        
        if (!filePath.endsWith(File.separator)) {
            filePath = filePath.concat(File.separator);
        }
        return filePath;
    }

    public static void postDomainMetrics(ZTSClient zts) {
        
        final String filepath = getFilePath();
        File dir = new File(filepath);
        File[] filenames = dir.listFiles();
        
        // make sure we have valid list of metric files
        
        if (filenames == null) {
            return;
        }
        
        for (int i = 0; i < filenames.length; i++) {
            String domainName = filenames[i].getName().split("_")[0];
            DomainMetrics domainMetrics = null;
            final String metricFile = filepath + filenames[i].getName();
            try {
                Path path = Paths.get(metricFile);
                domainMetrics = JSON.fromBytes(Files.readAllBytes(path), DomainMetrics.class);
                zts.postDomainMetrics(domainName, domainMetrics);
                Files.deleteIfExists(path);
            } catch (ZTSClientException | IOException ex) {
                LOG.error("Unable to push domain metrics from {} - error: {}",
                        metricFile, ex.getMessage());
            }
        }
    }
}
