/**
 * Copyright 2017 Yahoo Holdings, Inc.
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

import java.io.File;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ResourceException;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;

public class InstanceAWSProvider implements InstanceProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceAWSProvider.class);
    
    private static final String ATTR_ACCOUNT_ID = "accountId";
    private static final String ATTR_REGION = "region";
    private static final String ATTR_PENDING_TIME = "pendingTime";

    private static final String ZTS_CERT_USAGE        = "certUsage";
    private static final String ZTS_CERT_USAGE_CLIENT = "client";
    
    public static final String AWS_PROP_PUBLIC_CERT      = "athenz.zts.aws_public_cert";
    public static final String AWS_PROP_BOOT_TIME_OFFSET = "athenz.zts.aws_boot_time_offset";
    
    PublicKey awsPublicKey = null;      // AWS public key for validating instance documents
    long bootTimeOffset;                // boot time offset in milliseconds
    
    @Override
    public void initialize(String provider, String providerEndpoint) {
        
        String awsCertFileName = System.getProperty(AWS_PROP_PUBLIC_CERT);
        if (awsCertFileName != null && !awsCertFileName.isEmpty()) {
            File awsCertFile = new File(awsCertFileName);
            X509Certificate awsCert = Crypto.loadX509Certificate(awsCertFile);
            awsPublicKey = awsCert.getPublicKey();
        }
        
        // how long the instance must be booted in the past before we
        // stop validating the instance requests
        
        long timeout = TimeUnit.SECONDS.convert(5, TimeUnit.MINUTES);
        bootTimeOffset = 1000 * Long.parseLong(
                System.getProperty(AWS_PROP_BOOT_TIME_OFFSET, Long.toString(timeout)));
    }

    ResourceException error(String message) {
        LOGGER.error(message);
        return new ResourceException(ResourceException.FORBIDDEN, message);
    }
    
    String getAWSAccount(Map<String, String> attributes) {
        
        if (attributes == null) {
            LOGGER.error("validateAWSAccount: no attributes available");
            return null;
        }
    
        final String awsAccount = attributes.get("awsAccount");
        if (awsAccount == null) {
            LOGGER.error("validateAWSAccount: awsAccount attribute not available");
            return null;
        }
        
        return awsAccount;
    }
    
    boolean validateAWSAccount(final String awsAccount, final String docAccount) {
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("validateAWSAccount: ZTS domain account lookup: " + awsAccount);
            LOGGER.debug("validateAWSAccount: Instance document account: " + docAccount);
        }
        
        if (!awsAccount.equalsIgnoreCase(docAccount)) {
            LOGGER.error("verifyInstanceDocument: mismatch between account values: "
                    + " domain lookup: {} vs. instance document: {}", awsAccount, docAccount);
            return false;
        }
        return true;
    }
    
    boolean validateAWSProvider(final String provider, final String region) {
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("validateAWSProvider: validating provider {} with region {}", provider, region);
        }
        
        if (region == null) {
            LOGGER.error("validateAWSProvider: no region provided in instance document");
            return false;
        }
        
        final String suffix = "." + region;
        if (!provider.endsWith(suffix)) {
            LOGGER.error("validateAWSProvider: provider does not end with expected suffix {}", suffix);
            return false;
        }
        
        return true;
    }
    
    boolean validateAWSSignature(final String document, final String signature) {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("validateAWSSignature: validating AWS signature: {}", signature);
        }
        
        if (signature == null || signature.isEmpty()) {
            LOGGER.error("AWS instance document signature is empty");
            return false;
        }
        
        if (awsPublicKey == null) {
            LOGGER.error("AWS Public key is not available");
            return false;
        }
        
        boolean valid = false;
        try {
            valid = Crypto.validatePKCS7Signature(document, signature, awsPublicKey);
        } catch (CryptoException ex) {
             LOGGER.error("verifyInstanceDocument: unable to verify AWS instance document: {}",
                     ex.getMessage());
        }
        
        return valid;
    }
    
    boolean validateAWSDocument(final String provider, final String document, final String signature,
            final String awsAccount) {
        
        if (!validateAWSSignature(document, signature)) {
            return false;
        }
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("validateAWSDocument: parsing AWS document");
        }
        
        // convert our document into a struct that we can extract data
        
        Struct instanceDocument = JSON.fromString(document, Struct.class);
        if (instanceDocument == null) {
            LOGGER.error("validateAWSDocument: failed to parse: {}",
                    document);
            return false;
        }
        
        if (!validateAWSProvider(provider, instanceDocument.getString(ATTR_REGION))) {
            return false;
        }
        
        // verify that the account lookup and the account in the document match
        
        if (!validateAWSAccount(awsAccount, instanceDocument.getString(ATTR_ACCOUNT_ID))) {
            return false;
        }
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("validateAWSDocument: validating instance boot up time");
        }
        
        // verify that the boot up time for the instance is now
        
        Timestamp bootTime = Timestamp.fromString(instanceDocument.getString(ATTR_PENDING_TIME));
        if (bootTime.millis() < System.currentTimeMillis() - bootTimeOffset) {
            LOGGER.error("validateAWSDocument: Instance boot time is not recent enough: {}",
                    bootTime.toString());
            return false;
        }
        
        return true;
    }
    
    @Override
    public InstanceConfirmation confirmInstance(InstanceConfirmation confirmation) {
        
        AWSAttestationData info = JSON.fromString(confirmation.getAttestationData(),
                AWSAttestationData.class);
        
        // before doing anything else we want to make sure our
        // object has an associated aws account id
        
        final String awsAccount = getAWSAccount(confirmation.getAttributes());
        if (awsAccount == null) {
            throw error("Unable to extract AWS Account id");
        }
        
        // validate that the domain/service given in the confirmation
        // request match the attestation data
        
        final String serviceName = confirmation.getDomain() + "." + confirmation.getService();
        if (!serviceName.equals(info.getRole())) {
            throw error("Service name mismatch: " + info.getRole() + " vs. " + serviceName);
        }
        
        // if we have no document then we can only issue client
        // certs (e.g. support for lambda)
        
        final String document = info.getDocument();
        if (document != null && !document.isEmpty()) {
            
            // validate our document against given signature
            
            if (!validateAWSDocument(confirmation.getProvider(), document, info.getSignature(), awsAccount)) {
                throw error("Unable to validate AWS document");
            }
            
            // reset the attributes received from the server

            confirmation.setAttributes(null);

        } else {
            
            Map<String, String> attributes = new HashMap<>();
            attributes.put(ZTS_CERT_USAGE, ZTS_CERT_USAGE_CLIENT);
            confirmation.setAttributes(attributes);
        }
        
        // verify that the temporary credentials specified in the request
        // can be used to assume the given role thus verifying the
        // instance identity
        
        if (!verifyInstanceIdentity(info, awsAccount)) {
            throw error("Unable to verify instance identity");
        }
        
        return confirmation;
    }

    AWSSecurityTokenServiceClient getInstanceClient(AWSAttestationData info) {
        
        String access = info.getAccess();
        if (access == null || access.isEmpty()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("getInstanceClient: No access key id available in instance document");
            }
            return null;
        }
        
        String secret = info.getSecret();
        if (secret == null || secret.isEmpty()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("getInstanceClient: No secret access key available in instance document");
            }
            return null;
        }
        
        String token = info.getToken();
        if (token == null || token.isEmpty()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("getInstanceClient: No token available in instance document");
            }
            return null;
        }
        
        BasicSessionCredentials creds = new BasicSessionCredentials(access, secret, token);
        return new AWSSecurityTokenServiceClient(creds);
    }
    
    public boolean verifyInstanceIdentity(AWSAttestationData info, final String awsAccount) {
        
        GetCallerIdentityRequest req = new GetCallerIdentityRequest();
        
        try {
            AWSSecurityTokenServiceClient client = getInstanceClient(info);
            if (client == null) {
                LOGGER.error("verifyInstanceIdentity - unable to get AWS STS client object");
                return false;
            }
            
            GetCallerIdentityResult res = client.getCallerIdentity(req);
            if (res == null) {
                LOGGER.error("verifyInstanceIdentity - unable to get caller identity");
                return false;
            }
            
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("verifyInstanceIdentity: caller identity: {}", res.getArn());
            }
             
            String arn = "arn:aws:sts::" + awsAccount + ":assumed-role/" + info.getRole() + "/";
            if (!res.getArn().startsWith(arn)) {
                LOGGER.error("verifyInstanceIdentity - ARN mismatch - request:" +
                        arn + " caller-identity: " + res.getArn());
                return false;
            }
            
            return true;
            
        } catch (Exception ex) {
            LOGGER.error("CloudStore: verifyInstanceIdentity - unable get caller identity: " + ex.getMessage());
            return false;
        }
    }
}
