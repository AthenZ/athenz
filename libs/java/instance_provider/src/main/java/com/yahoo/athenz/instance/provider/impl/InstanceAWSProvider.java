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
    private static final String ATTR_PENDING_TIME = "pendingTime";
    private static final String AWS_DOCUMENT_LAMBDA = "lambda";

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
    
    boolean validateAWSAccount(Map<String, String> attributes, String docAccount) {
        if (attributes == null) {
            return false;
        }
        final String awsAccount = attributes.get("awsAccount");
        if (awsAccount == null) {
            return false;
        }
        if (!awsAccount.equalsIgnoreCase(docAccount)) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("validateAWSAccount: ZTS domain account lookup: " + awsAccount);
                LOGGER.debug("validateAWSAccount: Instance document account: " + docAccount);
            }
            LOGGER.error("verifyInstanceDocument: mismatch between account values: "
                    + " domain lookup: {} vs. instance document: {}", awsAccount, docAccount);
            return false;
        }
        return true;
    }
    
    public boolean validateAWSSignature(final String document, final String signature) {

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
    
    @Override
    public InstanceConfirmation confirmInstance(InstanceConfirmation confirmation) {
        
        AWSAttestationData info = JSON.fromString(confirmation.getAttestationData(),
                AWSAttestationData.class);
        
        final String document = info.getDocument();
        if (document == null || document.isEmpty()) {
            throw error("AWS instance document is empty");
        }
        
        // check if this is a special labmda document as opposed to
        // standard EC2 instance document
        
        if (!AWS_DOCUMENT_LAMBDA.equals(document)) {
        
            if (!validateAWSSignature(document, info.getSignature())) {
                throw error("AWS Instance document signature mismatch");
            }
            
            // convert our document into a struct that we can extract data
            
            Struct instanceDocument = null;
            try {
                instanceDocument = JSON.fromString(document, Struct.class);
            } catch (Exception ex) {
                LOGGER.error("verifyInstanceDocument: failed to parse: {} error: {}",
                        info.getDocument(), ex.getMessage());
            }
            
            if (instanceDocument == null) {
                throw error("Unable to parse instance document");
            }
            
            // verify that the account lookup and the account in the document match
            
            if (!validateAWSAccount(confirmation.getAttributes(), instanceDocument.getString(ATTR_ACCOUNT_ID))) {
                throw error("Unable to validate registered AWS account id in Athenz");
            }
            
            // verify that the boot up time for the instance is now
            
            Timestamp bootTime = Timestamp.fromMillis(Long.valueOf(instanceDocument.getString(ATTR_PENDING_TIME)));
            if (bootTime.millis() < System.currentTimeMillis() - bootTimeOffset) {
                throw error("Instance boot time is not recent enough");
            }
        }
        
        // verify that the temporary credentials specified in the request
        // can be used to assume the given role thus verifying the
        // instance identity
        
        if (!verifyInstanceIdentity(info)) {
            throw error("Unable to verify instance identity");
        }
        
        // reset the attributes received from the server
        
        confirmation.setAttributes(null);
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
    
    public boolean verifyInstanceIdentity(AWSAttestationData info) {

        StringBuilder serviceBuilder = new StringBuilder(256);
        serviceBuilder.append(info.getDomain()).append('.').append(info.getService());
        String service = serviceBuilder.toString();
        
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
            
            String arn = "arn:aws:sts::" + info.getAccount() + ":assumed-role/" + service + "/";
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
