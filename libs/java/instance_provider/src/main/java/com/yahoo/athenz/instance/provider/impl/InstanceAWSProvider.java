/*
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

import com.amazonaws.regions.Regions;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ResourceException;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;

import javax.net.ssl.*;

public class InstanceAWSProvider implements InstanceProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceAWSProvider.class);

    static final String ATTR_ACCOUNT_ID   = "accountId";
    static final String ATTR_REGION       = "region";
    static final String ATTR_PENDING_TIME = "pendingTime";

    static final String ATTR_INSTANCE_ID  = "instanceId";

    static final String ZTS_CERT_USAGE            = "certUsage";
    static final String ZTS_CERT_EXPIRY_TIME      = "certExpiryTime";
    static final String ZTS_CERT_SSH              = "certSSH";
    static final String ZTS_CERT_USAGE_CLIENT     = "client";

    static final String ZTS_CERT_INSTANCE_ID      = ".instanceid.athenz.";
    static final String ZTS_INSTANCE_SAN_DNS      = "sanDNS";
    static final String ZTS_INSTANCE_AWS_ACCOUNT  = "cloudAccount";
    static final String ZTS_INSTANCE_ID           = "instanceId";

    static final String AWS_PROP_PUBLIC_CERT      = "athenz.zts.aws_public_cert";
    static final String AWS_PROP_BOOT_TIME_OFFSET = "athenz.zts.aws_boot_time_offset";
    static final String AWS_PROP_DNS_SUFFIX       = "athenz.zts.aws_dns_suffix";
    static final String AWS_PROP_REGION_NAME      = "athenz.zts.aws_region_name";

    static final String AWS_PROP_CERT_VALIDITY_STS_ONLY = "athenz.zts.aws_cert_validity_sts_only";

    PublicKey awsPublicKey = null;      // AWS public key for validating instance documents
    long bootTimeOffset;                // boot time offset in milliseconds
    long certValidityTime;              // cert validity for STS creds only case
    boolean supportRefresh = false;
    String awsRegion;
    String dnsSuffix = null;

    @Override
    public void initialize(String provider, String providerEndpoint, SSLContext sslContext,
            KeyStore keyStore) {
        
        String awsCertFileName = System.getProperty(AWS_PROP_PUBLIC_CERT);
        if (awsCertFileName != null && !awsCertFileName.isEmpty()) {
            File awsCertFile = new File(awsCertFileName);
            X509Certificate awsCert = Crypto.loadX509Certificate(awsCertFile);
            awsPublicKey = awsCert.getPublicKey();
        }
        
        if (awsPublicKey == null) {
            LOGGER.error("AWS Public Key not specified - no instance requests will be authorized");
        }
        
        // how long the instance must be booted in the past before we
        // stop validating the instance requests
        
        long timeout = TimeUnit.SECONDS.convert(5, TimeUnit.MINUTES);
        bootTimeOffset = 1000 * Long.parseLong(
                System.getProperty(AWS_PROP_BOOT_TIME_OFFSET, Long.toString(timeout)));
        
        // determine the dns suffix. if this is not specified we'll
        // rejecting all entries
        
        dnsSuffix = System.getProperty(AWS_PROP_DNS_SUFFIX);
        if (dnsSuffix == null || dnsSuffix.isEmpty()) {
            LOGGER.error("AWS DNS Suffix not specified - no instance requests will be authorized");
        }

        // default certificate expiry for requests without instance
        // identity document

        int certValidityDays = Integer.parseInt(System.getProperty(AWS_PROP_CERT_VALIDITY_STS_ONLY, "7"));
        certValidityTime = TimeUnit.SECONDS.convert(certValidityDays, TimeUnit.DAYS);

        // get the aws region

        awsRegion = System.getProperty(AWS_PROP_REGION_NAME);
    }

    public ResourceException error(String message) {
        return error(ResourceException.FORBIDDEN, message);
    }
    
    public ResourceException error(int errorCode, String message) {
        LOGGER.error(message);
        return new ResourceException(errorCode, message);
    }
    
    String getInstanceProperty(final Map<String, String> attributes, final String propertyName) {
        
        if (attributes == null) {
            LOGGER.error("getInstanceProperty: no attributes available");
            return null;
        }
    
        final String value = attributes.get(propertyName);
        if (value == null) {
            LOGGER.error("getInstanceProperty: " + propertyName + " attribute not available");
            return null;
        }
        
        return value;
    }
    
    boolean validateAWSAccount(final String awsAccount, final String docAccount, StringBuilder errMsg) {
        
        if (!awsAccount.equalsIgnoreCase(docAccount)) {
            LOGGER.error("ZTS AWS Domain Lookup account id: {}", awsAccount);
            errMsg.append("mismatch between account values - instance document: ").append(docAccount);
            return false;
        }
        
        return true;
    }
    
    boolean validateAWSProvider(final String provider, final String region, StringBuilder errMsg) {
        
        if (region == null) {
            errMsg.append("no region provided in instance document");
            return false;
        }
        
        final String suffix = "." + region;
        if (!provider.endsWith(suffix)) {
            errMsg.append("provider ").append(provider).append(" does not end with expected suffix ").append(region);
            return false;
        }
        
        return true;
    }
    
    boolean validateAWSInstanceId(final String reqInstanceId, final String docInstanceId,
            StringBuilder errMsg) {
        
        if (!reqInstanceId.equalsIgnoreCase(docInstanceId)) {
            errMsg.append("mismatch between instance-id values: request: ").append(reqInstanceId)
                .append(" vs. instance document: ").append(docInstanceId);
            return false;
        }
        
        return true;
    }
    
    boolean validateAWSSignature(final String document, final String signature, StringBuilder errMsg) {
        
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
    
    boolean validateAWSDocument(final String provider, AWSAttestationData info,
            final String awsAccount, final String instanceId, boolean checkTime,
            StringBuilder errMsg) {
        
        final String document = info.getDocument();
        if (!validateAWSSignature(document, info.getSignature(), errMsg)) {
            return false;
        }
        
        // convert our document into a struct that we can extract data
        
        Struct instanceDocument = JSON.fromString(document, Struct.class);
        if (instanceDocument == null) {
            errMsg.append("Unable to parse identity document");
            LOGGER.error("Identity Document: {}", document);
            return false;
        }
        
        if (!validateAWSProvider(provider, instanceDocument.getString(ATTR_REGION), errMsg)) {
            return false;
        }
        
        // verify that the account lookup and the account in the document match
        
        if (!validateAWSAccount(awsAccount, instanceDocument.getString(ATTR_ACCOUNT_ID), errMsg)) {
            return false;
        }
        
        // verify the request has the expected account id
        
        final String infoInstanceId = getInstanceId(info, instanceDocument);
        if (!validateAWSInstanceId(instanceId, infoInstanceId, errMsg)) {
            return false;
        }
        
        // verify that the boot up time for the instance is now

        return checkTime ? validateInstanceBootTime(instanceDocument, errMsg) : true;
    }
    
    String getInstanceId(AWSAttestationData info, Struct instanceDocument) {
        return instanceDocument.getString(ATTR_INSTANCE_ID);
    }
    
    private boolean validateInstanceBootTime(Struct instanceDocument, StringBuilder errMsg) {
        
        // first check to see if the boot time enforcement is enabled
        
        if (bootTimeOffset <= 0) {
            return true;
        }
        
        Timestamp bootTime = Timestamp.fromString(instanceDocument.getString(ATTR_PENDING_TIME));
        if (bootTime.millis() < System.currentTimeMillis() - bootTimeOffset) {
            errMsg.append("Instance boot time is not recent enough: ");
            errMsg.append(bootTime.toString());
            return false;
        }
        
        return true;
    }
    
    boolean validateCertRequestHostnames(final Map<String, String> attributes, final String domain,
            final String service, StringBuilder instanceId) {
        
        // make sure we have valid dns suffix specified
        
        if (dnsSuffix == null || dnsSuffix.isEmpty()) {
            LOGGER.error("No AWS DNS suffix specified for validation");
            return false;
        }
        
        // first check to see if we're given any hostnames to validate
        // if the list is empty then something is not right thus we'll
        // reject the request
        
        final String hostnames = getInstanceProperty(attributes, ZTS_INSTANCE_SAN_DNS);
        if (hostnames == null || hostnames.isEmpty()) {
            LOGGER.error("Request contains no SAN DNS entries for validation");
            return false;
        }
        
        // generate the expected hostname for check
        
        final String hostNameCheck = service + "." + domain.replace('.', '-') + "." + dnsSuffix;
        
        // validate the entries
        
        boolean hostCheck = false;
        boolean instanceIdCheck = false;
        
        String[] hosts = hostnames.split(",");
        
        // we only allow two hostnames in our AWS CSR:
        // service.<domain-with-dashes>.<dns-suffix>
        // <instance-id>.instanceid.athenz.<dns-suffix>
        
        if (hosts.length != 2) {
            LOGGER.error("Request does not contain expected number of SAN DNS entries: {}",
                    hosts.length);
            return false;
        }
        
        for (String host : hosts) {
            
            int idx = host.indexOf(ZTS_CERT_INSTANCE_ID);
            if (idx != -1) {
                instanceId.append(host, 0, idx);
                if (!dnsSuffix.equals(host.substring(idx + ZTS_CERT_INSTANCE_ID.length()))) {
                    LOGGER.error("Host: {} does not have expected instance id format", host);
                    return false;
                }
                
                instanceIdCheck = true;
            } else {
                if (!hostNameCheck.equals(host)) {
                    LOGGER.error("Unable to verify SAN DNS entry: {}", host);
                    return false;
                }
                hostCheck = true;
            }
        }

        // report error cases separately for easier debugging
        
        if (!instanceIdCheck) {
            LOGGER.error("Request does not contain expected instance id SAN DNS entry");
            return false;
        }
        
        if (!hostCheck) {
            LOGGER.error("Request does not contain expected host SAN DNS entry");
            return false;
        }
        
        return true;
    }
    
    @Override
    public InstanceConfirmation confirmInstance(InstanceConfirmation confirmation) {
        
        AWSAttestationData info = JSON.fromString(confirmation.getAttestationData(),
                AWSAttestationData.class);
        
        final Map<String, String> instanceAttributes = confirmation.getAttributes();
        final String instanceDomain = confirmation.getDomain();
        final String instanceService = confirmation.getService();
        
        // before doing anything else we want to make sure our
        // object has an associated aws account id
        
        final String awsAccount = getInstanceProperty(instanceAttributes, ZTS_INSTANCE_AWS_ACCOUNT);
        if (awsAccount == null) {
            throw error("Unable to extract AWS Account id");
        }
        
        // validate that the domain/service given in the confirmation
        // request match the attestation data
        
        final String serviceName = instanceDomain + "." + instanceService;
        if (!serviceName.equals(info.getRole())) {
            throw error("Service name mismatch: " + info.getRole() + " vs. " + serviceName);
        }
        
        // validate the certificate host names
        
        StringBuilder instanceId = new StringBuilder(256);
        if (!validateCertRequestHostnames(instanceAttributes, instanceDomain,
                instanceService, instanceId)) {
            throw error("Unable to validate certificate request hostnames");
        }
        
        // validate our document against given signature if one is provided
        // if there is no instance document then we're going to ask ZTS not
        // to issue SSH host certificates and request a certificate for
        // a default of 7 days only

        boolean instanceDocumentCreds = info.getDocument() != null;
        if (instanceDocumentCreds) {
            StringBuilder errMsg = new StringBuilder(256);
            if (!validateAWSDocument(confirmation.getProvider(), info,
                    awsAccount, instanceId.toString(), true, errMsg)) {
                LOGGER.error("validateAWSDocument: {}", errMsg.toString());
                throw error("Unable to validate AWS document: " + errMsg.toString());
            }
        }
            
        // set the attributes to be returned to the ZTS server

        setConfirmationAttributes(confirmation, instanceDocumentCreds);

        // verify that the temporary credentials specified in the request
        // can be used to assume the given role thus verifying the
        // instance identity
        
        if (!verifyInstanceIdentity(info, awsAccount)) {
            throw error("Unable to verify instance identity credentials");
        }
        
        return confirmation;
    }

    @Override
    public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) {
        
        // if we don't have an attestation data then we're going to
        // return not found exception unless the provider is required
        // to support refresh and in that case we'll return forbidden
        
        final String attestationData = confirmation.getAttestationData();
        if (attestationData == null || attestationData.isEmpty()) {
            int errorCode = supportRefresh ? ResourceException.FORBIDDEN : ResourceException.NOT_FOUND;
            throw error(errorCode, "No attestation data provided");
        }
        
        AWSAttestationData info = JSON.fromString(attestationData, AWSAttestationData.class);
        
        final Map<String, String> instanceAttributes = confirmation.getAttributes();
        final String instanceDomain = confirmation.getDomain();
        final String instanceService = confirmation.getService();
        
        // before doing anything else we want to make sure our
        // object has an associated aws account id
        
        final String awsAccount = getInstanceProperty(instanceAttributes, ZTS_INSTANCE_AWS_ACCOUNT);
        if (awsAccount == null) {
            throw error("Unable to extract AWS Account id");
        }

        // extract the instance id as well

        final String instanceId = getInstanceProperty(instanceAttributes, ZTS_INSTANCE_ID);
        if (instanceId == null) {
            throw error("Unable to extract Instance Id");
        }

        // validate that the domain/service given in the confirmation
        // request match the attestation data
        
        final String serviceName = instanceDomain + "." + instanceService;
        if (!serviceName.equals(info.getRole())) {
            throw error("Service name mismatch: " + info.getRole() + " vs. " + serviceName);
        }

        // validate our document against given signature if one is provided
        // if there is no instance document then we're going to ask ZTS not
        // to issue SSH host certificates

        boolean instanceDocumentCreds = info.getDocument() != null;
        if (instanceDocumentCreds) {
            StringBuilder errMsg = new StringBuilder(256);
            if (!validateAWSDocument(confirmation.getProvider(), info,
                    awsAccount, instanceId, false, errMsg)) {
                LOGGER.error("validateAWSDocument: {}", errMsg.toString());
                throw error("Unable to validate AWS document: " + errMsg.toString());
            }
        }

        // set the attributes to be returned to the ZTS server

        setConfirmationAttributes(confirmation, instanceDocumentCreds);
        
        // verify that the temporary credentials specified in the request
        // can be used to assume the given role thus verifying the
        // instance identity
        
        if (!verifyInstanceIdentity(info, awsAccount)) {
            throw error("Unable to verify instance identity credentials");
        }
        
        return confirmation;
    }
    
    void setConfirmationAttributes(InstanceConfirmation confirmation, boolean instanceDocumentCreds) {

        Map<String, String> attributes = new HashMap<>();
        attributes.put(ZTS_CERT_SSH, Boolean.toString(instanceDocumentCreds));
        if (!instanceDocumentCreds) {
            attributes.put(ZTS_CERT_EXPIRY_TIME, Long.toString(certValidityTime));
        }
        confirmation.setAttributes(attributes);
    }
    
    AWSSecurityTokenService getInstanceClient(AWSAttestationData info) {
        
        String access = info.getAccess();
        if (access == null || access.isEmpty()) {
            LOGGER.error("getInstanceClient: No access key id available in instance document");
            return null;
        }
        
        String secret = info.getSecret();
        if (secret == null || secret.isEmpty()) {
            LOGGER.error("getInstanceClient: No secret access key available in instance document");
            return null;
        }
        
        String token = info.getToken();
        if (token == null || token.isEmpty()) {
            LOGGER.error("getInstanceClient: No token available in instance document");
            return null;
        }
        
        BasicSessionCredentials creds = new BasicSessionCredentials(access, secret, token);

        return AWSSecurityTokenServiceClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(creds))
                .withRegion(Regions.fromName(awsRegion))
                .build();
    }
    
    boolean verifyInstanceIdentity(AWSAttestationData info, final String awsAccount) {
        
        GetCallerIdentityRequest req = new GetCallerIdentityRequest();
        
        try {
            AWSSecurityTokenService client = getInstanceClient(info);
            if (client == null) {
                LOGGER.error("verifyInstanceIdentity - unable to get AWS STS client object");
                return false;
            }
            
            GetCallerIdentityResult res = client.getCallerIdentity(req);
            if (res == null) {
                LOGGER.error("verifyInstanceIdentity - unable to get caller identity");
                return false;
            }
             
            String arn = "arn:aws:sts::" + awsAccount + ":assumed-role/" + info.getRole() + "/";
            if (!res.getArn().startsWith(arn)) {
                LOGGER.error("verifyInstanceIdentity - ARN mismatch - request: {} caller-idenity: {}",
                        arn, res.getArn());
                return false;
            }
            
            return true;
            
        } catch (Exception ex) {
            LOGGER.error("CloudStore: verifyInstanceIdentity - unable get caller identity: {}",
                    ex.getMessage());
            return false;
        }
    }
}
