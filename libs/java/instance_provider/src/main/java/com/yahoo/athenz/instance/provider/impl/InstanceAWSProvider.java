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

import java.util.*;
import java.util.concurrent.TimeUnit;

import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigCsv;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigLong;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;

import javax.net.ssl.*;

import static com.yahoo.athenz.common.server.util.config.ConfigManagerSingleton.CONFIG_MANAGER;

public class InstanceAWSProvider implements InstanceProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceAWSProvider.class);

    static final String ATTR_ACCOUNT_ID   = "accountId";
    static final String ATTR_REGION       = "region";
    static final String ATTR_PENDING_TIME = "pendingTime";
    static final String ATTR_INSTANCE_ID  = "instanceId";
    static final String ATTR_PRIVATE_IP   = "privateIp";

    static final String AWS_PROP_BOOT_TIME_OFFSET  = "athenz.zts.aws_boot_time_offset";
    static final String AWS_PROP_DNS_SUFFIX        = "athenz.zts.aws_dns_suffix";
    static final String AWS_PROP_REGION_NAME       = "athenz.zts.aws_region_name";
    static final String AWS_PROP_EKS_DNS_SUFFIX    = "athenz.zts.aws_eks_dns_suffix";
    static final String AWS_PROP_EKS_CLUSTER_NAMES = "athenz.zts.aws_eks_cluster_names";

    static final String AWS_PROP_CERT_VALIDITY_STS_ONLY = "athenz.zts.aws_cert_validity_sts_only";

    DynamicConfigLong bootTimeOffsetSeconds; // boot time offset in seconds
    DynamicConfigCsv eksClusterNames;        // list of eks cluster names

    long certValidityTime;                   // cert validity for STS creds only case
    boolean supportRefresh = false;
    String awsRegion;
    Set<String> dnsSuffixes = null;
    List<String> eksDnsSuffixes = null;
    InstanceAWSUtils awsUtils = null;

    public long getTimeOffsetInMilli() {
        return bootTimeOffsetSeconds.get() * 1000;
    }

    @Override
    public Scheme getProviderScheme() {
        return Scheme.HTTP;
    }

    @Override
    public void initialize(String provider, String providerEndpoint, SSLContext sslContext,
            KeyStore keyStore) {

        // create our helper object to validate aws documents

        awsUtils = new InstanceAWSUtils();

        // how long the instance must be booted in the past before we
        // stop validating the instance requests

        long timeout = TimeUnit.SECONDS.convert(5, TimeUnit.MINUTES);
        bootTimeOffsetSeconds = new DynamicConfigLong(CONFIG_MANAGER, AWS_PROP_BOOT_TIME_OFFSET, timeout);

        // get our dynamic list of eks cluster names

        eksClusterNames = new DynamicConfigCsv(CONFIG_MANAGER, AWS_PROP_EKS_CLUSTER_NAMES, null);

        // determine the dns suffix. if this is not specified we'll
        // be rejecting all entries

        dnsSuffixes = new HashSet<>();
        final String dnsSuffix = System.getProperty(AWS_PROP_DNS_SUFFIX);
        if (StringUtil.isEmpty(dnsSuffix)) {
            LOGGER.error("AWS DNS Suffix not specified - no instance requests will be authorized");
        } else {
            dnsSuffixes.addAll(Arrays.asList(dnsSuffix.split(",")));
        }

        eksDnsSuffixes = InstanceUtils.processK8SDnsSuffixList(AWS_PROP_EKS_DNS_SUFFIX);

        // default certificate expiry for requests without instance
        // identity document

        int certValidityDays = Integer.parseInt(System.getProperty(AWS_PROP_CERT_VALIDITY_STS_ONLY, "7"));
        certValidityTime = TimeUnit.MINUTES.convert(certValidityDays, TimeUnit.DAYS);

        // get the aws region

        awsRegion = System.getProperty(AWS_PROP_REGION_NAME);
    }

    protected Set<String> getDnsSuffixes() {
        return dnsSuffixes;
    }

    protected List<String> getEksDnsSuffixes() {
        return eksDnsSuffixes;
    }

    protected List<String> getEksClusterNames() {
        return eksClusterNames.getStringsList();
    }

    public ProviderResourceException error(String message) {
        return error(ProviderResourceException.FORBIDDEN, message);
    }
    
    public ProviderResourceException error(int errorCode, String message) {
        LOGGER.error(message);
        return new ProviderResourceException(errorCode, message);
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

    protected boolean validateAWSDocument(final String provider, AWSAttestationData info,
            final String awsAccount, final String instanceId, boolean checkTime,
            StringBuilder privateIp, StringBuilder errMsg) {
        
        final String document = info.getDocument();
        if (!awsUtils.validateAWSSignature(document, info.getSignature(), errMsg)) {
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
        
        final String infoInstanceId = getInstanceId(info, instanceDocument, instanceId);
        if (!validateAWSInstanceId(instanceId, infoInstanceId, errMsg)) {
            return false;
        }

        // save the private ip

        final String ip = instanceDocument.getString(ATTR_PRIVATE_IP);
        if (ip != null) {
            privateIp.append(ip);
        }

        // verify that the boot up time for the instance is now

        return !checkTime || validateInstanceBootTime(instanceDocument, errMsg);
    }
    
    protected String getInstanceId(AWSAttestationData info, Struct instanceDocument, final String reqInstanceId) {
        return instanceDocument.getString(ATTR_INSTANCE_ID);
    }
    
    private boolean validateInstanceBootTime(Struct instanceDocument, StringBuilder errMsg) {
        
        // first check to see if the boot time enforcement is enabled
        
        if (getTimeOffsetInMilli() <= 0) {
            return true;
        }
        
        Timestamp bootTime = Timestamp.fromString(instanceDocument.getString(ATTR_PENDING_TIME));
        if (bootTime.millis() < System.currentTimeMillis() - getTimeOffsetInMilli()) {
            errMsg.append("Instance boot time is not recent enough: ");
            errMsg.append(bootTime);
            return false;
        }
        
        return true;
    }
    
    @Override
    public InstanceConfirmation confirmInstance(InstanceConfirmation confirmation) throws ProviderResourceException {
        
        AWSAttestationData info = JSON.fromString(confirmation.getAttestationData(),
                AWSAttestationData.class);
        
        final Map<String, String> instanceAttributes = confirmation.getAttributes();
        final String instanceDomain = confirmation.getDomain();
        final String instanceService = confirmation.getService();
        
        // before doing anything else we want to make sure our
        // object has an associated aws account id
        
        final String awsAccount = InstanceUtils.getInstanceProperty(instanceAttributes, ZTS_INSTANCE_AWS_ACCOUNT);
        if (StringUtil.isEmpty(awsAccount)) {
            throw error("Unable to extract AWS Account id");
        }
        
        // validate that the domain/service given in the confirmation
        // request match the attestation data. the role can represent
        // either one of two formats: <domain>.<service> or <service>.
        // with just the <service> format we already verify the <domain>
        // component based on the aws account id in the arn
        
        final String serviceName = instanceDomain + "." + instanceService;
        if (!(serviceName.equals(info.getRole()) || instanceService.equals(info.getRole()))) {
            throw error("Service name mismatch: " + info.getRole() + " vs. " + serviceName);
        }
        
        // validate the certificate host names
        
        StringBuilder instanceId = new StringBuilder(256);
        validateSanDnsNames(instanceAttributes, instanceDomain, instanceService, instanceId);
        
        // validate our document against given signature if one is provided
        // if there is no instance document then we're going to ask ZTS not
        // to issue SSH host certificates and request a certificate for
        // a default of 7 days only

        boolean instanceDocumentCreds = info.getDocument() != null;
        StringBuilder privateIp = new StringBuilder(64);
        if (instanceDocumentCreds) {
            StringBuilder errMsg = new StringBuilder(256);
            if (!validateAWSDocument(confirmation.getProvider(), info, awsAccount,
                    instanceId.toString(), true, privateIp, errMsg)) {
                throw error("Unable to validate AWS document: " + errMsg);
            }
        }
            
        // set the attributes to be returned to the ZTS server

        setConfirmationAttributes(confirmation, instanceDocumentCreds, privateIp.toString(), instanceId.toString());

        // verify that the temporary credentials specified in the request
        // can be used to assume the given role thus verifying the
        // instance identity
        
        if (!verifyInstanceIdentity(info, awsAccount)) {
            throw error("Unable to verify instance identity credentials");
        }
        
        return confirmation;
    }

    @Override
    public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) throws ProviderResourceException {
        
        // if we don't have an attestation data then we're going to
        // return not found exception unless the provider is required
        // to support refresh and in that case we'll return forbidden
        
        final String attestationData = confirmation.getAttestationData();
        if (attestationData == null || attestationData.isEmpty()) {
            int errorCode = supportRefresh ? ProviderResourceException.FORBIDDEN : ProviderResourceException.NOT_FOUND;
            throw error(errorCode, "No attestation data provided");
        }
        
        AWSAttestationData info = JSON.fromString(attestationData, AWSAttestationData.class);
        
        final Map<String, String> instanceAttributes = confirmation.getAttributes();
        final String instanceDomain = confirmation.getDomain();
        final String instanceService = confirmation.getService();
        
        // before doing anything else we want to make sure our
        // object has an associated aws account id
        
        final String awsAccount = InstanceUtils.getInstanceProperty(instanceAttributes, ZTS_INSTANCE_AWS_ACCOUNT);
        if (StringUtil.isEmpty(awsAccount)) {
            throw error("Unable to extract AWS Account id");
        }

        // validate that the domain/service given in the confirmation
        // request match the attestation data. the role can represent
        // either one of two formats: <domain>.<service> or <service>.
        // with just the <service> format we already verify the <domain>
        // component based on the aws account id in the arn

        final String serviceName = instanceDomain + "." + instanceService;
        if (!(serviceName.equals(info.getRole()) || instanceService.equals(info.getRole()))) {
            throw error("Service name mismatch: " + info.getRole() + " vs. " + serviceName);
        }

        // validate the certificate host names

        StringBuilder instanceId = new StringBuilder(256);
        validateSanDnsNames(instanceAttributes, instanceDomain, instanceService, instanceId);

        // validate our document against given signature if one is provided
        // if there is no instance document then we're going to ask ZTS not
        // to issue SSH host certificates

        boolean instanceDocumentCreds = info.getDocument() != null;
        StringBuilder privateIp = new StringBuilder(64);
        if (instanceDocumentCreds) {
            StringBuilder errMsg = new StringBuilder(256);
            if (!validateAWSDocument(confirmation.getProvider(), info, awsAccount,
                    instanceId.toString(), false, privateIp, errMsg)) {
                throw error("Unable to validate AWS document: " + errMsg);
            }
        }

        // set the attributes to be returned to the ZTS server

        setConfirmationAttributes(confirmation, instanceDocumentCreds, privateIp.toString(), instanceId.toString());
        
        // verify that the temporary credentials specified in the request
        // can be used to assume the given role thus verifying the
        // instance identity
        
        if (!verifyInstanceIdentity(info, awsAccount)) {
            throw error("Unable to verify instance identity credentials");
        }
        
        return confirmation;
    }

    public void validateSanDnsNames(final Map<String, String> instanceAttributes, final String instanceDomain,
                                    final String instanceService, StringBuilder instanceId) throws ProviderResourceException {
        if (!InstanceUtils.validateCertRequestSanDnsNames(instanceAttributes, instanceDomain,
                instanceService, getDnsSuffixes(), getEksDnsSuffixes(), getEksClusterNames(),
                true, instanceId, null)) {
            throw error("Unable to validate certificate request hostnames");
        }
    }

    protected void setConfirmationAttributes(InstanceConfirmation confirmation, boolean instanceDocumentCreds,
            final String privateIp, final String instanceId) {

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_CERT_SSH, Boolean.toString(instanceDocumentCreds));
        if (!instanceDocumentCreds) {
            attributes.put(InstanceProvider.ZTS_CERT_EXPIRY_TIME, Long.toString(certValidityTime));
        }
        if (!privateIp.isEmpty()) {
            attributes.put(InstanceProvider.ZTS_INSTANCE_PRIVATE_IP, privateIp);
        }
        if (!instanceId.isEmpty()) {
            attributes.put(InstanceProvider.ZTS_ATTESTED_SSH_CERT_PRINCIPALS, instanceId);
        }
        confirmation.setAttributes(attributes);
    }

    StsClient getInstanceClient(AWSAttestationData info) {
        
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

        AwsBasicCredentials credentials = AwsBasicCredentials.builder()
                .accessKeyId(access)
                .secretAccessKey(secret)
                .build();

        // Create Static Credentials Provider

        StaticCredentialsProvider credentialsProvider = StaticCredentialsProvider.create(credentials);

        // Create STS Client

        return StsClient.builder().credentialsProvider(credentialsProvider).region(Region.of(awsRegion)).build();
    }
    
    boolean verifyInstanceIdentity(AWSAttestationData info, final String awsAccount) {

        try {
            StsClient stsClient = getInstanceClient(info);
            if (stsClient == null) {
                LOGGER.error("verifyInstanceIdentity - unable to get AWS STS client object");
                return false;
            }

            GetCallerIdentityRequest request = GetCallerIdentityRequest.builder().build();
            GetCallerIdentityResponse response = stsClient.getCallerIdentity(request);
            if (response == null) {
                LOGGER.error("verifyInstanceIdentity - unable to get caller identity");
                return false;
            }
             
            String arn = "arn:aws:sts::" + awsAccount + ":assumed-role/" + info.getRole() + "/";
            if (!response.arn().startsWith(arn)) {
                LOGGER.error("verifyInstanceIdentity - ARN mismatch - request: {} caller-identity: {}",
                        arn, response.arn());
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
