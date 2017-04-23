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
package com.yahoo.athenz.zts.store;

import java.io.File;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.zts.AWSInstanceInformation;
import com.yahoo.athenz.zts.AWSTemporaryCredentials;
import com.yahoo.athenz.zts.Identity;
import com.yahoo.athenz.zts.InstanceInformation;
import com.yahoo.athenz.zts.OSTKInstanceInformation;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.utils.ZTSUtils;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;

public class CloudStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(CloudStore.class);

    public static final String ZTS_SSH_HOST = "host";
    public static final String ZTS_SSH_USER = "user";
    public static final String ZTS_SSH_TYPE = "certtype";
    
    private static final String ATTR_ACCOUNT_ID = "accountId";
    private static final String ATTR_PENDING_TIME = "pendingTime";
    
    String awsRole = null;
    String awsCloud = null;
    String awsProfile = null;
    String awsAccount = null;
    String awsDomain = null;
    String awsService = null;
    String awsRegion = null;
    boolean awsEnabled = false;
    CertSigner certSigner = null;
    BasicSessionCredentials credentials = null;
    Map<String, String> cloudAccountCache = null;
    int credsUpdateTime = 900;
    String x509CACertificate = null;  // public key certificate of the certifying authority in PEM format
    String sshHostCertificate = null; // ssh host certificate signer certificate
    String sshUserCertificate = null; // ssh user certificate signer certificate
    PublicKey awsPublicKey = null;    // AWS public key for validating instance documents
    private HttpClient httpClient = null;
    protected long bootTimeOffset;

    private static ScheduledExecutorService scheduledThreadPool;
    
    public CloudStore(CertSigner certSigner) {
        
        // save our cert signer and generate the PEM output of the certificate
        
        this.certSigner = certSigner;
        if (certSigner != null) {
            x509CACertificate = certSigner.getCACertificate();
            sshHostCertificate = certSigner.getSSHCertificate(ZTS_SSH_HOST);
            sshUserCertificate = certSigner.getSSHCertificate(ZTS_SSH_USER);
        }
        
        // initialize our account cache
        
        cloudAccountCache = new HashMap<String, String>();

        // Instantiate and start our HttpClient
        
        httpClient = new HttpClient();
        httpClient.setFollowRedirects(false);
        try {
            httpClient.start();
        } catch (Exception ex) {
            LOGGER.error("CloudStore: unable to start http client: " + ex.getMessage());
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Http client not available");
        }
        
        // let's retrieve our AWS public certificate which is posted here:
        // http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html
        
        String awsCertFileName = System.getProperty(ZTSConsts.ZTS_PROP_AWS_PUBLIC_CERT);
        if (awsCertFileName != null && !awsCertFileName.isEmpty()) {
            File awsCertFile = new File(awsCertFileName);
            X509Certificate awsCert = Crypto.loadX509Certificate(awsCertFile);
            awsPublicKey = awsCert.getPublicKey();
        }
        
        // check to see if we are given region name
        
        awsRegion = System.getProperty(ZTSConsts.ZTS_PROP_AWS_REGION_NAME);
        
        // how long the instance must be booted in the past before we
        // stop validating the instance requests
        
        long timeout = TimeUnit.SECONDS.convert(5, TimeUnit.MINUTES);
        bootTimeOffset = 1000 * Long.parseLong(
                System.getProperty(ZTSConsts.ZTS_PROP_AWS_BOOT_TIME_OFFSET, Long.toString(timeout)));
        
        // initialize aws support
        
        awsEnabled = Boolean.parseBoolean(System.getProperty(ZTSConsts.ZTS_PROP_AWS_ENABLED, "false"));
        initializeAwsSupport();
    }
    
    void close() {
        if (httpClient != null) {
            try {
                httpClient.stop();
            } catch (Exception e) {
            }
        }
    }
    
    public void setHttpClient(HttpClient client) {
        if (httpClient != null) {
            try {
                httpClient.stop();
            } catch (Exception e) {
            }
        }
        httpClient = client;
    }
    
    public boolean isAwsEnabled() {
        return awsEnabled;
    }
    
    void initializeAwsSupport() {
        
        // these operations require initialization of aws objects so
        // we'll process them only if we have been configured to run in aws

        if (!awsEnabled) {
            return;
        }
        
        // initialize and load our bootstrap data
        
        if (!loadBootMetaData()) {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Unable to load boot data");
        }
        
        // finally fetch the role credentials
        
        if (!fetchRoleCredentials())  {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Unable to fetch aws role credentials");
        }

        // Start our thread to get aws temporary credentials

        credsUpdateTime = ZTSUtils.retrieveConfigSetting(ZTSConsts.ZTS_PROP_AWS_CREDS_UPDATE_TIMEOUT, 900);

        scheduledThreadPool = Executors.newScheduledThreadPool(1);
        scheduledThreadPool.scheduleAtFixedRate(new RoleCredentialsFetcher(), credsUpdateTime,
                credsUpdateTime, TimeUnit.SECONDS);
    }
    
    public AmazonS3 getS3Client() {
        
        if (!awsEnabled) {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "AWS Support not enabled");
        }
        
        if (credentials == null) {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "AWS Role credentials are not available");
        }
        
        AmazonS3Client s3 = new AmazonS3Client(credentials);
        if (awsRegion != null) {
            s3.setRegion(Region.getRegion(Regions.fromName(awsRegion)));
        }
        return s3;
    }

    boolean loadBootMetaData() {
        
        // first load the dynamic document
        
        String document = getMetaData("/dynamic/instance-identity/document");
        if (document == null) {
            return false;
        }
        
        try {
            if (!parseInstanceInfo(document)) {
                return false;
            }
        } catch (Exception ex) {
            LOGGER.error("CloudStore: unable to parse instance identity document: "
                    + document + ", error: " + ex.getMessage());
            return false;
        }
        
        // then the document signature
        
        String docSignature = getMetaData("/dynamic/instance-identity/pkcs7");
        if (docSignature == null) {
            return false;
        }
        
        // next the iam profile data
        
        String iamRole = getMetaData("/meta-data/iam/info");
        if (iamRole == null) {
            return false;
        }
        
        // now parse and extract the profile details. we'll catch
        // all possible index out of bounds exceptions here and just
        // report the error and return false
        
        try {
            if (!parseIamRoleInfo(iamRole)) {
                return false;
            }
        } catch (Exception ex) {
            LOGGER.error("CloudStore: unable to parse iam role data: " + iamRole
                    + ", error: " + ex.getMessage());
            return false;
        }
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("CloudStore: service meta information:");
            LOGGER.debug("CloudStore:   cloud:   " + awsCloud);
            LOGGER.debug("CloudStore:   role:    " + awsRole);
            LOGGER.debug("CloudStore:   profile: " + awsProfile);
            LOGGER.debug("CloudStore:   account: " + awsAccount);
            LOGGER.debug("CloudStore:   domain:  " + awsDomain);
            LOGGER.debug("CloudStore:   service: " + awsService);
            LOGGER.debug("CloudStore:   region:  " + awsRegion);
        }
        return true;
    }
    
    boolean parseInstanceInfo(String document) {
        
        Struct instStruct = null;
        try {
            instStruct = JSON.fromString(document, Struct.class);
        } catch (Exception ex) {
            LOGGER.error("CloudStore: unable to parse instance identity document: "
                    + ex.getMessage());
        }
        
        if (instStruct == null) {
            LOGGER.error("CloudStore: unable to parse instance identity document: " + document);
            return false;
        }

        // if we don't extract our account id here, we'll try
        // to retrieve it from our iam role name
        
        awsAccount = instStruct.getString("accountId");
        
        // if we're overriding the region name, then we'll
        // extract that value here
        
        if (awsRegion == null || awsRegion.isEmpty()) {
            awsRegion = instStruct.getString("region");
            if (awsRegion == null || awsRegion.isEmpty()) {
                LOGGER.error("CloudStore: unable to extract region from instance identity document: " + document);
                return false;
            }
        }
        
        return true;
    }
        
    boolean parseIamRoleInfo(String iamRole) {
        
        Struct iamRoleStruct = null;
        try {
            iamRoleStruct = JSON.fromString(iamRole, Struct.class);
        } catch (Exception ex) {
            LOGGER.error("CloudStore: unable to parse iam role data: " + ex.getMessage());
        }
        
        if (iamRoleStruct == null) {
            LOGGER.error("CloudStore: unable to parse iam role data: " + iamRole);
            return false;
        }
        
        // extract and parse our profile arn
        // "InstanceProfileArn" : "arn:aws:iam::1111111111111:instance-profile/iaas.athenz.zts,athenz",

        String profileArn = iamRoleStruct.getString("InstanceProfileArn");
        if (profileArn == null || profileArn.isEmpty()) {
            LOGGER.error("CloudStore: unable to extract InstanceProfileArn from iam role data: " + iamRole);
            return false;
        }
        
        if (!parseInstanceProfileArn(profileArn)) {
            return false;
        }
        
        return true;
    }
    
    boolean parseInstanceProfileArn(String profileArn) {
        
        // "InstanceProfileArn" : "arn:aws:iam::1111111111111:instance-profile/iaas.athenz.zts,athenz",

        if (!profileArn.startsWith("arn:aws:iam::")) {
            LOGGER.error("CloudStore: InstanceProfileArn does not start with 'arn:aws:iam::' : " + profileArn);
            return false;
        }
        
        int idx = profileArn.indexOf(":instance-profile/");
        if (idx == -1) {
            LOGGER.error("CloudStore: unable to parse InstanceProfileArn: " + profileArn);
            return false;
        }
        
        awsProfile = profileArn.substring(idx + ":instance-profile/".length());
        
        // we should already have our aws account data but in case we didn't
        // get it from our instance document, we'll extract it from the profile name
        
        if (awsAccount == null || awsAccount.isEmpty()) {
            awsAccount = profileArn.substring("arn:aws:iam::".length(), idx);
        }
        
        // make sure we have valid profile and account data
        
        if (awsProfile.isEmpty() || awsAccount.isEmpty()) {
            LOGGER.error("CloudStore: unable to extract profile/account data from InstanceProfileArn: " + profileArn);
            return false;
        }
        
        // we need to extract the role and cloud names from the profile
        
        String[] comps = awsProfile.split(",");
        if (comps.length != 2) {
            LOGGER.error("CloudStore: unable to extract role/cloud name from profile: " + awsProfile);
            return false;
        }
        
        awsRole = comps[0];
        awsCloud = comps[1];
        
        // retrieve our domain and service names from our role name
        
        idx = awsRole.lastIndexOf('.');
        if (idx == -1) {
            LOGGER.error("CloudStore: malformed service name: " + awsRole);
            return false;
        }
        
        awsDomain = awsRole.substring(0, idx);
        awsService = awsRole.substring(idx + 1);
        
        // make sure we have valid service and domain values
        
        if (awsDomain.isEmpty() || awsService.isEmpty()) {
            LOGGER.error("CloudStore: unable to extract domain/service data from profile: " + awsRole);
            return false;
        }
        
        return true;
    }
    
    boolean fetchRoleCredentials() {
        
        // verify that we have a valid awsRole already retrieved
        
        if (awsRole == null || awsRole.isEmpty()) {
            LOGGER.error("CloudStore: awsRole is not avaialble to fetch role credentials");
            return false;
        }
        
        String creds = getMetaData("/meta-data/iam/security-credentials/" + awsRole);
        if (creds == null) {
            return false;
        }
        
        Struct credsStruct = null;
        try {
            credsStruct = JSON.fromString(creds, Struct.class);
        } catch (Exception ex) {
            LOGGER.error("CloudStore: unable to parse role credentials data: " + ex.getMessage());
        }
        
        if (credsStruct == null) {
            LOGGER.error("CloudStore: unable to parse role credentials data: " + creds);
            return false;
        }
        
        String accessKeyId = credsStruct.getString("AccessKeyId");
        String secretAccessKey = credsStruct.getString("SecretAccessKey");
        String token = credsStruct.getString("Token");
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("CloudStore: access key id: " + accessKeyId);
            LOGGER.debug("CloudStore: secret access key: " + secretAccessKey);
        }
        
        try {
            credentials = new BasicSessionCredentials(accessKeyId, secretAccessKey, token);
        } catch (Exception ex) {
            LOGGER.error("CloudStore: unable to generate session credentials from: "
                    + creds + ", error: " + ex.getMessage());
            return false;
        }
        
        return true;
    }
    
    String getMetaData(String path) {
        
        final String baseUri = "http://169.254.169.254/latest";
        ContentResponse response = null;
        try {
            response = httpClient.GET(baseUri + path);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            LOGGER.error("CloudStore: unable to fetch requested uri '" + path + "': "
                    + e.getMessage());
            return null;
        }
        if (response.getStatus() != 200) {
            LOGGER.error("CloudStore: unable to fetch requested uri '" + path +
                    "' status: " + response.getStatus());
            return null;
        }
        
        String data = response.getContentAsString();
        if (data == null || data.isEmpty()) {
            LOGGER.error("CloudStore: received empty response from uri '" + path +
                    "' status: " + response.getStatus());
            return null;
        }
        
        return data;
    }
    
    AssumeRoleRequest getAssumeRoleRequest(String account, String roleName, String principal) {
        
        // assume the target role to get the credentials for the client
        // aws format is arn:aws:iam::<account-id>:role/<role-name>
    
        String arn = "arn:aws:iam::" + account + ":role/" + roleName;
        
        AssumeRoleRequest req = new AssumeRoleRequest();
        req.setRoleArn(arn);
        req.setRoleSessionName(principal);
        
        return req;
    }
    
    AWSSecurityTokenServiceClient getTokenServiceClient() {
        return new AWSSecurityTokenServiceClient(credentials);
    }
    
    public AWSTemporaryCredentials assumeAWSRole(String account, String roleName, String principal) {

        if (!awsEnabled) {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "AWS Support not enabled");
        }

        AssumeRoleRequest req = getAssumeRoleRequest(account, roleName, principal);
        
        AWSTemporaryCredentials tempCreds = null;
        try {
            AWSSecurityTokenServiceClient client = getTokenServiceClient();
            AssumeRoleResult res = client.assumeRole(req);
        
            Credentials awsCreds = res.getCredentials();
            tempCreds = new AWSTemporaryCredentials()
                .setAccessKeyId(awsCreds.getAccessKeyId())
                .setSecretAccessKey(awsCreds.getSecretAccessKey())
                .setSessionToken(awsCreds.getSessionToken())
                .setExpiration(Timestamp.fromMillis(awsCreds.getExpiration().getTime()));
            
        } catch (Exception ex) {
            LOGGER.error("CloudStore: assumeAWSRole - unable to assume role: " + ex.getMessage());
            return null;
        }
        
        return tempCreds;
    }

    public String getAWSAccount(String domainName) {
        return cloudAccountCache.get(domainName);
    }
    
    void updateAccount(String domainName, String account) {
        
        /* if we have a value specified for the domain, then we're just
         * going to insert it into our map and update the record. If
         * the new value is not present and we had a value stored before
         * then let's remove it */

        if (account != null && !account.isEmpty()) {
            cloudAccountCache.put(domainName, account);
        } else if (cloudAccountCache.get(domainName) != null) {
            cloudAccountCache.remove(domainName);
        }
    }
    
    public boolean verifyInstanceDocument(OSTKInstanceInformation info, String publicKey) {

        // for now we're only validating the document signature

        boolean verified = false;
        try {
            final PublicKey pub = Crypto.loadPublicKey(publicKey);
            verified = Crypto.verify(info.getDocument(), pub, info.getSignature());
            if (!verified) {
                LOGGER.error("verifyInstanceDocument: OSTK document signature did not match");
        } else if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("verifyInstanceDocument: OSTK document signature matched");
        }
        } catch (Exception ex) {
            LOGGER.error("verifyInstanceDocument: Unable to verify signature: {}",
                    ex.getMessage());
        }
        return verified;
    }
    
    public boolean verifyInstanceDocument(AWSInstanceInformation info, String account) {
        
        final String document = info.getDocument();
        if (document == null || document.isEmpty()) {
            LOGGER.error("verifyInstanceDocument: AWS instance document is empty");
            return false;
        }
        
        final String signature = info.getSignature();
        if (signature == null || signature.isEmpty()) {
            LOGGER.error("verifyInstanceDocument: AWS instance document signature is empty");
            return false;
        }
        
        if (awsPublicKey == null) {
            LOGGER.error("verifyInstanceDocument: AWS Public key is not available");
            return false;
        }
        
        boolean valid = false;
        try {
            valid = Crypto.validatePKCS7Signature(document, signature, awsPublicKey);
        } catch (CryptoException ex) {
             LOGGER.error("verifyInstanceDocument: unable to verify AWS instance document: {}",
                     ex.getMessage());
        }
        
        if (!valid) {
            LOGGER.error("verifyInstanceDocument: AWS Instance document signature mismatch");
            return false;
        }
        
        // convert our document into a struct that we can extract data
        
        Struct instanceDocument = null;
        try {
            instanceDocument = JSON.fromString(info.getDocument(), Struct.class);
        } catch (Exception ex) {
            LOGGER.error("verifyInstanceDocument: failed to parse: {} error: {}",
                    info.getDocument(), ex.getMessage());
        }
        
        if (instanceDocument == null) {
            LOGGER.error("verifyInstanceDocument: unable to parse instance document");
            return false;
        }
        
        // verify that the account lookup and the account in the document match
        
        final String docAccount = instanceDocument.getString(ATTR_ACCOUNT_ID);
        if (!account.equalsIgnoreCase(docAccount)) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("verifyInstanceDocument: ZTS domain account lookup: " + account);
                LOGGER.debug("verifyInstanceDocument: Instance document account: " + docAccount);
            }
            LOGGER.error("verifyInstanceDocument: mismatch between account values: "
                    + " domain lookup: {} vs. instance document: {}", account, docAccount);
            return false;
        }
        
        // verify that the boot up time for the instance is now

        Timestamp bootTime = instanceDocument.getTimestamp(ATTR_PENDING_TIME);
        if (bootTime.millis() < System.currentTimeMillis() - bootTimeOffset) {
            LOGGER.error("verifyInstanceDocument: instance boot time is not recent enough");
            return false;
        }
        
        // verify that the temporary credentials specified in the request
        // can be used to assume the given role thus verifying the
        // instance identity
        
        if (!verifyInstanceIdentity(info)) {
            LOGGER.error("verifyInstanceDocument: unable to verify instance identity");
            return false;
        }
        
        return true;
    }
    
    public boolean verifyInstanceDocument(InstanceInformation info, String publicKey) {
        
        // for now we don't have support for this api and we're just
        // going to return false

        return false;
    }
    
    class RoleCredentialsFetcher implements Runnable {
        
        @Override
        public void run() {

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("RoleCredentialsFetcher: Starting aws role credentials fetcher task...");
            }
            
            try {
                fetchRoleCredentials();
            } catch (Exception ex) {
                LOGGER.error("RoleCredentialsFetcher: unable to fetch aws role credentials: "
                        + ex.getMessage());
            }
        }
    }

    AWSSecurityTokenServiceClient getInstanceClient(AWSInstanceInformation info) {
        
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
    
    public boolean verifyInstanceIdentity(AWSInstanceInformation info) {

        StringBuilder serviceBuilder = new StringBuilder(256);
        serviceBuilder.append(info.getDomain()).append('.').append(info.getService());
        String service = serviceBuilder.toString();
        
        GetCallerIdentityRequest req = new GetCallerIdentityRequest();
        
        try {
            AWSSecurityTokenServiceClient client = getInstanceClient(info);
            if (client == null) {
                LOGGER.error("CloudStore: verifyInstanceIdentity - unable to get AWS STS client object");
                return false;
            }
            
            GetCallerIdentityResult res = client.getCallerIdentity(req);
            if (res == null) {
                LOGGER.error("CloudStore: verifyInstanceIdentity - unable to get caller identity");
                return false;
            }
            
            String arn = "arn:aws:sts::" + info.getAccount() + ":assumed-role/" + service + "/";
            if (!res.getArn().startsWith(arn)) {
                LOGGER.error("CloudStore: verifyInstanceIdentity - ARN mismatch - request:" +
                        arn + " caller-identity: " + res.getArn());
                return false;
            }
            
            return true;
            
        } catch (Exception ex) {
            LOGGER.error("CloudStore: verifyInstanceIdentity - unable get caller identity: " + ex.getMessage());
            return false;
        }
    }

    public Identity generateIdentity(String cn, String csr, String ssh, String sshCertType) {

        // first verify that the cn in the certificate is valid
        
        csr = (csr != null && !csr.isEmpty()) ? csr : null;
        ssh = (ssh != null && !ssh.isEmpty()) ? ssh : null;

        // first verify that the cn in the certificate is valid
        
        if (csr != null) {
            PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
            if (certReq == null) {
                return null;
            }
            
            int idx = cn.lastIndexOf('.');
            if (idx == -1) {
                return null;
            }
            if (!ZTSUtils.verifyCertificateRequest(certReq, cn.substring(0, idx), cn.substring(idx + 1), null, null)) {
                return null;
            }
        }
        
        String sshReqType = null;
        String sshCertificateSigner = null;
        if (ssh != null) {
            sshReqType = getSshKeyReqType(ssh);
            if (sshReqType == null) {
                return null;
            }
            
            // check if we need to validate the type
            
            if (sshCertType != null && !sshReqType.equals(sshCertType)) {
                LOGGER.error("generateIdentity: Unable to validate ssh cert type: request {} vs required {}",
                        sshCertType, sshReqType);
                return null;
            }
            
            if (sshHostCertificate == null) {
                sshHostCertificate = certSigner.getSSHCertificate(ZTS_SSH_HOST);
            }
            if (sshUserCertificate == null) {
                sshUserCertificate = certSigner.getSSHCertificate(ZTS_SSH_USER);
            }
            sshCertificateSigner = sshReqType.equals(ZTS_SSH_HOST) ? sshHostCertificate : sshUserCertificate;
        }

        // generate a certificate for this certificate request

        String x509Cert = null;
        if (csr != null) {
            x509Cert = certSigner.generateX509Certificate(csr);
            if (x509Cert == null || x509Cert.isEmpty()) {
                LOGGER.error("generateIdentity: CertSigner was unable to generate X509 certificate");
                return null;
            }
            
            if (x509CACertificate == null) {
                x509CACertificate = certSigner.getCACertificate();
            }
        }
        
        String sshCert = null;
        if (ssh != null) {
            sshCert = certSigner.generateSSHCertificate(ssh);
            if (sshCert == null || sshCert.isEmpty()) {
                LOGGER.error("generateIdentity: CertSigner was unable to generate SSH certificate");
                return null;
            }
        }
        
        return new Identity().setName(cn)
                .setCertificate(x509Cert).setCaCertBundle(x509CACertificate)
                .setSshCertificate(sshCert).setSshCertificateSigner(sshCertificateSigner);
    }
    
    String getSshKeyReqType(String sshKeyReq) {
        
        Struct keyReq = null;
        try {
            keyReq = JSON.fromString(sshKeyReq, Struct.class);
        } catch (Exception ex) {
            LOGGER.error("getSshKeyReqType: Unable to parse json document: " + sshKeyReq);
            return null;
        }
        
        if (keyReq == null) {
            LOGGER.error("getSshKeyReqType: Unable to parse ssh key req: " + sshKeyReq);
            return null;
        }
        
        String sshType = keyReq.getString(ZTS_SSH_TYPE);
        if (sshType == null) {
            LOGGER.error("getSshKeyReqType: SSH Key request does not have certtype: " + sshKeyReq);
        }
        return sshType;
    }

    
    public CertSigner getCertSigner() {
        return this.certSigner;
    }
}
