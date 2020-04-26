/*
 * Copyright 2019 Oath Holdings Inc.
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
package com.yahoo.athenz.zts.cert;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.net.InetAddresses;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.common.server.ssh.SSHSigner;
import com.yahoo.athenz.common.server.ssh.SSHSignerFactory;
import com.yahoo.athenz.common.server.ssh.SSHCertRecord;
import com.yahoo.athenz.common.server.ssh.SSHRecordStore;
import com.yahoo.athenz.common.server.ssh.SSHRecordStoreConnection;
import com.yahoo.athenz.common.server.ssh.SSHRecordStoreFactory;
import com.yahoo.athenz.zts.*;
import com.yahoo.athenz.zts.utils.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.common.server.cert.CertSignerFactory;
import com.yahoo.athenz.common.server.cert.CertRecordStore;
import com.yahoo.athenz.common.server.cert.CertRecordStoreFactory;
import com.yahoo.athenz.common.server.cert.CertRecordStoreConnection;
import com.yahoo.athenz.common.server.cert.X509CertRecord;

public class InstanceCertManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceCertManager.class);

    private static final String CA_TYPE_X509 = "x509";

    private Authorizer authorizer;
    private CertSigner certSigner;
    private SSHSigner sshSigner;
    private HostnameResolver hostnameResolver;
    private CertRecordStore certStore = null;
    private SSHRecordStore sshStore = null;
    private ScheduledExecutorService certScheduledExecutor;
    private ScheduledExecutorService sshScheduledExecutor;
    private List<IPBlock> certRefreshIPBlocks;
    private Map<String, List<IPBlock>> instanceCertIPBlocks;
    private String caX509CertificateSigner = null;
    private String sshUserCertificateSigner = null;
    private String sshHostCertificateSigner = null;
    private boolean responseSendSSHSignerCerts;
    private boolean responseSendX509SignerCerts;
    private ObjectMapper jsonMapper;
    private Map<String, CertificateAuthorityBundle> certAuthorityBundles = null;

    public InstanceCertManager(final PrivateKeyStore keyStore, Authorizer authorizer, HostnameResolver hostnameResolver,
            boolean readOnlyMode) {

        // set our authorizer object

        this.authorizer = authorizer;

        // set hostname resolver

        this.hostnameResolver = hostnameResolver;

        // initialize our jackson object mapper

        jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        // create our x509 certsigner object

        loadCertSigner();

        // create our ssh signer object

        loadSSHSigner(authorizer);

        // if ZTS configured to issue certificate for services, it can
        // track of serial and instance values to make sure the same
        // certificate is not asked to be refreshed by multiple hosts
        
        loadCertificateObjectStore(keyStore);

        // if ZTS configured to issue ssh host certificates for services,
        // it can track of some details if enabled

        loadSSHObjectStore(keyStore);

        // load any configuration wrt certificate signers and any
        // configured certificate bundles

        if (!loadCertificateAuthorityBundles()) {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Unable to load Certificate Authority Bundles");
        }

        // load our allowed cert refresh and instance register ip blocks
        
        certRefreshIPBlocks = new ArrayList<>();
        loadAllowedIPAddresses(certRefreshIPBlocks, System.getProperty(ZTSConsts.ZTS_PROP_CERT_REFRESH_IP_FNAME));

        if (!loadAllowedInstanceCertIPAddresses()) {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Unable to load Provider Allowed IP Blocks");
        }

        // start our thread to delete expired cert records once a day
        // unless we're running in read-only mode thus no modifications
        // to the database

        if (!readOnlyMode && certStore != null && certSigner != null) {
            certScheduledExecutor = Executors.newScheduledThreadPool(1);
            certScheduledExecutor.scheduleAtFixedRate(
                    new ExpiredX509CertRecordCleaner(certStore, certSigner.getMaxCertExpiryTimeMins()),
                    0, 1, TimeUnit.DAYS);
        }

        if (!readOnlyMode && sshStore != null) {
            int expiryTimeMins = (int) TimeUnit.MINUTES.convert(30, TimeUnit.DAYS);
            sshScheduledExecutor = Executors.newScheduledThreadPool(1);
            sshScheduledExecutor.scheduleAtFixedRate(
                    new ExpiredSSHCertRecordCleaner(sshStore, expiryTimeMins), 0, 1, TimeUnit.DAYS);
        }
    }
    
    void shutdown() {
        if (certScheduledExecutor != null) {
            certScheduledExecutor.shutdownNow();
        }
        if (sshScheduledExecutor != null) {
            sshScheduledExecutor.shutdownNow();
        }
    }

    private boolean loadCertificateAuthorityBundles() {

        // check to see if we have been provided with a x.509/ssh certificate
        // bundle or we need to fetch one from the certsigner

        responseSendSSHSignerCerts = Boolean.parseBoolean(
                System.getProperty(ZTSConsts.ZTS_PROP_RESP_SSH_SIGNER_CERTS, "true"));
        responseSendX509SignerCerts = Boolean.parseBoolean(
                System.getProperty(ZTSConsts.ZTS_PROP_RESP_X509_SIGNER_CERTS, "true"));

        // if we're not asked to skip sending certificate signers then
        // check to see if we need to load them from files instead of
        // certsigner directly

        if (responseSendX509SignerCerts) {
            caX509CertificateSigner = loadCertificateBundle(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME);
        }
        if (responseSendSSHSignerCerts) {
            sshUserCertificateSigner = loadCertificateBundle(ZTSConsts.ZTS_PROP_SSH_USER_CA_CERT_FNAME);
            sshHostCertificateSigner = loadCertificateBundle(ZTSConsts.ZTS_PROP_SSH_HOST_CA_CERT_FNAME);
        }

        // now let's fetch our configured certificate authority bundles

        certAuthorityBundles = new HashMap<>();

        final String caBundleFile =  System.getProperty(ZTSConsts.ZTS_PROP_CERT_BUNDLES_FNAME);
        if (caBundleFile == null || caBundleFile.isEmpty()) {
            return true;
        }

        byte[] data = readFileContents(caBundleFile);
        if (data == null) {
            return false;
        }

        CertBundles certBundles = null;
        try {
            certBundles = jsonMapper.readValue(data, CertBundles.class);
        } catch (Exception ex) {
            LOGGER.error("Unable to parse CA bundle file: {} - {}", caBundleFile, ex.getMessage());
        }

        if (certBundles == null) {
            return false;
        }

        List<CertBundle> bundleList = certBundles.getCertBundles();
        if (bundleList == null || bundleList.isEmpty()) {
            LOGGER.error("No CA bundles available in the file: {}", caBundleFile);
            return false;
        }

        for (CertBundle bundle : bundleList) {
            if (!processCertificateAuthorityBundle(bundle)) {
                return false;
            }
        }

        return true;
    }

    private boolean processCertificateAuthorityBundle(CertBundle bundle) {

        final String name = bundle.getName();
        final String fileName = bundle.getFilename();
        if (fileName == null || fileName.isEmpty()) {
            LOGGER.error("Bundle {} does not have a file configured", name);
            return false;
        }

        // if this is x.509 certificate bundle then we're going
        // to extract our data, validate all certs and regenerate
        // our pem data to remove any other comments from the data
        // file to minimize the data size

        String bundleData = null;
        if (CA_TYPE_X509.equalsIgnoreCase(bundle.getType())) {
            bundleData = extractX509CertificateBundle(fileName);
        } else {
            byte[] data = readFileContents(fileName);
            if (data != null) {
                bundleData = new String(data);
            }
        }

        if (bundleData == null) {
            LOGGER.error("Unable to load bundle {} from file {}", name, fileName);
            return false;
        }

        CertificateAuthorityBundle certAuthorityBundle = new CertificateAuthorityBundle()
                .setName(name)
                .setCerts(bundleData);

        certAuthorityBundles.put(name, certAuthorityBundle);
        return true;
    }

    String extractX509CertificateBundle(final String filename) {

        try {
            // first load our certificates file to make sure
            // all the certs in the file are valid

            X509Certificate[] x509Certs = Crypto.loadX509Certificates(filename);

            // then re-generate the certs in pem format to
            // remove any comments/etc to minimize the data size

            return Crypto.x509CertificatesToPEM(x509Certs);

        } catch (CryptoException ex) {
            LOGGER.error("Unable to load certificate file", ex);
            return null;
        }
    }

    private boolean loadAllowedInstanceCertIPAddresses() {

        instanceCertIPBlocks = new HashMap<>();

        // read the file list of providers and allowed IP addresses
        // if the config is not set then we have no restrictions
        // otherwise all providers must be specified in the list

        String providerIPMapFile =  System.getProperty(ZTSConsts.ZTS_PROP_INSTANCE_CERT_IP_FNAME);
        if (providerIPMapFile == null || providerIPMapFile.isEmpty()) {
            return true;
        }

        byte[] data = readFileContents(providerIPMapFile);
        if (data == null) {
            return false;
        }

        ProviderIPBlocks ipBlocks = null;
        try {
            ipBlocks = jsonMapper.readValue(data, ProviderIPBlocks.class);
        } catch (Exception ex) {
            LOGGER.error("Unable to parse Provider IP file: {} - {}", providerIPMapFile, ex.getMessage());
        }

        if (ipBlocks == null) {
            return false;
        }

        for (ProviderIPBlock ipBlock : ipBlocks.getIpblocks()) {

            List<IPBlock> certIPBlocks;
            final String filename = ipBlock.getFilename();
            if (filename == null) {
                certIPBlocks = Collections.emptyList();
            } else {
                certIPBlocks = new ArrayList<>();
                if (!loadAllowedIPAddresses(certIPBlocks, filename)) {
                    LOGGER.error("Invalid provider ip file {}", filename);
                    return false;
                }
            }
            for (String provider : ipBlock.getProviders()) {
                instanceCertIPBlocks.put(provider, certIPBlocks);
            }
        }
        return true;
    }

    private void loadCertSigner() {

        String certSignerFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS,
                ZTSConsts.ZTS_CERT_SIGNER_FACTORY_CLASS);
        CertSignerFactory certSignerFactory;
        try {
            certSignerFactory = (CertSignerFactory) Class.forName(certSignerFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOGGER.error("Invalid CertSignerFactory class: " + certSignerFactoryClass
                    + " error: " + e.getMessage());
            throw new IllegalArgumentException("Invalid certsigner class");
        }

        // create our cert signer instance

        certSigner = certSignerFactory.create();
    }

    private void loadSSHSigner(Authorizer authorizer) {

        String sshSignerFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_SSH_SIGNER_FACTORY_CLASS);
        if (sshSignerFactoryClass == null || sshSignerFactoryClass.isEmpty()) {
            LOGGER.error("No SSHSignerFactory class configured");
            sshSigner = null;
            return;
        }
        SSHSignerFactory sshSignerFactory;
        try {
            sshSignerFactory = (SSHSignerFactory) Class.forName(sshSignerFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOGGER.error("Invalid SSHSignerFactory class: " + sshSignerFactoryClass
                    + " error: " + e.getMessage());
            throw new IllegalArgumentException("Invalid sshsigner class");
        }

        // create our cert signer instance

        sshSigner = sshSignerFactory.create();
        sshSigner.setAuthorizer(authorizer);
    }

    void setSSHSigner(SSHSigner sshSigner) {
        this.sshSigner = sshSigner;
    }

    void setCertSigner(CertSigner certSigner) {
        this.certSigner = certSigner;
    }

    Path getFilePath(File file) {
        return Paths.get(file.toURI());
    }

    byte[] readFileContents(final String filename) {

        File caFile = new File(filename);
        if (!caFile.exists()) {
            LOGGER.error("Configured file {} does not exist", filename);
            return null;
        }

        byte[] data = null;
        try {
            data = Files.readAllBytes(getFilePath(caFile));
        } catch (Exception ex) {
            LOGGER.error("Unable to read {}: {}", filename, ex.getMessage());
        }

        return data;
    }

    String loadCertificateBundle(final String propertyName) {

        final String caFileName = System.getProperty(propertyName);
        if (caFileName == null || caFileName.isEmpty()) {
            return null;
        }

        byte[] data = readFileContents(caFileName);
        if (data == null) {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Unable to load Certificate bundle from: " + caFileName);
        }

        return new String(data);
    }

    boolean loadAllowedIPAddresses(List<IPBlock> ipBlocks, final String ipAddressFileName) {

        if (ipAddressFileName == null || ipAddressFileName.isEmpty()) {
            return true;
        }

        byte[] data = readFileContents(ipAddressFileName);
        if (data == null) {
            return false;
        }

        IPPrefixes prefixes = null;
        try {
            prefixes = jsonMapper.readValue(data, IPPrefixes.class);
        } catch (Exception ex) {
            LOGGER.error("Unable to parse IP file: {} - {}", ipAddressFileName, ex.getMessage());
        }

        if (prefixes == null) {
            return false;
        }
        
        List<IPPrefix> prefixList = prefixes.getPrefixes();
        if (prefixList == null || prefixList.isEmpty()) {
            LOGGER.error("No prefix entries available in the IP file: {}", ipAddressFileName);
            return false;
        }
        
        for (IPPrefix prefix : prefixList) {
            
            // for now we're only supporting IPv4 blocks
            
            final String ipEntry = prefix.getIpv4Prefix();
            if (ipEntry == null) {
                continue;
            }
            
            try {
                ipBlocks.add(new IPBlock(ipEntry));
            } catch (Exception ex) {
                LOGGER.error("Skipping invalid ip block entry: {}, error: {}",
                        ipEntry, ex.getMessage());
                return false;
            }
        }
        
        return true;
    }
    
    private void loadCertificateObjectStore(PrivateKeyStore keyStore) {
        
        String certRecordStoreFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_CERT_RECORD_STORE_FACTORY_CLASS,
                ZTSConsts.ZTS_CERT_RECORD_STORE_FACTORY_CLASS);
        CertRecordStoreFactory certRecordStoreFactory;
        try {
            certRecordStoreFactory = (CertRecordStoreFactory) Class.forName(certRecordStoreFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOGGER.error("Invalid CertRecordStoreFactory class: {} error: {}",
                    certRecordStoreFactoryClass, e.getMessage());
            throw new IllegalArgumentException("Invalid cert record store factory class");
        }

        // create our cert record store instance
        
        certStore = certRecordStoreFactory.create(keyStore);
    }

    private void loadSSHObjectStore(PrivateKeyStore keyStore) {

        String sshRecordStoreFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_SSH_RECORD_STORE_FACTORY_CLASS);
        if (sshRecordStoreFactoryClass == null || sshRecordStoreFactoryClass.isEmpty()) {
            return;
        }

        SSHRecordStoreFactory sshRecordStoreFactory;
        try {
            sshRecordStoreFactory = (SSHRecordStoreFactory) Class.forName(sshRecordStoreFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOGGER.error("Invalid SSHRecordStoreFactory class: {} error: {}",
                    sshRecordStoreFactoryClass, e.getMessage());
            throw new IllegalArgumentException("Invalid ssh record store factory class");
        }

        // create our cert record store instance

        sshStore = sshRecordStoreFactory.create(keyStore);
    }

    public void setCertStore(CertRecordStore certStore) {
        this.certStore = certStore;
    }

    public void setSSHStore(SSHRecordStore sshStore) {
        this.sshStore = sshStore;
    }

    public CertificateAuthorityBundle getCertificateAuthorityBundle(final String name) {
        return certAuthorityBundles.get(name);
    }

    public List<X509CertRecord> getUnrefreshedCertsNotifications(String serverHostName, String provider) {
        if (certStore == null) {
            return new ArrayList<>();
        }

        try (CertRecordStoreConnection storeConnection = certStore.getConnection()) {
            long updateTs = System.currentTimeMillis();
            if (storeConnection.updateUnrefreshedCertificatesNotificationTimestamp(serverHostName, updateTs, provider)) {
                return storeConnection.getNotifyUnrefreshedCertificates(serverHostName, updateTs);
            }
        }

        return new ArrayList<>();
    }

    public X509CertRecord getX509CertRecord(final String provider, X509Certificate cert) {

        if (certStore == null) {
            return null;
        }

        final String instanceId = X509CertUtils.extractRequestInstanceId(cert);
        if (instanceId == null) {
            LOGGER.error("getX509CertRecord: Certificate does not have instance id");
            return null;
        }

        X509CertRecord certRecord;
        try (CertRecordStoreConnection storeConnection = certStore.getConnection()) {
            certRecord = storeConnection.getX509CertRecord(provider, instanceId,
                    Crypto.extractX509CertCommonName(cert));
        }
        
        return certRecord;
    }
    
    public X509CertRecord getX509CertRecord(final String provider, final String instanceId,
            final String service) {

        if (certStore == null) {
            return null;
        }

        X509CertRecord certRecord;
        try (CertRecordStoreConnection storeConnection = certStore.getConnection()) {
            certRecord = storeConnection.getX509CertRecord(provider, instanceId, service);
        }
        
        return certRecord;
    }
    
    public boolean updateX509CertRecord(X509CertRecord certRecord) {
        
        if (certStore == null) {
            return false;
        }
        
        boolean result;
        try (CertRecordStoreConnection storeConnection = certStore.getConnection()) {
            result = storeConnection.updateX509CertRecord(certRecord);
        }
        return result;
    }
    
    public boolean deleteX509CertRecord(final String provider, final String instanceId,
            final String service) {
        
        if (certStore == null) {
            return false;
        }
        
        boolean result;
        try (CertRecordStoreConnection storeConnection = certStore.getConnection()) {
            result = storeConnection.deleteX509CertRecord(provider, instanceId, service);
        }
        return result;
    }
    
    public boolean insertX509CertRecord(X509CertRecord certRecord) {
        
        if (certStore == null) {
            return false;
        }
        
        boolean result;
        try (CertRecordStoreConnection storeConnection = certStore.getConnection()) {
            result = storeConnection.insertX509CertRecord(certRecord);
        }
        
        return result;
    }

    public String generateX509Certificate(final String csr, final String keyUsage, int expiryTime) {

        String pemCert = certSigner.generateX509Certificate(csr, keyUsage, expiryTime);
        if (pemCert == null || pemCert.isEmpty()) {
            LOGGER.error("generateX509Certificate: CertSigner was unable to generate X509 certificate");
        }
        return pemCert;
    }

    public String getCACertificate() {
        return certSigner.getCACertificate();
    }

    public InstanceIdentity generateIdentity(String csr, String cn, String keyUsage,
            int expiryTime) {
        
        // generate a certificate for this certificate request

        final String pemCert = generateX509Certificate(csr, keyUsage, expiryTime);
        if (pemCert == null || pemCert.isEmpty()) {
            return null;
        }
        
        return new InstanceIdentity().setName(cn).setX509Certificate(pemCert)
                .setX509CertificateSigner(getX509CertificateSigner());
    }

    void updateX509CertificateSigner() {
        if (caX509CertificateSigner == null) {
            caX509CertificateSigner = getCACertificate();
        }
    }

    public String getX509CertificateSigner() {

        // if configured not to send x.509 signer certs
        // then we'll return right away as null

        if (!responseSendX509SignerCerts) {
            return null;
        }

        if (caX509CertificateSigner == null) {
            synchronized (InstanceCertManager.class) {
                updateX509CertificateSigner();
            }
        }
        return caX509CertificateSigner;
    }

    void resetX509CertificateSigner() {
        caX509CertificateSigner = null;
    }

    public SSHCertificates generateSSHCertificates(Principal principal, SSHCertRequest certRequest) {

        if (sshSigner == null) {
            LOGGER.error("SSH Signer is not available");
            return null;
        }

        // if this is a host certificate we're going to fetch our
        // ssh certificate record

        SSHCertRecord sshCertRecord = null;
        SSHCertRequestMeta meta = certRequest.getCertRequestMeta();
        if (ZTSConsts.ZTS_SSH_HOST.equals(meta.getCertType())) {
            sshCertRecord = getSSHCertRecord(meta.getInstanceId(), meta.getAthenzService());
        }

        // ssh signer is responsible for all authorization checks and processing
        // of this request. the signer already was given the authorizer object
        // that it can use for those checks.

        return sshSigner.generateCertificate(principal, certRequest, sshCertRecord, null);
    }

    SshHostCsr parseSshHostCsr(final String csr) {
        SshHostCsr sshHostCsr = null;
        try {
            sshHostCsr = jsonMapper.readValue(csr, SshHostCsr.class);
        } catch (Exception ex) {
            LOGGER.error("Unable to parse SSH CSR: {}", csr, ex);
        }
        return sshHostCsr;
    }

    void updateSSHHostPrincipals(SshHostCsr sshHostCsr, SSHCertRecord sshCertRecord) {

        if (sshHostCsr == null) {
            sshCertRecord.setPrincipals("127.0.0.1");
            return;
        }

        String recordPrincipals = "";

        // check both principals and x-principal fields

        String[] principals = sshHostCsr.getPrincipals();
        if (principals != null) {
            recordPrincipals += String.join(",", Arrays.asList(principals));
        }

        principals = sshHostCsr.getXPrincipals();
        if (principals != null) {
            recordPrincipals += "," + String.join(",", Arrays.asList(principals));
        }

        if (recordPrincipals.isEmpty()) {
            sshCertRecord.setPrincipals("127.0.0.1");
        } else {
            sshCertRecord.setPrincipals(recordPrincipals);
        }
    }

    public boolean generateSSHIdentity(Principal principal, InstanceIdentity identity, final String hostname,
            final String csr, SSHCertRecord sshCertRecord, final String certType) {

        if (sshSigner == null || csr == null || csr.isEmpty()) {
            return true;
        }

        if (ZTSConsts.ZTS_SSH_HOST.equals(certType)) {

            // parse our host csr

            SshHostCsr sshHostCsr = parseSshHostCsr(csr);
            if (hostname != null && !hostname.isEmpty() && hostnameResolver != null) {
                if (!validPrincipals(hostname, sshHostCsr)) {
                    LOGGER.error("SSH Host CSR validation failed, principal: {}, hostname: {}, csr: {}", principal, hostname, csr);
                    return false;
                }
            }

            // update our ssh record object

            updateSSHHostPrincipals(sshHostCsr, sshCertRecord);
        }

        SSHCertRequest certRequest = new SSHCertRequest();
        certRequest.setCsr(csr);

        SSHCertificates sshCerts;
        try {
            sshCerts = sshSigner.generateCertificate(principal, certRequest, sshCertRecord, certType);
        } catch (Exception ex) {
            LOGGER.error("SSHSigner was unable to generate SSH certificate for {}/{} - error {}",
                    identity.getInstanceId(), identity.getName(), ex.getMessage());
            return false;
        }

        if (sshCerts == null || sshCerts.getCertificates().isEmpty()) {
            LOGGER.error("SSHSigner returned an empty certificate set for {}/{}",
                    identity.getInstanceId(), identity.getName());
            return false;
        }

        // record the host ssh cert details if configured
        // any failure will be logged by the ssh record store
        // function also handles null objects. If our principal
        // is null then it's a register operation otherwise
        // we're handling a refresh operation

        updateSSHCertRecord(sshCertRecord, principal != null);

        // update our identity object with ssh cert details

        identity.setSshCertificate(sshCerts.getCertificates().get(0).getCertificate());
        identity.setSshCertificateSigner(getSSHCertificateSigner(certType));
        return true;
    }

    void updateSSHHostCertificateSigner() {
        if (sshHostCertificateSigner == null) {
            sshHostCertificateSigner = sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST);
        }
    }

    void updateSSHUserCertificateSigner() {
        if (sshUserCertificateSigner == null) {
            sshUserCertificateSigner = sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_USER);
        }
    }

    String getSSHCertificateSigner(String sshReqType) {

        // if configured not to send SSH signer certs
        // then we'll return right away as null

        if (!responseSendSSHSignerCerts) {
            return null;
        }

        if (sshSigner == null) {
            return null;
        }

        if (sshHostCertificateSigner == null) {
            synchronized (InstanceCertManager.class) {
                updateSSHHostCertificateSigner();
            }
        }
        
        if (sshUserCertificateSigner == null) {
            synchronized (InstanceCertManager.class) {
                updateSSHUserCertificateSigner();
            }
        }
        
        return sshReqType.equals(ZTSConsts.ZTS_SSH_HOST) ? sshHostCertificateSigner : sshUserCertificateSigner;
    }
    
    public boolean authorizeLaunch(Principal providerService, String domain, String service,
            StringBuilder errorMsg) {
        
        // first we need to make sure that the provider has been
        // authorized in Athenz to bootstrap/launch instances
        
        if (!authorizer.access(ZTSConsts.ZTS_ACTION_LAUNCH, ZTSConsts.ZTS_RESOURCE_INSTANCE,
                providerService, null)) {
            errorMsg.append("provider '").append(providerService.getFullName())
                .append("' not authorized to launch instances in Athenz");
            return false;
        }
        
        // next we need to verify that the service has authorized
        // the provider to bootstrap/launch an instance
        
        final String tenantResource = domain + ":service." + service;
        if (!authorizer.access(ZTSConsts.ZTS_ACTION_LAUNCH, tenantResource,
                providerService, null)) {
            errorMsg.append("provider '").append(providerService.getFullName())
                .append("' not authorized to launch ").append(domain).append('.')
                .append(service).append(" instances");
            return false;
        }
        
        return true;
    }
    
    public boolean verifyCertRefreshIPAddress(final String ipAddress) {
        return verifyIPAddressAccess(ipAddress, certRefreshIPBlocks);
    }

    public boolean verifyInstanceCertIPAddress(final String provider, final String ipAddress) {

        final List<IPBlock> certIPBlocks = instanceCertIPBlocks.get(provider);

        // if we have no blocks defined for the provider, then we'll return
        // failure if we have others defined or success if there are no
        // providers defined at all

        if (certIPBlocks == null) {
            return instanceCertIPBlocks.isEmpty();
        }

        return verifyIPAddressAccess(ipAddress, certIPBlocks);
    }

    /**
     * validates hostname against the resolver, and verifies that the ssh principals map to hostname
     * @param hostname of the instance
     * @param sshHostCsr ssh host csr from the sia
     * @return boolean true or false
     */
    public boolean validPrincipals(final String hostname, SshHostCsr sshHostCsr) {

        if (sshHostCsr == null) {
            return false;
        }

        String[] principals = sshHostCsr.getPrincipals();
        String[] xPrincipals = sshHostCsr.getXPrincipals();

        // Pass through when xPrincipals is not specified

        if (sshHostCsr.getXPrincipals() == null) {
            LOGGER.error("CSR has no xPrincipals to verify, hostname: {}, principals: {}", hostname, principals);
            return true;
        }

        LOGGER.debug("CSR principals: {}, xPrincipals: {}", principals, xPrincipals);

        List<String> cnames = new ArrayList<>();
        for (String name: xPrincipals) {
            // Skip IPs
            if (InetAddresses.isInetAddress(name)) {
                continue;
            }
            // Skip direct hostname principals
            if (name.equals(hostname)) {
                // verify that the hostname is a known name
                if (hostnameResolver != null && !hostnameResolver.isValidHostname(hostname)) {
                    LOGGER.error("{} is not a valid name", hostname);
                    return false;
                }
                continue;
            }

            cnames.add(name);
        }
        // If there are no custom cnames, return right away
        if (cnames.isEmpty()) {
            return true;
        }

        LOGGER.debug("validating xPrincipals in the csr: {}", cnames);
        if (hostnameResolver.isValidHostCnameList(hostname, cnames, CertType.SSH_HOST)) {
            return true;
        }

        LOGGER.error("{} does not map to some cnames {}", hostname, String.join(",", cnames));
        return false;
    }

    private boolean verifyIPAddressAccess(final String ipAddress, final List<IPBlock> ipBlocks) {
        
        // if the list has no IP addresses then we allow all
        
        if (ipBlocks.isEmpty()) {
            return true;
        }
        
        long ipAddr = IPBlock.convertIPToLong(ipAddress);
        for (IPBlock ipBlock : ipBlocks) {
            if (ipBlock.ipCheck(ipAddr)) {
                return true;
            }
        }
        return false;
    }

    public void logX509Cert(final Principal principal, final String ip, final String provider,
            final String instanceId, final X509Certificate x509Cert) {

        if (certStore == null) {
            return;
        }

        // catch and ignore all exceptions. logging is not significant
        // to return failure if we have received a valid certificate
        // from our certificate signer. The certstore implementation
        // must log any failures.

        try {
            certStore.log(principal, ip, provider, instanceId, x509Cert);
        } catch (Exception ignored) {
        }
    }

    public SSHCertRecord getSSHCertRecord(final String instanceId, final String service) {

        if (sshStore == null) {
            return null;
        }

        SSHCertRecord certRecord;
        try (SSHRecordStoreConnection storeConnection = sshStore.getConnection()) {
            certRecord = storeConnection.getSSHCertRecord(instanceId, service);
        }

        return certRecord;
    }

    public boolean updateSSHCertRecord(SSHCertRecord certRecord, boolean refresh) {

        if (sshStore == null) {
            return false;
        }

        if (certRecord == null) {
            return true;
        }

        boolean result;
        try (SSHRecordStoreConnection storeConnection = sshStore.getConnection()) {

            // if it's a refresh we're going to try to update first

            if (refresh && storeConnection.updateSSHCertRecord(certRecord)) {
                return true;
            }

            // if it's a register operation or if we get a failure, in the case
            // of refresh, then it's possible that we don't have the record so
            // we're going to create it

            result = storeConnection.insertSSHCertRecord(certRecord);
        }

        return result;
    }

    class ExpiredX509CertRecordCleaner implements Runnable {
        
        private CertRecordStore store;
        private int expiryTimeMins;
        
        public ExpiredX509CertRecordCleaner(CertRecordStore store, int expiryTimeMins) {
            this.store = store;
            this.expiryTimeMins = expiryTimeMins;
        }
        
        @Override
        public void run() {

            LOGGER.info("ExpiredX509CertRecordCleaner: Starting expired cert record cleaner thread...");
            
            int deletedRecords = 0;
            try {
                deletedRecords = cleanupExpiredX509CertRecords();
            } catch (Throwable t) {
                LOGGER.error("ExpiredX509CertRecordCleaner: unable to cleanup expired cert records: {}",
                        t.getMessage());
            }
            
            LOGGER.info("ExpiredX509CertRecordCleaner: Completed cleanup of {} expired cert records",
                    deletedRecords);
        }
        
        int cleanupExpiredX509CertRecords() {
            
            int deletedRecords;
            try (CertRecordStoreConnection storeConnection = store.getConnection()) {
                deletedRecords = storeConnection.deleteExpiredX509CertRecords(expiryTimeMins);
            }
            return deletedRecords;
        }
    }

    class ExpiredSSHCertRecordCleaner implements Runnable {

        private SSHRecordStore store;
        private int expiryTimeMins;

        public ExpiredSSHCertRecordCleaner(SSHRecordStore store, int expiryTimeMins) {
            this.store = store;
            this.expiryTimeMins = expiryTimeMins;
        }

        @Override
        public void run() {

            LOGGER.info("ExpiredSSHCertRecordCleaner: Starting expired ssh record cleaner thread...");

            int deletedRecords = 0;
            try {
                deletedRecords = cleanupExpiredSSHCertRecords();
            } catch (Throwable t) {
                LOGGER.error("ExpiredSSHCertRecordCleaner: unable to cleanup expired ssh records: {}",
                        t.getMessage());
            }

            LOGGER.info("ExpiredSSHCertRecordCleaner: Completed cleanup of {} expired ssh records",
                    deletedRecords);
        }

        int cleanupExpiredSSHCertRecords() {

            int deletedRecords;
            try (SSHRecordStoreConnection storeConnection = store.getConnection()) {
                deletedRecords = storeConnection.deleteExpiredSSHCertRecords(expiryTimeMins);
            }
            return deletedRecords;
        }
    }
}
