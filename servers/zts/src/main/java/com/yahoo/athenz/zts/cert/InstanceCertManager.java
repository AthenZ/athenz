package com.yahoo.athenz.zts.cert;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.zts.SSHCertificates;
import com.yahoo.athenz.zts.SSHCertRequest;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.InstanceIdentity;
import com.yahoo.athenz.zts.ResourceException;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.common.server.cert.CertSignerFactory;
import com.yahoo.athenz.common.server.ssh.SSHSigner;
import com.yahoo.athenz.common.server.ssh.SSHSignerFactory;
import com.yahoo.athenz.zts.utils.IPBlock;
import com.yahoo.athenz.zts.utils.IPPrefix;
import com.yahoo.athenz.zts.utils.IPPrefixes;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.rdl.JSON;

public class InstanceCertManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceCertManager.class);

    private Authorizer authorizer;
    private CertSigner certSigner;
    private SSHSigner sshSigner;
    private CertRecordStore certStore = null;
    private ScheduledExecutorService scheduledExecutor;
    private List<IPBlock> certRefreshIPBlocks;
    private List<IPBlock> instanceCertIPBlocks;
    private String caX509CertificateSigner = null;
    private String sshUserCertificateSigner = null;
    private String sshHostCertificateSigner = null;
    
    public InstanceCertManager(final PrivateKeyStore keyStore, Authorizer authorizer,
            boolean readOnlyMode) {

        // set our authorizer object

        this.authorizer = authorizer;

        // create our x509 certsigner object

        loadCertSigner();

        // create our ssh signer object

        loadSSHSigner(authorizer);

        // if ZTS configured to issue certificate for services, it can
        // track of serial and instance values to make sure the same
        // certificate is not asked to be refreshed by multiple hosts
        
        loadCertificateObjectStore(keyStore);

        // check to see if we have been provided with a x.509 certificate
        // bundle or we need to fetch one from the cert signed

        if (!loadCAX509CertificateBundle()) {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Unable to load X.509 CA Certificate bundle");
        }

        // load our allowed cert refresh and instance register ip blocks
        
        certRefreshIPBlocks = new ArrayList<>();
        loadAllowedIPAddresses(certRefreshIPBlocks, ZTSConsts.ZTS_PROP_CERT_REFRESH_IP_FNAME);
        
        instanceCertIPBlocks = new ArrayList<>();
        loadAllowedIPAddresses(instanceCertIPBlocks, ZTSConsts.ZTS_PROP_INSTANCE_CERT_IP_FNAME);

        // start our thread to delete expired cert records once a day
        // unless we're running in read-only mode thus no modifications
        // to the database

        if (!readOnlyMode && certStore != null && certSigner != null) {
            scheduledExecutor = Executors.newScheduledThreadPool(1);
            scheduledExecutor.scheduleAtFixedRate(
                    new ExpiredX509CertRecordCleaner(certStore, certSigner.getMaxCertExpiryTimeMins()),
                    0, 1, TimeUnit.DAYS);
        }
    }
    
    void shutdown() {
        if (scheduledExecutor != null) {
            scheduledExecutor.shutdownNow();
        }
    }

    void loadCertSigner() {

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

    void loadSSHSigner(Authorizer authorizer) {

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

    boolean loadCAX509CertificateBundle() {

        final String caFileName = System.getProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME);
        if (caFileName == null || caFileName.isEmpty()) {
            return true;
        }

        File caFile = new File(caFileName);
        if (!caFile.exists()) {
            LOGGER.error("Configured X.509 CA file {} does not exist", caFileName);
            return false;
        }

        try {
            caX509CertificateSigner = new String(Files.readAllBytes(Paths.get(caFile.toURI())));
        } catch (IOException ex) {
            LOGGER.error("Failed to read configured X.509 CA file {}: {}",
                    caFileName, ex.getMessage());
            return false;
        }

        return true;
    }

    boolean loadAllowedIPAddresses(List<IPBlock> ipBlocks, final String propName) {
        
        // get the configured path for the list of ip addresses
        
        final String ipAddresses =  System.getProperty(propName);
        if (ipAddresses == null) {
            return true;
        }
        
        File ipFile = new File(ipAddresses);
        if (!ipFile.exists()) {
            LOGGER.error("Configured allowed IP file {} does not exist", ipAddresses);
            return false;
        }
        
        IPPrefixes prefixes;
        try {
            prefixes = JSON.fromBytes(Files.readAllBytes(Paths.get(ipFile.toURI())), IPPrefixes.class);
        } catch (IOException ex) {
            LOGGER.error("Unable to parse IP file: {}", ipAddresses, ex);
            return false;
        }
        
        if (prefixes == null) {
            LOGGER.error("Unable to parse IP file: {}", ipAddresses);
            return false;
        }
        
        List<IPPrefix> prefixList = prefixes.getPrefixes();
        if (prefixList == null || prefixList.isEmpty()) {
            LOGGER.error("No prefix entries available in the IP file: {}", ipAddresses);
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
        
        // default timeout in seconds for certificate store commands
        
        if (certStore != null) {
            int opTimeout = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERT_OP_TIMEOUT, "10"));
            if (opTimeout < 0) {
                opTimeout = 10;
            }
            certStore.setOperationTimeout(opTimeout);
        }
    }
    
    public void setCertStore(CertRecordStore certStore) {
        this.certStore = certStore;
    }
    
    public X509CertRecord getX509CertRecord(String provider, X509Certificate cert) {

        if (certStore == null) {
            return null;
        }
        
        Collection<List<?>> certAttributes;
        try {
            certAttributes = cert.getSubjectAlternativeNames();
        } catch (CertificateParsingException ex) {
            LOGGER.error("getX509CertRecord: Unable to get cert SANS: {}", ex.getMessage());
            return null;
        }
        
        if (certAttributes == null) {
            LOGGER.error("getX509CertRecord: Certificate does not have SANs");
            return null;
        }
        
        String instanceId = null;
        final List<String> dnsNames = Crypto.extractX509CertDnsNames(cert);
        for (String dnsName : dnsNames) {
             int idx = dnsName.indexOf(ZTSConsts.ZTS_CERT_INSTANCE_ID);
             if (idx != -1) {
                 instanceId = dnsName.substring(0, idx);
                 break;
            }
        }
        
        if (instanceId == null) {
            LOGGER.error("getX509CertRecord: Certificate does not have instance id");
            return null;
        }

        X509CertRecord certRecord;
        try (CertRecordStoreConnection storeConnection = certStore.getConnection()) {
            certRecord = storeConnection.getX509CertRecord(provider, instanceId);
        }
        
        return certRecord;
    }
    
    public X509CertRecord getX509CertRecord(String provider, String instanceId) {

        if (certStore == null) {
            return null;
        }

        X509CertRecord certRecord;
        try (CertRecordStoreConnection storeConnection = certStore.getConnection()) {
            certRecord = storeConnection.getX509CertRecord(provider, instanceId);
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
    
    public boolean deleteX509CertRecord(String provider, String instanceId) {
        
        if (certStore == null) {
            return false;
        }
        
        boolean result;
        try (CertRecordStoreConnection storeConnection = certStore.getConnection()) {
            result = storeConnection.deleteX509CertRecord(provider, instanceId);
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

    public String getX509CertificateSigner() {
        if (caX509CertificateSigner == null) {
            synchronized (InstanceCertManager.class) {
                if (caX509CertificateSigner == null) {
                    caX509CertificateSigner = getCACertificate();
                }
            }
        }
        return caX509CertificateSigner;
    }

    public SSHCertificates getSSHCertificates(Principal principal, SSHCertRequest certRequest) {

        if (sshSigner == null) {
            LOGGER.error("getSSHCertificates: SSHSigner not available");
            return null;
        }

        // ssh signer is responsible for all authorization checks and processing
        // of this request. the signer already was given the authorizer object
        // that it can use for those checks.

        return sshSigner.generateCertificate(principal, certRequest);
    }

    public boolean generateSshIdentity(InstanceIdentity identity, String sshCsr, String sshCertType) {
        
        if (sshCsr == null || sshCsr.isEmpty()) {
            return true;
        }
        
        SSHRequest sshReq = new SSHRequest(sshCsr, sshCertType);
        if (!sshReq.validateType()) {
            return false;
        }
        
        final String sshCert = certSigner.generateSSHCertificate(sshCsr);
        if (sshCert == null || sshCert.isEmpty()) {
            LOGGER.error("CertSigner was unable to generate SSH certificate for {}/{}",
                    identity.getInstanceId(), identity.getName());
            return false;
        }

        identity.setSshCertificate(sshCert);
        identity.setSshCertificateSigner(getSshCertificateSigner(sshReq.getSshReqType()));
        return true;
    }
    
    String getSshCertificateSigner(String sshReqType) {
        
        if (sshHostCertificateSigner == null) {
            synchronized (InstanceCertManager.class) {
                if (sshHostCertificateSigner == null) {
                    sshHostCertificateSigner = certSigner.getSSHCertificate(ZTSConsts.ZTS_SSH_HOST);
                }
            }
        }
        
        if (sshUserCertificateSigner == null) {
            synchronized (InstanceCertManager.class) {
                if (sshUserCertificateSigner == null) {
                    sshUserCertificateSigner = certSigner.getSSHCertificate(ZTSConsts.ZTS_SSH_USER);
                }
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
    
    public boolean verifyInstanceCertIPAddress(final String ipAddress) {
        return verifyIPAddressAccess(ipAddress, instanceCertIPBlocks);
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
}
