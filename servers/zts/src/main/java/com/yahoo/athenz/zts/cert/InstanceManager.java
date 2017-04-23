package com.yahoo.athenz.zts.cert;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.common.server.db.DataSourceFactory;
import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.zts.InstanceIdentity;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cert.impl.JDBCCertRecordStore;

public class InstanceManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceManager.class);
    public static final String JDBC = "jdbc";

    private CertRecordStore certStore = null;
    private static String CA_X509_CERTIFICATE = null;
    
    public InstanceManager(PrivateKeyStore keyStore) {
        
        // if ZTS configured to issue certificate for services, it can
        // track of serial and instance values to make sure the same
        // certificate is not asked to be refreshed by multiple hosts
        
        loadCertificateObjectStore(keyStore);
    }
    
    void loadCertificateObjectStore(PrivateKeyStore keyStore) {
        
        String jdbcStore = System.getProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_STORE);
        if (jdbcStore == null || !jdbcStore.startsWith("jdbc:")) {
            return;
        }
        String jdbcUser = System.getProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_USER);
        String password = System.getProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_PASSWORD, "");
        String jdbcPassword = keyStore.getApplicationSecret(JDBC, password);
        PoolableDataSource src = DataSourceFactory.create(jdbcStore, jdbcUser, jdbcPassword);
        certStore = new JDBCCertRecordStore(src);
    }
    
    public void setCertStore(CertRecordStore certStore) {
        this.certStore = certStore;
    }
    
    public X509CertRecord getX509CertRecord(String provider, X509Certificate cert) {

        if (certStore == null) {
            return null;
        }
        
        Collection<List<?>> certAttributes = null;
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
        Iterator<List<?>> certAttrs = certAttributes.iterator();
        while (certAttrs.hasNext()) {
            List<?> altName = (List<?>) certAttrs.next();
            Integer nameType = (Integer) altName.get(0);
            if (nameType == 2) {
                final String dnsName = (String) altName.get(1);
                if (dnsName.startsWith(ZTSConsts.ZTS_CERT_INSTANCE_ID_PREFIX)) {
                    instanceId = dnsName.substring(ZTSConsts.ZTS_CERT_INSTANCE_ID_PREFIX.length());
                    break;
                }
            }
        }
        
        if (instanceId == null) {
            LOGGER.error("getX509CertRecord: Certificate does not have instance id");
            return null;
        }

        X509CertRecord certRecord = null;
        try (CertRecordStoreConnection storeConnection = certStore.getConnection(true)) {
            if (storeConnection == null) {
                LOGGER.error("getX509CertRecord: Unable to get certstore connection");
                return null;
            }
        
            certRecord = storeConnection.getX509CertRecord(provider, instanceId);
        }
        
        return certRecord;
    }
    
    public X509CertRecord getX509CertRecord(String provider, String instanceId) {

        if (certStore == null) {
            return null;
        }

        X509CertRecord certRecord = null;
        try (CertRecordStoreConnection storeConnection = certStore.getConnection(true)) {
            if (storeConnection == null) {
                LOGGER.error("getX509CertRecord: Unable to get certstore connection");
                return null;
            }
        
            certRecord = storeConnection.getX509CertRecord(provider, instanceId);
        }
        
        return certRecord;
    }
    
    public boolean updateX509CertRecord(X509CertRecord certRecord) {
        
        if (certStore == null) {
            return false;
        }
        
        boolean result = false;
        try (CertRecordStoreConnection storeConnection = certStore.getConnection(true)) {
            if (storeConnection == null) {
                LOGGER.error("Unable to get certstore connection");
                return false;
            }
            
            result = storeConnection.updateX509CertRecord(certRecord);
        }
        return result;
    }
    
    public boolean deleteX509CertRecord(String provider, String instanceId) {
        
        if (certStore == null) {
            return false;
        }
        
        boolean result = false;
        try (CertRecordStoreConnection storeConnection = certStore.getConnection(true)) {
            if (storeConnection == null) {
                LOGGER.error("Unable to get certstore connection");
                return false;
            }
            
            result = storeConnection.deleteX509CertRecord(provider, instanceId);
        }
        return result;
    }
    
    public boolean insertX509CertRecord(X509CertRecord certRecord) {
        
        if (certStore == null) {
            return false;
        }
        
        boolean result = false;
        try (CertRecordStoreConnection storeConnection = certStore.getConnection(true)) {
            if (storeConnection == null) {
                LOGGER.error("Unable to get certstore connection");
                return false;
            }
        
            result = storeConnection.insertX509CertRecord(certRecord);
        }
        
        return result;
    }
    
    public static InstanceIdentity generateIdentity(CertSigner certSigner, String csr,
            String cn, Map<String, String> attributes) {
        
        // generate a certificate for this certificate request

        String pemCert = certSigner.generateX509Certificate(csr);
        if (pemCert == null || pemCert.isEmpty()) {
            LOGGER.error("generateIdentity: CertSigner was unable to generate X509 certificate");
            return null;
        }
        
        if (CA_X509_CERTIFICATE == null) {
            synchronized (InstanceManager.class) {
                if (CA_X509_CERTIFICATE == null) {
                    CA_X509_CERTIFICATE = certSigner.getCACertificate();
                }
            }
        }
        
        return new InstanceIdentity().setName(cn).setX509Certificate(pemCert)
                .setX509CertificateSigner(CA_X509_CERTIFICATE)
                .setAttributes(attributes);
    }
}
