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
package com.yahoo.athenz.zts.cert;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.net.InetAddresses;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.common.ServerCommonConsts;
import com.yahoo.athenz.common.server.cert.*;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.ssh.*;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import com.yahoo.athenz.common.server.workload.WorkloadRecord;
import com.yahoo.athenz.common.server.workload.WorkloadRecordStore;
import com.yahoo.athenz.common.server.workload.WorkloadRecordStoreConnection;
import com.yahoo.athenz.common.server.workload.WorkloadRecordStoreFactory;
import com.yahoo.athenz.common.utils.X509CertUtils;
import com.yahoo.athenz.zts.*;
import com.yahoo.athenz.zts.utils.*;
import com.yahoo.rdl.Timestamp;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static com.yahoo.athenz.common.server.util.config.ConfigManagerSingleton.CONFIG_MANAGER;

public class InstanceCertManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceCertManager.class);

    private static final String CA_TYPE_X509 = "x509";
    private static final String ZTS_SVC_TOKEN_PROVIDER = "zts-svc-token-provider";

    private static final ObjectMapper JSON_MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private final Authorizer authorizer;
    private CertSigner certSigner;
    private SSHSigner sshSigner;
    private final HostnameResolver hostnameResolver;
    private CertRecordStore certStore = null;
    private SSHRecordStore sshStore = null;
    private WorkloadRecordStore workloadStore = null;
    private ScheduledExecutorService certScheduledExecutor;
    private ScheduledExecutorService sshScheduledExecutor;
    private final ScheduledExecutorService ipBlockScheduledExecutor;
    private final ConcurrentHashMap<String, List<IPBlock>> instanceCertIPBlocks;
    private String caX509CertificateSigner = null;
    private Map<String, String> caX509ProviderCertificateSigners = null;
    private Map<String, String> caSshProviderCertificateSigners = null;
    private String sshUserCertificateSigner = null;
    private String sshHostCertificateSigner = null;
    private boolean responseSendSSHSignerCerts;
    private boolean responseSendX509SignerCerts;
    private final DynamicConfigBoolean validateIPAddress;
    private Map<String, CertificateAuthorityBundle> certAuthorityBundles = null;

    public InstanceCertManager(final PrivateKeyStore keyStore, Authorizer authorizer, HostnameResolver hostnameResolver,
            DynamicConfigBoolean readOnlyMode) {

        // set our authorizer object

        this.authorizer = authorizer;

        // set hostname resolver

        this.hostnameResolver = hostnameResolver;

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

        // if ZTS configured to store workload information for services,
        // it can track of some details if enabled

        loadWorkloadObjectStore(keyStore);

        // load any configuration wrt certificate signers and any
        // configured certificate bundles

        if (!loadCertificateAuthorityBundles()) {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Unable to load Certificate Authority Bundles");
        }

        // load our allowed cert refresh and instance register ip blocks

        instanceCertIPBlocks = new ConcurrentHashMap<>();
        if (!loadAllowedInstanceCertIPAddresses(instanceCertIPBlocks)) {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Unable to load Provider Allowed IP Blocks");
        }

        // start our thread to refresh our allowed ip addresses every hour
        // the requirement here is that some process on the host will update
        // the files with the new ip addresses, and then we'll pick them up
        // and refresh our cache

        ipBlockScheduledExecutor = Executors.newScheduledThreadPool(1);
        ipBlockScheduledExecutor.scheduleAtFixedRate(
                new RefreshAllowedIPAddresses(instanceCertIPBlocks), 1, 1, TimeUnit.HOURS);

        // start our thread to delete expired cert records once a day
        // unless we're running in read-only mode thus no modifications
        // to the database
        final int limit = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERT_RECORD_CLEANER_LIMIT, "0"));
        final int duration = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERT_RECORD_CLEANER_DURATION, "1"));
        final TimeUnit timeUnit = parseTimeUnit(System.getProperty(ZTSConsts.ZTS_PROP_CERT_RECORD_CLEANER_TIMEUNIT, "day"));

        if (certStore != null && certSigner != null) {
            certScheduledExecutor = Executors.newScheduledThreadPool(1);
            certScheduledExecutor.scheduleAtFixedRate(
                    new ExpiredX509CertRecordCleaner(certStore, certSigner.getMaxCertExpiryTimeMins(), limit, readOnlyMode),
                    0, duration, timeUnit);
        }

        if (sshStore != null) {
            int expiryTimeMins = (int) TimeUnit.MINUTES.convert(30, TimeUnit.DAYS);
            sshScheduledExecutor = Executors.newScheduledThreadPool(1);
            sshScheduledExecutor.scheduleAtFixedRate(
                    new ExpiredSSHCertRecordCleaner(sshStore, expiryTimeMins, limit, readOnlyMode),
                    0, duration, timeUnit);
        }

        // check to see if we have it configured to validate IP addresses

        validateIPAddress = new DynamicConfigBoolean(CONFIG_MANAGER, ZTSConsts.ZTS_PROP_SSH_CERT_VALIDATE_IP, false);
    }

    static TimeUnit parseTimeUnit(String timeUnitStr) {
        switch (timeUnitStr) {
            case "second":
                return TimeUnit.SECONDS;
            case "minute":
                return TimeUnit.MINUTES;
            case "hour":
                return TimeUnit.HOURS;
            case "day":
                return TimeUnit.DAYS;
            default:
                return TimeUnit.DAYS;
        }
    }
    
    void shutdown() {
        if (certScheduledExecutor != null) {
            certScheduledExecutor.shutdownNow();
        }
        if (sshScheduledExecutor != null) {
            sshScheduledExecutor.shutdownNow();
        }
        if (ipBlockScheduledExecutor != null) {
            ipBlockScheduledExecutor.shutdownNow();
        }
    }

    // for testing only
    protected final ConcurrentHashMap<String, List<IPBlock>> getInstanceCertIPBlocks() {
        return instanceCertIPBlocks;
    }

    private boolean loadCertificateAuthorityBundles() {

        // check to see if we have been provided with an x.509/ssh certificate
        // bundle, or we need to fetch one from the certsigner

        responseSendSSHSignerCerts = Boolean.parseBoolean(
                System.getProperty(ZTSConsts.ZTS_PROP_RESP_SSH_SIGNER_CERTS, "true"));
        responseSendX509SignerCerts = Boolean.parseBoolean(
                System.getProperty(ZTSConsts.ZTS_PROP_RESP_X509_SIGNER_CERTS, "true"));

        // if we're not asked to skip sending certificate signers then
        // check to see if we need to load them from files instead of
        // cert-signer directly

        if (responseSendX509SignerCerts) {
            initializeX509ProviderCertificateSigners();
        }
        if (responseSendSSHSignerCerts) {
            initializeSSHProviderCertificateSigners();
        }

        // now let's fetch our configured certificate authority bundles

        certAuthorityBundles = new HashMap<>();

        final String caBundleFile =  System.getProperty(ZTSConsts.ZTS_PROP_CERT_BUNDLES_FNAME);
        if (StringUtil.isEmpty(caBundleFile)) {
            return true;
        }

        byte[] data = ZTSUtils.readFileContents(caBundleFile);
        if (data == null) {
            return false;
        }

        CertBundles certBundles = null;
        try {
            certBundles = JSON_MAPPER.readValue(data, CertBundles.class);
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

    void initializeSSHProviderCertificateSigners() {

        // first load our default ssh certificate signers that will be used
        // if no key-id specific signer is available

        sshUserCertificateSigner = loadCertificateBundle(ZTSConsts.ZTS_PROP_SSH_USER_CA_CERT_FNAME);
        sshHostCertificateSigner = loadCertificateBundle(ZTSConsts.ZTS_PROP_SSH_HOST_CA_CERT_FNAME);

        // initialize our provider bundle map and then check to see
        // if we have configured key-id specific providers. These must
        // be configured as a list of key-id:filename pairs

        caSshProviderCertificateSigners = new ConcurrentHashMap<>();
        iniitializeProviderCertificateSigners(caSshProviderCertificateSigners, ZTSConsts.ZTS_SSH_HOST,
                ZTSConsts.ZTS_PROP_SSH_HOST_CA_CERT_KEYID_FNAME);
        iniitializeProviderCertificateSigners(caSshProviderCertificateSigners, ZTSConsts.ZTS_SSH_USER,
                ZTSConsts.ZTS_PROP_SSH_USER_CA_CERT_KEYID_FNAME);
    }

    void initializeX509ProviderCertificateSigners() {

        // first load our default certificate bundle that will be used
        // if no key-id specific bundle is available

        caX509CertificateSigner = loadCertificateBundle(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME);

        // initialize our provider bundle map and then check to see
        // if we have configured key-id specific providers. These must
        // be configured as a list of key-id:filename pairs

        caX509ProviderCertificateSigners = new ConcurrentHashMap<>();
        iniitializeProviderCertificateSigners(caX509ProviderCertificateSigners, null,
                ZTSConsts.ZTS_PROP_X509_CA_CERT_KEYID_FNAME);
    }

    void iniitializeProviderCertificateSigners(Map<String, String> certSigners, final String reqType, final String propName) {

        final String providerKeyBundles = System.getProperty(propName, "");
        for (String providerKeyBundle : providerKeyBundles.split(",")) {
            if (providerKeyBundle.isEmpty()) {
                continue;
            }
            String[] providerKey = providerKeyBundle.split(":");
            if (providerKey.length != 2) {
                throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                        "Invalid provider certificate configuration value: " + propName + ": " + providerKeyBundle);
            }
            byte[] data = ZTSUtils.readFileContents(providerKey[1]);
            if (data == null) {
                throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                        "Unable to load Certificate bundle from: " + providerKey[1]);
            }
            final String keyName = reqType == null ? providerKey[0] : reqType + "." + providerKey[0];
            certSigners.put(keyName, new String(data));
        }
    }

    private boolean processCertificateAuthorityBundle(CertBundle bundle) {

        final String name = bundle.getName();
        final String fileName = bundle.getFilename();
        if (StringUtil.isEmpty(fileName)) {
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
            byte[] data = ZTSUtils.readFileContents(fileName);
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
            // remove any comments/etc. to minimize the data size

            return Crypto.x509CertificatesToPEM(x509Certs);

        } catch (CryptoException ex) {
            LOGGER.error("Unable to load certificate file", ex);
            return null;
        }
    }

    private static boolean loadAllowedInstanceCertIPAddresses(
            ConcurrentHashMap<String, List<IPBlock>> instanceProviderCertIPBlocks) {

        // first, let's load the default provider ip blocks for the zts svc token provider
        // we're not going to block the server from startup since this api
        // is deprecated and will be removed in the future

        List<IPBlock> svcCertIPBlocks = new ArrayList<>();
        if (loadAllowedIPAddresses(svcCertIPBlocks, System.getProperty(ZTSConsts.ZTS_PROP_CERT_REFRESH_IP_FNAME))) {
            if (hasProviderChangeThresholdNotExceeded(instanceProviderCertIPBlocks, ZTS_SVC_TOKEN_PROVIDER,
                    svcCertIPBlocks.size())) {
                instanceProviderCertIPBlocks.put(ZTS_SVC_TOKEN_PROVIDER, svcCertIPBlocks);
            }
        }

        // next, read the file list of providers and allowed IP addresses
        // if the config is not set then we have no restrictions
        // otherwise all providers must be specified in the list

        final String providerIPMapFile =  System.getProperty(ZTSConsts.ZTS_PROP_INSTANCE_CERT_IP_FNAME);
        if (StringUtil.isEmpty(providerIPMapFile)) {
            return true;
        }

        byte[] data = ZTSUtils.readFileContents(providerIPMapFile);
        if (data == null) {
            return false;
        }

        ProviderIPBlocks ipBlocks = null;
        try {
            ipBlocks = JSON_MAPPER.readValue(data, ProviderIPBlocks.class);
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
                if (hasProviderChangeThresholdNotExceeded(instanceProviderCertIPBlocks, provider, certIPBlocks.size())) {
                    instanceProviderCertIPBlocks.put(provider, certIPBlocks);
                }
            }
        }

        return true;
    }

    static boolean hasProviderChangeThresholdNotExceeded(ConcurrentHashMap<String, List<IPBlock>> providerCertIPBlocks,
            final String provider, int newSize) {

        // first check to see if the provider is already present

        List<IPBlock> existingIPBlocks = providerCertIPBlocks.get(provider);

        // we're going to skip the update if the new size is more than 25% of the original size
        // this is to prevent any accidental changes to the configuration

        if (existingIPBlocks != null && existingIPBlocks.size() - newSize > existingIPBlocks.size() / 4) {
            LOGGER.error("Provider {} IP block change threshold exceeded. Existing records: {}, new records: {}",
                    provider, existingIPBlocks.size(), newSize);
            return false;
        }

        return true;
    }

    private void loadCertSigner() {

        String certSignerFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS,
                ZTSConsts.ZTS_CERT_SIGNER_FACTORY_CLASS);
        if (StringUtil.isEmpty(certSignerFactoryClass)) {
            LOGGER.error("No CertSignerFactory class configured");
            certSigner = null;
            return;
        }
        try {
            CertSignerFactory certSignerFactory = (CertSignerFactory) Class.forName(certSignerFactoryClass)
                    .getDeclaredConstructor().newInstance();

            // create our cert signer instance

            certSigner = certSignerFactory.create();

        } catch (Exception ex) {
            LOGGER.error("Invalid CertSignerFactory class: {}", certSignerFactoryClass, ex);
            throw new IllegalArgumentException("Invalid certsigner class");
        }
    }

    private void loadSSHSigner(Authorizer authorizer) {

        final String sshSignerFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_SSH_SIGNER_FACTORY_CLASS);
        if (StringUtil.isEmpty(sshSignerFactoryClass)) {
            LOGGER.error("No SSHSignerFactory class configured");
            sshSigner = null;
            return;
        }
        try {
            SSHSignerFactory sshSignerFactory = (SSHSignerFactory) Class.forName(sshSignerFactoryClass)
                    .getDeclaredConstructor().newInstance();

            // create our cert signer instance

            sshSigner = sshSignerFactory.create();
            sshSigner.setAuthorizer(authorizer);

        } catch (Exception ex) {
            LOGGER.error("Invalid SSHSignerFactory class: {}", sshSignerFactoryClass, ex);
            throw new IllegalArgumentException("Invalid sshsigner class");
        }
    }

    void setSSHSigner(SSHSigner sshSigner) {
        this.sshSigner = sshSigner;
    }

    void setCertSigner(CertSigner certSigner) {
        this.certSigner = certSigner;
    }

    String loadCertificateBundle(final String propertyName) {

        final String caFileName = System.getProperty(propertyName);
        if (StringUtil.isEmpty(caFileName)) {
            return null;
        }

        byte[] data = ZTSUtils.readFileContents(caFileName);
        if (data == null) {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Unable to load Certificate bundle from: " + caFileName);
        }

        return new String(data);
    }

    static boolean loadAllowedIPAddresses(List<IPBlock> ipBlocks, final String ipAddressFileName) {

        if (StringUtil.isEmpty(ipAddressFileName)) {
            return true;
        }

        byte[] data = ZTSUtils.readFileContents(ipAddressFileName);
        if (data == null) {
            LOGGER.error("IP file: {} contents are null", ipAddressFileName);
            return false;
        }

        IPPrefixes prefixes = null;
        try {
            prefixes = JSON_MAPPER.readValue(data, IPPrefixes.class);
        } catch (Exception ex) {
            LOGGER.error("Unable to parse IP file: {} - {}", ipAddressFileName, ex.getMessage());
        }

        if (prefixes == null) {
            LOGGER.error("No prefixes available in the IP file: {}", ipAddressFileName);
            return false;
        }
        
        List<IPPrefix> prefixList = prefixes.getPrefixes();
        if (prefixList == null || prefixList.isEmpty()) {
            LOGGER.error("No prefix entries available in the IP file: {}", ipAddressFileName);
            return false;
        }
        
        for (IPPrefix prefix : prefixList) {
            
            // for now, we're only supporting IPv4 blocks
            
            final String ipEntry = prefix.getIpv4Prefix();
            if (ipEntry == null) {
                continue;
            }
            
            try {
                ipBlocks.add(new IPBlock(ipEntry));
            } catch (Exception ex) {
                LOGGER.error("Skipping invalid ip block entry: {}, error: {}", ipEntry, ex.getMessage());
            }
        }
        
        return true;
    }
    
    private void loadCertificateObjectStore(PrivateKeyStore keyStore) {
        
        String certRecordStoreFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_CERT_RECORD_STORE_FACTORY_CLASS,
                ZTSConsts.ZTS_CERT_RECORD_STORE_FACTORY_CLASS);
        try {
            CertRecordStoreFactory certRecordStoreFactory = (CertRecordStoreFactory) Class.forName(certRecordStoreFactoryClass)
                    .getDeclaredConstructor().newInstance();

            // create our cert record store instance

            certStore = certRecordStoreFactory.create(keyStore);
        } catch (Exception ex) {
            LOGGER.error("Invalid CertRecordStoreFactory class: {}", certRecordStoreFactoryClass, ex);
            throw new IllegalArgumentException("Invalid cert record store factory class");
        }
    }

    private void loadSSHObjectStore(PrivateKeyStore keyStore) {

        final String sshRecordStoreFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_SSH_RECORD_STORE_FACTORY_CLASS);
        if (StringUtil.isEmpty(sshRecordStoreFactoryClass)) {
            return;
        }

        try {
            SSHRecordStoreFactory sshRecordStoreFactory = (SSHRecordStoreFactory) Class.forName(sshRecordStoreFactoryClass)
                    .getDeclaredConstructor().newInstance();

            // create our cert record store instance

            sshStore = sshRecordStoreFactory.create(keyStore);

        } catch (Exception ex) {
            LOGGER.error("Invalid SSHRecordStoreFactory class: {}", sshRecordStoreFactoryClass, ex);
            throw new IllegalArgumentException("Invalid ssh record store factory class");
        }
    }

    private void loadWorkloadObjectStore(PrivateKeyStore keyStore) {

        final String workloadRecordStoreFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_WORKLOAD_RECORD_STORE_FACTORY_CLASS);
        if (StringUtil.isEmpty(workloadRecordStoreFactoryClass)) {
            return;
        }

        try {
            WorkloadRecordStoreFactory workloadRecordStoreFactory = (WorkloadRecordStoreFactory) Class.forName(workloadRecordStoreFactoryClass)
                    .getDeclaredConstructor().newInstance();

            // create our workload record store instance

            workloadStore = workloadRecordStoreFactory.create(keyStore);

        } catch (Exception ex) {
            LOGGER.error("Invalid WorkloadRecordStoreFactory class: {}", workloadRecordStoreFactoryClass, ex);
            throw new IllegalArgumentException("Invalid workload record store factory class");
        }
    }

    public void setCertStore(CertRecordStore certStore) {
        this.certStore = certStore;
    }

    public void setSSHStore(SSHRecordStore sshStore) {
        this.sshStore = sshStore;
    }

    public void setWorkloadStore(WorkloadRecordStore workloadStore) {
        this.workloadStore = workloadStore;
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
            return storeConnection.updateUnrefreshedCertificatesNotificationTimestamp(serverHostName, updateTs, provider);
        } catch (ServerResourceException ex) {
            throw ZTSUtils.error(ex);
        }
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
        } catch (ServerResourceException ex) {
            throw ZTSUtils.error(ex);
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
        } catch (ServerResourceException ex) {
            throw ZTSUtils.error(ex);
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
        } catch (ServerResourceException ex) {
            throw ZTSUtils.error(ex);
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
        } catch (ServerResourceException ex) {
            throw ZTSUtils.error(ex);
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
        } catch (ServerResourceException ex) {
            throw ZTSUtils.error(ex);
        }
        
        return result;
    }

    public String generateX509Certificate(final String provider, final String certIssuer, final String csr,
            final String keyUsage, int expiryTime, Priority priority, final String keySignerId) {

        if (certSigner == null) {
            LOGGER.error("CertSigner is not available");
            return null;
        }

        String pemCert = null;
        try {
            pemCert = certSigner.generateX509Certificate(provider, certIssuer, csr, keyUsage,
                    expiryTime, priority, keySignerId);
        } catch (ServerResourceException ex) {
            LOGGER.error("generateX509Certificate: CertSigner was unable to generate X509 certificate", ex);
        }
        if (StringUtil.isEmpty(pemCert)) {
            LOGGER.error("generateX509Certificate: CertSigner was unable to generate X509 certificate");
        }
        return pemCert;
    }

    public String getCACertificate(final String provider, final String signerKeyId) {

        if (certSigner == null) {
            LOGGER.error("CertSigner is not available");
            return null;
        }

        try {
            return certSigner.getCACertificate(provider, signerKeyId);
        } catch (ServerResourceException ex) {
            LOGGER.error("generateX509Certificate: CertSigner was unable to return CA certificate", ex);
            return null;
        }
    }

    public InstanceIdentity generateIdentity(final String provider, final String certIssuer,
            final String csr, final String cn, final String keyUsage, int expiryTime,
            Priority priority, final String signerKeyId) {
        
        // generate a certificate for this certificate request

        final String pemCert = generateX509Certificate(provider, certIssuer, csr, keyUsage,
                expiryTime, priority, signerKeyId);
        if (StringUtil.isEmpty(pemCert)) {
            return null;
        }
        
        return new InstanceIdentity().setName(cn).setX509Certificate(pemCert)
                .setX509CertificateSigner(getX509CertificateSigner(provider, signerKeyId));
    }

    public String getSignerPrimaryKey(final String provider, final String signerKeyId) {
        if (!StringUtil.isEmpty(signerKeyId)) {
            return signerKeyId;
        }
        return StringUtil.isEmpty(provider) ? "default" : provider;
    }

    public String getX509CertificateSigner(final String provider, final String signerKeyId) {

        // if configured not to send x.509 signer certs
        // then we'll return right away as null

        if (!responseSendX509SignerCerts) {
            return null;
        }

        // first check to see if we have a provider specific key configured

        final String providerKeyName = getSignerPrimaryKey(provider, signerKeyId);
        String certificateSigner = caX509ProviderCertificateSigners.get(providerKeyName);
        if (certificateSigner != null) {
            return certificateSigner;
        }

        // check to see if we have a default bundle configured

        if (caX509CertificateSigner != null) {
            return caX509CertificateSigner;
        }

        // fetch the bundle from the cert-signer and update our provider map

        certificateSigner = getCACertificate(provider, signerKeyId);
        if (certificateSigner != null) {
            caX509ProviderCertificateSigners.put(providerKeyName, certificateSigner);
        }

        return certificateSigner;
    }

    void resetX509CertificateSigner() {
        caX509CertificateSigner = null;
    }

    public SSHCertificates generateSSHCertificates(Principal principal, SSHCertRequest certRequest,
            String signerKeyId) {

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

        try {
            return sshSigner.generateCertificate(principal, certRequest, sshCertRecord, null, signerKeyId);
        } catch (ServerResourceException ex) {
            throw ZTSUtils.error(ex);
        }
    }

    SshHostCsr parseSshHostCsr(final String csr) {
        SshHostCsr sshHostCsr = null;
        try {
            sshHostCsr = JSON_MAPPER.readValue(csr, SshHostCsr.class);
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

        // check both principals and x-principal fields

        List<String> principals = null;
        if (sshHostCsr.getXPrincipals() != null) {
            principals = Arrays.asList(sshHostCsr.getXPrincipals());
        }

        List<String> keyIdPrincipals = null;
        if (sshHostCsr.getPrincipals() != null) {
            keyIdPrincipals = Arrays.asList(sshHostCsr.getPrincipals());
        }

        updateSSHHostPrincipals(principals, keyIdPrincipals, sshCertRecord);
    }

    void updateSSHHostPrincipals(SSHCertRequest sshCertRequest, SSHCertRecord sshCertRecord) {

        SSHCertRequestMeta requestMeta = sshCertRequest.getCertRequestMeta();
        SSHCertRequestData requestData = sshCertRequest.getCertRequestData();

        if (requestData == null || requestMeta == null) {
            sshCertRecord.setPrincipals("127.0.0.1");
            return;
        }

        updateSSHHostPrincipals(requestData.getPrincipals(), requestMeta.getKeyIdPrincipals(), sshCertRecord);
    }

    void updateSSHHostPrincipals(List<String> principals, List<String> keyIdPrincipals, SSHCertRecord sshCertRecord) {

        String recordPrincipals = "";

        if (principals != null || keyIdPrincipals != null) {
            Set<String> principalSet = new HashSet<>();
            if (principals != null) {
                principalSet.addAll(principals);
            }
            if (keyIdPrincipals != null) {
                principalSet.addAll(keyIdPrincipals);
            }
            if (!principalSet.isEmpty()) {
                recordPrincipals = String.join(",", principalSet);
            }
        }

        if (recordPrincipals.isEmpty()) {
            sshCertRecord.setPrincipals("127.0.0.1");
        } else {
            sshCertRecord.setPrincipals(recordPrincipals);
        }
    }

    public boolean generateSSHIdentity(Principal principal, InstanceIdentity identity, final String hostname,
            final String csr, SSHCertRequest sshCertRequest, SSHCertRecord sshCertRecord,
            final String certType, boolean refreshRequest, Set<String> attestedSshCertPrincipals,
            final String signerKeyId) {

        // in addition to our ssh signer, we must either have a non-empty
        // ssh csr or a cert request object

        if (sshSigner == null || (StringUtil.isEmpty(csr) && sshCertRequest == null)) {
            return true;
        }

        // keep track of the fact if the client provided a csr or the
        // expected ssh cert request object

        boolean sshCsrProvided = !StringUtil.isEmpty(csr);

        LOGGER.info("ssh certificate request - type: {}, data: {}, identity: {}",
                certType, sshCsrProvided ? "csr" : "sshcertrequest", identity.getName());

        if (ZTSConsts.ZTS_SSH_HOST.equals(certType)) {

            // parse our host csr

            if (sshCsrProvided) {

                SshHostCsr sshHostCsr = parseSshHostCsr(csr);
                if (!StringUtil.isEmpty(hostname) && hostnameResolver != null) {
                    if (!validPrincipals(hostname, sshCertRecord, sshHostCsr, attestedSshCertPrincipals)) {
                        LOGGER.error("SSH Host CSR validation failed, principal: {}, hostname: {}, csr: {}",
                                principal, hostname, sshHostCsr);
                        return false;
                    }
                }

                // update our ssh record object

                updateSSHHostPrincipals(sshHostCsr, sshCertRecord);

            } else {

                if (!validPrincipals(hostname, sshCertRecord, sshCertRequest, attestedSshCertPrincipals)) {
                    LOGGER.error("SSH Host CSR validation failed, principal: {}, hostname: {}, ssh-cert-request: {}",
                            principal, hostname, sshCertRequest);
                    return false;
                }

                // update our ssh record object

                updateSSHHostPrincipals(sshCertRequest, sshCertRecord);
            }
        }

        // if we have a csr specified then we're going to generate a new
        // empty ssh cert request object with the csr field set

        if (sshCsrProvided) {
            sshCertRequest = new SSHCertRequest().setCsr(csr);
        }

        SSHCertificates sshCerts;
        try {
            sshCerts = sshSigner.generateCertificate(principal, sshCertRequest, sshCertRecord, certType, signerKeyId);
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

        updateSSHCertRecord(sshCertRecord, refreshRequest);

        // update our identity object with ssh cert details

        identity.setSshCertificate(sshCerts.getCertificates().get(0).getCertificate());
        identity.setSshCertificateSigner(getSSHCertificateSigner(certType, signerKeyId));
        return true;
    }

    String getSSHCertificateSigner(final String sshReqType, final String signerKeyId) {

        // if configured not to send SSH signer certs
        // then we'll return right away as null

        if (!responseSendSSHSignerCerts || sshSigner == null) {
            return null;
        }

        final String primaryKeyName = sshReqType + "." + (StringUtil.isEmpty(signerKeyId) ? "default" : signerKeyId);
        String certificateSigner = caSshProviderCertificateSigners.get(primaryKeyName);
        if (certificateSigner != null) {
            return certificateSigner;
        }

        certificateSigner = sshReqType.equals(ZTSConsts.ZTS_SSH_HOST) ? sshHostCertificateSigner : sshUserCertificateSigner;
        if (certificateSigner != null) {
            return certificateSigner;
        }

        try {
            certificateSigner = sshSigner.getSignerCertificate(sshReqType, signerKeyId);
        } catch (ServerResourceException ex) {
            LOGGER.error("getSSHCertificateSigner: SSHSigner was unable to return signer certificate", ex);
        }
        if (certificateSigner != null) {
            caSshProviderCertificateSigners.put(primaryKeyName, certificateSigner);
        }

        return certificateSigner;
    }
    
    public boolean authorizeLaunch(Principal providerService, String domain, String service,
            StringBuilder errorMsg) {
        
        // first we need to make sure that the provider has been
        // authorized in Athenz to bootstrap/launch instances
        
        if (!authorizer.access(ServerCommonConsts.ACTION_LAUNCH, ServerCommonConsts.RESOURCE_INSTANCE,
                providerService, null)) {
            errorMsg.append("provider '").append(providerService.getFullName())
                .append("' not authorized to launch instances in Athenz");
            return false;
        }
        
        // next we need to verify that the service has authorized
        // the provider to bootstrap/launch an instance
        
        final String tenantResource = domain + ":service." + service;
        if (!authorizer.access(ServerCommonConsts.ACTION_LAUNCH, tenantResource,
                providerService, null)) {
            errorMsg.append("provider '").append(providerService.getFullName())
                .append("' not authorized to launch ").append(domain).append('.')
                .append(service).append(" instances");
            return false;
        }
        
        return true;
    }
    
    public boolean verifyCertRefreshIPAddress(final String ipAddress) {
        final List<IPBlock> certIPBlocks = instanceCertIPBlocks.get(ZTS_SVC_TOKEN_PROVIDER);
        if (certIPBlocks == null) {
            return true;
        }
        return verifyIPAddressAccess(ipAddress, certIPBlocks);
    }

    public boolean verifyInstanceCertIPAddress(final String provider, final String ipAddress) {

        final List<IPBlock> certIPBlocks = instanceCertIPBlocks.get(provider);

        // if we have no blocks defined for the provider, then we'll return
        // failure if we have others defined or success if there are no
        // providers defined at all

        if (certIPBlocks == null) {
            return instanceCertIPBlocks.isEmpty()
                    || (instanceCertIPBlocks.size() == 1 && instanceCertIPBlocks.containsKey(ZTS_SVC_TOKEN_PROVIDER));
        }

        return verifyIPAddressAccess(ipAddress, certIPBlocks);
    }

    /**
     * validates hostname against the resolver, and verifies that the ssh principals map to hostname
     * @param hostname of the instance
     * @param sshCertRecord ssh certificate record stored in db
     * @param sshHostCsr ssh host csr from the sia
     * @return boolean true or false
     */
    public boolean validPrincipals(final String hostname, SSHCertRecord sshCertRecord, SshHostCsr sshHostCsr,
            Set<String> attestedSshCertPrincipals) {

        if (sshHostCsr == null) {
            return false;
        }

        String[] principals = sshHostCsr.getPrincipals();
        String[] xPrincipals = sshHostCsr.getXPrincipals();

        // Pass through when xPrincipals is not specified

        if (xPrincipals == null) {
            LOGGER.error("CSR has no xPrincipals to verify, hostname: {}, principals: {}", hostname, principals);
            return true;
        }

        LOGGER.debug("Validate CSR principals: {}, xPrincipals: {}", principals, xPrincipals);
        return validateSSHHostnames(hostname, Arrays.asList(xPrincipals), sshCertRecord,
                attestedSshCertPrincipals, false);
    }

    public boolean validPrincipals(final String hostname, SSHCertRecord sshCertRecord,
            SSHCertRequest sshCertRequest, Set<String> attestedSshCertPrincipals) {

        SSHCertRequestData requestData = sshCertRequest.getCertRequestData();

        // if there are no principals specified, then we have nothing to check

        if (requestData == null) {
            return true;
        }

        List<String> principals = requestData.getPrincipals();

        // pass through when no principals are specified

        if (principals == null || principals.isEmpty()) {
            return true;
        }

        LOGGER.debug("Validate CSR principals: {}", principals);
        return validateSSHHostnames(hostname, principals, sshCertRecord, attestedSshCertPrincipals,
                validateIPAddress.get());
    }

    boolean validateSSHHostnames(final String hostname, List<String> principals, SSHCertRecord sshCertRecord,
            Set<String> attestedSshCertPrincipals, boolean validateIPs) {

        // if we don't have a hostname resolver then we won't be able
        // to validate any values, so we'll return failure right away

        if (hostnameResolver == null) {
            LOGGER.error("Hostname resolver not configured to validate ssh hostnames");
            return false;
        }

        List<String> cnames = new ArrayList<>();
        for (String name : principals) {

            // Skip attested host cert principals

            if (attestedSshCertPrincipals.contains(name)) {
                continue;
            }

            // all valid IP addresses should have been included in the
            // attested ssh cert principals so if we're configured to
            // validate them, we'll return failure right away

            if (InetAddresses.isInetAddress(name)) {
                LOGGER.error("{} is not a valid IP address for SSH principal", name);
                if (validateIPs) {
                    return false;
                }
                continue;
            }

            // Skip direct hostname principals

            if (name.equals(hostname)) {

                // verify that the hostname is a known name

                if (!hostnameResolver.isValidHostname(hostname)) {
                    LOGGER.error("{} is not a valid hostname", hostname);
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

        LOGGER.debug("validating principals in the ssh request/csr: {}", cnames);

        if (!hostnameResolver.isValidHostCnameList(sshCertRecord.getService(), hostname, cnames, CertType.SSH_HOST)) {
            LOGGER.error("{} does not map to some cnames {}", hostname, cnames);
            return false;
        }

        return true;
    }

    boolean verifyIPAddressAccess(final String ipAddress, final List<IPBlock> ipBlocks) {
        
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
        } catch (ServerResourceException ex) {
            throw ZTSUtils.error(ex);
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

        boolean result = false;
        try (SSHRecordStoreConnection storeConnection = sshStore.getConnection()) {

            // if it's a refresh we're going to try to update first

            if (refresh && storeConnection.updateSSHCertRecord(certRecord)) {
                return true;
            }

            // if it's a register operation or if we get a failure, in the case
            // of refresh, then it's possible that we don't have the record, so
            // we're going to create it

            result = storeConnection.insertSSHCertRecord(certRecord);
        } catch (Exception ex) {
            LOGGER.error("Unable to store ssh certificate record for principal {} - {}",
                    certRecord.getPrincipals(), ex.getMessage());
        }

        return result;
    }

    public boolean enableCertStoreNotifications(NotificationManager notificationManager, RolesProvider rolesProvider,
            String serverName) {
        boolean notificationsEnabled = false;
        if (certStore != null) {
            notificationsEnabled = certStore.enableNotifications(notificationManager, rolesProvider, serverName);
        }

        LOGGER.info("certStore Notifications {}", (notificationsEnabled ? "enabled" : "disabled"));
        return notificationsEnabled;
    }

    public boolean enableSSHStoreNotifications(NotificationManager notificationManager, RolesProvider rolesProvider,
            String serverName) {
        boolean notificationsEnabled = false;
        if (sshStore != null) {
            notificationsEnabled = sshStore.enableNotifications(notificationManager, rolesProvider, serverName);
        }

        LOGGER.info("sshStore Notifications {}", (notificationsEnabled ? "enabled" : "disabled"));
        return notificationsEnabled;
    }

    public boolean insertWorkloadRecord(WorkloadRecord workloadRecord) {

        if (workloadStore == null) {
            return false;
        }

        boolean result = false;
        try (WorkloadRecordStoreConnection storeConnection = workloadStore.getConnection()) {
            result = storeConnection.insertWorkloadRecord(workloadRecord);
        } catch (ServerResourceException ex) {
            LOGGER.error("Unable to insert workload record: {}", ex.getMessage());
        }

        return result;
    }

    public boolean updateWorkloadRecord(WorkloadRecord workloadRecord) {

        if (workloadStore == null) {
            return false;
        }

        boolean result = false;
        try (WorkloadRecordStoreConnection storeConnection = workloadStore.getConnection()) {
            result = storeConnection.updateWorkloadRecord(workloadRecord);
            if (!result) {
                // failed update could be because of a new IP address for the same instance id,
                // so we are going to try insert operation.
                result = storeConnection.insertWorkloadRecord(workloadRecord);
            }
        } catch (ServerResourceException ex) {
            LOGGER.error("Unable to update workload record: {}", ex.getMessage());
        }
        return result;
    }

    public List<Workload> getWorkloadsByService(String domain, String service) {
        if (workloadStore == null) {
            return Collections.emptyList();
        }
        try (WorkloadRecordStoreConnection storeConnection = workloadStore.getConnection()) {
            List<WorkloadRecord> workloadRecords = storeConnection.getWorkloadRecordsByService(domain, service);
            Map<String, List<String>> flattenedIpAddresses = new HashMap<>();
            String mapKey;
            for (WorkloadRecord workloadRecord : workloadRecords) {
                mapKey = workloadRecord.getInstanceId() + ":" + workloadRecord.getProvider() +
                        ":" + workloadRecord.getUpdateTime().getTime() +
                        ":" + workloadRecord.getCertExpiryTime().getTime() + ":" + workloadRecord.getHostname();
                if (flattenedIpAddresses.containsKey(mapKey)) {
                    flattenedIpAddresses.get(mapKey).add(workloadRecord.getIp());
                } else {
                    List<String> ipList = new ArrayList<>();
                    ipList.add(workloadRecord.getIp());
                    flattenedIpAddresses.put(mapKey, ipList);
                }
            }
            return flattenedIpAddresses.entrySet().stream().map(entry -> {
                Workload wl = new Workload();
                String[] tempArr = entry.getKey().split(":");
                wl.setUuid(tempArr[0])
                        .setProvider(tempArr[1])
                        .setUpdateTime(Timestamp.fromMillis(Long.parseLong(tempArr[2])))
                        .setCertExpiryTime(Timestamp.fromMillis(Long.parseLong(tempArr[3])))
                        .setHostname(tempArr[4])
                        .setIpAddresses(entry.getValue());
                return wl;
            }).collect(Collectors.toList());
        } catch (ServerResourceException ex) {
            throw ZTSUtils.error(ex);
        }
    }

    public List<Workload> getWorkloadsByIp(String ip) {
        if (workloadStore == null) {
            return Collections.emptyList();
        }
        try (WorkloadRecordStoreConnection storeConnection = workloadStore.getConnection()) {
            return storeConnection.getWorkloadRecordsByIp(ip).stream()
                    .map(wr -> {
                        Workload wl = new Workload();
                        String[] strArr = AthenzUtils.splitPrincipalName(wr.getService());
                        if (strArr != null) {
                            wl.setDomainName(strArr[0]).setServiceName(strArr[1]);
                        }
                        wl.setProvider(wr.getProvider()).setUuid(wr.getInstanceId())
                                .setUpdateTime(Timestamp.fromDate(wr.getUpdateTime()))
                                .setHostname(wr.getHostname())
                                .setCertExpiryTime(Timestamp.fromDate(wr.getCertExpiryTime()));                        return wl;
                    })
                    .filter(distinctByKey(w -> w.getUuid() + "#" +
                            AthenzUtils.getPrincipalName(w.getDomainName(), w.getServiceName())))
                    .collect(Collectors.toList());
        } catch (ServerResourceException ex) {
            throw ZTSUtils.error(ex);
        }
    }

    public static <T> Predicate<T> distinctByKey(Function<? super T, Object> keyExtractor) {
        Map<Object, Boolean> map = new ConcurrentHashMap<>();
        return t -> map.putIfAbsent(keyExtractor.apply(t), Boolean.TRUE) == null;
    }

    static class ExpiredX509CertRecordCleaner implements Runnable {
        
        private final CertRecordStore store;
        private final int expiryTimeMins;
        private final int limit;
        private final DynamicConfigBoolean readOnlyMode;

        public ExpiredX509CertRecordCleaner(CertRecordStore store, int expiryTimeMins, int limit, DynamicConfigBoolean readOnlyMode) {
            this.store = store;
            this.expiryTimeMins = expiryTimeMins;
            this.limit = limit;
            this.readOnlyMode = readOnlyMode;
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

            // if we're running in read only mode, there is nothing to do

            if (readOnlyMode.get()) {
                return 0;
            }

            int deletedRecords;
            try (CertRecordStoreConnection storeConnection = store.getConnection()) {
                deletedRecords = storeConnection.deleteExpiredX509CertRecords(expiryTimeMins, limit);
            } catch (ServerResourceException ex) {
                throw ZTSUtils.error(ex);
            }
            return deletedRecords;
        }
    }

    static class ExpiredSSHCertRecordCleaner implements Runnable {

        private final SSHRecordStore store;
        private final int expiryTimeMins;
        private final int limit;
        private final DynamicConfigBoolean readOnlyMode;

        public ExpiredSSHCertRecordCleaner(SSHRecordStore store, int expiryTimeMins, int limit, DynamicConfigBoolean readOnlyMode) {
            this.store = store;
            this.expiryTimeMins = expiryTimeMins;
            this.limit = limit;
            this.readOnlyMode = readOnlyMode;
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

            // if we're running in read only mode, there is nothing to do

            if (readOnlyMode.get()) {
                return 0;
            }

            int deletedRecords;
            try (SSHRecordStoreConnection storeConnection = store.getConnection()) {
                deletedRecords = storeConnection.deleteExpiredSSHCertRecords(expiryTimeMins, limit);
            } catch (ServerResourceException ex) {
                throw ZTSUtils.error(ex);
            }
            return deletedRecords;
        }
    }

    static class RefreshAllowedIPAddresses implements Runnable {

        ConcurrentHashMap<String, List<IPBlock>> instanceProviderCertIPBlocks;

        public RefreshAllowedIPAddresses(ConcurrentHashMap<String, List<IPBlock>> instanceProviderCertIPBlocks) {
            this.instanceProviderCertIPBlocks = instanceProviderCertIPBlocks;
        }

        @Override
        public void run() {

            LOGGER.info("RefreshAllowedIPAddresses: Starting to refresh allowed IP block list thread...");
            loadAllowedInstanceCertIPAddresses(instanceProviderCertIPBlocks);
            LOGGER.info("RefreshAllowedIPAddresses: Completed refreshing allowed IP block lists");
        }
    }
}
