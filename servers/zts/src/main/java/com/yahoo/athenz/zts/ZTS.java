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

package com.yahoo.athenz.zts;

import java.net.InetAddress;
import java.security.PrivateKey;

import org.eclipse.jetty.server.HttpConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.AuthorityKeyStore;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.PrivateKeyStoreFactory;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.metrics.MetricFactory;
import com.yahoo.athenz.common.server.log.AuditLogFactory;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.rest.Http.AuthorityList;
import com.yahoo.athenz.zts.cert.CertSigner;
import com.yahoo.athenz.zts.cert.CertSignerFactory;
import com.yahoo.athenz.zts.cert.InstanceIdentityStore;
import com.yahoo.athenz.zts.cert.InstanceIdentityStoreFactory;
import com.yahoo.athenz.zts.store.ChangeLogStore;
import com.yahoo.athenz.zts.store.ChangeLogStoreFactory;
import com.yahoo.athenz.zts.store.CloudStore;
import com.yahoo.athenz.zts.store.DataStore;

public class ZTS {

    private static final Logger LOG = LoggerFactory.getLogger(ZTS.class);

    static final String ZTS_PRINCIPAL_AUTHORITY_CLASS = "com.yahoo.athenz.auth.impl.PrincipalAuthority";
    static final String ZTS_CHANGE_LOG_STORE_FACTORY_CLASS = "com.yahoo.athenz.zts.store.file.ZMSFileChangeLogStoreFactory";
    static final String ZTS_PKEY_STORE_FACTORY_CLASS = "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory";
    static final String ZTS_CERT_SIGNER_FACTORY_CLASS = "com.yahoo.athenz.zts.cert.impl.HttpCertSignerFactory";
    static final String ZTS_INSTANCE_IDENTITY_STORE_FACTORY_CLASS = "com.yahoo.athenz.zts.cert.impl.LocalInstanceIdentityStoreFactory";

    // This String is used to create the desired AuditLogMsgBuilder object.
    // Its OK if its null, we will just get the default msg builder.
    //
    private static String AUDIT_LOG_MSG_BLDR_CLASS;

    static {
        try {
            AUDIT_LOG_MSG_BLDR_CLASS = System.getProperty(ZTSConsts.ZTS_PROP_AUDIT_LOG_MSG_BLDR_CLASS);
            // test the class to ensure it is valid
            try {
                @SuppressWarnings("unused")
                AuditLogMsgBuilder msgBldr = AuditLogFactory.getMsgBuilder(AUDIT_LOG_MSG_BLDR_CLASS);
            } catch (Exception exc) {
                LOG.warn("AuditLogMsgBuilder: Cannot instantiate message builder class from="
                        + AUDIT_LOG_MSG_BLDR_CLASS
                        + ", therefore will use default log message builder class instead: "
                         + exc.getMessage());
                AUDIT_LOG_MSG_BLDR_CLASS = null;
            }
        } catch (Exception exc) {
            LOG.warn("Failed to get the audit log message builder class using property="
                    + ZTSConsts.ZTS_PROP_AUDIT_LOG_MSG_BLDR_CLASS
                    + ", ZTS will use the default log message builder class instead: "
                     + exc.getMessage());
           AUDIT_LOG_MSG_BLDR_CLASS = null;
        }
    }

    private static final AuditLogger AUDITLOG = getAuditLogger();

    // Creates an AuditLogger
    //
    static AuditLogger getAuditLogger() {
        String auditLoggerClassName      = System.getProperty(ZTSConsts.ZTS_PROP_AUDIT_LOGGER_CLASS);
        String auditLoggerClassNameParam = System.getProperty(ZTSConsts.ZTS_PROP_AUDIT_LOGGER_CLASS_PARAM);
        AuditLogger auditLog = null;
        try {
            if (auditLoggerClassNameParam != null) {
                auditLog = AuditLogFactory.getLogger(auditLoggerClassName, auditLoggerClassNameParam);
            } else {
                auditLog = AuditLogFactory.getLogger(auditLoggerClassName);
            }
        } catch (Exception exc) {
            LOG.warn("Failed to create audit logger from class="
                    + auditLoggerClassName + ", ZTS will use the default logger instead: "
                     + exc.getMessage());
            auditLog = AuditLogFactory.getLogger();
        }
        return auditLog;
    }

    static Authority getAuthority(String className) {
        
        LOG.debug("Loading authority {}...", className);
        
        Authority authority = null;
        try {
            authority = (Authority) Class.forName(className).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOG.error("Invalid Authority class: " + className + " error: " + e.getMessage());
            return null;
        }
        return authority;
    }
    
    static String getServerHostName() {
        
        String serverHostName = System.getProperty(ZTSConsts.ZTS_PROP_HOSTNAME);
        if (serverHostName == null || serverHostName.isEmpty()) {
            try {
                InetAddress localhost = java.net.InetAddress.getLocalHost();
                serverHostName = localhost.getCanonicalHostName();
            } catch (java.net.UnknownHostException e) {
                LOG.info("Unable to determine local hostname: " + e.getMessage());
                serverHostName = "localhost";
            }
        }
        
        return serverHostName;
    }
    
    static int getPortNumber(String property, int defaultValue) {
        
        String propValue = System.getProperty(property);
        if (propValue == null) {
            return defaultValue;
        }
        
        int port = defaultValue;
        try {
            
            // first try to convert the string property to integer
            
            port = Integer.parseInt(propValue);
            
            // now verify that it's a valid port number
            
            if (port < 0 || port > 65535) {
                throw new NumberFormatException();
            }
            
        } catch (NumberFormatException ex) {
            LOG.info("Invalid port: " + propValue + ". Using default port: " + defaultValue);
            port = defaultValue;
        }
        
        return port;
    }
    
    static CertSigner getCertSigner() {
        
        String certSignerFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS,
                ZTS_CERT_SIGNER_FACTORY_CLASS);
        CertSignerFactory certSignerFactory = null;
        try {
            certSignerFactory = (CertSignerFactory) Class.forName(certSignerFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOG.error("Invalid CertSigerFactory class: " + certSignerFactoryClass
                    + " error: " + e.getMessage());
            return null;
        }

        // create our cert signer instance
        
        return certSignerFactory.create();
    }

    static InstanceIdentityStore getInstanceIdentityStore(CertSigner certSigner) {

        String instanceIdentityStoreFactoryClass = System.getProperty(
                ZTSConsts.ZTS_PROP_INSTANCE_IDENTITY_STORE_FACTORY_CLASS,
                ZTS_INSTANCE_IDENTITY_STORE_FACTORY_CLASS);
        InstanceIdentityStoreFactory instanceIdentityStoreFactory = null;
        try {
            instanceIdentityStoreFactory = (InstanceIdentityStoreFactory)
                    Class.forName(instanceIdentityStoreFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOG.error("Invalid InstanceIdentityStoreFactory class: " + instanceIdentityStoreFactoryClass
                    + " error: " + e.getMessage());
            return null;
        }

        // create our instance identity store instance

        return instanceIdentityStoreFactory.create(certSigner);
    }
    
    static Metric getMetric() {
        
        String metricFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_METRIC_FACTORY_CLASS,
                ZTSConsts.ZTS_METRIC_FACTORY_CLASS);
        boolean statsEnabled = Boolean.parseBoolean(System.getProperty(ZTSConsts.ZTS_PROP_STATS_ENABLED, "false"));
        if (!statsEnabled && !metricFactoryClass.equals(ZTSConsts.ZTS_METRIC_FACTORY_CLASS)) {
            LOG.warn("Override users metric factory property with default since stats are disabled");
            metricFactoryClass = ZTSConsts.ZTS_METRIC_FACTORY_CLASS;
        }
        
        MetricFactory metricFactory = null;
        try {
            metricFactory = (MetricFactory) Class.forName(metricFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOG.error("Invalid MetricFactory class: " + metricFactoryClass
                    + " error: " + e.getMessage());
            return null;
        }
        
        Metric metric = metricFactory.create();
        if (metric != null) {
            metric.increment("zts_startup");
        }
        return metric;
    }
    
    static PrivateKeyStore getPrivateKeyStore() {
        
        String pkeyFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                ZTS_PKEY_STORE_FACTORY_CLASS);
        PrivateKeyStoreFactory pkeyFactory = null;
        try {
            pkeyFactory = (PrivateKeyStoreFactory) Class.forName(pkeyFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOG.error("Invalid PrivateKeyStoreFactory class: " + pkeyFactoryClass
                    + " error: " + e.getMessage());
            return null;
        }
        
        return pkeyFactory.create();
    }
    
    
    private static ChangeLogStore getChangeLogStore(String homeDir, PrivateKey pkey, String pkeyId,
            CloudStore cloudStore) {

        String clogFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_DATA_CHANGE_LOG_STORE_FACTORY_CLASS,
                ZTS_CHANGE_LOG_STORE_FACTORY_CLASS);
        ChangeLogStoreFactory clogFactory = null;
        try {
            clogFactory = (ChangeLogStoreFactory) Class.forName(clogFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOG.error("Invalid ChangeLogStoreFactory class: " + clogFactoryClass
                    + " error: " + e.getMessage());
            return null;
        }
        
        // create our struct store
        
        return clogFactory.create(homeDir, pkey, pkeyId, cloudStore);
    }
    
    public static ZTSJettyContainer createJettyContainer() {
        
        String root = System.getenv("ROOT");
        if (root == null) {
            root = "/home/athenz";
        }
        
        String homeDir = System.getProperty(ZTSConsts.ZTS_PROP_HOME, root + "/var/zts_server");
        
        // retrieve our http and https port numbers
        
        int httpPort = getPortNumber(ZTSConsts.ZTS_PROP_HTTP_PORT, ZTSConsts.ZTS_HTTP_PORT_DEFAULT);
        int httpsPort = getPortNumber(ZTSConsts.ZTS_PROP_HTTPS_PORT, ZTSConsts.ZTS_HTTPS_PORT_DEFAULT);
        
        String serverHostName = getServerHostName();
        
        // get our authorities
        
        String authListConfig = System.getProperty(ZTSConsts.ZTS_PROP_AUTHORITY_CLASSES,
                ZTS_PRINCIPAL_AUTHORITY_CLASS);
        AuthorityList authorities = new AuthorityList();

        String[] authorityList = authListConfig.split(",");
        for (int idx = 0; idx < authorityList.length; idx++) {
            Authority authority = getAuthority(authorityList[idx]);
            if (authority == null) {
                return null;
            }
            authority.initialize();
            authorities.add(authority);
        }
        
        PrivateKeyStore keyStore = getPrivateKeyStore();
        if (keyStore == null) {
            return null;
        }
        
        CertSigner certSigner = getCertSigner();
        if (certSigner == null) {
            return null;
        }

        Metric metric = getMetric();
        if (metric == null) {
            return null;
        }
        
        /// extract our official per-host ZTS private key
        
        StringBuilder privKeyId = new StringBuilder(256);
        PrivateKey pkey = keyStore.getPrivateKey(ZTSConsts.ZTS_SERVICE, serverHostName, privKeyId);
        
        // create our cloud store if configured
        
        CloudStore cloudStore = new CloudStore(certSigner);

        // create our instance identity store

        InstanceIdentityStore instanceIdentityStore = getInstanceIdentityStore(certSigner);
        if (instanceIdentityStore == null) {
            return null;
        }
        
        // create our change log store
        
        ChangeLogStore clogStore = getChangeLogStore(homeDir, pkey, privKeyId.toString(), cloudStore);
        if (clogStore == null) {
            return null;
        }

        // create our data store
        
        DataStore dataStore = new DataStore(clogStore, cloudStore);
        
        // Initialize our storage subsystem which would load all data into
        // memory and if necessary retrieve the data from ZMS. It will also
        // create the thread to monitor for changes from ZMS
        
        if (!dataStore.init()) {
            metric.increment("zts_startup_fail_sum");
            throw new ResourceException(500, "Unable to initialize storage subsystem");
        }
        
        // create our Jetty container
        
        ZTSJettyContainer container = new ZTSJettyContainer(AUDITLOG, AUDIT_LOG_MSG_BLDR_CLASS);
        container.resource(ZTSResources.class);
        
        // Create our ZTS impl handler
        
        ZTSImpl ztsImpl = null;
        try {
            ztsImpl = new ZTSImpl(serverHostName, dataStore, cloudStore, instanceIdentityStore, metric,
                    pkey, privKeyId.toString(), AUDITLOG, AUDIT_LOG_MSG_BLDR_CLASS);
            ztsImpl.putAuthorityList(authorities);
        } catch (Exception ex) {
            metric.increment("zts_startup_fail_sum");
            throw ex;
        }
        container.delegate(new ZTSBinder(ztsImpl));

        // make sure to set the keystore for any instance that requires it
        
        for (Authority authority : authorities.getAuthorities()) {
            if (AuthorityKeyStore.class.isInstance(authority)) {
                ((AuthorityKeyStore) authority).setKeyStore(ztsImpl);
            }
        }
        
        container.setBanner("http://" + serverHostName + " http port: " +
                httpPort + " https port: " + httpsPort);
        int maxThreads = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_MAX_THREADS, "1024"));
        container.createServer(maxThreads);
        
        HttpConfiguration httpConfig = container.newHttpConfiguration(httpsPort);
        container.addHTTPConnectors(httpConfig, httpPort, httpsPort);
        container.addServletHandlers(homeDir, serverHostName);
        
        container.addRequestLogHandler(root);
        return container;
    }

    public static void main(String [] args) {

        System.getProperties().remove("socksProxyHost");
        
        try {
            ZTSJettyContainer container = createJettyContainer();
            container.run(null);
            
        } catch (Exception exc) {
            
            // log that we are shutting down and re-throw the exception
            
            LOG.error("Startup failure. Shutting down: " + exc.getMessage());
            throw exc;
        }
    }
}
