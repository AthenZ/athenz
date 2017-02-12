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

package com.yahoo.athenz.zms;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.eclipse.jetty.server.HttpConfiguration;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.PrivateKeyStoreFactory;
import com.yahoo.athenz.common.metrics.MetricFactory;
import com.yahoo.athenz.common.server.log.AuditLogFactory;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.rest.Http.AuthorityList;

import java.net.InetAddress;

public class ZMS {

    private static final Logger LOG = LoggerFactory.getLogger(ZMS.class);

    private static final String ZMS_PRINCIPAL_AUTHORITY_CLASS = "com.yahoo.athenz.auth.impl.PrincipalAuthority";
    private static final String ZMS_PKEY_STORE_FACTORY_CLASS = "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory";
    
    private static String ROOT_DIR;
    
    // This String is used to create the desired AuditLogMsgBuilder object.
    // Its OK if its null, we will just get the default msg builder.
    //
    private static String AUDIT_LOG_MSG_BLDR_CLASS;
    static {
        try {
            AUDIT_LOG_MSG_BLDR_CLASS = System.getProperty(ZMSConsts.ZMS_PROP_AUDIT_LOG_MSG_BLDR_CLASS);
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
                    + ZMSConsts.ZMS_PROP_AUDIT_LOG_MSG_BLDR_CLASS
                    + ", ZMS will use the default log message builder class instead: "
                    + exc.getMessage());
            AUDIT_LOG_MSG_BLDR_CLASS = null;
        }
    }

    private static final AuditLogger AUDITLOG = getAuditLogger();

    // Create an AuditLogger
    //
    static AuditLogger getAuditLogger() {
        String auditLoggerClassName      = System.getProperty(ZMSConsts.ZMS_PROP_AUDIT_LOGGER_CLASS);
        String auditLoggerClassNameParam = System.getProperty(ZMSConsts.ZMS_PROP_AUDIT_LOGGER_CLASS_PARAM);
        AuditLogger auditLog = null;
        try {
            if (auditLoggerClassNameParam != null) {
                auditLog = AuditLogFactory.getLogger(auditLoggerClassName, auditLoggerClassNameParam);
            } else {
                auditLog = AuditLogFactory.getLogger(auditLoggerClassName);
            }
        } catch (Exception exc) {
            LOG.warn("Failed to create audit logger from class="
                    + auditLoggerClassName + ", ZMS will use the default logger instead: "
                    + exc.getMessage());
            auditLog = AuditLogFactory.getLogger();
        }
        return auditLog;
    }
    
    static String getServerHostName() {
        
        String serverHostName = System.getProperty(ZMSConsts.ZMS_PROP_HOSTNAME);
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
            LOG.info("invalid port: " + propValue + ". Using default port: " + defaultValue);
            port = defaultValue;
        }
        
        return port;
    }
    
    public static String getRootDir() {
        
        if (ROOT_DIR == null) {
            ROOT_DIR = System.getenv(ZMSConsts.STR_ENV_ROOT);
        }
        
        if (ROOT_DIR == null) {
            ROOT_DIR = ZMSConsts.STR_DEF_ROOT;
        }

        return ROOT_DIR;
    }
    
    public static ZMSJettyContainer createJettyContainer() {
        
        ZMSJettyContainer container = null;
        
        // retrieve our http and https port numbers
        
        int httpPort = getPortNumber(ZMSConsts.ZMS_PROP_HTTP_PORT, ZMSConsts.ZMS_HTTP_PORT_DEFAULT);
        int httpsPort = getPortNumber(ZMSConsts.ZMS_PROP_HTTPS_PORT, ZMSConsts.ZMS_HTTPS_PORT_DEFAULT);

        String serverHostName = getServerHostName();
        
        // get our authorities
        
        String authListConfig = System.getProperty(ZMSConsts.ZMS_PROP_AUTHORITY_CLASSES,
                ZMS_PRINCIPAL_AUTHORITY_CLASS);
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
        
        String pkeyFactoryClass = System.getProperty(ZMSConsts.ZMS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                ZMS_PKEY_STORE_FACTORY_CLASS);
        PrivateKeyStoreFactory pkeyFactory = null;
        try {
            pkeyFactory = (PrivateKeyStoreFactory) Class.forName(pkeyFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOG.error("Invalid PrivateKeyStoreFactory class: " + pkeyFactoryClass
                    + " error: " + e.getMessage());
            return null;
        }
        
        String metricFactoryClass = System.getProperty(ZMSConsts.ZMS_PROP_METRIC_FACTORY_CLASS,
                ZMSConsts.ZMS_METRIC_FACTORY_CLASS);
        boolean statsEnabled = Boolean.parseBoolean(System.getProperty(ZMSConsts.ZMS_PROP_STATS_ENABLED, "false"));
        if (!statsEnabled && !metricFactoryClass.equals(ZMSConsts.ZMS_METRIC_FACTORY_CLASS)) {
            LOG.warn("Override users metric factory property with default since stats are disabled");
            metricFactoryClass = ZMSConsts.ZMS_METRIC_FACTORY_CLASS;
        }

        MetricFactory metricFactory = null;
        try {
            metricFactory = (MetricFactory) Class.forName(metricFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOG.error("Invalid MetricFactory class: " + metricFactoryClass
                    + " error: " + e.getMessage());
            return null;
        }
        
        ZMSServerImpl core = new ZMSServerImpl(serverHostName, pkeyFactory, metricFactory,
                AUDITLOG, AUDIT_LOG_MSG_BLDR_CLASS, authorities);
        
        container = new ZMSJettyContainer(AUDITLOG);
        container.resource(ZMSResources.class);
        container.delegate(ZMSHandler.class, core.getInstance());
        container.setBanner("http://" + serverHostName + " http port: " +
                httpPort + " https port: " + httpsPort);

        int maxThreads = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_MAX_THREADS, "1024"));
        container.createServer(maxThreads);
        
        HttpConfiguration httpConfig = container.newHttpConfiguration(httpsPort);
        container.addHTTPConnectors(httpConfig, httpPort, httpsPort);
        container.addServletHandlers(serverHostName);
        
        container.addRequestLogHandler(getRootDir());
        
        return container;
    }

    public static void main(String [] args) throws Exception {

        System.getProperties().remove("socksProxyHost");

        try {
            ZMSJettyContainer container = createJettyContainer();
            container.run(null);
        } catch (Exception exc) {
            
            // log that we are shutting down, re-throw the exception
            
            LOG.error("Startup failure. Shutting down: " + exc.getMessage());
            throw exc;
        }
    }
}
