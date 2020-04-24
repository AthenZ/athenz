/**
 * Copyright 2017 Yahoo Inc.
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
package com.yahoo.athenz.example.instance.provider;

import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.glassfish.jersey.internal.inject.AbstractBinder;
import org.glassfish.jersey.jackson.JacksonFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;

public class InstanceProviderContainer {

    private static final String ZMS_KEYSTORE_PASSWORD = "yahoo.zms.ssl_key_store_password";
    private static final String ZMS_TRUSTSTORE_PASSWORD = "yahoo.zms.ssl_trust_store_password";
    private static final String ZMS_KEYSTORE_PATH = "yahoo.zms.ssl_key_store";
    private static final String ZMS_KEYSTORE_TYPE = "yahoo.zms.ssl_key_store_type";
    private static final String ZMS_TRUSTSTORE_PATH = "yahoo.zms.ssl_trust_store";
    private static final String ZMS_TRUSTSTORE_TYPE = "yahoo.zms.ssl_trust_store_type";
    
    InstanceProviderHandler handler;
    
    public InstanceProviderContainer(InstanceProviderHandler handler) {
        this.handler = handler;
    }
    
    SslContextFactory createSSLContextObject() {
        
        String keyStorePath = System.getProperty(ZMS_KEYSTORE_PATH);
        String keyStorePassword = System.getProperty(ZMS_KEYSTORE_PASSWORD);
        String keyStoreType = System.getProperty(ZMS_KEYSTORE_TYPE, "PKCS12");
        String trustStorePath = System.getProperty(ZMS_TRUSTSTORE_PATH);
        String trustStorePassword = System.getProperty(ZMS_TRUSTSTORE_PASSWORD);
        String trustStoreType = System.getProperty(ZMS_TRUSTSTORE_TYPE, "PKCS12");

        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
        if (keyStorePath != null) {
            sslContextFactory.setKeyStorePath(keyStorePath);
        }
        if (keyStorePassword != null) {
            sslContextFactory.setKeyStorePassword(keyStorePassword);
        }
        sslContextFactory.setKeyStoreType(keyStoreType);

        if (trustStorePath != null) {
            sslContextFactory.setTrustStorePath(trustStorePath);
        }
        if (trustStorePassword != null) {
            sslContextFactory.setTrustStorePassword(trustStorePassword);
        }
        sslContextFactory.setTrustStoreType(trustStoreType);

        sslContextFactory.setNeedClientAuth(true);
        return sslContextFactory;
    }
    
    public void run() {
        try {
            QueuedThreadPool threadPool = new QueuedThreadPool();
            threadPool.setMaxThreads(16);

            Server server = new Server(threadPool);
            ServletContextHandler handler = new ServletContextHandler();
            handler.setContextPath("");
            ResourceConfig config = new ResourceConfig(InstanceProviderResources.class)
                    .register(JacksonFeature.class)
                    .register(new Binder());
            handler.addServlet(new ServletHolder(new ServletContainer(config)), "/*");
            server.setHandler(handler);
            
            // SSL Context Factory

            SslContextFactory sslContextFactory = createSSLContextObject();

            // SSL HTTP Configuration
            
            HttpConfiguration httpConfig = new HttpConfiguration();
            httpConfig.setSecureScheme("https");
            httpConfig.setSecurePort(10043);
    
            HttpConfiguration httpsConfig = new HttpConfiguration(httpConfig);
            httpsConfig.addCustomizer(new SecureRequestCustomizer());

            // SSL Connector
            
            ServerConnector sslConnector = new ServerConnector(server,
                    new SslConnectionFactory(sslContextFactory, HttpVersion.HTTP_1_1.asString()),
                    new HttpConnectionFactory(httpsConfig));
            sslConnector.setPort(10043);
            server.addConnector(sslConnector);
            
            server.start();
            server.join();
        } catch (Exception e) {
            System.err.println("*** " + e);
        }
    }

    class Binder extends AbstractBinder {
        @Override
        protected void configure() {
            bind(handler).to(InstanceProviderHandler.class);
        }
    }
}
