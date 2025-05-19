/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.common.server.log.jetty;

import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.metrics.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JettyConnectionLoggerFactory {
    private static final Logger LOG = LoggerFactory.getLogger(JettyConnectionLoggerFactory.class);
    public static final String ATHENZ_PROP_SSL_LOGGER_FACTORY_CLASS = "athenz.ssl_logger_factory_class";
    public static final String ATHENZ_SSL_LOGGER_FACTORY_CLASS = "com.yahoo.athenz.common.server.log.jetty.FileSSLConnectionLogFactory";

    public JettyConnectionLogger create() {
        ConnectionLog connectionLog = getSslConnectionLog();
        Metric metric = Utils.getMetric();
        return new JettyConnectionLogger(connectionLog, metric);
    }

    private ConnectionLog getSslConnectionLog() {
        SSLConnectionLogFactory sslConnectionLogFactory;
        final String sslConnectionLogFactoryClass = System.getProperty(ATHENZ_PROP_SSL_LOGGER_FACTORY_CLASS,
                ATHENZ_SSL_LOGGER_FACTORY_CLASS);
        try {
            sslConnectionLogFactory = (SSLConnectionLogFactory) Class.forName(
                    sslConnectionLogFactoryClass).getDeclaredConstructor().newInstance();
        } catch (Exception ex) {
            LOG.error("Invalid SSLConnectionLogFactory class: {}", sslConnectionLogFactoryClass, ex);
            throw new IllegalArgumentException("Invalid SSLConnectionLogFactory", ex);
        }
        return sslConnectionLogFactory.create();
    }
}
