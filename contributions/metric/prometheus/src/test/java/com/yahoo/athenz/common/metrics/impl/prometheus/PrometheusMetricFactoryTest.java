/*
 * Copyright 2019 Yahoo Inc.
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
package com.yahoo.athenz.common.metrics.impl.prometheus;

import org.testng.Assert;
import org.testng.annotations.Test;

import io.prometheus.client.CollectorRegistry;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.Socket;

import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.metrics.impl.NoOpMetric;

public class PrometheusMetricFactoryTest {

    private static String setProperty(String key, String value) {
        return System.setProperty(PrometheusMetricFactory.SYSTEM_PROP_PREFIX + key, value);
    }

    private static String clearProperty(String key) {
        return System.clearProperty(PrometheusMetricFactory.SYSTEM_PROP_PREFIX + key);
    }

    @Test
    public void testGetProperty() {
        String expected = "false";

        setProperty(PrometheusMetricFactory.ENABLE_PROP, expected);
        String prop = PrometheusMetricFactory.getProperty(PrometheusMetricFactory.ENABLE_PROP, "true");
        clearProperty(PrometheusMetricFactory.ENABLE_PROP);

        // assertions
        Assert.assertEquals(prop, expected);
    }

    @Test
    public void testCreateMetricDisable() {
        Class<?> expected = NoOpMetric.class;

        setProperty(PrometheusMetricFactory.ENABLE_PROP, "false");
        Metric metric = new PrometheusMetricFactory().create();
        clearProperty(PrometheusMetricFactory.ENABLE_PROP);

        // assertions
        Assert.assertEquals(metric.getClass(), expected);
    }

    @Test
    public void testCreateJvmMetricEnable()
            throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {

        setProperty(PrometheusMetricFactory.JVM_ENABLE_PROP, "true");
        setProperty(PrometheusMetricFactory.HTTP_SERVER_ENABLE_PROP, "false");
        PrometheusMetric metric = (PrometheusMetric) new PrometheusMetricFactory().create();
        clearProperty(PrometheusMetricFactory.JVM_ENABLE_PROP);
        clearProperty(PrometheusMetricFactory.HTTP_SERVER_ENABLE_PROP);

        Field registryField = metric.getClass().getDeclaredField("registry");
        registryField.setAccessible(true);
        CollectorRegistry registry = (CollectorRegistry) registryField.get(metric);

        // assertions
        Assert.assertNotNull(registry.getSampleValue("process_cpu_seconds_total"));
    }

    @Test(expectedExceptions = { RuntimeException.class, BindException.class }, expectedExceptionsMessageRegExp = ".* Address.* in use.*")
    public void testCreateErrorUsedPort() throws IOException {
        int port = 18181;
        try (Socket socket = new Socket()) {
            socket.bind(new InetSocketAddress(port));

            setProperty(PrometheusMetricFactory.HTTP_SERVER_ENABLE_PROP, "true");
            setProperty(PrometheusMetricFactory.HTTP_SERVER_PORT_PROP, String.valueOf(port));
            new PrometheusMetricFactory().create();
            clearProperty(PrometheusMetricFactory.HTTP_SERVER_ENABLE_PROP);
            clearProperty(PrometheusMetricFactory.HTTP_SERVER_PORT_PROP);
        }
    }

    @Test
    public void testCreate() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
        Class<PrometheusPullServer> expectedExporterClass = PrometheusPullServer.class;
        String expectedNamespace = "expected_athenz_server";
        boolean expectedIsLabelRequestDomainNameEnable = true;
        boolean expectedIsLabelPrincipalDomainNameEnable = true;
        boolean expectedIsLabelHttpMethodNameEnable = true;
        boolean expectedIsLabelHttpStatusNameEnable = true;
        boolean expectedIsLabelApiNameEnable = true;

        PrometheusMetric metric = null;
        try {
            setProperty(PrometheusMetricFactory.HTTP_SERVER_ENABLE_PROP, "true");
            setProperty(PrometheusMetricFactory.NAMESPACE_PROP, expectedNamespace);
            setProperty(PrometheusMetricFactory.LABEL_REQUEST_DOMAIN_NAME_ENABLE_PROP, String.valueOf(expectedIsLabelRequestDomainNameEnable));
            setProperty(PrometheusMetricFactory.LABEL_PRINCIPAL_DOMAIN_NAME_ENABLE_PROP, String.valueOf(expectedIsLabelPrincipalDomainNameEnable));

            setProperty(PrometheusMetricFactory.LABEL_HTTP_METHOD_NAME_ENABLE_PROP, String.valueOf(expectedIsLabelHttpMethodNameEnable));
            setProperty(PrometheusMetricFactory.LABEL_HTTP_STATUS_NAME_ENABLE_PROP, String.valueOf(expectedIsLabelHttpStatusNameEnable));
            setProperty(PrometheusMetricFactory.LABEL_API_NAME_ENABLE_PROP, String.valueOf(expectedIsLabelApiNameEnable));

            metric = (PrometheusMetric) new PrometheusMetricFactory().create();
            clearProperty(PrometheusMetricFactory.HTTP_SERVER_ENABLE_PROP);
            clearProperty(PrometheusMetricFactory.NAMESPACE_PROP);
            clearProperty(PrometheusMetricFactory.LABEL_REQUEST_DOMAIN_NAME_ENABLE_PROP);
            clearProperty(PrometheusMetricFactory.LABEL_PRINCIPAL_DOMAIN_NAME_ENABLE_PROP);
            clearProperty(PrometheusMetricFactory.LABEL_HTTP_METHOD_NAME_ENABLE_PROP);
            clearProperty(PrometheusMetricFactory.LABEL_HTTP_STATUS_NAME_ENABLE_PROP);
            clearProperty(PrometheusMetricFactory.LABEL_API_NAME_ENABLE_PROP);

            // assertions
            Field exporterField = metric.getClass().getDeclaredField("exporter");
            exporterField.setAccessible(true);
            PrometheusExporter exporter = (PrometheusExporter) exporterField.get(metric);
            Assert.assertEquals(exporter.getClass(), expectedExporterClass);

            Field namespaceField = metric.getClass().getDeclaredField("namespace");
            namespaceField.setAccessible(true);
            String namespace = (String) namespaceField.get(metric);
            Assert.assertEquals(namespace, expectedNamespace);

            Field isLabelRequestDomainNameEnableField = metric.getClass().getDeclaredField("isLabelRequestDomainNameEnable");
            isLabelRequestDomainNameEnableField.setAccessible(true);
            boolean isLabelRequestDomainNameEnable = (Boolean) isLabelRequestDomainNameEnableField.get(metric);
            Assert.assertEquals(isLabelRequestDomainNameEnable, expectedIsLabelRequestDomainNameEnable);

            Field isLabelPrincipalDomainNameEnableField = metric.getClass().getDeclaredField("isLabelPrincipalDomainNameEnable");
            isLabelPrincipalDomainNameEnableField.setAccessible(true);
            boolean isLabelPrincipalDomainNameEnable = (Boolean) isLabelPrincipalDomainNameEnableField.get(metric);
            Assert.assertEquals(isLabelPrincipalDomainNameEnable, expectedIsLabelPrincipalDomainNameEnable);

            Field isLabelHttpMethodNameEnableField = metric.getClass().getDeclaredField("isLabelHttpMethodNameEnable");
            isLabelHttpMethodNameEnableField.setAccessible(true);
            boolean isLabelHttpMethodNameEnable = (Boolean) isLabelHttpMethodNameEnableField.get(metric);
            Assert.assertEquals(isLabelHttpMethodNameEnable, expectedIsLabelHttpMethodNameEnable);

            Field isLabelHttpStatusNameEnableField = metric.getClass().getDeclaredField("isLabelHttpStatusNameEnable");
            isLabelHttpStatusNameEnableField.setAccessible(true);
            boolean isLabelHttpStatusNameEnable = (Boolean) isLabelHttpStatusNameEnableField.get(metric);
            Assert.assertEquals(isLabelHttpStatusNameEnable, expectedIsLabelHttpStatusNameEnable);

            Field isLabelApiNameEnableField = metric.getClass().getDeclaredField("isLabelApiNameEnable");
            isLabelApiNameEnableField.setAccessible(true);
            boolean isLabelApiNameEnable = (Boolean) isLabelApiNameEnableField.get(metric);
            Assert.assertEquals(isLabelApiNameEnable, expectedIsLabelApiNameEnable);

        } finally {
            // cleanup
            if (metric != null) {
                metric.quit();
            }
        }
    }

}
