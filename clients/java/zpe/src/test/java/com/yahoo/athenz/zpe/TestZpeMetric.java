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
package com.yahoo.athenz.zpe;

import java.io.IOException;
import junit.framework.TestCase;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.io.File;
import org.testng.annotations.Test;

import com.yahoo.athenz.zpe.AuthZpeClient;
import com.yahoo.athenz.zpe.ZpeConsts;
import com.yahoo.athenz.zpe.ZpeMetric;
import com.yahoo.athenz.zts.DomainMetric;
import com.yahoo.athenz.zts.DomainMetrics;
import com.yahoo.rdl.JSON;

public class TestZpeMetric extends TestCase {
    
    @Test
    public void testZpeMetric() throws IOException {

        // setting the system property to write in file every 5 secs
        System.setProperty(ZpeConsts.ZPE_PROP_METRIC_WRITE_INTERVAL, "5000");
        
        final String metricDirPath = "/tmp/zpe-metrics";
        File metricsDir = new File(metricDirPath);
        metricsDir.mkdirs();
        System.setProperty(ZpeConsts.ZPE_PROP_METRIC_FILE_PATH, metricDirPath);

        final String TEST_DOMAIN = "test";
        ZpeMetric.statsEnabled = true;
        ZpeMetric test = new ZpeMetric();

        // cleaning the directory
        File dir = new File(test.getFilePath());
        if (dir.exists()) {
            for (File file: dir.listFiles()) {
                if (!file.isDirectory()) {
                    file.delete();
                }
            }
        } else {
            dir.mkdirs();
        }

        // incrementing metrics for testing
        test.increment(ZpeConsts.ZPE_METRIC_NAME, AuthZpeClient.DEFAULT_DOMAIN);
        test.increment(ZpeConsts.ZPE_METRIC_NAME, AuthZpeClient.DEFAULT_DOMAIN);
        test.increment(ZpeConsts.ZPE_METRIC_NAME, AuthZpeClient.DEFAULT_DOMAIN);
        test.increment(ZpeConsts.ZPE_METRIC_NAME, AuthZpeClient.DEFAULT_DOMAIN);
        test.increment(ZpeConsts.ZPE_METRIC_NAME, AuthZpeClient.DEFAULT_DOMAIN);
        test.increment(ZpeConsts.ZPE_METRIC_NAME, AuthZpeClient.DEFAULT_DOMAIN);
        
        try {
            Thread.sleep(4000);
        } catch (InterruptedException e) {
        }

        test.increment(ZpeConsts.ZPE_METRIC_NAME, TEST_DOMAIN);
        test.increment(ZpeConsts.ZPE_METRIC_NAME, TEST_DOMAIN);
        test.increment(ZpeConsts.ZPE_METRIC_NAME, AuthZpeClient.DEFAULT_DOMAIN);
        test.increment(ZpeConsts.ZPE_METRIC_NAME, AuthZpeClient.DEFAULT_DOMAIN);
        test.increment(ZpeConsts.ZPE_METRIC_NAME, AuthZpeClient.DEFAULT_DOMAIN);
        test.increment(ZpeConsts.ZPE_METRIC_NAME, AuthZpeClient.DEFAULT_DOMAIN);

        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
        }

        // Reading from the json file generated

        boolean sysDomainMetricVerified = false;
        boolean testDomainMetricVerified = false;
        for (File file : dir.listFiles()) {
            String filepath = test.getFilePath() + file.getName();
            Path path = Paths.get(filepath);
            DomainMetrics domainMetrics = JSON.fromBytes(Files.readAllBytes(path), DomainMetrics.class);
            // verifying the value of the metric
            List<DomainMetric> metricList = domainMetrics.getMetricList();
            for (DomainMetric metric : metricList) {
                if (metric.getMetricType().toString().equals(ZpeConsts.ZPE_METRIC_NAME)) {
                    if (domainMetrics.getDomainName().equals("sys.auth")) {
                        assertEquals(10, metric.getMetricVal());
                        sysDomainMetricVerified = true;
                    } else if (domainMetrics.getDomainName().equals("test")) {
                        assertEquals(2, metric.getMetricVal());
                        testDomainMetricVerified = true;
                    }
                }
            }
        }
        assertTrue(sysDomainMetricVerified);
        assertTrue(testDomainMetricVerified);

        // unsetting the system property
        System.clearProperty(ZpeConsts.ZPE_PROP_METRIC_WRITE_INTERVAL);
    }

}