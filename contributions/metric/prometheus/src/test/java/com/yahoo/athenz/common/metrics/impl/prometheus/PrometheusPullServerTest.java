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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.HttpHostConnectException;
import org.apache.http.impl.client.HttpClientBuilder;

import io.prometheus.client.CollectorRegistry;
import io.prometheus.client.Counter;

public class PrometheusPullServerTest {

    @Test
    public void testConstructor() throws IOException {

        int port = 8181;
        String counterName = "constructor_test_total";
        String counterHelp = "constructor_test_help";
        double counterValue = 1234.6789;

        CollectorRegistry registry = new CollectorRegistry();
        Counter counter = Counter.build().name(counterName).help(counterHelp).register(registry);
        counter.inc(counterValue);

        // new
        String expectedResponseText = String.join(
            "\n",
            String.format("# HELP %s %s", counterName, counterHelp),
            String.format("# TYPE %s %s", counterName, counter.getClass().getSimpleName().toLowerCase()),
            String.format("%s %.4f", counterName, counterValue)
        );
        PrometheusPullServer exporter = null;
        try {
            exporter = new PrometheusPullServer(port, registry);

            HttpClient client = HttpClientBuilder.create().build();
            HttpGet request = new HttpGet(String.format("http://localhost:%d/metrics", port));
            HttpResponse response = client.execute(request);
            BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
            String responseText = rd.lines().collect(Collectors.joining("\n"));

            // assertions
            Assert.assertEquals(responseText, expectedResponseText);
        } finally {
            // cleanup
            if (exporter != null) {
                exporter.quit();
            }
        }
    }

    @Test(expectedExceptions = { HttpHostConnectException.class }, expectedExceptionsMessageRegExp = ".* failed: Connection refused.*")
    public void testQuit() throws IOException {
        int port = 8181;
        CollectorRegistry registry = new CollectorRegistry();
        PrometheusPullServer exporter = new PrometheusPullServer(port, registry);
        exporter.quit();

        HttpClient client = HttpClientBuilder.create().build();
        HttpGet request = new HttpGet(String.format("http://localhost:%d/metrics", port));
        client.execute(request);
    }

}
