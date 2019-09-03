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

import java.io.IOException;
import java.net.InetSocketAddress;

import io.prometheus.client.CollectorRegistry;
import io.prometheus.client.exporter.HTTPServer;

public class PrometheusPullServer implements PrometheusExporter {

    private HTTPServer server;

    public PrometheusPullServer(int pullingPort, CollectorRegistry registry) throws IOException {
        boolean isDaemon = true;
        this.server = new HTTPServer(new InetSocketAddress(pullingPort), registry, isDaemon);
    }

    @Override
    public void flush() {
        // should response to pull request from prometheus only, no action on flush
    }

    @Override
    public void quit() {
        this.server.stop();
    }

}
