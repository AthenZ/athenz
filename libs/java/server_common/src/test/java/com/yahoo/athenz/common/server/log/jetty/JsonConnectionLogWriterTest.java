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

import org.testng.annotations.Test;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

import static org.testng.Assert.assertNotNull;

public class JsonConnectionLogWriterTest {

    @Test
    void testSerialization() throws IOException {
        UUID id = UUID.randomUUID();
        Instant instant = Instant.parse("2021-01-13T12:12:12Z");
        ConnectionLogEntry entry = ConnectionLogEntry.builder(id, instant)
                .withPeerPort(1234)
                .build();
        String expectedJson = "{" +
                "\"id\":\""+ id +"\"," +
                "\"timestamp\":\"2021-01-13T12:12:12Z\"," +
                "\"peerPort\":1234" +
                "}";

        JsonConnectionLogWriter writer = new JsonConnectionLogWriter();
        String actualJson = writer.logEntryToString(entry);
        JsonTestHelper.assertJsonEquals(actualJson, expectedJson);
    }

    @Test
    void testSerializationFailedHandshake() throws IOException {
        UUID id = UUID.randomUUID();
        Instant instant = Instant.parse("2021-01-13T12:12:12Z");
        ConnectionLogEntry entry = ConnectionLogEntry.builder(id, instant)
                .withPeerPort(1234)
                .withSslHandshakeFailureCause("ssl failure cause")
                .withSslHandshakeFailureMessage("ssl failure message")
                .withSslHandshakeFailureType("ssl failure type")
                .withDuration(5)
                .build();
        String expectedJson = "{" +
                "\"id\":\""+ id +"\"," +
                "\"timestamp\":\"2021-01-13T12:12:12Z\"," +
                "\"duration\":5.000," +
                "\"peerPort\":1234," +
                "\"handshake-failure\":{" +
                "\"message\":\"ssl failure message\"," +
                "\"cause\":\"ssl failure cause\"," +
                "\"type\":\"ssl failure type\"}" +
                "}";

        JsonConnectionLogWriter writer = new JsonConnectionLogWriter();
        String actualJson = writer.logEntryToString(entry);
        JsonTestHelper.assertJsonEquals(actualJson, expectedJson);

        FileSSLConnectionLogFactory fileSSLConnectionLogFactory = new FileSSLConnectionLogFactory();
        ConnectionLog connectionLog = fileSSLConnectionLogFactory.create();
        assertNotNull(connectionLog);
        connectionLog.log(entry);
    }
}
