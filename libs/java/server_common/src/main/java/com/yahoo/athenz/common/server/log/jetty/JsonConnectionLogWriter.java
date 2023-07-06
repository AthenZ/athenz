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

import com.fasterxml.jackson.core.JsonEncoding;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

class JsonConnectionLogWriter {

    private final JsonFactory jsonFactory = new JsonFactory(new ObjectMapper());

    public String logEntryToString(ConnectionLogEntry record) throws IOException {
            try (OutputStream outputStream = new ByteArrayOutputStream();
                 JsonGenerator generator = createJsonGenerator(outputStream)) {
                generator.writeStartObject();
                generator.writeStringField("id", record.id());
                generator.writeStringField("timestamp", record.timestamp().toString());

                writeOptionalSeconds(generator, "duration", unwrap(record.durationSeconds()));
                writeOptionalString(generator, "peerAddress", unwrap(record.peerAddress()));
                writeOptionalInteger(generator, "peerPort", unwrap(record.peerPort()));
                writeOptionalString(generator, "athenzPrincipal", unwrap(record.athenzPrincipal()));

                String sslHandshakeFailureException = unwrap(record.sslHandshakeFailureException());
                String sslHandshakeFailureMessage = unwrap(record.sslHandshakeFailureMessage());
                String sslHandshakeFailureCause = unwrap(record.sslHandshakeFailureCause());
                String sslHandshakeFailureType = unwrap(record.sslHandshakeFailureType());

                if (isAnyValuePresent(sslHandshakeFailureException, sslHandshakeFailureMessage, sslHandshakeFailureCause, sslHandshakeFailureType)) {
                    generator.writeObjectFieldStart("handshake-failure");
                    writeOptionalString(generator, "exception", sslHandshakeFailureException);
                    writeOptionalString(generator, "message", sslHandshakeFailureMessage);
                    writeOptionalString(generator, "cause", sslHandshakeFailureCause);
                    writeOptionalString(generator, "type", sslHandshakeFailureType);

                    generator.writeEndObject();
                }
                generator.writeEndObject();
                generator.flush();
                return outputStream.toString();
            }
    }

    private void writeOptionalString(JsonGenerator generator, String name, String value) throws IOException {
        if (value != null) {
            generator.writeStringField(name, value);
        }
    }

    private void writeOptionalInteger(JsonGenerator generator, String name, Integer value) throws IOException {
        if (value != null) {
            generator.writeNumberField(name, value);
        }
    }

    private void writeOptionalSeconds(JsonGenerator generator, String name, Double value) throws IOException {
        if (value != null) {
            FormatUtil.writeSecondsField(generator, name, value);
        }
    }

    private static boolean isAnyValuePresent(Object... values) {
        return Arrays.stream(values).anyMatch(Objects::nonNull);
    }

    private static <T> T unwrap(Optional<T> maybeValue) {
        return maybeValue.orElse(null);
    }

    private JsonGenerator createJsonGenerator(OutputStream outputStream) throws IOException {
        return jsonFactory.createGenerator(outputStream, JsonEncoding.UTF8)
                .configure(JsonGenerator.Feature.AUTO_CLOSE_TARGET, false)
                .configure(JsonGenerator.Feature.FLUSH_PASSED_TO_STREAM, false);
    }
}

