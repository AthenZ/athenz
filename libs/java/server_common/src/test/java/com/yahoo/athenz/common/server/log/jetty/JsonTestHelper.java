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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Joiner;
import org.hamcrest.MatcherAssert;
import uk.co.datumedge.hamcrest.json.SameJSONAs;

import java.io.UncheckedIOException;

public class JsonTestHelper {

    private static final ObjectMapper mapper = new ObjectMapper();

    /**
     * Convenience method to input JSON without escaping double quotes and newlines
     * Each parameter represents a line of JSON encoded data
     * The lines are joined with newline and single quotes are replaced with double quotes
     */
    public static String inputJson(String... lines) {
        return Joiner.on("\n").join(lines).replaceAll("'", "\"");
    }

    /** Structurally compare two JSON encoded strings */
    public static void assertJsonEquals(String inputJson, String expectedJson) {
        MatcherAssert.assertThat(inputJson, SameJSONAs.sameJSONAs(expectedJson));
    }

    /** Structurally compare a {@link JsonNode} and a JSON string. */
    public static void assertJsonEquals(JsonNode left, String rightJson) {
        try {
            String leftJson = mapper.writeValueAsString(left);
            assertJsonEquals(leftJson, rightJson);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Structurally compare two {@link JsonNode}s. */
    public static void assertJsonEquals(JsonNode left, JsonNode right) {
        try {
            String leftJson = mapper.writeValueAsString(left);
            String rightJson = mapper.writeValueAsString(right);
            assertJsonEquals(leftJson, rightJson);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }
}
