/*
 * Copyright The Athenz Authors
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

package com.yahoo.athenz.zts.external.gcp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

public class GcpExchangeTokenResponseTest {

    @Test
    public void testGcpExchangeTokenResponse() throws JsonProcessingException {

        final String responseStr = "{\n" +
                "  \"access_token\": \"access-token\",\n" +
                "  \"issued_token_type\": \"jwt\",\n" +
                "  \"token_type\": \"Bearer\",\n" +
                "  \"expires_in\": 300\n" +
                "}";

        ObjectMapper mapper = new ObjectMapper();
        GcpExchangeTokenResponse response = mapper.readValue(responseStr, GcpExchangeTokenResponse.class);
        assertNotNull(response);
        assertEquals("Bearer", response.getTokenType());
        assertEquals("access-token", response.getAccessToken());
        assertEquals("jwt", response.getIssuedTokenType());
        assertEquals(300, response.getExpiresIn());
    }
}
