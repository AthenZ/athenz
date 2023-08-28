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

public class GcpAccessTokenResponseTest {

    @Test
    public void testGcpAccessTokenResponse() throws JsonProcessingException {

        final String responseStr = "{\n" +
                "  \"accessToken\": \"access-token\",\n" +
                "  \"expireTime\": \"2014-10-02T15:01:23Z\"\n" +
                "}";

        ObjectMapper mapper = new ObjectMapper();
        GcpAccessTokenResponse response = mapper.readValue(responseStr, GcpAccessTokenResponse.class);
        assertNotNull(response);
        assertEquals("access-token", response.getAccessToken());
        assertEquals("2014-10-02T15:01:23Z", response.getExpireTime());
    }
}
