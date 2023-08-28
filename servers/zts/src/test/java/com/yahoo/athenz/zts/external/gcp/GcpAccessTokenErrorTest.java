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

import static org.testng.Assert.*;

public class GcpAccessTokenErrorTest {

    @Test
    public void testGcpAccessTokenError() throws JsonProcessingException {

        final String responseStr = "{\n" +
                "  \"error\": {\n" +
                "    \"code\": 403,\n" +
                "    \"message\": \"Permission 'iam.serviceAccounts.getAccessToken' denied on resource (or it may not exist).\",\n" +
                "    \"status\": \"PERMISSION_DENIED\",\n" +
                "    \"details\": [\n" +
                "      {\n" +
                "        \"@type\": \"type.googleapis.com/google.rpc.ErrorInfo\",\n" +
                "        \"reason\": \"IAM_PERMISSION_DENIED\",\n" +
                "        \"domain\": \"iam.googleapis.com\",\n" +
                "        \"metadata\": {\n" +
                "          \"permission\": \"iam.serviceAccounts.getAccessToken\"\n" +
                "        }\n" +
                "      }\n" +
                "    ]\n" +
                "  }\n" +
                "}";

        ObjectMapper mapper = new ObjectMapper();
        GcpAccessTokenError response = mapper.readValue(responseStr, GcpAccessTokenError.class);
        assertNotNull(response);
        assertEquals("Permission 'iam.serviceAccounts.getAccessToken' denied on resource (or it may not exist).", response.getErrorMessage());

        GcpAccessTokenError.Error error = response.getError();
        assertNotNull(error);
        assertEquals(403, error.getCode());
        assertEquals("Permission 'iam.serviceAccounts.getAccessToken' denied on resource (or it may not exist).", error.getMessage());
        assertEquals("PERMISSION_DENIED", error.getStatus());
    }

    @Test
    public void testGcpAccessTokenErrorNoBody() throws JsonProcessingException {

        final String responseStr = "{\n" +
                "    \"code\": 403,\n" +
                "    \"message\": \"Permission 'iam.serviceAccounts.getAccessToken' denied on resource (or it may not exist).\",\n" +
                "    \"status\": \"PERMISSION_DENIED\"\n" +
                "}";

        ObjectMapper mapper = new ObjectMapper();
        GcpAccessTokenError response = mapper.readValue(responseStr, GcpAccessTokenError.class);
        assertNotNull(response);
        assertEquals("", response.getErrorMessage());
        assertNull(response.getError());
    }
}
