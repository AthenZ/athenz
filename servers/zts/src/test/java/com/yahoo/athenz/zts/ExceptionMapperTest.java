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
package com.yahoo.athenz.zts;

import org.testng.annotations.Test;

import jakarta.ws.rs.core.Response;

import static org.testng.Assert.assertEquals;

public class ExceptionMapperTest {

    @Test
    public void testExceptionMappers() {

        JsonGeneralExceptionMapper mapper1 = new JsonGeneralExceptionMapper();
        Response response = mapper1.toResponse(null);
        assertEquals(400, response.getStatus());

        JsonMappingExceptionMapper mapper2 = new JsonMappingExceptionMapper();
        response = mapper2.toResponse(null);
        assertEquals(400, response.getStatus());

        JsonParseExceptionMapper mapper3 = new JsonParseExceptionMapper();
        response = mapper3.toResponse(null);
        assertEquals(400, response.getStatus());

        JsonProcessingExceptionMapper mapper4 = new JsonProcessingExceptionMapper();
        response = mapper4.toResponse(null);
        assertEquals(400, response.getStatus());
    }
}
