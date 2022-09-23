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

import com.fasterxml.jackson.core.JsonGenerationException;

import jakarta.annotation.Priority;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

@Provider
@Priority(1)
public class JsonGeneralExceptionMapper implements ExceptionMapper<JsonGenerationException> {

    @Override
    public Response toResponse(JsonGenerationException ex) {
        return Response.status(Response.Status.BAD_REQUEST)
                .entity(ZTSConsts.ZTS_JSON_PARSER_ERROR_RESPONSE)
                .build();
    }
}
