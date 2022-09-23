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
package com.yahoo.athenz.common.server.rest;

import static org.testng.Assert.*;
import org.testng.annotations.*;

public class ResourceExceptionTest {
    
    @Test
    public void testCodeForSymbol() {
        assertEquals(ResourceException.codeForSymbol("ok"), 200);
        assertEquals(ResourceException.codeForSymbol("CREATED"), 201);
        assertEquals(ResourceException.codeForSymbol("ACCEPTED"), 202);
        assertEquals(ResourceException.codeForSymbol("NO_CONTENT"), 204);
        assertEquals(ResourceException.codeForSymbol("MOVED_PERMANENTLY"), 301);
        assertEquals(ResourceException.codeForSymbol("FOUND"), 302);
        assertEquals(ResourceException.codeForSymbol("SEE_OTHER"), 303);
        assertEquals(ResourceException.codeForSymbol("NOT_MODIFIED"), 304);
        assertEquals(ResourceException.codeForSymbol("TEMPORARY_REDIRECT"), 307);
        assertEquals(ResourceException.codeForSymbol("BAD_REQUEST"), 400);
        assertEquals(ResourceException.codeForSymbol("FORBIDDEN"), 403);
        assertEquals(ResourceException.codeForSymbol("UNAUTHORIZED"), 401);
        assertEquals(ResourceException.codeForSymbol("NOT_FOUND"), 404);
        assertEquals(ResourceException.codeForSymbol("CONFLICT"), 409);
        assertEquals(ResourceException.codeForSymbol("GONE"), 410);
        assertEquals(ResourceException.codeForSymbol("PRECONDITION_FAILED"), 412);
        assertEquals(ResourceException.codeForSymbol("UNSUPPORTED_MEDIA_TYPE"), 415);
        assertEquals(ResourceException.codeForSymbol("INTERNAL_SERVER_ERROR"), 500);
        assertEquals(ResourceException.codeForSymbol("NOT_IMPLEMENTED"), 501);
        assertEquals(ResourceException.codeForSymbol("SERVICE_UNAVAILABLE"), 503);
        assertEquals(ResourceException.codeForSymbol("UNAUTHORIZED"), 401);
        assertEquals(ResourceException.codeForSymbol("1111"), 1111);
        assertEquals(ResourceException.codeForSymbol("abc"), 0);
    }

    @Test
    public void testSymbolForCode() {
        assertEquals(ResourceException.symbolForCode(200), "OK");
        assertEquals(ResourceException.symbolForCode(201), "CREATED");
        assertEquals(ResourceException.symbolForCode(202), "ACCEPTED");
        assertEquals(ResourceException.symbolForCode(204), "NO_CONTENT");
        assertEquals(ResourceException.symbolForCode(301), "MOVED_PERMANENTLY");
        assertEquals(ResourceException.symbolForCode(302), "FOUND");
        assertEquals(ResourceException.symbolForCode(303), "SEE_OTHER");
        assertEquals(ResourceException.symbolForCode(304), "NOT_MODIFIED");
        assertEquals(ResourceException.symbolForCode(307), "TEMPORARY_REDIRECT");
        assertEquals(ResourceException.symbolForCode(400), "BAD_REQUEST");
        assertEquals(ResourceException.symbolForCode(403), "FORBIDDEN");
        assertEquals(ResourceException.symbolForCode(401), "UNAUTHORIZED");
        assertEquals(ResourceException.symbolForCode(404), "NOT_FOUND");
        assertEquals(ResourceException.symbolForCode(409), "CONFLICT");
        assertEquals(ResourceException.symbolForCode(410), "GONE");
        assertEquals(ResourceException.symbolForCode(412), "PRECONDITION_FAILED");
        assertEquals(ResourceException.symbolForCode(415), "UNSUPPORTED_MEDIA_TYPE");
        assertEquals(ResourceException.symbolForCode(500), "INTERNAL_SERVER_ERROR");
        assertEquals(ResourceException.symbolForCode(501), "NOT_IMPLEMENTED");
        assertEquals(ResourceException.symbolForCode(503), "SERVICE_UNAVAILABLE");
        assertEquals(ResourceException.symbolForCode(401), "UNAUTHORIZED");
        assertNull(ResourceException.symbolForCode(1111));
    }

    @Test
    public void testResourceException() {
        ResourceException exception = new ResourceException(200);
        assertEquals(exception.getCode(), 200);
        assertEquals(exception.getData(), "OK");
        assertEquals(exception.getData(String.class), "OK");
    }
}
