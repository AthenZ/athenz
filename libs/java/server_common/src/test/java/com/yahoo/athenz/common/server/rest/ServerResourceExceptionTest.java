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

import com.yahoo.athenz.common.server.ServerResourceException;
import org.testng.annotations.*;

public class ServerResourceExceptionTest {
    
    @Test
    public void testCodeForSymbol() {
        assertEquals(ServerResourceException.codeForSymbol("ok"), 200);
        assertEquals(ServerResourceException.codeForSymbol("CREATED"), 201);
        assertEquals(ServerResourceException.codeForSymbol("ACCEPTED"), 202);
        assertEquals(ServerResourceException.codeForSymbol("NO_CONTENT"), 204);
        assertEquals(ServerResourceException.codeForSymbol("MOVED_PERMANENTLY"), 301);
        assertEquals(ServerResourceException.codeForSymbol("FOUND"), 302);
        assertEquals(ServerResourceException.codeForSymbol("SEE_OTHER"), 303);
        assertEquals(ServerResourceException.codeForSymbol("NOT_MODIFIED"), 304);
        assertEquals(ServerResourceException.codeForSymbol("TEMPORARY_REDIRECT"), 307);
        assertEquals(ServerResourceException.codeForSymbol("BAD_REQUEST"), 400);
        assertEquals(ServerResourceException.codeForSymbol("FORBIDDEN"), 403);
        assertEquals(ServerResourceException.codeForSymbol("UNAUTHORIZED"), 401);
        assertEquals(ServerResourceException.codeForSymbol("NOT_FOUND"), 404);
        assertEquals(ServerResourceException.codeForSymbol("CONFLICT"), 409);
        assertEquals(ServerResourceException.codeForSymbol("GONE"), 410);
        assertEquals(ServerResourceException.codeForSymbol("PRECONDITION_FAILED"), 412);
        assertEquals(ServerResourceException.codeForSymbol("UNSUPPORTED_MEDIA_TYPE"), 415);
        assertEquals(ServerResourceException.codeForSymbol("INTERNAL_SERVER_ERROR"), 500);
        assertEquals(ServerResourceException.codeForSymbol("NOT_IMPLEMENTED"), 501);
        assertEquals(ServerResourceException.codeForSymbol("SERVICE_UNAVAILABLE"), 503);
        assertEquals(ServerResourceException.codeForSymbol("UNAUTHORIZED"), 401);
        assertEquals(ServerResourceException.codeForSymbol("1111"), 1111);
        assertEquals(ServerResourceException.codeForSymbol("abc"), 0);
    }

    @Test
    public void testSymbolForCode() {
        assertEquals(ServerResourceException.symbolForCode(200), "OK");
        assertEquals(ServerResourceException.symbolForCode(201), "CREATED");
        assertEquals(ServerResourceException.symbolForCode(202), "ACCEPTED");
        assertEquals(ServerResourceException.symbolForCode(204), "NO_CONTENT");
        assertEquals(ServerResourceException.symbolForCode(301), "MOVED_PERMANENTLY");
        assertEquals(ServerResourceException.symbolForCode(302), "FOUND");
        assertEquals(ServerResourceException.symbolForCode(303), "SEE_OTHER");
        assertEquals(ServerResourceException.symbolForCode(304), "NOT_MODIFIED");
        assertEquals(ServerResourceException.symbolForCode(307), "TEMPORARY_REDIRECT");
        assertEquals(ServerResourceException.symbolForCode(400), "BAD_REQUEST");
        assertEquals(ServerResourceException.symbolForCode(403), "FORBIDDEN");
        assertEquals(ServerResourceException.symbolForCode(401), "UNAUTHORIZED");
        assertEquals(ServerResourceException.symbolForCode(404), "NOT_FOUND");
        assertEquals(ServerResourceException.symbolForCode(409), "CONFLICT");
        assertEquals(ServerResourceException.symbolForCode(410), "GONE");
        assertEquals(ServerResourceException.symbolForCode(412), "PRECONDITION_FAILED");
        assertEquals(ServerResourceException.symbolForCode(415), "UNSUPPORTED_MEDIA_TYPE");
        assertEquals(ServerResourceException.symbolForCode(500), "INTERNAL_SERVER_ERROR");
        assertEquals(ServerResourceException.symbolForCode(501), "NOT_IMPLEMENTED");
        assertEquals(ServerResourceException.symbolForCode(503), "SERVICE_UNAVAILABLE");
        assertEquals(ServerResourceException.symbolForCode(401), "UNAUTHORIZED");
        assertNull(ServerResourceException.symbolForCode(1111));
    }

    @Test
    public void testResourceException() {
        ServerResourceException exception = new ServerResourceException(200);
        assertEquals(exception.getCode(), 200);
        assertEquals(exception.getMessage(), "OK");

        exception = new ServerResourceException(404, "Domain not found");
        assertEquals(exception.getCode(), 404);
        assertEquals(exception.getMessage(), "Domain not found");
    }
}
