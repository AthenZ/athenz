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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import org.testng.annotations.Test;

public class ClientResourceExceptionTest {

    @Test
    public void testCodeToString() {

        assertEquals(ClientResourceException.codeToString(200), "OK");
        assertEquals(ClientResourceException.codeToString(201), "Created");
        assertEquals(ClientResourceException.codeToString(202), "Accepted");
        assertEquals(ClientResourceException.codeToString(204), "No Content");
        assertEquals(ClientResourceException.codeToString(301), "Moved Permanently");
        assertEquals(ClientResourceException.codeToString(302), "Found");
        assertEquals(ClientResourceException.codeToString(303), "See Other");
        assertEquals(ClientResourceException.codeToString(304), "Not Modified");
        assertEquals(ClientResourceException.codeToString(307), "Temporary Redirect");
        assertEquals(ClientResourceException.codeToString(400), "Bad Request");
        assertEquals(ClientResourceException.codeToString(401), "Unauthorized");
        assertEquals(ClientResourceException.codeToString(403), "Forbidden");
        assertEquals(ClientResourceException.codeToString(404), "Not Found");
        assertEquals(ClientResourceException.codeToString(409), "Conflict");
        assertEquals(ClientResourceException.codeToString(410), "Gone");
        assertEquals(ClientResourceException.codeToString(412), "Precondition Failed");
        assertEquals(ClientResourceException.codeToString(415), "Unsupported Media Type");
        assertEquals(ClientResourceException.codeToString(428), "Precondition Required");
        assertEquals(ClientResourceException.codeToString(429), "Too Many Requests");
        assertEquals(ClientResourceException.codeToString(431), "Request Header Fields Too Large");
        assertEquals(ClientResourceException.codeToString(500), "Internal Server Error");
        assertEquals(ClientResourceException.codeToString(501), "Not Implemented");
        assertEquals(ClientResourceException.codeToString(503), "Service Unavailable");
        assertEquals(ClientResourceException.codeToString(511), "Network Authentication Required");
        assertEquals(ClientResourceException.codeToString(1001), "1001");
    }

    @Test
    public void testConstants() {

        assertEquals(ClientResourceException.OK, 200);
        assertEquals(ClientResourceException.CREATED, 201);
        assertEquals(ClientResourceException.ACCEPTED, 202);
        assertEquals(ClientResourceException.NO_CONTENT, 204);
        assertEquals(ClientResourceException.MOVED_PERMANENTLY, 301);
        assertEquals(ClientResourceException.FOUND, 302);
        assertEquals(ClientResourceException.SEE_OTHER, 303);
        assertEquals(ClientResourceException.NOT_MODIFIED, 304);
        assertEquals(ClientResourceException.TEMPORARY_REDIRECT, 307);
        assertEquals(ClientResourceException.BAD_REQUEST, 400);
        assertEquals(ClientResourceException.UNAUTHORIZED, 401);
        assertEquals(ClientResourceException.FORBIDDEN, 403);
        assertEquals(ClientResourceException.NOT_FOUND, 404);
        assertEquals(ClientResourceException.CONFLICT, 409);
        assertEquals(ClientResourceException.GONE, 410);
        assertEquals(ClientResourceException.PRECONDITION_FAILED, 412);
        assertEquals(ClientResourceException.UNSUPPORTED_MEDIA_TYPE, 415);
        assertEquals(ClientResourceException.PRECONDITION_REQUIRED, 428);
        assertEquals(ClientResourceException.TOO_MANY_REQUESTS, 429);
        assertEquals(ClientResourceException.REQUEST_HEADER_FIELDS_TOO_LARGE, 431);
        assertEquals(ClientResourceException.INTERNAL_SERVER_ERROR, 500);
        assertEquals(ClientResourceException.NOT_IMPLEMENTED, 501);
        assertEquals(ClientResourceException.SERVICE_UNAVAILABLE, 503);
        assertEquals(ClientResourceException.NETWORK_AUTHENTICATION_REQUIRED, 511);
    }

    @Test
    public void testCodeOnly() {

        ClientResourceException exc = new ClientResourceException(400);
        assertEquals(exc.getCode(), 400);
        assertNotNull(exc.getData());
        assertTrue(exc.getData() instanceof ClientResourceError);
        assertEquals(exc.getData().toString(), "{code: 400, message: \"Bad Request\"}");
        assertTrue(exc.getMessage().contains("ClientResourceException (400)"));
    }

    @Test
    public void testCodeOnlyWithDifferentCodes() {

        ClientResourceException exc404 = new ClientResourceException(404);
        assertEquals(exc404.getCode(), 404);
        assertEquals(exc404.getData().toString(), "{code: 404, message: \"Not Found\"}");

        ClientResourceException exc500 = new ClientResourceException(500);
        assertEquals(exc500.getCode(), 500);
        assertEquals(exc500.getData().toString(), "{code: 500, message: \"Internal Server Error\"}");
    }

    @Test
    public void testCodeWithData() {

        ClientResourceException exc = new ClientResourceException(400, "Invalid domain name");
        assertEquals(exc.getCode(), 400);
        assertEquals(exc.getData(), "Invalid domain name");
        assertTrue(exc.getMessage().contains("ClientResourceException (400)"));
        assertTrue(exc.getMessage().contains("Invalid domain name"));
    }

    @Test
    public void testGetData() {

        ClientResourceException exc = new ClientResourceException(400, "Invalid domain name");
        assertEquals(exc.getData(), "Invalid domain name");
        assertEquals(exc.getCode(), 400);
    }

    @Test
    public void testGetDataCast() {

        ClientResourceException exc = new ClientResourceException(400, 5000);
        assertEquals(exc.getData(Integer.class), Integer.valueOf(5000));
    }

    @Test
    public void testGetDataCastWithString() {

        ClientResourceException exc = new ClientResourceException(404, "Resource not found");
        assertEquals(exc.getData(String.class), "Resource not found");
    }

    @Test
    public void testGetDataCastWithClientResourceError() {

        ClientResourceError error = new ClientResourceError().code(500).message("Internal Server Error");
        ClientResourceException exc = new ClientResourceException(500, error);
        ClientResourceError result = exc.getData(ClientResourceError.class);
        assertEquals(result.code, 500);
        assertEquals(result.message, "Internal Server Error");
    }

    @Test
    public void testIsRuntimeException() {

        ClientResourceException exc = new ClientResourceException(400);
        assertTrue(exc instanceof RuntimeException);
    }

    @Test
    public void testMessageFormat() {

        ClientResourceException exc = new ClientResourceException(401, "Unauthorized access");
        String message = exc.getMessage();
        assertTrue(message.startsWith("ClientResourceException (401)"));
        assertTrue(message.contains("Unauthorized access"));
    }
}

