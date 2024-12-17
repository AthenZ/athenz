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
package com.yahoo.athenz.zms;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

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
    public void testCodeOnly() {

        ClientResourceException exc = new ClientResourceException(400);
        assertEquals(exc.getData().toString(), "{code: 400, message: \"Bad Request\"}");
    }

    @Test
    public void testGetData() {

        ClientResourceException exc = new ClientResourceException(400, "Invalid domain name");
        assertEquals(exc.getData(), "Invalid domain name");
    }

    @Test
    public void testGetDataCast() {

        ClientResourceException exc = new ClientResourceException(400, 5000);
        assertEquals(exc.getData(Integer.class), Integer.valueOf(5000));
    }
}
