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

        assertEquals("OK", ClientResourceException.codeToString(200));
        assertEquals("Created", ClientResourceException.codeToString(201));
        assertEquals("Accepted", ClientResourceException.codeToString(202));
        assertEquals("No Content", ClientResourceException.codeToString(204));
        assertEquals("Moved Permanently", ClientResourceException.codeToString(301));
        assertEquals("Found", ClientResourceException.codeToString(302));
        assertEquals("See Other", ClientResourceException.codeToString(303));
        assertEquals("Not Modified", ClientResourceException.codeToString(304));
        assertEquals("Temporary Redirect", ClientResourceException.codeToString(307));
        assertEquals("Bad Request", ClientResourceException.codeToString(400));
        assertEquals("Unauthorized", ClientResourceException.codeToString(401));
        assertEquals("Forbidden", ClientResourceException.codeToString(403));
        assertEquals("Not Found", ClientResourceException.codeToString(404));
        assertEquals("Conflict", ClientResourceException.codeToString(409));
        assertEquals("Gone", ClientResourceException.codeToString(410));
        assertEquals("Precondition Failed", ClientResourceException.codeToString(412));
        assertEquals("Unsupported Media Type", ClientResourceException.codeToString(415));
        assertEquals("Precondition Required", ClientResourceException.codeToString(428));
        assertEquals("Too Many Requests", ClientResourceException.codeToString(429));
        assertEquals("Request Header Fields Too Large", ClientResourceException.codeToString(431));
        assertEquals("Internal Server Error", ClientResourceException.codeToString(500));
        assertEquals("Not Implemented", ClientResourceException.codeToString(501));
        assertEquals("Service Unavailable", ClientResourceException.codeToString(503));
        assertEquals("Network Authentication Required", ClientResourceException.codeToString(511));
        assertEquals("1001", ClientResourceException.codeToString(1001));
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
