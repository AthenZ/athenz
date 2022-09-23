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

import static org.testng.Assert.*;
import org.testng.annotations.Test;

public class ResourceExceptionTest {

    @Test
    public void testCodeToString() {

        assertEquals("OK", ResourceException.codeToString(200));
        assertEquals("Created", ResourceException.codeToString(201));
        assertEquals("Accepted", ResourceException.codeToString(202));
        assertEquals("No Content", ResourceException.codeToString(204));
        assertEquals("Moved Permanently", ResourceException.codeToString(301));
        assertEquals("Found", ResourceException.codeToString(302));
        assertEquals("See Other", ResourceException.codeToString(303));
        assertEquals("Not Modified", ResourceException.codeToString(304));
        assertEquals("Temporary Redirect", ResourceException.codeToString(307));
        assertEquals("Bad Request", ResourceException.codeToString(400));
        assertEquals("Unauthorized", ResourceException.codeToString(401));
        assertEquals("Forbidden", ResourceException.codeToString(403));
        assertEquals("Not Found", ResourceException.codeToString(404));
        assertEquals("Conflict", ResourceException.codeToString(409));
        assertEquals("Gone", ResourceException.codeToString(410));
        assertEquals("Precondition Failed", ResourceException.codeToString(412));
        assertEquals("Unsupported Media Type", ResourceException.codeToString(415));
        assertEquals("Precondition Required", ResourceException.codeToString(428));
        assertEquals("Too Many Requests", ResourceException.codeToString(429));
        assertEquals("Request Header Fields Too Large", ResourceException.codeToString(431));
        assertEquals("Internal Server Error", ResourceException.codeToString(500));
        assertEquals("Not Implemented", ResourceException.codeToString(501));
        assertEquals("Service Unavailable", ResourceException.codeToString(503));
        assertEquals("Network Authentication Required", ResourceException.codeToString(511));
        assertEquals("1001", ResourceException.codeToString(1001));
    }

    @Test
    public void testCodeOnly() {

        ResourceException exc = new ResourceException(400);
        assertEquals(exc.getData().toString(), "{code: 400, message: \"Bad Request\"}");
    }

    @Test
    public void testGetData() {

        ResourceException exc = new ResourceException(400, "Invalid domain name");
        assertEquals(exc.getData(), "Invalid domain name");
    }

    @Test
    public void testGetDataCast() {

        ResourceException exc = new ResourceException(400, 5000);
        assertEquals(exc.getData(Integer.class), new Integer(5000));
    }
}
