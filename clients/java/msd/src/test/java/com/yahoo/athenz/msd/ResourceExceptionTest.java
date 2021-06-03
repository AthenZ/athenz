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
package com.yahoo.athenz.msd;

import static org.testng.Assert.assertEquals;

import org.testng.annotations.Test;

public class ResourceExceptionTest {

    @Test
    public void testCodeToString() {

        assertEquals(ResourceException.codeToString(200), "OK");
        assertEquals(ResourceException.codeToString(201), "Created");
        assertEquals(ResourceException.codeToString(202), "Accepted");
        assertEquals(ResourceException.codeToString(204), "No Content");
        assertEquals(ResourceException.codeToString(301), "Moved Permanently");
        assertEquals(ResourceException.codeToString(302), "Found");
        assertEquals(ResourceException.codeToString(303), "See Other");
        assertEquals(ResourceException.codeToString(304), "Not Modified");
        assertEquals(ResourceException.codeToString(307), "Temporary Redirect");
        assertEquals(ResourceException.codeToString(400), "Bad Request");
        assertEquals(ResourceException.codeToString(401), "Unauthorized");
        assertEquals(ResourceException.codeToString(403), "Forbidden");
        assertEquals(ResourceException.codeToString(404), "Not Found");
        assertEquals(ResourceException.codeToString(409), "Conflict");
        assertEquals(ResourceException.codeToString(410), "Gone");
        assertEquals(ResourceException.codeToString(412), "Precondition Failed");
        assertEquals(ResourceException.codeToString(415), "Unsupported Media Type");
        assertEquals(ResourceException.codeToString(428), "Precondition Required");
        assertEquals(ResourceException.codeToString(429), "Too Many Requests");
        assertEquals(ResourceException.codeToString(431), "Request Header Fields Too Large");
        assertEquals(ResourceException.codeToString(500), "Internal Server Error");
        assertEquals(ResourceException.codeToString(501), "Not Implemented");
        assertEquals(ResourceException.codeToString(503), "Service Unavailable");
        assertEquals(ResourceException.codeToString(511), "Network Authentication Required");
        assertEquals(ResourceException.codeToString(1001), "1001");
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
        assertEquals(exc.getCode(), 400);
    }

    @Test
    public void testGetDataCast() {

        ResourceException exc = new ResourceException(400, 5000);
        assertEquals(exc.getData(Integer.class), Integer.valueOf(5000));
    }
}
