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
package com.yahoo.athenz.instance.provider;

import static org.testng.Assert.*;

import org.testng.annotations.Test;

public class ResourceExceptionTest {

    @Test
    public void testResourceException() {

        ResourceException exc = new ResourceException(400, "Bad Request");
        assertEquals(exc.getMessage(), "ResourceException (400): Bad Request");
        assertEquals(exc.getCode(), 400);

        ResourceException excObj = new ResourceException(403, (Object) "Object String");
        assertEquals(excObj.getMessage(), "ResourceException (403): Object String");
        assertEquals(excObj.getCode(), 403);
    }
}
