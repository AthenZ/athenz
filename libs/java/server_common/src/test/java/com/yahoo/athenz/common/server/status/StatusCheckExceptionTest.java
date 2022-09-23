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
package com.yahoo.athenz.common.server.status;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

public class StatusCheckExceptionTest {

    @Test
    public void TestStatusCheckException() {

        StatusCheckException ex = new StatusCheckException();
        assertEquals(ex.getCode(), 500);

        ex = new StatusCheckException(401);
        assertEquals(ex.getCode(), 401);
        assertEquals(ex.getMsg(), "UNAUTHORIZED");

        ex = new StatusCheckException(400, "Bad data");
        assertEquals(ex.getCode(), 400);
        assertEquals(ex.getMsg(), "Bad data");

        Throwable cause = new Throwable("failure");
        ex = new StatusCheckException(cause);
        assertEquals(ex.getCode(), 500);
        assertEquals(ex.getMsg(), "failure");
    }
}
