/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.common.server.log.jetty;

import org.testng.annotations.Test;
import javax.net.ssl.SSLHandshakeException;

import static org.testng.Assert.*;

public class ExceptionCauseFetcherTest {

    @Test
    public void testGetCause() {
        int level = 0;
        SSLHandshakeException exception = new SSLHandshakeException("level" + level++);
        SSLHandshakeException childException = new SSLHandshakeException("level" + level++);
        exception.initCause(childException);
        for (int i = 0; i < 96; ++i) {
            SSLHandshakeException newChild = new SSLHandshakeException("level" + level++);
            childException.initCause(newChild);
            childException = newChild;
        }

        String cause = ExceptionCauseFetcher.getInnerCause(exception, "init message");
        assertEquals("level97", cause);
    }

    @Test
    public void testGetCauseReachedLimit() {
        int level = 0;
        SSLHandshakeException exception = new SSLHandshakeException("level" + level++);
        SSLHandshakeException childException = new SSLHandshakeException("level" + level++);
        exception.initCause(childException);
        for (int i = 0; i < 500; ++i) {
            SSLHandshakeException newChild = new SSLHandshakeException("level" + level++);
            childException.initCause(newChild);
            childException = newChild;
        }

        String cause = ExceptionCauseFetcher.getInnerCause(exception, "init message");
        // The max level is 100 so even though we created 500 levels, we'll get the cause from level 100
        assertEquals("level100", cause);
    }
}
