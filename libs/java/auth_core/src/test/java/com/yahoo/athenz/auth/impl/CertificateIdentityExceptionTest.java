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
package com.yahoo.athenz.auth.impl;

import static org.testng.Assert.*;

import org.testng.annotations.Test;

public class CertificateIdentityExceptionTest {

    @Test
    public void testCertificateIdentityException() {
        CertificateIdentityException ex;

        ex = new CertificateIdentityException();
        assertNotNull(ex);

        ex = new CertificateIdentityException("err msg");
        assertEquals(ex.getMessage(), "err msg");
        assertTrue(ex.isReportError());

        ex = new CertificateIdentityException("err msg2", false);
        assertEquals(ex.getMessage(), "err msg2");
        assertFalse(ex.isReportError());

        Throwable t = new Throwable();
        ex = new CertificateIdentityException(t);
        assertSame(ex.getCause(), t);
    }

}
