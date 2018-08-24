/*
 * Copyright 2018 Oath Inc.
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
package com.yahoo.athenz.zts.cert.impl;

import static org.testng.Assert.*;

import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Collection;

import org.testng.annotations.Test;
import org.mockito.Mockito;

import java.security.cert.X509Certificate;

public class X509CertUtilsTest {

    @Test
    public void testExtractRequestInstanceId() throws CertificateParsingException {

        assertNull(X509CertUtils.extractRequestInstanceId(null));

        X509Certificate cert = Mockito.mock(X509Certificate.class);
        Collection<List<?>> dnsNames = new ArrayList<>();
        ArrayList<Object> item1 = new ArrayList<>();
        item1.add(2);
        item1.add("host1.domain.athenz");
        dnsNames.add(item1);
        Mockito.when(cert.getSubjectAlternativeNames()).thenReturn(dnsNames);

        assertNull(X509CertUtils.extractRequestInstanceId(cert));

        ArrayList<Object> item2 = new ArrayList<>();
        item2.add(2);
        item2.add("instanceid1.instanceid.athenz.test");
        dnsNames.add(item2);

        assertEquals("instanceid1", X509CertUtils.extractRequestInstanceId(cert));
    }
}
