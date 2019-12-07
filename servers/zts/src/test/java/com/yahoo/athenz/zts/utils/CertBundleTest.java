/*
 * Copyright 2019 Oath Holdings Inc.
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
package com.yahoo.athenz.zts.utils;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class CertBundleTest {

    @Test
    public void testCertBundle() {

        CertBundle bundle = new CertBundle();
        bundle.setFilename("filename");
        bundle.setName("athenz");
        bundle.setType("x.509");

        assertEquals(bundle.getFilename(), "filename");
        assertEquals(bundle.getName(), "athenz");
        assertEquals(bundle.getType(), "x.509");
    }
}
