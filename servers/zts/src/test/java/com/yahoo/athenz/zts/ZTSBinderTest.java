/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.zts;

import static org.testng.Assert.*;
import org.mockito.Mockito;

import org.testng.annotations.Test;

public class ZTSBinderTest {

    @Test
    public void testZTSBinder() {
        ZTSImpl handlerMock = Mockito.mock(ZTSImpl.class);
        ZTSBinder binder = new ZTSBinder(handlerMock);

        assertTrue(binder.toString().contains("Binder:"));
    }

    @Test(expectedExceptions = { IllegalArgumentException.class })
    public void testZTSBinderConfigure() {
        // shouldn't accessed configure
        ZTSImpl handlerMock = Mockito.mock(ZTSImpl.class);
        new ZTSBinder(handlerMock).configure();
    }
}
