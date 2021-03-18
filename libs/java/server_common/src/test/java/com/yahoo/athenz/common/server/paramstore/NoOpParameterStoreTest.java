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

package com.yahoo.athenz.common.server.paramstore;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static com.yahoo.athenz.common.server.paramstore.AWSParameterStoreSyncerTest.initDynamicParameterStoreInstance;
import static com.yahoo.athenz.common.server.paramstore.DynamicParameterStoreFactory.DYNAMIC_PARAM_STORE_CLASS;
import static org.testng.Assert.*;

public class NoOpParameterStoreTest {

    @BeforeClass
    public void setUp() {
        initDynamicParameterStoreInstance();
        System.clearProperty(DYNAMIC_PARAM_STORE_CLASS);
    }

    @Test
    public void invalidFactoryClass() {
        System.setProperty(DYNAMIC_PARAM_STORE_CLASS, "com.yahoo.athenz.common.server.paramstore.noexist");
        try {
            DynamicParameterStoreFactory.create();
            fail();
        } catch (ExceptionInInitializerError ignored) { }
        System.clearProperty(DYNAMIC_PARAM_STORE_CLASS);
    }
    
    @Test
    public void testNoOpParameterStore() {
        DynamicParameterStore noOpParamStore = DynamicParameterStoreFactory.create();
        assertTrue(noOpParamStore instanceof NoOpParameterStore);
        assertNull(noOpParamStore.get("someParam"));
        assertEquals(noOpParamStore.get("someParam", "def"), "def");
    }
}
