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
package com.yahoo.athenz.zpe;

import static org.testng.Assert.assertEquals;

import org.testng.annotations.Test;

public class TestZpeYcrKey {

    @Test
    public void testGetSetYcrKey() {

        ZpeYcrKey ycrkey = new ZpeYcrKey();

        ycrkey.setKeyName("key1");
        ycrkey.setVersion((short) 0);

        assertEquals(ycrkey.getKeyName(), "key1");
        assertEquals(ycrkey.getVersion(), (short) 0);
    }
}
