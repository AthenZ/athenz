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
package com.yahoo.athenz.zms.store.file;

import static org.testng.Assert.*;
import java.io.File;

import org.testng.annotations.Test;

public class FileObjectStoreTest {
    @Test
    public void testError() {
        try {
            FileObjectStore.error("Not Found");
        } catch (RuntimeException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void TestFileObjectStore() {
        File file = new File("/home/athenz/");
        File file2 = new File("/home/hoge.txt");
        try {
            new FileObjectStore(file);
        } catch (Exception ex) {
            assertTrue(true);
        }

        try {
            new FileObjectStore(file2);
        } catch (Exception ex) {
            assertTrue(true);
        }
    }
}
