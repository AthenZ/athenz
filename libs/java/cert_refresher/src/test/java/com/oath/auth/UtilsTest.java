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

package com.oath.auth;

import java.io.FileNotFoundException;
import java.io.IOException;

import org.junit.Assert;
import org.junit.Test;

public class UtilsTest {

    @Test (expected = FileNotFoundException.class)
    public void getKeyStoreTest() throws FileNotFoundException, IOException, KeyRefresherException {
        Utils.getKeyStore(null);
        Assert.fail("Should have thrown FileNotFoundException.");
    }
    
    @Test (expected = FileNotFoundException.class)
    public void createKeyStoreTest() throws FileNotFoundException, IOException, KeyRefresherException, InterruptedException {
        Utils.createKeyStore(null, null);
        Assert.fail("Should have thrown FileNotFoundException.");
    }
    
    @Test (expected = FileNotFoundException.class)
    public void getKeyManagersTest() throws FileNotFoundException, IOException, InterruptedException, KeyRefresherException {
        Utils.getKeyManagers(null, null);
        Assert.fail("Should have thrown FileNotFoundException.");
    }
}
