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
package com.yahoo.athenz.zts;

import com.yahoo.rdl.Timestamp;
import org.testng.annotations.Test;

import java.util.ArrayList;

import static org.testng.Assert.*;

public class AthenzJWKConfigTest {

    @Test
    public void testAthenzJWKConfig() {
        AthenzJWKConfig conf = new AthenzJWKConfig();
        AthenzJWKConfig confOther = new AthenzJWKConfig();

        long now = System.currentTimeMillis();
        conf.setModified(Timestamp.fromMillis(now));
        confOther.setModified(Timestamp.fromMillis(now));
        assertEquals(now, conf.getModified().millis());

        assertEquals(conf, conf);
        assertEquals(conf, confOther);

        assertNotEquals(null, conf);
        assertNotEquals("AthenzJWKConfig", conf);

        conf.setZms(new JWKList());
        assertNotNull(conf.getZms());
        assertNotEquals(conf, confOther);
        assertNotEquals(confOther, conf);

        confOther.setZms(new JWKList().setKeys(new ArrayList<>()));
        assertNotEquals(conf, confOther);
        assertNotEquals(confOther, conf);

        conf.setZts(new JWKList());
        confOther.setZms(new JWKList());
        confOther.setZts(null);
        assertNull(confOther.getZts());
        assertNotEquals(conf, confOther);
        assertNotEquals(confOther, conf);
    }
}
