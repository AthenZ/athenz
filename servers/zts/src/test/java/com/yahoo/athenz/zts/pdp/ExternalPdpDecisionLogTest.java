/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zts.pdp;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class ExternalPdpDecisionLogTest {

    @Test
    public void testLog() {
        ExternalPdpDecisionLog log = new ExternalPdpDecisionLog("r1", ExternalPdpMode.FILTER, "access_token")
                .with("outcome", "permit").with("skipped", null);
        assertEquals(log.getFields().get("request_id"), "r1");
        assertEquals(log.getFields().get("mode"), "FILTER");
        assertEquals(log.getFields().get("flow"), "access_token");
        assertEquals(log.getFields().get("outcome"), "permit");
        assertFalse(log.getFields().containsKey("skipped"));
        log.write();

        // values that cannot be serialized fall back to the map representation
        new ExternalPdpDecisionLog("r2", ExternalPdpMode.AUDIT, "jag").with("bad", new Object()).write();
    }
}
