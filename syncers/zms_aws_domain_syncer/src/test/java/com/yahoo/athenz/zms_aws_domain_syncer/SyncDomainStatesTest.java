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

package com.yahoo.athenz.zms_aws_domain_syncer;

import org.testng.annotations.Test;

import java.util.ArrayList;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class SyncDomainStatesTest {

    @Test
    public void testSyncDomainStates() {

        SyncerDomainStates states = new SyncerDomainStates();
        states.setVersion("1");
        states.setDomainStates(new ArrayList<>());

        assertEquals(states.getVersion(), "1");
        assertTrue(states.getDomainStates().isEmpty());
    }
}
