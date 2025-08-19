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
package io.athenz.syncer.common.zms.impl;

import io.athenz.syncer.common.zms.DomainState;
import org.testng.annotations.Test;

import java.util.Map;

import static org.testng.Assert.*;

public class StateFileBuilderNoOpTest {
    @Test
    public void testBuildStateMap() {
        StateFileBuilderNoOp builder = new StateFileBuilderNoOp();
        Map<String, DomainState> stateMap = builder.buildStateMap();

        assertNotNull(stateMap, "The state map should not be null");
        assertTrue(stateMap.isEmpty(), "The state map should be empty");
        assertEquals(0, stateMap.size(), "The state map should have zero entries");
    }
}