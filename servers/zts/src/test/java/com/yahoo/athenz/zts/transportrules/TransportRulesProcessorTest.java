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

package com.yahoo.athenz.zts.transportrules;

import com.yahoo.athenz.zts.TransportDirection;
import com.yahoo.athenz.zts.TransportRule;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class TransportRulesProcessorTest {

    @Test (dataProvider = "actions-provider")
    public void testIsTransportRuleAction(String action, boolean expectation) {
        assertEquals(TransportRulesProcessor.isTransportRuleAction(action), expectation);
    }

    @Test (dataProvider = "actions-transport-provider")
    public void testParseTransportRuleAction(String action, TransportRule expectedRule) {
        assertEquals(TransportRulesProcessor.parseTransportRuleAction(action), expectedRule);
    }

    @DataProvider (name = "actions-provider")
    public Object[][] actionsProvider() {
        return new Object[][] {
                {"TCP-IN:1024-65535:4443", true},
                {"TCP-OUT:1024-65535:4443", true},
                {"UDP-OUT:1024-65535:4443", true},
                {"UDP-OUT:1024:4443", true},
                {"HTTP-OUT:1024-65535:4443", false},
                {"TCP-IN:102432:4443", false},
                {"TCP-IN:102432:444343", false},
                {"TCP-IN:AA:WE", false},
        };
    }

    @DataProvider (name = "actions-transport-provider")
    public Object[][] actionsTransportProvider() {
        return new Object[][] {
                {"TCP-IN:1024-65535:4443", new TransportRule().setProtocol("TCP").setPort(4443).setSourcePortRange("1024-65535").setDirection(TransportDirection.IN)},
                {"TCP-OUT:1024-65535:4443", new TransportRule().setProtocol("TCP").setPort(4443).setSourcePortRange("1024-65535").setDirection(TransportDirection.OUT)},
                {"UDP-OUT:1024-65535:4443", new TransportRule().setProtocol("UDP").setPort(4443).setSourcePortRange("1024-65535").setDirection(TransportDirection.OUT)},
                {"UDP-OUT:1024:4443", new TransportRule().setProtocol("UDP").setPort(4443).setSourcePortRange("1024").setDirection(TransportDirection.OUT)},
                {"HTTP-OUT:1024-65535:4443", null},
                {"TCP-IN:102432:4443", null},
                {"TCP-IN:102432:444343", null},
                {"TCP-IN:AA:WE", null},
        };
    }

    @Test
    public void testTransportRulesProcessorConstructor() {
        TransportRulesProcessor trp = new TransportRulesProcessor();
        assertNotNull(trp);
    }
}