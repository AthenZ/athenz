/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.msd;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotEquals;

import com.yahoo.rdl.Timestamp;
import java.util.Collections;
import org.testng.annotations.Test;

public class TransportPolicySnapshotUsageTest {

    @Test
    public void testTransportPolicySnapshotUsagePrincipalFields() {

        TransportPolicySnapshotUsagePrincipal principal1 = new TransportPolicySnapshotUsagePrincipal()
                .setName("athenz.examples.httpd")
                .setTime(Timestamp.fromMillis(123456789123L));

        assertEquals(principal1.getName(), "athenz.examples.httpd");
        assertEquals(principal1.getTime(), Timestamp.fromMillis(123456789123L));

        TransportPolicySnapshotUsagePrincipal principal2 = new TransportPolicySnapshotUsagePrincipal()
                .setName("athenz.examples.httpd")
                .setTime(Timestamp.fromMillis(123456789123L));

        assertEquals(principal1, principal1);
        assertEquals(principal1, principal2);

        principal2.setName("athenz.examples.nginx");
        assertNotEquals(principal1, principal2);

        principal2.setName("athenz.examples.httpd");
        principal2.setTime(Timestamp.fromMillis(999999999L));
        assertNotEquals(principal1, principal2);

        principal2.setTime(null);
        assertNotEquals(principal1, principal2);

        principal2.setName(null);
        assertNotEquals(principal1, principal2);

        assertFalse(principal1.equals("xyz"));
    }

    @Test
    public void testTransportPolicySnapshotUsageWarningFields() {

        TransportPolicySnapshotUsageWarning warning1 = new TransportPolicySnapshotUsageWarning()
                .setSource("sherpa")
                .setCode("UPSTREAM_UNAVAILABLE");

        assertEquals(warning1.getSource(), "sherpa");
        assertEquals(warning1.getCode(), "UPSTREAM_UNAVAILABLE");

        TransportPolicySnapshotUsageWarning warning2 = new TransportPolicySnapshotUsageWarning()
                .setSource("sherpa")
                .setCode("UPSTREAM_UNAVAILABLE");

        assertEquals(warning1, warning1);
        assertEquals(warning1, warning2);

        warning2.setSource("other");
        assertNotEquals(warning1, warning2);

        warning2.setSource("sherpa");
        warning2.setCode("SOMETHING_ELSE");
        assertNotEquals(warning1, warning2);

        warning2.setCode(null);
        assertNotEquals(warning1, warning2);

        warning2.setSource(null);
        assertNotEquals(warning1, warning2);

        assertFalse(warning1.equals("xyz"));
    }

    @Test
    public void testTransportPolicySnapshotUsageFields() {

        TransportPolicySnapshotUsagePrincipal principal = new TransportPolicySnapshotUsagePrincipal()
                .setName("athenz.examples.httpd")
                .setTime(Timestamp.fromMillis(123456789123L));
        TransportPolicySnapshotUsageWarning warning = new TransportPolicySnapshotUsageWarning()
                .setSource("sherpa")
                .setCode("UPSTREAM_UNAVAILABLE");

        TransportPolicySnapshotUsage usage1 = new TransportPolicySnapshotUsage()
                .setPrincipals(Collections.singletonList(principal))
                .setPartial(true)
                .setWarning(warning);

        assertEquals(usage1.getPrincipals(), Collections.singletonList(principal));
        assertEquals(usage1.getPartial(), Boolean.TRUE);
        assertEquals(usage1.getWarning(), warning);

        TransportPolicySnapshotUsage usage2 = new TransportPolicySnapshotUsage()
                .setPrincipals(Collections.singletonList(principal))
                .setPartial(true)
                .setWarning(warning);

        assertEquals(usage1, usage1);
        assertEquals(usage1, usage2);

        usage2.setPrincipals(Collections.emptyList());
        assertNotEquals(usage1, usage2);

        usage2.setPrincipals(Collections.singletonList(principal));
        usage2.setPartial(false);
        assertNotEquals(usage1, usage2);

        usage2.setPartial(true);
        usage2.setWarning(null);
        assertNotEquals(usage1, usage2);

        usage2.setWarning(warning);
        usage2.setPartial(null);
        assertNotEquals(usage1, usage2);

        usage2.setPartial(true);
        usage2.setPrincipals(null);
        assertNotEquals(usage1, usage2);

        assertFalse(usage1.equals("xyz"));
    }

    @Test
    public void testTransportPolicySnapshotUsageRequestFields() {

        TransportPolicySnapshotUsageRequest request1 = new TransportPolicySnapshotUsageRequest()
                .setSnapshotName("v1");

        assertEquals(request1.getSnapshotName(), "v1");

        TransportPolicySnapshotUsageRequest request2 = new TransportPolicySnapshotUsageRequest()
                .setSnapshotName("v1");

        assertEquals(request1, request1);
        assertEquals(request1, request2);

        request2.setSnapshotName("v2");
        assertNotEquals(request1, request2);

        request2.setSnapshotName(null);
        assertNotEquals(request1, request2);

        assertFalse(request1.equals("xyz"));
    }

    @Test
    public void testTransportPolicySnapshotUsageResponseFields() {

        TransportPolicySnapshotUsageWarning warning = new TransportPolicySnapshotUsageWarning()
                .setSource("msd")
                .setCode("REPORTING_DISABLED");

        TransportPolicySnapshotUsageResponse response1 = new TransportPolicySnapshotUsageResponse()
                .setRecorded(false)
                .setWarning(warning);

        assertFalse(response1.getRecorded());
        assertEquals(response1.getWarning(), warning);

        TransportPolicySnapshotUsageResponse response2 = new TransportPolicySnapshotUsageResponse()
                .setRecorded(false)
                .setWarning(warning);

        assertEquals(response1, response1);
        assertEquals(response1, response2);

        response2.setWarning(null);
        assertNotEquals(response1, response2);

        response2.setWarning(warning);
        response2.setRecorded(true);
        assertNotEquals(response1, response2);

        assertFalse(response1.equals("xyz"));
    }
}
