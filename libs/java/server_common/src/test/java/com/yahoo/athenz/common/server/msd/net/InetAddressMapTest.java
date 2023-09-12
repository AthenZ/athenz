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

package com.yahoo.athenz.common.server.msd.net;

import com.yahoo.athenz.msd.DynamicWorkload;
import org.testng.annotations.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.TreeMap;

import static org.testng.Assert.*;

public class InetAddressMapTest {

    @Test
    public void putIp() {
        InetAddressMap<DynamicWorkload> dynamicIps = new InetAddressMap<>(new TreeMap<>(InetComparator::compare), new TreeMap<>(InetComparator::compare));

        dynamicIps.putIp("10.1.2.3", new DynamicWorkload().setDomainName("athenz.examples").setServiceName("api0"));

        InetAddress a = null;
        InetAddress b = null;
        InetAddress c = null;
        try {
            a = InetAddress.getByName("10.1.2.3");
            b = InetAddress.getByName("10.1.2.4");
            c = InetAddress.getByName("2001:4998:efeb:2ff::a:2");
        } catch (UnknownHostException e) {
            fail();
        }

        assertEquals(dynamicIps.getV4().size(), 1);
        assertEquals(dynamicIps.getV6().size(), 0);
        assertTrue(dynamicIps.getV4().containsKey(a));
        assertFalse(dynamicIps.getV4().containsKey(b));

        dynamicIps.putIp("2001:4998:efeb:2ff::a:2", new DynamicWorkload().setDomainName("athenz.examples").setServiceName("api0"));

        assertEquals(dynamicIps.getV4().size(), 1);
        assertEquals(dynamicIps.getV6().size(), 1);
        assertTrue(dynamicIps.getV4().containsKey(a));
        assertTrue(dynamicIps.getV6().containsKey(c));
    }

    @Test
    public void putIpInvalid() {
        InetAddressMap<DynamicWorkload> dynamicIps = new InetAddressMap<>(new TreeMap<>(InetComparator::compare), new TreeMap<>(InetComparator::compare));

        dynamicIps.putIp("10.1.2.a", new DynamicWorkload().setDomainName("athenz.examples").setServiceName("api0"));

        assertEquals(dynamicIps.getV4().size(), 0);
        assertEquals(dynamicIps.getV6().size(), 0);
    }

    @Test
    public void putIps() {
        InetAddressMap<DynamicWorkload> dynamicIps = new InetAddressMap<>(new TreeMap<>(InetComparator::compare), new TreeMap<>(InetComparator::compare));

        List<String> ips = Arrays.asList("10.1.2.3", "10.1.2.4", "2001:4998:efeb:2ff::a:2", "10.1.2.a");
        dynamicIps.putIps(ips, new DynamicWorkload().setDomainName("athenz.examples").setServiceName("api0"));

        InetAddress a = null;
        InetAddress b = null;
        InetAddress c = null;
        try {
            a = InetAddress.getByName("10.1.2.3");
            b = InetAddress.getByName("10.1.2.4");
            c = InetAddress.getByName("2001:4998:efeb:2ff::a:2");
        } catch (UnknownHostException e) {
            fail();
        }

        assertEquals(dynamicIps.getV4().size(), 2);
        assertEquals(dynamicIps.getV6().size(), 1);
        assertTrue(dynamicIps.getV4().containsKey(a));
        assertTrue(dynamicIps.getV4().containsKey(b));
        assertTrue(dynamicIps.getV6().containsKey(c));
    }
}