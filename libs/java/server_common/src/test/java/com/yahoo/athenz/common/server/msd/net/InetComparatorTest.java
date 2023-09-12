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
import java.util.*;

import static org.testng.Assert.*;

public class InetComparatorTest {

    @Test
    public void testCompare() throws UnknownHostException {
        assertTrue(InetComparator.compare(InetAddress.getByName("10.1.2.3"), InetAddress.getByName("10.0.2.3")) > 0);
        assertEquals(0, InetComparator.compare(InetAddress.getByName("10.1.2.3"), InetAddress.getByName("10.1.2.3")));
        assertTrue(InetComparator.compare(InetAddress.getByName("10.1.2.3"), InetAddress.getByName("10.1.2.4")) < 0);
        assertTrue(InetComparator.compare(InetAddress.getByName("10.255.2.3"), InetAddress.getByName("255.254.254.253")) < 0);
    }

    @Test
    public void testTreeMap() throws UnknownHostException {
        NavigableMap<InetAddress, DynamicWorkload> map = new TreeMap<>(InetComparator::compare);
        map.put(InetAddress.getByName("12.1.3.1"), new DynamicWorkload().setDomainName("athenz.examples").setServiceName("api0"));
        map.put(InetAddress.getByName("10.1.2.3"), new DynamicWorkload().setDomainName("athenz.examples").setServiceName("api1"));
        map.put(InetAddress.getByName("10.1.2.4"), new DynamicWorkload().setDomainName("athenz.examples").setServiceName("api2"));
        map.put(InetAddress.getByName("10.1.3.1"), new DynamicWorkload().setDomainName("athenz.examples").setServiceName("api31"));
        map.put(InetAddress.getByName("10.1.3.2"), new DynamicWorkload().setDomainName("athenz.examples").setServiceName("api32"));
        map.put(InetAddress.getByName("11.1.3.1"), new DynamicWorkload().setDomainName("athenz.examples").setServiceName("api4"));
        map.put(InetAddress.getByName("10.2.3.1"), new DynamicWorkload().setDomainName("athenz.examples").setServiceName("api5"));
        map.put(InetAddress.getByName("10.2.3.2"), new DynamicWorkload().setDomainName("athenz.examples").setServiceName("api6"));

        String low = "10.1.2.0";
        String high = "10.1.3.2";
        SortedMap<InetAddress, DynamicWorkload> matched = map.subMap(InetAddress.getByName(low), InetAddress.getByName(high));
        Set<InetAddress> matchedKeys = matched.keySet();
        assertEquals(matchedKeys.size(), 3);
        assertTrue(matchedKeys.contains(InetAddress.getByName("10.1.2.3")));
        assertTrue(matchedKeys.contains(InetAddress.getByName("10.1.2.4")));
        assertTrue(matchedKeys.contains(InetAddress.getByName("10.1.3.1")));
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testIncompatibleArgs() throws UnknownHostException {
        NavigableMap<InetAddress, DynamicWorkload> map = new TreeMap<>(InetComparator::compare);
        map.put(InetAddress.getByName("12.1.3.1"), new DynamicWorkload().setDomainName("athenz.examples").setServiceName("api0"));
        map.put(InetAddress.getByName("2001:4998:efeb:2ff::a:2"), new DynamicWorkload().setDomainName("athenz.examples").setServiceName("api1"));
    }
}
