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
import com.yahoo.athenz.msd.StaticWorkload;
import org.testng.annotations.Test;
import static org.testng.Assert.*;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.NavigableMap;
import java.util.TreeMap;

public class InetWorkloadTest {
    @Test
    public void testDataObject() throws UnknownHostException {
        NavigableMap<InetAddress, DynamicWorkload> dynamicV4 = new TreeMap<>(InetComparator::compare);
        dynamicV4.put(InetAddress.getByName("12.1.3.1"), new DynamicWorkload().setDomainName("athenz.examples").setServiceName("api0"));
        dynamicV4.put(InetAddress.getByName("10.1.2.3"), new DynamicWorkload().setDomainName("athenz.examples").setServiceName("api1"));

        NavigableMap<InetAddress, DynamicWorkload> dynamicV6 = new TreeMap<>(InetComparator::compare);
        dynamicV6.put(InetAddress.getByName("2001:4998:efeb:2ff::a:2"), new DynamicWorkload().setDomainName("athenz.examples").setServiceName("api0"));

        InetAddressMap<DynamicWorkload> dynamicIps = new InetAddressMap<>(dynamicV4, dynamicV6);

        NavigableMap<InetAddress, StaticWorkload> staticV4 = new TreeMap<>(InetComparator::compare);
        staticV4.put(InetAddress.getByName("12.1.3.1"), new StaticWorkload().setDomainName("athenz.examples").setServiceName("static-api0"));
        staticV4.put(InetAddress.getByName("10.1.2.3"), new StaticWorkload().setDomainName("athenz.examples").setServiceName("static-api1"));

        NavigableMap<InetAddress, StaticWorkload> staticV6 = new TreeMap<>(InetComparator::compare);
        staticV6.put(InetAddress.getByName("2001:4998:efeb:2ff::a:3"), new StaticWorkload().setDomainName("athenz.examples").setServiceName("static-api0"));

        InetAddressMap<StaticWorkload> staticIps = new InetAddressMap<>(staticV4, staticV6);

        InetWorkload inetWorkload = new InetWorkload(dynamicIps, staticIps);

        assertNotNull(inetWorkload.getDynamicIps());
        assertTrue(inetWorkload.getDynamicIps().getV4().containsKey(InetAddress.getByName("12.1.3.1")));
        assertEquals(inetWorkload.getDynamicIps().getV4().size(), 2);

        assertNotNull(inetWorkload.getStaticIps());
        assertTrue(inetWorkload.getStaticIps().getV4().containsKey(InetAddress.getByName("10.1.2.3")));
        assertEquals(inetWorkload.getStaticIps().getV4().size(), 2);
        assertEquals(inetWorkload.getStaticIps().getV6().size(), 1);
        assertTrue(inetWorkload.getStaticIps().getV6().containsKey(InetAddress.getByName("2001:4998:efeb:2ff::a:3")));
    }

}