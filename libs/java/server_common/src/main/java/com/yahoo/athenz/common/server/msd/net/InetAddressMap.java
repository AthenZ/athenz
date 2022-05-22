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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.NavigableMap;

public class InetAddressMap<T> {
    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    NavigableMap<InetAddress, T> v4;
    NavigableMap<InetAddress, T> v6;

    public NavigableMap<InetAddress, T> getV4() {
        return v4;
    }

    public NavigableMap<InetAddress, T> getV6() {
        return v6;
    }

    public InetAddressMap(NavigableMap<InetAddress, T> v4, NavigableMap<InetAddress, T> v6) {
        this.v4 = v4;
        this.v6 = v6;
    }

    public void putIp(String ipStr, T w) {
        try {
            InetAddress ip = InetAddress.getByName(ipStr);
            if (ip instanceof Inet4Address) {
                v4.put(InetAddress.getByName(ipStr), w);
            } else {
                v6.put(InetAddress.getByName(ipStr), w);
            }
        } catch (UnknownHostException e) {
            LOG.error("bad ip: {}, workload: {}", ipStr, w);
        }
    }

    public void putIps(List<String> ips, T w) {
        if (ips == null) {
            return;
        }
        ips.stream().forEach(i -> putIp(i, w));
    }
}
