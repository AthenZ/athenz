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
package io.athenz.server.k8s.common.impl;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class KubernetesPodResolverUtilTest {

    @Test
    public void testGetPodSiblings() throws UnknownHostException {
        String serviceName = "msd.api.svc.cluster.local";
        InetAddress podAddress1 = Mockito.mock(InetAddress.class);
        InetAddress podAddress2 = Mockito.mock(InetAddress.class);
        Mockito.when(podAddress1.getHostAddress()).thenReturn("192.168.1.10");
        Mockito.when(podAddress2.getHostAddress()).thenReturn("192.168.1.11");

        MockedStatic<InetAddress> inetAddressMock = Mockito.mockStatic(InetAddress.class);
        inetAddressMock.when(() -> InetAddress.getAllByName(serviceName)).thenReturn(new InetAddress[]{podAddress1, podAddress2});
        InetAddress[] podsIPs = KubernetesPodResolverUtil.getSiblingPodIPs(serviceName);
        Assert.assertEquals(podsIPs.length, 2);
        inetAddressMock.close();
    }

    @Test
    public void testGetPodSiblingsEmptyServiceNameException() {
        String serviceName = "";
        Exception ex = null;
        try {
            KubernetesPodResolverUtil.getSiblingPodIPs(serviceName);
        } catch (IllegalArgumentException | UnknownHostException e) {
            ex = e;
        }
        if (ex == null) {
            Assert.fail("expected IllegalArgumentException not thrown");
        }

        Exception nullEx = null;
        try {
            KubernetesPodResolverUtil.getSiblingPodIPs(null);
        } catch (IllegalArgumentException | UnknownHostException e) {
            nullEx = e;
        }
        if (nullEx == null) {
            Assert.fail("expected IllegalArgumentException not thrown");
        }
    }

    @Test
    public void testGetPodSiblingsInvalidHostnameException() {
        String serviceName = "foo";
        MockedStatic<InetAddress> inetAddressMock = Mockito.mockStatic(InetAddress.class);
        inetAddressMock.when(() -> InetAddress.getAllByName(serviceName)).thenThrow(UnknownHostException.class);
        Exception ex = null;
        try {
            KubernetesPodResolverUtil.getSiblingPodIPs(serviceName);
        } catch (IllegalArgumentException | UnknownHostException e) {
            ex = e;
        }
        if (ex == null) {
            Assert.fail("expected UnknownHostException not thrown");
        }
        inetAddressMock.close();
    }
}
