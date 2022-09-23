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

package com.yahoo.athenz.zts;

import java.util.Collections;

import org.testng.annotations.Test;

import com.yahoo.rdl.Timestamp;

import static org.testng.Assert.*;

public class ServiceIdentityTest {

    @Test
    public void testServiceIdentity() {

        ServiceIdentity si1 = new ServiceIdentity();
        ServiceIdentity si2 = new ServiceIdentity();

        si1.setExecutable("exe");
        si1.setGroup("sample_group");
        si1.setHosts(Collections.singletonList("host"));
        si1.setModified(Timestamp.fromMillis(1234567890123L));
        si1.setName("apicomponent");
        si1.setProviderEndpoint("sample_endpoint");
        si1.setPublicKeys(Collections.singletonList(new PublicKeyEntry()));
        si1.setUser("user.test");

        si2.setExecutable("exe");
        si2.setGroup("sample_group");
        si2.setHosts(Collections.singletonList("host"));
        si2.setModified(Timestamp.fromMillis(1234567890123L));
        si2.setName("apicomponent");
        si2.setProviderEndpoint("sample_endpoint");
        si2.setPublicKeys(Collections.singletonList(new PublicKeyEntry()));
        si2.setUser("user.test");

        assertEquals(si1.getExecutable(), "exe");
        assertEquals(si1.getGroup(), "sample_group");
        assertEquals(si1.getHosts(), Collections.singletonList("host"));
        assertEquals(si1.getModified(), Timestamp.fromMillis(1234567890123L));
        assertEquals(si1.getName(), "apicomponent");
        assertEquals(si1.getProviderEndpoint(), "sample_endpoint");
        assertEquals(si1.getPublicKeys(), Collections.singletonList(new PublicKeyEntry()));
        assertEquals(si1.getUser(), "user.test");

        assertEquals(si1, si2);
        assertEquals(si1, si1);

        si1.setExecutable("exe2");
        assertNotEquals(si2, si1);
        si1.setExecutable(null);
        assertNotEquals(si2, si1);
        si1.setExecutable("exe");
        assertEquals(si2, si1);

        si1.setGroup("sample_group1");
        assertNotEquals(si2, si1);
        si1.setGroup(null);
        assertNotEquals(si2, si1);
        si1.setGroup("sample_group");
        assertEquals(si2, si1);

        si1.setName("apicomponent1");
        assertNotEquals(si2, si1);
        si1.setName(null);
        assertNotEquals(si2, si1);
        si1.setName("apicomponent");
        assertEquals(si2, si1);

        si1.setProviderEndpoint("sample_endpoint1");
        assertNotEquals(si2, si1);
        si1.setProviderEndpoint(null);
        assertNotEquals(si2, si1);
        si1.setProviderEndpoint("sample_endpoint");
        assertEquals(si2, si1);

        si1.setUser("user.test1");
        assertNotEquals(si2, si1);
        si1.setUser(null);
        assertNotEquals(si2, si1);
        si1.setUser("user.test");
        assertEquals(si2, si1);

        si1.setModified(Timestamp.fromMillis(1234567890124L));
        assertNotEquals(si2, si1);
        si1.setModified(null);
        assertNotEquals(si2, si1);
        si1.setModified(Timestamp.fromMillis(1234567890123L));
        assertEquals(si2, si1);

        si1.setHosts(Collections.singletonList("host1"));
        assertNotEquals(si2, si1);
        si1.setHosts(null);
        assertNotEquals(si2, si1);
        si1.setHosts(Collections.singletonList("host"));
        assertEquals(si2, si1);

        si1.setPublicKeys(Collections.singletonList(new PublicKeyEntry().setKey("key")));
        assertNotEquals(si2, si1);
        si1.setPublicKeys(null);
        assertNotEquals(si2, si1);
        si1.setPublicKeys(Collections.singletonList(new PublicKeyEntry()));
        assertEquals(si2, si1);

        assertNotEquals(si2, null);
        assertNotEquals("si1", si1);
    }
}
