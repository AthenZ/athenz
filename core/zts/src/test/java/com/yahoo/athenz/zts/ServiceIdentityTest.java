/**
 * Copyright 2016 Yahoo Inc.
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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.testng.annotations.Test;

import com.yahoo.rdl.Timestamp;

public class ServiceIdentityTest {

    @Test
    public void testsetgetServiceIdentity() {
        ServiceIdentity si = new ServiceIdentity();
        ServiceIdentity si2 = new ServiceIdentity();
        PublicKeyEntry pkey = new PublicKeyEntry();

        // set
        pkey.setId("key01");
        pkey.setKey("pkey==");

        List<PublicKeyEntry> pkeylist = new ArrayList<PublicKeyEntry>();
        pkeylist.add(pkey);

        List<String> hosts = new ArrayList<String>();
        hosts.add("example.host");

        si.setExecutable("add-domain");
        si.setGroup("sample_group");
        si.setHosts(hosts);
        si.setModified(Timestamp.fromMillis(1234567890123L));
        si.setName("apicomponent");
        si.setProviderEndpoint("sample_endpoint");
        si.setPublicKeys(pkeylist);
        si.setUser("user.test");

        si2.setExecutable("add-domain");
        si.setGroup("sample_group");
        si2.setHosts(hosts);
        si2.setModified(Timestamp.fromMillis(1234567890123L));
        si2.setName("apicomponent");
        si2.setProviderEndpoint("sample_endpoint");
        si2.setPublicKeys(pkeylist);
        si2.setUser("user.test");

        // get assertions
        assertEquals(pkey.getId(), "key01");
        assertEquals(pkey.getKey(), "pkey==");

        assertEquals(si.getExecutable(), "add-domain");
        assertEquals(si.getGroup(), "sample_group");
        assertEquals(si.getHosts(), hosts);
        assertEquals(si.getModified(), Timestamp.fromMillis(1234567890123L));
        assertEquals(si.getName(), "apicomponent");
        assertEquals(si.getProviderEndpoint(), "sample_endpoint");
        assertEquals(si.getPublicKeys(), pkeylist);
        assertEquals(si.getUser(), "user.test");

        // equals true
        assertTrue(pkey.equals(pkey));
        assertTrue(si.equals(si));

        // equals false
        assertFalse(pkey.equals(new String()));
        assertFalse(pkey.equals(new PublicKeyEntry()));
        PublicKeyEntry pkey2 = new PublicKeyEntry().setKey("pkey==");
        assertFalse(pkey2.equals(pkey));

        assertFalse(si.equals(new String()));
        
        si2.setGroup(null);
        assertFalse(si2.equals(si));
        si2.setUser(null);
        assertFalse(si2.equals(si));
        si2.setHosts(null);
        assertFalse(si2.equals(si));
        si2.setExecutable(null);
        assertFalse(si2.equals(si));
        si2.setModified(null);
        assertFalse(si2.equals(si));
        si2.setProviderEndpoint(null);
        assertFalse(si2.equals(si));
        si2.setPublicKeys(null);
        assertFalse(si2.equals(si));
        si2.setName(null);
        assertFalse(si2.equals(si));
        assertFalse(si2.equals(null));
        assertFalse(si.equals(new ServiceIdentity()));

    }

}
