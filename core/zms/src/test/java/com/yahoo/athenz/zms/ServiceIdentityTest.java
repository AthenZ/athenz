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

package com.yahoo.athenz.zms;

import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.Validator;
import org.testng.annotations.Test;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.*;
import static org.testng.Assert.assertFalse;

public class ServiceIdentityTest {

    @Test
    public void testServiceIdentity() {

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        PublicKeyEntry pke = new PublicKeyEntry().setId("v1").setKey("pubkey====");
        List<PublicKeyEntry> pkel = Collections.singletonList(pke);
        List<String> hosts = List.of("test.host");
        Map<String, TagValueList> tags = Collections.singletonMap("tagKey",
                new TagValueList().setList(Collections.singletonList("tagValue")));

        // ServiceIdentity test
        ServiceIdentity si = new ServiceIdentity().setName("test.service").setPublicKeys(pkel)
                .setProviderEndpoint("http://test.endpoint").setModified(Timestamp.fromMillis(123456789123L))
                .setExecutable("exec/path").setHosts(hosts).setUser("user.test").setGroup("test.group")
                .setDescription("description")
                .setTags(tags)
                .setResourceOwnership(new ResourceServiceIdentityOwnership().setObjectOwner("TF"))
                .setX509CertSignerKeyId("x509-keyid").setSshCertSignerKeyId("ssh-keyid")
                .setCreds("creds");

        Validator.Result result = validator.validate(si, "ServiceIdentity");
        assertTrue(result.valid);

        assertEquals(si.getName(), "test.service");
        assertEquals(si.getPublicKeys(), pkel);
        assertEquals(si.getProviderEndpoint(), "http://test.endpoint");
        assertEquals(si.getModified(), Timestamp.fromMillis(123456789123L));
        assertEquals(si.getExecutable(), "exec/path");
        assertEquals(si.getHosts(), hosts);
        assertEquals(si.getUser(), "user.test");
        assertEquals(si.getGroup(), "test.group");
        assertEquals(si.getDescription(), "description");
        assertEquals(si.getTags().get("tagKey").getList().get(0), "tagValue");
        assertEquals(si.getResourceOwnership(), new ResourceServiceIdentityOwnership().setObjectOwner("TF"));
        assertEquals(si.getX509CertSignerKeyId(), "x509-keyid");
        assertEquals(si.getSshCertSignerKeyId(), "ssh-keyid");
        assertEquals(si.getCreds(), "creds");

        ServiceIdentity si2 = new ServiceIdentity().setName("test.service").setPublicKeys(pkel)
                .setProviderEndpoint("http://test.endpoint").setModified(Timestamp.fromMillis(123456789123L))
                .setExecutable("exec/path").setHosts(hosts).setUser("user.test").setGroup("test.group")
                .setDescription("description")
                .setTags(tags)
                .setResourceOwnership(new ResourceServiceIdentityOwnership().setObjectOwner("TF"))
                .setX509CertSignerKeyId("x509-keyid").setSshCertSignerKeyId("ssh-keyid")
                .setCreds("creds");

        assertTrue(si2.equals(si));
        assertTrue(si.equals(si));

        si2.setX509CertSignerKeyId("x509-keyid2");
        assertNotEquals(si2, si);
        si2.setX509CertSignerKeyId(null);
        assertNotEquals(si2, si);
        si2.setX509CertSignerKeyId("x509-keyid");
        assertEquals(si2, si);

        si2.setSshCertSignerKeyId("ssh-keyid2");
        assertNotEquals(si2, si);
        si2.setSshCertSignerKeyId(null);
        assertNotEquals(si2, si);
        si2.setSshCertSignerKeyId("ssh-keyid");
        assertEquals(si2, si);

        si2.setResourceOwnership(new ResourceServiceIdentityOwnership().setObjectOwner("ZTS"));
        assertNotEquals(si2, si);
        si2.setResourceOwnership(null);
        assertNotEquals(si2, si);
        si2.setResourceOwnership(new ResourceServiceIdentityOwnership().setObjectOwner("TF"));
        assertEquals(si2, si);

        si2.setGroup("group2");
        assertNotEquals(si2, si);
        si2.setGroup(null);
        assertNotEquals(si2, si);
        si2.setGroup("test.group");
        assertEquals(si2, si);

        si2.setUser("user2");
        assertNotEquals(si2, si);
        si2.setUser(null);
        assertNotEquals(si2, si);
        si2.setUser("user.test");
        assertEquals(si2, si);

        si2.setHosts(List.of("test.host2"));
        assertNotEquals(si2, si);
        si2.setHosts(null);
        assertNotEquals(si2, si);
        si2.setHosts(hosts);
        assertEquals(si2, si);

        si2.setExecutable("exec/path2");
        assertNotEquals(si2, si);
        si2.setExecutable(null);
        assertNotEquals(si2, si);
        si2.setExecutable("exec/path");
        assertEquals(si2, si);

        si2.setModified(Timestamp.fromMillis(123456789124L));
        assertNotEquals(si2, si);
        si2.setModified(null);
        assertNotEquals(si2, si);
        si2.setModified(Timestamp.fromMillis(123456789123L));
        assertEquals(si2, si);

        si2.setProviderEndpoint("http://test.endpoint2");
        assertNotEquals(si2, si);
        si2.setProviderEndpoint(null);
        assertNotEquals(si2, si);
        si2.setProviderEndpoint("http://test.endpoint");
        assertEquals(si2, si);

        si2.setDescription("description2");
        assertNotEquals(si2, si);
        si2.setDescription(null);
        assertNotEquals(si2, si);
        si2.setDescription("description");
        assertEquals(si2, si);

        si2.setName("test.service2");
        assertNotEquals(si2, si);
        si2.setName(null);
        assertNotEquals(si2, si);
        si2.setName("test.service");
        assertEquals(si2, si);

        si2.setPublicKeys(Collections.emptyList());
        assertNotEquals(si2, si);
        si2.setPublicKeys(null);
        assertNotEquals(si2, si);
        si2.setPublicKeys(pkel);
        assertEquals(si2, si);

        si2.setTags(Collections.emptyMap());
        assertNotEquals(si2, si);
        si2.setTags(null);
        assertNotEquals(si2, si);
        si2.setTags(tags);
        assertEquals(si2, si);

        si2.setCreds("creds2");
        assertNotEquals(si2, si);
        si2.setCreds(null);
        assertNotEquals(si2, si);
        si2.setCreds("creds");
        assertEquals(si2, si);

        assertFalse(si.equals(new String()));
    }

    @Test
    public void testCredsEntry() {

        CredsEntry credsEntry = new CredsEntry().setValue("value");
        assertEquals(credsEntry.getValue(), "value");

        CredsEntry credsEntry2 = new CredsEntry().setValue("value");
        assertEquals(credsEntry2, credsEntry);

        credsEntry2.setValue("value2");
        assertNotEquals(credsEntry2, credsEntry);
        credsEntry2.setValue(null);
        assertNotEquals(credsEntry2, credsEntry);
        credsEntry2.setValue("value");
        assertEquals(credsEntry2, credsEntry);

        assertFalse(credsEntry.equals(new String()));
    }
}
