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

package com.yahoo.athenz.instance.provider.impl;

import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.instance.provider.AttrValidator;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ResourceException;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.*;

import static org.testng.Assert.*;

public class SecureBootProviderTest {

    @Test
    public void testInitializeDnsSuffix() {
        System.setProperty(SecureBootProvider.ZTS_PROP_SB_PROVIDER_DNS_SUFFIX, "zts.abc.cloud");
        SecureBootProvider provider = new SecureBootProvider();
        provider.initialize("sys.auth.sb-provider", "com.yahoo.athenz.instance.provider.impl.SecureBootProvider", null, null);
        assertTrue(provider.dnsSuffixes.contains("zts.abc.cloud"));

        System.clearProperty(SecureBootProvider.ZTS_PROP_SB_PROVIDER_DNS_SUFFIX);
    }

    @Test
    public void testConfirmInstance() {
        System.setProperty(SecureBootProvider.ZTS_PROP_SB_ATTR_VALIDATOR_FACTORY_CLASS, "com.yahoo.athenz.instance.provider.impl.MockAttrValidatorFactory");

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(hostnameResolver.getAllByName("athenz-examples1.abc.com")).thenReturn(
                new HashSet<>(Arrays.asList("10.1.1.2", "2001:db8:a0b:12f0:0:0:0:1"))
        );

        SecureBootProvider provider = new SecureBootProvider();
        provider.initialize("sys.auth.sb-provider", "com.yahoo.athenz.instance.provider.impl.SecureBootProvider", null, null);
        provider.setHostnameResolver(hostnameResolver);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("sample attestation data");
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.sb-provider");

        Map<String, String> attributes = new HashMap<>();
        String subjectDn = "CN=athenz-examples1.abc.com,OU=Testing Domain,O=Athenz,L=LA,ST=CA,C=US";
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, "athenz-examples1.abc.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_ISSUER_DN, "CN=issuer1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_SUBJECT_DN, subjectDn);
        confirmation.setAttributes(attributes);

        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertNotNull(result);
        assertEquals(result.getAttributes().get(InstanceProvider.ZTS_CERT_SSH), "true");

        provider.close();
        System.clearProperty(SecureBootProvider.ZTS_PROP_SB_ATTR_VALIDATOR_FACTORY_CLASS);
    }

    @Test
    public void testConfirmInstanceWithSanIp() {
        System.setProperty(SecureBootProvider.ZTS_PROP_SB_ATTR_VALIDATOR_FACTORY_CLASS, "com.yahoo.athenz.instance.provider.impl.MockAttrValidatorFactory");

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(hostnameResolver.getAllByName("athenz-examples1.abc.com")).thenReturn(
                new HashSet<>(Arrays.asList("10.1.1.2", "2001:db8:a0b:12f0:0:0:0:1"))
        );

        SecureBootProvider provider = new SecureBootProvider();
        provider.initialize("sys.auth.sb-provider", "com.yahoo.athenz.instance.provider.impl.SecureBootProvider", null, null);
        provider.setHostnameResolver(hostnameResolver);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("sample attestation data");
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.sb-provider");

        Map<String, String> attributes = new HashMap<>();
        String subjectDn = "CN=athenz-examples1.abc.com,OU=Testing Domain,O=Athenz,L=LA,ST=CA,C=US";
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, "athenz-examples1.abc.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.2");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_ISSUER_DN, "CN=issuer1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_SUBJECT_DN, subjectDn);
        confirmation.setAttributes(attributes);

        assertNotNull(provider.confirmInstance(confirmation));
        provider.close();
        System.clearProperty(SecureBootProvider.ZTS_PROP_SB_ATTR_VALIDATOR_FACTORY_CLASS);
    }

    @Test
    public void testConfirmInstancePrincipalNotAllowed() {
        System.setProperty(SecureBootProvider.ZTS_PROP_SB_PRINCIPAL_LIST, "media.api");
        SecureBootProvider provider = new SecureBootProvider();
        provider.initialize("sys.auth.sb-provider", "com.yahoo.athenz.instance.provider.impl.SecureBootProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("sample attestation data");
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.sb-provider");

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException e) {
            assertTrue(e.getMessage().contains("Service not supported to be launched by SecureBoot Provider"));
        }

        System.clearProperty(SecureBootProvider.ZTS_PROP_SB_PRINCIPAL_LIST);
    }

    @Test
    public void testConfirmInstanceIssuerNotAllowed() {
        System.setProperty(SecureBootProvider.ZTS_PROP_SB_ISSUER_DN_LIST, "CN=issuer1");
        SecureBootProvider provider = new SecureBootProvider();
        provider.initialize("sys.auth.sb-provider", "com.yahoo.athenz.instance.provider.impl.SecureBootProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("sample attestation data");
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.sb-provider");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_ISSUER_DN, "CN=issuer2");
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException e) {
            assertTrue(e.getMessage().contains("Invalid issuer"));
        }

        System.clearProperty(SecureBootProvider.ZTS_PROP_SB_ISSUER_DN_LIST);
    }

    @Test
    public void testConfirmInstanceInvalidHostname() {
        SecureBootProvider provider = new SecureBootProvider();
        provider.initialize("sys.auth.sb-provider", "com.yahoo.athenz.instance.provider.impl.SecureBootProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("sample attestation data");
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.sb-provider");


        Map<String, String> attributes = new HashMap<>();
        String subjectDn = "CN=athenz-examples1.abc.com,OU=Testing Domain,O=Athenz,L=LA,ST=CA,C=US";
        attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_ISSUER_DN, "CN=issuer1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_SUBJECT_DN, subjectDn);
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException e) {
            assertTrue(e.getMessage().contains("Unable to validate certificate request hostname"));
        }
    }

    @Test
    public void testConfirmInstanceAttributeMismatch() {
        AttrValidator attrValidator = instanceConfirmation -> false;

        SecureBootProvider provider = new SecureBootProvider();
        provider.initialize("sys.auth.sb-provider", "com.yahoo.athenz.instance.provider.impl.SecureBootProvider", null, null);
        provider.setAttrValidator(attrValidator);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("sample attestation data");
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.sb-provider");

        Map<String, String> attributes = new HashMap<>();
        String subjectDn = "CN=athenz-examples1.abc.com,OU=Testing Domain,O=Athenz,L=LA,ST=CA,C=US";
        attributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, "athenz-examples1.abc.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_ISSUER_DN, "CN=issuer1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_SUBJECT_DN, subjectDn);
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException e) {
            assertTrue(e.getMessage().contains("Unable to validate request instance attributes"));
        }
        provider.close();
    }

    @Test
    public void testConfirmInstanceInvalidSanIp() {
        System.setProperty(SecureBootProvider.ZTS_PROP_SB_ATTR_VALIDATOR_FACTORY_CLASS, "com.yahoo.athenz.instance.provider.impl.MockAttrValidatorFactory");

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(hostnameResolver.getAllByName("athenz-examples1.abc.com")).thenReturn(
                new HashSet<>(Arrays.asList("10.1.1.2", "2001:db8:a0b:12f0:0:0:0:1"))
        );

        SecureBootProvider provider = new SecureBootProvider();
        provider.initialize("sys.auth.sb-provider", "com.yahoo.athenz.instance.provider.impl.SecureBootProvider", null, null);
        provider.setHostnameResolver(hostnameResolver);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("sample attestation data");
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.sb-provider");

        Map<String, String> attributes = new HashMap<>();
        String subjectDn = "CN=athenz-examples1.abc.com,OU=Testing Domain,O=Athenz,L=LA,ST=CA,C=US";
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, "athenz-examples1.abc.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.3");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_ISSUER_DN, "CN=issuer1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_SUBJECT_DN, subjectDn);
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException e) {
            assertTrue(e.getMessage().contains("Unable to validate request IP address"));
        }
        provider.close();
        System.clearProperty(SecureBootProvider.ZTS_PROP_SB_ATTR_VALIDATOR_FACTORY_CLASS);
    }


    @Test
    public void testConfirmInstanceInvalidSanDns() {
        System.setProperty(SecureBootProvider.ZTS_PROP_SB_ATTR_VALIDATOR_FACTORY_CLASS, "com.yahoo.athenz.instance.provider.impl.MockAttrValidatorFactory");

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(hostnameResolver.getAllByName("athenz-examples1.abc.com")).thenReturn(
                new HashSet<>(Arrays.asList("10.1.1.2", "2001:db8:a0b:12f0:0:0:0:1"))
        );

        SecureBootProvider provider = new SecureBootProvider();
        provider.initialize("sys.auth.sb-provider", "com.yahoo.athenz.instance.provider.impl.SecureBootProvider", null, null);
        provider.setHostnameResolver(hostnameResolver);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("sample attestation data");
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.sb-provider");

        Map<String, String> attributes = new HashMap<>();
        String subjectDn = "CN=athenz-examples1.abc.com,OU=Testing Domain,O=Athenz,L=LA,ST=CA,C=US";
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.unknown.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, "athenz-examples1.abc.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.2");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_ISSUER_DN, "CN=issuer1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_SUBJECT_DN, subjectDn);
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException e) {
            assertTrue(e.getMessage().contains("Unable to validate certificate request DNS"));
        }
        provider.close();
        System.clearProperty(SecureBootProvider.ZTS_PROP_SB_ATTR_VALIDATOR_FACTORY_CLASS);
    }

    @Test
    public void testRefreshInstance() {
        System.setProperty(SecureBootProvider.ZTS_PROP_SB_ATTR_VALIDATOR_FACTORY_CLASS, "com.yahoo.athenz.instance.provider.impl.MockAttrValidatorFactory");

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(hostnameResolver.getAllByName("athenz-examples1.abc.com")).thenReturn(
                new HashSet<>(Arrays.asList("10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"))
        );

        SecureBootProvider provider = new SecureBootProvider();
        provider.initialize("sys.auth.sb-provider", "com.yahoo.athenz.instance.provider.impl.SecureBootProvider", null, null);
        provider.setHostnameResolver(hostnameResolver);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("sample attestation data");
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.sb-provider");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, "athenz-examples1.abc.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_HOSTNAME, "athenz-examples1.abc.com");
        confirmation.setAttributes(attributes);

        assertNotNull(provider.refreshInstance(confirmation));
        provider.close();
        System.clearProperty(SecureBootProvider.ZTS_PROP_SB_ATTR_VALIDATOR_FACTORY_CLASS);
    }

    @Test
    public void testNewAttrValidator() {
        System.setProperty(SecureBootProvider.ZTS_PROP_SB_ATTR_VALIDATOR_FACTORY_CLASS, "com.yahoo.athenz.instance.provider.impl.MockAttrValidatorFactory");
        AttrValidator attrValidator = SecureBootProvider.newAttrValidator(null);
        assertNotNull(attrValidator);
        assertTrue(attrValidator.confirm(null));
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testNewAttrValidatorFail() {
        System.setProperty(SecureBootProvider.ZTS_PROP_SB_ATTR_VALIDATOR_FACTORY_CLASS, "NoClass");
        SecureBootProvider.newAttrValidator(null);
    }

    @Test
    public void testGetProviderScheme() {
        assertEquals(InstanceProvider.Scheme.CLASS, new SecureBootProvider().getProviderScheme());
    }

    @Test
    public void testValidateHostname() {
        assertFalse(SecureBootProvider.validateHostname("", true, null));
        assertFalse(SecureBootProvider.validateHostname(null, true, null));

        // For register, if a hostname must match the CN
        assertFalse(SecureBootProvider.validateHostname("athenz-examples1.abc.com", true, null));
        assertFalse(SecureBootProvider.validateHostname("athenz-examples1.abc.com", true, new HashMap<>()));

        String subjectDn = "CN=athenz-examples1.abc.com,OU=Testing Domain,O=Athenz,L=LA,ST=CA,C=US";
        assertTrue(SecureBootProvider.validateHostname("athenz-examples1.abc.com", true,
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_CERT_SUBJECT_DN, subjectDn)));

        // For refresh, the hostname must match the one in cert hostname passed in via ZTS
        assertTrue(SecureBootProvider.validateHostname("athenz-examples1.abc.com", false,
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_CERT_HOSTNAME, "athenz-examples1.abc.com")));
        assertFalse(SecureBootProvider.validateHostname("athenz-examples1.abc.com", false,
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_CERT_HOSTNAME, "bogus1.abc.com")));
        assertTrue(SecureBootProvider.validateHostname("athenz-examples1.abc.com", false,
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_SAN_URI, "athenz.examples.api.zts.athenz.cloud")));

    }

    @Test
    public void testValidateSanIp() {

        assertTrue(new SecureBootProvider().validateSanIp("athenz-examples1.abc.com", null));
        assertTrue(new SecureBootProvider().validateSanIp("athenz-examples1.abc.com", new HashMap<>()));
        assertTrue(new SecureBootProvider().validateSanIp("athenz-examples1.abc.com",
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_SAN_IP, "")));
        assertTrue(new SecureBootProvider().validateSanIp("athenz-examples1.abc.com",
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_SAN_IP, ",")));
        assertTrue(new SecureBootProvider().validateSanIp("athenz-examples1.abc.com",
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_SAN_IP, ",,,,")));

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(hostnameResolver.getAllByName("athenz-examples1.abc.com")).thenReturn(
                new HashSet<>(Arrays.asList("10.1.1.2", "2001:db8:a0b:12f0:0:0:0:1"))
        );

        SecureBootProvider provider = new SecureBootProvider();
        provider.initialize("sys.auth.sb-provider", "com.yahoo.athenz.instance.provider.impl.SecureBootProvider", null, null);
        provider.setHostnameResolver(hostnameResolver);

        assertTrue(provider.validateSanIp("athenz-examples1.abc.com",
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.2,2001:db8:a0b:12f0:0:0:0:1")));
        assertTrue(provider.validateSanIp("athenz-examples1.abc.com",
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.2")));
        assertTrue(provider.validateSanIp("athenz-examples1.abc.com",
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_SAN_IP, "2001:db8:a0b:12f0:0:0:0:1")));
        assertTrue(provider.validateSanIp("athenz-examples1.abc.com",
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_SAN_IP, "2001:db8:a0b:12f0:0:0:0:1,10.1.1.2")));

        assertFalse(provider.validateSanIp("athenz-examples1.abc.com",
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.3")));
        assertFalse(provider.validateSanIp("athenz-examples1.abc.com",
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.3,2001:db8:a0b:12f0:0:0:0:1")));
        assertFalse(provider.validateSanIp("athenz-examples1.abc.com",
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.2,2001:db8:a0b:12f0:0:0:0:2")));


    }

    @Test
    public void testValidateSanIpWithCompressedHostIp() {
        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(hostnameResolver.getAllByName("athenz-examples1.abc.com")).thenReturn(
                new HashSet<>(Arrays.asList("200.152.166.210", "2804:1bc:f044:1fa::6002"))
        );

        SecureBootProvider provider = new SecureBootProvider();
        provider.initialize("sys.auth.sb-provider", "com.yahoo.athenz.instance.provider.impl.SecureBootProvider", null, null);
        provider.setHostnameResolver(hostnameResolver);

        assertTrue(provider.validateSanIp("athenz-examples1.abc.com",
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_SAN_IP, "200.152.166.210,2804:1bc:f044:1fa:0:0:0:6002")));

        assertFalse(provider.validateSanIp("athenz-examples1.abc.com",
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_SAN_IP, "200.152.166.210,2904:1bc:f044:1fa:0:0:0:6002")));

    }

    @Test
    public void testValidateSanIpWithInvalidHostIp() {
        // [200.152.166.210, 2804:1bc:f044:1fa:0:0:0:6002] with hostIps:[2804:1bc:f044:1fa::6002, 200.152.166.210]
        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(hostnameResolver.getAllByName("athenz-examples1.abc.com")).thenReturn(
                new HashSet<>(Arrays.asList("200.152.166.210", "2804:1bc:f044:1fa::6002", "unparseable:1bc:f044:1fa::6002"))
        );

        SecureBootProvider provider = new SecureBootProvider();
        provider.initialize("sys.auth.sb-provider", "com.yahoo.athenz.instance.provider.impl.SecureBootProvider", null, null);
        provider.setHostnameResolver(hostnameResolver);

        assertTrue(provider.validateSanIp("athenz-examples1.abc.com",
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_SAN_IP, "200.152.166.210,2804:1bc:f044:1fa:0:0:0:6002")));
    }


        @Test
    public void testValidateCnHostname() {
        String subjectDn = "CN=athenz-examples1.abc.com,OU=Testing Domain,O=Athenz,L=LA,ST=CA,C=US";
        assertTrue(SecureBootProvider.validateCnHostname("athenz-examples1.abc.com",
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_CERT_SUBJECT_DN, subjectDn)));

        assertFalse(SecureBootProvider.validateCnHostname("athenz-examples2.abc.com",
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_CERT_SUBJECT_DN, subjectDn)));
        assertFalse(SecureBootProvider.validateCnHostname("athenz-examples2.abc.com", null));
    }

    @Test
    public void testValidateCertHostname() {
        assertTrue(SecureBootProvider.validateCertHostname("athenz-examples1.abc.com", null));
        assertTrue(SecureBootProvider.validateCertHostname("athenz-examples1.abc.com", new HashMap<>()));
        assertTrue(SecureBootProvider.validateCertHostname("athenz-examples1.abc.com",
                Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_CERT_HOSTNAME, "athenz-examples1.abc.com")));

    }

    @Test
    public void testValidateIssuer() {
        assertFalse(new SecureBootProvider().validateIssuer(null));
        assertFalse(new SecureBootProvider().validateIssuer(new HashMap<>()));
        assertTrue(new SecureBootProvider().validateIssuer(Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_CERT_ISSUER_DN, "issuerdn")));

        System.setProperty(SecureBootProvider.ZTS_PROP_SB_ISSUER_DN_LIST, "CN=issuer1,OU=Testing Domain,O=Athenz,L=LA,ST=CA,C=US;CN=issuer2");
        String issuerDn = "CN=issuer2";
        assertTrue(new SecureBootProvider().validateIssuer(Collections.singletonMap(InstanceProvider.ZTS_INSTANCE_CERT_ISSUER_DN, issuerDn)));
        System.clearProperty(SecureBootProvider.ZTS_PROP_SB_ISSUER_DN_LIST);
    }

    @Test
    public void testParseDnList() {
        List<String> list = new ArrayList<>();
        list.add("CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US");
        list.add("CN=Count, OU=BobInc, O=Bob Systems, C=US");
        list.add("C=US, O=Alice Systems, OU=Alice, CN=Ellington");

        Set<String> dnSet = SecureBootProvider.parseDnList(list);
        assertTrue(dnSet.contains("CN=Duke,OU=JavaSoft,O=Sun Microsystems,C=US"));
        assertTrue(dnSet.contains("CN=Count,OU=BobInc,O=Bob Systems,C=US"));
        assertTrue(dnSet.contains("C=US,O=Alice Systems,OU=Alice,CN=Ellington"));
        assertEquals(dnSet.size(), 3);

    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testParseDnListInvalid() {
        List<String> list = new ArrayList<>();
        list.add("unparseable");

        SecureBootProvider.parseDnList(list);
        fail();
    }

    @Test
    public void flattenIp() {
        assertEquals(SecureBootProvider.flattenIp("2804:1bc:f044:1fa::6002"), "2804:1bc:f044:1fa:0:0:0:6002");
        assertEquals(SecureBootProvider.flattenIp("10.2.3.4"), "10.2.3.4");
        assertEquals(SecureBootProvider.flattenIp("unparseable.2.3.4"), "");
    }
}