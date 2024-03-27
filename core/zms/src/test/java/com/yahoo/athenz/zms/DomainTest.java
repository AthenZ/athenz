/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zms;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.UUID;
import com.yahoo.rdl.Validator;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.*;
import static org.testng.Assert.assertFalse;

public class DomainTest {

    @Test
    public void testDomainMetaStoreValidValuesList() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);
        List<String> validValues = new ArrayList<>();
        validValues.add("bs1");
        validValues.add("bs2");
        validValues.add("bs3");
        validValues.add("bs4");
        validValues.add("bs5");
        DomainMetaStoreValidValuesList validValuesList = new DomainMetaStoreValidValuesList();
        validValuesList.setValidValues(validValues);

        Validator.Result result = validator.validate(validValuesList, "DomainMetaStoreValidValuesList");
        assertTrue(result.valid);
        assertEquals(validValuesList.getValidValues().get(0), "bs1");
        assertEquals(validValuesList.getValidValues().size(), 5);

        List<String> validValues2 = new ArrayList<>();
        validValues2.add("bs1");
        validValues2.add("bs2");
        validValues2.add("bs3");
        validValues2.add("bs4");
        validValues2.add("bs5");
        DomainMetaStoreValidValuesList validValuesList2 = new DomainMetaStoreValidValuesList();
        validValuesList2.setValidValues(validValues2);

        assertEquals(validValuesList, validValuesList2);

        validValuesList2.getValidValues().remove("bs3");
        assertNotEquals(validValuesList2, validValuesList);
        validValuesList.getValidValues().remove("bs3");
        assertEquals(validValuesList2, validValuesList);
        assertNotEquals(validValuesList, null);
        assertNotEquals(schema, validValuesList2);
    }

    @Test
    public void testDomainMetaMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        DomainMeta dm = new DomainMeta().init();
        dm.setDescription("domain desc").setOrg("org:test").setEnabled(true).setAuditEnabled(false)
                .setAccount("aws").setYpmId(10).setApplicationId("101")
                .setCertDnsDomain("athenz.cloud").setMemberExpiryDays(30).setTokenExpiryMins(300)
                .setServiceCertExpiryMins(120).setRoleCertExpiryMins(150).setSignAlgorithm("ec")
                .setServiceExpiryDays(40).setUserAuthorityFilter("OnShore").setGroupExpiryDays(50)
                .setAzureSubscription("azure").setGcpProject("gcp").setBusinessService("business-service")
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setMemberPurgeExpiryDays(10).setGcpProjectNumber("1240").setProductId("abcd-1234")
                .setFeatureFlags(3).setContacts(Map.of("pe-owner", "user.test")).setEnvironment("production")
                .setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF"));

        Validator.Result result = validator.validate(dm, "DomainMeta");
        assertTrue(result.valid);

        assertEquals(dm.getDescription(), "domain desc");
        assertEquals(dm.getOrg(), "org:test");
        assertTrue(dm.getEnabled());
        assertFalse(dm.getAuditEnabled());
        assertEquals(dm.getAccount(), "aws");
        assertEquals(dm.getAzureSubscription(), "azure");
        assertEquals(dm.getGcpProject(), "gcp");
        assertEquals(dm.getGcpProjectNumber(), "1240");
        assertEquals((int) dm.getYpmId(), 10);
        assertEquals(dm.getApplicationId(), "101");
        assertEquals(dm.getCertDnsDomain(), "athenz.cloud");
        assertEquals(dm.getMemberExpiryDays(), Integer.valueOf(30));
        assertEquals(dm.getServiceExpiryDays(), Integer.valueOf(40));
        assertEquals(dm.getGroupExpiryDays(), Integer.valueOf(50));
        assertEquals(dm.getTokenExpiryMins(), Integer.valueOf(300));
        assertEquals(dm.getServiceCertExpiryMins(), Integer.valueOf(120));
        assertEquals(dm.getRoleCertExpiryMins(), Integer.valueOf(150));
        assertEquals(dm.getSignAlgorithm(), "ec");
        assertEquals(dm.getUserAuthorityFilter(), "OnShore");
        assertEquals(dm.getTags(),
                Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertEquals(dm.getBusinessService(), "business-service");
        assertEquals(dm.getMemberPurgeExpiryDays(), 10);
        assertEquals(dm.getProductId(), "abcd-1234");
        assertEquals(dm.getFeatureFlags(), 3);
        assertEquals(dm.getContacts(), Map.of("pe-owner", "user.test"));
        assertEquals(dm.getEnvironment(), "production");
        assertEquals(dm.getResourceOwnership(), new ResourceDomainOwnership().setMetaOwner("TF"));

        DomainMeta dm2 = new DomainMeta().init();
        dm2.setDescription("domain desc").setOrg("org:test").setEnabled(true).setAuditEnabled(false)
                .setAccount("aws").setYpmId(10).setApplicationId("101")
                .setCertDnsDomain("athenz.cloud").setMemberExpiryDays(30).setTokenExpiryMins(300)
                .setServiceCertExpiryMins(120).setRoleCertExpiryMins(150).setSignAlgorithm("ec")
                .setServiceExpiryDays(40).setUserAuthorityFilter("OnShore").setGroupExpiryDays(50)
                .setAzureSubscription("azure").setGcpProject("gcp").setBusinessService("business-service")
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setMemberPurgeExpiryDays(10).setGcpProjectNumber("1240").setProductId("abcd-1234")
                .setFeatureFlags(3).setContacts(Map.of("pe-owner", "user.test")).setEnvironment("production")
                .setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF"));

        assertEquals(dm, dm2);
        assertEquals(dm, dm);

        dm2.setEnvironment("staging");
        assertNotEquals(dm, dm2);
        dm2.setEnvironment(null);
        assertNotEquals(dm, dm2);
        dm2.setEnvironment("production");
        assertEquals(dm, dm2);

        dm2.setContacts(Map.of("product-owner", "user.test"));
        assertNotEquals(dm, dm2);
        dm2.setContacts(null);
        assertNotEquals(dm, dm2);
        dm2.setContacts(Map.of("pe-owner", "user.test"));
        assertEquals(dm, dm2);

        dm2.setUserAuthorityFilter("NotOnShore");
        assertNotEquals(dm, dm2);
        dm2.setUserAuthorityFilter(null);
        assertNotEquals(dm, dm2);
        dm2.setUserAuthorityFilter("OnShore");
        assertEquals(dm, dm2);

        dm2.setProductId("abcd-1235");
        assertNotEquals(dm, dm2);
        dm2.setProductId(null);
        assertNotEquals(dm, dm2);
        dm2.setProductId("abcd-1234");
        assertEquals(dm, dm2);

        dm2.setAccount("aws2");
        assertNotEquals(dm, dm2);
        dm2.setAccount(null);
        assertNotEquals(dm, dm2);
        dm2.setAccount("aws");
        assertEquals(dm, dm2);

        dm2.setAzureSubscription("azure2");
        assertNotEquals(dm, dm2);
        dm2.setAzureSubscription(null);
        assertNotEquals(dm, dm2);
        dm2.setAzureSubscription("azure");
        assertEquals(dm, dm2);

        dm2.setGcpProject("gcp2");
        assertNotEquals(dm, dm2);
        dm2.setGcpProject(null);
        assertNotEquals(dm, dm2);
        dm2.setGcpProject("gcp");
        assertEquals(dm, dm2);

        dm2.setGcpProjectNumber("12401");
        assertNotEquals(dm, dm2);
        dm2.setGcpProjectNumber(null);
        assertNotEquals(dm, dm2);
        dm2.setGcpProjectNumber("1240");
        assertEquals(dm, dm2);

        dm2.setTags(Collections.singletonMap("tagKeyOther", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertNotEquals(dm, dm2);
        dm2.setTags(null);
        assertNotEquals(dm, dm2);
        dm2.setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertEquals(dm, dm2);

        dm2.setSignAlgorithm("rsa");
        assertNotEquals(dm, dm2);
        dm2.setSignAlgorithm(null);
        assertNotEquals(dm, dm2);
        dm2.setSignAlgorithm("ec");
        assertEquals(dm, dm2);

        dm2.setMemberExpiryDays(45);
        assertNotEquals(dm, dm2);
        dm2.setMemberExpiryDays(null);
        assertNotEquals(dm, dm2);
        dm2.setMemberExpiryDays(30);
        assertEquals(dm, dm2);

        dm2.setMemberPurgeExpiryDays(45);
        assertNotEquals(dm, dm2);
        dm2.setMemberPurgeExpiryDays(null);
        assertNotEquals(dm, dm2);
        dm2.setMemberPurgeExpiryDays(10);
        assertEquals(dm, dm2);

        dm2.setServiceExpiryDays(45);
        assertNotEquals(dm, dm2);
        dm2.setServiceExpiryDays(null);
        assertNotEquals(dm, dm2);
        dm2.setServiceExpiryDays(40);
        assertEquals(dm, dm2);

        dm2.setGroupExpiryDays(55);
        assertNotEquals(dm, dm2);
        dm2.setGroupExpiryDays(null);
        assertNotEquals(dm, dm2);
        dm2.setGroupExpiryDays(50);
        assertEquals(dm, dm2);

        dm2.setTokenExpiryMins(450);
        assertNotEquals(dm, dm2);
        dm2.setTokenExpiryMins(null);
        assertNotEquals(dm, dm2);
        dm2.setTokenExpiryMins(300);
        assertEquals(dm, dm2);

        dm2.setServiceCertExpiryMins(130);
        assertNotEquals(dm, dm2);
        dm2.setServiceCertExpiryMins(null);
        assertNotEquals(dm, dm2);
        dm2.setServiceCertExpiryMins(120);
        assertEquals(dm, dm2);

        dm2.setRoleCertExpiryMins(450);
        assertNotEquals(dm, dm2);
        dm2.setRoleCertExpiryMins(null);
        assertNotEquals(dm, dm2);
        dm2.setRoleCertExpiryMins(150);
        assertEquals(dm, dm2);

        dm2.setFeatureFlags(7);
        assertNotEquals(dm, dm2);
        dm2.setFeatureFlags(null);
        assertNotEquals(dm, dm2);
        dm2.setFeatureFlags(3);
        assertEquals(dm, dm2);

        dm2.setBusinessService("business-service2");
        assertNotEquals(dm, dm2);
        dm2.setBusinessService(null);
        assertNotEquals(dm, dm2);
        dm2.setBusinessService("business-service");
        assertEquals(dm, dm2);

        dm2.setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF2"));
        assertNotEquals(dm, dm2);
        dm2.setResourceOwnership(null);
        assertNotEquals(dm, dm2);
        dm2.setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF"));
        assertEquals(dm, dm2);

        dm2.setCertDnsDomain(null);
        assertNotEquals(dm, dm2);
        dm2.setApplicationId(null);
        assertNotEquals(dm, dm2);
        dm2.setYpmId(null);
        assertNotEquals(dm, dm2);
        dm2.setAccount(null);
        assertNotEquals(dm, dm2);
        dm2.setAuditEnabled(null);
        assertNotEquals(dm, dm2);
        dm2.setEnabled(null);
        assertNotEquals(dm, dm2);
        dm2.setOrg(null);
        assertNotEquals(dm, dm2);
        dm2.setDescription(null);
        assertNotEquals(dm, dm2);
        assertNotEquals(dm2, null);
        assertNotEquals(schema, dm);

        // init will not reset false state

        dm2.setEnabled(false);
        dm2.setAuditEnabled(false);
        dm2.init();
        assertFalse(dm2.getAuditEnabled());
        assertFalse(dm2.getEnabled());
    }

    @Test
    public void testTopLevelDomainMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> admins = List.of("test.admin1");

        // DomainTemplateList test
        List<String> templateNames = List.of("test");
        DomainTemplateList dtl = new DomainTemplateList().setTemplateNames(templateNames);

        Validator.Result result = validator.validate(dtl, "DomainTemplateList");
        assertTrue(result.valid);

        assertEquals(dtl.getTemplateNames(), templateNames);
        assertEquals(dtl, dtl);
        assertNotEquals(new DomainTemplateList(), dtl);

        // TopLevelDomain test
        TopLevelDomain tld = new TopLevelDomain().setDescription("domain desc").setOrg("org:test").setEnabled(true)
                .setAuditEnabled(false).setAccount("aws").setYpmId(10).setName("testdomain").setAdminUsers(admins)
                .setTemplates(dtl).setApplicationId("id1").setCertDnsDomain("athenz.cloud").setMemberExpiryDays(30)
                .setTokenExpiryMins(300).setRoleCertExpiryMins(120).setServiceCertExpiryMins(150).setSignAlgorithm("rsa")
                .setServiceExpiryDays(40).setUserAuthorityFilter("OnShore").setGroupExpiryDays(50).setAzureSubscription("azure")
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setBusinessService("business-service").setMemberPurgeExpiryDays(10).setGcpProject("gcp")
                .setGcpProjectNumber("1242").setProductId("abcd-1234").setFeatureFlags(3)
                .setContacts(Map.of("pe-owner", "user.test")).setEnvironment("production")
                .setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF"));

        result = validator.validate(tld, "TopLevelDomain");
        assertTrue(result.valid);

        assertEquals(tld.getDescription(), "domain desc");
        assertEquals(tld.getOrg(), "org:test");
        assertTrue(tld.getEnabled());
        assertFalse(tld.getAuditEnabled());
        assertEquals(tld.getAccount(), "aws");
        assertEquals(tld.getAzureSubscription(), "azure");
        assertEquals(tld.getGcpProject(), "gcp");
        assertEquals(tld.getGcpProjectNumber(), "1242");
        assertEquals((int) tld.getYpmId(), 10);
        assertEquals(tld.getName(), "testdomain");
        assertEquals(tld.getAdminUsers(), admins);
        assertEquals(tld.getApplicationId(), "id1");
        assertNotNull(tld.getTemplates());
        assertEquals(tld.getCertDnsDomain(), "athenz.cloud");
        assertEquals(tld.getMemberExpiryDays(), Integer.valueOf(30));
        assertEquals(tld.getServiceExpiryDays(), Integer.valueOf(40));
        assertEquals(tld.getGroupExpiryDays(), Integer.valueOf(50));
        assertEquals(tld.getTokenExpiryMins(), Integer.valueOf(300));
        assertEquals(tld.getServiceCertExpiryMins(), Integer.valueOf(150));
        assertEquals(tld.getRoleCertExpiryMins(), Integer.valueOf(120));
        assertEquals(tld.getSignAlgorithm(), "rsa");
        assertEquals(tld.getUserAuthorityFilter(), "OnShore");
        assertEquals(tld.getTags(),
                Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertEquals(tld.getBusinessService(), "business-service");
        assertEquals(tld.getMemberPurgeExpiryDays(), 10);
        assertEquals(tld.getProductId(), "abcd-1234");
        assertEquals(tld.getFeatureFlags(), 3);
        assertEquals(tld.getContacts(), Map.of("pe-owner", "user.test"));
        assertEquals(tld.getEnvironment(), "production");
        assertEquals(tld.getResourceOwnership(), new ResourceDomainOwnership().setMetaOwner("TF"));

        TopLevelDomain tld2 = new TopLevelDomain().setDescription("domain desc").setOrg("org:test").setEnabled(true)
                .setAuditEnabled(false).setAccount("aws").setYpmId(10).setName("testdomain").setAdminUsers(admins)
                .setTemplates(dtl).setApplicationId("id1").setCertDnsDomain("athenz.cloud").setMemberExpiryDays(30)
                .setTokenExpiryMins(300).setRoleCertExpiryMins(120).setServiceCertExpiryMins(150).setSignAlgorithm("rsa")
                .setServiceExpiryDays(40).setUserAuthorityFilter("OnShore").setGroupExpiryDays(50).setAzureSubscription("azure")
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setBusinessService("business-service").setMemberPurgeExpiryDays(10).setGcpProject("gcp")
                .setGcpProjectNumber("1242").setProductId("abcd-1234").setFeatureFlags(3)
                .setContacts(Map.of("pe-owner", "user.test")).setEnvironment("production")
                .setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF"));

        assertEquals(tld, tld2);
        assertEquals(tld, tld);

        tld2.setEnvironment("staging");
        assertNotEquals(tld, tld2);
        tld2.setEnvironment(null);
        assertNotEquals(tld, tld2);
        tld2.setEnvironment("production");
        assertEquals(tld, tld2);

        tld2.setContacts(Map.of("product-owner", "user.test"));
        assertNotEquals(tld, tld2);
        tld2.setContacts(null);
        assertNotEquals(tld, tld2);
        tld2.setContacts(Map.of("pe-owner", "user.test"));
        assertEquals(tld, tld2);

        tld2.setUserAuthorityFilter("NotOnShore");
        assertNotEquals(tld, tld2);
        tld2.setUserAuthorityFilter(null);
        assertNotEquals(tld, tld2);
        tld2.setUserAuthorityFilter("OnShore");
        assertEquals(tld, tld2);

        tld2.setAccount("aws2");
        assertNotEquals(tld, tld2);
        tld2.setAccount(null);
        assertNotEquals(tld, tld2);
        tld2.setAccount("aws");
        assertEquals(tld, tld2);

        tld2.setProductId("abcd-1235");
        assertNotEquals(tld, tld2);
        tld2.setProductId(null);
        assertNotEquals(tld, tld2);
        tld2.setProductId("abcd-1234");
        assertEquals(tld, tld2);

        tld2.setAzureSubscription("azure2");
        assertNotEquals(tld, tld2);
        tld2.setAzureSubscription(null);
        assertNotEquals(tld, tld2);
        tld2.setAzureSubscription("azure");
        assertEquals(tld, tld2);

        tld2.setGcpProject("gcp2");
        assertNotEquals(tld, tld2);
        tld2.setGcpProject(null);
        assertNotEquals(tld, tld2);
        tld2.setGcpProject("gcp");
        assertEquals(tld, tld2);

        tld2.setGcpProjectNumber("12421");
        assertNotEquals(tld, tld2);
        tld2.setGcpProjectNumber(null);
        assertNotEquals(tld, tld2);
        tld2.setGcpProjectNumber("1242");
        assertEquals(tld, tld2);

        tld2.setTags(Collections.singletonMap("tagKeyOther", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertNotEquals(tld, tld2);
        tld2.setTags(null);
        assertNotEquals(tld, tld2);
        tld2.setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertEquals(tld, tld2);

        tld2.setSignAlgorithm("ec");
        assertNotEquals(tld, tld2);
        tld2.setSignAlgorithm(null);
        assertNotEquals(tld, tld2);
        tld2.setSignAlgorithm("rsa");
        assertEquals(tld, tld2);

        tld2.setMemberExpiryDays(45);
        assertNotEquals(tld, tld2);
        tld2.setMemberExpiryDays(null);
        assertNotEquals(tld, tld2);
        tld2.setMemberExpiryDays(30);
        assertEquals(tld, tld2);

        tld2.setMemberPurgeExpiryDays(45);
        assertNotEquals(tld, tld2);
        tld2.setMemberPurgeExpiryDays(null);
        assertNotEquals(tld, tld2);
        tld2.setMemberPurgeExpiryDays(10);
        assertEquals(tld, tld2);

        tld2.setServiceExpiryDays(45);
        assertNotEquals(tld, tld2);
        tld2.setServiceExpiryDays(null);
        assertNotEquals(tld, tld2);
        tld2.setServiceExpiryDays(40);
        assertEquals(tld, tld2);

        tld2.setGroupExpiryDays(55);
        assertNotEquals(tld, tld2);
        tld2.setGroupExpiryDays(null);
        assertNotEquals(tld, tld2);
        tld2.setGroupExpiryDays(50);
        assertEquals(tld, tld2);

        tld2.setRoleCertExpiryMins(450);
        assertNotEquals(tld, tld2);
        tld2.setRoleCertExpiryMins(null);
        assertNotEquals(tld, tld2);
        tld2.setRoleCertExpiryMins(120);
        assertEquals(tld, tld2);

        tld2.setServiceCertExpiryMins(450);
        assertNotEquals(tld, tld2);
        tld2.setServiceCertExpiryMins(null);
        assertNotEquals(tld, tld2);
        tld2.setServiceCertExpiryMins(150);
        assertEquals(tld, tld2);

        tld2.setTokenExpiryMins(450);
        assertNotEquals(tld, tld2);
        tld2.setTokenExpiryMins(null);
        assertNotEquals(tld, tld2);
        tld2.setTokenExpiryMins(300);
        assertEquals(tld, tld2);

        tld2.setFeatureFlags(7);
        assertNotEquals(tld, tld2);
        tld2.setFeatureFlags(null);
        assertNotEquals(tld, tld2);
        tld2.setFeatureFlags(3);
        assertEquals(tld, tld2);

        tld2.setBusinessService("business-service2");
        assertNotEquals(tld, tld2);
        tld2.setBusinessService(null);
        assertNotEquals(tld, tld2);
        tld2.setBusinessService("business-service");
        assertEquals(tld, tld2);

        tld2.setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF2"));
        assertNotEquals(tld, tld2);
        tld2.setResourceOwnership(null);
        assertNotEquals(tld, tld2);
        tld2.setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF"));
        assertEquals(tld, tld2);

        tld2.setTemplates(null);
        assertNotEquals(tld, tld2);
        tld2.setAdminUsers(null);
        assertNotEquals(tld, tld2);
        tld2.setName(null);
        assertNotEquals(tld, tld2);
        tld2.setCertDnsDomain(null);
        assertNotEquals(tld, tld2);
        tld2.setApplicationId(null);
        assertNotEquals(tld, tld2);
        tld2.setYpmId(null);
        assertNotEquals(tld, tld2);
        tld2.setAccount(null);
        assertNotEquals(tld, tld2);
        tld2.setAuditEnabled(null);
        assertNotEquals(tld, tld2);
        tld2.setEnabled(null);
        assertNotEquals(tld, tld2);
        tld2.setOrg(null);
        assertNotEquals(tld, tld2);
        tld2.setDescription(null);
        assertNotEquals(tld, tld2);
        assertNotEquals(tld2, null);
        assertNotEquals(schema, tld);
    }

    @Test
    public void testSubDomainMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> admins = List.of("test.admin1");

        SubDomain sd = new SubDomain().setDescription("domain desc").setOrg("org:test").setEnabled(true)
                .setAuditEnabled(false).setAccount("aws").setYpmId(10).setName("testdomain").setAdminUsers(admins)
                .setTemplates(new DomainTemplateList().setTemplateNames(List.of("vipng")))
                .setParent("domain.parent").setApplicationId("101").setCertDnsDomain("athenz.cloud")
                .setMemberExpiryDays(30).setTokenExpiryMins(300).setServiceCertExpiryMins(120)
                .setRoleCertExpiryMins(150).setSignAlgorithm("rsa").setServiceExpiryDays(40)
                .setUserAuthorityFilter("OnShore").setGroupExpiryDays(50).setAzureSubscription("azure")
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setBusinessService("business-service").setMemberPurgeExpiryDays(10).setGcpProject("gcp")
                .setGcpProjectNumber("1244").setProductId("abcd-1234").setFeatureFlags(3)
                .setContacts(Map.of("pe-owner", "user.test")).setEnvironment("production")
                .setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF"));

        Validator.Result result = validator.validate(sd, "SubDomain");
        assertTrue(result.valid, result.error);

        assertEquals(sd.getDescription(), "domain desc");
        assertEquals(sd.getOrg(), "org:test");
        assertTrue(sd.getEnabled());
        assertFalse(sd.getAuditEnabled());
        assertEquals(sd.getAccount(), "aws");
        assertEquals(sd.getAzureSubscription(), "azure");
        assertEquals(sd.getGcpProject(), "gcp");
        assertEquals(sd.getGcpProjectNumber(), "1244");
        assertEquals((int) sd.getYpmId(), 10);
        assertEquals(sd.getName(), "testdomain");
        assertEquals(sd.getAdminUsers(), admins);
        assertNotNull(sd.getTemplates());
        assertEquals(sd.getParent(), "domain.parent");
        assertEquals(sd.getApplicationId(), "101");
        assertEquals(sd.getCertDnsDomain(), "athenz.cloud");
        assertEquals(sd.getMemberExpiryDays(), Integer.valueOf(30));
        assertEquals(sd.getServiceExpiryDays(), Integer.valueOf(40));
        assertEquals(sd.getGroupExpiryDays(), Integer.valueOf(50));
        assertEquals(sd.getTokenExpiryMins(), Integer.valueOf(300));
        assertEquals(sd.getRoleCertExpiryMins(), Integer.valueOf(150));
        assertEquals(sd.getServiceCertExpiryMins(), Integer.valueOf(120));
        assertEquals(sd.getSignAlgorithm(), "rsa");
        assertEquals(sd.getUserAuthorityFilter(), "OnShore");
        assertEquals(sd.getTags(),
                Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertEquals(sd.getBusinessService(), "business-service");
        assertEquals(sd.getMemberPurgeExpiryDays(), 10);
        assertEquals(sd.getProductId(), "abcd-1234");
        assertEquals(sd.getFeatureFlags(), 3);
        assertEquals(sd.getContacts(), Map.of("pe-owner", "user.test"));
        assertEquals(sd.getEnvironment(), "production");
        assertEquals(sd.getResourceOwnership(), new ResourceDomainOwnership().setMetaOwner("TF"));

        SubDomain sd2 = new SubDomain().setDescription("domain desc").setOrg("org:test").setEnabled(true)
                .setAuditEnabled(false).setAccount("aws").setYpmId(10).setName("testdomain").setAdminUsers(admins)
                .setTemplates(new DomainTemplateList().setTemplateNames(List.of("vipng")))
                .setParent("domain.parent").setApplicationId("101").setCertDnsDomain("athenz.cloud")
                .setMemberExpiryDays(30).setTokenExpiryMins(300).setServiceCertExpiryMins(120)
                .setRoleCertExpiryMins(150).setSignAlgorithm("rsa").setServiceExpiryDays(40)
                .setUserAuthorityFilter("OnShore").setGroupExpiryDays(50).setAzureSubscription("azure")
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setBusinessService("business-service").setMemberPurgeExpiryDays(10).setGcpProject("gcp")
                .setGcpProjectNumber("1244").setProductId("abcd-1234").setFeatureFlags(3)
                .setContacts(Map.of("pe-owner", "user.test")).setEnvironment("production")
                .setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF"));

        assertEquals(sd, sd2);
        assertEquals(sd, sd);
        assertNotEquals(schema, sd);

        sd2.setEnvironment("staging");
        assertNotEquals(sd, sd2);
        sd2.setEnvironment(null);
        assertNotEquals(sd, sd2);
        sd2.setEnvironment("production");
        assertEquals(sd, sd2);

        sd2.setContacts(Map.of("product-owner", "user.test"));
        assertNotEquals(sd, sd2);
        sd2.setContacts(null);
        assertNotEquals(sd, sd2);
        sd2.setContacts(Map.of("pe-owner", "user.test"));
        assertEquals(sd, sd2);

        sd2.setUserAuthorityFilter("NotOnShore");
        assertNotEquals(sd, sd2);
        sd2.setUserAuthorityFilter(null);
        assertNotEquals(sd, sd2);
        sd2.setUserAuthorityFilter("OnShore");
        assertEquals(sd, sd2);

        sd2.setProductId("abcd-1235");
        assertNotEquals(sd, sd2);
        sd2.setProductId(null);
        assertNotEquals(sd, sd2);
        sd2.setProductId("abcd-1234");
        assertEquals(sd, sd2);

        sd2.setAccount("aws2");
        assertNotEquals(sd, sd2);
        sd2.setAccount(null);
        assertNotEquals(sd, sd2);
        sd2.setAccount("aws");
        assertEquals(sd, sd2);

        sd2.setAzureSubscription("azure2");
        assertNotEquals(sd, sd2);
        sd2.setAzureSubscription(null);
        assertNotEquals(sd, sd2);
        sd2.setAzureSubscription("azure");
        assertEquals(sd, sd2);

        sd2.setGcpProject("gcp2");
        assertNotEquals(sd, sd2);
        sd2.setGcpProject(null);
        assertNotEquals(sd, sd2);
        sd2.setGcpProject("gcp");
        assertEquals(sd, sd2);

        sd2.setGcpProjectNumber("12441");
        assertNotEquals(sd, sd2);
        sd2.setGcpProjectNumber(null);
        assertNotEquals(sd, sd2);
        sd2.setGcpProjectNumber("1244");
        assertEquals(sd, sd2);

        sd2.setTags(Collections.singletonMap("tagKeyOther", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertNotEquals(sd, sd2);
        sd2.setTags(null);
        assertNotEquals(sd, sd2);
        sd2.setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertEquals(sd, sd2);

        sd2.setSignAlgorithm("ec");
        assertNotEquals(sd, sd2);
        sd2.setSignAlgorithm(null);
        assertNotEquals(sd, sd2);
        sd2.setSignAlgorithm("rsa");
        assertEquals(sd, sd2);

        sd2.setMemberExpiryDays(45);
        assertNotEquals(sd, sd2);
        sd2.setMemberExpiryDays(null);
        assertNotEquals(sd, sd2);
        sd2.setMemberExpiryDays(30);
        assertEquals(sd, sd2);

        sd2.setMemberPurgeExpiryDays(45);
        assertNotEquals(sd, sd2);
        sd2.setMemberPurgeExpiryDays(null);
        assertNotEquals(sd, sd2);
        sd2.setMemberPurgeExpiryDays(10);
        assertEquals(sd, sd2);

        sd2.setServiceExpiryDays(45);
        assertNotEquals(sd, sd2);
        sd2.setServiceExpiryDays(null);
        assertNotEquals(sd, sd2);
        sd2.setServiceExpiryDays(40);
        assertEquals(sd, sd2);

        sd2.setGroupExpiryDays(55);
        assertNotEquals(sd, sd2);
        sd2.setGroupExpiryDays(null);
        assertNotEquals(sd, sd2);
        sd2.setGroupExpiryDays(50);
        assertEquals(sd, sd2);

        sd2.setTokenExpiryMins(450);
        assertNotEquals(sd, sd2);
        sd2.setTokenExpiryMins(null);
        assertNotEquals(sd, sd2);
        sd2.setTokenExpiryMins(300);
        assertEquals(sd, sd2);

        sd2.setServiceCertExpiryMins(450);
        assertNotEquals(sd, sd2);
        sd2.setServiceCertExpiryMins(null);
        assertNotEquals(sd, sd2);
        sd2.setServiceCertExpiryMins(120);
        assertEquals(sd, sd2);

        sd2.setRoleCertExpiryMins(450);
        assertNotEquals(sd, sd2);
        sd2.setRoleCertExpiryMins(null);
        assertNotEquals(sd, sd2);
        sd2.setRoleCertExpiryMins(150);
        assertEquals(sd, sd2);

        sd2.setFeatureFlags(7);
        assertNotEquals(sd, sd2);
        sd2.setFeatureFlags(null);
        assertNotEquals(sd, sd2);
        sd2.setFeatureFlags(3);
        assertEquals(sd, sd2);

        sd2.setBusinessService("business-service2");
        assertNotEquals(sd, sd2);
        sd2.setBusinessService(null);
        assertNotEquals(sd, sd2);
        sd2.setBusinessService("business-service");
        assertEquals(sd, sd2);

        sd2.setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF2"));
        assertNotEquals(sd, sd2);
        sd2.setResourceOwnership(null);
        assertNotEquals(sd, sd2);
        sd2.setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF"));
        assertEquals(sd, sd2);

        sd2.setParent(null);
        assertNotEquals(sd, sd2);
        sd2.setTemplates(null);
        assertNotEquals(sd, sd2);
        sd2.setAdminUsers(null);
        assertNotEquals(sd, sd2);
        sd2.setName(null);
        assertNotEquals(sd, sd2);
        sd2.setCertDnsDomain(null);
        assertNotEquals(sd, sd2);
        sd2.setApplicationId(null);
        assertNotEquals(sd, sd2);
        sd2.setYpmId(null);
        assertNotEquals(sd, sd2);
        sd2.setAccount(null);
        assertNotEquals(sd, sd2);
        sd2.setAuditEnabled(null);
        assertNotEquals(sd, sd2);
        sd2.setEnabled(null);
        assertNotEquals(sd, sd2);
        sd2.setOrg(null);
        assertNotEquals(sd, sd2);
        sd2.setDescription(null);
        assertNotEquals(sd, sd2);
        assertNotEquals(sd2, null);
    }

    @Test
    public void testUserDomainMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        UserDomain ud = new UserDomain().setDescription("domain desc").setOrg("org:test").setEnabled(true)
                .setAuditEnabled(false).setAccount("aws").setYpmId(10).setName("testuser")
                .setTemplates(new DomainTemplateList().setTemplateNames(List.of("template")))
                .setApplicationId("101").setCertDnsDomain("athenz.cloud").setMemberExpiryDays(30)
                .setTokenExpiryMins(300).setServiceCertExpiryMins(120).setRoleCertExpiryMins(150)
                .setSignAlgorithm("rsa").setServiceExpiryDays(40).setUserAuthorityFilter("OnShore")
                .setGroupExpiryDays(50).setAzureSubscription("azure").setBusinessService("business-service")
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setMemberPurgeExpiryDays(10).setGcpProject("gcp").setGcpProjectNumber("1246")
                .setProductId("abcd-1234").setFeatureFlags(3).setContacts(Map.of("pe-owner", "user.test"))
                .setEnvironment("production").setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF"));

        Validator.Result result = validator.validate(ud, "UserDomain");
        assertTrue(result.valid);

        assertEquals(ud.getDescription(), "domain desc");
        assertEquals(ud.getOrg(), "org:test");
        assertTrue(ud.getEnabled());
        assertFalse(ud.getAuditEnabled());
        assertEquals(ud.getAccount(), "aws");
        assertEquals(ud.getAzureSubscription(), "azure");
        assertEquals(ud.getGcpProject(), "gcp");
        assertEquals(ud.getGcpProjectNumber(), "1246");
        assertEquals((int) ud.getYpmId(), 10);
        assertEquals(ud.getName(), "testuser");
        assertEquals(ud.getApplicationId(), "101");
        assertNotNull(ud.getTemplates());
        assertEquals(ud.getCertDnsDomain(), "athenz.cloud");
        assertEquals(ud.getMemberExpiryDays(), Integer.valueOf(30));
        assertEquals(ud.getServiceExpiryDays(), Integer.valueOf(40));
        assertEquals(ud.getGroupExpiryDays(), Integer.valueOf(50));
        assertEquals(ud.getTokenExpiryMins(), Integer.valueOf(300));
        assertEquals(ud.getRoleCertExpiryMins(), Integer.valueOf(150));
        assertEquals(ud.getServiceCertExpiryMins(), Integer.valueOf(120));
        assertEquals(ud.getSignAlgorithm(), "rsa");
        assertEquals(ud.getUserAuthorityFilter(), "OnShore");
        assertEquals(ud.getTags(),
                Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertEquals(ud.getBusinessService(), "business-service");
        assertEquals(ud.getMemberPurgeExpiryDays(), 10);
        assertEquals(ud.getProductId(), "abcd-1234");
        assertEquals(ud.getFeatureFlags(), 3);
        assertEquals(ud.getContacts(), Map.of("pe-owner", "user.test"));
        assertEquals(ud.getEnvironment(), "production");
        assertEquals(ud.getResourceOwnership(), new ResourceDomainOwnership().setMetaOwner("TF"));

        UserDomain ud2 = new UserDomain().setDescription("domain desc").setOrg("org:test").setEnabled(true)
                .setAuditEnabled(false).setAccount("aws").setYpmId(10).setName("testuser")
                .setTemplates(new DomainTemplateList().setTemplateNames(List.of("template")))
                .setApplicationId("101").setCertDnsDomain("athenz.cloud").setMemberExpiryDays(30)
                .setTokenExpiryMins(300).setServiceCertExpiryMins(120).setRoleCertExpiryMins(150)
                .setSignAlgorithm("rsa").setServiceExpiryDays(40).setUserAuthorityFilter("OnShore")
                .setGroupExpiryDays(50).setAzureSubscription("azure").setBusinessService("business-service")
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setMemberPurgeExpiryDays(10).setGcpProject("gcp").setGcpProjectNumber("1246")
                .setProductId("abcd-1234").setFeatureFlags(3).setContacts(Map.of("pe-owner", "user.test"))
                .setEnvironment("production").setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF"));

        assertEquals(ud, ud2);
        assertEquals(ud, ud);

        ud2.setEnvironment("staging");
        assertNotEquals(ud, ud2);
        ud2.setEnvironment(null);
        assertNotEquals(ud, ud2);
        ud2.setEnvironment("production");
        assertEquals(ud, ud2);

        ud2.setContacts(Map.of("product-owner", "user.test"));
        assertNotEquals(ud, ud2);
        ud2.setContacts(null);
        assertNotEquals(ud, ud2);
        ud2.setContacts(Map.of("pe-owner", "user.test"));
        assertEquals(ud, ud2);

        ud2.setUserAuthorityFilter("NotOnShore");
        assertNotEquals(ud, ud2);
        ud2.setUserAuthorityFilter(null);
        assertNotEquals(ud, ud2);
        ud2.setUserAuthorityFilter("OnShore");
        assertEquals(ud, ud2);

        ud2.setAccount("aws2");
        assertNotEquals(ud, ud2);
        ud2.setAccount(null);
        assertNotEquals(ud, ud2);
        ud2.setAccount("aws");
        assertEquals(ud, ud2);

        ud2.setProductId("abcd-1235");
        assertNotEquals(ud, ud2);
        ud2.setProductId(null);
        assertNotEquals(ud, ud2);
        ud2.setProductId("abcd-1234");
        assertEquals(ud, ud2);

        ud2.setAzureSubscription("azure2");
        assertNotEquals(ud, ud2);
        ud2.setAzureSubscription(null);
        assertNotEquals(ud, ud2);
        ud2.setAzureSubscription("azure");
        assertEquals(ud, ud2);

        ud2.setGcpProject("gcp2");
        assertNotEquals(ud, ud2);
        ud2.setGcpProject(null);
        assertNotEquals(ud, ud2);
        ud2.setGcpProject("gcp");
        assertEquals(ud, ud2);

        ud2.setGcpProjectNumber("12461");
        assertNotEquals(ud, ud2);
        ud2.setGcpProjectNumber(null);
        assertNotEquals(ud, ud2);
        ud2.setGcpProjectNumber("1246");
        assertEquals(ud, ud2);

        ud2.setTags(Collections.singletonMap("tagKeyOther", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertNotEquals(ud, ud2);
        ud2.setTags(null);
        assertNotEquals(ud, ud2);
        ud2.setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertEquals(ud, ud2);

        ud2.setSignAlgorithm("ec");
        assertNotEquals(ud, ud2);
        ud2.setSignAlgorithm(null);
        assertNotEquals(ud, ud2);
        ud2.setSignAlgorithm("rsa");
        assertEquals(ud, ud2);

        ud2.setMemberExpiryDays(45);
        assertNotEquals(ud, ud2);
        ud2.setMemberExpiryDays(null);
        assertNotEquals(ud, ud2);
        ud2.setMemberExpiryDays(30);
        assertEquals(ud, ud2);

        ud2.setMemberPurgeExpiryDays(45);
        assertNotEquals(ud, ud2);
        ud2.setMemberPurgeExpiryDays(null);
        assertNotEquals(ud, ud2);
        ud2.setMemberPurgeExpiryDays(10);
        assertEquals(ud, ud2);

        ud2.setServiceExpiryDays(45);
        assertNotEquals(ud, ud2);
        ud2.setServiceExpiryDays(null);
        assertNotEquals(ud, ud2);
        ud2.setServiceExpiryDays(40);
        assertEquals(ud, ud2);

        ud2.setGroupExpiryDays(55);
        assertNotEquals(ud, ud2);
        ud2.setGroupExpiryDays(null);
        assertNotEquals(ud, ud2);
        ud2.setGroupExpiryDays(50);
        assertEquals(ud, ud2);

        ud2.setTokenExpiryMins(450);
        assertNotEquals(ud, ud2);
        ud2.setTokenExpiryMins(null);
        assertNotEquals(ud, ud2);
        ud2.setTokenExpiryMins(300);
        assertEquals(ud, ud2);

        ud2.setServiceCertExpiryMins(450);
        assertNotEquals(ud, ud2);
        ud2.setServiceCertExpiryMins(null);
        assertNotEquals(ud, ud2);
        ud2.setServiceCertExpiryMins(120);
        assertEquals(ud, ud2);

        ud2.setRoleCertExpiryMins(450);
        assertNotEquals(ud, ud2);
        ud2.setRoleCertExpiryMins(null);
        assertNotEquals(ud, ud2);
        ud2.setRoleCertExpiryMins(150);
        assertEquals(ud, ud2);

        ud2.setFeatureFlags(7);
        assertNotEquals(ud, ud2);
        ud2.setFeatureFlags(null);
        assertNotEquals(ud, ud2);
        ud2.setFeatureFlags(3);
        assertEquals(ud, ud2);

        ud2.setBusinessService("business-service2");
        assertNotEquals(ud, ud2);
        ud2.setBusinessService(null);
        assertNotEquals(ud, ud2);
        ud2.setBusinessService("business-service");
        assertEquals(ud, ud2);

        ud2.setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF2"));
        assertNotEquals(ud, ud2);
        ud2.setResourceOwnership(null);
        assertNotEquals(ud, ud2);
        ud2.setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF"));
        assertEquals(ud, ud2);

        ud2.setTemplates(null);
        assertNotEquals(ud, ud2);
        ud2.setName(null);
        assertNotEquals(ud, ud2);
        ud2.setCertDnsDomain(null);
        assertNotEquals(ud, ud2);
        ud2.setApplicationId(null);
        assertNotEquals(ud, ud2);
        ud2.setYpmId(null);
        assertNotEquals(ud, ud2);
        ud2.setAccount(null);
        assertNotEquals(ud, ud2);
        ud2.setAuditEnabled(null);
        assertNotEquals(ud, ud2);
        ud2.setEnabled(null);
        assertNotEquals(ud, ud2);
        ud2.setOrg(null);
        assertNotEquals(ud, ud2);
        ud2.setDescription(null);
        assertNotEquals(ud, ud2);
        assertNotEquals(ud2, null);
        assertNotEquals(schema, ud);
    }

    @Test
    public void testEmptyBusinessService() throws JsonProcessingException {
        DomainMeta domainMeta = new DomainMeta();

        // Set business service to "" (empty string). Will be part of Json.
        domainMeta.setAccount("testAccount");
        domainMeta.setBusinessService("");
        ObjectMapper om = new ObjectMapper();
        String jsonString = om.writeValueAsString(domainMeta);
        assertEquals("{\"account\":\"testAccount\",\"businessService\":\"\"}", jsonString);

        // Set business service with regular value. Will be part of Json.
        domainMeta.setBusinessService("Now with value");
        jsonString = om.writeValueAsString(domainMeta);
        assertEquals("{\"account\":\"testAccount\",\"businessService\":\"Now with value\"}", jsonString);

        // Set business service with null. Will NOT be part of Json.
        domainMeta.setBusinessService(null);
        jsonString = om.writeValueAsString(domainMeta);
        assertEquals("{\"account\":\"testAccount\"}", jsonString);
    }

    @Test
    public void testDomainMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        Domain d = new Domain();
        d.setName("test.domain").setModified(Timestamp.fromMillis(123456789123L)).setId(UUID.fromMillis(100))
                .setDescription("test desc").setOrg("test-org").setEnabled(true).setAuditEnabled(true)
                .setAccount("aws").setYpmId(1).setApplicationId("101").setCertDnsDomain("athenz.cloud")
                .setMemberExpiryDays(30).setTokenExpiryMins(300).setServiceCertExpiryMins(120)
                .setRoleCertExpiryMins(150).setSignAlgorithm("rsa").setServiceExpiryDays(40)
                .setUserAuthorityFilter("OnShore").setGroupExpiryDays(50).setAzureSubscription("azure")
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setBusinessService("business-service").setMemberPurgeExpiryDays(10).setGcpProject("gcp")
                .setGcpProjectNumber("1237").setProductId("abcd-1234").setFeatureFlags(3)
                .setContacts(Map.of("pe-owner", "user.test")).setEnvironment("production")
                .setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF"));

        Validator.Result result = validator.validate(d, "Domain");
        assertTrue(result.valid);

        assertEquals(d.getName(), "test.domain");
        assertEquals(d.getModified(), Timestamp.fromMillis(123456789123L));
        assertEquals(d.getId(), UUID.fromMillis(100));
        assertEquals(d.getDescription(), "test desc");
        assertEquals(d.getOrg(), "test-org");
        assertTrue(d.getEnabled());
        assertTrue(d.getAuditEnabled());
        assertEquals(d.getAccount(), "aws");
        assertEquals(d.getAzureSubscription(), "azure");
        assertEquals(d.getGcpProject(), "gcp");
        assertEquals(d.getGcpProjectNumber(), "1237");
        assertEquals((int) d.getYpmId(), 1);
        assertEquals(d.getApplicationId(), "101");
        assertEquals(d.getCertDnsDomain(), "athenz.cloud");
        assertEquals(d.getMemberExpiryDays(), Integer.valueOf(30));
        assertEquals(d.getServiceExpiryDays(), Integer.valueOf(40));
        assertEquals(d.getGroupExpiryDays(), Integer.valueOf(50));
        assertEquals(d.getTokenExpiryMins(), Integer.valueOf(300));
        assertEquals(d.getServiceCertExpiryMins(), Integer.valueOf(120));
        assertEquals(d.getRoleCertExpiryMins(), Integer.valueOf(150));
        assertEquals(d.getSignAlgorithm(), "rsa");
        assertEquals(d.getUserAuthorityFilter(), "OnShore");
        assertEquals(d.getTags(),
                Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertEquals(d.getBusinessService(), "business-service");
        assertEquals(d.getMemberPurgeExpiryDays(), 10);
        assertEquals(d.getProductId(), "abcd-1234");
        assertEquals(d.getFeatureFlags(), 3);
        assertEquals(d.getContacts(), Map.of("pe-owner", "user.test"));
        assertEquals(d.getEnvironment(), "production");
        assertEquals(d.getResourceOwnership(), new ResourceDomainOwnership().setMetaOwner("TF"));

        Domain d2 = new Domain();
        d2.setName("test.domain").setModified(Timestamp.fromMillis(123456789123L)).setId(UUID.fromMillis(100))
                .setDescription("test desc").setOrg("test-org").setEnabled(true).setAuditEnabled(true)
                .setAccount("aws").setYpmId(1).setApplicationId("101").setCertDnsDomain("athenz.cloud")
                .setMemberExpiryDays(30).setTokenExpiryMins(300).setServiceCertExpiryMins(120)
                .setRoleCertExpiryMins(150).setSignAlgorithm("rsa").setServiceExpiryDays(40)
                .setUserAuthorityFilter("OnShore").setGroupExpiryDays(50).setAzureSubscription("azure")
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setBusinessService("business-service").setMemberPurgeExpiryDays(10).setGcpProject("gcp")
                .setGcpProjectNumber("1237").setProductId("abcd-1234").setFeatureFlags(3)
                .setContacts(Map.of("pe-owner", "user.test")).setEnvironment("production")
                .setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF"));

        assertEquals(d, d2);
        assertEquals(d, d);

        d2.setEnvironment("staging");
        assertNotEquals(d, d2);
        d2.setEnvironment(null);
        assertNotEquals(d, d2);
        d2.setEnvironment("production");
        assertEquals(d, d2);

        d2.setContacts(Map.of("product-owner", "user.test"));
        assertNotEquals(d, d2);
        d2.setContacts(null);
        assertNotEquals(d, d2);
        d2.setContacts(Map.of("pe-owner", "user.test"));
        assertEquals(d, d2);

        d2.setUserAuthorityFilter("NotOnShore");
        assertNotEquals(d, d2);
        d2.setUserAuthorityFilter(null);
        assertNotEquals(d, d2);
        d2.setUserAuthorityFilter("OnShore");
        assertEquals(d, d2);

        d2.setProductId("abcd-1235");
        assertNotEquals(d, d2);
        d2.setProductId(null);
        assertNotEquals(d, d2);
        d2.setProductId("abcd-1234");
        assertEquals(d, d2);
        
        d2.setAccount("aws2");
        assertNotEquals(d, d2);
        d2.setAccount(null);
        assertNotEquals(d, d2);
        d2.setAccount("aws");
        assertEquals(d, d2);

        d2.setAzureSubscription("azure2");
        assertNotEquals(d, d2);
        d2.setAzureSubscription(null);
        assertNotEquals(d, d2);
        d2.setAzureSubscription("azure");
        assertEquals(d, d2);

        d2.setGcpProject("gcp2");
        assertNotEquals(d, d2);
        d2.setGcpProject(null);
        assertNotEquals(d, d2);
        d2.setGcpProject("gcp");
        assertEquals(d, d2);

        d2.setGcpProjectNumber("12378");
        assertNotEquals(d, d2);
        d2.setGcpProjectNumber(null);
        assertNotEquals(d, d2);
        d2.setGcpProjectNumber("1237");
        assertEquals(d, d2);

        d2.setTags(Collections.singletonMap("tagKeyOther", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertNotEquals(d, d2);
        d2.setTags(null);
        assertNotEquals(d, d2);
        d2.setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertEquals(d, d2);

        d2.setSignAlgorithm("ec");
        assertNotEquals(d, d2);
        d2.setSignAlgorithm(null);
        assertNotEquals(d, d2);
        d2.setSignAlgorithm("rsa");
        assertEquals(d, d2);

        d2.setMemberExpiryDays(45);
        assertNotEquals(d, d2);
        d2.setMemberExpiryDays(null);
        assertNotEquals(d, d2);
        d2.setMemberExpiryDays(30);
        assertEquals(d, d2);

        d2.setMemberPurgeExpiryDays(45);
        assertNotEquals(d, d2);
        d2.setMemberPurgeExpiryDays(null);
        assertNotEquals(d, d2);
        d2.setMemberPurgeExpiryDays(10);
        assertEquals(d, d2);

        d2.setServiceExpiryDays(45);
        assertNotEquals(d, d2);
        d2.setServiceExpiryDays(null);
        assertNotEquals(d, d2);
        d2.setServiceExpiryDays(40);
        assertEquals(d, d2);

        d2.setGroupExpiryDays(55);
        assertNotEquals(d, d2);
        d2.setGroupExpiryDays(null);
        assertNotEquals(d, d2);
        d2.setGroupExpiryDays(50);
        assertEquals(d, d2);

        d2.setTokenExpiryMins(450);
        assertNotEquals(d, d2);
        d2.setTokenExpiryMins(null);
        assertNotEquals(d, d2);
        d2.setTokenExpiryMins(300);
        assertEquals(d, d2);

        d2.setServiceCertExpiryMins(130);
        assertNotEquals(d, d2);
        d2.setServiceCertExpiryMins(null);
        assertNotEquals(d, d2);
        d2.setServiceCertExpiryMins(120);
        assertEquals(d, d2);

        d2.setRoleCertExpiryMins(450);
        assertNotEquals(d, d2);
        d2.setRoleCertExpiryMins(null);
        assertNotEquals(d, d2);
        d2.setRoleCertExpiryMins(150);
        assertEquals(d, d2);

        d2.setFeatureFlags(7);
        assertNotEquals(d, d2);
        d2.setFeatureFlags(null);
        assertNotEquals(d, d2);
        d2.setFeatureFlags(3);
        assertEquals(d, d2);

        d2.setBusinessService("business-service2");
        assertNotEquals(d, d2);
        d2.setBusinessService(null);
        assertNotEquals(d, d2);
        d2.setBusinessService("business-service");
        assertEquals(d, d2);

        d2.setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF2"));
        assertNotEquals(d, d2);
        d2.setResourceOwnership(null);
        assertNotEquals(d, d2);
        d2.setResourceOwnership(new ResourceDomainOwnership().setMetaOwner("TF"));
        assertEquals(d, d2);

        d2.setId(UUID.fromMillis(101));
        assertNotEquals(d, d2);
        d2.setId(null);
        assertNotEquals(d, d2);
        d2.setModified(null);
        assertNotEquals(d, d2);
        d2.setName(null);
        assertNotEquals(d, d2);
        d2.setCertDnsDomain(null);
        assertNotEquals(d, d2);
        d2.setApplicationId(null);
        assertNotEquals(d, d2);
        d2.setYpmId(null);
        assertNotEquals(d, d2);
        d2.setAccount(null);
        assertNotEquals(d, d2);
        d2.setAuditEnabled(null);
        assertNotEquals(d, d2);
        d2.setEnabled(null);
        assertNotEquals(d, d2);
        d2.setOrg(null);
        assertNotEquals(d, d2);
        d2.setDescription(null);
        assertNotEquals(d, d2);
        assertNotEquals(d2, null);
        assertNotEquals(schema, d);
    }

    @Test
    public void testDomainList() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> domainnames = List.of("test.domain");

        DomainList dl = new DomainList().setNames(domainnames).setNext("next");

        Validator.Result result = validator.validate(dl, "DomainList");
        assertTrue(result.valid);

        assertEquals(dl.getNames(), domainnames);
        assertEquals(dl.getNext(), "next");

        DomainList dl2 = new DomainList().setNames(domainnames).setNext("next");
        assertEquals(dl, dl2);
        assertEquals(dl, dl);

        dl2.setNext(null);
        assertNotEquals(dl, dl2);
        dl2.setNames(null);
        assertNotEquals(dl, dl2);
        assertNotEquals(dl2, null);
        assertNotEquals(schema, dl);
    }
}
