/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.zms;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.zms.store.AthenzDomain;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import jakarta.ws.rs.core.Response;
import org.testng.Assert;
import org.testng.annotations.*;

import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;

import static org.testng.Assert.*;

public class ZMSTagTest {
    
    private final ZMSTestInitializer zmsTestInitializer = new ZMSTestInitializer();
    private  ZMSImpl zmsImpl;
    private  RsrcCtxWrapper ctx;
    private final String domainName = "sys.auth";

    @BeforeClass
    public void startMemoryMySQL() {
        zmsTestInitializer.startMemoryMySQL();
    }

    @AfterClass
    public void stopMemoryMySQL() {
        zmsTestInitializer.stopMemoryMySQL();
    }

    @BeforeMethod
    public void setUp() throws Exception {
        zmsTestInitializer.setUp();
        zmsImpl = zmsTestInitializer.getZms();
        ctx = zmsTestInitializer.getMockDomRsrcCtx();
        Role role = zmsTestInitializer.createRoleObject(domainName, "role1", null);
        zmsImpl.putRole(ctx, domainName, "role1", zmsTestInitializer.getAuditRef(), false, null, role);
        deleteAllCreatedPolicies();
    }

    @AfterMethod
    public void clearConnections() {
        zmsTestInitializer.clearConnections();
        deleteAllCreatedPolicies();
    }

    void deleteAllCreatedPolicies() {
        Policies policyList = zmsImpl.getPolicies(ctx, domainName, false, null, null, null);
        for (Policy policy : policyList.getList()) {
            String policyName = policy.getName().replace(domainName + ":policy.", "");
            if (!policyName.contains("admin")) {
                zmsImpl.deletePolicy(ctx, domainName, policyName, "", null);
            }
        }
    }

    @Test
    public void testQueryPutPolicyWithTags() {

        final String auditRef = zmsTestInitializer.getAuditRef();

        // put policy with multiple tags
        final String policyWithTags = "policyWithTags";
        final String tagKey = "tag-key";
        List<String> tagValues = Arrays.asList("val1", "val2");
        Policy policy = zmsTestInitializer.createPolicyObject(domainName, policyWithTags,
                domainName + ":role.role1", false, "root",
                "serivce:service1", AssertionEffect.ALLOW);
        policy.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(tagValues)));
        zmsImpl.putPolicy(ctx, domainName, policyWithTags, auditRef, false, null, policy);

        // put policy with single tags
        final String policiesingleTag = "policiesingleTag";
        List<String> singleTagValue = Collections.singletonList("val1");
        policy = zmsTestInitializer.createPolicyObject(domainName, policiesingleTag,
                domainName + ":role.role1", false, "root",
                "service:service1", AssertionEffect.ALLOW);
        policy.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(singleTagValue)));
        zmsImpl.putPolicy(ctx, domainName, policiesingleTag, auditRef, false, null, policy);

        //put policy without tags
        final String noTagsPolicy = "noTagsPolicy";
        policy = zmsTestInitializer.createPolicyObject(domainName, noTagsPolicy,
                domainName + ":role.role1", false, "root",
                "service:service1", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, domainName, noTagsPolicy, auditRef, false, null, policy);

        // get policies without tags query - both tags should be presented
        Policies policyList = zmsImpl.getPolicies(ctx, domainName, Boolean.FALSE, null,null, null);
        hasPolicyWithTags(policyList, policyWithTags, domainName, tagKey, tagValues, 2);
        hasPolicyWithTags(policyList, policiesingleTag, domainName, tagKey, singleTagValue, 1);
        hasPolicyWithTags(policyList, noTagsPolicy, domainName, null, null,0);

        // get policies with exact tag value
        policyList = zmsImpl.getPolicies(ctx, domainName, Boolean.TRUE, Boolean.FALSE ,tagKey, "val1");
        hasPolicyWithTags(policyList, policyWithTags, domainName, tagKey, tagValues, 2);
        hasPolicyWithTags(policyList, policiesingleTag, domainName, tagKey, singleTagValue, 1);
        // ensure there are no more policies
        assertEquals(policyList.getList().size(), 2);

        // get policies with exact tag value
        policyList = zmsImpl.getPolicies(ctx, domainName, Boolean.TRUE, Boolean.FALSE, tagKey, "val2");
        hasPolicyWithTags(policyList, policyWithTags, domainName, tagKey, tagValues, 2);
        // ensure there are no more policies
        assertEquals(policyList.getList().size(), 1);

        // get policies with only tag key
        policyList = zmsImpl.getPolicies(ctx, domainName, Boolean.TRUE, Boolean.FALSE, tagKey, null);
        hasPolicyWithTags(policyList, policyWithTags, domainName, tagKey, tagValues, 2);
        hasPolicyWithTags(policyList, policiesingleTag, domainName, tagKey, singleTagValue, 1);
        // ensure there are no more policies
        assertEquals(policyList.getList().size(), 2);
    }

    @Test
    public void testPolicyTagsLimit() {

        final String auditRef = zmsTestInitializer.getAuditRef();

        // define limit of 3 policy tags
        System.setProperty(ZMSConsts.ZMS_PROP_QUOTA_POLICY_TAG, "3");
        ZMSImpl zmsTest = zmsTestInitializer.zmsInit();

        final String policyName = "policyWithTagLimit";
        final String tagKey = "tag-key";

        //insert policy with 4 tags
        List<String> tagValues = Arrays.asList("val1", "val2", "val3", "val4");
        Policy policy = zmsTestInitializer.createPolicyObject(domainName, policyName,
                domainName + ":role.role1", false, "root",
                "service:service1", AssertionEffect.ALLOW);
        policy.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(tagValues)));
        try {
            zmsTest.putPolicy(ctx, domainName, policyName, auditRef, false, null, policy);
            fail();
        } catch(ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains(
                    "policy tag quota exceeded - limit: 3, current tags count: 0, new tags count: 4"));
        }

        try {
            // policy should not be created if fails to process tags.
            zmsTest.getPolicy(ctx, domainName, policyName);
            fail();
        } catch(ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        System.clearProperty(ZMSConsts.ZMS_PROP_QUOTA_POLICY_TAG);
    }

    @Test
    public void testQueryUpdatePolicyWithTags() {

        final String auditRef = zmsTestInitializer.getAuditRef();

        final String tagKey = "tag-key-update";
        //put policy without tags
        final String noTagsPolicy = "noTagsPolicy";
        Policy policy = zmsTestInitializer.createPolicyObject(domainName, noTagsPolicy,
                domainName + ":role.role1", false, "root",
                "service:service1", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, domainName, noTagsPolicy, auditRef, false, null, policy);

        // assert there are no tags
        Policies policyList = zmsImpl.getPolicies(ctx, domainName, Boolean.TRUE, null, null, null);
        hasPolicyWithTags(policyList, noTagsPolicy, domainName, null, null,0);

        // update tag list
        List<String> tagValues = Arrays.asList("val1", "val2", "val3");
        policy.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(tagValues)));
        zmsImpl.putPolicy(ctx, domainName, noTagsPolicy, auditRef, false, null, policy);

        // 1 tags should be presented
        policyList = zmsImpl.getPolicies(ctx, domainName, Boolean.TRUE, null, null,null);
        hasPolicyWithTags(policyList, noTagsPolicy, domainName, tagKey, tagValues, 3);

        // get policies with exact tag value
        policyList = zmsImpl.getPolicies(ctx, domainName, Boolean.FALSE, null, tagKey, "val1");
        hasPolicyWithTags(policyList, noTagsPolicy, domainName, tagKey, tagValues, 3);
        assertEquals(policyList.getList().size(), 1);

        // get policies with only tag key
        policyList = zmsImpl.getPolicies(ctx, domainName, Boolean.TRUE, null, tagKey, null);
        hasPolicyWithTags(policyList, noTagsPolicy, domainName, tagKey, tagValues , 3);
        assertEquals(policyList.getList().size(), 1);

        // now create a different tags Map, part is from tagValues
        String newPolicyName = "newPolicy";
        Map<String, TagValueList> tagsMap = new HashMap<>();
        List<String> newTagValues1 = Arrays.asList("val1", "new-val");
        String newTagKey = "newTagKey";
        List<String> newTagValues2 = Arrays.asList("val4", "val5", "val6");
        tagsMap.put(tagKey, new TagValueList().setList(newTagValues1));
        tagsMap.put(newTagKey, new TagValueList().setList(newTagValues2));
        Policy newPolicy = zmsTestInitializer.createPolicyObject(domainName, newPolicyName,
                domainName + ":role.role1", false, "root",
                "service:service1", AssertionEffect.ALLOW);
        newPolicy.setTags(tagsMap);
        zmsImpl.putPolicy(ctx, domainName, newPolicyName, auditRef, false, null, newPolicy);

        // 3 tags should be presented there is 1 initial policy in the sys.auth domain
        policyList = zmsImpl.getPolicies(ctx, domainName, Boolean.TRUE, null, null, null);
        hasPolicyWithTags(policyList, noTagsPolicy, domainName, tagKey, tagValues, 3);
        hasPolicyWithTags(policyList, newPolicyName, domainName, tagKey, newTagValues1, 2);
        hasPolicyWithTags(policyList, newPolicyName, domainName, newTagKey, newTagValues2, 3);
        int preDefinedPolicies = 1;
        assertEquals(policyList.getList().size(), 2 + preDefinedPolicies);

        // get policies with exact tag value
        policyList = zmsImpl.getPolicies(ctx, domainName, Boolean.TRUE, null, tagKey, "val1");
        hasPolicyWithTags(policyList, noTagsPolicy, domainName, tagKey, tagValues, 3);
        hasPolicyWithTags(policyList, newPolicyName, domainName, tagKey, newTagValues1, 2);
        hasPolicyWithTags(policyList, newPolicyName, domainName, newTagKey, newTagValues2, 3);
        assertEquals(policyList.getList().size(), 2);

        // get policies with non-existent tag value
        policyList = zmsImpl.getPolicies(ctx, domainName, Boolean.TRUE, null, tagKey, "val2");
        hasPolicyWithTags(policyList, noTagsPolicy, domainName, tagKey, tagValues, 3);
        assertEquals(policyList.getList().size(), 1);

        // get policies with new tag key
        policyList = zmsImpl.getPolicies(ctx, domainName, Boolean.TRUE, null, newTagKey, null);
        hasPolicyWithTags(policyList, newPolicyName, domainName, newTagKey, newTagValues2, 3);
        assertEquals(policyList.getList().size(), 1);
    }

    private void hasPolicyWithTags(Policies policyList, String policyName, String domainName,
                                   String tagKey, List<String> tagValues, int tagValuesLength) {
        Policy policy = getPolicy(policyList, policyName, domainName);
        Assert.assertNotNull(policy);
        if (tagKey != null) {
            if (tagValues != null) {
                Assert.assertEquals(policy.getTags().get(tagKey).getList().size(), tagValuesLength);
                for (String tagValue : tagValues) {
                    Assert.assertTrue(hasTag(policy, tagKey, tagValue));
                }
            } else {
                Assert.assertTrue(hasTag(policy, tagKey, null));
            }
        }
    }

    private boolean hasTag(Policy policy, String tagKey, String tagValue) {
        TagValueList tagValues = policy.getTags().get(tagKey);
        if (tagValue != null) {
            return tagValues.getList().contains(tagValue);
        }
        return !tagValues.getList().isEmpty();
    }

    private Policy getPolicy(Policies policyList, String policyName, String domainName) {
        return policyList.getList().stream()
                .filter(g -> ZMSUtils.extractPolicyName(domainName, g.getName()).equalsIgnoreCase(policyName))
                .findFirst()
                .get();
    }

    @Test
    public void testGetPolicyWithTags() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "setup-policy-with-tags";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);
        Map<String, TagValueList> policy1Tags = Collections.singletonMap("tag-key",
                new TagValueList().setList(Arrays.asList("val2", "val3")));
        Policy policy1 = zmsTestInitializer.createPolicyObject(domainName, "policy1");
        policy1.setTags(policy1Tags);
        zmsImpl.putPolicy(ctx, domainName, "policy1", auditRef, false, null, policy1);

        Policy policy1version2 = zmsTestInitializer.createPolicyObject(domainName, "policy1");
        Map<String, TagValueList> policy2Tags = Collections.singletonMap("tag-key2",
                new TagValueList().setList(Arrays.asList("val5", "val6")));
        policy1version2.setVersion("2");
        policy1version2.setActive(false);
        policy1version2.setTags(policy2Tags);
        zmsImpl.putPolicy(ctx, domainName, "policy1", auditRef, false, null, policy1version2);

        Policy returnedPolicy = zmsImpl.getPolicy(ctx, domainName, "policy1");
        hasTag(returnedPolicy, "tag-key", "val2");

        zmsImpl.setActivePolicyVersion(ctx,domainName, "policy1",
                new PolicyOptions().setFromVersion("0").setVersion("2"), "test", null);

        Policy returnedPolicy2 = zmsImpl.getPolicy(ctx, domainName, "policy1");
        hasTag(returnedPolicy2, "tag-key2", "val6");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testSetupPolicyListWithTags() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "setup-policy-with-tags";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);
        Map<String, TagValueList> policy1Tags = Collections.singletonMap("tag-key",
                new TagValueList().setList(Arrays.asList("val2", "val3")));
        Policy policy1 = zmsTestInitializer.createPolicyObject(domainName, "policy1");
        policy1.setTags(policy1Tags);
        zmsImpl.putPolicy(ctx, domainName, "policy1", auditRef, false, null, policy1);

        Policy policy1version2 = zmsTestInitializer.createPolicyObject(domainName, "policy1");
        policy1version2.setVersion("2");
        policy1version2.setActive(false);
        policy1version2.setTags(policy1Tags);
        zmsImpl.putPolicy(ctx, domainName, "policy1", auditRef, false, null, policy1version2);

        Map<String, TagValueList> policy2Tags = Collections.singletonMap("tag-key",
                new TagValueList().setList(Arrays.asList("val2")));
        Policy policy2 = zmsTestInitializer.createPolicyObject(domainName, "policy2");
        policy2.setTags(policy2Tags);
        zmsImpl.putPolicy(ctx, domainName, "policy2", auditRef, false, null, policy2);

        AthenzDomain domain = zmsImpl.getAthenzDomain(domainName, false);
        List<Policy> policies = zmsImpl.setupPolicyList(domain, Boolean.FALSE, Boolean.FALSE, "tag-key", "val3");
        assertEquals(1, policies.size()); // need to account for admin policy

        assertEquals(policies.get(0).getName(), "setup-policy-with-tags:policy.policy1");
        assertEquals(policies.get(0).getVersion(), "0");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    private void hasServiceWithTags(ServiceIdentities services, String serviceName, String domain,
                                    String tagKey, List<String> tagValues, int tagValuesLength) {
        ServiceIdentity service = getServiceIdentity(services, serviceName, domain);
        Assert.assertNotNull(service);
        if (tagKey != null) {
            if (tagValues != null) {
                Assert.assertEquals(service.getTags().get(tagKey).getList().size(), tagValuesLength);
                for (String tagValue : tagValues) {
                    Assert.assertTrue(verifyServiceHasTag(service, tagKey, tagValue));
                }
            } else {
                Assert.assertTrue(verifyServiceHasTag(service, tagKey, null));
            }
        }
    }

    private boolean verifyServiceHasTag(ServiceIdentity service, String tagKey, String tagValue) {
        TagValueList tagValues = service.getTags().get(tagKey);
        if (tagValue != null) {
            return tagValues.getList().contains(tagValue);
        }
        return (tagValues == null || tagValues.getList().isEmpty());
    }

    private ServiceIdentity getServiceIdentity(ServiceIdentities services, String serviceName, String domain) {
        return services.getList().stream()
                .filter(r -> ZMSUtils.extractServiceName(domain, r.getName()).equalsIgnoreCase(serviceName))
                .findFirst()
                .get();
    }

    @Test
    public void testQueryPutServiceWithTags() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "sys.auth";
        // put service with multiple tags
        final String serviceWithTags = "swt-serviceWithTags";
        final String tagKey = "tag-key";
        List<String> multipleTagValues = Arrays.asList("val1", "val2");
        ServiceIdentity service = zmsTestInitializer.createServiceObject(domainName, serviceWithTags,
                "http://localhost", "/usr/bin/java", "root", "users", "host1");
        service.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(multipleTagValues)));
        zmsImpl.putServiceIdentity(ctx, domainName, serviceWithTags, auditRef, false, null, service);

        // put service with single tags
        final String serviceSingleTag = "swt-serviceSingleTag";
        List<String> singleTagValue = Collections.singletonList("val1");
        service = zmsTestInitializer.createServiceObject(domainName, serviceSingleTag,
                "http://localhost", "/usr/bin/java", "root", "users", "host1");
        service.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(singleTagValue)));
        zmsImpl.putServiceIdentity(ctx, domainName, serviceSingleTag, auditRef, false, null, service);

        //put service without tags
        final String noTagsService = "swt-noTagsService";
        service = zmsTestInitializer.createServiceObject(domainName, noTagsService,
                "http://localhost", "/usr/bin/java", "root", "users", "host1");
        zmsImpl.putServiceIdentity(ctx, domainName, noTagsService, auditRef, false, null, service);

        // get services without tags query - all 3 services should be  presented
        ServiceIdentities serviceList = zmsImpl.getServiceIdentities(ctx, domainName, Boolean.TRUE,
                Boolean.TRUE, null, null);
        hasServiceWithTags(serviceList, serviceWithTags, domainName, tagKey, multipleTagValues, 2);
        hasServiceWithTags(serviceList, serviceSingleTag, domainName, tagKey, singleTagValue, 1);
        hasServiceWithTags(serviceList, noTagsService, domainName, null, null, 0);
        List<ServiceIdentity> TestPolicies = serviceList.getList().stream().filter(
                service1 -> ZMSUtils.extractServiceName(domainName,
                        service1.getName()).startsWith("swt-")).collect(Collectors.toList());
        assertEquals(TestPolicies.size(), 3);

        // get policies with exact tag value
        serviceList = zmsImpl.getServiceIdentities(ctx, domainName, Boolean.TRUE, Boolean.TRUE, tagKey, "val1");
        hasServiceWithTags(serviceList, serviceWithTags, domainName, tagKey, multipleTagValues, 2);
        hasServiceWithTags(serviceList, serviceSingleTag, domainName, tagKey, singleTagValue, 1);
        // ensure there are no more policies
        assertEquals(serviceList.getList().size(), 2);

        // get policies with exact tag value
        serviceList = zmsImpl.getServiceIdentities(ctx, domainName, Boolean.TRUE, Boolean.TRUE, tagKey, "val2");
        hasServiceWithTags(serviceList, serviceWithTags, domainName, tagKey, multipleTagValues, 2);
        // ensure there are no more policies
        assertEquals(serviceList.getList().size(), 1);

        // get policies with only tag key without the unactive service version
        serviceList = zmsImpl.getServiceIdentities(ctx, domainName, Boolean.TRUE, Boolean.FALSE, tagKey, null);
        hasServiceWithTags(serviceList, serviceWithTags, domainName, tagKey, multipleTagValues, 2);
        hasServiceWithTags(serviceList, serviceSingleTag, domainName, tagKey, singleTagValue, 1);
        // ensure there are no more policies
        assertEquals(serviceList.getList().size(), 2);
    }

    @Test
    public void testServiceTagsLimit() {

        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        // define limit of 3 service tags
        System.setProperty(ZMSConsts.ZMS_PROP_QUOTA_SERVICE_TAG, "3");
        ZMSImpl zmsTest = zmsTestInitializer.zmsInit();

        final String domainName = "sys.auth";
        final String serviceName = "serviceWithTagLimit";
        final String tagKey = "tag-key";

        //insert service with 4 tags
        List<String> tagValues = Arrays.asList("val1", "val2", "val3", "val4");
        ServiceIdentity service = zmsTestInitializer.createServiceObject(domainName, serviceName,
                "http://localhost", "/usr/bin/java", "root", "users", "host1");
        service.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(tagValues)));
        try {
            zmsTest.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service);
            fail();
        } catch(ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains(
                    "service tag quota exceeded - limit: 3, current tags count: 0, new tags count: 4"));
        }

        try {
            // service should not be created if fails to process tags...
            zmsTest.getServiceIdentity(ctx, domainName, serviceName);
            fail();
        } catch(ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        System.clearProperty(ZMSConsts.ZMS_PROP_QUOTA_SERVICE_TAG);
    }

    @Test
    public void testQueryUpdateServiceWithTags() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "sys.auth";
        final String tagKey = "tag-key-update";

        //put service without tags
        final String noTagsService = "uswt-noTagsService";
        final String withTagsService = "uswt-withTagsService";

        HashMap<String, TagValueList> multipleTags = new HashMap<>();

        ServiceIdentity service = zmsTestInitializer.createServiceObject(domainName, noTagsService,
                "http://localhost", "/usr/bin/java", "root", "users", "host1");
        zmsImpl.putServiceIdentity(ctx, domainName, noTagsService, auditRef, false, null, service);

        ServiceIdentity service2 = zmsTestInitializer.createServiceObject(domainName, withTagsService,
                "http://localhost", "/usr/bin/java", "root", "users", "host1");
        List<String> tagValues = Arrays.asList("val1", "val2");
        List<String> tag2Values = Arrays.asList("val3", "val4");
        multipleTags.put(tagKey, new TagValueList().setList(tagValues));
        multipleTags.put("tagKey2", new TagValueList().setList(tag2Values));
        service2.setTags(multipleTags);
        zmsImpl.putServiceIdentity(ctx, domainName, withTagsService, auditRef, false, null, service2);

        // assert there are no tags
        ServiceIdentities serviceList = zmsImpl.getServiceIdentities(ctx, domainName,
                Boolean.TRUE, Boolean.TRUE, null, null);
        hasServiceWithTags(serviceList, noTagsService, domainName,null, null, 0);
        hasServiceWithTags(serviceList, withTagsService, domainName,tagKey, multipleTags.get(tagKey).getList(), 2);
        hasServiceWithTags(serviceList, withTagsService, domainName,"tagKey2",
                multipleTags.get("tagKey2").getList(), 2);

        // update tag list
        List<String> updatedTagValues = Arrays.asList("val1", "val2", "val3");
        service.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(updatedTagValues)));
        zmsImpl.putServiceIdentity(ctx, domainName, noTagsService, auditRef, false, null, service);

        multipleTags.remove("tagKey2");
        List<String> newTagValues = Arrays.asList("val3", "val6","val7");
        multipleTags.put(tagKey, new TagValueList().setList(newTagValues));
        service2.setTags(multipleTags);
        zmsImpl.putServiceIdentity(ctx, domainName, withTagsService, auditRef, false, null, service2);

        // 3 tags should be presented
        serviceList = zmsImpl.getServiceIdentities(ctx, domainName, Boolean.TRUE, Boolean.TRUE, null, null);
        hasServiceWithTags(serviceList, noTagsService, domainName, tagKey, updatedTagValues, 3);
        hasServiceWithTags(serviceList, withTagsService, domainName, tagKey, multipleTags.get(tagKey).getList(), 3);
        hasServiceWithTags(serviceList, withTagsService, domainName, "tagKey2", null, 0);

        // get policies with exact tag value without unactive versions.
        serviceList = zmsImpl.getServiceIdentities(ctx, domainName, Boolean.FALSE, Boolean.FALSE, tagKey, "val3");
        hasServiceWithTags(serviceList, noTagsService, domainName, tagKey, tagValues, 3);
        hasServiceWithTags(serviceList, withTagsService, domainName, tagKey, newTagValues, 3);
        assertEquals(serviceList.getList().size(), 2);

        // get policies with no existing tag value
        serviceList = zmsImpl.getServiceIdentities(ctx, domainName, Boolean.TRUE, Boolean.TRUE, tagKey, "val10");
        assertEquals(serviceList.getList().size(), 0);
    }

    @Test
    public void testQueryPutRoleWithTags() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "sys.auth";

        // put role with multiple tags
        final String roleWithTags = "roleWithTags";
        final String tagKey = "tag-key";
        List<String> tagValues = Arrays.asList("val1", "val2");
        Role role = zmsTestInitializer.createRoleObject(domainName, roleWithTags, null);
        role.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(tagValues)));
        zmsImpl.putRole(ctx, domainName, roleWithTags, auditRef, false, null, role);

        // put role with single tags
        final String roleSingleTag = "roleSingleTag";
        List<String> singleTagValue = Collections.singletonList("val1");
        role = zmsTestInitializer.createRoleObject(domainName, roleSingleTag, null);
        role.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(singleTagValue)));
        zmsImpl.putRole(ctx, domainName, roleSingleTag, auditRef, false, null, role);

        //put role without tags
        final String noTagsRole = "noTagsRole";
        role = zmsTestInitializer.createRoleObject(domainName, noTagsRole, null);
        zmsImpl.putRole(ctx, domainName, noTagsRole, auditRef, false, null, role);

        // get roles without tags query - both tags should be presented
        Roles roleList = zmsImpl.getRoles(ctx, domainName, Boolean.TRUE, null, null);
        hasRoleWithTags(roleList, roleWithTags, tagKey, tagValues, 2);
        hasRoleWithTags(roleList, roleSingleTag, tagKey, singleTagValue, 1);
        hasRoleWithTags(roleList, noTagsRole, null, null, 0);

        // get roles with exact tag value
        roleList = zmsImpl.getRoles(ctx, domainName, Boolean.TRUE, tagKey, "val1");
        hasRoleWithTags(roleList, roleWithTags, tagKey, tagValues, 2);
        hasRoleWithTags(roleList, roleSingleTag, tagKey, singleTagValue, 1);
        // ensure there are no more roles
        assertEquals(roleList.getList().size(), 2);

        // get roles with exact tag value
        roleList = zmsImpl.getRoles(ctx, domainName, Boolean.TRUE, tagKey, "val2");
        hasRoleWithTags(roleList, roleWithTags, tagKey, tagValues, 2);
        // ensure there are no more roles
        assertEquals(roleList.getList().size(), 1);

        // get roles with only tag key
        roleList = zmsImpl.getRoles(ctx, domainName, Boolean.TRUE, tagKey, null);
        hasRoleWithTags(roleList, roleWithTags, tagKey, tagValues, 2);
        hasRoleWithTags(roleList, roleSingleTag, tagKey, singleTagValue, 1);
        // ensure there are no more roles
        assertEquals(roleList.getList().size(), 2);
    }

    @Test
    public void testRoleTagsLimit() {

        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        // define limit of 3 role tags
        System.setProperty(ZMSConsts.ZMS_PROP_QUOTA_ROLE_TAG, "3");
        ZMSImpl zmsTest = zmsTestInitializer.zmsInit();

        final String domainName = "sys.auth";
        final String roleName = "roleWithTagLimit";
        final String tagKey = "tag-key";

        //insert role with 4 tags
        List<String> tagValues = Arrays.asList("val1", "val2", "val3", "val4");
        Role role = zmsTestInitializer.createRoleObject(domainName, roleName, null);
        role.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(tagValues)));
        try {
            zmsTest.putRole(ctx, domainName, roleName, auditRef, false, null, role);
            fail();
        } catch(ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains(
                    "role tag quota exceeded - limit: 3, current tags count: 0, new tags count: 4"));
        }

        try {
            // role should not be created if fails to process tags..
            zmsTest.getRole(ctx, domainName, roleName, false, false, false);
            fail();
        } catch(ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        System.clearProperty(ZMSConsts.ZMS_PROP_QUOTA_ROLE_TAG);
    }

    @Test
    public void testQueryUpdateRoleWithTags() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "sys.auth";
        final String tagKey = "tag-key-update";

        //put role without tags
        final String noTagsRole = "noTagsRole";
        Role role = zmsTestInitializer.createRoleObject(domainName, noTagsRole, null);
        zmsImpl.putRole(ctx, domainName, noTagsRole, auditRef, false, null, role);

        // assert there are no tags
        Roles roleList = zmsImpl.getRoles(ctx, domainName, Boolean.TRUE, null, null);
        hasRoleWithTags(roleList, noTagsRole, null, null, 0);

        // update tag list
        List<String> tagValues = Arrays.asList("val1", "val2", "val3");
        role.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(tagValues)));
        zmsImpl.putRole(ctx, domainName, noTagsRole, auditRef, false, null, role);

        // 2 tags should be presented
        roleList = zmsImpl.getRoles(ctx, domainName, Boolean.TRUE, null, null);
        hasRoleWithTags(roleList, noTagsRole, tagKey, tagValues, 3);

        // get roles with exact tag value
        roleList = zmsImpl.getRoles(ctx, domainName, Boolean.FALSE, tagKey, "val1");
        hasRoleWithTags(roleList, noTagsRole, tagKey, tagValues, 3);
        assertEquals(roleList.getList().size(), 1);

        // get roles with only tag key
        roleList = zmsImpl.getRoles(ctx, domainName, Boolean.TRUE, tagKey, null);
        hasRoleWithTags(roleList, noTagsRole, tagKey, tagValues, 3);
        assertEquals(roleList.getList().size(), 1);

        // now create a different tags Map, part is from tagValues
        Map<String, TagValueList> tagsMap = new HashMap<>();
        List<String> modifiedTagValues = Arrays.asList("val1", "new-val");
        String newTagKey = "newTagKey";
        List<String> newTagValues = Arrays.asList("val4", "val5", "val6");
        tagsMap.put(tagKey, new TagValueList().setList(modifiedTagValues));
        tagsMap.put(newTagKey, new TagValueList().setList(newTagValues));
        role.setTags(tagsMap);
        zmsImpl.putRole(ctx, domainName, noTagsRole, auditRef, false, null, role);

        // 1 tags should be presented
        roleList = zmsImpl.getRoles(ctx, domainName, Boolean.TRUE, null, null);
        hasRoleWithTags(roleList, noTagsRole, tagKey, modifiedTagValues, 2);
        hasRoleWithTags(roleList, noTagsRole, newTagKey, newTagValues, 3);

        // get roles with exact tag value
        roleList = zmsImpl.getRoles(ctx, domainName, Boolean.TRUE, tagKey, "val1");
        hasRoleWithTags(roleList, noTagsRole, tagKey, modifiedTagValues, 2);
        assertEquals(roleList.getList().size(), 1);

        // get roles with non-existent tag value
        roleList = zmsImpl.getRoles(ctx, domainName, Boolean.TRUE, tagKey, "val2");
        assertEquals(roleList.getList().size(), 0);

        // get roles with new tag key
        roleList = zmsImpl.getRoles(ctx, domainName, Boolean.TRUE, tagKey, null);
        hasRoleWithTags(roleList, noTagsRole, newTagKey, newTagValues, 3);
        assertEquals(roleList.getList().size(), 1);
    }

    @Test
    public void testUpdateRoleMetaWithoutTags() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "update-role-meta-without-tags";
        final String updateRoleMetaTag = "tag-key-update-role-meta";
        final List<String> updateRoleMetaTagValues = Collections.singletonList("update-meta-value");

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // put role without tags
        final String roleName = "roleTagsUpdateMeta";
        Role role = zmsTestInitializer.createRoleObject(domainName, roleName, null);
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role);

        // no tags should be presented
        Roles roleList = zmsImpl.getRoles(ctx, domainName, Boolean.TRUE, updateRoleMetaTag, null);
        assertTrue(roleList.getList().isEmpty());

        RoleMeta rm = new RoleMeta()
                .setTags(Collections.singletonMap(updateRoleMetaTag,
                        new TagValueList().setList(updateRoleMetaTagValues)));

        // update role tags using role meta
        zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, null, rm);

        // assert that updateRoleMetaTag is in role tags
        roleList = zmsImpl.getRoles(ctx, domainName, Boolean.TRUE, updateRoleMetaTag, null);
        hasRoleWithTags(roleList, roleName, updateRoleMetaTag, updateRoleMetaTagValues, 1);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testUpdateRoleMetaWithExistingTag() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "update-role-meta-with-existing-tag";
        final String tagKey = "tag-key";
        final String updateRoleMetaTag = "tag-key-update-role-meta-exist-tag";
        final List<String> updateRoleMetaTagValues = Collections.singletonList("update-meta-value");

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // put role with tag
        final String roleName = "roleWithTagUpdateMeta";
        List<String> singleTagValue = Collections.singletonList("val1");
        Role role = zmsTestInitializer.createRoleObject(domainName, roleName, null);
        role.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(singleTagValue)));
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role);

        // tag tagKey should be presented
        Roles roleList = zmsImpl.getRoles(ctx, domainName, Boolean.TRUE, tagKey, null);
        hasRoleWithTags(roleList, roleName, tagKey, singleTagValue, 1);

        RoleMeta rm = new RoleMeta()
                .setTags(Collections.singletonMap(updateRoleMetaTag,
                        new TagValueList().setList(updateRoleMetaTagValues)));

        // update role tags using role meta
        zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, null, rm);

        // role should contain only the new tag
        roleList = zmsImpl.getRoles(ctx, domainName, Boolean.TRUE, updateRoleMetaTag, null);
        hasRoleWithTags(roleList, roleName, updateRoleMetaTag, updateRoleMetaTagValues, 1);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    private void hasRoleWithTags(Roles roleList, String roleName, String tagKey, List<String> tagValues,
                                 int tagValuesLength) {
        Role role = getRole(roleList, roleName);
        Assert.assertNotNull(role);
        if (tagKey != null) {
            if (tagValues != null) {
                Assert.assertEquals(role.getTags().get(tagKey).getList().size(), tagValuesLength);
                for (String tagValue : tagValues) {
                    Assert.assertTrue(hasTag(role, tagKey, tagValue));
                }
            } else {
                Assert.assertTrue(hasTag(role, tagKey, null));
            }
        }
    }

    private boolean hasTag(Role role, String tagKey, String tagValue) {
        TagValueList tagValues = role.getTags().get(tagKey);
        if (tagValue != null) {
            return tagValues.getList().contains(tagValue);
        }
        return !tagValues.getList().isEmpty();
    }

    private Role getRole(Roles roleList, String roleName) {
        return roleList.getList().stream()
                .filter(r -> AthenzUtils.extractRoleName(r.getName()).equalsIgnoreCase(roleName))
                .findFirst()
                .get();
    }

    @Test
    public void testDomainMetaWithTags() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "domain-with-tags";

        TopLevelDomain topLevelDomain = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain With Tags", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, topLevelDomain);

        DomainMeta domainMeta = zmsTestInitializer.createDomainMetaObject("Domain Meta for domain tags",
                "testOrg", true, true, "12345", 1001);
        domainMeta.setTags(simpleDomainTag());
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, domainMeta);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertEquals(domain.getTags(), simpleDomainTag());
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testDomainTagsLimit() {
        // define limit of 3 domain tags
        System.setProperty(ZMSConsts.ZMS_PROP_QUOTA_DOMAIN_TAG, "3");
        ZMSImpl zmsTest = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "tld-with-tag-limit";

        TopLevelDomain topLevelDomain = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain With Tag Limit", "testOrg", zmsTestInitializer.getAdminUser());
        topLevelDomain.setTags(Collections.singletonMap("tag-key",
                new TagValueList().setList(Arrays.asList("val1", "val2", "val3", "val4"))));
        try {
            zmsTest.postTopLevelDomain(ctx, auditRef, null, topLevelDomain);
            fail();
        } catch(ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains(
                    "domain tag quota exceeded - limit: 3, current tags count: 0, new tags count: 4"));
        }
        try {
            // domain should not be created if fails to process tags..
            zmsTest.getDomain(ctx, domainName);
            fail();
        } catch(ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        System.clearProperty(ZMSConsts.ZMS_PROP_QUOTA_DOMAIN_TAG);
    }

    @Test
    public void testTopLevelSubDomainWithTags() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "tld-with-tags";

        TopLevelDomain topLevelDomain = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain With Tags", "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        topLevelDomain.setTags(simpleDomainTag());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, topLevelDomain);

        String subDomName = "subdomain-with-tag";
        SubDomain subDom = zmsTestInitializer.createSubDomainObject(subDomName, domainName,
                "subdomain desc", "testOrg", zmsTestInitializer.getAdminUser());
        subDom.setTags(simpleDomainTag());
        zmsImpl.postSubDomain(ctx, domainName, auditRef, null, subDom);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertEquals(domain.getTags(), simpleDomainTag());

        Domain subDomainObj = zmsImpl.getDomain(ctx, domainName + "." + subDomName);
        assertEquals(subDomainObj.getTags(), simpleDomainTag());

        zmsImpl.deleteSubDomain(ctx, domainName, subDomName, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testUserLevelDomainWithTags() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String domainName = "dguttman-tags";

        UserDomain userDomain = zmsTestInitializer.createUserDomainObject(domainName, "Test Domain1", "testOrg");
        userDomain.setTags(simpleDomainTag());
        zmsImpl.postUserDomain(ctx, domainName, auditRef, null, userDomain);

        Domain domain = zmsImpl.getDomain(ctx, "user." + domainName);
        assertEquals(domain.getTags(), simpleDomainTag());

        zmsImpl.deleteUserDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testGetSignedDomainWithTags() throws JsonProcessingException, ParseException, JOSEException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "jws-domain-tags";

        // create multiple top level domains
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        dom1.setTags(simpleDomainTag());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Response response = zmsImpl.getJWSDomain(ctx, domainName, null, null);
        JWSDomain jwsDomain = (JWSDomain) response.getEntity();
        DomainData domainData = zmsTestInitializer.getDomainData(jwsDomain);
        assertNotNull(domainData);
        assertEquals(domainData.getName(), domainName);

        Map<String, String> header = jwsDomain.getHeader();
        assertEquals(header.get("kid"), "0");

        assertEquals(domainData.getTags(), simpleDomainTag());

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal sysPrincipal = principalAuthority.authenticate("v=U1;d=sys;n=zts;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx = zmsTestInitializer.createResourceContext(sysPrincipal);

        response = zmsImpl.getSignedDomains(rsrcCtx, domainName, null, null, null, false, null);
        SignedDomains sdoms = (SignedDomains) response.getEntity();
        assertNotNull(sdoms);

        Map<String, TagValueList> signedDomainTags = sdoms.getDomains().stream()
                .filter(dom -> dom.getDomain().getName().equals(domainName))
                .map(dom -> dom.getDomain().getTags())
                .findFirst().get();

        assertEquals(signedDomainTags, simpleDomainTag());

        // test with meta only
        response = zmsImpl.getSignedDomains(rsrcCtx, domainName, "true", "all", null, false, null);
        sdoms = (SignedDomains) response.getEntity();
        assertNotNull(sdoms);

        signedDomainTags = sdoms.getDomains().stream()
                .filter(dom -> dom.getDomain().getName().equals(domainName))
                .map(dom -> dom.getDomain().getTags())
                .findFirst().get();

        assertEquals(signedDomainTags, simpleDomainTag());

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    private Map<String, TagValueList> simpleDomainTag() {
        return Collections.singletonMap("tag-key", new TagValueList().setList(Arrays.asList("val1", "val2")));
    }

    @Test
    public void testGetDomainListUsingTags() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        // first domain - no tags
        String domainNoTags = "tld-no-tags";
        TopLevelDomain tldNoTags = zmsTestInitializer.createTopLevelDomainObject(domainNoTags,
                "Test Domain Without Tags", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, tldNoTags);
        Domain domainObjNoTags = zmsImpl.getDomain(ctx, domainNoTags);
        assertNull(domainObjNoTags.getTags());

        // first domain - 1 tag
        String domainName1 = "tld-tag-1";
        TopLevelDomain topLevelDomain = zmsTestInitializer.createTopLevelDomainObject(domainName1,
                "Test Domain With Tags", "testOrg", zmsTestInitializer.getAdminUser());
        topLevelDomain.setTags(simpleDomainTag());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, topLevelDomain);
        Domain domain1 = zmsImpl.getDomain(ctx, domainName1);
        assertEquals(domain1.getTags(), simpleDomainTag());

        // second domain - 2 tags
        Map<String, TagValueList> twoTags = new HashMap<>();
        twoTags.put("tag-key", new TagValueList().setList(Arrays.asList("tld2-val1", "tld2-val2")));
        twoTags.put("tag-key-2", new TagValueList().setList(Arrays.asList("tld2-val3", "tld2-val4")));
        String domainName2 = "tld-tag-2";
        TopLevelDomain topLevelDomain2 = zmsTestInitializer.createTopLevelDomainObject(domainName2,
                "Test Domain With Tags", "testOrg", zmsTestInitializer.getAdminUser());
        topLevelDomain2.setTags(twoTags);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, topLevelDomain2);
        Domain domain2 = zmsImpl.getDomain(ctx, domainName1);
        assertEquals(domain2.getTags(), simpleDomainTag());

        // domain-list no tags - all domains should be presented
        DomainList dl = zmsImpl.getDomainList(ctx, null, null, null, null,
                null, null, null, null, null, null, null, null, null, null, null);
        assertTrue(dl.getNames().containsAll(Arrays.asList(domainNoTags, domainName1, domainName2)));

        // domain-list with only tag-key, should include both domains
        dl = zmsImpl.getDomainList(ctx, null, null, null, null,
                null, null, null, null, null, null, "tag-key", null, null, null, null);

        assertEquals(dl.getNames().size(), 2);
        assertTrue(dl.getNames().containsAll(Arrays.asList(domainName1, domainName2)));

        // domain-list with tag-key AND tag-value, should include only domainName1
        dl = zmsImpl.getDomainList(ctx, null, null, null, null,
                null, null, null, null, null, null, "tag-key", "val1", null, null, null);

        assertEquals(dl.getNames().size(), 1);
        assertTrue(dl.getNames().contains(domainName1));

        zmsImpl.deleteTopLevelDomain(ctx, domainNoTags, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName1, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName2, auditRef, null);
    }

    @Test
    public void testUpdateDomainTag() {
        final String domainName = "domain-with-tags";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain topLevelDomain = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain With Tags", "testOrg", zmsTestInitializer.getAdminUser());
        topLevelDomain.setTags(simpleDomainTag());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, topLevelDomain);

        // domain should contain the tag
        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertEquals(domain.getTags(), simpleDomainTag());

        // update domain meta with the same tag..
        DomainMeta domainMeta = zmsTestInitializer.createDomainMetaObject("Domain Meta for domain tags",
                "testOrg", true, true, "12345", 1001);
        domainMeta.setTags(simpleDomainTag());
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, domainMeta);

        // should be the same tag result..
        domain = zmsImpl.getDomain(ctx, domainName);
        assertEquals(domain.getTags(), simpleDomainTag());

        // update domain meta with the same tag, key, but different values..
        domainMeta = zmsTestInitializer.createDomainMetaObject("Domain Meta for domain tags", "testOrg",
                true, true, "12345", 1001);
        Map<String, TagValueList> newTags = Collections.singletonMap("tag-key",
                new TagValueList().setList(Arrays.asList("val2", "val3")));
        domainMeta.setTags(newTags);
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, domainMeta);

        // should be the newTags
        domain = zmsImpl.getDomain(ctx, domainName);
        assertEquals(domain.getTags(), newTags);

        // update domain meta with the different tags
        domainMeta = zmsTestInitializer.createDomainMetaObject("Domain Meta for domain tags",
                "testOrg", true, true, "12345", 1001);
        Map<String, TagValueList> newTags2 = Collections.singletonMap("tag-key-2",
                new TagValueList().setList(Arrays.asList("new-val1", "new-val2")));
        domainMeta.setTags(newTags2);
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, domainMeta);

        // should be the newTags2
        domain = zmsImpl.getDomain(ctx, domainName);
        assertEquals(domain.getTags(), newTags2);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }
}

