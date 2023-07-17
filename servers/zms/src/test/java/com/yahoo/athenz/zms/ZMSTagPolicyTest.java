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

    import com.yahoo.athenz.zms.utils.ZMSUtils;
    import org.testng.Assert;
    import org.testng.annotations.*;

    import java.util.*;

    import static org.testng.Assert.*;

public class ZMSTagPolicyTest {
    
        private final ZMSTestInitializer zmsTestInitializer = new ZMSTestInitializer();
        private  ZMSImpl zmsImpl;
        private  RsrcCtxWrapper ctx;
        private final String domainName = "sys.auth";
        private final int preDefinedPolicies = 1;

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
            zmsImpl.putRole(ctx, domainName, "role1", zmsTestInitializer.getAuditRef(), false, role);
            deleteAllCreatedPolicies();
        }

        @AfterMethod
        public void clearConnections() {
            zmsTestInitializer.clearConnections();
            deleteAllCreatedPolicies();
        }

        void deleteAllCreatedPolicies() {
            Policies policyList = zmsImpl.getPolicies(ctx, domainName, false, null,null, null);
            for (Policy policy : policyList.getList()) {
                String policyName = policy.getName().toString().replace(domainName + ":policy.", "");
                if (!policyName.contains("admin")) {
                    zmsImpl.deletePolicy(ctx, domainName, policyName, "");
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
            Policy policy = zmsTestInitializer.createPolicyObject(domainName, policyWithTags, domainName + ":role.role1", false, "root",
                    "serivce:service1", AssertionEffect.ALLOW);
            policy.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(tagValues)));
            zmsImpl.putPolicy(ctx, domainName, policyWithTags, auditRef, false, policy);

            // put policy with single tags
            final String policiesingleTag = "policiesingleTag";
            List<String> singleTagValue = Collections.singletonList("val1");
            policy = zmsTestInitializer.createPolicyObject(domainName, policiesingleTag, domainName + ":role.role1", false, "root",
                    "service:service1", AssertionEffect.ALLOW);
            policy.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(singleTagValue)));
            zmsImpl.putPolicy(ctx, domainName, policiesingleTag, auditRef, false, policy);

            //put policy without tags
            final String noTagsPolicy = "noTagsPolicy";
            policy = zmsTestInitializer.createPolicyObject(domainName, noTagsPolicy, domainName + ":role.role1", false, "root",
                    "service:service1", AssertionEffect.ALLOW);
            zmsImpl.putPolicy(ctx, domainName, noTagsPolicy, auditRef, false, policy);

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
            Policy policy = zmsTestInitializer.createPolicyObject(domainName, policyName, domainName + ":role.role1", false, "root",
                    "service:service1", AssertionEffect.ALLOW);
            policy.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(tagValues)));
            try {
                zmsTest.putPolicy(ctx, domainName, policyName, auditRef, false, policy);
                fail();
            } catch(ResourceException ex) {
                assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
                assertTrue(ex.getMessage().contains("policy tag quota exceeded - limit: 3, current tags count: 0, new tags count: 4"));
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
            Policy policy = zmsTestInitializer.createPolicyObject(domainName, noTagsPolicy, domainName + ":role.role1", false, "root",
                    "service:service1", AssertionEffect.ALLOW);
            zmsImpl.putPolicy(ctx, domainName, noTagsPolicy, auditRef, false, policy);

            // assert there are no tags
            Policies policyList = zmsImpl.getPolicies(ctx, domainName, Boolean.TRUE, null, null, null);
            hasPolicyWithTags(policyList, noTagsPolicy, domainName, null, null,0);

            // update tag list
            List<String> tagValues = Arrays.asList("val1", "val2", "val3");
            policy.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(tagValues)));
            zmsImpl.putPolicy(ctx, domainName, noTagsPolicy, auditRef, false, policy);

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
            Policy newPolicy = zmsTestInitializer.createPolicyObject(domainName, newPolicyName, domainName + ":role.role1", false, "root",
                    "service:service1", AssertionEffect.ALLOW);
            newPolicy.setTags(tagsMap);
            zmsImpl.putPolicy(ctx, domainName, newPolicyName, auditRef, false, newPolicy);

            // 3 tags should be presented there is 1 initial policy in the sys.auth domain
            policyList = zmsImpl.getPolicies(ctx, domainName, Boolean.TRUE, null, null, null);
            hasPolicyWithTags(policyList, noTagsPolicy, domainName, tagKey, tagValues, 3);
            hasPolicyWithTags(policyList, newPolicyName, domainName, tagKey, newTagValues1, 2);
            hasPolicyWithTags(policyList, newPolicyName, domainName, newTagKey, newTagValues2, 3);
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

        private void hasPolicyWithTags(Policies policyList, String policyName, String domainName, String tagKey, List<String> tagValues, int tagValuesLength) {
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
}

