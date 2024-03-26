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

import com.yahoo.athenz.auth.util.AthenzUtils;
import org.testng.Assert;
import org.testng.annotations.*;

import java.util.*;

import static org.testng.Assert.*;

public class ZMSGroupTagsTest {

    private final ZMSTestInitializer zmsTestInitializer = new ZMSTestInitializer();

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
    }

    @AfterMethod
    public void clearConnections() {
        zmsTestInitializer.clearConnections();
    }

    @Test
    public void testQueryPutGroupWithTags() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "sys.auth";

        // put group with multiple tags
        final String groupWithTags = "groupWithTags";
        final String tagKey = "tag-key";
        List<String> tagValues = Arrays.asList("val1", "val2");
        Group group = zmsTestInitializer.createGroupObject(domainName, groupWithTags, null);
        group.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(tagValues)));
        zmsImpl.putGroup(ctx, domainName, groupWithTags, auditRef, false, null, group);

        // put group with single tags
        final String groupSingleTag = "groupSingleTag";
        List<String> singleTagValue = Collections.singletonList("val1");
        group = zmsTestInitializer.createGroupObject(domainName, groupSingleTag, null);
        group.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(singleTagValue)));
        zmsImpl.putGroup(ctx, domainName, groupSingleTag, auditRef, false, null, group);

        //put group without tags
        final String noTagsGroup = "noTagsGroup";
        group = zmsTestInitializer.createGroupObject(domainName, noTagsGroup, null);
        zmsImpl.putGroup(ctx, domainName, noTagsGroup, auditRef, false, null, group);

        // get groups without tags query - both tags should be presented
        Groups groupList = zmsImpl.getGroups(ctx, domainName, Boolean.TRUE, null, null);
        hasGroupWithTags(groupList, groupWithTags, tagKey, tagValues, 2);
        hasGroupWithTags(groupList, groupSingleTag, tagKey, singleTagValue, 1);
        hasGroupWithTags(groupList, noTagsGroup, null, null, 0);

        // get groups with exact tag value
        groupList = zmsImpl.getGroups(ctx, domainName, Boolean.TRUE, tagKey, "val1");
        hasGroupWithTags(groupList, groupWithTags, tagKey, tagValues, 2);
        hasGroupWithTags(groupList, groupSingleTag, tagKey, singleTagValue, 1);
        // ensure there are no more groups
        assertEquals(groupList.getList().size(), 2);

        // get groups with exact tag value
        groupList = zmsImpl.getGroups(ctx, domainName, Boolean.TRUE, tagKey, "val2");
        hasGroupWithTags(groupList, groupWithTags, tagKey, tagValues, 2);
        // ensure there are no more groups
        assertEquals(groupList.getList().size(), 1);

        // get groups with only tag key
        groupList = zmsImpl.getGroups(ctx, domainName, Boolean.TRUE, tagKey, null);
        hasGroupWithTags(groupList, groupWithTags, tagKey, tagValues, 2);
        hasGroupWithTags(groupList, groupSingleTag, tagKey, singleTagValue, 1);
        // ensure there are no more groups
        assertEquals(groupList.getList().size(), 2);
    }

    @Test
    public void testGroupTagsLimit() {

        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        // define limit of 3 group tags
        System.setProperty(ZMSConsts.ZMS_PROP_QUOTA_GROUP_TAG, "3");
        ZMSImpl zmsTest = zmsTestInitializer.zmsInit();

        final String domainName = "sys.auth";
        final String groupName = "groupWithTagLimit";
        final String tagKey = "tag-key";

        //insert group with 4 tags
        List<String> tagValues = Arrays.asList("val1", "val2", "val3", "val4");
        Group group = zmsTestInitializer.createGroupObject(domainName, groupName, null);
        group.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(tagValues)));
        try {
            zmsTest.putGroup(ctx, domainName, groupName, auditRef, false, null, group);
            fail();
        } catch(ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("group tag quota exceeded - limit: 3, current tags count: 0, new tags count: 4"));
        }

        try {
            // group should not be created if fails to process tags.
            zmsTest.getGroup(ctx, domainName, groupName, false, false);
            fail();
        } catch(ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        System.clearProperty(ZMSConsts.ZMS_PROP_QUOTA_GROUP_TAG);
    }


    @Test
    public void testQueryUpdateGroupWithTags() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "sys.auth";
        final String tagKey = "tag-key-update";

        //put group without tags
        final String noTagsGroup = "noTagsGroup";
        Group group = zmsTestInitializer.createGroupObject(domainName, noTagsGroup, null);
        zmsImpl.putGroup(ctx, domainName, noTagsGroup, auditRef, false, null, group);

        // assert there are no tags
        Groups groupList = zmsImpl.getGroups(ctx, domainName, Boolean.TRUE, null, null);
        hasGroupWithTags(groupList, noTagsGroup, null, null, 0);

        // update tag list
        List<String> tagValues = Arrays.asList("val1", "val2", "val3");
        group.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(tagValues)));
        zmsImpl.putGroup(ctx, domainName, noTagsGroup, auditRef, false, null, group);

        // 2 tags should be presented
        groupList = zmsImpl.getGroups(ctx, domainName, Boolean.TRUE, null, null);
        hasGroupWithTags(groupList, noTagsGroup, tagKey, tagValues, 3);

        // get groups with exact tag value
        groupList = zmsImpl.getGroups(ctx, domainName, Boolean.FALSE, tagKey, "val1");
        hasGroupWithTags(groupList, noTagsGroup, tagKey, tagValues, 3);
        assertEquals(groupList.getList().size(), 1);

        // get groups with only tag key
        groupList = zmsImpl.getGroups(ctx, domainName, Boolean.TRUE, tagKey, null);
        hasGroupWithTags(groupList, noTagsGroup, tagKey, tagValues, 3);
        assertEquals(groupList.getList().size(), 1);

        // now create a different tags Map, part is from tagValues
        Map<String, TagValueList> tagsMap = new HashMap<>();
        List<String> modifiedTagValues = Arrays.asList("val1", "new-val");
        String newTagKey = "newTagKey";
        List<String> newTagValues = Arrays.asList("val4", "val5", "val6");
        tagsMap.put(tagKey, new TagValueList().setList(modifiedTagValues));
        tagsMap.put(newTagKey, new TagValueList().setList(newTagValues));
        group.setTags(tagsMap);
        zmsImpl.putGroup(ctx, domainName, noTagsGroup, auditRef, false, null, group);

        // 1 tags should be presented
        groupList = zmsImpl.getGroups(ctx, domainName, Boolean.TRUE, null, null);
        hasGroupWithTags(groupList, noTagsGroup, tagKey, modifiedTagValues, 2);
        hasGroupWithTags(groupList, noTagsGroup, newTagKey, newTagValues, 3);

        // get groups with exact tag value
        groupList = zmsImpl.getGroups(ctx, domainName, Boolean.TRUE, tagKey, "val1");
        hasGroupWithTags(groupList, noTagsGroup, tagKey, modifiedTagValues, 2);
        assertEquals(groupList.getList().size(), 1);

        // get groups with non-existent tag value
        groupList = zmsImpl.getGroups(ctx, domainName, Boolean.TRUE, tagKey, "val2");
        assertEquals(groupList.getList().size(), 0);

        // get groups with new tag key
        groupList = zmsImpl.getGroups(ctx, domainName, Boolean.TRUE, tagKey, null);
        hasGroupWithTags(groupList, noTagsGroup, newTagKey, newTagValues, 3);
        assertEquals(groupList.getList().size(), 1);
    }

    @Test
    public void testUpdateGroupMetaWithoutTags() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "update-group-meta-without-tags";
        final String updateGroupMetaTag = "tag-key-update-group-meta";
        final List<String> updateGroupMetaTagValues = Collections.singletonList("update-meta-value");

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // put group without tags
        final String groupName = "groupTagsUpdateMeta";
        Group group = zmsTestInitializer.createGroupObject(domainName, groupName, null);
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group);

        // no tags should be presented
        Groups groupList = zmsImpl.getGroups(ctx, domainName, Boolean.TRUE, updateGroupMetaTag, null);
        assertTrue(groupList.getList().isEmpty());

        GroupMeta gm = new GroupMeta()
                .setTags(Collections.singletonMap(updateGroupMetaTag,
                        new TagValueList().setList(updateGroupMetaTagValues)));

        // update group tags using group meta
        zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, null, gm);

        // assert that updateGroupMetaTag is in group tags
        groupList = zmsImpl.getGroups(ctx, domainName, Boolean.TRUE, updateGroupMetaTag, null);
        hasGroupWithTags(groupList, groupName, updateGroupMetaTag, updateGroupMetaTagValues, 1);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testUpdateGroupMetaWithExistingTag() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "update-group-meta-with-existing-tag";
        final String tagKey = "tag-key";
        final String updateGroupMetaTag = "tag-key-update-group-meta-exist-tag";
        final List<String> updateGroupMetaTagValues = Collections.singletonList("update-meta-value");

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // put group with tag
        final String groupName = "groupWithTagUpdateMeta";
        List<String> singleTagValue = Collections.singletonList("val1");
        Group group = zmsTestInitializer.createGroupObject(domainName, groupName, null);
        group.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(singleTagValue)));
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group);

        // tag tagKey should be presented
        Groups groupList = zmsImpl.getGroups(ctx, domainName, Boolean.TRUE, tagKey, null);
        hasGroupWithTags(groupList, groupName, tagKey, singleTagValue, 1);

        GroupMeta gm = new GroupMeta()
                .setTags(Collections.singletonMap(updateGroupMetaTag,
                        new TagValueList().setList(updateGroupMetaTagValues)));

        // update group tags using group meta
        zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, null, gm);

        // group should contain only the new tag
        groupList = zmsImpl.getGroups(ctx, domainName, Boolean.TRUE, updateGroupMetaTag, null);
        hasGroupWithTags(groupList, groupName, updateGroupMetaTag, updateGroupMetaTagValues, 1);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    private void hasGroupWithTags(Groups groupList, String groupName, String tagKey, List<String> tagValues, int tagValuesLength) {
        Group group = getGroup(groupList, groupName);
        Assert.assertNotNull(group);
        if (tagKey != null) {
            if (tagValues != null) {
                Assert.assertEquals(group.getTags().get(tagKey).getList().size(), tagValuesLength);
                for (String tagValue : tagValues) {
                    Assert.assertTrue(hasTag(group, tagKey, tagValue));
                }
            } else {
                Assert.assertTrue(hasTag(group, tagKey, null));
            }
        }
    }

    private boolean hasTag(Group group, String tagKey, String tagValue) {
        TagValueList tagValues = group.getTags().get(tagKey);
        if (tagValue != null) {
            return tagValues.getList().contains(tagValue);
        }
        return !tagValues.getList().isEmpty();
    }

    private Group getGroup(Groups groupList, String groupName) {
        return groupList.getList().stream()
                .filter(g -> AthenzUtils.extractGroupName(g.getName()).equalsIgnoreCase(groupName))
                .findFirst()
                .get();
    }
}
