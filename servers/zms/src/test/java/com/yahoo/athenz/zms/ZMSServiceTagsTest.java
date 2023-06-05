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
import com.yahoo.athenz.zms.store.ObjectStoreConnection;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.*;

import java.util.*;

import static org.testng.Assert.*;

public class ZMSServiceTagsTest {


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
            deleteAllCreatedServices();
        }

        @AfterMethod
        public void clearConnections() {
            zmsTestInitializer.clearConnections();
            deleteAllCreatedServices();
        }

        void deleteAllCreatedServices() {
            ServiceIdentities serviceList = zmsImpl.getServiceIdentities(ctx, domainName, false, null,null, null);
            for (ServiceIdentity service : serviceList.getList()) {
                String serviceName = service.getName().toString().replace(domainName + ".", "");
                    zmsImpl.deleteServiceIdentity(ctx, domainName, serviceName, "");
            }
        }

        @Test
        public void testQueryPutServiceWithTags() {

            final String auditRef = zmsTestInitializer.getAuditRef();

            // put service with multiple tags
            final String serviceWithTags = "serviceWithTags";
            final String tagKey = "tag-key";
            List<String> tagValues = Arrays.asList("val1", "val2");
            ServiceIdentity service = zmsTestInitializer.createServiceObject(domainName, serviceWithTags, "http://localhost", "/usr/bin/java", "root",
                    "users", "host1");
            service.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(tagValues)));
            zmsImpl.putServiceIdentity(ctx, domainName, serviceWithTags, auditRef, false, service);

            // put service with single tags
            final String serviceSingleTag = "serviceSingleTag";
            List<String> singleTagValue = Collections.singletonList("val1");
            service = zmsTestInitializer.createServiceObject(domainName, serviceSingleTag, "http://localhost", "/usr/bin/java", "root",
                    "users", "host1");
            service.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(singleTagValue)));
            zmsImpl.putServiceIdentity(ctx, domainName, serviceSingleTag, auditRef, false, service);

            //put service without tags
            final String noTagsService = "noTagsService";
            service = zmsTestInitializer.createServiceObject(domainName, noTagsService, "http://localhost", "/usr/bin/java", "root",
                    "users", "host1");
            zmsImpl.putServiceIdentity(ctx, domainName, noTagsService, auditRef, false, service);

            // get services without tags query - both tags should be presented
            ServiceIdentities serviceList = zmsImpl.getServiceIdentities(ctx, domainName, Boolean.TRUE, null,null, null);
            hasServiceWithTags(serviceList, serviceWithTags, tagKey, tagValues, 2);
            hasServiceWithTags(serviceList, serviceSingleTag, tagKey, singleTagValue, 1);
            hasServiceWithTags(serviceList, noTagsService, null, null, 0);

            // get services with exact tag value
            serviceList = zmsImpl.getServiceIdentities(ctx, domainName, Boolean.TRUE, null,tagKey, "val1");
            hasServiceWithTags(serviceList, serviceWithTags, tagKey, tagValues, 2);
            hasServiceWithTags(serviceList, serviceSingleTag, tagKey, singleTagValue, 1);
            // ensure there are no more services
            assertEquals(serviceList.getList().size(), 2);

            // get services with exact tag value
            serviceList = zmsImpl.getServiceIdentities(ctx, domainName, Boolean.TRUE, null, tagKey, "val2");
            hasServiceWithTags(serviceList, serviceWithTags, tagKey, tagValues, 2);
            // ensure there are no more services
            assertEquals(serviceList.getList().size(), 1);

            // get services with only tag key
            serviceList = zmsImpl.getServiceIdentities(ctx, domainName, Boolean.TRUE, null, tagKey, null);
            hasServiceWithTags(serviceList, serviceWithTags, tagKey, tagValues, 2);
            hasServiceWithTags(serviceList, serviceSingleTag, tagKey, singleTagValue, 1);
            // ensure there are no more services
            assertEquals(serviceList.getList().size(), 2);
        }

        public void testProcessUpdateServiceTags() {
            ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);

        }


        @Test
        public void testServiceTagsLimit() {

            final String auditRef = zmsTestInitializer.getAuditRef();

            // define limit of 3 service tags
            System.setProperty(ZMSConsts.ZMS_PROP_QUOTA_SERVICE_TAG, "3");
            ZMSImpl zmsTest = zmsTestInitializer.zmsInit();

            final String serviceName = "serviceWithTagLimit";
            final String tagKey = "tag-key";

            //insert service with 4 tags
            List<String> tagValues = Arrays.asList("val1", "val2", "val3", "val4");
            ServiceIdentity service = zmsTestInitializer.createServiceObject(domainName, serviceName, "http://localhost", "/usr/bin/java", "root",
                    "users", "host1");
            service.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(tagValues)));
            try {
                zmsTest.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, service);
                fail();
            } catch(ResourceException ex) {
                assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
                assertTrue(ex.getMessage().contains("service tag quota exceeded - limit: 3, current tags count: 0, new tags count: 4"));
            }

            try {
                // service should not be created if fails to process tags.
                zmsTest.getServiceIdentity(ctx, domainName, serviceName);
                fail();
            } catch(ResourceException ex) {
                assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
            }

            System.clearProperty(ZMSConsts.ZMS_PROP_QUOTA_SERVICE_TAG);
        }


        @Test
        public void testQueryUpdateServiceWithTags() {

            final String auditRef = zmsTestInitializer.getAuditRef();


            final String tagKey = "tag-key-update";
            //put service without tags
            final String noTagsService = "noTagsService";
            ServiceIdentity service = zmsTestInitializer.createServiceObject(domainName, noTagsService, "http://localhost", "/usr/bin/java", "root",
                    "users", "host1");
            zmsImpl.putServiceIdentity(ctx, domainName, noTagsService, auditRef, false, service);

            // assert there are no tags
            ServiceIdentities serviceList = zmsImpl.getServiceIdentities(ctx, domainName, Boolean.TRUE, null, null, null);
            hasServiceWithTags(serviceList, noTagsService, null, null, 0);

            // update tag list
            List<String> tagValues = Arrays.asList("val1", "val2", "val3");
            service.setTags(Collections.singletonMap(tagKey, new TagValueList().setList(tagValues)));
            zmsImpl.putServiceIdentity(ctx, domainName, noTagsService, auditRef, false, service);

            // 1 tags should be presented
            serviceList = zmsImpl.getServiceIdentities(ctx, domainName, Boolean.TRUE, null, null,null);
            hasServiceWithTags(serviceList, noTagsService, tagKey, tagValues, 3);

            // get services with exact tag value
            serviceList = zmsImpl.getServiceIdentities(ctx, domainName, Boolean.FALSE, null, tagKey, "val1");
            hasServiceWithTags(serviceList, noTagsService, tagKey, tagValues, 3);
            assertEquals(serviceList.getList().size(), 1);

            // get services with only tag key
            serviceList = zmsImpl.getServiceIdentities(ctx, domainName, Boolean.TRUE, null, tagKey, null);
            hasServiceWithTags(serviceList, noTagsService, tagKey, tagValues, 3);
            assertEquals(serviceList.getList().size(), 1);

            // now create a different tags Map, part is from tagValues
            String newServiceName = "newService";
            Map<String, TagValueList> tagsMap = new HashMap<>();
            List<String> newTagValues1 = Arrays.asList("val1", "new-val");
            String newTagKey = "newTagKey";
            List<String> newTagValues2 = Arrays.asList("val4", "val5", "val6");
            tagsMap.put(tagKey, new TagValueList().setList(newTagValues1));
            tagsMap.put(newTagKey, new TagValueList().setList(newTagValues2));
            ServiceIdentity newService = zmsTestInitializer.createServiceObject(domainName, newServiceName, "http://localhost", "/usr/bin/java", "root",
                    "users", "host1");
            newService.setTags(tagsMap);
            zmsImpl.putServiceIdentity(ctx, domainName, newServiceName, auditRef, false, newService);

            // 3 tags should be presented there is 1 initial service in the sys.auth domain
            serviceList = zmsImpl.getServiceIdentities(ctx, domainName, Boolean.TRUE, null, null, null);
            hasServiceWithTags(serviceList, noTagsService, tagKey, tagValues, 3);
            hasServiceWithTags(serviceList, newServiceName, tagKey, newTagValues1, 2);
            hasServiceWithTags(serviceList, newServiceName, newTagKey, newTagValues2, 3);
            assertEquals(serviceList.getList().size(), 2);

            // get services with exact tag value
            serviceList = zmsImpl.getServiceIdentities(ctx, domainName, Boolean.TRUE, null, tagKey, "val1");
            hasServiceWithTags(serviceList, noTagsService, tagKey, tagValues, 3);
            hasServiceWithTags(serviceList, newServiceName, tagKey, newTagValues1, 2);
            hasServiceWithTags(serviceList, newServiceName, newTagKey, newTagValues2, 3);
            assertEquals(serviceList.getList().size(), 2);

            // get services with non-existent tag value
            serviceList = zmsImpl.getServiceIdentities(ctx, domainName, Boolean.TRUE, null, tagKey, "val2");
            hasServiceWithTags(serviceList, noTagsService, tagKey, tagValues, 3);
            assertEquals(serviceList.getList().size(), 1);

            // get services with new tag key
            serviceList = zmsImpl.getServiceIdentities(ctx, domainName, Boolean.TRUE, null, newTagKey, null);
            hasServiceWithTags(serviceList, newServiceName, newTagKey, newTagValues2, 3);
            assertEquals(serviceList.getList().size(), 1);
        }

        private void hasServiceWithTags(ServiceIdentities serviceList, String serviceName, String tagKey, List<String> tagValues, int tagValuesLength) {
            ServiceIdentity service = getService(serviceList, serviceName);
            Assert.assertNotNull(service);
            if (tagKey != null) {
                if (tagValues != null) {
                    Assert.assertEquals(service.getTags().get(tagKey).getList().size(), tagValuesLength);
                    for (String tagValue : tagValues) {
                        Assert.assertTrue(hasTag(service, tagKey, tagValue));
                    }
                } else {
                    Assert.assertTrue(hasTag(service, tagKey, null));
                }
            }
        }

        private boolean hasTag(ServiceIdentity service, String tagKey, String tagValue) {
            TagValueList tagValues = service.getTags().get(tagKey);
            if (tagValue != null) {
                return tagValues.getList().contains(tagValue);
            }
            return !tagValues.getList().isEmpty();
        }

        private ServiceIdentity getService(ServiceIdentities serviceList, String serviceName) {
            return serviceList.getList().stream()
                    .filter(g -> AthenzUtils.extractPrincipalServiceName(g.getName()).equalsIgnoreCase(serviceName))
                    .findFirst()
                    .get();
        }
    }

