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
package io.athenz.server.aws.common.store.impl;

import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_AWS_BUCKET_NAME;
import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_AWS_REGION_NAME;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

import java.util.*;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;

public class S3FilteredChangeLogStoreTest {

    @BeforeMethod
    public void setup() {
        System.setProperty(ZTS_PROP_AWS_BUCKET_NAME, "s3-unit-test-bucket-name");
        System.setProperty(ZTS_PROP_AWS_REGION_NAME, "test-region");
    }

    @Test
    public void testListObjectsFilteredNoModTime() {

        Set<String> supportedDomains = new HashSet<>(Arrays.asList("iaas", "cd.docker"));
        MockS3FilteredChangeLogStore store = new MockS3FilteredChangeLogStore(supportedDomains);

        ListObjectsV2Response mockResponse = mock(ListObjectsV2Response.class);
        ArrayList<S3Object> objectList = new ArrayList<>();
        objectList.add(S3Object.builder().key("iaas").build());
        objectList.add(S3Object.builder().key("iaas.athenz").build());
        objectList.add(S3Object.builder().key("cd.docker").build());
        objectList.add(S3Object.builder().key("platforms").build());

        when(mockResponse.contents()).thenReturn(objectList);
        when(mockResponse.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockResponse);

        ArrayList<String> domains = new ArrayList<>();
        store.listObjects(store.awsS3Client, domains, 0);

        assertEquals(domains.size(), 2);
        assertTrue(domains.contains("iaas"));
        assertTrue(domains.contains("cd.docker"));
        assertFalse(domains.contains("iaas.athenz"));
        assertFalse(domains.contains("platforms"));
    }

    @Test
    public void testListObjectsFilteredWithModTime() {

        Set<String> supportedDomains = new HashSet<>(Arrays.asList("iaas", "iaas.athenz", "cd.docker"));
        MockS3FilteredChangeLogStore store = new MockS3FilteredChangeLogStore(supportedDomains);

        ListObjectsV2Response mockResponse = mock(ListObjectsV2Response.class);
        ArrayList<S3Object> objectList = new ArrayList<>();
        objectList.add(S3Object.builder().key("iaas").lastModified((new Date(100)).toInstant()).build());
        objectList.add(S3Object.builder().key("iaas.athenz").lastModified((new Date(200)).toInstant()).build());
        objectList.add(S3Object.builder().key("cd.docker").lastModified((new Date(200)).toInstant()).build());
        objectList.add(S3Object.builder().key("platforms").lastModified((new Date(200)).toInstant()).build());

        when(mockResponse.contents()).thenReturn(objectList);
        when(mockResponse.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockResponse);

        ArrayList<String> domains = new ArrayList<>();
        store.listObjects(store.awsS3Client, domains, (new Date(150)).getTime());

        // iaas filtered out by modTime (100 <= 150), platforms filtered out by domain filter
        assertEquals(domains.size(), 2);
        assertTrue(domains.contains("iaas.athenz"));
        assertTrue(domains.contains("cd.docker"));
    }

    @Test
    public void testListObjectsFilteredMultiplePages() {

        Set<String> supportedDomains = new HashSet<>(Arrays.asList("iaas", "platforms"));
        MockS3FilteredChangeLogStore store = new MockS3FilteredChangeLogStore(supportedDomains);

        ListObjectsV2Response mockResponse = mock(ListObjectsV2Response.class);

        ArrayList<S3Object> objectList1 = new ArrayList<>();
        objectList1.add(S3Object.builder().key("iaas").build());
        objectList1.add(S3Object.builder().key("iaas.athenz").build());

        ArrayList<S3Object> objectList2 = new ArrayList<>();
        objectList2.add(S3Object.builder().key("cd.docker").build());
        objectList2.add(S3Object.builder().key("platforms").build());

        when(mockResponse.contents())
                .thenReturn(objectList1)
                .thenReturn(objectList2);
        when(mockResponse.isTruncated())
                .thenReturn(true)
                .thenReturn(false);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockResponse);

        ArrayList<String> domains = new ArrayList<>();
        store.listObjects(store.awsS3Client, domains, 0);

        assertEquals(domains.size(), 2);
        assertTrue(domains.contains("iaas"));
        assertTrue(domains.contains("platforms"));
    }

    @Test
    public void testListObjectsEmptyFilter() {

        Set<String> supportedDomains = new HashSet<>();
        MockS3FilteredChangeLogStore store = new MockS3FilteredChangeLogStore(supportedDomains);

        ListObjectsV2Response mockResponse = mock(ListObjectsV2Response.class);
        ArrayList<S3Object> objectList = new ArrayList<>();
        objectList.add(S3Object.builder().key("iaas").build());
        objectList.add(S3Object.builder().key("cd.docker").build());

        when(mockResponse.contents()).thenReturn(objectList);
        when(mockResponse.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockResponse);

        ArrayList<String> domains = new ArrayList<>();
        store.listObjects(store.awsS3Client, domains, 0);

        assertEquals(domains.size(), 0);
    }

    @Test
    public void testListObjectsFilteredSkipsHiddenDomains() {

        Set<String> supportedDomains = new HashSet<>(Arrays.asList("iaas", ".hidden"));
        MockS3FilteredChangeLogStore store = new MockS3FilteredChangeLogStore(supportedDomains);

        ListObjectsV2Response mockResponse = mock(ListObjectsV2Response.class);
        ArrayList<S3Object> objectList = new ArrayList<>();
        objectList.add(S3Object.builder().key("iaas").build());
        objectList.add(S3Object.builder().key(".hidden").build());
        objectList.add(S3Object.builder().key("cd.docker").build());

        when(mockResponse.contents()).thenReturn(objectList);
        when(mockResponse.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockResponse);

        ArrayList<String> domains = new ArrayList<>();
        store.listObjects(store.awsS3Client, domains, 0);

        assertEquals(domains.size(), 1);
        assertTrue(domains.contains("iaas"));
        assertFalse(domains.contains(".hidden"));
    }

    @Test
    public void testGetServerDomainListFiltered() {

        Set<String> supportedDomains = new HashSet<>(Collections.singletonList("iaas"));
        MockS3FilteredChangeLogStore store = new MockS3FilteredChangeLogStore(supportedDomains);

        ListObjectsV2Response mockResponse = mock(ListObjectsV2Response.class);
        ArrayList<S3Object> objectList = new ArrayList<>();
        objectList.add(S3Object.builder().key("iaas").build());
        objectList.add(S3Object.builder().key("iaas.athenz").build());
        objectList.add(S3Object.builder().key("cd.docker").build());

        when(mockResponse.contents()).thenReturn(objectList);
        when(mockResponse.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockResponse);

        Set<String> domains = store.getServerDomainList();

        assertEquals(domains.size(), 1);
        assertTrue(domains.contains("iaas"));
    }

    @Test
    public void testGetLocalDomainListFiltered() {

        Set<String> supportedDomains = new HashSet<>(Arrays.asList("iaas", "cd.docker"));
        MockS3FilteredChangeLogStore store = new MockS3FilteredChangeLogStore(supportedDomains);

        ListObjectsV2Response mockResponse = mock(ListObjectsV2Response.class);
        ArrayList<S3Object> objectList = new ArrayList<>();
        objectList.add(S3Object.builder().key("iaas").build());
        objectList.add(S3Object.builder().key("iaas.athenz").build());
        objectList.add(S3Object.builder().key("cd.docker").build());
        objectList.add(S3Object.builder().key("platforms").build());

        when(mockResponse.contents()).thenReturn(objectList);
        when(mockResponse.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockResponse);

        List<String> domains = store.getLocalDomainList();

        assertEquals(domains.size(), 2);
        assertTrue(domains.contains("iaas"));
        assertTrue(domains.contains("cd.docker"));
    }

    static class MockS3FilteredChangeLogStore extends S3FilteredChangeLogStore {

        S3Client awsS3Client;

        public MockS3FilteredChangeLogStore(Set<String> supportedDomains) {
            super(supportedDomains);
            awsS3Client = mock(S3Client.class);
        }

        @Override
        S3Client getS3Client() {
            if (awsS3Client == null) {
                awsS3Client = mock(S3Client.class);
            }
            return awsS3Client;
        }
    }
}
