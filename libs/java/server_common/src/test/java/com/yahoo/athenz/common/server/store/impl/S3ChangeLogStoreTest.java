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
package com.yahoo.athenz.common.server.store.impl;

import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_AWS_BUCKET_NAME;
import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_AWS_REGION_NAME;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

import com.amazonaws.services.s3.AmazonS3;
import com.yahoo.athenz.zms.JWSDomain;
import com.yahoo.rdl.Timestamp;
import org.apache.http.client.methods.HttpRequestBase;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.ListObjectsRequest;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectInputStream;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zms.SignedDomains;

public class S3ChangeLogStoreTest {

    private static final String DEFAULT_TIMEOUT_SECONDS = "athenz.zts.bucket.threads.timeout";
    private final int defaultTimeoutSeconds = Integer.parseInt(System.getProperty(DEFAULT_TIMEOUT_SECONDS, "1800"));

    @BeforeMethod
    public void setup() {
        System.setProperty(ZTS_PROP_AWS_BUCKET_NAME, "s3-unit-test-bucket-name");
        System.setProperty(ZTS_PROP_AWS_REGION_NAME, "test-region");
    }

    @Test
    public void testInvalidBucketName() {
        System.clearProperty(ZTS_PROP_AWS_BUCKET_NAME);
        try {
            new S3ChangeLogStore();
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("S3 Bucket name cannot be null"));
        }

        System.setProperty(ZTS_PROP_AWS_BUCKET_NAME, "");
        try {
            new S3ChangeLogStore();
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("S3 Bucket name cannot be null"));
        }

        System.setProperty(ZTS_PROP_AWS_BUCKET_NAME, "s3-unit-test-bucket-name");
        new S3ChangeLogStore();
    }

    @Test
    public void testFullRefreshSupport() {
        S3ChangeLogStore store = new S3ChangeLogStore();
        assertFalse(store.supportsFullRefresh());
    }
    
    @Test
    public void testNoOpMethods() {
        S3ChangeLogStore store = new S3ChangeLogStore();
        store.removeLocalDomain("iaas.athenz");
        store.saveLocalDomain("iaas.athenz", new SignedDomain());
        store.saveLocalDomain("iaas.athenz", new JWSDomain());
    }
    
    @Test
    public void testSetLastModificationTimestamp() {
        S3ChangeLogStore store = new S3ChangeLogStore();
        assertEquals(store.lastModTime, 0);
        
        store.setLastModificationTimestamp("12345");
        assertEquals(store.lastModTime, 12345);

        store.setLastModificationTimestamp(null);
        assertEquals(store.lastModTime, 0);
    }

    @Test
    public void testGetLocalSignedDomainList() throws IOException {

        MockS3ChangeLogStore store = new MockS3ChangeLogStore(0);

        InputStream is1 = new FileInputStream("src/test/resources/iaas.json");
        MockS3ObjectInputStream s3Is1 = new MockS3ObjectInputStream(is1, null);

        InputStream is2 = new FileInputStream("src/test/resources/iaas.json");
        MockS3ObjectInputStream s3Is2 = new MockS3ObjectInputStream(is2, null);

        S3Object object = mock(S3Object.class);
        when(object.getObjectContent()).thenReturn(s3Is1).thenReturn(s3Is2);

        when(store.awsS3Client.getObject("s3-unit-test-bucket-name", "iaas")).thenReturn(object);
        ObjectListing mockObjectListing = mock(ObjectListing.class);
        when(store.awsS3Client.listObjects(any(ListObjectsRequest.class))).thenReturn(mockObjectListing);
        List<S3ObjectSummary> tempList = new ArrayList<>();
        S3ObjectSummary s3ObjectSummary = mock(S3ObjectSummary.class);
        when(s3ObjectSummary.getKey()).thenReturn("iaas");
        tempList.add(s3ObjectSummary);
        when(mockObjectListing.getObjectSummaries()).thenReturn(tempList);

        List<String> temp = store.getLocalDomainList();
        assertNotNull(temp);

        SignedDomain signedDomain = store.getLocalSignedDomain("iaas");
        assertNotNull(signedDomain);

        is1.close();
        is2.close();
    }

    @Test
    public void testGetAllSignedDomainsException() throws IOException {
        testGetAllDomainsException(false);
    }

    @Test
    public void testGetAllJWSDomainsException() throws IOException {
        testGetAllDomainsException(true);
    }

    public void testGetAllDomainsException(boolean jwsSupport) throws IOException {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(1);
        store.setJWSDomainSupport(jwsSupport);

        InputStream is1 = new FileInputStream("src/test/resources/iaas.json");
        MockS3ObjectInputStream s3Is1 = new MockS3ObjectInputStream(is1, null);

        InputStream is2 = new FileInputStream("src/test/resources/iaas.json");
        MockS3ObjectInputStream s3Is2 = new MockS3ObjectInputStream(is2, null);

        S3Object object = mock(S3Object.class);
        when(object.getObjectContent()).thenReturn(s3Is1).thenReturn(s3Is2);

        when(store.awsS3Client.getObject("s3-unit-test-bucket-name", "iaas")).thenReturn(object);
        ObjectListing mockObjectListing = mock(ObjectListing.class);
        when(store.awsS3Client.listObjects(any(ListObjectsRequest.class))).thenReturn(mockObjectListing);
        List<S3ObjectSummary> tempList = new ArrayList<>();
        S3ObjectSummary s3ObjectSummary = mock(S3ObjectSummary.class);
        when(s3ObjectSummary.getKey()).thenReturn("iaas");
        tempList.add(s3ObjectSummary);
        when(mockObjectListing.getObjectSummaries()).thenReturn(tempList);

        List<String> temp = new LinkedList<>();
        temp.add("iaas");

        try {
            when(store.executorService.awaitTermination(defaultTimeoutSeconds, TimeUnit.SECONDS)).thenThrow(new InterruptedException());
            assertFalse(store.getAllDomains(temp));
            assertFalse(store.getLocalDomainList().isEmpty());
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        is1.close();
        is2.close();
    }

    @Test
    public void testListObjectsAllObjectsNoPage() {

        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        ArrayList<S3ObjectSummary> objectList = new ArrayList<>();
        S3ObjectSummary objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas");
        objectList.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas.athenz");
        objectList.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey(".date");
        objectList.add(objectSummary);

        ObjectListing objectListing = mock(ObjectListing.class);
        when(objectListing.getObjectSummaries()).thenReturn(objectList);
        when(objectListing.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);

        ArrayList<String> domains = new ArrayList<>();
        store.listObjects(store.awsS3Client, domains, 0);

        assertEquals(domains.size(), 2);
        assertTrue(domains.contains("iaas"));
        assertTrue(domains.contains("iaas.athenz"));
    }

    @Test
    public void testListObjectsAllObjectsNoPageModTime() {

        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        ArrayList<S3ObjectSummary> objectList = new ArrayList<>();
        S3ObjectSummary objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas");
        objectSummary.setLastModified(new Date(100));
        objectList.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas.athenz");
        objectSummary.setLastModified(new Date(200));
        objectList.add(objectSummary);

        ObjectListing objectListing = mock(ObjectListing.class);
        when(objectListing.getObjectSummaries()).thenReturn(objectList);
        when(objectListing.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);

        ArrayList<String> domains = new ArrayList<>();
        store.listObjects(store.awsS3Client, domains, (new Date(150)).getTime());

        assertEquals(domains.size(), 1);
        assertTrue(domains.contains("iaas.athenz"));
    }

    @Test
    public void testListObjectsAllObjectsMultiplePages() {

        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        ArrayList<S3ObjectSummary> objectList1 = new ArrayList<>();
        S3ObjectSummary objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas");
        objectList1.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas.athenz");
        objectList1.add(objectSummary);

        ArrayList<S3ObjectSummary> objectList2 = new ArrayList<>();
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("cd");
        objectList2.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("cd.docker");
        objectList2.add(objectSummary);

        ArrayList<S3ObjectSummary> objectList3 = new ArrayList<>();
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("platforms");
        objectList3.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("platforms.mh2");
        objectList3.add(objectSummary);

        ObjectListing objectListing = mock(ObjectListing.class);
        when(objectListing.getObjectSummaries())
            .thenReturn(objectList1)
            .thenReturn(objectList2)
            .thenReturn(objectList3);
        when(objectListing.isTruncated())
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        when(store.awsS3Client.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);
        when(store.awsS3Client.listNextBatchOfObjects(any(ObjectListing.class))).thenReturn(objectListing);

        ArrayList<String> domains = new ArrayList<>();
        store.listObjects(store.awsS3Client, domains, 0);

        assertEquals(domains.size(), 6);
        assertTrue(domains.contains("iaas"));
        assertTrue(domains.contains("iaas.athenz"));
        assertTrue(domains.contains("cd"));
        assertTrue(domains.contains("cd.docker"));
        assertTrue(domains.contains("platforms"));
        assertTrue(domains.contains("platforms.mh2"));
    }

    @Test
    public void testListObjectsAllObjectsErrorCondition() {

        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        ArrayList<S3ObjectSummary> objectList1 = new ArrayList<>();
        S3ObjectSummary objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas");
        objectList1.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas.athenz");
        objectList1.add(objectSummary);

        ArrayList<S3ObjectSummary> objectList2 = new ArrayList<>();
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("cd");
        objectList2.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("cd.docker");
        objectList2.add(objectSummary);

        ObjectListing objectListing = mock(ObjectListing.class);
        when(objectListing.getObjectSummaries())
                .thenReturn(objectList1)
                .thenReturn(objectList2);
        when(objectListing.isTruncated())
                .thenReturn(true);
        when(store.awsS3Client.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);
        when(store.awsS3Client.listNextBatchOfObjects(any(ObjectListing.class)))
                .thenReturn(objectListing)
                .thenReturn(null);

        ArrayList<String> domains = new ArrayList<>();
        store.listObjects(store.awsS3Client, domains, 0);

        assertEquals(domains.size(), 4);
        assertTrue(domains.contains("iaas"));
        assertTrue(domains.contains("iaas.athenz"));
        assertTrue(domains.contains("cd"));
        assertTrue(domains.contains("cd.docker"));
    }

    @Test
    public void testListObjectsAllObjectsMultiplePagesModTime() {
        
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();
        
        ArrayList<S3ObjectSummary> objectList1 = new ArrayList<>();
        S3ObjectSummary objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas");
        objectSummary.setLastModified(new Date(100));
        objectList1.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas.athenz");
        objectSummary.setLastModified(new Date(100));
        objectList1.add(objectSummary);
        
        ArrayList<S3ObjectSummary> objectList2 = new ArrayList<>();
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("cd");
        objectSummary.setLastModified(new Date(100));
        objectList2.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("cd.docker");
        objectSummary.setLastModified(new Date(200));
        objectList2.add(objectSummary);
        
        ArrayList<S3ObjectSummary> objectList3 = new ArrayList<>();
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("platforms");
        objectSummary.setLastModified(new Date(200));
        objectList3.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("platforms.mh2");
        objectSummary.setLastModified(new Date(200));
        objectList3.add(objectSummary);
        
        ObjectListing objectListing = mock(ObjectListing.class);
        when(objectListing.getObjectSummaries())
            .thenReturn(objectList1)
            .thenReturn(objectList2)
            .thenReturn(objectList3);
        when(objectListing.isTruncated())
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        when(store.awsS3Client.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);
        when(store.awsS3Client.listNextBatchOfObjects(any(ObjectListing.class))).thenReturn(objectListing);

        ArrayList<String> domains = new ArrayList<>();
        store.listObjects(store.awsS3Client, domains, (new Date(150)).getTime());
        
        assertEquals(domains.size(), 3);
        assertTrue(domains.contains("cd.docker"));
        assertTrue(domains.contains("platforms"));
        assertTrue(domains.contains("platforms.mh2"));
    }
    
    @Test
    public void testGetLocalSignedDomains() {
        
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();
        ArrayList<S3ObjectSummary> objectList = new ArrayList<>();
        S3ObjectSummary objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas");
        objectList.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas.athenz");
        objectList.add(objectSummary);
        
        ObjectListing objectListing = mock(ObjectListing.class);
        when(objectListing.getObjectSummaries()).thenReturn(objectList);
        when(objectListing.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);
        
        // verify that our last mod time is 0 before the call
        
        assertEquals(store.lastModTime, 0);
        
        // retrieve the list of domains
        
        List<String> domains = store.getLocalDomainList();
        
        assertEquals(domains.size(), 2);
        assertTrue(domains.contains("iaas"));
        assertTrue(domains.contains("iaas.athenz"));
        
        // also verify that last mod time is updated
        
        assertTrue(store.lastModTime > 0);

        // get the list again

        domains = store.getLocalDomainList();

        assertEquals(domains.size(), 2);
        assertTrue(domains.contains("iaas"));
        assertTrue(domains.contains("iaas.athenz"));
    }

    @Test
    public void testGetServerDomains() {
        
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();
        ArrayList<S3ObjectSummary> objectList = new ArrayList<>();
        S3ObjectSummary objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas");
        objectList.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas.athenz");
        objectList.add(objectSummary);
        
        ObjectListing objectListing = mock(ObjectListing.class);
        when(objectListing.getObjectSummaries()).thenReturn(objectList);
        when(objectListing.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);
        
        // verify that our last mod time is 0 before the call
        
        assertEquals(store.lastModTime, 0);
        
        // retrieve the list of domains
        
        Set<String> domains = store.getServerDomainList();
        
        assertEquals(domains.size(), 2);
        assertTrue(domains.contains("iaas"));
        assertTrue(domains.contains("iaas.athenz"));
        
        // also verify that last mod time is not updated
        
        assertEquals(store.lastModTime, 0);
    }
    
    @Test
    public void testGetSignedDomainNotFound() {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();
        when(store.awsS3Client.getObject(any(GetObjectRequest.class))).thenReturn(null);
        
        assertNull(store.getSignedDomain(store.awsS3Client, "iaas"));
    }
    
    @Test
    public void testGetSignedDomainClientException() {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();
        
        when(store.awsS3Client.getObject(any(GetObjectRequest.class))).thenThrow(new AmazonClientException("failed client operation"));
        assertNull(store.getSignedDomain(store.awsS3Client, "iaas"));
    }
    
    @Test
    public void testGetSignedDomainServiceException() {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();
        
        when(store.awsS3Client.getObject(any(GetObjectRequest.class))).thenThrow(new AmazonServiceException("failed server operation"));
        assertNull(store.getSignedDomain(store.awsS3Client, "iaas"));
    }
    
    private static class MockS3ObjectInputStream extends S3ObjectInputStream {
        MockS3ObjectInputStream(InputStream in, HttpRequestBase httpRequest) {
            super(in, httpRequest);
        }
    }
    
    @Test
    public void testGetSignedDomainInternal() throws IOException {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        InputStream is = new FileInputStream("src/test/resources/iaas.json");
        MockS3ObjectInputStream s3Is = new MockS3ObjectInputStream(is, null);
        
        S3Object object = mock(S3Object.class);
        when(object.getObjectContent()).thenReturn(s3Is);

        when(store.awsS3Client.getObject("s3-unit-test-bucket-name", "iaas")).thenReturn(object);
        
        SignedDomain signedDomain = store.getSignedDomain(store.awsS3Client, "iaas");
        assertNotNull(signedDomain);
        DomainData domainData = signedDomain.getDomain();
        assertNotNull(domainData);
        assertEquals(domainData.getName(), "iaas");
        is.close();
    }
    
    @Test
    public void testGetLocalSignedDomain() throws IOException {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        InputStream is1 = new FileInputStream("src/test/resources/iaas.json");
        MockS3ObjectInputStream s3Is1 = new MockS3ObjectInputStream(is1, null);

        InputStream is2 = new FileInputStream("src/test/resources/iaas.json");
        MockS3ObjectInputStream s3Is2 = new MockS3ObjectInputStream(is2, null);

        S3Object object = mock(S3Object.class);
        when(object.getObjectContent()).thenReturn(s3Is1).thenReturn(s3Is2);

        // first we'll return null from our s3 client

        store.resetAWSS3Client();
        SignedDomain signedDomain = store.getLocalSignedDomain("iaas");
        assertNull(signedDomain);

        // next setup our mock aws return object

        when(store.awsS3Client.getObject("s3-unit-test-bucket-name", "iaas")).thenReturn(object);
        signedDomain = store.getLocalSignedDomain("iaas");
        assertNotNull(signedDomain);

        DomainData domainData = signedDomain.getDomain();
        assertNotNull(domainData);
        assertEquals(domainData.getName(), "iaas");

        signedDomain = store.getLocalSignedDomain("iaas");
        assertNotNull(signedDomain);

        is1.close();
        is2.close();
    }

    @Test
    public void testGetServerSignedDomain() {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();
        assertNull(store.getServerSignedDomain("iaas"));
    }

    @Test
    public void testGetServerDomainModifiedList() {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();
        assertNull(store.getServerDomainModifiedList());
    }

    @Test
    public void testGetSignedDomainException() throws IOException {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        InputStream is = new FileInputStream("src/test/resources/iaas.json");
        MockS3ObjectInputStream s3Is = new MockS3ObjectInputStream(is, null);
        
        S3Object object = mock(S3Object.class);
        when(object.getObjectContent()).thenReturn(s3Is);

        // first call we return null, second call we return success
        
        when(store.awsS3Client.getObject("s3-unit-test-bucket-name", "iaas"))
                .thenThrow(new AmazonServiceException("test")).thenReturn(object);
        
        SignedDomain signedDomain = store.getLocalSignedDomain("iaas");
        assertNotNull(signedDomain);
        DomainData domainData = signedDomain.getDomain();
        assertNotNull(domainData);
        assertEquals(domainData.getName(), "iaas");
        is.close();
    }
    
    @Test
    public void testGetUpdatedSignedDomainsNoChanges() {
        
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();
        
        ArrayList<S3ObjectSummary> objectList = new ArrayList<>();
        S3ObjectSummary objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas");
        objectSummary.setLastModified(new Date(100));
        objectList.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas.athenz");
        objectSummary.setLastModified(new Date(200));
        objectList.add(objectSummary);
        
        ObjectListing objectListing = mock(ObjectListing.class);
        when(objectListing.getObjectSummaries()).thenReturn(objectList);
        when(objectListing.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);
        
        // set the last modification time to not return any of the domains
        store.lastModTime = (new Date(250)).getTime();
        
        StringBuilder lastModTimeBuffer = new StringBuilder(512);
        SignedDomains signedDomains = store.getUpdatedSignedDomains(lastModTimeBuffer);
        assertTrue(lastModTimeBuffer.length() > 0);
        assertEquals(signedDomains.getDomains().size(), 0);
    }
    
    @Test
    public void testGetUpdatedSignedDomainsWithChange() throws IOException {
        
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();
        
        ArrayList<S3ObjectSummary> objectList = new ArrayList<>();
        S3ObjectSummary objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas");
        objectSummary.setLastModified(new Date(100));
        objectList.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas.athenz");
        objectSummary.setLastModified(new Date(200));
        objectList.add(objectSummary);

        // we'll also include an invalid domain that should be skipped

        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("unknown");
        objectSummary.setLastModified(new Date(200));
        objectList.add(objectSummary);

        ObjectListing objectListing = mock(ObjectListing.class);
        when(objectListing.getObjectSummaries()).thenReturn(objectList);
        when(objectListing.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);
        
        InputStream is = new FileInputStream("src/test/resources/iaas.json");
        MockS3ObjectInputStream s3Is = new MockS3ObjectInputStream(is, null);
        
        S3Object object = mock(S3Object.class);
        when(object.getObjectContent()).thenReturn(s3Is);

        when(store.awsS3Client.getObject("s3-unit-test-bucket-name", "iaas")).thenReturn(object);
        when(store.awsS3Client.getObject("s3-unit-test-bucket-name", "iaas.athenz")).thenReturn(object);
        
        // set the last modification time to return one of the domains
        store.lastModTime = (new Date(150)).getTime();
        
        StringBuilder lastModTimeBuffer = new StringBuilder(512);
        SignedDomains signedDomains = store.getUpdatedSignedDomains(lastModTimeBuffer);
        assertTrue(lastModTimeBuffer.length() > 0);
        
        List<SignedDomain> domainList = signedDomains.getDomains();
        assertEquals(domainList.size(), 1);
        
        DomainData domainData = domainList.get(0).getDomain();
        assertNotNull(domainData);
        assertEquals(domainData.getName(), "iaas");
        is.close();
    }

    @Test
    public void testGetS3Client() {
        S3ChangeLogStore store = new S3ChangeLogStore();
        AmazonS3 s3Client = store.getS3Client();
        assertNotNull(s3Client);
    }

    @Test
    public void initNoRegionException() {
        System.clearProperty(ZTS_PROP_AWS_REGION_NAME);
        S3ChangeLogStore store = new S3ChangeLogStore(null);
        try {
            store.getS3Client();
            fail();
        } catch (RuntimeException ex) {
            assertEquals(ex.getMessage(), "S3ChangeLogStore: Couldn't detect AWS region");
        }
    }

    @Test
    public void testAsyncDomainObjectsFetcher() throws IOException {

        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        // Generate mocked s3Client
        int numberOfDomainsToMock = 500;
        AmazonS3 s3client = buildMockS3Client(numberOfDomainsToMock);
        store.setAwsS3Client(s3client);
        List<String> localDomainList = store.getLocalDomainList();

        assertEquals(localDomainList.size(), numberOfDomainsToMock);
    }

    @Test
    public void testAsyncDomainObjectsFetcherSignedDomains() throws IOException {

        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        // Generate mocked s3Client
        int numberOfDomainsToMock = 800;
        AmazonS3 s3client = buildMockS3Client(numberOfDomainsToMock);
        store.setAwsS3Client(s3client);

        List<String> domainsList = new ArrayList<>();
        for (int i = 0; i < numberOfDomainsToMock; ++i) {
            domainsList.add("domain" + i);
        }
        store.getAllDomains(domainsList);

        assertEquals(store.tempSignedDomainMap.size(), numberOfDomainsToMock);
    }

    private AmazonS3 buildMockS3Client(int numOfDomains) throws IOException {
        AmazonS3 s3client = Mockito.mock(AmazonS3.class);

        ArrayList<S3ObjectSummary> objectList = new ArrayList<>();
        for (int i = 0; i < numOfDomains; ++i) {
            // Add domain to mock objectListing
            S3ObjectSummary objectSummary = new S3ObjectSummary();
            String domainName = "domain" + i;
            objectSummary.setKey(domainName);
            objectSummary.setLastModified(new Date(100 + i));
            objectList.add(objectSummary);

            // Add domain mock object
            String jsonDomainObject = generateJsonDomainObject(domainName);
            InputStream domainObjectStream = new ByteArrayInputStream(jsonDomainObject.getBytes());
            MockS3ObjectInputStream s3ObjectInputStream = new MockS3ObjectInputStream(domainObjectStream, null);

            S3Object domainObject = mock(S3Object.class);
            when(domainObject.getObjectContent()).thenReturn(s3ObjectInputStream);

            Mockito.when(s3client.getObject(Mockito.anyString(), Mockito.eq(domainName))).thenReturn(domainObject);
            domainObjectStream.close();
        }

        ObjectListing objectListing = mock(ObjectListing.class);
        when(objectListing.getObjectSummaries()).thenReturn(objectList);
        when(objectListing.isTruncated()).thenReturn(false);

        when(s3client.listObjects(Mockito.any(ListObjectsRequest.class))).thenReturn(objectListing);
        return s3client;
    }

    private String generateJsonDomainObject(String domainName) {
        String domainPostFix = domainName.substring("domain".length());
        int postFixInt = Integer.parseInt(domainPostFix);
        String modifiedTimeStamp = Timestamp.fromMillis(100 + postFixInt).toString();
        String adminRole = domainName + ":role.admin";
        String policyAdmin = domainName + ":policy.admin";
        return "{\"domain\":{" +
                "\"roles\":[" +
                "{" +
                "\"modified\":" + "\"" + modifiedTimeStamp + "\"," +
                "\"name\":" + "\"" + adminRole + "\"," +
                "\"members\":[" +
                "\"yby.hga\"," +
                "\"yby.zms_test_admin\"" +
                "]" +
                "}" +
                "]," +
                "\"policies\":{" +
                "\"contents\":{" +
                "\"domain\":" + "\"" + modifiedTimeStamp + "\"," +
                "\"policies\":[" +
                "{" +
                "\"modified\":" + "\"" + modifiedTimeStamp + "\"," +
                "\"assertions\":[" +
                "{" +
                "\"role\":" + "\"" + adminRole + "\"," +
                "\"action\":\"*\"," +
                "\"effect\":\"ALLOW\"," +
                "\"resource\":\"iaas:*\"" +
                "}" +
                "]," +
                "\"name\":" + "\"" + policyAdmin + "\"" +
                "}" +
                "]" +
                "}," +
                "\"keyId\":\"zms.dev.0\"," +
                "\"signature\":\"MEUCID0ciS7zBGIEJbUo2aIamnwcA4K_Sx4HtE1LZkPCtZKKAiEA9sAufsEnjODZM8U1p4EOqObJZ9L2Szna_qwsFtinm0U-\"" +
                "}," +
                "\"modified\":" + "\"" + modifiedTimeStamp + "\"," +
                "\"services\":[]," +
                "\"name\":" + "\"" + domainName + "\"" +
                "}," +
                "\"keyId\":\"zms.dev.0\"," +
                "\"signature\":\"MEQCIBl9i0P.apXlpPJ7NCl1FMOHCHTPBgazwtHcEflDIIB1AiA3IUSh7CEDRUXM3PkjU8hBT6XNnXQRLT2ywi2Q0ZciMw--\"}";
    }

    @Test
    public void testGetLocalJWSDomain() throws IOException {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        InputStream is1 = new FileInputStream("src/test/resources/iaas.jws");
        MockS3ObjectInputStream s3Is1 = new MockS3ObjectInputStream(is1, null);

        InputStream is2 = new FileInputStream("src/test/resources/iaas.json");
        MockS3ObjectInputStream s3Is2 = new MockS3ObjectInputStream(is2, null);

        S3Object object = mock(S3Object.class);
        when(object.getObjectContent()).thenReturn(s3Is1).thenReturn(s3Is2);

        // first we'll return null from our s3 client

        store.resetAWSS3Client();
        JWSDomain jwsDomain = store.getLocalJWSDomain("iaas");
        assertNull(jwsDomain);

        // next setup our mock aws return object

        when(store.awsS3Client.getObject("s3-unit-test-bucket-name", "iaas")).thenReturn(object);
        jwsDomain = store.getLocalJWSDomain("iaas");
        assertNotNull(jwsDomain);

        jwsDomain = store.getLocalJWSDomain("iaas");
        assertNotNull(jwsDomain);

        is1.close();
        is2.close();
    }

    @Test
    public void testGetUpdatedJWSDomainsNoChanges() {

        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        ArrayList<S3ObjectSummary> objectList = new ArrayList<>();
        S3ObjectSummary objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas");
        objectSummary.setLastModified(new Date(100));
        objectList.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas.athenz");
        objectSummary.setLastModified(new Date(200));
        objectList.add(objectSummary);

        ObjectListing objectListing = mock(ObjectListing.class);
        when(objectListing.getObjectSummaries()).thenReturn(objectList);
        when(objectListing.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);

        // set the last modification time to not return any of the domains
        store.lastModTime = (new Date(250)).getTime();

        StringBuilder lastModTimeBuffer = new StringBuilder(512);
        List<JWSDomain> jwsDomains = store.getUpdatedJWSDomains(lastModTimeBuffer);
        assertTrue(lastModTimeBuffer.length() > 0);
        assertEquals(jwsDomains.size(), 0);
    }

    @Test
    public void testGetUpdatedJWSDomainsWithChange1() throws IOException {

        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        ArrayList<S3ObjectSummary> objectList = new ArrayList<>();
        S3ObjectSummary objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas");
        objectSummary.setLastModified(new Date(100));
        objectList.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas.athenz");
        objectSummary.setLastModified(new Date(200));
        objectList.add(objectSummary);

        // we'll also include an invalid domain that should be skipped

        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("unknown");
        objectSummary.setLastModified(new Date(200));
        objectList.add(objectSummary);

        ObjectListing objectListing = mock(ObjectListing.class);
        when(objectListing.getObjectSummaries()).thenReturn(objectList);
        when(objectListing.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);

        InputStream is = new FileInputStream("src/test/resources/iaas.jws");
        MockS3ObjectInputStream s3Is = new MockS3ObjectInputStream(is, null);

        S3Object object = mock(S3Object.class);
        when(object.getObjectContent()).thenReturn(s3Is);

        when(store.awsS3Client.getObject("s3-unit-test-bucket-name", "iaas")).thenReturn(object);
        when(store.awsS3Client.getObject("s3-unit-test-bucket-name", "iaas.athenz")).thenReturn(object);

        // set the last modification time to return one of the domains
        store.lastModTime = (new Date(150)).getTime();

        StringBuilder lastModTimeBuffer = new StringBuilder(512);
        List<JWSDomain> jwsDomains = store.getUpdatedJWSDomains(lastModTimeBuffer);
        assertTrue(lastModTimeBuffer.length() > 0);
        assertEquals(jwsDomains.size(), 1);
        is.close();
    }

    @Test
    public void testGetServerJWSDomain() {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();
        assertNull(store.getServerJWSDomain("iaas"));
    }

    @Test
    public void testGetJWSDomainException() throws IOException {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        InputStream is = new FileInputStream("src/test/resources/iaas.jws");
        MockS3ObjectInputStream s3Is = new MockS3ObjectInputStream(is, null);

        S3Object object = mock(S3Object.class);
        when(object.getObjectContent()).thenReturn(s3Is);

        // first call we return null, second call we return success

        when(store.awsS3Client.getObject("s3-unit-test-bucket-name", "iaas"))
                .thenThrow(new AmazonServiceException("test")).thenReturn(object);

        JWSDomain jwsDomain = store.getLocalJWSDomain("iaas");
        assertNotNull(jwsDomain);

        is.close();
    }

    @Test
    public void testGetJWSDomainNotFound() {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();
        when(store.awsS3Client.getObject(any(GetObjectRequest.class))).thenReturn(null);

        assertNull(store.getJWSDomain(store.awsS3Client, "iaas"));
    }

    @Test
    public void testGetJWSDomainClientException() {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        when(store.awsS3Client.getObject(any(GetObjectRequest.class))).thenThrow(new AmazonClientException("failed client operation"));
        assertNull(store.getJWSDomain(store.awsS3Client, "iaas"));
    }

    @Test
    public void testGetJWSDomainServiceException() {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        when(store.awsS3Client.getObject(any(GetObjectRequest.class))).thenThrow(new AmazonServiceException("failed server operation"));
        assertNull(store.getJWSDomain(store.awsS3Client, "iaas"));
    }

    @Test
    public void testGetLocalJWSDomainList() throws IOException {

        MockS3ChangeLogStore store = new MockS3ChangeLogStore(0);
        store.setJWSDomainSupport(true);

        InputStream is1 = new FileInputStream("src/test/resources/iaas.jws");
        MockS3ObjectInputStream s3Is1 = new MockS3ObjectInputStream(is1, null);

        InputStream is2 = new FileInputStream("src/test/resources/iaas.jws");
        MockS3ObjectInputStream s3Is2 = new MockS3ObjectInputStream(is2, null);

        S3Object object = mock(S3Object.class);
        when(object.getObjectContent()).thenReturn(s3Is1).thenReturn(s3Is2);

        when(store.awsS3Client.getObject("s3-unit-test-bucket-name", "iaas")).thenReturn(object);
        ObjectListing mockObjectListing = mock(ObjectListing.class);
        when(store.awsS3Client.listObjects(any(ListObjectsRequest.class))).thenReturn(mockObjectListing);
        List<S3ObjectSummary> tempList = new ArrayList<>();
        S3ObjectSummary s3ObjectSummary = mock(S3ObjectSummary.class);
        when(s3ObjectSummary.getKey()).thenReturn("iaas");
        tempList.add(s3ObjectSummary);
        when(mockObjectListing.getObjectSummaries()).thenReturn(tempList);

        List<String> temp = store.getLocalDomainList();
        assertNotNull(temp);
        JWSDomain jwsDomain = store.getLocalJWSDomain("iaas");
        assertNotNull(jwsDomain);

        is1.close();
        is2.close();
    }

    @Test
    public void testGetLocalJWSDomains() {

        MockS3ChangeLogStore store = new MockS3ChangeLogStore();
        store.setJWSDomainSupport(true);

        ArrayList<S3ObjectSummary> objectList = new ArrayList<>();
        S3ObjectSummary objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas");
        objectList.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas.athenz");
        objectList.add(objectSummary);

        ObjectListing objectListing = mock(ObjectListing.class);
        when(objectListing.getObjectSummaries()).thenReturn(objectList);
        when(objectListing.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);

        // verify that our last mod time is 0 before the call

        assertEquals(store.lastModTime, 0);

        // retrieve the list of domains

        List<String> domains = store.getLocalDomainList();

        assertEquals(domains.size(), 2);
        assertTrue(domains.contains("iaas"));
        assertTrue(domains.contains("iaas.athenz"));

        // also verify that last mod time is updated

        assertTrue(store.lastModTime > 0);

        // get the list again

        domains = store.getLocalDomainList();

        assertEquals(domains.size(), 2);
        assertTrue(domains.contains("iaas"));
        assertTrue(domains.contains("iaas.athenz"));
    }
}
