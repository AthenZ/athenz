/*
 *  Copyright 2020 Verizon Media
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
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

import org.apache.http.client.methods.HttpRequestBase;
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
    private int defaultTimeoutSeconds = Integer.valueOf(System.getProperty(DEFAULT_TIMEOUT_SECONDS, "1800"));

    @BeforeMethod
    public void setup() {
        System.setProperty(ZTS_PROP_AWS_BUCKET_NAME, "s3-unit-test-bucket-name");
    }

    @Test
    public void testInvalidBucketName() {
        System.clearProperty(ZTS_PROP_AWS_BUCKET_NAME);
        try {
            new S3ChangeLogStore(null);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("S3 Bucket name cannot be null"));
        }

        System.setProperty(ZTS_PROP_AWS_BUCKET_NAME, "");
        try {
            new S3ChangeLogStore(null);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("S3 Bucket name cannot be null"));
        }

        System.setProperty(ZTS_PROP_AWS_BUCKET_NAME, "s3-unit-test-bucket-name");
        assertNotNull(new S3ChangeLogStore(null));
    }

    @Test
    public void testFullRefreshSupport() {
        S3ChangeLogStore store = new S3ChangeLogStore(null);
        assertFalse(store.supportsFullRefresh());
    }
    
    @Test
    public void testNoOpMethods() {
        S3ChangeLogStore store = new S3ChangeLogStore(null);
        store.removeLocalDomain("iaas.athenz");
        store.saveLocalDomain("iaas.athenz", null);
    }
    
    @Test
    public void testSetLastModificationTimestamp() {
        S3ChangeLogStore store = new S3ChangeLogStore(null);
        assertEquals(store.lastModTime, 0);
        
        store.setLastModificationTimestamp("12345");
        assertEquals(store.lastModTime, 12345);

        store.setLastModificationTimestamp(null);
        assertEquals(store.lastModTime, 0);
    }

    @Test
    public void testGetLocalDomainList() throws FileNotFoundException {

        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null, 0);

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
        store.getLocalSignedDomain("iaas");
    }

    @Test
    public void testGetAllSignedDomainsException() throws FileNotFoundException {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null, 1);

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
            assertFalse(store.getAllSignedDomains(temp));
            assertTrue(store.getLocalDomainList().size() > 0);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testListObjectsAllObjectsNoPage() {
        
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);
        
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
        
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);
        
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
        
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);
        
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

        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);

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
        
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);
        
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
    public void testGetLocalDomains() {
        
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);
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
        
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);
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
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);
        when(store.awsS3Client.getObject(any(GetObjectRequest.class))).thenReturn(null);
        
        assertNull(store.getSignedDomain(store.awsS3Client, "iaas"));
    }
    
    @Test
    public void testGetSignedDomainClientException() {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);
        
        when(store.awsS3Client.getObject(any(GetObjectRequest.class))).thenThrow(new AmazonClientException("failed client operation"));
        assertNull(store.getSignedDomain(store.awsS3Client, "iaas"));
    }
    
    @Test
    public void testGetSignedDomainServiceException() {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);
        
        when(store.awsS3Client.getObject(any(GetObjectRequest.class))).thenThrow(new AmazonServiceException("failed server operation"));
        assertNull(store.getSignedDomain(store.awsS3Client, "iaas"));
    }
    
    private class MockS3ObjectInputStream extends S3ObjectInputStream {
        MockS3ObjectInputStream(InputStream in, HttpRequestBase httpRequest) {
            super(in, httpRequest);
        }
    }
    
    @Test
    public void testGetSignedDomainInternal() throws IOException {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);

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
    public void testGetSignedDomain() throws IOException {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);

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
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);
        assertNull(store.getServerSignedDomain("iaas"));
    }

    @Test
    public void testGetServerDomainModifiedList() {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);
        assertNull(store.getServerDomainModifiedList());
    }

    @Test
    public void testGetSignedDomainException() throws IOException {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);

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
        
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);
        
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
    public void testGetUpdatedSignedDomainsWithChange() throws FileNotFoundException {
        
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);
        
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
    }
}
