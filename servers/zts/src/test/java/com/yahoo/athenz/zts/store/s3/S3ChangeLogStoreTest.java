/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.zts.store.s3;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.apache.http.client.methods.HttpRequestBase;
import org.testng.annotations.AfterMethod;
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
import com.yahoo.athenz.zts.store.s3.S3ChangeLogStore;

public class S3ChangeLogStoreTest {

    @BeforeMethod
    public void setup() {
    }
    
    @AfterMethod
    public void shutdown() {
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
    public void testListObjectsAllObjectsNoPage() {
        
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
        when(store.s3.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);
        
        ArrayList<String> domains = new ArrayList<>();
        store.listObjects(store.s3, domains, 0);
        
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
        when(store.s3.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);
        
        ArrayList<String> domains = new ArrayList<>();
        store.listObjects(store.s3, domains, (new Date(150)).getTime());
        
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
        when(store.s3.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);
        when(store.s3.listNextBatchOfObjects(any(ObjectListing.class))).thenReturn(objectListing);

        ArrayList<String> domains = new ArrayList<>();
        store.listObjects(store.s3, domains, 0);
        
        assertEquals(domains.size(), 6);
        assertTrue(domains.contains("iaas"));
        assertTrue(domains.contains("iaas.athenz"));
        assertTrue(domains.contains("cd"));
        assertTrue(domains.contains("cd.docker"));
        assertTrue(domains.contains("platforms"));
        assertTrue(domains.contains("platforms.mh2"));
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
        when(store.s3.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);
        when(store.s3.listNextBatchOfObjects(any(ObjectListing.class))).thenReturn(objectListing);

        ArrayList<String> domains = new ArrayList<>();
        store.listObjects(store.s3, domains, (new Date(150)).getTime());
        
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
        when(store.s3.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);
        
        // verify that our last mod time is 0 before the call
        
        assertEquals(store.lastModTime, 0);
        
        // retrieve the list of domains
        
        List<String> domains = store.getLocalDomainList();
        
        assertEquals(domains.size(), 2);
        assertTrue(domains.contains("iaas"));
        assertTrue(domains.contains("iaas.athenz"));
        
        // also verify that last mod time is updated
        
        assertTrue(store.lastModTime > 0);
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
        when(store.s3.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);
        
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
        when(store.s3.getObject(any(GetObjectRequest.class))).thenReturn((S3Object) null);
        
        assertNull(store.getSignedDomain(store.s3, "iaas"));
    }
    
    @Test
    public void testGetSignedDomainClientException() {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);
        
        when(store.s3.getObject(any(GetObjectRequest.class))).thenThrow(new AmazonClientException("failed client operation"));
        assertNull(store.getSignedDomain(store.s3, "iaas"));
    }
    
    @Test
    public void testGetSignedDomainServiceException() {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);
        
        when(store.s3.getObject(any(GetObjectRequest.class))).thenThrow(new AmazonServiceException("failed server operation"));
        assertNull(store.getSignedDomain(store.s3, "iaas"));
    }
    
    private class MockS3ObjectInputStream extends S3ObjectInputStream {
        public MockS3ObjectInputStream(InputStream in, HttpRequestBase httpRequest) {
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

        when(store.s3.getObject(any(GetObjectRequest.class))).thenReturn(object);
        
        SignedDomain signedDomain = store.getSignedDomain(store.s3, "iaas");
        assertNotNull(signedDomain);
        DomainData domainData = signedDomain.getDomain();
        assertNotNull(domainData);
        assertEquals(domainData.getName(), "iaas");
        is.close();
    }
    
    @Test
    public void testGetSignedDomain() throws IOException {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore(null);

        InputStream is = new FileInputStream("src/test/resources/iaas.json");
        MockS3ObjectInputStream s3Is = new MockS3ObjectInputStream(is, null);
        
        S3Object object = mock(S3Object.class);
        when(object.getObjectContent()).thenReturn(s3Is);

        when(store.s3.getObject(any(GetObjectRequest.class))).thenReturn(object);
        
        SignedDomain signedDomain = store.getSignedDomain("iaas");
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
        when(store.s3.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);
        
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
        
        ObjectListing objectListing = mock(ObjectListing.class);
        when(objectListing.getObjectSummaries()).thenReturn(objectList);
        when(objectListing.isTruncated()).thenReturn(false);
        when(store.s3.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);
        
        InputStream is = new FileInputStream("src/test/resources/iaas.json");
        MockS3ObjectInputStream s3Is = new MockS3ObjectInputStream(is, null);
        
        S3Object object = mock(S3Object.class);
        when(object.getObjectContent()).thenReturn(s3Is);

        when(store.s3.getObject(any(GetObjectRequest.class))).thenReturn(object);
        
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
