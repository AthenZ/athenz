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

import java.io.*;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.TimeUnit;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zms.JWSDomain;
import com.yahoo.rdl.Timestamp;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.TlsTrustManagersProvider;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3ClientBuilder;
import software.amazon.awssdk.services.s3.model.*;
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
        GetObjectResponse response = Mockito.mock(GetObjectResponse.class);

        InputStream is1 = new FileInputStream("src/test/resources/iaas.json");
        ResponseInputStream<GetObjectResponse> s3Is1 = new ResponseInputStream<>(response, is1);

        InputStream is2 = new FileInputStream("src/test/resources/iaas.json");
        ResponseInputStream<GetObjectResponse> s3Is2 = new ResponseInputStream<>(response, is2);

        GetObjectRequest getObjectRequest = GetObjectRequest.builder().bucket("s3-unit-test-bucket-name")
                .key("iaas").build();
        when(store.awsS3Client.getObject(getObjectRequest)).thenReturn(s3Is1).thenReturn(s3Is2);
        ListObjectsV2Response mockListObjectsV2Response = mock(ListObjectsV2Response.class);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockListObjectsV2Response);
        List<S3Object> tempList = new ArrayList<>();
        S3Object s3ObjectSummary = mock(S3Object.class);
        when(s3ObjectSummary.key()).thenReturn("iaas");
        tempList.add(s3ObjectSummary);
        when(mockListObjectsV2Response.contents()).thenReturn(tempList);

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

        GetObjectResponse response = Mockito.mock(GetObjectResponse.class);

        InputStream is1 = new FileInputStream("src/test/resources/iaas.json");
        ResponseInputStream<GetObjectResponse> s3Is1 = new ResponseInputStream<>(response, is1);

        InputStream is2 = new FileInputStream("src/test/resources/iaas.json");
        ResponseInputStream<GetObjectResponse> s3Is2 = new ResponseInputStream<>(response, is2);

        GetObjectRequest getObjectRequest = GetObjectRequest.builder().bucket("s3-unit-test-bucket-name")
                .key("iaas").build();
        when(store.awsS3Client.getObject(getObjectRequest)).thenReturn(s3Is1).thenReturn(s3Is2);

        ListObjectsV2Response mockListObjectsV2Response = mock(ListObjectsV2Response.class);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockListObjectsV2Response);
        List<S3Object> tempList = new ArrayList<>();
        S3Object s3ObjectSummary = mock(S3Object.class);
        when(s3ObjectSummary.key()).thenReturn("iaas");
        tempList.add(s3ObjectSummary);
        when(mockListObjectsV2Response.contents()).thenReturn(tempList);

        List<String> temp = new LinkedList<>();
        temp.add("iaas");

        try {
            when(store.executorService.awaitTermination(defaultTimeoutSeconds, TimeUnit.SECONDS)).thenThrow(new InterruptedException());
            assertFalse(store.getAllDomains(temp));
            assertFalse(store.getLocalDomainList().isEmpty());
        } catch (InterruptedException ignored) {
        }

        is1.close();
        is2.close();
    }

    @Test
    public void testListObjectsAllObjectsNoPage() {

        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        ListObjectsV2Response mockListObjectsV2Response = mock(ListObjectsV2Response.class);
        ArrayList<S3Object> objectList = new ArrayList<>();

        S3Object objectSummary = S3Object.builder().key("iaas").build();
        objectList.add(objectSummary);
        objectSummary = S3Object.builder().key("iaas.athenz").build();
        objectList.add(objectSummary);
        objectSummary = S3Object.builder().key(".date").build();
        objectList.add(objectSummary);

        when(mockListObjectsV2Response.contents()).thenReturn(objectList);

        when(mockListObjectsV2Response.contents()).thenReturn(objectList);
        when(mockListObjectsV2Response.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockListObjectsV2Response);

        ArrayList<String> domains = new ArrayList<>();
        store.listObjects(store.awsS3Client, domains, 0);

        assertEquals(domains.size(), 2);
        assertTrue(domains.contains("iaas"));
        assertTrue(domains.contains("iaas.athenz"));
    }

    @Test
    public void testListObjectsAllObjectsNoPageModTime() {

        MockS3ChangeLogStore store = new MockS3ChangeLogStore();
        ListObjectsV2Response mockListObjectsV2Response = mock(ListObjectsV2Response.class);

        ArrayList<S3Object> objectList = new ArrayList<>();
        S3Object objectSummary = S3Object.builder().key("iaas").lastModified((new Date(100)).toInstant()).build();
        objectList.add(objectSummary);
        objectSummary = S3Object.builder().key("iaas.athenz").lastModified((new Date(200)).toInstant()).build();
        objectList.add(objectSummary);

        when(mockListObjectsV2Response.contents()).thenReturn(objectList);
        when(mockListObjectsV2Response.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockListObjectsV2Response);

        ArrayList<String> domains = new ArrayList<>();
        store.listObjects(store.awsS3Client, domains, (new Date(150)).getTime());

        assertEquals(domains.size(), 1);
        assertTrue(domains.contains("iaas.athenz"));
    }

    @Test
    public void testListObjectsAllObjectsMultiplePages() {

        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        ListObjectsV2Response mockListObjectsV2Response = mock(ListObjectsV2Response.class);

        ArrayList<S3Object> objectList1 = new ArrayList<>();
        S3Object objectSummary = S3Object.builder().key("iaas").build();
        objectList1.add(objectSummary);
        objectSummary = S3Object.builder().key("iaas.athenz").build();
        objectList1.add(objectSummary);

        ArrayList<S3Object> objectList2 = new ArrayList<>();
        objectSummary = S3Object.builder().key("cd").build();
        objectList2.add(objectSummary);
        objectSummary = S3Object.builder().key("cd.docker").build();
        objectList2.add(objectSummary);

        ArrayList<S3Object> objectList3 = new ArrayList<>();
        objectSummary = S3Object.builder().key("platforms").build();
        objectList3.add(objectSummary);
        objectSummary = S3Object.builder().key("platforms.mh2").build();
        objectList3.add(objectSummary);

        when(mockListObjectsV2Response.contents())
            .thenReturn(objectList1)
            .thenReturn(objectList2)
            .thenReturn(objectList3);
        when(mockListObjectsV2Response.isTruncated())
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockListObjectsV2Response);

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

        ListObjectsV2Response mockListObjectsV2Response = mock(ListObjectsV2Response.class);

        ArrayList<S3Object> objectList1 = new ArrayList<>();
        S3Object objectSummary = S3Object.builder().key("iaas").build();
        objectList1.add(objectSummary);
        objectSummary = S3Object.builder().key("iaas.athenz").build();
        objectList1.add(objectSummary);

        ArrayList<S3Object> objectList2 = new ArrayList<>();
        objectSummary = S3Object.builder().key("cd").build();
        objectList2.add(objectSummary);
        objectSummary = S3Object.builder().key("cd.docker").build();
        objectList2.add(objectSummary);

        when(mockListObjectsV2Response.contents())
                .thenReturn(objectList1)
                .thenReturn(objectList2);
        when(mockListObjectsV2Response.isTruncated()).thenReturn(true);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class)))
                .thenReturn(mockListObjectsV2Response)
                .thenReturn(mockListObjectsV2Response)
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

        ListObjectsV2Response mockListObjectsV2Response = mock(ListObjectsV2Response.class);

        ArrayList<S3Object> objectList1 = new ArrayList<>();
        S3Object objectSummary = S3Object.builder().key("iaas").lastModified((new Date(100)).toInstant()).build();
        objectList1.add(objectSummary);
        objectSummary = S3Object.builder().key("iaas.athenz").lastModified((new Date(100)).toInstant()).build();
        objectList1.add(objectSummary);

        ArrayList<S3Object> objectList2 = new ArrayList<>();
        objectSummary = S3Object.builder().key("cd").lastModified((new Date(100)).toInstant()).build();
        objectList2.add(objectSummary);
        objectSummary = S3Object.builder().key("cd.docker").lastModified((new Date(200)).toInstant()).build();
        objectList2.add(objectSummary);

        ArrayList<S3Object> objectList3 = new ArrayList<>();
        objectSummary = S3Object.builder().key("platforms").lastModified((new Date(200)).toInstant()).build();
        objectList3.add(objectSummary);
        objectSummary = S3Object.builder().key("platforms.mh2").lastModified((new Date(200)).toInstant()).build();
        objectList3.add(objectSummary);
        
        when(mockListObjectsV2Response.contents())
            .thenReturn(objectList1)
            .thenReturn(objectList2)
            .thenReturn(objectList3);
        when(mockListObjectsV2Response.isTruncated())
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockListObjectsV2Response);

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

        ListObjectsV2Response mockListObjectsV2Response = mock(ListObjectsV2Response.class);

        ArrayList<S3Object> objectList1 = new ArrayList<>();
        S3Object objectSummary = S3Object.builder().key("iaas").build();
        objectList1.add(objectSummary);
        objectSummary = S3Object.builder().key("iaas.athenz").build();
        objectList1.add(objectSummary);
        
        when(mockListObjectsV2Response.contents()).thenReturn(objectList1);
        when(mockListObjectsV2Response.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockListObjectsV2Response);
        
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

        ListObjectsV2Response mockListObjectsV2Response = mock(ListObjectsV2Response.class);

        ArrayList<S3Object> objectList1 = new ArrayList<>();
        S3Object objectSummary = S3Object.builder().key("iaas").build();
        objectList1.add(objectSummary);
        objectSummary = S3Object.builder().key("iaas.athenz").build();
        objectList1.add(objectSummary);
        
        when(mockListObjectsV2Response.contents()).thenReturn(objectList1);
        when(mockListObjectsV2Response.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockListObjectsV2Response);
        
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

        S3Exception s3Exception = Mockito.mock(S3Exception.class);
        when(s3Exception.getMessage()).thenReturn("failed client operation");
        when(store.awsS3Client.getObject(any(GetObjectRequest.class))).thenThrow(s3Exception);
        assertNull(store.getSignedDomain(store.awsS3Client, "iaas"));
    }
    
    @Test
    public void testGetSignedDomainServiceException() {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        S3Exception s3Exception = Mockito.mock(S3Exception.class);
        when(s3Exception.getMessage()).thenReturn("failed server operation");
        when(store.awsS3Client.getObject(any(GetObjectRequest.class))).thenThrow(s3Exception);
        assertNull(store.getSignedDomain(store.awsS3Client, "iaas"));
    }
    
    @Test
    public void testGetSignedDomainInternal() throws IOException {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        GetObjectResponse response = Mockito.mock(GetObjectResponse.class);

        InputStream is = new FileInputStream("src/test/resources/iaas.json");
        ResponseInputStream<GetObjectResponse> s3Is = new ResponseInputStream<>(response, is);

        GetObjectRequest getObjectRequest = GetObjectRequest.builder().bucket("s3-unit-test-bucket-name")
                .key("iaas").build();
        when(store.awsS3Client.getObject(getObjectRequest)).thenReturn(s3Is);
        
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

        GetObjectResponse response = Mockito.mock(GetObjectResponse.class);

        InputStream is1 = new FileInputStream("src/test/resources/iaas.json");
        ResponseInputStream<GetObjectResponse> s3Is1 = new ResponseInputStream<>(response, is1);

        InputStream is2 = new FileInputStream("src/test/resources/iaas.json");
        ResponseInputStream<GetObjectResponse> s3Is2 = new ResponseInputStream<>(response, is2);

        // first we'll return null from our s3 client

        store.resetAWSS3Client();
        SignedDomain signedDomain = store.getLocalSignedDomain("iaas");
        assertNull(signedDomain);

        // next setup our mock aws return object

        GetObjectRequest getObjectRequest = GetObjectRequest.builder().bucket("s3-unit-test-bucket-name")
                .key("iaas").build();
        when(store.awsS3Client.getObject(getObjectRequest)).thenReturn(s3Is1).thenReturn(s3Is2);
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

        GetObjectResponse response = Mockito.mock(GetObjectResponse.class);

        InputStream is = new FileInputStream("src/test/resources/iaas.json");
        ResponseInputStream<GetObjectResponse> s3Is = new ResponseInputStream<>(response, is);

        // first call we return null, second call we return success

        GetObjectRequest getObjectRequest = GetObjectRequest.builder().bucket("s3-unit-test-bucket-name")
                .key("iaas").build();
        S3Exception s3Exception = Mockito.mock(S3Exception.class);
        when(s3Exception.getMessage()).thenReturn("failed client operation");
        when(store.awsS3Client.getObject(getObjectRequest)).
                thenThrow(s3Exception).thenReturn(s3Is);

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

        ListObjectsV2Response mockListObjectsV2Response = mock(ListObjectsV2Response.class);

        ArrayList<S3Object> objectList = new ArrayList<>();
        S3Object objectSummary = S3Object.builder().key("iaas").lastModified((new Date(100)).toInstant()).build();
        objectList.add(objectSummary);
        objectSummary = S3Object.builder().key("iaas.athenz").lastModified((new Date(200)).toInstant()).build();
        objectList.add(objectSummary);
        
        when(mockListObjectsV2Response.contents()).thenReturn(objectList);
        when(mockListObjectsV2Response.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockListObjectsV2Response);
        
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

        ListObjectsV2Response mockListObjectsV2Response = mock(ListObjectsV2Response.class);

        ArrayList<S3Object> objectList = new ArrayList<>();
        S3Object objectSummary = S3Object.builder().key("iaas").lastModified((new Date(100)).toInstant()).build();
        objectList.add(objectSummary);
        objectSummary = S3Object.builder().key("iaas.athenz").lastModified((new Date(200)).toInstant()).build();
        objectList.add(objectSummary);

        // we'll also include an invalid domain that should be skipped

        objectSummary = S3Object.builder().key("unknown").lastModified((new Date(200)).toInstant()).build();
        objectList.add(objectSummary);

        when(mockListObjectsV2Response.contents()).thenReturn(objectList);
        when(mockListObjectsV2Response.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockListObjectsV2Response);

        GetObjectResponse response = Mockito.mock(GetObjectResponse.class);

        InputStream is = new FileInputStream("src/test/resources/iaas.json");
        ResponseInputStream<GetObjectResponse> s3Is = new ResponseInputStream<>(response, is);

        GetObjectRequest getObjectRequest1 = GetObjectRequest.builder().bucket("s3-unit-test-bucket-name")
                .key("iaas").build();
        when(store.awsS3Client.getObject(getObjectRequest1)).thenReturn(s3Is);
        GetObjectRequest getObjectRequest2 = GetObjectRequest.builder().bucket("s3-unit-test-bucket-name")
                .key("iaas.athenz").build();
        when(store.awsS3Client.getObject(getObjectRequest2)).thenReturn(s3Is);

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
        S3Client s3Client = store.getS3Client();
        assertNotNull(s3Client);
    }

    @Test
    public void testGetS3ClientWithCustomEndpointAndCaCert() throws Exception {
        System.setProperty(ZTS_PROP_AWS_BUCKET_NAME, "test-bucket");
        System.setProperty(ZTS_PROP_AWS_REGION_NAME, "us-west-2");
        System.setProperty("athenz.zts.aws_s3_endpoint", "https://custom.s3.endpoint");
        System.setProperty("athenz.zts.aws_s3_ca_cert", "src/test/resources/dummy_ca.pem");

        // Mocks
        try (MockedStatic<ApacheHttpClient> mockHttpClientStatic = Mockito.mockStatic(ApacheHttpClient.class);
             MockedStatic<S3Client> mockS3ClientStatic = Mockito.mockStatic(S3Client.class);
             MockedStatic<Crypto> mockCryptoStatic = Mockito.mockStatic(Crypto.class)) {

            // Mock Crypto
            mockCryptoStatic.when(() -> Crypto.loadX509Certificates(any(String.class))).thenReturn(new X509Certificate[]{mock(X509Certificate.class)});

            // Mock ApacheHttpClient builder
            ApacheHttpClient.Builder mockHttpBuilder = mock(ApacheHttpClient.Builder.class);
            SdkHttpClient mockHttpClient = mock(SdkHttpClient.class);

            mockHttpClientStatic.when(ApacheHttpClient::builder).thenReturn(mockHttpBuilder);
            when(mockHttpBuilder.tlsTrustManagersProvider(any(TlsTrustManagersProvider.class))).thenReturn(mockHttpBuilder);
            when(mockHttpBuilder.build()).thenReturn(mockHttpClient);

            // Mock S3Client builder
            S3ClientBuilder mockS3Builder = mock(S3ClientBuilder.class);
            S3Client mockS3Client = mock(S3Client.class);

            mockS3ClientStatic.when(S3Client::builder).thenReturn(mockS3Builder);
            when(mockS3Builder.region(any(Region.class))).thenReturn(mockS3Builder);
            when(mockS3Builder.endpointOverride(any(URI.class))).thenReturn(mockS3Builder);
            when(mockS3Builder.httpClient(any(SdkHttpClient.class))).thenReturn(mockS3Builder);
            when(mockS3Builder.build()).thenReturn(mockS3Client);

            S3ChangeLogStore store = new S3ChangeLogStore();
            S3Client client = store.getS3Client();
            assertNotNull(client);

            // Verify ApacheHttpClient configured with TrustManager
            Mockito.verify(mockHttpBuilder).tlsTrustManagersProvider(any(TlsTrustManagersProvider.class));

            // Verify S3Client configured with Endpoint Override
            ArgumentCaptor<URI> uriCaptor = ArgumentCaptor.forClass(URI.class);
            Mockito.verify(mockS3Builder).endpointOverride(uriCaptor.capture());
            assertEquals(uriCaptor.getValue().toString(), "https://custom.s3.endpoint");
        } finally {
            System.clearProperty("athenz.zts.aws_s3_endpoint");
            System.clearProperty("athenz.zts.aws_s3_ca_cert");
        }
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
        S3Client s3client = buildMockS3Client(numberOfDomainsToMock);
        store.setAwsS3Client(s3client);
        List<String> localDomainList = store.getLocalDomainList();

        assertEquals(localDomainList.size(), numberOfDomainsToMock);
    }

    @Test
    public void testAsyncDomainObjectsFetcherSignedDomains() throws IOException {

        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        // Generate mocked s3Client
        int numberOfDomainsToMock = 800;
        S3Client s3client = buildMockS3Client(numberOfDomainsToMock);
        store.setAwsS3Client(s3client);

        List<String> domainsList = new ArrayList<>();
        for (int i = 0; i < numberOfDomainsToMock; ++i) {
            domainsList.add("domain" + i);
        }
        store.getAllDomains(domainsList);

        assertEquals(store.tempSignedDomainMap.size(), numberOfDomainsToMock);
    }

    private S3Client buildMockS3Client(int numOfDomains) throws IOException {

        S3Client s3client = Mockito.mock(S3Client.class);

        ListObjectsV2Response mockListObjectsV2Response = mock(ListObjectsV2Response.class);
        ArrayList<S3Object> objectList = new ArrayList<>();
        for (int i = 0; i < numOfDomains; ++i) {
            // Add domain to mock objectListing

            final String domainName = "domain" + i;
            S3Object objectSummary = S3Object.builder().key(domainName).lastModified((new Date(100 + i)).toInstant()).build();
            objectList.add(objectSummary);

            GetObjectResponse response = Mockito.mock(GetObjectResponse.class);

            // Add domain mock object
            String jsonDomainObject = generateJsonDomainObject(domainName);
            InputStream domainObjectStream = new ByteArrayInputStream(jsonDomainObject.getBytes());
            ResponseInputStream<GetObjectResponse> responseInputStream = new ResponseInputStream<>(response, domainObjectStream);

            GetObjectRequest getObjectRequest = GetObjectRequest.builder().bucket("s3-unit-test-bucket-name")
                    .key(domainName).build();
            Mockito.when(s3client.getObject(getObjectRequest)).thenReturn(responseInputStream);
            domainObjectStream.close();
        }

        when(mockListObjectsV2Response.contents()).thenReturn(objectList);
        when(mockListObjectsV2Response.isTruncated()).thenReturn(false);
        when(s3client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockListObjectsV2Response);

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

        GetObjectResponse response = Mockito.mock(GetObjectResponse.class);

        InputStream is1 = new FileInputStream("src/test/resources/iaas.jws");
        ResponseInputStream<GetObjectResponse> s3Is1 = new ResponseInputStream<>(response, is1);

        InputStream is2 = new FileInputStream("src/test/resources/iaas.json");
        ResponseInputStream<GetObjectResponse> s3Is2 = new ResponseInputStream<>(response, is2);

        // first we'll return null from our s3 client

        store.resetAWSS3Client();
        JWSDomain jwsDomain = store.getLocalJWSDomain("iaas");
        assertNull(jwsDomain);

        // next setup our mock aws return object

        GetObjectRequest getObjectRequest = GetObjectRequest.builder().bucket("s3-unit-test-bucket-name")
                .key("iaas").build();
        when(store.awsS3Client.getObject(getObjectRequest)).thenReturn(s3Is1).thenReturn(s3Is2);
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

        ListObjectsV2Response mockListObjectsV2Response = mock(ListObjectsV2Response.class);

        ArrayList<S3Object> objectList = new ArrayList<>();
        S3Object objectSummary = S3Object.builder().key("iaas").lastModified((new Date(100)).toInstant()).build();
        objectList.add(objectSummary);
        objectSummary = S3Object.builder().key("iaas.athenz").lastModified((new Date(200)).toInstant()).build();
        objectList.add(objectSummary);

        when(mockListObjectsV2Response.contents()).thenReturn(objectList);
        when(mockListObjectsV2Response.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockListObjectsV2Response);

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

        ListObjectsV2Response mockListObjectsV2Response = mock(ListObjectsV2Response.class);

        ArrayList<S3Object> objectList = new ArrayList<>();
        S3Object objectSummary = S3Object.builder().key("iaas").lastModified((new Date(100)).toInstant()).build();
        objectList.add(objectSummary);
        objectSummary = S3Object.builder().key("iaas.athenz").lastModified((new Date(200)).toInstant()).build();
        objectList.add(objectSummary);

        // we'll also include an invalid domain that should be skipped

        objectSummary = S3Object.builder().key("unknown").lastModified((new Date(200)).toInstant()).build();
        objectList.add(objectSummary);

        when(mockListObjectsV2Response.contents()).thenReturn(objectList);
        when(mockListObjectsV2Response.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockListObjectsV2Response);

        GetObjectResponse response = Mockito.mock(GetObjectResponse.class);

        InputStream is = new FileInputStream("src/test/resources/iaas.jws");
        ResponseInputStream<GetObjectResponse> s3Is = new ResponseInputStream<>(response, is);

        GetObjectRequest getObjectRequest1 = GetObjectRequest.builder().bucket("s3-unit-test-bucket-name")
                .key("iaas").build();
        when(store.awsS3Client.getObject(getObjectRequest1)).thenReturn(s3Is);
        GetObjectRequest getObjectRequest2 = GetObjectRequest.builder().bucket("s3-unit-test-bucket-name")
                .key("iaas.athenz").build();
        when(store.awsS3Client.getObject(getObjectRequest2)).thenReturn(s3Is);

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

        GetObjectResponse response = Mockito.mock(GetObjectResponse.class);

        InputStream is = new FileInputStream("src/test/resources/iaas.jws");
        ResponseInputStream<GetObjectResponse> s3Is = new ResponseInputStream<>(response, is);

        // first call we return null, second call we return success

        GetObjectRequest getObjectRequest = GetObjectRequest.builder().bucket("s3-unit-test-bucket-name")
                .key("iaas").build();
        S3Exception s3Exception = Mockito.mock(S3Exception.class);
        when(s3Exception.getMessage()).thenReturn("failed client operation");
        when(store.awsS3Client.getObject(getObjectRequest))
                .thenThrow(s3Exception).thenReturn(s3Is);

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

        S3Exception s3Exception = Mockito.mock(S3Exception.class);
        when(s3Exception.getMessage()).thenReturn("failed client operation");
        when(store.awsS3Client.getObject(any(GetObjectRequest.class))).thenThrow(s3Exception);
        assertNull(store.getJWSDomain(store.awsS3Client, "iaas"));
    }

    @Test
    public void testGetJWSDomainServiceException() {
        MockS3ChangeLogStore store = new MockS3ChangeLogStore();

        S3Exception s3Exception = Mockito.mock(S3Exception.class);
        when(s3Exception.getMessage()).thenReturn("failed server operation");
        when(store.awsS3Client.getObject(any(GetObjectRequest.class))).thenThrow(s3Exception);
        assertNull(store.getJWSDomain(store.awsS3Client, "iaas"));
    }

    @Test
    public void testGetLocalJWSDomainList() throws IOException {

        MockS3ChangeLogStore store = new MockS3ChangeLogStore(0);
        store.setJWSDomainSupport(true);

        GetObjectResponse response = Mockito.mock(GetObjectResponse.class);

        InputStream is1 = new FileInputStream("src/test/resources/iaas.jws");
        ResponseInputStream<GetObjectResponse> s3Is1 = new ResponseInputStream<>(response, is1);

        InputStream is2 = new FileInputStream("src/test/resources/iaas.jws");
        ResponseInputStream<GetObjectResponse> s3Is2 = new ResponseInputStream<>(response, is2);

        GetObjectRequest getObjectRequest = GetObjectRequest.builder().bucket("s3-unit-test-bucket-name")
                .key("iaas").build();
        when(store.awsS3Client.getObject(getObjectRequest)).thenReturn(s3Is1).thenReturn(s3Is2);
        ListObjectsV2Response mockListObjectsV2Response = mock(ListObjectsV2Response.class);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockListObjectsV2Response);
        List<S3Object> tempList = new ArrayList<>();
        S3Object s3ObjectSummary = mock(S3Object.class);
        when(s3ObjectSummary.key()).thenReturn("iaas");
        tempList.add(s3ObjectSummary);
        when(mockListObjectsV2Response.contents()).thenReturn(tempList);

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

        ListObjectsV2Response mockListObjectsV2Response = mock(ListObjectsV2Response.class);

        ArrayList<S3Object> objectList1 = new ArrayList<>();
        S3Object objectSummary = S3Object.builder().key("iaas").build();
        objectList1.add(objectSummary);
        objectSummary = S3Object.builder().key("iaas.athenz").build();
        objectList1.add(objectSummary);

        when(mockListObjectsV2Response.contents()).thenReturn(objectList1);
        when(mockListObjectsV2Response.isTruncated()).thenReturn(false);
        when(store.awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockListObjectsV2Response);

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
