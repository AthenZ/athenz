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

package com.yahoo.athenz.zms_aws_domain_syncer;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.*;
import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Timestamp;
import org.apache.http.client.methods.HttpRequestBase;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class StateFileBuilderTest {

    @BeforeMethod
    void beforeMethod() throws IllegalAccessException, NoSuchFieldException {
        Field instance = Config.class.getDeclaredField("instance");
        instance.setAccessible(true);
        instance.set(null, null);

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_BUILDER_THREADS, "10");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT, "1800");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET, "testbucket");
        Config.getInstance().loadConfigParams();
    }

    private static class MockS3ObjectInputStream extends S3ObjectInputStream {
        MockS3ObjectInputStream(InputStream in, HttpRequestBase httpRequest) {
            super(in, httpRequest);
        }
    }

    private AmazonS3 buildMockS3Client(int numOfDomains) {
        String bucketName = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_BUCKET);
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
            final String jsonDomainObject = generateJsonDomainObject(domainName);
            InputStream domainObjectStream = new ByteArrayInputStream(jsonDomainObject.getBytes());
            MockS3ObjectInputStream s3ObjectInputStream = new MockS3ObjectInputStream(domainObjectStream, null);

            S3Object domainObject = mock(S3Object.class);
            when(domainObject.getObjectContent()).thenReturn(s3ObjectInputStream);

            Mockito.when(s3client.getObject(Mockito.eq(bucketName), Mockito.eq(domainName))).thenReturn(domainObject);
        }

        ObjectListing objectListing = mock(ObjectListing.class);
        when(objectListing.getObjectSummaries()).thenReturn(objectList);
        when(objectListing.isTruncated()).thenReturn(false);

        when(s3client.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);
        return s3client;
    }

    private String generateJsonDomainObject(String domainName) {

        final String domainPostFix = domainName.substring("domain".length());
        int postFixInt = Integer.parseInt(domainPostFix);
        Timestamp modifiedTimeStamp = Timestamp.fromMillis(100 + postFixInt);

        return JSON.string(TestUtils.createJWSDomain(domainName, modifiedTimeStamp));
    }

    @Test
    public void testBuildStateMap() {

        // Generate mocked s3Client
        int numberOfDomainsToMock = 500;
        AmazonS3 s3client = buildMockS3Client(numberOfDomainsToMock);

        DomainValidator domainValidator = new DomainValidator();
        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        when(validator.getDomainData(any())).thenAnswer(invocationOnMock -> {
            Object[] arguments = invocationOnMock.getArguments();
            return domainValidator.getDomainData((JWSDomain) arguments[0]);
        });

        StateFileBuilder stateFileBuilder = new StateFileBuilder(s3client, validator);
        Map<String, DomainState> stateMap = stateFileBuilder.buildStateMap();
        assertEquals(stateMap.size(), numberOfDomainsToMock);

        // Check domain contents
        for (int i = 0; i < numberOfDomainsToMock; ++i) {
            String domainName = "domain" + i;
            DomainState domainState = stateMap.get(domainName);

            assertEquals(domainName, domainState.getDomain());
            assertEquals(Timestamp.fromMillis(100 + i).toString(), domainState.getModified());
        }
    }

    @Test
    public void testBuildStateMapHalfBadSignatures() {

        // Generate mocked s3Client
        int numberOfDomainsToMock = 500;
        AmazonS3 s3client = buildMockS3Client(numberOfDomainsToMock);

        // Generate a signature validator that will return "valid" for
        // half of the domains and "invalid" for the other
        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenAnswer(new Answer<>() {
            private boolean currentAnswer = false;

            @Override
            public Object answer(InvocationOnMock invocationOnMock) {
                currentAnswer = !currentAnswer;
                return currentAnswer;
            }
        });
        DomainValidator domainValidator = new DomainValidator();
        when(validator.getDomainData(any())).thenAnswer(invocationOnMock -> {
            Object[] arguments = invocationOnMock.getArguments();
            return domainValidator.getDomainData((JWSDomain) arguments[0]);
        });

        StateFileBuilder stateFileBuilder = new StateFileBuilder(s3client, validator);
        Map<String, DomainState> stateMap = stateFileBuilder.buildStateMap();

        // Half of the domains should be valid
        assertEquals(stateMap.size(), numberOfDomainsToMock / 2);
    }

    @Test
    public void testListObjectsAllObjectsNoPage() {

        ArrayList<S3ObjectSummary> objectList = new ArrayList<>();
        S3ObjectSummary objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas");
        objectSummary.setLastModified(new Date(100));
        objectList.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey("iaas.athenz");
        objectSummary.setLastModified(new Date(200));
        objectList.add(objectSummary);
        objectSummary = new S3ObjectSummary();
        objectSummary.setKey(".date");
        objectSummary.setLastModified(new Date(300));
        objectList.add(objectSummary);

        ObjectListing objectListing = mock(ObjectListing.class);
        when(objectListing.getObjectSummaries()).thenReturn(objectList);
        when(objectListing.isTruncated()).thenReturn(false);

        AmazonS3 awsS3ClientMock = Mockito.mock(AmazonS3.class);
        when(awsS3ClientMock.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        StateFileBuilder stateFileBuilder = new StateFileBuilder(awsS3ClientMock, validator);
        List<String> domains = stateFileBuilder.listObjects(awsS3ClientMock);

        assertEquals(domains.size(), 2);
        assertTrue(domains.contains("iaas"));
        assertTrue(domains.contains("iaas.athenz"));
    }

    @Test
    public void testListObjectsAllObjectsMultiplePages() {

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

        AmazonS3 awsS3ClientMock = Mockito.mock(AmazonS3.class);

        when(awsS3ClientMock.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);
        when(awsS3ClientMock.listNextBatchOfObjects(any(ObjectListing.class))).thenReturn(objectListing);

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        StateFileBuilder stateFileBuilder = new StateFileBuilder(awsS3ClientMock, validator);
        List<String> domains = stateFileBuilder.listObjects(awsS3ClientMock);

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

        AmazonS3 awsS3ClientMock = Mockito.mock(AmazonS3.class);

        when(awsS3ClientMock.listObjects(any(ListObjectsRequest.class))).thenReturn(objectListing);
        when(awsS3ClientMock.listNextBatchOfObjects(any(ObjectListing.class)))
                .thenReturn(objectListing)
                .thenReturn(null);

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        StateFileBuilder stateFileBuilder = new StateFileBuilder(awsS3ClientMock, validator);
        List<String> domains = stateFileBuilder.listObjects(awsS3ClientMock);

        assertEquals(domains.size(), 4);
        assertTrue(domains.contains("iaas"));
        assertTrue(domains.contains("iaas.athenz"));
        assertTrue(domains.contains("cd"));
        assertTrue(domains.contains("cd.docker"));
    }
}
