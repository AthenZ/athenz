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

import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;

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

    private S3Client buildMockS3Client(int numOfDomains, boolean skipHeadObjectMock) {

        final String bucketName = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_BUCKET);
        S3Client s3client = Mockito.mock(S3Client.class);

        ArrayList<S3Object> objectList = new ArrayList<>();
        for (int i = 0; i < numOfDomains; ++i) {

            final String domainName = "domain" + i;

            if (!skipHeadObjectMock) {
                HeadObjectResponse headObjectResponse = Mockito.mock(HeadObjectResponse.class);
                when(headObjectResponse.lastModified()).thenReturn(new Date().toInstant());
                Mockito.when(s3client.headObject(any(HeadObjectRequest.class))).thenReturn(headObjectResponse);
            }

            // Add domain to mock objectListing

            S3Object objectSummary = S3Object.builder().key(domainName).build();
            objectList.add(objectSummary);

            // Add domain mock object
            final String jsonDomainObject = generateJsonDomainObject(domainName);
            InputStream domainObjectStream = new ByteArrayInputStream(jsonDomainObject.getBytes());

            GetObjectResponse response = Mockito.mock(GetObjectResponse.class);
            GetObjectRequest getObjectRequest = GetObjectRequest.builder().bucket(bucketName).key(domainName).build();
            ResponseInputStream<GetObjectResponse> s3Is = new ResponseInputStream<>(response, domainObjectStream);
            Mockito.when(s3client.getObject(getObjectRequest)).thenReturn(s3Is);
        }

        ListObjectsV2Response mockListObjectsV2Response = mock(ListObjectsV2Response.class);
        when(mockListObjectsV2Response.contents()).thenReturn(objectList);
        when(mockListObjectsV2Response.isTruncated()).thenReturn(false);
        when(s3client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockListObjectsV2Response);

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
        S3Client s3client = buildMockS3Client(numberOfDomainsToMock, false);

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
    public void testBuildStateMaNoMetadata() {

        // Generate mocked s3Client
        int numberOfDomainsToMock = 500;
        S3Client s3client = buildMockS3Client(numberOfDomainsToMock, true);

        DomainValidator domainValidator = new DomainValidator();
        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        when(validator.getDomainData(any())).thenAnswer(invocationOnMock -> {
            Object[] arguments = invocationOnMock.getArguments();
            return domainValidator.getDomainData((JWSDomain) arguments[0]);
        });

        StateFileBuilder stateFileBuilder = new StateFileBuilder(s3client, validator);
        Map<String, DomainState> stateMap = stateFileBuilder.buildStateMap();
        assertEquals(stateMap.size(), 0);
    }

    @Test
    public void testBuildStateMapHalfBadSignatures() {

        // Generate mocked s3Client
        int numberOfDomainsToMock = 500;
        S3Client s3client = buildMockS3Client(numberOfDomainsToMock, false);

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

        S3Client awsS3Client = Mockito.mock(S3Client.class);

        ListObjectsV2Response mockListObjectsV2Response = mock(ListObjectsV2Response.class);

        ArrayList<S3Object> objectList1 = new ArrayList<>();
        S3Object objectSummary = S3Object.builder().key("iaas").build();
        objectList1.add(objectSummary);
        objectSummary = S3Object.builder().key("iaas.athenz").build();
        objectList1.add(objectSummary);

        objectSummary = S3Object.builder().key(".date").build();
        objectList1.add(objectSummary);

        when(mockListObjectsV2Response.contents()).thenReturn(objectList1);
        when(mockListObjectsV2Response.isTruncated()).thenReturn(false);
        when(awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockListObjectsV2Response);

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        StateFileBuilder stateFileBuilder = new StateFileBuilder(awsS3Client, validator);
        List<String> domains = stateFileBuilder.listObjects(awsS3Client);

        assertEquals(domains.size(), 2);
        assertTrue(domains.contains("iaas"));
        assertTrue(domains.contains("iaas.athenz"));
    }

    @Test
    public void testListObjectsAllObjectsMultiplePages() {

        S3Client awsS3Client = Mockito.mock(S3Client.class);

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
        when(awsS3Client.listObjectsV2(any(ListObjectsV2Request.class))).thenReturn(mockListObjectsV2Response);

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        StateFileBuilder stateFileBuilder = new StateFileBuilder(awsS3Client, validator);
        List<String> domains = stateFileBuilder.listObjects(awsS3Client);

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

        S3Client awsS3Client = Mockito.mock(S3Client.class);

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
        when(mockListObjectsV2Response.isTruncated())
                .thenReturn(true);
        when(awsS3Client.listObjectsV2(any(ListObjectsV2Request.class)))
                .thenReturn(mockListObjectsV2Response)
                .thenReturn(mockListObjectsV2Response)
                .thenReturn(null);

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        StateFileBuilder stateFileBuilder = new StateFileBuilder(awsS3Client, validator);
        List<String> domains = stateFileBuilder.listObjects(awsS3Client);

        assertEquals(domains.size(), 4);
        assertTrue(domains.contains("iaas"));
        assertTrue(domains.contains("iaas.athenz"));
        assertTrue(domains.contains("cd"));
        assertTrue(domains.contains("cd.docker"));
    }
}
