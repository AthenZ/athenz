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

package io.athenz.syncer.common.zms;

import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.JWSDomain;
import com.yahoo.athenz.zms.ZMSClient;
import com.yahoo.athenz.zms.ZMSClientException;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.Objects;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class ZmsReaderTest {

    private final ClassLoader classLoader = this.getClass().getClassLoader();

    @Test
    public void testGetZmsDomain() {
        System.out.println("testGetZmsDomain");

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        DomainValidator domainValidator = new DomainValidator();
        when(validator.getDomainData(any())).thenAnswer(
                invocationOnMock -> domainValidator.getDomainData(invocationOnMock.getArgument(0)));

        ZMSClient mockZMSClt = new MockZmsClient().createClient();
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        JWSDomain jwsDomain = zmsReader.getDomain("clouds");
        assertNotNull(jwsDomain);
        DomainData domData = zmsReader.getDomainData(jwsDomain);
        Assert.assertEquals(domData.getName(), "clouds");
    }

    @Test
    public void testGetClientFailure() {

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        Config.getInstance().loadProperties();

        // by default, we'll get invalid key/cert causing a failure
        try {
            new ZmsReader();
            fail();
        } catch (Exception ignored) {
        }

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
    }

    @Test
    public void testGetClientSuccess() throws Exception {

        final String certFile = Objects.requireNonNull(classLoader.getResource("unit_test_x509.pem")).getFile();
        final String keyFile = Objects.requireNonNull(classLoader.getResource("unit_test_private.pem")).getFile();
        final String caFile = Objects.requireNonNull(classLoader.getResource("unit_test_truststore.jks")).getFile();

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATHENZ_SVC_KEYFILE, keyFile);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATHENZ_SVC_CERT, certFile);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUST_STORE_PATH, caFile);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUST_STORE_PASSWORD, "secret");
        System.setProperty(Config.PROP_PREFIX + Config.ZMS_CFG_PARAM_ZMS_URL, "https://athenz.io");
        Config.getInstance().loadProperties();

        ZmsReader zmsReader = new ZmsReader();
        assertNotNull(zmsReader);

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATHENZ_SVC_KEYFILE);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATHENZ_SVC_CERT);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUST_STORE_PATH);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUST_STORE_PASSWORD);
        System.clearProperty(Config.PROP_PREFIX + Config.ZMS_CFG_PARAM_ZMS_URL);
    }

    @Test
    public void testGetDomainListFailure() {

        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);
        when(zmsClient.getSignedDomains(any(), any(), any(), anyBoolean(), any(), any()))
                .thenThrow(new ZMSClientException(400, "zms-failure"));
        DomainValidator validator = new DomainValidator();

        ZmsReader zmsReader = new ZmsReader(zmsClient, validator);
        assertNull(zmsReader.getDomainList());
    }

    @Test
    public void testGetDomainFailure() {

        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);
        when(zmsClient.getJWSDomain(any(), any(), any()))
                .thenThrow(new ZMSClientException(429, "rate-limit"))
                .thenThrow(new ZMSClientException(400, "invalid-request"));
        DomainValidator validator = new DomainValidator();

        ZmsReader zmsReader = new ZmsReader(zmsClient, validator);
        assertNull(zmsReader.getDomain("coretech"));
    }

    @Test
    public void testGetDomainFailureInvalidJson() {

        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);
        JWSDomain jwsDomain = new JWSDomain().setPayload("invalid");
        when(zmsClient.getJWSDomain(any(), any(), any())).thenReturn(jwsDomain);
        DomainValidator validator = new DomainValidator();

        ZmsReader zmsReader = new ZmsReader(zmsClient, validator);
        assertNull(zmsReader.getDomain("coretech"));
    }

    @Test
    public void testGetDomainWithInterruptedSleep() {
        // Mock ZMSClient to throw TOO_MANY_REQUESTS then return valid domain on second call
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);
        JWSDomain validDomain = new JWSDomain().setPayload("{\"domain\":{\"name\":\"test-domain\"}}");

        when(zmsClient.getJWSDomain(any(), any(), any()))
                .thenThrow(new ZMSClientException(ZMSClientException.TOO_MANY_REQUESTS, "rate-limited"))
                .thenReturn(validDomain);

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        when(validator.getDomainData(any())).thenReturn(new DomainData().setName("test-domain"));

        // Create ZmsReader with our mocks
        ZmsReader zmsReader = new ZmsReader(zmsClient, validator);

        // Set the interrupt flag before calling getDomain
        Thread.currentThread().interrupt();

        // Call getDomain - should handle the interrupt during sleep
        JWSDomain result = zmsReader.getDomain("test-domain");

        // Verify results
        assertNotNull(result);
        DomainData domainData = zmsReader.getDomainData(result);
        assertEquals("test-domain", domainData.getName());

        // Verify getJWSDomain was called twice (initial failure + retry)
        verify(zmsClient, times(2)).getJWSDomain(any(), any(), any());
    }
}
