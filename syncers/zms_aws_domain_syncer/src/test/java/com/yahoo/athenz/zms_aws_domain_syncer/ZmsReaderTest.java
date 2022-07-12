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

import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.JWSDomain;
import com.yahoo.athenz.zms.ZMSClient;
import com.yahoo.athenz.zms.ZMSClientException;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class ZmsReaderTest {

    @Test
    public void testGetZmsDomain() {
        System.out.println("testGetZmsDomain");

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        DomainValidator domainValidator = new DomainValidator();
        when(validator.getDomainData(any())).thenAnswer(invocationOnMock -> {
            return domainValidator.getDomainData(invocationOnMock.getArgument(0));
        });

        ZMSClient mockZMSClt = new MockZmsClient().createClient();
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        JWSDomain jwsDomain = zmsReader.getDomain("clouds");
        assertNotNull(jwsDomain);
        DomainData domData = zmsReader.getDomainData(jwsDomain);
        assertEquals(domData.getName(), "clouds");
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
    public void testGetClient() {

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        Config.getInstance().loadProperties();

        try {
            new ZmsReader();
            fail();
        } catch (Exception ignored) {
        }

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
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
}
