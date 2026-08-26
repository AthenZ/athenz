/*
 * Copyright The Athenz Authors
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
package com.yahoo.athenz.instance.provider.impl;

import com.yahoo.athenz.instance.provider.AWSAttestationValidator;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.testng.Assert.assertTrue;

public class CompositeAWSAttestationValidatorTest {

    @Test
    public void testDefaultConstructor() {
        CompositeAWSAttestationValidator validator = new CompositeAWSAttestationValidator();
        assertTrue(validator.stsCredentialsValidator instanceof AWSStsCredentialsAttestationValidator);
        assertTrue(validator.webIdentityTokenValidator instanceof AWSWebIdentityTokenAttestationValidator);
    }

    @Test
    public void testInitializeDelegatesToBoth() {
        AWSAttestationValidator sts = Mockito.mock(AWSAttestationValidator.class);
        AWSAttestationValidator webId = Mockito.mock(AWSAttestationValidator.class);
        CompositeAWSAttestationValidator validator = new CompositeAWSAttestationValidator(sts, webId);
        validator.initialize(null, null, null);
        Mockito.verify(sts).initialize(any(), any(), any());
        Mockito.verify(webId).initialize(any(), any(), any());
    }

    @Test
    public void testRouteToWebIdentityWhenTokenPresent() {
        AWSAttestationValidator sts = Mockito.mock(AWSAttestationValidator.class);
        AWSAttestationValidator webId = Mockito.mock(AWSAttestationValidator.class);
        Mockito.when(webId.validateIdentity(any(), any(), eq("1234"), any())).thenReturn(true);
        CompositeAWSAttestationValidator validator = new CompositeAWSAttestationValidator(sts, webId);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken("some-jwt-token");
        StringBuilder errMsg = new StringBuilder(256);
        assertTrue(validator.validateIdentity(confirmation, info, "1234", errMsg));

        Mockito.verify(webId).validateIdentity(confirmation, info, "1234", errMsg);
        Mockito.verify(sts, Mockito.never()).validateIdentity(any(), any(), any(), any());
    }

    @Test
    public void testRouteToStsWhenNoToken() {
        AWSAttestationValidator sts = Mockito.mock(AWSAttestationValidator.class);
        AWSAttestationValidator webId = Mockito.mock(AWSAttestationValidator.class);
        Mockito.when(sts.validateIdentity(any(), any(), eq("1234"), any())).thenReturn(true);
        CompositeAWSAttestationValidator validator = new CompositeAWSAttestationValidator(sts, webId);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        AWSAttestationData info = new AWSAttestationData();
        info.setAccess("access");
        StringBuilder errMsg = new StringBuilder(256);
        assertTrue(validator.validateIdentity(confirmation, info, "1234", errMsg));

        Mockito.verify(sts).validateIdentity(confirmation, info, "1234", errMsg);
        Mockito.verify(webId, Mockito.never()).validateIdentity(any(), any(), any(), any());
    }
}
