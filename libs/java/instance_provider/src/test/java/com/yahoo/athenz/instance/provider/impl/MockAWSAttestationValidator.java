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

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.instance.provider.AWSAttestationValidator;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;

import javax.net.ssl.SSLContext;

/**
 * Test attestation validator whose result can be toggled so provider tests can
 * force instance identity verification to succeed or fail without calling AWS.
 */
public class MockAWSAttestationValidator implements AWSAttestationValidator {

    boolean identityResult = true;

    @Override
    public void initialize(SSLContext sslContext, Authorizer authorizer) {
    }

    @Override
    public boolean validateIdentity(InstanceConfirmation confirmation, AWSAttestationData info,
            final String awsAccount, StringBuilder errMsg) {
        if (!identityResult) {
            errMsg.append("mock identity failure");
        }
        return identityResult;
    }
}
