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
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.instance.provider.AWSAttestationValidator;
import com.yahoo.athenz.instance.provider.AWSAttestationValidatorFactory;

import javax.net.ssl.SSLContext;

/**
 * Default factory that creates a {@link CompositeAWSAttestationValidator} which
 * supports both the AWS STS temporary credentials and AWS web identity token
 * attestation mechanisms.
 */
public class DefaultAWSAttestationValidatorFactory implements AWSAttestationValidatorFactory {

    @Override
    public AWSAttestationValidator create(SSLContext sslContext, Authorizer authorizer, Principal providerPrincipal) {
        AWSAttestationValidator validator = new CompositeAWSAttestationValidator();
        validator.initialize(sslContext, authorizer, providerPrincipal);
        return validator;
    }
}
