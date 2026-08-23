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
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import org.eclipse.jetty.util.StringUtil;

import javax.net.ssl.SSLContext;

/**
 * CompositeAWSAttestationValidator routes each attestation request to the
 * appropriate validator: if the attestation data carries an AWS web identity
 * token then the token is validated, otherwise the request falls back to the
 * traditional STS temporary credentials validation. This allows both mechanisms
 * to be supported simultaneously during a migration.
 */
public class CompositeAWSAttestationValidator implements AWSAttestationValidator {

    final AWSAttestationValidator stsCredentialsValidator;
    final AWSAttestationValidator webIdentityTokenValidator;

    public CompositeAWSAttestationValidator() {
        this(new AWSStsCredentialsAttestationValidator(), new AWSWebIdentityTokenAttestationValidator());
    }

    CompositeAWSAttestationValidator(AWSAttestationValidator stsCredentialsValidator,
            AWSAttestationValidator webIdentityTokenValidator) {
        this.stsCredentialsValidator = stsCredentialsValidator;
        this.webIdentityTokenValidator = webIdentityTokenValidator;
    }

    @Override
    public void initialize(SSLContext sslContext, Authorizer authorizer, Principal providerPrincipal) {
        stsCredentialsValidator.initialize(sslContext, authorizer, providerPrincipal);
        webIdentityTokenValidator.initialize(sslContext, authorizer, providerPrincipal);
    }

    @Override
    public boolean validateIdentity(InstanceConfirmation confirmation, AWSAttestationData info,
            final String awsAccount, StringBuilder errMsg) {
        if (!StringUtil.isEmpty(info.getIdentityToken())) {
            return webIdentityTokenValidator.validateIdentity(confirmation, info, awsAccount, errMsg);
        }
        return stsCredentialsValidator.validateIdentity(confirmation, info, awsAccount, errMsg);
    }
}
