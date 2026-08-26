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
package com.yahoo.athenz.instance.provider;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;

import javax.net.ssl.SSLContext;

/**
 * Factory for creating {@link AWSAttestationValidator} instances. The factory
 * class is configurable so that Athenz adopters can swap in their own
 * attestation validation implementation.
 */
public interface AWSAttestationValidatorFactory {

    /**
     * Creates and initializes an AWSAttestationValidator.
     * @param sslContext the ssl context to use for any outbound https calls
     * @param authorizer the authorizer to use for any RBAC based checks
     * @param providerPrincipal the principal object for the provider service
     * @return an initialized AWSAttestationValidator
     */
    AWSAttestationValidator create(SSLContext sslContext, Authorizer authorizer, Principal providerPrincipal);
}
