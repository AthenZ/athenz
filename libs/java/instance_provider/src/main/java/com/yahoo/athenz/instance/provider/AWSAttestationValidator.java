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
import com.yahoo.athenz.instance.provider.impl.AWSAttestationData;

import javax.net.ssl.SSLContext;

/**
 * AWSAttestationValidator verifies that the attestation data presented by an
 * AWS instance proves that the instance is the requested role in the given
 * AWS account. Implementations may validate the identity using STS temporary
 * credentials (the traditional GetCallerIdentity approach) or by validating an
 * AWS-issued web identity JWT, allowing Athenz adopters to choose the mechanism
 * that fits their environment.
 */
public interface AWSAttestationValidator {

    /**
     * Initialize the validator with the given ssl context, authorizer and
     * provider principal. The ssl context is used when the validator needs to
     * fetch remote data (e.g. the issuer's JWKS); the authorizer is used for
     * any RBAC based checks while the provider principal identifies the
     * provider service carrying out those checks.
     * @param sslContext the ssl context to use for any outbound https calls
     * @param authorizer the authorizer to use for any RBAC based checks
     * @param providerPrincipal the principal object for the provider service
     */
    void initialize(SSLContext sslContext, Authorizer authorizer, Principal providerPrincipal);

    /**
     * Validates that the given attestation data proves the instance identity.
     * @param confirmation the instance confirmation request (domain, service, attributes)
     * @param info the parsed AWS attestation data from the confirmation request
     * @param awsAccount the AWS account id(s) associated with the requested identity. this
     *                   may be empty if the domain has no associated aws account, in which
     *                   case the implementation must either reject the request or authorize
     *                   it through some other mechanism (e.g. a launch policy check)
     * @param errMsg StringBuilder to append error details to on failure
     * @return true if the attestation data is valid, otherwise false
     */
    boolean validateIdentity(InstanceConfirmation confirmation, AWSAttestationData info,
            String awsAccount, StringBuilder errMsg);
}
