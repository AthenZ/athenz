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

package com.yahoo.athenz.common.server.external;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.server.rest.ResourceException;
import com.yahoo.athenz.zts.DomainDetails;
import com.yahoo.athenz.zts.ExternalCredentialsRequest;
import com.yahoo.athenz.zts.ExternalCredentialsResponse;

public interface ExternalCredentialsProvider {

    /**
     * Set the server authorizer object that the external credentials
     * provider can use it for any authorization checks, if necessary
     * @param authorizer Authorizer object
     */
    void setAuthorizer(Authorizer authorizer);

    /**
     * Get credentials from the external provider for the given principal
     * with the provided id token based on attributes specified in the
     * request object
     * @param principal principal object requesting credentials
     * @param domainDetails domain attributes including associated cloud provider account/project
     * @param idToken principal's id token
     * @param externalCredentialsRequest credentials request object
     * @return response object including the requested credentials
     * @throws ResourceException in case of any errors
     */
    ExternalCredentialsResponse getCredentials(Principal principal, DomainDetails domainDetails,
        final String idToken, ExternalCredentialsRequest externalCredentialsRequest) throws ResourceException;
}
