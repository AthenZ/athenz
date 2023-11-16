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

import com.yahoo.athenz.zts.ExternalCredentialsRequest;
import com.yahoo.athenz.zts.ExternalCredentialsResponse;

public interface ExternalCredentialsProvider {

    /**
     * Provide the capability for the class based instance provider to
     * obtain external credentials for the given provider (e.g. aws/gcp)
     * @param provider name of the provider (aws/gcp)
     * @param domainName name of the domain
     * @param extCredsRequest request object with optional and required attributes
     * @return ExternalCredentialsResponse object that includes requested external credentials
     */
    ExternalCredentialsResponse getExternalCredentials(String provider, String domainName,
        ExternalCredentialsRequest extCredsRequest);
}
