/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.zts.cert;

import com.yahoo.athenz.zts.Identity;
import com.yahoo.athenz.zts.InstanceInformation;

public interface SvcCertStore {

    /**
     * Generate Identity for the csr passed.
     * @param csr Certificate request
     * @param serviceYrn
     * @return Identity
     */
    Identity generateIdentity(String csr, String serviceYrn);

    /**
     * Is the request valid? Is the HostDocument valid and matches the signature
     * Does the domain match the one in host document
     * @param instanceInformation
     * @return boolean true if instanceInformation is valid, false otherwise
     */
    boolean isValidRequest(InstanceInformation instanceInformation);
}
