/*
 * Copyright 2018 Oath Inc.
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
package com.yahoo.athenz.common.server.ssh;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.zts.SSHCertRequest;
import com.yahoo.athenz.zts.SSHCertificates;

public interface SSHSigner {

    /**
     * Generate an SSH Certificate based on the given request
     * for a given principal
     * @param principal Principal requesting the ssh certificates
     * @param certRequest SSH Certificate Request
     * @return SSH Certificates
     */
    default SSHCertificates generateCertificate(Principal principal, SSHCertRequest certRequest) {
        return null;
    }

    /**
     * Retrieve the SSH Signer certificate for the given type
     * @param type signer type: user or host
     * @return SSH Signer Certificate
     */
    default String getSignerCertificate(String type) {
        return null;
    }

    /**
     * Set the server authorizer object that the ssh signer
     * can use to for any authorization checks, if necessary
     * @param authorizer Authorizer object
     */

    default void setAuthorizer(Authorizer authorizer) {
    }

    /**
     * Close the sshSigner signer object and release all
     * allocated resources (if any)
     */
    default void close() {
    }
}
