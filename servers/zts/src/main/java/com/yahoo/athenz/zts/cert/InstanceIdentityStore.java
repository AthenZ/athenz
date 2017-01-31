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

public interface InstanceIdentityStore {

    /**
     * Generate Identity for the certificate request passed. The identity
     * store implementation must validate that the CSR is generated for the
     * given CommonName. It may impose further restrictions on the rest of the
     * Subject DN.The identity object must include the signed X509 certificate
     * along with the CA certificate.
     * @param csr Certificate request
     * @param cn the common name for the identity
     * @return Identity object with X509 certificate.
     */
    Identity generateIdentity(String csr, String cn);

    /**
     * Is the CSR valid for the given cn and public key. The method
     * validates that cn passed is exactly what's in the csr subject
     * and the public key in the csr is identical to the one passed.
     * @param csr Certificate request
     * @param cn service common name to be matched against
     * @param publicKey public key to be matched against
     * @return boolean true if details match, false otherwise
     */
    boolean verifyCertificateRequest(String csr, String cn, String publicKey);

    /**
     * The identity store will validate if the given instance request
     * is valid or not. It must validate that the HostDocument included
     * in the request object is valid and signature can be verified.
     * Additionally, it must verify that the domain details in the host
     * document match to the details in the instance object.
     * @param instanceInformation host instance details
     * @return boolean true if instanceInformation is valid, false otherwise
     */
    boolean verifyInstanceIdentity(InstanceInformation instanceInformation);
}
