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
package com.yahoo.athenz.zts.cert.impl;

import com.yahoo.athenz.zts.*;
import com.yahoo.athenz.zts.cert.CertSigner;
import com.yahoo.athenz.zts.cert.InstanceIdentityStore;
import com.yahoo.athenz.zts.utils.ZTSUtils;

public class LocalInstanceIdentityStore implements InstanceIdentityStore {
    CertSigner certSigner = null;
    String caPEMCertificate = null;

    public LocalInstanceIdentityStore() {
    }

    public LocalInstanceIdentityStore(CertSigner certSigner) {
        this.certSigner = certSigner;
        if (certSigner != null) {
            caPEMCertificate = certSigner.getCACertificate();
        }
    }

    @Override
    public boolean verifyCertificateRequest(String csr, String cn, String publicKey) {
        return ZTSUtils.verifyCertificateRequest(csr, cn, publicKey);
    }
    
    @Override
    public Identity generateIdentity(String csr, String cn) {
        return ZTSUtils.generateIdentity(certSigner, csr, cn, caPEMCertificate);
    }

    /**
     * This local implementation does not verify the instance document
     * and is provided as a sample only.
     */
    @Override
    public boolean verifyInstanceIdentity(InstanceInformation instanceInformation) {
        return true;
    }
}
