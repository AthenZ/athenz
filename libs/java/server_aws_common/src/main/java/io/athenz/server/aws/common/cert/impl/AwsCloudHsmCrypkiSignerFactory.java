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
package io.athenz.server.aws.common.cert.impl;

import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.common.server.cert.CertSignerFactory;
import com.yahoo.athenz.crypki.CrypkiCertSigner;
import com.yahoo.athenz.crypki.CrypkiRequestFactory;
import com.yahoo.athenz.crypki.CrypkiSigner;
import com.yahoo.athenz.crypki.CrypkiSignerFactory;
import com.yahoo.athenz.crypki.hsm.HsmClient;
import com.yahoo.athenz.crypki.hsm.HsmCrypkiSigner;

/**
 * ZTS factory: {@code athenz.zts.cert_signer_factory_class=io.athenz.server.aws.common.cert.impl.AwsCloudHsmCrypkiSignerFactory}
 *
 * Uses the Crypki {@link HsmClient} SPI. Default CloudHSM PKCS#11 module path is
 * {@code /opt/cloudhsm/lib/libcloudhsm_pkcs11.so}.
 */
public class AwsCloudHsmCrypkiSignerFactory implements CertSignerFactory, CrypkiSignerFactory {

    private final HsmClient hsmClient;

    public AwsCloudHsmCrypkiSignerFactory() {
        this(null);
    }

    public AwsCloudHsmCrypkiSignerFactory(HsmClient hsmClient) {
        this.hsmClient = hsmClient;
    }

    @Override
    public CrypkiSigner createSigner() {
        return new HsmCrypkiSigner(hsmClient == null ? newCloudHsmClient() : hsmClient);
    }

    @Override
    public CertSigner create() {
        return new CrypkiCertSigner(createSigner(), CrypkiRequestFactory.forHsm());
    }

    HsmClient newCloudHsmClient() {
        return new AwsCloudHsmClient();
    }
}
