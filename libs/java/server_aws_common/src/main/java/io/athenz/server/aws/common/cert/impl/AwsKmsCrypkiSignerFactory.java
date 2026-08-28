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
import com.yahoo.athenz.crypki.kms.KmsClient;
import com.yahoo.athenz.crypki.kms.KmsCrypkiSigner;

/**
 * ZTS factory: {@code athenz.zts.cert_signer_factory_class=io.athenz.server.aws.common.cert.impl.AwsKmsCrypkiSignerFactory}
 */
public class AwsKmsCrypkiSignerFactory implements CertSignerFactory, CrypkiSignerFactory {

    private final KmsClient kmsClient;

    public AwsKmsCrypkiSignerFactory() {
        this(null);
    }

    public AwsKmsCrypkiSignerFactory(KmsClient kmsClient) {
        this.kmsClient = kmsClient;
    }

    @Override
    public CrypkiSigner createSigner() {
        return new KmsCrypkiSigner(kmsClient == null ? newKmsClient() : kmsClient);
    }

    @Override
    public CertSigner create() {
        return new CrypkiCertSigner(createSigner(), CrypkiRequestFactory.forKms());
    }

    KmsClient newKmsClient() {
        return new AwsKmsClient();
    }
}
