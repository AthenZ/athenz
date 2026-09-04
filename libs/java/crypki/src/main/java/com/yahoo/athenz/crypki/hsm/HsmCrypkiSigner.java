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
package com.yahoo.athenz.crypki.hsm;

import com.yahoo.athenz.crypki.signer.DefaultCrypkiSigner;

/**
 * In-process signer whose private key never leaves an HSM. AWS CloudHSM
 * implements {@link HsmClient} in server-aws-common.
 */
public class HsmCrypkiSigner extends DefaultCrypkiSigner {

    public HsmCrypkiSigner(HsmClient hsmClient) {
        super(hsmClient::getSigningKey);
    }

    public HsmCrypkiSigner(HsmClient hsmClient, int maxCertExpiryTimeMins) {
        super(hsmClient::getSigningKey, maxCertExpiryTimeMins);
    }
}
