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
package com.yahoo.athenz.zms_aws_json_domain_syncer;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zms.SignedDomain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;

public class DomainValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(DomainValidator.class);

    // Validate domain signature.
    // This method is not thread safe.
    public boolean validateSignedDomain(SignedDomain signedDomain) {

        String keyId = signedDomain.getKeyId();
        Config configInstance = Config.getInstance();

        PublicKey zmsKey = configInstance.getZmsPublicKey(keyId);
        if (zmsKey == null) {
            LOGGER.error("DomainValidator:getDomain: ZMS Public Key id: " + keyId
                    + " : not available. Cannot validate domain=" + signedDomain.getDomain().getName());
            return false;
        }

        if (!Crypto.verify(SignUtils.asCanonicalString(signedDomain.getDomain()), zmsKey, signedDomain.getSignature())) {
            LOGGER.error("DomainValidator:getDomain: ZMS Public Key id: " + keyId
                    + " : Validation failed for domain: " + signedDomain);
            return false;
        }

        return true;
    }
}
