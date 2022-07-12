/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.zms_aws_domain_syncer;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.JWSDomain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.util.Base64;
import java.util.function.Function;

public class DomainValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(DomainValidator.class);

    private final ObjectMapper jsonMapper;
    private final Base64.Decoder base64Decoder;

    public DomainValidator() {

        // initialize our jackson object mapper and base64 decoder

        jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        base64Decoder = Base64.getUrlDecoder();
    }

    public DomainData getDomainData(JWSDomain jwsDomain) {
        try {
            byte[] payload = base64Decoder.decode(jwsDomain.getPayload());
            return jsonMapper.readValue(payload, DomainData.class);
        } catch (Exception ex) {
            LOGGER.error("unable to parse jws domain payload", ex);
        }
        return null;
    }

    String extractDomainName(JWSDomain jwsDomain) {
        DomainData domainData = getDomainData(jwsDomain);
        return domainData != null ? domainData.getName() : null;
    }

    public boolean validateJWSDomain(JWSDomain jwsDomain) {

        Function<String, PublicKey> keyGetter = Config.getInstance()::getZmsPublicKey;
        boolean result = Crypto.validateJWSDocument(jwsDomain.getProtectedHeader(), jwsDomain.getPayload(),
                jwsDomain.getSignature(), keyGetter);

        if (!result) {
            LOGGER.error("domain={} signature validation failed", extractDomainName(jwsDomain));
            return false;
        }

        // we also want to validate that we have a valid domain payload

        return getDomainData(jwsDomain) != null;
    }
}
