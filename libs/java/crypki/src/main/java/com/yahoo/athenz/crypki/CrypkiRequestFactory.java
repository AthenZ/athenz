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
package com.yahoo.athenz.crypki;

import com.yahoo.athenz.common.server.cert.Priority;
import org.eclipse.jetty.util.StringUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Builds a {@link X509SignRequest} from ZTS {@code CertSigner} arguments.
 * Key-id resolution matches the historical HttpCertSigner behavior.
 */
public class CrypkiRequestFactory {

    private final String defaultKeyId;
    private final Map<String, String> providerSignerKeys;
    private final int maxCertExpiryTimeMins;

    public CrypkiRequestFactory() {
        this(CrypkiConsts.DEFAULT_KEY_ID, Map.of(), CrypkiConsts.DEFAULT_MAX_CERT_EXPIRY_TIME_MINS);
    }

    /**
     * Default key id is {@code athenz.crypki.kms.key_id} so ZTS refresh
     * (no {@code signerKeyId}) uses the KMS alias or key UUID, not
     * {@code x509-key}.
     */
    public static CrypkiRequestFactory forKms() {
        return new CrypkiRequestFactory(
                System.getProperty(CrypkiConsts.PROP_KMS_KEY_ID, CrypkiConsts.DEFAULT_KEY_ID),
                Map.of(), CrypkiConsts.DEFAULT_MAX_CERT_EXPIRY_TIME_MINS);
    }

    /**
     * Default key id is {@code athenz.crypki.hsm.key_label} so ZTS refresh
     * (no {@code signerKeyId}) uses the PKCS#11 label, not {@code x509-key}.
     */
    public static CrypkiRequestFactory forHsm() {
        return new CrypkiRequestFactory(
                System.getProperty(CrypkiConsts.PROP_HSM_KEY_LABEL, CrypkiConsts.DEFAULT_HSM_KEY_LABEL),
                Map.of(), CrypkiConsts.DEFAULT_MAX_CERT_EXPIRY_TIME_MINS);
    }

    public CrypkiRequestFactory(String defaultKeyId, Map<String, String> providerSignerKeys,
            int maxCertExpiryTimeMins) {
        this.defaultKeyId = defaultKeyId == null || defaultKeyId.isEmpty()
                ? CrypkiConsts.DEFAULT_KEY_ID : defaultKeyId;
        this.providerSignerKeys = providerSignerKeys == null ? Map.of() : providerSignerKeys;
        this.maxCertExpiryTimeMins = maxCertExpiryTimeMins <= 0
                ? CrypkiConsts.DEFAULT_MAX_CERT_EXPIRY_TIME_MINS : maxCertExpiryTimeMins;
    }

    public X509SignRequest create(String provider, String csr, String keyUsage, int expireMins,
            Priority priority, String signerKeyId) {
        return X509SignRequest.builder()
                .keyId(resolveKeyId(provider, signerKeyId))
                .csrPem(csr)
                .validitySeconds(toValiditySeconds(expireMins))
                .extKeyUsage(toExtKeyUsage(keyUsage))
                .priority(priority)
                .build();
    }

    public String resolveKeyId(String provider, String signerKeyId) {
        if (!StringUtil.isEmpty(signerKeyId)) {
            return signerKeyId;
        }
        if (StringUtil.isEmpty(provider)) {
            return defaultKeyId;
        }
        final String keyId = providerSignerKeys.get(provider);
        return keyId == null ? defaultKeyId : keyId;
    }

    public int toValiditySeconds(int expireMins) {
        if (expireMins > 0 && expireMins < maxCertExpiryTimeMins) {
            return (int) TimeUnit.SECONDS.convert(expireMins, TimeUnit.MINUTES);
        }
        return (int) TimeUnit.SECONDS.convert(maxCertExpiryTimeMins, TimeUnit.MINUTES);
    }

    public static List<Integer> toExtKeyUsage(String keyUsage) {
        if (CrypkiConsts.CERT_USAGE_CLIENT.equals(keyUsage)) {
            List<Integer> usage = new ArrayList<>();
            usage.add(2);
            return usage;
        }
        if (CrypkiConsts.CERT_USAGE_CODE_SIGNING.equals(keyUsage)) {
            List<Integer> usage = new ArrayList<>();
            usage.add(3);
            return usage;
        }
        if (CrypkiConsts.CERT_USAGE_TIMESTAMPING.equals(keyUsage)) {
            List<Integer> usage = new ArrayList<>();
            usage.add(8);
            return usage;
        }
        return Collections.emptyList();
    }
}
