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
package com.yahoo.athenz.crypki.kms;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.crypki.CrypkiConsts;
import com.yahoo.athenz.crypki.CrypkiException;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves the CA PEM (and optional backend key id) for an Athenz
 * {@code x509CertSignerKeyId}. ZTS request fields use SimpleName
 * ({@code tenant-a-ca}); they cannot be {@code alias/...} or GCP resource
 * names. Domain/service metadata stores the same field as String.
 * KMS and CloudHSM share this JSON shape. A single default path
 * keeps current deployments working. An optional JSON map lets each
 * tenant key id load its own CA PEM and, when needed, the real KMS key
 * id or CloudHSM label.
 *
 * <p>CA PEMs are loaded once and cached for the process lifetime. ZTS
 * {@code InstanceCertManager} also caches {@code getCACertificate} per
 * signer key until restart, so an in-place PEM rewrite would mint leaves
 * under a CA that ZTS no longer returns to clients. Rotate a tenant CA
 * by replacing the file and restarting ZTS.
 */
public class KmsCaCertificateStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(KmsCaCertificateStore.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String defaultCertPath;
    private final String missingDefaultProp;
    private final Map<String, Mapping> mappings;
    private final Map<String, X509Certificate> cache = new ConcurrentHashMap<>();

    public static KmsCaCertificateStore fromProperties() {
        return new KmsCaCertificateStore(
                System.getProperty(CrypkiConsts.PROP_KMS_CA_CERT_PATH),
                System.getProperty(CrypkiConsts.PROP_KMS_CA_CERT_MAP_PATH));
    }

    public static KmsCaCertificateStore fromHsmProperties() {
        return new KmsCaCertificateStore(
                System.getProperty(CrypkiConsts.PROP_HSM_CA_CERT_PATH),
                System.getProperty(CrypkiConsts.PROP_HSM_CA_CERT_MAP_PATH),
                CrypkiConsts.PROP_HSM_CA_CERT_PATH);
    }

    public KmsCaCertificateStore(String defaultCertPath, String mapPath) {
        this(defaultCertPath, mapPath, CrypkiConsts.PROP_KMS_CA_CERT_PATH);
    }

    public KmsCaCertificateStore(String defaultCertPath, String mapPath, String missingDefaultProp) {
        this.defaultCertPath = defaultCertPath;
        this.missingDefaultProp = missingDefaultProp;
        this.mappings = loadMap(mapPath);
    }

    public X509Certificate get(String keyId) {
        return certificate(resolvePath(keyId));
    }

    X509Certificate certificate(String certPath) {
        return cache.computeIfAbsent(certPath, KmsCaCertificateStore::loadCertificate);
    }

    /**
     * Cloud KMS key id for this Athenz signer id. Object map entries may
     * set {@code keyId}; otherwise the requested id is returned unchanged.
     */
    public String resolveCloudKeyId(String keyId) {
        if (!StringUtil.isEmpty(keyId)) {
            Mapping mapped = mappings.get(keyId);
            if (mapped != null && !StringUtil.isEmpty(mapped.cloudKeyId)) {
                return mapped.cloudKeyId;
            }
        }
        return keyId;
    }

    String resolvePath(String keyId) {
        if (!StringUtil.isEmpty(keyId)) {
            Mapping mapped = mappings.get(keyId);
            if (mapped != null && !StringUtil.isEmpty(mapped.caCertPath)) {
                return mapped.caCertPath;
            }
        }
        if (StringUtil.isEmpty(defaultCertPath)) {
            throw new CrypkiException("Missing " + missingDefaultProp + " for key " + keyId);
        }
        return defaultCertPath;
    }

    public Map<String, String> getCertPathsByKeyId() {
        Map<String, String> paths = new LinkedHashMap<>();
        for (Map.Entry<String, Mapping> entry : mappings.entrySet()) {
            paths.put(entry.getKey(), entry.getValue().caCertPath);
        }
        return paths;
    }

    static Map<String, Mapping> loadMap(String mapPath) {
        if (StringUtil.isEmpty(mapPath)) {
            return Collections.emptyMap();
        }
        try {
            JsonNode root = MAPPER.readTree(Files.readString(Path.of(mapPath)));
            if (root == null || root.isNull()) {
                return Collections.emptyMap();
            }
            if (!root.isObject()) {
                throw new CrypkiException("CA certificate map must be a JSON object: " + mapPath);
            }
            if (root.isEmpty()) {
                return Collections.emptyMap();
            }
            Map<String, Mapping> parsed = new LinkedHashMap<>();
            root.fields().forEachRemaining(field ->
                    parsed.put(field.getKey(), mappingFromNode(field.getKey(), field.getValue())));
            LOGGER.info("Loaded {} CA certificate mappings from {}", parsed.size(), mapPath);
            return Collections.unmodifiableMap(parsed);
        } catch (CrypkiException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new CrypkiException("Unable to parse CA certificate map: " + mapPath, ex);
        }
    }

    static Mapping mappingFromNode(String keyId, JsonNode node) {
        if (node == null || node.isNull()) {
            throw new CrypkiException("CA map entry for " + keyId + " is missing caCertPath");
        }
        if (node.isTextual()) {
            return requireCertPath(keyId, null, node.asText());
        }
        if (node.isObject()) {
            return requireCertPath(keyId, textOrEmpty(node.get("keyId")),
                    textOrEmpty(node.get("caCertPath")));
        }
        throw new CrypkiException("Invalid CA map entry for " + keyId);
    }

    static Mapping requireCertPath(String keyId, String cloudKeyId, String caCertPath) {
        String path = caCertPath == null ? "" : caCertPath.strip();
        if (path.isEmpty()) {
            throw new CrypkiException("CA map entry for " + keyId + " is missing caCertPath");
        }
        return new Mapping(cloudKeyId, path);
    }

    static String textOrEmpty(JsonNode node) {
        return node == null || node.isNull() || !node.isTextual() ? "" : node.asText();
    }

    static X509Certificate loadCertificate(String certPath) {
        try {
            X509Certificate certificate = Crypto.loadX509Certificate(Files.readString(Path.of(certPath)));
            if (certificate == null) {
                throw new CrypkiException("Unable to load CA certificate: " + certPath);
            }
            return certificate;
        } catch (CrypkiException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new CrypkiException("Unable to load CA certificate: " + certPath, ex);
        }
    }

    static final class Mapping {
        final String cloudKeyId;
        final String caCertPath;

        Mapping(String cloudKeyId, String caCertPath) {
            this.cloudKeyId = cloudKeyId;
            this.caCertPath = caCertPath;
        }
    }

}
