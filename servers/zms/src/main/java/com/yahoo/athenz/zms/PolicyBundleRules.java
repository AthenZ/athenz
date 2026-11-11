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
package com.yahoo.athenz.zms;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.store.PolicyBundleValidator;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Structural validation rules for policy bundles. Each engine has its own
 * set of allowed files; common rules (relative paths, size limits, roots)
 * apply to all engines. ZMS does not compile or evaluate the content - an
 * optional engine specific PolicyBundleValidator can be configured for that.
 */
public class PolicyBundleRules {

    private static final Logger LOG = LoggerFactory.getLogger(PolicyBundleRules.class);

    static final int MAX_PATH_LENGTH = 512;
    static final int MAX_DESCRIPTION_LENGTH = 4096;
    static final int MAX_ROOT_LENGTH = 256;
    // roots are stored comma separated in a VARCHAR(2048) column
    static final int MAX_ROOTS_TOTAL_LENGTH = 2048;

    // ZTS generates the signing keys data file at this path relative to the
    // first bundle root when the bundle is served so users are not allowed
    // to include a file at that location

    static final String RESERVED_KEYS_PATH = "athenz/zts/keys/data.json";

    private static final Pattern PATH_SEGMENT_PATTERN = Pattern.compile("[a-zA-Z0-9_][a-zA-Z0-9_.-]*");
    private static final Pattern ROOT_PATTERN = Pattern.compile("[a-zA-Z0-9_][a-zA-Z0-9_-]*(/[a-zA-Z0-9_][a-zA-Z0-9_-]*)*");

    private static final String REGO_EXT_MODULE = ".rego";
    private static final String REGO_FILE_DATA_JSON = "data.json";

    final Set<String> engines;
    final int maxVersions;
    final int maxFiles;
    final int maxFileSize;
    final int maxBundleSize;
    final int maxRoots;
    final String validationMode;
    final PolicyBundleValidator contentValidator;
    final ObjectMapper jsonMapper = new ObjectMapper();

    public PolicyBundleRules(PolicyBundleValidator contentValidator) {

        this.contentValidator = contentValidator;

        engines = new HashSet<>();
        final String engineList = System.getProperty(ZMSConsts.ZMS_PROP_BUNDLE_ENGINES,
                ZMSConsts.BUNDLE_ENGINE_REGO);
        for (String engine : engineList.split(",")) {
            engine = engine.trim().toLowerCase();
            if (ZMSConsts.BUNDLE_ENGINE_REGO.equals(engine)) {
                engines.add(engine);
            } else if (!engine.isEmpty()) {
                LOG.error("Ignoring unsupported policy bundle engine: {}", engine);
            }
        }

        maxVersions = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_MAX_BUNDLE_VERSIONS, "5"));
        maxFiles = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_MAX_BUNDLE_FILES, "100"));
        maxFileSize = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_MAX_BUNDLE_FILE_SIZE, "1048576"));
        maxBundleSize = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_MAX_BUNDLE_SIZE, "4194304"));
        maxRoots = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_MAX_BUNDLE_ROOTS, "16"));

        String mode = System.getProperty(ZMSConsts.ZMS_PROP_BUNDLE_VALIDATION_MODE,
                ZMSConsts.BUNDLE_VALIDATION_MODE_ENFORCE).toLowerCase();
        if (!ZMSConsts.BUNDLE_VALIDATION_MODE_OFF.equals(mode) && !ZMSConsts.BUNDLE_VALIDATION_MODE_WARN.equals(mode)) {
            mode = ZMSConsts.BUNDLE_VALIDATION_MODE_ENFORCE;
        }
        validationMode = mode;
    }

    public int getMaxVersions() {
        return maxVersions;
    }

    /**
     * Validate the given bundle and compute the sha-256 digest of each
     * file (any client provided digest values are replaced).
     * @param domainName name of the domain
     * @param bundleName name of the bundle
     * @param bundle bundle object to be validated
     * @param caller api name
     */
    public void validate(final String domainName, final String bundleName, PolicyBundle bundle, final String caller) {

        final String fullBundleName = ResourceUtils.policyBundleResourceName(domainName, bundleName);
        if (!fullBundleName.equals(bundle.getName())) {
            throw ZMSUtils.requestError("bundle name mismatch: " + fullBundleName + " != " + bundle.getName(), caller);
        }

        final String engine = bundle.getEngine();
        if (!engines.contains(engine)) {
            throw ZMSUtils.requestError("unsupported bundle engine: " + engine, caller);
        }

        if (bundle.getDescription() != null && bundle.getDescription().length() > MAX_DESCRIPTION_LENGTH) {
            throw ZMSUtils.requestError("bundle description exceeds maximum length of " + MAX_DESCRIPTION_LENGTH, caller);
        }

        validateRoots(domainName, bundle.getRoots(), caller);
        validateFiles(engine, bundle.getFiles(), reservedKeysPath(domainName, bundleName, bundle.getRoots()), caller);
        validateContent(domainName, bundleName, bundle, caller);
    }

    void validateRoots(final String domainName, List<String> roots, final String caller) {

        if (roots == null) {
            return;
        }
        if (roots.size() > maxRoots) {
            throw ZMSUtils.requestError("bundle roots exceed maximum count of " + maxRoots, caller);
        }
        // roots must be within the domain namespace (<domain with . as />)
        // so one domain cannot claim data owned by another domain

        final String domainRoot = domainName.replace('.', '/');
        int totalLength = 0;
        for (String root : roots) {
            if (root == null || root.length() > MAX_ROOT_LENGTH || !ROOT_PATTERN.matcher(root).matches()) {
                throw ZMSUtils.requestError("invalid bundle root: " + root, caller);
            }
            if (!root.equals(domainRoot) && !root.startsWith(domainRoot + "/")) {
                throw ZMSUtils.requestError("bundle root must be within the domain namespace '"
                        + domainRoot + "': " + root, caller);
            }
            totalLength += root.length() + 1;
        }
        // opa requires manifest roots to be non-overlapping so reject
        // duplicates and ancestor/descendant pairs

        for (int i = 0; i < roots.size(); i++) {
            for (int j = i + 1; j < roots.size(); j++) {
                final String r1 = roots.get(i);
                final String r2 = roots.get(j);
                if (r1.equals(r2) || r1.startsWith(r2 + "/") || r2.startsWith(r1 + "/")) {
                    throw ZMSUtils.requestError("overlapping bundle roots: " + r1 + ", " + r2, caller);
                }
            }
        }
        if (totalLength - 1 > MAX_ROOTS_TOTAL_LENGTH) {
            throw ZMSUtils.requestError("bundle roots exceed maximum total length of " + MAX_ROOTS_TOTAL_LENGTH, caller);
        }
    }

    // the effective first root matches the one used by ZTS when generating the archive

    String reservedKeysPath(final String domainName, final String bundleName, List<String> roots) {
        final String root = (roots != null && !roots.isEmpty()) ? roots.get(0)
                : domainName.replace('.', '/') + "/" + bundleName.replace('.', '/');
        return root + "/" + RESERVED_KEYS_PATH;
    }

    void validateFiles(final String engine, List<PolicyBundleFile> files, final String reservedPath,
            final String caller) {

        if (files == null || files.isEmpty()) {
            throw ZMSUtils.requestError("bundle must include at least one file", caller);
        }
        if (files.size() > maxFiles) {
            throw ZMSUtils.requestError("bundle files exceed maximum count of " + maxFiles, caller);
        }

        Set<String> paths = new HashSet<>();
        long bundleSize = 0;
        int policyFiles = 0;
        int schemaFiles = 0;

        for (PolicyBundleFile file : files) {

            if (file == null) {
                throw ZMSUtils.requestError("bundle includes an empty file object", caller);
            }

            final String path = file.getPath();
            validatePath(path, caller);
            if (reservedPath.equals(path)) {
                throw ZMSUtils.requestError("bundle file path " + path + " is reserved for generated files", caller);
            }
            if (!paths.add(path)) {
                throw ZMSUtils.requestError("duplicate bundle file path: " + path, caller);
            }

            if (file.getContent() == null) {
                throw ZMSUtils.requestError("bundle file has no content: " + path, caller);
            }
            final byte[] content = file.getContent().getBytes(StandardCharsets.UTF_8);
            if (content.length > maxFileSize) {
                throw ZMSUtils.requestError("bundle file " + path + " exceeds maximum size of " + maxFileSize, caller);
            }
            bundleSize += content.length;
            if (bundleSize > maxBundleSize) {
                throw ZMSUtils.requestError("bundle exceeds maximum size of " + maxBundleSize, caller);
            }

            final String fileName = path.substring(path.lastIndexOf('/') + 1);
            if (ZMSConsts.BUNDLE_ENGINE_REGO.equals(engine)) {
                if (fileName.endsWith(REGO_EXT_MODULE)) {
                    policyFiles += 1;
                } else if (fileName.equals(REGO_FILE_DATA_JSON)) {
                    validateJson(path, file.getContent(), caller);
                } else {
                    // data.yaml is not supported since ZTS must compute the OPA
                    // structured file digest for data files when signing bundles
                    throw ZMSUtils.requestError("file " + path + " is not supported for rego bundles - allowed: *"
                            + REGO_EXT_MODULE + ", " + REGO_FILE_DATA_JSON, caller);
                }
            } else {
                throw ZMSUtils.requestError("file " + path + " is not supported for bundles", caller);
            }

            file.setSha256(sha256Hex(content));
        }

        if (policyFiles == 0) {
            throw ZMSUtils.requestError("bundle must include at least one policy file", caller);
        }
    }

    void validatePath(final String path, final String caller) {

        if (StringUtil.isEmpty(path) || path.length() > MAX_PATH_LENGTH) {
            throw ZMSUtils.requestError("invalid bundle file path: " + path, caller);
        }

        // every segment must be a valid name: this rejects absolute paths,
        // empty segments, "." and ".." references, hidden files such as
        // .manifest and .signatures.json, backslashes and any other special
        // characters

        final String[] segments = path.split("/", -1);
        for (String segment : segments) {
            if (!PATH_SEGMENT_PATTERN.matcher(segment).matches()) {
                throw ZMSUtils.requestError("invalid bundle file path: " + path, caller);
            }
        }
    }

    void validateJson(final String path, final String content, final String caller) {
        try {
            // the whole content must be exactly one json document. readTree
            // accepts empty input and ignores trailing values by default
            // while ZTS rejects both when hashing the file

            if (jsonMapper.readerFor(JsonNode.class).with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                    .readTree(content).isMissingNode()) {
                throw new IllegalArgumentException("empty content");
            }
        } catch (Exception ex) {
            throw ZMSUtils.requestError("bundle file " + path + " is not valid json: " + ex.getMessage(), caller);
        }
    }

    void validateContent(final String domainName, final String bundleName, PolicyBundle bundle, final String caller) {

        if (contentValidator == null || ZMSConsts.BUNDLE_VALIDATION_MODE_OFF.equals(validationMode)) {
            return;
        }

        final String error = contentValidator.validatePolicyBundle(domainName, bundleName, bundle);
        if (error == null) {
            return;
        }

        if (ZMSConsts.BUNDLE_VALIDATION_MODE_WARN.equals(validationMode)) {
            LOG.warn("policy bundle {} validation failed: {}", bundle.getName(), error);
            return;
        }
        throw ZMSUtils.requestError("bundle validation failed: " + error, caller);
    }

    static String sha256Hex(final byte[] content) {
        final byte[] digest = Crypto.sha256(content);
        StringBuilder hex = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            hex.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return hex.toString();
    }
}
