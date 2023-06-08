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

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.config.AthenzConfig;
import com.yahoo.athenz.zms.PublicKeyEntry;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Config {

    private static final Logger LOGGER = LoggerFactory.getLogger(Config.class);

    static final String DEFAULT_STATEPATH = "/opt/zms_syncer";
    static final String ATHENZ_CONFIG_FILE = "/zms_syncer/conf/athenz.conf";
    static final String DEFAULT_ATH_SVC_KEYFILE = "/var/lib/sia/keys/athenz.syncer.key.pem";
    static final String DEFAULT_ATH_SVC_CERT = "/var/lib/sia/certs/athenz.syncer.cert.pem";
    static final String DEFAULT_TRUSTSOURCE_PATH = "/usr/lib/jvm/jre-1.8.0/lib/security/cacerts";
    static final String DEFAULT_TRUSTSOURCE_PASSWORD = "changeit";
    static final String DEFAULT_STATE_BUILDER_THREADS = "10";
    static final String DEFAULT_STATE_BUILDER_TIMEOUT = "1800";
    static final String DEFAULT_DOMAIN_REFRESH_COUNT = "10";
    static final String DEFAULT_DOMAIN_REFRESH_TIMEOUT = "2592000";
    static final String DEFAULT_JSON_MAX_NESTING_DEPTH = "1000";
    static final String DEFAULT_JSON_MAX_NUMBER_LENGTH = "1000";
    static final String DEFAULT_JSON_MAX_STRING_LENGTH = "200000000";

    // system properties - take precedence over config file settings

    static final String PROP_PREFIX = "yahoo.auth.zms_syncer_aws.";

    static final String SYNC_CFG_PARAM_DEBUG = "debug";
    static final String SYNC_CFG_PARAM_ROOT_PATH = "root_path";
    static final String SYNC_CFG_PARAM_STATE_PATH = "state_path";
    static final String SYNC_CFG_PARAM_SLEEP_INTERVAL = "sleep_interval";
    static final String SYNC_CFG_PARAM_AWS_BUCKET = "aws_bucket";
    static final String SYNC_CFG_PARAM_AWS_SSE_ALGORITHM = "aws_sse_algorithm";
    static final String SYNC_CFG_PARAM_AWS_CONNECT_TIMEOUT = "aws_connect_timeout";
    static final String SYNC_CFG_PARAM_AWS_REQUEST_TIMEOUT = "aws_request_timeout";
    static final String SYNC_CFG_PARAM_ATHENZ_SVC_KEYFILE = "key_file";
    static final String SYNC_CFG_PARAM_ATHENZ_SVC_CERT = "cert_file";
    static final String SYNC_CFG_PARAM_TRUST_STORE_PATH = "truststore_path";
    static final String SYNC_CFG_PARAM_TRUST_STORE_PASSWORD = "truststore_password";
    static final String SYNC_CFG_PARAM_AWS_KEY_ID = "aws_cred_keyid";
    static final String SYNC_CFG_PARAM_AWS_ACCESS_KEY = "aws_cred_access_key";
    static final String SYNC_CFG_PARAM_AWS_S3_REGION = "aws_s3_region";
    static final String SYNC_CFG_PARAM_STATE_BUILDER_THREADS = "state_builder_threads";
    static final String SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT = "state_builder_timeout";
    static final String SYNC_CFG_PARAM_DOMAIN_REFRESH_COUNT = "domain_refresh_count";
    static final String SYNC_CFG_PARAM_DOMAIN_REFRESH_TIMEOUT = "domain_refresh_timeout";
    static final String SYNC_CFG_PARAM_JSON_MAX_NESTING_DEPTH = "json_max_nesting_depth";
    static final String SYNC_CFG_PARAM_JSON_MAX_NUMBER_LENGTH = "json_max_number_length";
    static final String SYNC_CFG_PARAM_JSON_MAX_STRING_LENGTH = "json_max_string_length";

    static final String[] SYNC_CFG_PARAMS = {
            SYNC_CFG_PARAM_DEBUG,
            SYNC_CFG_PARAM_ROOT_PATH,
            SYNC_CFG_PARAM_STATE_PATH,
            SYNC_CFG_PARAM_SLEEP_INTERVAL,
            SYNC_CFG_PARAM_AWS_BUCKET,
            SYNC_CFG_PARAM_AWS_CONNECT_TIMEOUT,
            SYNC_CFG_PARAM_AWS_REQUEST_TIMEOUT,
            SYNC_CFG_PARAM_AWS_SSE_ALGORITHM,
            SYNC_CFG_PARAM_ATHENZ_SVC_KEYFILE,
            SYNC_CFG_PARAM_ATHENZ_SVC_CERT,
            SYNC_CFG_PARAM_TRUST_STORE_PATH,
            SYNC_CFG_PARAM_TRUST_STORE_PASSWORD,
            SYNC_CFG_PARAM_AWS_KEY_ID,
            SYNC_CFG_PARAM_AWS_ACCESS_KEY,
            SYNC_CFG_PARAM_AWS_S3_REGION,
            SYNC_CFG_PARAM_STATE_BUILDER_THREADS,
            SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT,
            SYNC_CFG_PARAM_DOMAIN_REFRESH_COUNT,
            SYNC_CFG_PARAM_DOMAIN_REFRESH_TIMEOUT,
            SYNC_CFG_PARAM_JSON_MAX_NESTING_DEPTH,
            SYNC_CFG_PARAM_JSON_MAX_NUMBER_LENGTH,
            SYNC_CFG_PARAM_JSON_MAX_STRING_LENGTH
    };

    static final String ZMS_CFG_PARAM_ZMS_URL = "zmsUrl";

    Map<String, String> propertyMap = new HashMap<>();
    boolean debugEnabled = false;
    boolean syncMergeStatus = false;
    boolean athenzMergeStatus = false;
    Map<String, PublicKey> zmsPublicKeyMap = new HashMap<>();

    // the one and only instance
    private static Config instance;

    public static Config getInstance() {
        if (instance == null) {
            synchronized (Config.class) {
                if (instance == null) {
                    instance = new Config();
                }
            }
        }
        return instance;
    }

    private Config() {
        loadConfigParams();
    }

    void loadConfigParams() {
        // properties take precedence over config file settings
        loadProperties();
        mergeSyncConfigFile();
        mergeAthenzConfigFile();
    }

    void loadProperties() {
        propertyMap.clear();
        for (String pname : SYNC_CFG_PARAMS) {
            final String propName = PROP_PREFIX + pname;
            final String val = System.getProperty(propName);
            if (val != null) {
                propertyMap.put(pname, val);
            }
        }

        final String propName = PROP_PREFIX + ZMS_CFG_PARAM_ZMS_URL;
        final String zmsUrl = System.getProperty(propName);
        if (zmsUrl != null) {
            propertyMap.put(ZMS_CFG_PARAM_ZMS_URL, zmsUrl);
        }

        String rootDir = System.getenv("ROOT");
        if (rootDir == null) {
            rootDir = "/opt";
        }
        String rootPath = propertyMap.get(SYNC_CFG_PARAM_ROOT_PATH);
        if (rootPath == null) {
            propertyMap.put(SYNC_CFG_PARAM_ROOT_PATH, rootDir);
            rootPath = rootDir;
        }
        LOGGER.info("set root path: {}", rootPath);
    }

    Struct parseJsonConfigFile(final String fileName) {

        LOGGER.info("parse json file: {}", fileName);
        Struct conf = null;
        try {
            Path path = Paths.get(fileName);
            conf = JSON.fromBytes(Files.readAllBytes(path), Struct.class);
        } catch (Exception ex) {
            LOGGER.error("unable to parse file: {} error: {}", fileName, ex.getMessage());
        }
        return conf;
    }

    SyncerDomainStates parseSyncerDomainStates(final String fileName) {

        LOGGER.info("parse syncer domain state file: {}", fileName);
        SyncerDomainStates states = null;
        try {
            Path path = Paths.get(fileName);
            states = JSON.fromBytes(Files.readAllBytes(path), SyncerDomainStates.class);
        } catch (Exception ex) {
            LOGGER.error("parseSyncerDomainStates: Unable to parse file: {} error: {}",
                    fileName, ex.getMessage());
        }
        return states;
    }

    AthenzConfig parseAthenzConfFile(final String fileName) {

        LOGGER.info("parse athenz conf file: {}", fileName);
        AthenzConfig conf = null;
        try {
            Path path = Paths.get(fileName);
            conf = JSON.fromBytes(Files.readAllBytes(path), AthenzConfig.class);
        } catch (Exception ex) {
            LOGGER.error("unable to parse file: {} error: {}", fileName, ex.getMessage());
        }
        return conf;
    }

    private void mergeSyncConfigFile() {

        final String rootPath = propertyMap.get(SYNC_CFG_PARAM_ROOT_PATH);
        LOGGER.info("using root path: {}", rootPath);

        // setup config file path
        final String configFile = rootPath + "/zms_syncer/conf/zms_syncer.conf";
        try {
            Struct fileParams = parseJsonConfigFile(configFile);
            for (String name : SYNC_CFG_PARAMS) {

                // don't allow over-ride from config file for root path
                if (name.equals(SYNC_CFG_PARAM_ROOT_PATH)) {
                    continue;
                }

                final String propVal = propertyMap.get(name);
                final String fileVal = fileParams.getString(name);
                final String val = propVal != null ? propVal : fileVal;
                if (Config.isEmpty(val)) {
                    continue;
                }

                switch (name) {
                    case SYNC_CFG_PARAM_STATE_PATH:
                        // check if we need to add the root prefix
                        if (val.startsWith("/")) {
                            propertyMap.put(name, val);
                        } else {
                            propertyMap.put(name, rootPath + "/" + val);
                        }
                        break;
                    case SYNC_CFG_PARAM_DEBUG:
                        debugEnabled = Boolean.parseBoolean(val);
                        break;
                    default:
                        propertyMap.put(name, val);
                        break;
                }
            }

            // ensure the following have defaults

            propertyMap.putIfAbsent(SYNC_CFG_PARAM_STATE_PATH, DEFAULT_STATEPATH);
            propertyMap.putIfAbsent(SYNC_CFG_PARAM_ATHENZ_SVC_KEYFILE, DEFAULT_ATH_SVC_KEYFILE);
            propertyMap.putIfAbsent(SYNC_CFG_PARAM_ATHENZ_SVC_CERT, DEFAULT_ATH_SVC_CERT);
            propertyMap.putIfAbsent(SYNC_CFG_PARAM_TRUST_STORE_PATH, DEFAULT_TRUSTSOURCE_PATH);
            propertyMap.putIfAbsent(SYNC_CFG_PARAM_TRUST_STORE_PASSWORD, DEFAULT_TRUSTSOURCE_PASSWORD);
            propertyMap.putIfAbsent(SYNC_CFG_PARAM_STATE_BUILDER_THREADS, DEFAULT_STATE_BUILDER_THREADS);
            propertyMap.putIfAbsent(SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT, DEFAULT_STATE_BUILDER_TIMEOUT);
            propertyMap.putIfAbsent(SYNC_CFG_PARAM_DOMAIN_REFRESH_COUNT, DEFAULT_DOMAIN_REFRESH_COUNT);
            propertyMap.putIfAbsent(SYNC_CFG_PARAM_DOMAIN_REFRESH_TIMEOUT, DEFAULT_DOMAIN_REFRESH_TIMEOUT);
            propertyMap.putIfAbsent(SYNC_CFG_PARAM_JSON_MAX_NESTING_DEPTH, DEFAULT_JSON_MAX_NESTING_DEPTH);
            propertyMap.putIfAbsent(SYNC_CFG_PARAM_JSON_MAX_NUMBER_LENGTH, DEFAULT_JSON_MAX_NUMBER_LENGTH);
            propertyMap.putIfAbsent(SYNC_CFG_PARAM_JSON_MAX_STRING_LENGTH, DEFAULT_JSON_MAX_STRING_LENGTH);

            syncMergeStatus = true;
        } catch (Exception ex) {
            LOGGER.error("failed to load config file: {}", configFile, ex);
            syncMergeStatus = false;
        }
    }

    private void mergeAthenzConfigFile() {

        final String rootPath = propertyMap.get(SYNC_CFG_PARAM_ROOT_PATH);
        LOGGER.info("using root path: {}", rootPath);

        // setup config file path
        final String athenzConfFilePath = rootPath + ATHENZ_CONFIG_FILE;
        try {
            AthenzConfig athenzConfFile = parseAthenzConfFile(athenzConfFilePath);
            List<PublicKeyEntry> publicKeys = athenzConfFile.getZmsPublicKeys();
            if (publicKeys != null) {
                for (PublicKeyEntry publicKey : publicKeys) {
                    final String keyId = publicKey.getId();
                    final String key = publicKey.getKey();
                    if (key == null || keyId == null) {
                        continue;
                    }
                    zmsPublicKeyMap.put(keyId, Crypto.loadPublicKey(Crypto.ybase64DecodeString(key)));
                    LOGGER.info("loaded zmsPublicKey keyId: {}", keyId);
                }
            }

            String zmsUrl = propertyMap.get(ZMS_CFG_PARAM_ZMS_URL);
            if (zmsUrl == null) {
                zmsUrl = athenzConfFile.getZmsUrl();
            }
            if (!Config.isEmpty(zmsUrl)) {
                propertyMap.put(ZMS_CFG_PARAM_ZMS_URL, zmsUrl);
            }
            athenzMergeStatus = true;
        } catch (Exception exc) {
            LOGGER.error("failed to load config file: {}", athenzConfFilePath, exc);
            athenzMergeStatus = false;
        }
    }

    // paramName should be one of the strings from SYNC_CFG_PARAMS and ZMS_CFG_PARAMS

    public String getConfigParam(String paramName) {
        return propertyMap.get(paramName);
    }

    public boolean isConfigSuccessful() {
        return syncMergeStatus && athenzMergeStatus;
    }

    public boolean isDebugEnabled() {
        return debugEnabled;
    }

    public PublicKey getZmsPublicKey(String keyId) {
        return zmsPublicKeyMap.get(keyId);
    }

    public static boolean isEmpty(final String value) {
        return value == null || value.isEmpty();
    }
}
