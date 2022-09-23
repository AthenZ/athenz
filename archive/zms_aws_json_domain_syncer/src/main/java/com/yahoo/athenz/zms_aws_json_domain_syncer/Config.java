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

    // system properties - take precedence over config file settings
    //
    static final String PROP_PREFIX = "yahoo.athenz.zms_aws_json_domain_syncer";

    static final String SYNC_CFG_PARAM_DEBUG = "debug";
    static final String SYNC_CFG_PARAM_ROOTPATH = "root_path";
    static final String SYNC_CFG_PARAM_STATEPATH = "state_path";
    static final String SYNC_CFG_PARAM_SLEEPINT = "sleep_interval";
    static final String SYNC_CFG_PARAM_IGNDOMS = "ignored_domains";
    static final String SYNC_CFG_PARAM_AWSBUCK = "aws_bucket";
    static final String SYNC_CFG_PARAM_AWS_SSE_ALGORITHM = "aws_sse_algorithm";
    static final String SYNC_CFG_PARAM_AWSCONTO = "aws_connect_timeout";
    static final String SYNC_CFG_PARAM_AWSREQTO = "aws_request_timeout";
    static final String SYNC_CFG_PARAM_CLOUDCLASS = "syncer_cloud_class";
    static final String SYNC_CFG_PARAM_ZMSCLTFACT = "zms_client_factory";
    static final String SYNC_CFG_PARAM_ATH_SVC_KEYFILE = "key_file";
    static final String SYNC_CFG_PARAM_ATH_SVC_CERT = "cert_file";
    static final String SYNC_CFG_PARAM_TRUSTSOURCE_PATH = "truststore_path";
    static final String SYNC_CFG_PARAM_TRUSTSOURCE_PASSWORD = "truststore_password";
    static final String SYNC_CFG_PARAM_AWSKEYID = "aws_cred_keyid";
    static final String SYNC_CFG_PARAM_AWSACCKEY = "aws_cred_access_key";
    static final String SYNC_CFG_PARAM_AWSREGION = "aws_s3_region";
    static final String SYNC_CFG_PARAM_STATE_BUILDER_THREADS = "state_builder_threads";
    static final String SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT = "state_builder_timeout";

    static final String[] SYNC_CFG_PARAMS = {
            SYNC_CFG_PARAM_DEBUG,
            SYNC_CFG_PARAM_ROOTPATH,
            SYNC_CFG_PARAM_STATEPATH,
            SYNC_CFG_PARAM_SLEEPINT,
            SYNC_CFG_PARAM_IGNDOMS,
            SYNC_CFG_PARAM_AWSBUCK,
            SYNC_CFG_PARAM_AWSCONTO,
            SYNC_CFG_PARAM_AWSREQTO,
            SYNC_CFG_PARAM_CLOUDCLASS,
            SYNC_CFG_PARAM_ZMSCLTFACT,
            SYNC_CFG_PARAM_AWS_SSE_ALGORITHM,
            SYNC_CFG_PARAM_ATH_SVC_KEYFILE,
            SYNC_CFG_PARAM_ATH_SVC_CERT,
            SYNC_CFG_PARAM_TRUSTSOURCE_PATH,
            SYNC_CFG_PARAM_TRUSTSOURCE_PASSWORD,
            SYNC_CFG_PARAM_AWSKEYID,
            SYNC_CFG_PARAM_AWSACCKEY,
            SYNC_CFG_PARAM_AWSREGION,
            SYNC_CFG_PARAM_STATE_BUILDER_THREADS,
            SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT
    };

    //zms specific params - including athenz.conf related configuration

    static final String ZMS_CFG_PARAM_ZMS_URL = "zmsUrl";

    Map<String, String> propertyMap = new HashMap<>();
    boolean debugEnabled = false;
    String[] ignoredDomains = {};
    boolean syncMergeStatus = false;
    boolean athenzMergeStatus = false;
    Map<String, PublicKey> zmsPublicKeyMap = new HashMap<>();

    //The one and only instance
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
        loadProperties(); // properties take precedence over config file settings
        mergeSyncConfigFile();
        mergeAthenzConfigFile();
    }

    void loadProperties() {
        propertyMap.clear();
        for (String pname : SYNC_CFG_PARAMS) {
            String propName = PROP_PREFIX + pname;
            String val = System.getProperty(propName);
            if (val != null) {
                propertyMap.put(pname, val);
            }
        }

        String propName = PROP_PREFIX + ZMS_CFG_PARAM_ZMS_URL;
        String zmsUrl = System.getProperty(propName);
        if (zmsUrl != null) {
            propertyMap.put(ZMS_CFG_PARAM_ZMS_URL, zmsUrl);
        }

        String rootDir = System.getenv("ROOT");
        if (rootDir == null) {
            rootDir = "/opt";
        }
        String rootPath = propertyMap.get(SYNC_CFG_PARAM_ROOTPATH);
        if (rootPath == null) {
            propertyMap.put(SYNC_CFG_PARAM_ROOTPATH, rootDir);
            rootPath = rootDir;
        }
        LOGGER.info("CONFIG:loadProperties: set root path: " + rootPath);
    }

    Struct parseJsonConfigFile(String fileName) {
        LOGGER.info("parseJsonConfigFile: Parse json file: " + fileName);
        Struct conf = null;
        try {
            Path path = Paths.get(fileName);
            conf = JSON.fromBytes(Files.readAllBytes(path), Struct.class);
        } catch (Exception e) {
            LOGGER.error("parseJsonConfigFile: Unable to parse file: {} error: {}", fileName, e.getMessage());
        }
        return conf;
    }

    SyncerDomainStates parseSyncerDomainStates(String fileName) {
        LOGGER.info("parseSyncerDomainStates: Parse json file: " + fileName);
        SyncerDomainStates states = null;
        try {
            Path path = Paths.get(fileName);
            states = JSON.fromBytes(Files.readAllBytes(path), SyncerDomainStates.class);
        } catch (Exception e) {
            LOGGER.error("parseSyncerDomainStates: Unable to parse file: {} error: {}", fileName, e.getMessage());
        }
        return states;
    }

    AthenzConfig parseAthenzConfFile(String fileName) {
        LOGGER.info("Reading configuration file: " + fileName);
        AthenzConfig conf = null;
        try {
            Path path = Paths.get(fileName);
            conf = JSON.fromBytes(Files.readAllBytes(path), AthenzConfig.class);
        } catch (Exception e) {
            LOGGER.error("parseAthenzConfFile: Unable to parse file: {} error: {}", fileName, e.getMessage());
        }
        return conf;
    }

    private void mergeSyncConfigFile() {

        String rootPath = propertyMap.get(SYNC_CFG_PARAM_ROOTPATH);
        LOGGER.info("CONFIG:mergeSyncConfigFile: using root path: " + rootPath);

        // setup config file path
        String configFile = rootPath + "/zms_syncer/conf/zms_syncer.conf";
        try {
            Struct fileParams = parseJsonConfigFile(configFile);
            for (String name : SYNC_CFG_PARAMS) {
                if (name.equals(SYNC_CFG_PARAM_ROOTPATH)) { // dont allow over-ride from config file
                    continue;
                }

                String propVal = propertyMap.get(name);
                String fileVal = fileParams.getString(name);
                String val = propVal != null ? propVal : fileVal;
                if (val == null || val.isEmpty()) {
                    continue;
                }

                // ensure these paths are set correctly: SYNC_CFG_PARAM_STATEPATH SYNC_CFG_PARAM_AWSFILE
                switch (name) {
                    case SYNC_CFG_PARAM_STATEPATH:

                        if (val.startsWith("/")) {
                            propertyMap.put(name, val);
                        } else {
                            // needs the root prefix added
                            propertyMap.put(name, rootPath + "/" + val);
                        }
                        break;
                    case SYNC_CFG_PARAM_DEBUG:
                        debugEnabled = Boolean.parseBoolean(val);
                        break;
                    case SYNC_CFG_PARAM_IGNDOMS:
                        // break out into a list
                        String[] ignDomains = val.split(",");
                        for (int cnt = 0; cnt < ignDomains.length; ++cnt) {
                            ignDomains[cnt] = ignDomains[cnt].trim();
                        }
                        ignoredDomains = ignDomains;
                        break;
                    default:
                        propertyMap.put(name, val);
                        break;
                }
            }

            // ensure the following have defaults
            //

            propertyMap.putIfAbsent(SYNC_CFG_PARAM_STATEPATH, DEFAULT_STATEPATH);
            propertyMap.putIfAbsent(SYNC_CFG_PARAM_ATH_SVC_KEYFILE, DEFAULT_ATH_SVC_KEYFILE);
            propertyMap.putIfAbsent(SYNC_CFG_PARAM_ATH_SVC_CERT, DEFAULT_ATH_SVC_CERT);
            propertyMap.putIfAbsent(SYNC_CFG_PARAM_TRUSTSOURCE_PATH, DEFAULT_TRUSTSOURCE_PATH);
            propertyMap.putIfAbsent(SYNC_CFG_PARAM_TRUSTSOURCE_PASSWORD, DEFAULT_TRUSTSOURCE_PASSWORD);
            propertyMap.putIfAbsent(SYNC_CFG_PARAM_STATE_BUILDER_THREADS, DEFAULT_STATE_BUILDER_THREADS);
            propertyMap.putIfAbsent(SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT, DEFAULT_STATE_BUILDER_TIMEOUT);

            syncMergeStatus = true;
        } catch (Exception exc) {
            LOGGER.error("CONFIG:mergeSyncConfigFile: failed to load config file: " + configFile);
            syncMergeStatus = false;
        }
    }

    private void mergeAthenzConfigFile() {

        String rootPath = propertyMap.get(SYNC_CFG_PARAM_ROOTPATH);
        LOGGER.info("CONFIG:mergeAthenzConfigFile: using root path: " + rootPath);

        // setup config file path
        String athenzConfFilePath = rootPath + ATHENZ_CONFIG_FILE;
        try {
            AthenzConfig athenzConfFile = parseAthenzConfFile(athenzConfFilePath);
            List<PublicKeyEntry> publicKeys = athenzConfFile.getZmsPublicKeys();
            if (publicKeys != null) {
                for (PublicKeyEntry publicKey : publicKeys) {
                    String keyId = publicKey.getId();
                    String key = publicKey.getKey();
                    if (key == null || keyId == null) {
                        continue;
                    }
                    zmsPublicKeyMap.put(keyId, Crypto.loadPublicKey(Crypto.ybase64DecodeString(key)));
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.info("Loaded zmsPublicKey keyId: " + keyId + " key: " + key);
                    }
                }
            }

            String zmsUrl = propertyMap.get(ZMS_CFG_PARAM_ZMS_URL);
            if (zmsUrl == null) {
                zmsUrl = athenzConfFile.getZmsUrl();
            }
            if (zmsUrl != null && !zmsUrl.isEmpty()) {
                propertyMap.put(ZMS_CFG_PARAM_ZMS_URL, zmsUrl);
            }
            athenzMergeStatus = true;
        } catch (Exception exc) {
            LOGGER.error("CONFIG:mergeAthenzConfigFile: failed to load config file: " + athenzConfFilePath);
            athenzMergeStatus = false;
        }
    }

    // paramName should be one of the strings from SYNC_CFG_PARAMS and ZMS_CFG_PARAMS
    //
    public String getConfigParam(String paramName) {
        return propertyMap.get(paramName);
    }

    public boolean isConfigSuccessful() {
        return syncMergeStatus && athenzMergeStatus;
    }

    public boolean isDebugEnabled() {
        return debugEnabled;
    }

    public String[] getIgnoredDomains() {
        return ignoredDomains;
    }

    public PublicKey getZmsPublicKey(String keyId) {
        return zmsPublicKeyMap.get(keyId);
    }
}

