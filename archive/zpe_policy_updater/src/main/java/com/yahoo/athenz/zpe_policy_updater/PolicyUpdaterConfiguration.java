/**
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
package com.yahoo.athenz.zpe_policy_updater;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.security.PublicKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.config.AthenzConfig;
import com.yahoo.athenz.zms.PublicKeyEntry;
import com.yahoo.athenz.zts.ZTSClient;

public class PolicyUpdaterConfiguration {
    
    private static final Logger LOG = LoggerFactory.getLogger(PolicyUpdaterConfiguration.class);

    private static final String ZPU_PROP_ATHENZ_CONF = "athenz.athenz_conf";
    private static final String ZPU_PROP_DEBUG       = "athenz.zpe_policy_updater.debug";
    private static final String ZPU_PROP_POLDIR      = "athenz.zpe_policy_updater.dir";
    private static final String ZPU_PROP_POL_TMP_DIR = "athenz.zpe_policy_updater.tmp_dir";
    static final String ZPU_PROP_TEST_ROOT_PATH      = "athenz.zpe_policy_updater.test_root_path";
    
    private static final String ATHENZ_CONFIG_FILE = "/conf/athenz/athenz.conf";
    private static final String ZPU_CONFIG_FILE = "/conf/zpe_policy_updater/zpu.conf";
    private static final String ZPU_CONFIG_DOMAINS = "domains";
    private static final String ZPU_CONFIG_USER    = "user";
    private static final String ZPU_USER_DEFAULT   = "root";
    
    private static final String STARTUP_DELAY = "STARTUP_DELAY";
    private static final int DEFAULT_STARTUP_DELAY = 0;
    private static final int MAX_STARTUP_DELAY = 86400;
    
    public static final String ZTS_PUBLIC_KEY_PREFIX = "zts.public_key.";
    public static final String ZMS_PUBLIC_KEY_PREFIX = "zms.public_key.";
    
    private boolean debugMode = false;
    private int startupDelay = 0;
    private Map<String, PublicKey> ztsPublicKeyMap = new HashMap<String, PublicKey>();
    private Map<String, PublicKey> zmsPublicKeyMap = new HashMap<String, PublicKey>();
    private String rootDir;
    private String policyFileDir;
    private String policyFileTmpDir;
    private String defaultAthenzConfigFile;
    private String defaultZPUConfigFile;
    private List<String> domainList  = null;
    private String zpuDirOwner = null;

    public PolicyUpdaterConfiguration() {
        
        debugMode = Boolean.parseBoolean(System.getProperty(ZPU_PROP_DEBUG, "false"));

        rootDir = System.getenv("ROOT");
        if (null == rootDir) {
            rootDir = File.separator + "home" + File.separator + "athenz";
        }
        rootDir = System.getProperty(ZPU_PROP_TEST_ROOT_PATH, rootDir);
        
        // default configuration file paths
        
        defaultAthenzConfigFile = System.getProperty(ZPU_PROP_ATHENZ_CONF,
                rootDir + ATHENZ_CONFIG_FILE);
        defaultZPUConfigFile = rootDir + ZPU_CONFIG_FILE;
        
        // Final destination of signed policy files
        String policyFileDirDefault = rootDir + File.separator + "var"
                + File.separator + "zpe";
        
        policyFileDir = System.getProperty(ZPU_PROP_POLDIR, policyFileDirDefault);

        // Temporary destination of signed policy files
        String policyFileTmpDirDefault = rootDir + File.separator + "tmp"
                + File.separator + "zpe";
        
        policyFileTmpDir = System.getProperty(ZPU_PROP_POL_TMP_DIR, policyFileTmpDirDefault);
        
        String startupDelayString = System.getenv(STARTUP_DELAY);

        if (startupDelayString != null) {
            startupDelay = Integer.parseInt(startupDelayString);
        } else {
            startupDelay = DEFAULT_STARTUP_DELAY;
        }

        startupDelay *= 60; // convert from min to secs
        
        if (startupDelay < 0) {
            startupDelay = DEFAULT_STARTUP_DELAY;
        } 
        
        if (startupDelay > MAX_STARTUP_DELAY) {
            startupDelay = MAX_STARTUP_DELAY;
        }
        
        LOG.info("debug mode: {}", debugMode);
        LOG.info("policyFileDir: {}", policyFileDir);
        LOG.info("startup delay: {} seconds", startupDelay);
    }

    public void init(String pathToAthenzConfigFile, String pathToZPUConfigFile) throws Exception {

        AthenzConfig athenzConfFile = null;
        if (pathToAthenzConfigFile == null) {
            athenzConfFile = readAthenzConfiguration(defaultAthenzConfigFile);
        } else {
            athenzConfFile = readAthenzConfiguration(pathToAthenzConfigFile);
        }

        LOG.info("Policy Updater configuration is set to:");
        LOG.info("policyFileDir: {}", policyFileDir);
        
        List<PublicKeyEntry> publicKeys = athenzConfFile.getZtsPublicKeys();
        if (publicKeys != null) {
            for (PublicKeyEntry publicKey : publicKeys) {
                String keyId = publicKey.getId();
                String key = publicKey.getKey();
                if (key == null || keyId == null) {
                    continue;
                }
                addZtsPublicKey(keyId, Crypto.loadPublicKey(Crypto.ybase64DecodeString(key)));
                LOG.info("Loaded ztsPublicKey keyId: {} key: {}", keyId, key);
            }
        }
        
        publicKeys = athenzConfFile.getZmsPublicKeys();
        if (publicKeys != null) {
            for (PublicKeyEntry publicKey : publicKeys) {
                String keyId = publicKey.getId();
                String key = publicKey.getKey();
                if (key == null || keyId == null) {
                    continue;
                }
                addZmsPublicKey(keyId, Crypto.loadPublicKey(Crypto.ybase64DecodeString(key)));
                LOG.info("Loaded zmsPublicKey keyId: {} key: {}", keyId, key);
            }
        }
        
        Struct zpuConfFile = null;
        if (pathToZPUConfigFile == null) {
            zpuConfFile = readZpuConfiguration(defaultZPUConfigFile);
        } else {
            zpuConfFile = readZpuConfiguration(pathToZPUConfigFile);
        }
        String domains = zpuConfFile.getString(ZPU_CONFIG_DOMAINS);
        if (domains != null && !domains.isEmpty()) {
            domainList = Arrays.asList(domains.split(","));
        }
        zpuDirOwner = zpuConfFile.getString(ZPU_CONFIG_USER);
        if (zpuDirOwner == null || zpuDirOwner.isEmpty()) {
            zpuDirOwner = ZPU_USER_DEFAULT;
        }
        if (isDebugMode()) {
            LOG.debug("config-init: user: {} file={}", zpuDirOwner, pathToZPUConfigFile);
        }
    }

    private AthenzConfig readAthenzConfiguration(String pathToFile) {
        LOG.info("Reading configuration file: {}", pathToFile);
        AthenzConfig conf = null;
        try {
            Path path = Paths.get(pathToFile);
            conf = JSON.fromBytes(Files.readAllBytes(path), AthenzConfig.class);
        } catch (Exception e) {
        }

        return conf;
    }

    private Struct readZpuConfiguration(String pathToFile) {
        LOG.info("Reading configuration file: {}", pathToFile);
        Struct conf = null;
        try {
            Path path = Paths.get(pathToFile);
            conf = JSON.fromBytes(Files.readAllBytes(path), Struct.class);
        } catch (Exception e) {
        }

        return conf;
    }

    public PublicKey getZtsPublicKey(ZTSClient zts, String keyId) {
        return ztsPublicKeyMap.get(keyId);
    }

    public PublicKey getZmsPublicKey(ZTSClient zts, String keyId) {
        return zmsPublicKeyMap.get(keyId);
    }
    
    public void addZtsPublicKey(String keyId, PublicKey ztsPublicKey) {
        ztsPublicKeyMap.put(keyId, ztsPublicKey);
    }

    public void addZmsPublicKey(String keyId, PublicKey zmsPublicKey) {
        zmsPublicKeyMap.put(keyId, zmsPublicKey);
    }
    
    public String getRootDir() {
        return rootDir;
    }

    public void setRootDir(String rootDir) {
        this.rootDir = rootDir;
    }
    
    public String getPolicyFileDir() {
        return policyFileDir;
    }

    public void setPolicyFileDir(String policyFileDir) {
        this.policyFileDir = policyFileDir;
    }

    public String getPolicyFileTmpDir() {
        return policyFileTmpDir;
    }

    public void setPolicyFileTmpDir(String policyFileTmpDir) {
        this.policyFileTmpDir = policyFileTmpDir;
    }

    public boolean isDebugMode() {
        return debugMode;
    }

    public void setDebugMode(boolean debugMode) {
        this.debugMode = debugMode;
    }

    public int getStartupDelayIntervalInSecs() {
        return startupDelay;
    }

    public void setStartupDelayInterval(int startupDelayIntervalInMin) {
        this.startupDelay = startupDelayIntervalInMin * 60;
    }
    
    public List<String> getDomainList() {
        return domainList;
    }
    
    public String getZpuDirOwner() {
        return zpuDirOwner;
    }
}
