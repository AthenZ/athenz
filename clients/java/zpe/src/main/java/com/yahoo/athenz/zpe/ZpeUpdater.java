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
package com.yahoo.athenz.zpe;

import java.io.File;
import java.util.List;
import java.util.Map;

import com.yahoo.athenz.auth.token.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.token.RoleToken;
import com.yahoo.rdl.Struct;

public class ZpeUpdater implements ZpeClient {
    
    private static final Logger LOG = LoggerFactory.getLogger(ZpeUpdater.class);
    
    // default policy directory "/home/athenz/var/zpe/"
    private static final String ZPECLT_POLDIR_DEFAULT;
    private static final ZpeUpdPolLoader POLICYLOADER;
    
    static {
        String rootDir = System.getenv("ROOT");

        if (null == rootDir) {
            rootDir = File.separator + "home" + File.separator + "athenz";
        }

        ZPECLT_POLDIR_DEFAULT = rootDir + File.separator + "var" + File.separator + "zpe";
        String dirName = System.getProperty(ZpeConsts.ZPE_PROP_POLICY_DIR, ZPECLT_POLDIR_DEFAULT);
        
        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("static-init: start monitoring policy directory={}", dirName);
            }
            // load the file
            POLICYLOADER = new ZpeUpdPolLoader(dirName);

            // this will start monitoring policy directory for file mods
            POLICYLOADER.start();

        } catch (Exception exc) {
            LOG.error("static-init: failed loading policy files. System property({}) Policy-directory({}})",
                    ZpeConsts.ZPE_PROP_POLICY_DIR, dirName, exc);
            throw new RuntimeException(exc);
        }
    }
    
    // @param domain can be null
    @Override
    public void init(String domain) {
        try {
            synchronized (POLICYLOADER) {
                POLICYLOADER.wait(5000);  // wait max of 5 seconds
            }
        } catch (InterruptedException exc) {
            LOG.warn("init: waiting for policy loader to be ready, continuing...");
        }
    }

    // return current cache of role tokens collected from the remote clients
    @Override
    public Map<String, RoleToken> getRoleTokenCacheMap() {
        return ZpeUpdPolLoader.getRoleTokenCacheMap();
    }

    @Override
    public Map<String, AccessToken> getAccessTokenCacheMap() {
        return ZpeUpdPolLoader.getAccessTokenCacheMap();
    }

    @Override
    public Map<String, List<Struct>> getWildcardAllowAssertions(String domain) {
        return POLICYLOADER.getWildcardRoleAllowMap(domain);
    }

    @Override
    public Map<String, List<Struct>> getRoleAllowAssertions(String domain) {
        return POLICYLOADER.getStandardRoleAllowMap(domain);
    }

    @Override
    public Map<String, List<Struct>> getWildcardDenyAssertions(String domain) {
        return POLICYLOADER.getWildcardRoleDenyMap(domain);
    }

    @Override
    public Map<String, List<Struct>> getRoleDenyAssertions(String domain) {
        return POLICYLOADER.getStandardRoleDenyMap(domain);
    }

    @Override
    public int getDomainCount() {
        return POLICYLOADER.getDomainCount();
    }
}
