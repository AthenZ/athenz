/*
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.zts.store.impl;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zms.SignedDomains;
import com.yahoo.athenz.zms.ZMSClient;
import com.yahoo.athenz.zms.ZMSClientException;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.store.ChangeLogStore;
import com.yahoo.rdl.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.security.PrivateKey;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A simple implementation of StructStore that simply stores
 * the Struct as JSON in its own file.
 */
public class ZMSFileChangeLogStore implements ChangeLogStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZMSFileChangeLogStore.class);

    File rootDir;
    public String lastModTime;

    private PrivateKey privateKey;
    private String privateKeyId;
    private Authority authority;
    private String zmsUrl;
    
    private static final String ATTR_TAG           = "tag";
    private static final String VALUE_TRUE         = "true";
    private static final String LAST_MOD_FNAME     = ".lastModTime";
    private static final String ATTR_LAST_MOD_TIME = "lastModTime";
    
    public ZMSFileChangeLogStore(String rootDirectory, PrivateKey privateKey, String privateKeyId) {

        // save our private key and authority
        
        this.privateKey = privateKey;
        this.privateKeyId = privateKeyId;
        
        // setup principal authority for our zms client
        
        authority = new com.yahoo.athenz.auth.impl.PrincipalAuthority();
        
        // check to see if we need to override the ZMS url from the config file
        
        zmsUrl = System.getProperty(ZTSConsts.ZTS_PROP_ZMS_URL_OVERRIDE);
        
        // setup our directory for storing domain files
        
        rootDir = new File(rootDirectory);
        
        if (!rootDir.exists()) {
            if (!rootDir.mkdirs()) {
                error("cannot create specified root: " + rootDirectory);
            }
        } else {
            if (!rootDir.isDirectory()) {
                error("specified root is not a directory: " + rootDirectory);
            }
        }
        
        // make sure only the user has access
        
        Path rootPath = rootDir.toPath();
        Set<PosixFilePermission> perms = EnumSet.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);
        try {
            Files.setPosixFilePermissions(rootPath, perms);
        } catch (IOException e) {
            error("unable to set directory owner permissions: " + e.getMessage());
        }
        
        // retrieve our last modification timestamp
        
        lastModTime = retrieveLastModificationTime();
        
        // if we do not have a last modification timestamp then we're going to
        // clean up all locally cached domain files
        
        if (lastModTime == null) {
            List<String> localDomains = getLocalDomainList();
            for (String domain : localDomains) {
                delete(domain);
            }
        }
    }

    @Override
    public boolean supportsFullRefresh() {
        return true;
    }

    @Override
    public SignedDomain getSignedDomain(String domainName) {
        return get(domainName, SignedDomain.class);
    }
    
    @Override
    public void removeLocalDomain(String domainName) {
        delete(domainName);
    }
    
    @Override
    public void saveLocalDomain(String domainName, SignedDomain signedDomain) {
        put(domainName, JSON.bytes(signedDomain));
    }
    
    void setupDomainFile(File file) {
        
        try {
            new FileOutputStream(file).close();
            //noinspection ResultOfMethodCallIgnored
            file.setLastModified(System.currentTimeMillis());
            Path path = file.toPath();
            Set<PosixFilePermission> perms = EnumSet.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(path, perms);
        } catch (IOException ex) {
            error("unable to setup domain file with permissions: " + ex.getMessage());
        }
    }
    
    public synchronized <T> T get(String name, Class<T> classType) {

        File file = new File(rootDir, name);
        if (!file.exists()) {
            return null;
        }
        Path path = Paths.get(file.toURI());
        try {
            return JSON.fromBytes(Files.readAllBytes(path), classType);
        } catch (IOException ex) {
            LOGGER.error("Unable to retrieve file: {} error: {}", file.getPath(), ex.getMessage());
        }
        return null;
    }
        
    public synchronized void put(String name, byte[] data) {
        
        File file = new File(rootDir, name);
        if (!file.exists()) {
            setupDomainFile(file);
        }
        Path path = Paths.get(file.toURI());
        try {
            Files.write(path, data);
        } catch (IOException ex) {
            error("unable to save file: " + file.getPath() + " error: " + ex.getMessage());
        }
    }

    public synchronized void delete(String name) {
        File file = new File(rootDir, name);
        if (!file.exists()) {
            return;
        }
        
        try {
            Files.delete(file.toPath());
        } catch (Exception exc) {
            error("Cannot delete file or directory: " + name + " : exc: " + exc);
        }
    }

    @Override
    public List<String> getLocalDomainList() {
        return scan();
    }
    
    List<String> scan() {
        
        List<String> names = new ArrayList<>();
        String[] domains = rootDir.list();
        if (domains == null) {
            return names;
        }
        for (String name : domains) {
            
            // we are going to skip any hidden files
            
            if (name.charAt(0) != '.') {
                names.add(name);
            }
        }
        
        return names;
    }
    
    ZMSClient getZMSClient() {
        
        PrincipalToken token = new PrincipalToken.Builder("S1", ZTSConsts.ATHENZ_SYS_DOMAIN, ZTSConsts.ZTS_SERVICE)
                .expirationWindow(24 * 60 * 60L).keyId(privateKeyId).build();
        token.sign(privateKey);
        
        Principal principal = SimplePrincipal.create(ZTSConsts.ATHENZ_SYS_DOMAIN,
                ZTSConsts.ZTS_SERVICE, token.getSignedToken(), authority);
        
        ZMSClient zmsClient = new ZMSClient(zmsUrl);
        zmsClient.addCredentials(principal);
        return zmsClient;
    }
    
    @Override
    public Set<String> getServerDomainList() {
        
        Set<String> zmsDomainList;
        try (ZMSClient zmsClient = getZMSClient()) {
            zmsDomainList = new HashSet<>(zmsClient.getDomainList().getNames());
        } catch (ZMSClientException ex) {
            LOGGER.error("Unable to retrieve domain list from ZMS: " + ex.getMessage());
            return null;
        }
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Number of ZMS domains: " + zmsDomainList.size());
        }
        
        return zmsDomainList;
    }
    
    public String retrieveLastModificationTime() {
        Struct lastModStruct = get(LAST_MOD_FNAME, Struct.class);
        if (lastModStruct == null) {
            return null;
        }
        return lastModStruct.getString(ATTR_LAST_MOD_TIME);
    }
    
    @Override
    public void setLastModificationTimestamp(String newLastModTime) {

        lastModTime = newLastModTime;
        if (lastModTime == null) {
            delete(LAST_MOD_FNAME);
        } else {
            
            // update the last modification timestamp
            
            Struct lastModStruct = new Struct();
            lastModStruct.put(ATTR_LAST_MOD_TIME, lastModTime);
            put(LAST_MOD_FNAME, JSON.bytes(lastModStruct));
        }
    }
    
    String retrieveTagHeader(Map<String, List<String>> responseHeaders) {
        
        // our tag value is going to be returned from the server in the
        // response headers as the value to the key "tag"

        List<String> tagData = responseHeaders.get(ATTR_TAG);
        if (tagData == null || tagData.isEmpty()) {
            LOGGER.error("Response headers from ZMS does not include 'ETag/tag' value");
            return null;
        }
        return tagData.get(0);
    }
    
    List<SignedDomain> getSignedDomainList(ZMSClient zmsClient, SignedDomains domainList) {
        
        List<SignedDomain> domains = new ArrayList<>();
        for (SignedDomain domain : domainList.getDomains()) {
            
            final String domainName = domain.getDomain().getName();
            
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("getSignedDomainList: fetching domain {}", domainName);
            }
            
            try {
                SignedDomains singleDomain = zmsClient.getSignedDomains(domainName,
                        null, null, null);
                
                if (singleDomain == null || singleDomain.getDomains().isEmpty()) {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("getSignedDomainList: unable to fetch domain {}",
                                domainName);
                    }
                    continue;
                }
                domains.addAll(singleDomain.getDomains());
                
            } catch (ZMSClientException ex) {
                LOGGER.error("Error fetching domain {} from ZMS: {}", domainName,
                        ex.getMessage());
            }
        }
        return domains;
    }
    
    @Override
    public SignedDomains getUpdatedSignedDomains(StringBuilder lastModTimeBuffer) {

        try (ZMSClient zmsClient = getZMSClient()) {

            // request all the changes from ZMS. In this call we're asking for
            // meta data only so we'll only get the list of domains
            
            Map<String, List<String>> responseHeaders = new HashMap<>();
            SignedDomains domainList = zmsClient.getSignedDomains(null, VALUE_TRUE,
                    lastModTime, responseHeaders);
            
            // retrieve the tag value for the request
            
            String newLastModTime = retrieveTagHeader(responseHeaders);
            if (newLastModTime == null) {
                return null;
            }
            
            // set the last modification time to be returned to the caller
            
            lastModTimeBuffer.setLength(0);
            lastModTimeBuffer.append(newLastModTime);
            
            // now let's iterate through our list and retrieve one domain
            // at a time
            
            if (domainList == null || domainList.getDomains() == null) {
                return null;
            }
            
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("getUpdatedSignedDomains: {} updated domains", domainList.getDomains().size());
            }
            
            List<SignedDomain> domains = getSignedDomainList(zmsClient, domainList);
            return new SignedDomains().setDomains(domains);
            
        } catch (ZMSClientException ex) {
            LOGGER.error("Error when refreshing data from ZMS: {}", ex.getMessage());
            return null;
        }
    }
    
    public static void deleteDirectory(File file) {
        if (!file.exists()) {
            return;
        }
        
        if (file.isDirectory()) {
            
            File[] fileList = file.listFiles();
            if (fileList != null) {
                for (File ff : fileList) {
                    deleteDirectory(ff);
                }
            }
        }
        if (!file.delete()) {
            error("Cannot delete file: " + file);
        }
    }
    
    static void error(String msg) {
        LOGGER.error(msg);
        throw new RuntimeException("ZMSFileChangeLogStore: " + msg);
    }
}
