/**
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
package com.yahoo.athenz.zts.store.file;

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
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.security.PrivateKey;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A simple implementation of StructStore that simply stores
 * the Struct as JSON in its own file.
 */
public class ZMSFileChangeLogStore implements ChangeLogStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZMSFileChangeLogStore.class);

    File rootDir = null;
    public String lastModTime = null;

    private PrivateKey privateKey = null;
    private String privateKeyId = "0";
    private Authority authority = null;
    private String zmsUrl = null;
    
    private static final String ATTR_TAG = "tag";
    private static final String LAST_MOD_FNAME = ".lastModTime";
    private static final String ATTR_LAST_MOD_TIME = "lastModTime";
    private static final String FILE_EXT = ".json";
    
    private static final String ZTS_PROP_ZMS_URL_OVERRIDE = "athenz.zts.zms_url";
    
    public ZMSFileChangeLogStore(String rootDirectory, PrivateKey privateKey, String privateKeyId) {

        // save our private key and authority
        
        this.privateKey = privateKey;
        this.privateKeyId = privateKeyId;
        
        // setup principal authority for our zms client
        
        authority = new com.yahoo.athenz.auth.impl.PrincipalAuthority();
        
        // check to see if we need to override the ZMS url from the config file
        
        zmsUrl = System.getProperty(ZTS_PROP_ZMS_URL_OVERRIDE, System.getenv("ZMS_URL"));
        
        // setup our directory for storing domain files
        
        rootDir = new File(rootDirectory);
        setupDomainDir(rootDir);
        
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

    void setupDomainDir(File domainDir) {
        
        if (!domainDir.exists()) {
            if (!domainDir.mkdirs()) {
                error("cannot create specified root: " + domainDir.getAbsolutePath());
            }
        } else {
            if (!domainDir.isDirectory()) {
                error("specified root is not a directory: " + domainDir.getAbsolutePath());
            }
        }
        
        Path rootPath = domainDir.toPath();
        Set<PosixFilePermission> perms = EnumSet.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);
        try {
            Files.setPosixFilePermissions(rootPath, perms);
        } catch (IOException e) {
            error("unable to set directory owner permissions: " + e.getMessage());
        }
    }
    
    @Override
    public boolean supportsFullRefresh() {
        return true;
    }

    @Override
    public SignedDomain getSignedDomain(String domainName) {
        File file = getDomainFile(domainName);
        return getData(file, SignedDomain.class);
    }
    
    @Override
    public void removeLocalDomain(String domainName) {
        File file = getDomainFile(domainName);
        delete(file);
    }
    
    @Override
    public void saveLocalDomain(String domainName, SignedDomain signedDomain) {
        File file = getDomainFile(domainName);
        writeData(file, JSON.bytes(signedDomain));
    }
    
    void setupFileOwnershp(File file) {
        
        try {
            new FileOutputStream(file).close();
            file.setLastModified(System.currentTimeMillis());
            Path path = file.toPath();
            Set<PosixFilePermission> perms = EnumSet.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(path, perms);
        } catch (IOException ex) {
            ex.printStackTrace();
            error("unable to setup file with owner permissions: " + ex.getMessage());
        }
    }
    
    public synchronized <T> T getData(File file, Class<T> classType) {

        if (!file.exists()) {
            return null;
        }
        Path path = Paths.get(file.toURI());
        try {
            return JSON.fromBytes(Files.readAllBytes(path), classType);
        } catch (IOException ex) {
            LOGGER.error("Unable to retrieve domain file: {} error: {}",
                    file.getPath(), ex.getMessage());
        }
        return null;
    }
    
    File getDomainFile(String domainName) {
        
        // first we need to separate our domain name
        // into components (parent and child). if the domain
        // is a top level domain then we have nothing to
        // do, otherwise, we're going to setup the directory
        // path for all subdomains e.g.
        // domain sys : path -> <rootDir>/sys.json
        // domain sys.auth : path -> <rootDir>/sys/auth.json
        // domain sys.auth.ci : path -> <rootDir>/sys/auth/ci.json
        
        File file = null;
        int idx;
        if ((idx = domainName.lastIndexOf('.')) == -1) {
            file = new File(rootDir, domainName + FILE_EXT);
        } else {
            final String domainParent = domainName.substring(0, idx)
                    .replace('.', File.pathSeparatorChar);
            File parent = new File(rootDir.getAbsolutePath() + File.pathSeparator + domainParent);
            setupDomainDir(parent);
            final String child = domainName.substring(idx + 1);
            file = new File(parent, child + FILE_EXT);
        }
        return file;
    }
    
    public synchronized void writeData(File file, byte[] data) {
        
        if (!file.exists()) {
            setupFileOwnershp(file);
        }
        Path path = Paths.get(file.toURI());
        try {
            Files.write(path, data);
        } catch (IOException ex) {
            ex.printStackTrace();
            error("unable to save domain file: " + file.getPath() + " error: " + ex.getMessage());
        }
    }

    public synchronized void delete(File parentDir, String name) {
        File file = new File(parentDir, name);
        if (!file.exists()) {
            return;
        }
        
        try {
            Files.delete(file.toPath());
        } catch (Exception exc) {
            error("Cannot delete file or directory: " + name + " : exc: " + exc);
        }
    }
    
    public synchronized void delete(String name) {
        delete(rootDir, name);
    }

    @Override
    public List<String> getLocalDomainList() {
        
        DomainFiles df = new DomainFiles(rootDir.getAbsolutePath());
        try {
            Files.walkFileTree(rootDir.toPath(), df);
        } catch (IOException ex) {
            LOGGER.error("Unable to retrieve list of local domains: " + ex.getMessage());
            return Collections.emptyList();
        }
        return df.getDomains();
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
        
        Set<String> zmsDomainList = null;
        try (ZMSClient zmsClient = getZMSClient()) {
            zmsDomainList = new HashSet<String>(zmsClient.getDomainList().getNames());
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
        File file = new File(rootDir, LAST_MOD_FNAME);
        Struct lastModStruct = getData(file, Struct.class);
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
            File file = new File(rootDir, LAST_MOD_FNAME);
            writeData(file, JSON.bytes(lastModStruct));
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
    
    @Override
    public SignedDomains getUpdatedSignedDomains(StringBuilder lastModTimeBuffer) {

        try (ZMSClient zmsClient = getZMSClient()) {

            // request all the changes from ZMS
            
            Map<String, List<String>> responseHeaders = new HashMap<String, List<String>>();
            SignedDomains signedDomains = zmsClient.getSignedDomains(null, null,
                    lastModTime, responseHeaders);
            
            // retrieve the tag value for the request
            
            String newLastModTime = retrieveTagHeader(responseHeaders);
            if (newLastModTime == null) {
                return null;
            }
            
            // set the last modification time to be returned to the caller
            
            lastModTimeBuffer.setLength(0);
            lastModTimeBuffer.append(newLastModTime);
            
            return signedDomains;
            
        } catch (ZMSClientException e) {
            LOGGER.error("Error when refreshing data from ZMS: " + e.getMessage());
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
    
    public static class DomainFiles extends SimpleFileVisitor<Path> {

        List<String> domains = new ArrayList<>();
        private String domainParent;
        private String rootDir;
        
        public DomainFiles(String rootDir) {
            this.rootDir = rootDir;
        }
        
        @Override
        public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attr) {
            final String domainDir = dir.toString().substring(rootDir.length());
            domainParent = domainDir.replace(File.pathSeparatorChar, '.');
            if (!domainParent.isEmpty() && domainParent.charAt(0) == '.') {
                domainParent = domainParent.substring(1);
            }
            return FileVisitResult.CONTINUE;
        }
        
        @Override
        public FileVisitResult visitFile(Path file, BasicFileAttributes attr) {
            if (attr.isRegularFile()) {
                final String fileName = file.toFile().getName();
                if (fileName.endsWith(FILE_EXT)) {
                    String domain = fileName.substring(0, fileName.length() - FILE_EXT.length());
                    if (!domainParent.isEmpty()) {
                        domain = domainParent + "." + domain;
                    }
                    domains.add(domain);
                }
            }
            return FileVisitResult.CONTINUE;
        }
        
        public List<String> getDomains() {
            return domains;
        }
    }
}
