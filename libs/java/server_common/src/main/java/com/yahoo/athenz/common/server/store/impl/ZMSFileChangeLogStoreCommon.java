/*
 *  Copyright 2020 Verizon Media
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.common.server.store.impl;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.common.server.util.FilesHelper;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zms.SignedDomains;
import com.yahoo.athenz.zms.ZMSClient;
import com.yahoo.athenz.zms.ZMSClientException;
import com.yahoo.rdl.Struct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.attribute.PosixFilePermission;
import java.util.*;

public class ZMSFileChangeLogStoreCommon {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZMSFileChangeLogStoreCommon.class);

    File rootDir;
    ObjectMapper jsonMapper;
    FilesHelper filesHelper;

    public String lastModTime;

    private static final String ATTR_TAG           = "tag";
    private static final String VALUE_TRUE         = "true";
    private static final String LAST_MOD_FNAME     = ".lastModTime";
    private static final String ATTR_LAST_MOD_TIME = "lastModTime";

    public ZMSFileChangeLogStoreCommon(final String rootDirectory) {

        // create our file helper object

        filesHelper = new FilesHelper();

        // initialize our jackson object mapper

        jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

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

        Set<PosixFilePermission> perms = EnumSet.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);
        setupFilePermissions(rootDir, perms);

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

    public boolean supportsFullRefresh() {
        return false;
    }

    public SignedDomain getLocalSignedDomain(final String domainName) {
        return get(domainName, SignedDomain.class);
    }

    public SignedDomain getServerSignedDomain(ZMSClient zmsClient, final String domainName) {

        SignedDomains signedDomains = zmsClient.getSignedDomains(domainName, null, null, null);

        if (signedDomains == null) {
            LOGGER.error("No data was returned from ZMS for domain {}", domainName);
            return null;
        }

        List<SignedDomain> domains = signedDomains.getDomains();
        if (domains == null || domains.size() != 1) {
            LOGGER.error("Invalid data was returned from ZMS for domain {}", domainName);
            return null;
        }

        return domains.get(0);
    }

    public void removeLocalDomain(String domainName) {
        delete(domainName);
    }

    public void saveLocalDomain(String domainName, SignedDomain signedDomain) {
        put(domainName, jsonValueAsBytes(signedDomain, SignedDomain.class));
    }

    void setupFilePermissions(File file, Set<PosixFilePermission> perms) {
        try {
            filesHelper.setPosixFilePermissions(file, perms);
        } catch (IOException ex) {
            error("unable to setup file with permissions: " + ex.getMessage());
        }
    }

    void setupDomainFile(File file) {

        try {
            filesHelper.createEmptyFile(file);
            Set<PosixFilePermission> perms = EnumSet.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE);
            setupFilePermissions(file, perms);
        } catch (IOException ex) {
            error("unable to setup domain file with permissions: " + ex.getMessage());
        }
    }

    public synchronized <T> T get(String name, Class<T> classType) {

        File file = new File(rootDir, name);
        if (!file.exists()) {
            return null;
        }

        try {
            return jsonMapper.readValue(file, classType);
        } catch (Exception ex) {
            LOGGER.error("Unable to retrieve file: {} error: {}", file.getAbsolutePath(), ex.getMessage());
        }
        return null;
    }

    public synchronized void put(String name, byte[] data) {

        File file = new File(rootDir, name);
        if (!file.exists()) {
            setupDomainFile(file);
        }

        try {
            filesHelper.write(file, data);
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
            filesHelper.delete(file);
        } catch (Exception exc) {
            error("Cannot delete file or directory: " + name + " : exc: " + exc);
        }
    }

    public List<String> getLocalDomainList() {

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

    public Set<String> getServerDomainList(ZMSClient zmsClient) {
        return new HashSet<>(zmsClient.getDomainList().getNames());
    }

    public SignedDomains getServerDomainModifiedList(ZMSClient zmsClient) {
        return zmsClient.getSignedDomains(null, VALUE_TRUE, null, null);
    }

    public String retrieveLastModificationTime() {
        Struct lastModStruct = get(LAST_MOD_FNAME, Struct.class);
        if (lastModStruct == null) {
            return null;
        }
        return lastModStruct.getString(ATTR_LAST_MOD_TIME);
    }

    public void setLastModificationTimestamp(String newLastModTime) {

        lastModTime = newLastModTime;
        if (lastModTime == null) {
            delete(LAST_MOD_FNAME);
        } else {

            // update the last modification timestamp

            Struct lastModStruct = new Struct();
            lastModStruct.put(ATTR_LAST_MOD_TIME, lastModTime);
            put(LAST_MOD_FNAME, jsonValueAsBytes(lastModStruct, Struct.class));
        }
    }

    byte[] jsonValueAsBytes(Object obj, Class<?> cls) {
        try {
            return jsonMapper.writerWithView(cls).writeValueAsBytes(obj);
        } catch (Exception ex) {
            LOGGER.error("Unable to serialize json object: {}", ex.getMessage());
            return null;
        }
    }

    public String retrieveTagHeader(Map<String, List<String>> responseHeaders) {

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

            while (true) {
                try {
                    SignedDomains singleDomain = zmsClient.getSignedDomains(domainName,
                            null, null, null);

                    if (singleDomain != null && !singleDomain.getDomains().isEmpty()) {
                        domains.addAll(singleDomain.getDomains());
                    }

                    break;

                } catch (ZMSClientException ex) {

                    LOGGER.error("Error fetching domain {} from ZMS: {}", domainName,
                            ex.getMessage());

                    // if we get a rate limiting failure, we're going to sleep
                    // for a second and retry our operation again

                    if (ex.getCode() != ZMSClientException.TOO_MANY_REQUESTS) {
                        break;
                    }

                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException ignored) {
                    }
                }
            }
        }
        return domains;
    }

    public SignedDomains getUpdatedSignedDomains(ZMSClient zmsClient, StringBuilder lastModTimeBuffer) {

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
    }

    static void error(String msg) {
        LOGGER.error(msg);
        throw new RuntimeException("ZMSFileChangeLogStore: " + msg);
    }
}
