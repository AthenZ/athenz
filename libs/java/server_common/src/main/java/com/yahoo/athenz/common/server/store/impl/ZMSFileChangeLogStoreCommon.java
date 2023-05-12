/*
 *  Copyright The Athenz Authors
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
import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.Struct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.attribute.PosixFilePermission;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

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

    boolean requestConditions;
    int maxRateLimitRetryCount = 101;

    public ZMSFileChangeLogStoreCommon(final String rootDirectory) {

        // create our file helper object

        filesHelper = new FilesHelper();

        // initialize our jackson object mapper

        jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        // set up our directory for storing domain files

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

    public void setRequestConditions(final boolean requestConditions) {
        this.requestConditions = requestConditions;
    }

    public boolean supportsFullRefresh() {
        return false;
    }

    public SignedDomain getLocalSignedDomain(final String domainName) {
        return get(domainName, SignedDomain.class);
    }

    public JWSDomain getLocalJWSDomain(final String domainName) {
        return get(domainName, JWSDomain.class);
    }

    public SignedDomain getServerSignedDomain(ZMSClient zmsClient, final String domainName) {

        SignedDomains signedDomains = makeSignedDomainsCall(zmsClient, domainName, null, null, null);

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

    public JWSDomain getServerJWSDomain(ZMSClient zmsClient, final String domainName) {
        return zmsClient.getJWSDomain(domainName, null, null);
    }

    public void removeLocalDomain(String domainName) {
        delete(domainName);
    }

    public void saveLocalDomain(String domainName, SignedDomain signedDomain) {
        put(domainName, jsonValueAsBytes(signedDomain, SignedDomain.class));
    }

    public void saveLocalDomain(String domainName, JWSDomain jwsDomain) {
        put(domainName, jsonValueAsBytes(jwsDomain, JWSDomain.class));
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

    public Map<String, DomainAttributes> getLocalDomainAttributeList() {

        Map<String, DomainAttributes> domainAttrs = new HashMap<>();
        String[] domains = rootDir.list();
        if (domains == null) {
            return domainAttrs;
        }
        for (String name : domains) {

            // we are going to skip any hidden files

            if (name.charAt(0) != '.') {
                File file = new File(rootDir, name);
                domainAttrs.put(name, new DomainAttributes().setFetchTime(file.lastModified() / 1000));
            }
        }

        return domainAttrs;
    }

    public Set<String> getServerDomainList(ZMSClient zmsClient) {
        return new HashSet<>(zmsClient.getDomainList().getNames());
    }

    public SignedDomains getServerDomainModifiedList(ZMSClient zmsClient) {
        return makeSignedDomainsCall(zmsClient, null, VALUE_TRUE, null, null);
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

            // we're going to retry up to 100 times in case of rate limiting
            // from ZMS Server. If not able to retrieve after so many times
            // we'll pick up the change again during our full sync time

            for (int count = 1; count < maxRateLimitRetryCount; count++) {
                try {

                    SignedDomains singleDomain = makeSignedDomainsCall(zmsClient, domainName, null, null, null);

                    if (singleDomain != null && !singleDomain.getDomains().isEmpty()) {
                        domains.addAll(singleDomain.getDomains());
                    }

                    break;

                } catch (ZMSClientException ex) {

                    LOGGER.error("Error fetching domain {} from ZMS: {}", domainName, ex.getMessage());

                    // if we get a rate limiting failure, we're going to sleep
                    // for some period and retry our operation again

                    if (ex.getCode() != ZMSClientException.TOO_MANY_REQUESTS) {
                        break;
                    }

                    try {
                        Thread.sleep(randomSleepForRetry(count));
                    } catch (InterruptedException ignored) {
                    }
                }
            }
        }
        return domains;
    }

    List<JWSDomain> getJWSDomainList(ZMSClient zmsClient, SignedDomains domainList) {

        List<JWSDomain> domains = new ArrayList<>();
        for (SignedDomain domain : domainList.getDomains()) {

            final String domainName = domain.getDomain().getName();

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("getJWSDomainList: fetching domain {}", domainName);
            }

            // we're going to retry up to 100 times in case of rate limiting
            // from ZMS Server. If not able to retrieve after so many times
            // we'll pick up the change again during our full sync time

            for (int count = 1; count < maxRateLimitRetryCount; count++) {
                try {

                    JWSDomain jwsDomain = zmsClient.getJWSDomain(domainName, null, null);
                    if (jwsDomain != null) {
                        domains.add(jwsDomain);
                    }

                    break;

                } catch (ZMSClientException ex) {

                    LOGGER.error("Error fetching domain {} from ZMS: {}", domainName, ex.getMessage());

                    // if we get a rate limiting failure, we're going to sleep
                    // for some period and retry our operation again

                    if (ex.getCode() != ZMSClientException.TOO_MANY_REQUESTS) {
                        break;
                    }

                    try {
                        Thread.sleep(randomSleepForRetry(count));
                    } catch (InterruptedException ignored) {
                    }
                }
            }
        }
        return domains;
    }

    /**
     * For the first three tries we're going to sleep given number of seconds
     * After the 4th try we'll just pick a random number of seconds between
     * 4 and 10 - this will randomize the sleep between zts instances so that
     * all of them do not sleep exact same number of seconds and end up
     * being rate limited over and over again.
     * @param count number of retries
     * @return number of seconds to sleep
     */
    long randomSleepForRetry(int count) {
        return count < 4 ? 1000L * count : ThreadLocalRandom.current().nextInt(4, 11) * 1000L;
    }

    SignedDomains getModifiedDomainList(ZMSClient zmsClient, StringBuilder lastModTimeBuffer) {

        // request all the changes from ZMS. In this call we're asking for
        // metadata only so we'll only get the list of domains

        Map<String, List<String>> responseHeaders = new HashMap<>();
        SignedDomains domainList = makeSignedDomainsCall(zmsClient, null, VALUE_TRUE, lastModTime, responseHeaders);

        // retrieve the tag value for the request

        String newLastModTime = retrieveTagHeader(responseHeaders);
        if (newLastModTime == null) {
            return null;
        }

        // set the last modification time to be returned to the caller

        lastModTimeBuffer.setLength(0);
        lastModTimeBuffer.append(newLastModTime);

        return domainList;
    }

    public SignedDomains getUpdatedSignedDomains(ZMSClient zmsClient, StringBuilder lastModTimeBuffer) {

        // request all the changes from ZMS. In this call we're asking for
        // metadata only so we'll only get the list of domains

        SignedDomains domainList = getModifiedDomainList(zmsClient, lastModTimeBuffer);
        if (domainList == null || domainList.getDomains() == null) {
            return null;
        }

        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("getUpdatedSignedDomains: {} updated domains", domainList.getDomains().size());
        }

        // now let's iterate through our list and retrieve one domain at a time

        List<SignedDomain> domains = getSignedDomainList(zmsClient, domainList);
        return new SignedDomains().setDomains(domains);
    }

    public List<JWSDomain> getUpdatedJWSDomains(ZMSClient zmsClient, StringBuilder lastModTimeBuffer) {

        // request all the changes from ZMS. In this call we're asking for
        // metadata only so we'll only get the list of domains

        SignedDomains domainList = getModifiedDomainList(zmsClient, lastModTimeBuffer);
        if (domainList == null || domainList.getDomains() == null) {
            return null;
        }

        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("getUpdatedJWSDomains: {} updated domains", domainList.getDomains().size());
        }

        // now let's iterate through our list and retrieve one domain at a time

        return getJWSDomainList(zmsClient, domainList);
    }

    static void error(String msg) {
        LOGGER.error(msg);
        throw new RuntimeException("ZMSFileChangeLogStore: " + msg);
    }

    private SignedDomains makeSignedDomainsCall(ZMSClient zmsClient, String domainName, String metaOnly, String matchingTag, Map<String, List<String>> responseHeaders) {
        return zmsClient.getSignedDomains(domainName, metaOnly, null, true, requestConditions, matchingTag, responseHeaders);
    }
}
