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

package io.athenz.server.gcp.common.store.impl;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.gax.paging.Page;
import com.google.cloud.storage.Blob;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.zms.JWSDomain;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zms.SignedDomains;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class GcsChangeLogStore implements ChangeLogStore {
    private static final Logger LOGGER = LoggerFactory.getLogger(GcsChangeLogStore.class);

    long lastModTime;
    Storage storage;
    final String projectId;
    final String bucketName;

    private ObjectMapper jsonMapper;
    boolean jwsDomainSupport;

    private static final String PROP_NUMBER_OF_THREADS = "athenz.zts.bucket.threads";
    private static final String PROP_THREADPOOL_TIMEOUT_SECONDS = "athenz.zts.bucket.threads.timeout";
    private final int nThreads = Integer.parseInt(System.getProperty(PROP_NUMBER_OF_THREADS, "10"));
    private final int threadPoolTimeoutSeconds = Integer.parseInt(System.getProperty(PROP_THREADPOOL_TIMEOUT_SECONDS, "1800"));
    protected Map<String, SignedDomain> tempSignedDomainMap = new ConcurrentHashMap<>();
    protected Map<String, JWSDomain> tempJWSDomainMap = new ConcurrentHashMap<>();

    public GcsChangeLogStore(String projectId, String bucketName) {
        this.projectId = projectId;
        this.bucketName = bucketName;
        this.storage = StorageOptions.newBuilder().setProjectId(projectId).build().getService();

        LOGGER.debug("GcsChangeLog: Bucket name: {}", bucketName);

        // initialize our jackson object mapper
        jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    @Override
    public void setJWSDomainSupport(boolean jwsDomainSupport) {
        this.jwsDomainSupport = jwsDomainSupport;
    }

    @Override
    public boolean supportsFullRefresh() {
        return false;
    }

    @Override
    public SignedDomain getLocalSignedDomain(String domainName) {
        LOGGER.debug("getLocalSignedDomain: {}", domainName);

        // clear the mapping if present and value is stored else null is returned

        SignedDomain signedDomain = tempSignedDomainMap.remove(domainName);

        // when for some reason the getAllSignedDomains() was unsuccessful
        // signedDomain will be null

        if (signedDomain == null) {
            LOGGER.info("getLocalSignedDomain: not present in cache, fetching from GCS...");
            signedDomain = getSignedDomain(domainName);
        }

        return signedDomain;
    }

    @Override
    public JWSDomain getLocalJWSDomain(String domainName) {
        LOGGER.debug("getLocalJWSDomain: {}", domainName);

        // clear the mapping if present and value is stored else null is returned

        JWSDomain jwsDomain = tempJWSDomainMap.remove(domainName);

        // when for some reason the getAllJWSDomains() was unsuccessful
        // jwsDomain will be null

        if (jwsDomain == null) {

            LOGGER.info("getLocalJWSDomain: not present in cache, fetching from GCS...");

            jwsDomain = getJWSDomain(domainName);
        }
        return jwsDomain;
    }

    SignedDomain getSignedDomain(String domainName) {
        LOGGER.debug("getSignedDomain with GCS: {}", domainName);

        SignedDomain signedDomain = null;
        try {
            byte[] domainContent = storage.readAllBytes(bucketName, domainName);
            signedDomain = jsonMapper.readValue(domainContent, SignedDomain.class);
        } catch (Exception ex) {
            LOGGER.error("GcsChangeLog: getSignedDomain - unable to get domain {} error: {}",
                    domainName, ex.getMessage());
        }
        return signedDomain;
    }

    JWSDomain getJWSDomain(String domainName) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("getJWSDomain with GCS: {}", domainName);
        }

        JWSDomain jwsDomain = null;
        try {
            byte[] domainContent = storage.readAllBytes(bucketName, domainName);
            jwsDomain = jsonMapper.readValue(domainContent, JWSDomain.class);
        } catch (Exception ex) {
            LOGGER.error("GcsChangeLog: getJWSDomain - unable to get domain {} error: {}",
                    domainName, ex.getMessage());
        }
        return jwsDomain;
    }

    @Override
    public void removeLocalDomain(String domainName) {
        // in GCP our Athenz syncer is responsible for pushing new
        // changes including removing deleted domain to GCS so this
        // api is just a no-op
    }

    @Override
    public void saveLocalDomain(String domainName, SignedDomain signedDomain) {
        // in GCP our Athenz syncer is responsible for pushing new
        // changes into GCS so this api is just a no-op
    }

    @Override
    public void saveLocalDomain(String domainName, JWSDomain jwsDomain) {
        // in GCP our Athenz syncer is responsible for pushing new
        // changes into GCS so this api is just a no-op
    }

    /**
     * list the objects in the zts bucket. If the mod time is specified as 0
     * then we want to list all objects otherwise, we only list objects
     * that are newer than the specified timestamp
     * @param domains collection to be updated to include domain names
     * @param modTime only include domains newer than this timestamp
     */
    void listObjects(Collection<String> domains, long modTime) {
        LOGGER.debug("listObjects: Retrieving domains from {} with mod time > {}", bucketName, modTime);

        Page<Blob> blobs = storage.list(bucketName);

        for (Blob blob : blobs.iterateAll()) {
            String name = blob.getName();
            if (name.startsWith(".")) {
                continue;
            }

            if (modTime > 0) {
                Long updateTime = blob.getUpdateTime();
                if (updateTime != null && updateTime <= modTime) {
                    continue;
                }
            }

            domains.add(name);
        }
    }

    @Override
    public List<String> getLocalDomainList() {

        // check to see if we need to maintain our last modification time.
        // this will be necessary if our last mod time field is null. We need
        // to save the timestamp at the beginning just in case we end up getting
        // paged results and while processing the last page, the Syncer pushes
        // updated domains from the earlier pages

        if (lastModTime == 0) {
            lastModTime = System.currentTimeMillis();
        }

        ArrayList<String> domains = new ArrayList<>();
        listObjects(domains, 0);
        tempSignedDomainMap.clear();
        tempJWSDomainMap.clear();

        getAllDomains(domains);

        return domains;
    }

    public boolean getAllDomains(List<String> domains) {
        LOGGER.info("Getting all domains from GCS with multiple threads...");

        ExecutorService threadPoolExecutor = getExecutorService();
        for (String domain: domains) {
            threadPoolExecutor.execute(new ObjectGcsThread(domain, tempSignedDomainMap,
                    tempJWSDomainMap, storage, jwsDomainSupport));
        }

        // shutdown() ensures no further tasks can be submitted to the ExecutorService

        threadPoolExecutor.shutdown();

        // If an Exception is thrown then we clear the HashMap where the SignedDomains are stored,
        // and also we use the shutdownNow() function to cancel currently executing tasks.

        try {
            LOGGER.info("Waiting for completion of all getdomain tasks...");

            threadPoolExecutor.awaitTermination(threadPoolTimeoutSeconds, TimeUnit.SECONDS);

            LOGGER.info("Executor completed all of its tasks");

        } catch (InterruptedException ex) {
            LOGGER.error("Interrupted Exception in getAllSignedDomains", ex);
            tempSignedDomainMap.clear();
            tempJWSDomainMap.clear();
            threadPoolExecutor.shutdownNow();
            return false;
        }

        return true;
    }

    @Override
    public Set<String> getServerDomainList() {
        HashSet<String> domains = new HashSet<>();
        listObjects(domains, 0);
        return domains;
    }

    /**
     * with GCS change log store there is no need to carry out the domain check
     * operations since during startup we read the domains from our domain
     * bucket and not from ZMS directly
     * @return list of SignedDomain objects (always null)
     */
    @Override
    public SignedDomains getServerDomainModifiedList() {
        return null;
    }

    @Override
    public SignedDomain getServerSignedDomain(String domainName) {
        return null;
    }

    @Override
    public JWSDomain getServerJWSDomain(String domainName) {
        return null;
    }

    List<String> getUpdatedDomainList(StringBuilder lastModTimeBuffer) {

        LOGGER.debug("Retrieving updating domains from GCS...");

        // We need save the timestamp at the beginning just in case we end up getting
        // paged results and while processing the last page, GCS gets pushed
        // updated domains from the earlier pages

        lastModTimeBuffer.append(System.currentTimeMillis());

        List<String> domains = new ArrayList<>();
        listObjects(domains, lastModTime);

        LOGGER.info("Retrieved {} updated domains", domains.size());

        return domains;
    }

    @Override
    public SignedDomains getUpdatedSignedDomains(StringBuilder lastModTimeBuffer) {

        // get the updated domain list and fetch each one individually

        List<String> domains = getUpdatedDomainList(lastModTimeBuffer);

        List<SignedDomain> signedDomainList = new ArrayList<>();
        for (String domain : domains) {
            SignedDomain signedDomain = getSignedDomain(domain);
            if (signedDomain != null) {
                signedDomainList.add(signedDomain);
            }
        }

        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(signedDomainList);
        return signedDomains;
    }

    @Override
    public List<JWSDomain> getUpdatedJWSDomains(StringBuilder lastModTimeBuffer) {

        // get the updated domain list and fetch each one individually

        List<String> domains = getUpdatedDomainList(lastModTimeBuffer);

        List<JWSDomain> jwsDomainList = new ArrayList<>();
        for (String domain : domains) {
            JWSDomain jwsDomain = getJWSDomain(domain);
            if (jwsDomain != null) {
                jwsDomainList.add(jwsDomain);
            }
        }

        return jwsDomainList;
    }

    @Override
    public void setLastModificationTimestamp(String newLastModTime) {
        if (newLastModTime == null || newLastModTime.isBlank()) {
            lastModTime = 0;
            return;
        }

        try {
            lastModTime = Long.parseLong(newLastModTime);
        } catch (NumberFormatException e) {
            LOGGER.error("Invalid timestamp format: {}", newLastModTime, e);
            lastModTime = 0;
        }
    }

    public ExecutorService getExecutorService() {
        return Executors.newFixedThreadPool(nThreads);
    }

    class ObjectGcsThread implements Runnable {

        String domainName;
        Storage storage;
        Map<String, JWSDomain> jwsDomainMap;
        Map<String, SignedDomain> signedDomainMap;
        boolean jwsSupport;

        public ObjectGcsThread(String domainName, Map<String, SignedDomain> signedDomainMap,
                               Map<String, JWSDomain> jwsDomainMap, Storage storage, boolean jwsSupport) {

            this.domainName = domainName;
            this.storage = storage;
            this.signedDomainMap = signedDomainMap;
            this.jwsDomainMap = jwsDomainMap;
            this.jwsSupport = jwsSupport;
        }

        @Override
        public void run() {
            if (jwsSupport) {
                saveJWSDomain();
            } else {
                saveSignedDomain();
            }
        }

        void saveSignedDomain() {
            SignedDomain signedDomain = null;
            try {
                signedDomain = getSignedDomain(domainName);
            } catch (Exception ex) {
                LOGGER.error("GcsChangeLogThread: ObjectGcsThread- getSignedDomain - unable to get domain {} error: {}",
                        domainName, ex.getMessage());
            }
            if (signedDomain != null) {
                signedDomainMap.put(domainName, signedDomain);
            }
        }

        void saveJWSDomain() {
            JWSDomain jwsDomain = null;
            try {
                jwsDomain = getJWSDomain(domainName);
            } catch (Exception ex) {
                LOGGER.error("GcsChangeLogThread: ObjectGcsThread- getJWSDomain - unable to get domain {} error: {}",
                        domainName, ex.getMessage());
            }
            if (jwsDomain != null) {
                jwsDomainMap.put(domainName, jwsDomain);
            }
        }
    }
}
