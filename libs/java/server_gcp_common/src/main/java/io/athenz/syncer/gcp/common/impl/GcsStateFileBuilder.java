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

package io.athenz.syncer.gcp.common.impl;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.cloud.storage.Blob;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import com.yahoo.athenz.zms.JWSDomain;
import io.athenz.syncer.common.zms.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

public class GcsStateFileBuilder implements StateFileBuilder {
    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private final static String THREADS_NUMBER = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_STATE_BUILDER_THREADS);
    private final static String FETCHING_ITEMS_TIMEOUT = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT);

    final Map<String, JWSDomainData> tempJWSDomainMap = new ConcurrentHashMap<>();
    final ExecutorService executorService;
    private final ObjectMapper jsonMapper = new ObjectMapper();
    private final DomainValidator domainValidator;
    private final Storage storage;
    private final String projectId;
    private final String bucketName;

    public GcsStateFileBuilder(String projectId, String bucketName, DomainValidator domainValidator) {
        if (projectId == null || projectId.isEmpty()) {
            throw new IllegalArgumentException("GCP project id is not specified");
        }

        if (bucketName == null || bucketName.isEmpty()) {
            throw new IllegalArgumentException("GCP bucket name is not specified");
        }

        this.projectId = projectId;
        this.bucketName = bucketName;

        this.domainValidator = domainValidator;
        this.storage = StorageOptions.newBuilder().setProjectId(projectId).build().getService();

        int nThreads = Integer.parseInt(THREADS_NUMBER);
        LOG.info("number of threads to build state from the bucket: {}", nThreads);

        executorService = Executors.newFixedThreadPool(nThreads);
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public Map<String, DomainState> buildStateMap() {
        LOG.info("building state map from bucket...");

        List<String> domains = listObjects();
        final int timeout = Integer.parseInt(FETCHING_ITEMS_TIMEOUT);

        LOG.info("timeout to build state from the bucket: {}", timeout);

        for (String domain: domains) {
            executorService.execute(new BucketObjectThread(storage, bucketName, domain, tempJWSDomainMap));
        }

        executorService.shutdown();

        // If an Exception is thrown then we clear the HashMap where the SignedDomains are stored,
        // and also we use the shutdownNow() function to cancel currently executing tasks.

        try {
            LOG.info("waiting for completion of all get domain tasks...");
            executorService.awaitTermination(timeout, TimeUnit.SECONDS);
            LOG.info("Executor completed all of its tasks");
        } catch (InterruptedException ex) {
            LOG.error("interrupted Exception in get domain tasks", ex);
            tempJWSDomainMap.clear();
            executorService.shutdownNow();
        }

        LOG.info("fetched {} domain object names from the bucket {}", tempJWSDomainMap.size(), bucketName);

        Map<String, DomainState> stateMap = tempJWSDomainMap.entrySet().stream()
                .filter(entry -> domainValidator.validateJWSDomain(entry.getValue().getJwsDomain()))
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        value -> DomainState.getDomainState(domainValidator.getDomainData(value.getValue().getJwsDomain()),
                                value.getValue().getFetchTime())
                ));

        LOG.info("validated signatures of {} domain object from the bucket {}", stateMap.size(), bucketName);
        return stateMap;
    }

    /**
     * list the objects in the bucket.
     * @return List of domains from GCS bucket
     */
    List<String> listObjects() {
        LOG.debug("retrieving domains from {}", bucketName);

        return StreamSupport.stream(storage.list(bucketName).iterateAll().spliterator(), false)
                .map(Blob::getName)
                .filter(name -> !name.startsWith("."))
                .collect(Collectors.toList());
    }

    class BucketObjectThread implements Runnable {
        String domainName;
        Map<String, JWSDomainData> jwsDomainMap;
        final Storage storage;
        final String bucketName;


        public BucketObjectThread(Storage storage, String bucketName, String domainName, Map<String, JWSDomainData> jwsDomainMap) {
            this.storage = storage;
            this.bucketName = bucketName;
            this.domainName = domainName;
            this.jwsDomainMap = jwsDomainMap;
        }

        @Override
        public void run() {
            LOG.debug("Getting bucket object for domain: {}", domainName);

            JWSDomain jwsDomain = null;

            // Get blob metadata
            Blob blob = storage.get(bucketName, domainName);
            if (blob == null) {
                LOG.error("unable to get domain {}", domainName);
                System.out.println("Object not found.");
                return;
            }

            long fetchTime = blob.getUpdateTimeOffsetDateTime().toInstant().toEpochMilli();

            try {
                jwsDomain = jsonMapper.readValue(blob.getContent(), JWSDomain.class);
            } catch (Exception e) {
                LOG.error("unable to get domain {}", domainName);
            }

            if (jwsDomain != null) {
                LOG.debug("fetched domain: {},", domainName);
                jwsDomainMap.put(domainName, new JWSDomainData(jwsDomain, fetchTime));
            }
        }
    }
}
