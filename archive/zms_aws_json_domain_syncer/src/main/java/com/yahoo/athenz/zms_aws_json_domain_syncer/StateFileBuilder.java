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

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.*;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.SignedDomain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class StateFileBuilder {
    private final static String BUCKET_NAME = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWSBUCK);
    private final static String THREADS_NUMBER = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_STATE_BUILDER_THREADS);
    private final static String FETCHING_ITEMS_TIMEOUT = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT);

    private static final Logger LOGGER = LoggerFactory.getLogger(StateFileBuilder.class);

    private final AmazonS3 s3client;
    private Map<String, SignedDomain> tempSignedDomainMap = new ConcurrentHashMap<>();
    private final ExecutorService executorService;
    private final ObjectMapper jsonMapper = new ObjectMapper();
    private final DomainValidator domainValidator;

    public StateFileBuilder() throws Exception {
        this(S3ClientFactory.getS3Client(), new DomainValidator());
    }

    public StateFileBuilder(AmazonS3 s3client, DomainValidator domainValidator) {
        this.s3client = s3client;
        int nThreads = Integer.parseInt(THREADS_NUMBER);
        LOGGER.info("Number of threads to build state from S3: " + nThreads);
        executorService = Executors.newFixedThreadPool(nThreads);
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.domainValidator = domainValidator;
    }

    public Map<String, DomainState> buildStateMap() {
        LOGGER.info("Building state map from S3");
        List<String> domains = listObjects(s3client);
        final int timeout = Integer.parseInt(FETCHING_ITEMS_TIMEOUT);
        LOGGER.info("Timeout to build state from S3: " + timeout);
        for (String domain: domains) {
            executorService.execute(new ObjectS3Thread(domain, tempSignedDomainMap, s3client));
        }

        executorService.shutdown();

        // If an Exception is thrown then we clear the HashMap where the SignedDomains are stored
        // and also we use the shutdownNow() function to cancel currently executing tasks.

        try {
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("Waiting for completion of all getdomain tasks...");
            }

            executorService.awaitTermination(timeout, TimeUnit.SECONDS);

            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("Executor completed all of its tasks");
            }

        } catch (InterruptedException ex) {
            LOGGER.error("Interrupted Exception in getAllSignedDomains", ex);
            tempSignedDomainMap.clear();
            executorService.shutdownNow();

        }

        LOGGER.info("Fetched {} domain object names from S3 bucket {}", tempSignedDomainMap.size(), BUCKET_NAME);
        Map<String, DomainState> stateMap = tempSignedDomainMap.entrySet().stream()
                .filter(entry -> domainValidator.validateSignedDomain(entry.getValue()))
                .collect(Collectors.toMap(
                        key -> key.getKey(),
                        value -> {
                            DomainData domData = value.getValue().getDomain();
                            String domName = domData.getName();
                            String domMod = domData.getModified().toString();

                            DomainState domState = new DomainState();
                            domState.setDomain(domName);
                            domState.setModified(domMod);
                            return domState;
                        }
                ));

        LOGGER.info("Validated signatures of {} domain object from S3 bucket {}", stateMap.size(), BUCKET_NAME);
        return stateMap;
    }

    /**
     * list the objects in the bucket.
     * @param s3
     * @return List of domains from s3 bucket
     */
    List<String> listObjects(AmazonS3 s3) {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("listObjects: Retrieving domains from {}", BUCKET_NAME);
        }

        ObjectListing objectListing = s3.listObjects(new ListObjectsRequest()
                .withBucketName(BUCKET_NAME));

        List<String> domains = new ArrayList<>();
        String objectName;
        while (objectListing != null) {

            // process each entry in our result set and add the domain
            // name to our return list

            final List<S3ObjectSummary> objectSummaries = objectListing.getObjectSummaries();
            boolean listTruncated = objectListing.isTruncated();

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("listObjects: retrieved {} objects, more objects available - {}",
                        objectSummaries.size(), listTruncated);
            }

            for (S3ObjectSummary objectSummary : objectSummaries) {

                // for now skip any folders/objects that start with '.'

                objectName = objectSummary.getKey();
                if (objectName.charAt(0) == '.') {
                    continue;
                }
                domains.add(objectName);
            }

            // check if the object listing is truncated or not (break out in this case)
            // technically we can skip this call and just call listNextBatchOfResults
            // since that returns null if the object listing is not truncated but
            // this direct check here makes the logic easier to follow

            if (!listTruncated) {
                break;
            }

            objectListing = s3.listNextBatchOfObjects(objectListing);
        }

        return domains;
    }

    class ObjectS3Thread implements Runnable {

        private static final int MAX_RETRY_COUNT = 3;

        String domainName;
        AmazonS3 s3;
        Map<String, SignedDomain> signedDomainMap;

        public ObjectS3Thread(String domainName, Map<String, SignedDomain> signedDomainMap, AmazonS3 s3) {
            this.domainName = domainName;
            this.s3 = s3;
            this.signedDomainMap = signedDomainMap;
        }

        @Override
        public void run() {
            SignedDomain signedDomain = null;
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Getting s3 object for domain: " + domainName);
            }

            try {
                S3Object object = s3.getObject(BUCKET_NAME, domainName);
                try (S3ObjectInputStream s3is = object.getObjectContent()) {
                    signedDomain = jsonMapper.readValue(s3is, SignedDomain.class);
                }
            } catch (Exception ex) {
                LOGGER.error("StateFileBuilder: ObjectS3Thread- getSignedDomain - unable to get domain {} error: {}",
                        domainName, ex.getMessage());
            }
            if (signedDomain != null) {
                signedDomainMap.put(domainName, signedDomain);
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Fetched domain: {}, Modified: {}", domainName, signedDomain.getDomain().getModified().toString());
                }
            }
        }
    }
}
