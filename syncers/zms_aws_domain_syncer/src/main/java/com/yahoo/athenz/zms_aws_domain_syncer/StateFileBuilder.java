/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.zms_aws_domain_syncer;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.*;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.JWSDomain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class StateFileBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(StateFileBuilder.class);

    private final static String BUCKET_NAME = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_BUCKET);
    private final static String THREADS_NUMBER = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_STATE_BUILDER_THREADS);
    private final static String FETCHING_ITEMS_TIMEOUT = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT);

    private final AmazonS3 s3client;
    private final Map<String, JWSDomainData> tempJWSDomainMap = new ConcurrentHashMap<>();
    private final ExecutorService executorService;
    private final ObjectMapper jsonMapper = new ObjectMapper();
    private final DomainValidator domainValidator;

    public StateFileBuilder() throws Exception {
        this(S3ClientFactory.getS3Client(), new DomainValidator());
    }

    public StateFileBuilder(AmazonS3 s3client, DomainValidator domainValidator) {

        this.s3client = s3client;
        this.domainValidator = domainValidator;

        int nThreads = Integer.parseInt(THREADS_NUMBER);
        LOGGER.info("number of threads to build state from S3: {}", nThreads);

        executorService = Executors.newFixedThreadPool(nThreads);
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public Map<String, DomainState> buildStateMap() {

        LOGGER.info("building state map from S3...");

        List<String> domains = listObjects(s3client);
        final int timeout = Integer.parseInt(FETCHING_ITEMS_TIMEOUT);

        LOGGER.info("timeout to build state from S3: {}", timeout);

        for (String domain: domains) {
            executorService.execute(new ObjectS3Thread(domain, tempJWSDomainMap, s3client));
        }

        executorService.shutdown();

        // If an Exception is thrown then we clear the HashMap where the SignedDomains are stored,
        // and also we use the shutdownNow() function to cancel currently executing tasks.

        try {
            LOGGER.info("waiting for completion of all get domain tasks...");
            executorService.awaitTermination(timeout, TimeUnit.SECONDS);
            LOGGER.info("Executor completed all of its tasks");
        } catch (InterruptedException ex) {
            LOGGER.error("interrupted Exception in get domain tasks", ex);
            tempJWSDomainMap.clear();
            executorService.shutdownNow();
        }

        LOGGER.info("fetched {} domain object names from S3 bucket {}", tempJWSDomainMap.size(), BUCKET_NAME);

        Map<String, DomainState> stateMap = tempJWSDomainMap.entrySet().stream()
                .filter(entry -> domainValidator.validateJWSDomain(entry.getValue().getJwsDomain()))
                .collect(Collectors.toMap(
                        key -> key.getKey(),
                        value -> getDomainState(domainValidator.getDomainData(value.getValue().getJwsDomain()),
                                value.getValue().getFetchTime())
                ));

        LOGGER.info("validated signatures of {} domain object from S3 bucket {}", stateMap.size(), BUCKET_NAME);
        return stateMap;
    }

    DomainState getDomainState(final DomainData domData, long fetchTime) {
        final String domName = domData.getName();
        final String domMod = domData.getModified().toString();

        DomainState domState = new DomainState();
        domState.setDomain(domName);
        domState.setModified(domMod);
        domState.setFetchTime(fetchTime);
        return domState;
    }

    /**
     * list the objects in the bucket.
     * @param s3 aws s3 object
     * @return List of domains from s3 bucket
     */
    List<String> listObjects(AmazonS3 s3) {

        LOGGER.debug("retrieving domains from {}", BUCKET_NAME);

        ObjectListing objectListing = s3.listObjects(new ListObjectsRequest().withBucketName(BUCKET_NAME));

        List<String> domains = new ArrayList<>();
        while (objectListing != null) {

            // process each entry in our result set and add the domain
            // name to our return list

            final List<S3ObjectSummary> objectSummaries = objectListing.getObjectSummaries();
            boolean listTruncated = objectListing.isTruncated();

            LOGGER.debug("retrieved {} objects, more objects available - {}",
                        objectSummaries.size(), listTruncated);

            for (S3ObjectSummary objectSummary : objectSummaries) {

                // for now skip any folders/objects that start with '.'

                final String objectName = objectSummary.getKey();
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

    static class JWSDomainData {
        JWSDomain jwsDomain;
        long fetchTime;

        public JWSDomainData(JWSDomain jwsDomain, long fetchTime) {
            this.jwsDomain = jwsDomain;
            this.fetchTime = fetchTime;
        }
        JWSDomain getJwsDomain() {
            return jwsDomain;
        }
        long getFetchTime() {
            return fetchTime;
        }
    }

    class ObjectS3Thread implements Runnable {

        String domainName;
        AmazonS3 s3;
        Map<String, JWSDomainData> jwsDomainMap;

        public ObjectS3Thread(String domainName, Map<String, JWSDomainData> jwsDomainMap, AmazonS3 s3) {
            this.domainName = domainName;
            this.s3 = s3;
            this.jwsDomainMap = jwsDomainMap;
        }

        @Override
        public void run() {

            LOGGER.debug("Getting s3 object for domain: {}", domainName);

            JWSDomain jwsDomain = null;
            long fetchTime = 0;

            try {
                S3Object object = s3.getObject(BUCKET_NAME, domainName);
                try (S3ObjectInputStream s3is = object.getObjectContent()) {
                    jwsDomain = jsonMapper.readValue(s3is, JWSDomain.class);
                    fetchTime = object.getObjectMetadata().getLastModified().getTime() / 1000;
                }
            } catch (Exception ex) {
                LOGGER.error("unable to get domain {} error: {}", domainName, ex.getMessage());
            }

            if (jwsDomain != null) {

                LOGGER.debug("fetched domain: {},", domainName);
                jwsDomainMap.put(domainName, new JWSDomainData(jwsDomain, fetchTime));
            }
        }
    }
}
