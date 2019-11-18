/*
 * Copyright 2019 Oath Holdings, Inc.
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

import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.ListObjectsRequest;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectInputStream;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zms.SignedDomains;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.store.ChangeLogStore;
import com.yahoo.athenz.zts.store.CloudStore;

public class S3ChangeLogStore implements ChangeLogStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(S3ChangeLogStore.class);

    long lastModTime;
    AmazonS3 awsS3Client = null;

    private String s3BucketName;
    private CloudStore cloudStore;
    private ObjectMapper jsonMapper;

    private static final String NUMBER_OF_THREADS = "athenz.zts.bucket.threads";
    private static final String DEFAULT_TIMEOUT_SECONDS = "athenz.zts.bucket.threads.timeout";
    private int nThreads = Integer.valueOf(System.getProperty(NUMBER_OF_THREADS, "10"));
    private int defaultTimeoutSeconds = Integer.valueOf(System.getProperty(DEFAULT_TIMEOUT_SECONDS, "1800"));
    private volatile HashMap<String, SignedDomain> tempSignedDomainMap = new HashMap<>();

    public S3ChangeLogStore(CloudStore cloudStore) {
        this.cloudStore = cloudStore;
        s3BucketName = System.getProperty(ZTSConsts.ZTS_PROP_AWS_BUCKET_NAME);
        if (s3BucketName == null || s3BucketName.isEmpty()) {
            error("S3 Bucket name cannot be null");
        }
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("AWSS3ChangeLog: S3 Bucket name: " + s3BucketName);
        }

        // initialize our jackson object mapper

        jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    @Override
    public boolean supportsFullRefresh() {
        return false;
    }
    
    @Override
    public SignedDomain getSignedDomain(String domainName) {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("getSignedDomain: {}", domainName);
        }

        // clear the mapping if present and value is stored else null is returned

        SignedDomain signedDomain = tempSignedDomainMap.remove(domainName);

        // when for some reason the getAllSignedDomains() was unsuccessful
        // signedDomain will be null

        if (signedDomain == null) {

            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("getSignedDomain: not present in cache, fetching from S3...");
            }

            // make sure we have an aws s3 client for our request

            if (awsS3Client == null) {
                awsS3Client = getS3Client();
            }

            signedDomain = getSignedDomain(awsS3Client, domainName);

            // if we got a failure for any reason, we're going
            // get a new aws s3 client and try again

            if (signedDomain == null) {
                awsS3Client = getS3Client();
                signedDomain = getSignedDomain(awsS3Client, domainName);
            }
        }
        return signedDomain;
    }
    
    SignedDomain getSignedDomain(AmazonS3 s3, String domainName) {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("getSignedDomain with S3: {}", domainName);
        }
        
        SignedDomain signedDomain = null;
        try {
            S3Object object = s3.getObject(s3BucketName, domainName);
            try (S3ObjectInputStream s3is = object.getObjectContent()) {
                signedDomain = jsonMapper.readValue(s3is, SignedDomain.class);
            }
        } catch (Exception ex) {
            LOGGER.error("AWSS3ChangeLog: getSignedDomain - unable to get domain {} error: {}",
                    domainName, ex.getMessage());
        }
        return signedDomain;
    }
    
    @SuppressWarnings("EmptyMethod")
    @Override
    public void removeLocalDomain(String domainName) {
        // in AWS our Athenz syncer is responsible for pushing new
        // changes including removing deleted domain to S3 so this
        // api is just a no-op
    }

    @SuppressWarnings("EmptyMethod")
    @Override
    public void saveLocalDomain(String domainName, SignedDomain signedDomain) {
        // in AWS our Athenz syncer is responsible for pushing new
        // changes into S3 so this api is just a no-op
    }

    /**
     * list the objects in the zts bucket. If the mod time is specified as 0
     * then we want to list all objects otherwise, we only list objects
     * that are newer than the specified timestamp
     * @param s3 AWS S3 client object
     * @param domains collection to be updated to include domain names
     * @param modTime only include domains newer than this timestamp
     */
    void listObjects(AmazonS3 s3, Collection<String> domains, long modTime) {
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("listObjects: Retrieving domains from {} with mod time > {}",
                    s3BucketName, modTime);
        }
        
        ObjectListing objectListing = s3.listObjects(new ListObjectsRequest()
                .withBucketName(s3BucketName));
        
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
                
                // if mod time is specified then make sure we automatically skip
                // any domains older than the specified value
                
                if (modTime > 0 && objectSummary.getLastModified().getTime() <= modTime) {
                    continue;
                }
                
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
        
        // we are going to initialize our s3 client here since
        // this is the first entry point before we start
        // fetching all the domains individually
        
        awsS3Client = getS3Client();
        
        ArrayList<String> domains = new ArrayList<>();
        listObjects(awsS3Client, domains, 0);
        tempSignedDomainMap.clear();

        // we are trying to get the signed domain list from the s3 bucket twice here.
        // The function get AllSignedDomains will return false when an InterruptedException
        // is thrown. If it can't be done successfully then we thrown a RuntimeException.

        if (!getAllSignedDomains(domains)) {
            getAllSignedDomains(domains);
        }
        return domains;
    }

    public boolean getAllSignedDomains(List<String> domains) {

        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("Getting all domains from S3 with multiple threads...");
        }

        ExecutorService threadPoolExecutor = getExecutorService();
        AmazonS3 tempS3 = getS3Client();
        for (String domain: domains) {
            threadPoolExecutor.execute(new S3ChangeLogStore.ObjectS3Thread(domain, tempSignedDomainMap, tempS3));
        }

        // shutdown() ensures no further tasks can be submitted to the ExecutorService

        threadPoolExecutor.shutdown();

        // If an Exception is thrown then we clear the HashMap where the SignedDomains are stored
        // and also we use the shutdownNow() function to cancel currently executing tasks.

        try {
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("Waiting for completion of all getdomain tasks...");
            }

            threadPoolExecutor.awaitTermination(defaultTimeoutSeconds, TimeUnit.SECONDS);

            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("Executor completed all of its tasks");
            }

        } catch (InterruptedException ex) {
            LOGGER.error("Interrupted Exception in getAllSignedDomains", ex);
            tempSignedDomainMap.clear();
            threadPoolExecutor.shutdownNow();
            return false;
        }

        return true;
    }

    @Override
    public Set<String> getServerDomainList() {
        
        // for the server domain list operation since it's called
        // periodically by the thread to see if any domains have
        // been deleted, we're going to get a new s3 client
        // instead of using our original client
        
        HashSet<String> domains = new HashSet<>();
        listObjects(getS3Client(), domains, 0);
        return domains;
    }

    @Override
    public SignedDomains getUpdatedSignedDomains(StringBuilder lastModTimeBuffer) {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("getUpdatedSignedDomains: Retrieving updating signed domains from S3...");
        }
        
        // We need save the timestamp at the beginning just in case we end up getting
        // paged results and while processing the last page, S3 gets pushed
        // updated domains from the earlier pages
        
        lastModTimeBuffer.append(System.currentTimeMillis());
        
        // AWS S3 API does not provide support for listing objects filtered
        // based on its last modification timestamp so we need to get
        // the full list and filter ourselves
        
        // instead of using our fetched s3 client, we're going to
        // obtain a new one to get the changes
        
        AmazonS3 s3 = getS3Client();
        ArrayList<String> domains = new ArrayList<>();
        listObjects(s3, domains, lastModTime);
        
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("getUpdatedSignedDomains: {} updated domains", domains.size());
        }
        
        ArrayList<SignedDomain> signedDomainList = new ArrayList<>();
        SignedDomain signedDomain;
        for (String domain : domains) {
            signedDomain = getSignedDomain(s3, domain);
            if (signedDomain != null) {
                signedDomainList.add(signedDomain);
            }
        }
        
        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(signedDomainList);
        return signedDomains;
    }

    @Override
    public void setLastModificationTimestamp(String newLastModTime) {
        if (newLastModTime == null) {
            lastModTime = 0;
        } else {
            lastModTime = Long.parseLong(newLastModTime);
        }
    }

    AmazonS3 getS3Client() {
        return cloudStore.getS3Client();
    }

    public ExecutorService getExecutorService() {
        return Executors.newFixedThreadPool(nThreads);
    }

    static void error(String msg) {
        LOGGER.error(msg);
        throw new RuntimeException("S3ChangeLogStore: " + msg);
    }

    class ObjectS3Thread implements Runnable {

        String domainName;
        AmazonS3 s3;
        HashMap<String, SignedDomain> signedDomainMap;

        public ObjectS3Thread(String domainName, HashMap<String, SignedDomain> signedDomainMap, AmazonS3 s3) {
            this.domainName = domainName;
            this.s3 = s3;
            this.signedDomainMap = signedDomainMap;
        }

        @Override
        public void run() {
            SignedDomain signedDomain = null;
            try {
                S3Object object = s3.getObject(s3BucketName, domainName);
                try (S3ObjectInputStream s3is = object.getObjectContent()) {
                    signedDomain = jsonMapper.readValue(s3is, SignedDomain.class);
                }
            } catch (Exception ex) {
                LOGGER.error("AWSS3ChangeLogThread: ObjectS3Thread- getSignedDomain - unable to get domain {} error: {}",
                        domainName, ex.getMessage());
            }
            if (signedDomain != null) {
                signedDomainMap.put(domainName, signedDomain);
            }
        }
    }
}
