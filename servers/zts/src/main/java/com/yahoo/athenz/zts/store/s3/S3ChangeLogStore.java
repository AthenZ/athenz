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
package com.yahoo.athenz.zts.store.s3;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.ListObjectsRequest;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zms.SignedDomains;
import com.yahoo.athenz.zts.store.ChangeLogStore;
import com.yahoo.athenz.zts.store.CloudStore;
import com.yahoo.rdl.JSON;

public class S3ChangeLogStore implements ChangeLogStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(S3ChangeLogStore.class);
    private static final String ZTS_PROP_BUCKET_NAME = "athenz.zts.aws_bucket_name";
    private static final String ZTS_BUCKET_DEFAULT = "athenz-domain-sys.auth";

    long lastModTime = 0;
    CloudStore cloudStore = null;
    String s3BucketName = null;
    
    public S3ChangeLogStore(CloudStore cloudStore) {
        this.cloudStore = cloudStore;
        s3BucketName = System.getProperty(ZTS_PROP_BUCKET_NAME, ZTS_BUCKET_DEFAULT);
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("AWSS3ChangeLog: S3 Bucket name: " + s3BucketName);
        }
    }

    @Override
    public boolean supportsFullRefresh() {
        return false;
    }
    
    @Override
    public SignedDomain getSignedDomain(String domainName) {
        AmazonS3 s3 = getS3Client();
        return getSignedDomain(s3, domainName);
    }
    
    SignedDomain getSignedDomain(AmazonS3 s3, String domainName) {

        SignedDomain signedDomain = null;
        try {
            S3Object object = s3.getObject(new GetObjectRequest(s3BucketName, domainName));
            if (object == null) {
                LOGGER.error("AWSS3ChangeLog: getSignedDomain - domain not found " + domainName);
                return null;
            }
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(object.getObjectContent()));
            StringBuilder data = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                data.append(line);
            }
            reader.close();
            signedDomain = JSON.fromString(data.toString(), SignedDomain.class);
        } catch (Exception ex) {
            LOGGER.error("AWSS3ChangeLog: getSignedDomain - unable to get domain " + domainName +
                    " error: " + ex.getMessage());
        }
        return signedDomain;
    }
    
    @Override
    public void removeLocalDomain(String domainName) {
        
        // in AWS our Athenz syncer is responsible for pushing new
        // changes including removing deleted domain to S3 so this
        // api is just a no-op
        
        return;
    }

    @Override
    public void saveLocalDomain(String domainName, SignedDomain signedDomain) {
        
        // in AWS our Athenz syncer is responsible for pushing new
        // changes into S3 so this api is just a no-op
        
        return;
    }

    /**
     * list the objects in the zts bucket. If te mod time is specified as 0
     * then we want to list all objects otherwise, we only list objects
     * that are newer than the specified timestamp
     * @param s3 AWS S3 client object
     * @param domains collection to be updated to include domain names
     * @param modTime only include domains newer than this timestamp
     */
    void listObjects(AmazonS3 s3, Collection<String> domains, long modTime) {
        
        ObjectListing objectListing = s3.listObjects(new ListObjectsRequest()
                .withBucketName(s3BucketName));
        
        String objectName = null;
        while (objectListing != null) {
            
            // process each entry in our result set and add the domain
            // name to our return list

            for (S3ObjectSummary objectSummary : objectListing.getObjectSummaries()) {
                
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
            
            if (!objectListing.isTruncated()) {
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
        
        ArrayList<String> domains = new ArrayList<>();
        listObjects(getS3Client(), domains, 0);
        return domains;
    }

    @Override
    public Set<String> getServerDomainList() {
        
        HashSet<String> domains = new HashSet<>();
        listObjects(getS3Client(), domains, 0);
        return domains;
    }

    @Override
    public SignedDomains getUpdatedSignedDomains(StringBuilder lastModTimeBuffer) {

        // We need save the timestamp at the beginning just in case we end up getting
        // paged results and while processing the last page, S3 gets pushed
        // updated domains from the earlier pages
        
        lastModTimeBuffer.append(System.currentTimeMillis());
        
        // AWS S3 API does not provide support for listing objects filtered
        // based on its last modification timestamp so we need to get
        // the full list and filter ourselves
        
        AmazonS3 s3 = getS3Client();
        ArrayList<String> domains = new ArrayList<>();
        listObjects(s3, domains, lastModTime);
        
        ArrayList<SignedDomain> signedDomainList = new ArrayList<>();
        SignedDomain signedDomain = null;
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
}
