/*
 * Copyright 2017 Yahoo Holdings Inc.
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
package com.yahoo.athenz.zts;

import java.io.Closeable;
import java.io.IOException;
import javax.net.ssl.SSLContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;

public class AWSCredentialsProviderImpl implements AWSCredentialsProvider, Closeable {
    
    private static final Logger LOG = LoggerFactory.getLogger(AWSCredentialsProviderImpl.class);
    
    private String domainName;
    private String roleName;
    private String externalId;
    private Integer minExpiryTime;
    private Integer maxExpiryTime;
    private ZTSClient ztsClient;
    private volatile AWSCredentials credentials;
    private boolean closeZTSClient;

    /**
     * Constructs a new AWSCredentialsProvider object with the given zts client object,
     * Athenz domain name and AWS Role Name to retrieve temporary credentials for.
     * @param ztsClient ZTS Client object
     * @param domainName name of the Athenz domain
     * @param roleName is the name of the IAM role
     */
    public AWSCredentialsProviderImpl(ZTSClient ztsClient, String domainName, String roleName) {
        this(ztsClient, domainName, roleName, null, null, null);
    }

    /**
     * Constructs a new AWSCredentialsProvider object with the given zts client object,
     * Athenz domain name and AWS Role Name to retrieve temporary credentials for.
     * @param ztsClient ZTS Client object
     * @param domainName name of the Athenz domain
     * @param roleName is the name of the IAM role
     * @param minExpiryTime (optional) specifies that the returned creds must be
     *          at least valid (min/lower bound) for specified number of seconds,
     * @param maxExpiryTime (optional) specifies that the returned creds must be
     *          at most valid (max/upper bound) for specified number of seconds.
     * @param externalId (optional) external id to satisfy configured assume role condition
     */
    public AWSCredentialsProviderImpl(ZTSClient ztsClient, String domainName, String roleName,
            String externalId, Integer minExpiryTime, Integer maxExpiryTime) {
        this.domainName = domainName;
        this.roleName = roleName;
        this.minExpiryTime = minExpiryTime;
        this.maxExpiryTime = maxExpiryTime;
        this.externalId = externalId;
        this.ztsClient = ztsClient;
        this.closeZTSClient = false;
    }

    /**
     * Constructs a new AWSCredentialsProvider object with the given SSLContext object,
     * ZTS Server Url, Athenz domain name and AWS Role Name to retrieve temporary
     * credentials for. The constructor will automatically create and use the ZTS
     * client object for retrieving credentials. This object must be closed so
     * the ZTS client object is closed as well.
     * @param ztsUrl ZTS Server's URL
     * @param sslContext SSLContext that includes service's private key and x.509 certificate
     * for authenticating requests
     * @param domainName name of the Athenz domain
     * @param roleName is the name of the IAM role
     * @param minExpiryTime (optional) specifies that the returned creds must be
     *          at least valid (min/lower bound) for specified number of seconds,
     * @param maxExpiryTime (optional) specifies that the returned creds must be
     *          at most valid (max/upper bound) for specified number of seconds.
     * @param externalId (optional) external id to satisfy configured assume role condition
     */
    public AWSCredentialsProviderImpl(String ztsUrl, SSLContext sslContext,
            String domainName, String roleName, String externalId,
            Integer minExpiryTime, Integer maxExpiryTime) {
        this(null, domainName, roleName, externalId, minExpiryTime, maxExpiryTime);
        this.ztsClient = new ZTSClient(ztsUrl, sslContext);
        this.closeZTSClient = true;
    }

    /**
     * Constructs a new AWSCredentialsProvider object with the given SSLContext object,
     * ZTS Server Url, Athenz domain name and AWS Role Name to retrieve temporary
     * credentials for. The constructor will automatically create and use the ZTS
     * client object for retrieving credentials. This object must be closed so
     * the ZTS client object is closed as well.
     * @param ztsUrl ZTS Server's URL
     * @param sslContext SSLContext that includes service's private key and x.509 certificate
     * for authenticating requests
     * @param domainName name of the domain
     * @param roleName is the name of the role
     */
    public AWSCredentialsProviderImpl(String ztsUrl, SSLContext sslContext,
            String domainName, String roleName) {
        this(ztsUrl, sslContext, domainName, roleName, null, null, null);
    }

    @Override
    public void close() throws IOException {
        if (closeZTSClient) {
            ztsClient.close();
        }
    }
    
    @Override
    public AWSCredentials getCredentials() {
        
        // we are going to first refresh our credentials object.
        // for initial request this will fetch the credentials
        // while for others it will check if it exists in the cache
        // and only fetch if it's about to expire
        
        refresh();
        return credentials;
    }

    @Override
    public void refresh() {
        try {
            AWSTemporaryCredentials creds = ztsClient.getAWSTemporaryCredentials(domainName, roleName,
                    externalId, minExpiryTime, maxExpiryTime);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Refresh: Credentials with id: {} and expiration {} were fetched",
                        creds.getAccessKeyId(), creds.getExpiration());
            }

            this.credentials = new BasicSessionCredentials(
                    creds.getAccessKeyId(),
                    creds.getSecretAccessKey(),
                    creds.getSessionToken());

        } catch (ZTSClientException ex) {
            credentials = null;
            LOG.error("Refresh: Failed to get the AWS temporary credentials from ZTS: {}",
                    ex.getMessage());
        } catch (Exception ex) {
            credentials = null;
            LOG.error("Refresh: Failed to refresh credentials: {}", ex.getMessage());
        }
    }
}
