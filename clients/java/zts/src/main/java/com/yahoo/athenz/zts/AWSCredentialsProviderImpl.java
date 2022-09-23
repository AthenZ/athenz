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
package com.yahoo.athenz.zts;

import java.io.Closeable;
import java.io.IOException;
import javax.net.ssl.SSLContext;

import com.yahoo.rdl.Timestamp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;

public class AWSCredentialsProviderImpl implements AWSCredentialsProvider, Closeable {
    
    private static final Logger LOG = LoggerFactory.getLogger(AWSCredentialsProviderImpl.class);

    private static final String ZTS_CLIENT_PROP_AWS_AUTO_REFRESH_ENABLE = "athenz.zts.client.aws_auto_refresh_enable";
    private static boolean awsAutoRefreshEnable = Boolean.parseBoolean(
            System.getProperty(ZTS_CLIENT_PROP_AWS_AUTO_REFRESH_ENABLE, "true"));

    private String domainName;
    private String roleName;
    private String externalId;
    private Integer minExpiryTime;
    private Integer maxExpiryTime;
    private ZTSClient ztsClient;
    private Timestamp awsCredsTimestamp;
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

        initCredProvider(ztsClient, false, domainName, roleName, null,
                null, null);
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

        initCredProvider(ztsClient, false, domainName, roleName, externalId,
                minExpiryTime, maxExpiryTime);
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

        initCredProvider(new ZTSClient(ztsUrl, sslContext), true, domainName, roleName,
                externalId, minExpiryTime, maxExpiryTime);
    }

    public AWSCredentialsProviderImpl(String ztsUrl, SSLContext sslContext,
            String domainName, String roleName, String externalId,
            Integer minExpiryTime, Integer maxExpiryTime,
            ZTSClientNotificationSender ztsClientNotificationSender) {

        ZTSClient client = new ZTSClient(ztsUrl, sslContext);
        client.setNotificationSender(ztsClientNotificationSender);
        initCredProvider(client, true, domainName, roleName,
                externalId, minExpiryTime, maxExpiryTime);
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

        initCredProvider(new ZTSClient(ztsUrl, sslContext), true, domainName, roleName, null, null, null);
    }

    private void initCredProvider(ZTSClient ztsClient, boolean closeZTSClient,
            String domainName, String roleName, String externalId,
            Integer minExpiryTime, Integer maxExpiryTime) {

        this.domainName = domainName;
        this.roleName = roleName;
        this.minExpiryTime = minExpiryTime;
        this.maxExpiryTime = maxExpiryTime;
        this.externalId = externalId;
        this.ztsClient = ztsClient;
        this.closeZTSClient = closeZTSClient;
        this.awsCredsTimestamp = null;

        // unless the caller has disabled the refresh functionality
        // we're going to fetch the credentials so we have them in
        // the cache when the first request comes in

        if (awsAutoRefreshEnable) {
            refresh();
        }
    }

    /**
     * Configure whether or not to auto refresh the credentials when
     * the credentials provider object is created
     * @param state boolean state to enable call to refresh credentials
     */
    public static void setAwsAutoRefreshEnable(boolean state) {
        awsAutoRefreshEnable = state;
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

            awsCredsTimestamp = creds.getExpiration();
            this.credentials = new BasicSessionCredentials(
                    creds.getAccessKeyId(),
                    creds.getSecretAccessKey(),
                    creds.getSessionToken());

        } catch (Exception ex) {

            // if our existing credentials have already expired then
            // we should reset it to null and throw an exception back
            // to the client so it knows something is wrong

            if (awsCredsTimestamp != null && awsCredsTimestamp.millis() <= System.currentTimeMillis()) {
                awsCredsTimestamp = null;
                credentials = null;
            }

            // if we have no credentials then we'll throw an exception
            // otherwise we'll just log it

            LOG.error("Refresh: Failed to get the AWS temporary credentials from ZTS", ex);
            if (credentials == null) {
                throw ex;
            }
        }
    }
}
