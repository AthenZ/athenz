package com.yahoo.athenz.zts;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AWSCredentialsProviderImpl implements AWSCredentialsProvider {
    private static final Logger LOG = LoggerFactory.getLogger(AWSCredentialsProviderImpl.class);
    private static String athensSvcDomain = "";
    private static String athensDomRole = "";
    private volatile AWSCredentials credentials;
    private ZTSClient ztsClt;


    public AWSCredentialsProviderImpl(ZTSClient ztsClt, String athensSvcDomain, String athensDomRole) {
        this.ztsClt = ztsClt;
        this.athensDomRole = athensDomRole;
        this.athensSvcDomain = athensSvcDomain;
    }

    @Override
    public AWSCredentials getCredentials() {
        this.refresh();
        return this.credentials;
    }

    @Override
    public void refresh() {
        try {
            long start = System.currentTimeMillis();
            AWSTemporaryCredentials creds = ztsClt.getAWSTemporaryCredentials(athensSvcDomain, athensDomRole);
            LOG.debug("AWSCredentialsProviderImpl:refresh: Credentials with id: \"" + creds.accessKeyId + "\" were fetched");
            long end = System.currentTimeMillis();
            long credentialFetchingTime = (end - start);
            LOG.debug("AWSCredentialsProviderImpl:refresh: The Zts client took " + credentialFetchingTime + " milliseconds to fetch the credentials");
            this.credentials = new BasicSessionCredentials(
                    creds.getAccessKeyId(),
                    creds.getSecretAccessKey(),
                    creds.getSessionToken());
        } catch (Exception exp) {
            this.handleError(exp);
        }
    }

    private void handleError(Throwable t) {
        this.credentials = null;
        LOG.error("AWSCredentialsProviderImpl:refresh: Failed to get the AWS temporary credentials from ZTS. Error: " + t.getMessage(), t);
    }
}
