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
            AWSTemporaryCredentials creds = ztsClt.getAWSTemporaryCredentials(athensSvcDomain, athensDomRole);
            if (LOG.isDebugEnabled()) {
                LOG.debug("AWSCredentialsProviderImpl:refresh: Credentials with id: \"" + creds.accessKeyId + "\" were fetched");
            }

            this.credentials = new BasicSessionCredentials(
                    creds.getAccessKeyId(),
                    creds.getSecretAccessKey(),
                    creds.getSessionToken());
        } catch (ZTSClientException exp) {
            this.credentials = null;
            LOG.error("AWSCredentialsProviderImpl:refresh: Failed to get the AWS temporary credentials from ZTS. Status: " + exp.getCode() + "Error" + exp.getData());
        } catch (Exception exp) {
            this.credentials = null;
            LOG.error("AWSCredentialsProviderImpl:refresh: Failed to refresh credentials . Error: " + exp.getMessage());
        }
    }
}
