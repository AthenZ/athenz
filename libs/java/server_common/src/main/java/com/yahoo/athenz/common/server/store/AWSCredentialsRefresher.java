/*
 *  Copyright 2020 Verizon Media
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

package com.yahoo.athenz.common.server.store;

import com.amazonaws.auth.AWSCredentials;
import com.yahoo.athenz.common.server.util.ConfigProperties;
import com.yahoo.athenz.zms.ResourceException;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.common.ServerCommonConsts.*;

public class AWSCredentialsRefresher implements Closeable {
    private static final Logger LOGGER = LoggerFactory.getLogger(AWSCredentialsRefresher.class);

    private AWSCredentials credentials;

    private String awsRegion;
    private AWSInstanceMetadataFetcher awsInstanceMetadataFetcher;
    private ScheduledExecutorService scheduledAwsCredService;

    public AWSCredentialsRefresher(AWSInstanceMetadataFetcher awsInstanceMetadataFetcher) {
        this.awsInstanceMetadataFetcher = awsInstanceMetadataFetcher;

        // check to see if we are given region name
        awsRegion = System.getProperty(ZTS_PROP_AWS_REGION_NAME);
        boolean shouldGetRegion = StringUtil.isEmpty(awsRegion);
        // initialize and load our bootstrap data
        if (!awsInstanceMetadataFetcher.loadBootMetaData(shouldGetRegion)) {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Unable to load boot data");
        }

        credentials = awsInstanceMetadataFetcher.fetchRoleCredentials();
        if (credentials == null)  {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Unable to fetch aws role credentials");
        }

        // Start our thread to get/update aws temporary credentials

        int credsUpdateTime = ConfigProperties.retrieveConfigSetting(
                ZTS_PROP_AWS_CREDS_UPDATE_TIMEOUT, ZTS_PROP_AWS_CREDS_UPDATE_TIMEOUT_DEFAULT);

        scheduledAwsCredService = Executors.newScheduledThreadPool(1);
        scheduledAwsCredService.scheduleAtFixedRate(new AWSCredentialsRefreshTask(), credsUpdateTime,
                credsUpdateTime, TimeUnit.SECONDS);
    }

    public AWSCredentialsRefresher() {
        this(new AWSInstanceMetadataFetcher());
    }

    public AWSCredentials getCredentials() {
        return credentials;
    }

    public String getAwsRegion() {
        return awsRegion;
    }

    class AWSCredentialsRefreshTask implements Runnable {

        @Override
        public void run() {

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("AWSCredentialsRefreshTask: Starting aws credentials updater task...");
            }

            try {
                credentials = awsInstanceMetadataFetcher.fetchRoleCredentials();
            } catch (Exception ex) {
                LOGGER.error("AWSCredentialsRefreshTask: unable to fetch aws role credentials: {}",
                        ex.getMessage());
            }
        }
    }

    @Override
    public void close() {
        if (scheduledAwsCredService != null) {
            scheduledAwsCredService.shutdownNow();
        }

        if (awsInstanceMetadataFetcher != null) {
        awsInstanceMetadataFetcher.close();
        }
    }
}
