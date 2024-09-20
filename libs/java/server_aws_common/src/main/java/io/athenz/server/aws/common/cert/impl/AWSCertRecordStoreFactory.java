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
package io.athenz.server.aws.common.cert.impl;

import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.yahoo.athenz.common.ServerCommonConsts;
import com.yahoo.athenz.common.server.cert.CertRecordStore;
import com.yahoo.athenz.common.server.cert.CertRecordStoreFactory;
import com.yahoo.athenz.common.server.cert.impl.JDBCCertRecordStore;
import io.athenz.server.aws.common.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.db.DataSourceFactory;
import com.yahoo.athenz.common.server.db.PoolableDataSource;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.rds.RdsClient;
import software.amazon.awssdk.services.rds.RdsUtilities;
import software.amazon.awssdk.services.rds.model.GenerateAuthenticationTokenRequest;

public class AWSCertRecordStoreFactory implements CertRecordStoreFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(AWSCertRecordStoreFactory.class);

    public static final String ZTS_PROP_AWS_RDS_USER               = "athenz.zts.aws_rds_user";
    public static final String ZTS_PROP_AWS_RDS_ENGINE             = "athenz.zts.aws_rds_engine";
    public static final String ZTS_PROP_AWS_RDS_DATABASE           = "athenz.zts.aws_rds_database";
    public static final String ZTS_PROP_AWS_RDS_PRIMARY_INSTANCE   = "athenz.zts.aws_rds_master_instance";
    public static final String ZTS_PROP_AWS_RDS_PRIMARY_PORT       = "athenz.zts.aws_rds_master_port";
    public static final String ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME = "athenz.zts.aws_rds_creds_refresh_time";

    private static Properties mysqlConnectionProperties = new Properties();
    private static String rdsUser = null;
    private static String rdsPrimary = null;
    private int rdsPort = 3306;
    
    @Override
    public CertRecordStore create(PrivateKeyStore keyStore) {
        
        rdsUser = System.getProperty(ZTS_PROP_AWS_RDS_USER);
        rdsPrimary = System.getProperty(ZTS_PROP_AWS_RDS_PRIMARY_INSTANCE);
        rdsPort = Integer.parseInt(System.getProperty(ZTS_PROP_AWS_RDS_PRIMARY_PORT, "3306"));
        
        final String rdsEngine = System.getProperty(ZTS_PROP_AWS_RDS_ENGINE, "mysql");
        final String rdsDatabase = System.getProperty(ZTS_PROP_AWS_RDS_DATABASE, "zts_store");

        final String jdbcStore = String.format("jdbc:%s://%s:%d/%s", rdsEngine, rdsPrimary, rdsPort, rdsDatabase);
        String rdsToken = getAuthToken(rdsPrimary, rdsPort, rdsUser);
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Connecting to {} with auth token {}", jdbcStore, rdsToken);
        }

        mysqlConnectionProperties.setProperty(ServerCommonConsts.DB_PROP_VERIFY_SERVER_CERT,
                System.getProperty(ServerCommonConsts.DB_PROP_VERIFY_SERVER_CERT, "true"));
        mysqlConnectionProperties.setProperty(ServerCommonConsts.DB_PROP_USE_SSL,
                System.getProperty(ServerCommonConsts.DB_PROP_USE_SSL, "true"));
        mysqlConnectionProperties.setProperty(ServerCommonConsts.DB_PROP_USER, rdsUser);
        mysqlConnectionProperties.setProperty(ServerCommonConsts.DB_PROP_PASSWORD, rdsToken);
        
        PoolableDataSource dataSource = DataSourceFactory.create(jdbcStore, mysqlConnectionProperties);
        
        long credsRefreshTime = Integer.parseInt(System.getProperty(ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "300"));

        ScheduledExecutorService scheduledThreadPool = Executors.newScheduledThreadPool(1);
        scheduledThreadPool.scheduleAtFixedRate(new CredentialsUpdater(), credsRefreshTime,
                credsRefreshTime, TimeUnit.SECONDS);
        
        return new JDBCCertRecordStore(dataSource);
    }

    String getAuthToken(String hostname, int port, String rdsUser) {

        String authToken = null;
        try (RdsClient rdsClient = RdsClient.builder().region(Utils.getAwsRegion((Region.US_EAST_1)))
                .credentialsProvider(ProfileCredentialsProvider.create()).build()) {

            RdsUtilities utilities = rdsClient.utilities();

            GenerateAuthenticationTokenRequest tokenRequest = GenerateAuthenticationTokenRequest.builder()
                    .credentialsProvider(ProfileCredentialsProvider.create())
                    .username(rdsUser)
                    .port(port)
                    .hostname(hostname)
                    .build();

            authToken = utilities.generateAuthenticationToken(tokenRequest);

        } catch (Exception ex) {
            LOGGER.error("getAuthToken: unable to generate auth token", ex);
        }

        return authToken;
    }

    class CredentialsUpdater implements Runnable {
        
        @Override
        public void run() {

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("CredentialsUpdater: Starting credential updater thread...");
            }
            
            try {
                final String rdsToken = getAuthToken(rdsPrimary, rdsPort, rdsUser);
                mysqlConnectionProperties.setProperty(ServerCommonConsts.DB_PROP_PASSWORD, rdsToken);
                
            } catch (Throwable t) {
                LOGGER.error("CredentialsUpdater: unable to update auth token: {}", t.getMessage());
            }
        }
    }
}
