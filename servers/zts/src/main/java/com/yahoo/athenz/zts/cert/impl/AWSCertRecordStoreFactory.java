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
package com.yahoo.athenz.zts.cert.impl;

import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.yahoo.athenz.common.server.cert.CertRecordStore;
import com.yahoo.athenz.common.server.cert.CertRecordStoreFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.auth.InstanceProfileCredentialsProvider;
import com.amazonaws.services.rds.auth.GetIamAuthTokenRequest;
import com.amazonaws.services.rds.auth.RdsIamAuthTokenGenerator;
import com.amazonaws.util.EC2MetadataUtils;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.db.DataSourceFactory;
import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.zts.ZTSConsts;

public class AWSCertRecordStoreFactory implements CertRecordStoreFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(AWSCertRecordStoreFactory.class);
    
    private static Properties mysqlConnectionProperties = new Properties();
    private static String rdsUser = null;
    private static String rdsIamRole = null;
    private static String rdsMaster = null;
    private int rdsPort = 3306;
    
    @Override
    public CertRecordStore create(PrivateKeyStore keyStore) {
        
        rdsUser = System.getProperty(ZTSConsts.ZTS_PROP_AWS_RDS_USER);
        rdsIamRole = System.getProperty(ZTSConsts.ZTS_PROP_AWS_RDS_IAM_ROLE);
        rdsMaster = System.getProperty(ZTSConsts.ZTS_PROP_AWS_RDS_MASTER_INSTANCE);
        rdsPort = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_AWS_RDS_MASTER_PORT, "3306"));
        
        final String rdsEngine = System.getProperty(ZTSConsts.ZTS_PROP_AWS_RDS_ENGINE, "mysql");
        final String rdsDatabase = System.getProperty(ZTSConsts.ZTS_PROP_AWS_RDS_DATABASE, "zts_store");

        final String jdbcStore = String.format("jdbc:%s://%s:%d/%s", rdsEngine, rdsMaster, rdsPort, rdsDatabase);
        String rdsToken = getAuthToken(rdsMaster, rdsPort, rdsUser, rdsIamRole);
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Connecting to {} with auth token {}", jdbcStore, rdsToken);
        }

        mysqlConnectionProperties.setProperty(ZTSConsts.DB_PROP_VERIFY_SERVER_CERT,
                System.getProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_VERIFY_SERVER_CERT, "true"));
        mysqlConnectionProperties.setProperty(ZTSConsts.DB_PROP_USE_SSL,
                System.getProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_USE_SSL, "true"));
        mysqlConnectionProperties.setProperty(ZTSConsts.DB_PROP_USER, rdsUser);
        mysqlConnectionProperties.setProperty(ZTSConsts.DB_PROP_PASSWORD, rdsToken);
        
        PoolableDataSource dataSource = DataSourceFactory.create(jdbcStore, mysqlConnectionProperties);
        
        long credsRefreshTime = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "300"));

        ScheduledExecutorService scheduledThreadPool = Executors.newScheduledThreadPool(1);
        scheduledThreadPool.scheduleAtFixedRate(new CredentialsUpdater(), credsRefreshTime,
                credsRefreshTime, TimeUnit.SECONDS);
        
        return new JDBCCertRecordStore(dataSource);
    }

    String getInstanceRegion() {
        return EC2MetadataUtils.getEC2InstanceRegion();
    }

    RdsIamAuthTokenGenerator getTokenGenerator(InstanceProfileCredentialsProvider awsCredProvider) {
        return RdsIamAuthTokenGenerator.builder()
                .credentials(awsCredProvider)
                .region(getInstanceRegion())
                .build();
    }

    String getAuthToken(String hostname, int port, String rdsUser, String rdsIamRole) {

        InstanceProfileCredentialsProvider awsCredProvider = new InstanceProfileCredentialsProvider(true);
        RdsIamAuthTokenGenerator generator = getTokenGenerator(awsCredProvider);
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Instance {} Port {} User {} Region: {} Role: {}", hostname, port, rdsUser,
                    getInstanceRegion(), rdsIamRole);
        }
        
        return generator.getAuthToken(GetIamAuthTokenRequest.builder()
               .hostname(hostname).port(port).userName(rdsUser)
               .build());
    }

    class CredentialsUpdater implements Runnable {
        
        @Override
        public void run() {

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("CredentialsUpdater: Starting credential updater thread...");
            }
            
            try {
                final String rdsToken = getAuthToken(rdsMaster, rdsPort, rdsUser, rdsIamRole);
                mysqlConnectionProperties.setProperty(ZTSConsts.DB_PROP_PASSWORD, rdsToken);
                
            } catch (Throwable t) {
                LOGGER.error("CredentialsUpdater: unable to update auth token: {}", t.getMessage());
            }
        }
    }
}
