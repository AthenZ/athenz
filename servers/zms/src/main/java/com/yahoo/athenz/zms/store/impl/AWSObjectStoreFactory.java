/*
 * Copyright 2017 Yahoo Holdings, Inc.
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
package com.yahoo.athenz.zms.store.impl;

import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.auth.InstanceProfileCredentialsProvider;
import com.amazonaws.services.rds.auth.GetIamAuthTokenRequest;
import com.amazonaws.services.rds.auth.RdsIamAuthTokenGenerator;
import com.amazonaws.util.EC2MetadataUtils;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.db.DataSourceFactory;
import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.zms.ZMSConsts;
import com.yahoo.athenz.zms.store.ObjectStore;
import com.yahoo.athenz.zms.store.ObjectStoreFactory;
import com.yahoo.athenz.zms.store.impl.jdbc.JDBCObjectStore;

public class AWSObjectStoreFactory implements ObjectStoreFactory {

    private static final Logger LOG = LoggerFactory.getLogger(AWSObjectStoreFactory.class);
    
    private static Properties mysqlMasterConnectionProperties = new Properties();
    private static Properties mysqlReplicaConnectionProperties = new Properties();
    @SuppressWarnings("FieldCanBeLocal")
    private static ScheduledExecutorService scheduledThreadPool;
    private static String rdsUser = null;
    private static String rdsIamRole = null;
    private static String rdsMaster = null;
    private static String rdsReplica = null;
    private int rdsPort = 3306;
    
    @Override
    public ObjectStore create(PrivateKeyStore keyStore) {
        
        rdsUser = System.getProperty(ZMSConsts.ZMS_PROP_AWS_RDS_USER);
        rdsIamRole = System.getProperty(ZMSConsts.ZMS_PROP_AWS_RDS_IAM_ROLE);
        rdsMaster = System.getProperty(ZMSConsts.ZMS_PROP_AWS_RDS_MASTER_INSTANCE);
        rdsReplica = System.getProperty(ZMSConsts.ZMS_PROP_AWS_RDS_REPLICA_INSTANCE);
        rdsPort = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_AWS_RDS_MASTER_PORT, "3306"));
        
        final String rdsEngine = System.getProperty(ZMSConsts.ZMS_PROP_AWS_RDS_ENGINE, "mysql");
        final String rdsDatabase = System.getProperty(ZMSConsts.ZMS_PROP_AWS_RDS_DATABASE, "zms_store");
        final String jdbcMasterStore = String.format("jdbc:%s://%s:%d/%s", rdsEngine,
                rdsMaster, rdsPort, rdsDatabase);
        final String rdsMasterToken = getAuthToken(rdsMaster, rdsPort, rdsUser, rdsIamRole);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Connecting to master {} with auth token {}", jdbcMasterStore, rdsMasterToken);
        }
        
        mysqlMasterConnectionProperties.setProperty(ZMSConsts.DB_PROP_VERIFY_SERVER_CERT,
                System.getProperty(ZMSConsts.ZMS_PROP_JDBC_VERIFY_SERVER_CERT, "true"));
        mysqlMasterConnectionProperties.setProperty(ZMSConsts.DB_PROP_USE_SSL,
                System.getProperty(ZMSConsts.ZMS_PROP_JDBC_USE_SSL, "true"));
        mysqlMasterConnectionProperties.setProperty(ZMSConsts.DB_PROP_USER, rdsUser);
        mysqlMasterConnectionProperties.setProperty(ZMSConsts.DB_PROP_PASSWORD, rdsMasterToken);
        
        PoolableDataSource dataMasterSource = DataSourceFactory.create(jdbcMasterStore, mysqlMasterConnectionProperties);
        
        // now check to see if we also have a read-only replica jdbc store configured

        PoolableDataSource dataReplicaSource = null;
        if (rdsReplica != null) {
            
            final String jdbcReplicaStore = String.format("jdbc:%s://%s:%d/%s", rdsEngine,
                    rdsReplica, rdsPort, rdsDatabase);
            final String rdsReplicaToken = getAuthToken(rdsReplica, rdsPort, rdsUser, rdsIamRole);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("Connecting to replica {} with auth token {}", jdbcReplicaStore, rdsReplicaToken);
            }
            
            mysqlReplicaConnectionProperties.setProperty(ZMSConsts.DB_PROP_VERIFY_SERVER_CERT,
                    System.getProperty(ZMSConsts.ZMS_PROP_JDBC_VERIFY_SERVER_CERT, "true"));
            mysqlReplicaConnectionProperties.setProperty(ZMSConsts.DB_PROP_USE_SSL,
                    System.getProperty(ZMSConsts.ZMS_PROP_JDBC_USE_SSL, "true"));
            mysqlReplicaConnectionProperties.setProperty(ZMSConsts.DB_PROP_USER, rdsUser);
            mysqlReplicaConnectionProperties.setProperty(ZMSConsts.DB_PROP_PASSWORD, rdsReplicaToken);
            
            dataReplicaSource = DataSourceFactory.create(jdbcReplicaStore, mysqlReplicaConnectionProperties);
        }
        
        // start our credentials refresh task
        
        long credsRefreshTime = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "300"));

        scheduledThreadPool = Executors.newScheduledThreadPool(1);
        scheduledThreadPool.scheduleAtFixedRate(new CredentialsUpdater(), credsRefreshTime,
                credsRefreshTime, TimeUnit.SECONDS);
        
        return new JDBCObjectStore(dataMasterSource, dataReplicaSource);
    }

    InstanceProfileCredentialsProvider getNewInstanceCredentialsProvider() {
        return new InstanceProfileCredentialsProvider(true);
    }

    String getRegion() {
        return EC2MetadataUtils.getEC2InstanceRegion();
    }

    String getGeneratorAuthToken(RdsIamAuthTokenGenerator generator, final String hostname,
                                 int port, final String rdsUser) {
        return generator.getAuthToken(GetIamAuthTokenRequest.builder()
                .hostname(hostname).port(port).userName(rdsUser)
                .build());
    }

    String getAuthToken(String hostname, int port, String rdsUser, String rdsIamRole) {

        InstanceProfileCredentialsProvider awsCredProvider = getNewInstanceCredentialsProvider();
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("getAuthToken: Access key id: {}", awsCredProvider.getCredentials().getAWSAccessKeyId());
        }

        RdsIamAuthTokenGenerator generator = RdsIamAuthTokenGenerator.builder()
                .credentials(awsCredProvider)
                .region(getRegion())
                .build();
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Instance {} Port {} User {} Region: {} Role: {}", hostname, port, rdsUser,
                    getRegion(), rdsIamRole);
        }
        
        return getGeneratorAuthToken(generator, hostname, port, rdsUser);
    }
    
    void updateCredentials(String hostname, Properties mysqlProperties) {
        
        // if we have no hostname specified then we have nothing to do
        
        if (hostname == null) {
            return;
        }
        
        // obtain iam role credentials and update the properties object
        
        try {
            final String rdsToken = getAuthToken(hostname, rdsPort, rdsUser, rdsIamRole);
            mysqlProperties.setProperty(ZMSConsts.DB_PROP_PASSWORD, rdsToken);
        } catch (Throwable t) {
            LOG.error("CredentialsUpdater: unable to update auth token: " + t.getMessage());
        }
    }
    
    class CredentialsUpdater implements Runnable {
        
        @Override
        public void run() {

            if (LOG.isDebugEnabled()) {
                LOG.debug("CredentialsUpdater: Starting credential updater thread...");
            }
            
            updateCredentials(rdsMaster, mysqlMasterConnectionProperties);
            updateCredentials(rdsReplica, mysqlReplicaConnectionProperties);
        }
    }
}
