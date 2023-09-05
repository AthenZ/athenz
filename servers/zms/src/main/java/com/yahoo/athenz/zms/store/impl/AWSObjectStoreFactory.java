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

    private static final String JDBC_TLS_VERSIONS = "TLSv1.2,TLSv1.3";

    private static final Properties MYSQL_PRIMARY_CONNECTION_PROPERTIES = new Properties();
    private static final Properties MYSQL_REPLICA_CONNECTION_PROPERTIES = new Properties();
    @SuppressWarnings("FieldCanBeLocal")
    private static ScheduledExecutorService scheduledThreadPool;
    private static String rdsUser = null;
    private static String rdsPrimary = null;
    private static String rdsReplica = null;
    private int rdsPort = 3306;
    
    @Override
    public ObjectStore create(PrivateKeyStore keyStore) {
        
        rdsUser = System.getProperty(ZMSConsts.ZMS_PROP_AWS_RDS_USER);
        rdsPrimary = System.getProperty(ZMSConsts.ZMS_PROP_AWS_RDS_PRIMARY_INSTANCE);
        rdsReplica = System.getProperty(ZMSConsts.ZMS_PROP_AWS_RDS_REPLICA_INSTANCE);
        rdsPort = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_AWS_RDS_PRIMARY_PORT, "3306"));
        
        final String rdsEngine = System.getProperty(ZMSConsts.ZMS_PROP_AWS_RDS_ENGINE, "mysql");
        final String rdsDatabase = System.getProperty(ZMSConsts.ZMS_PROP_AWS_RDS_DATABASE, "zms_server");
        final String jdbcPrimaryStore = String.format("jdbc:%s://%s:%d/%s", rdsEngine,
                rdsPrimary, rdsPort, rdsDatabase);
        final String rdsPrimaryToken = getAuthToken(rdsPrimary, rdsPort, rdsUser);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Connecting to primary {} with auth token {}", jdbcPrimaryStore, rdsPrimaryToken);
        }

        setConnectionProperties(MYSQL_PRIMARY_CONNECTION_PROPERTIES, rdsPrimaryToken);
        PoolableDataSource dataPrimarySource = DataSourceFactory.create(jdbcPrimaryStore, MYSQL_PRIMARY_CONNECTION_PROPERTIES);
        
        // now check to see if we also have a read-only replica jdbc store configured

        PoolableDataSource dataReplicaSource = null;
        if (rdsReplica != null) {
            
            final String jdbcReplicaStore = String.format("jdbc:%s://%s:%d/%s", rdsEngine,
                    rdsReplica, rdsPort, rdsDatabase);
            final String rdsReplicaToken = getAuthToken(rdsReplica, rdsPort, rdsUser);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("Connecting to replica {} with auth token {}", jdbcReplicaStore, rdsReplicaToken);
            }

            setConnectionProperties(MYSQL_REPLICA_CONNECTION_PROPERTIES, rdsReplicaToken);
            dataReplicaSource = DataSourceFactory.create(jdbcReplicaStore, MYSQL_REPLICA_CONNECTION_PROPERTIES);
        }
        
        // start our credentials refresh task
        
        long credsRefreshTime = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "300"));

        scheduledThreadPool = Executors.newScheduledThreadPool(1);
        scheduledThreadPool.scheduleAtFixedRate(new CredentialsUpdater(), credsRefreshTime,
                credsRefreshTime, TimeUnit.SECONDS);
        
        return new JDBCObjectStore(dataPrimarySource, dataReplicaSource);
    }

    void setConnectionProperties(Properties mysqlProperties, final String token) {
        mysqlProperties.setProperty(ZMSConsts.DB_PROP_VERIFY_SERVER_CERT,
                System.getProperty(ZMSConsts.ZMS_PROP_JDBC_VERIFY_SERVER_CERT, "true"));
        mysqlProperties.setProperty(ZMSConsts.DB_PROP_USE_SSL,
                System.getProperty(ZMSConsts.ZMS_PROP_JDBC_USE_SSL, "true"));
        mysqlProperties.setProperty(ZMSConsts.DB_PROP_TLS_PROTOCOLS,
                System.getProperty(ZMSConsts.ZMS_PROP_JDBC_TLS_VERSIONS, JDBC_TLS_VERSIONS));
        mysqlProperties.setProperty(ZMSConsts.DB_PROP_USER, rdsUser);
        mysqlProperties.setProperty(ZMSConsts.DB_PROP_PASSWORD, token);
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

    String getAuthToken(String hostname, int port, String rdsUser) {

        InstanceProfileCredentialsProvider awsCredProvider = getNewInstanceCredentialsProvider();
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("getAuthToken: Access key id: {}", awsCredProvider.getCredentials().getAWSAccessKeyId());
        }

        RdsIamAuthTokenGenerator generator = RdsIamAuthTokenGenerator.builder()
                .credentials(awsCredProvider)
                .region(getRegion())
                .build();
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Instance {} Port {} User {} Region: {}", hostname, port, rdsUser, getRegion());
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
            final String rdsToken = getAuthToken(hostname, rdsPort, rdsUser);
            mysqlProperties.setProperty(ZMSConsts.DB_PROP_PASSWORD, rdsToken);
        } catch (Exception ex) {
            LOG.error("CredentialsUpdater: unable to update auth token", ex);
        }
    }
    
    class CredentialsUpdater implements Runnable {
        
        @Override
        public void run() {

            if (LOG.isDebugEnabled()) {
                LOG.debug("CredentialsUpdater: Starting credential updater thread...");
            }
            
            updateCredentials(rdsPrimary, MYSQL_PRIMARY_CONNECTION_PROPERTIES);
            updateCredentials(rdsReplica, MYSQL_REPLICA_CONNECTION_PROPERTIES);
        }
    }
}
