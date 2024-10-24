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
package io.athenz.server.aws.common.store.impl;

import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import io.athenz.server.aws.common.utils.Utils;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.rds.RdsClient;
import software.amazon.awssdk.services.rds.RdsUtilities;
import software.amazon.awssdk.services.rds.model.GenerateAuthenticationTokenRequest;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.db.DataSourceFactory;
import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.common.server.store.ObjectStore;
import com.yahoo.athenz.common.server.store.ObjectStoreFactory;
import com.yahoo.athenz.common.server.store.impl.JDBCObjectStore;

public class AWSObjectStoreFactory implements ObjectStoreFactory {

    private static final Logger LOG = LoggerFactory.getLogger(AWSObjectStoreFactory.class);

    public static final String ZMS_PROP_JDBC_VERIFY_SERVER_CERT = "athenz.zms.jdbc_verify_server_certificate";
    public static final String ZMS_PROP_JDBC_USE_SSL            = "athenz.zms.jdbc_use_ssl";
    public static final String ZMS_PROP_JDBC_TLS_VERSIONS       = "athenz.zms.jdbc_tls_versions";

    public static final String ZMS_PROP_AWS_RDS_USER               = "athenz.zms.aws_rds_user";
    public static final String ZMS_PROP_AWS_RDS_ENGINE             = "athenz.zms.aws_rds_engine";
    public static final String ZMS_PROP_AWS_RDS_DATABASE           = "athenz.zms.aws_rds_database";
    public static final String ZMS_PROP_AWS_RDS_PRIMARY_INSTANCE   = "athenz.zms.aws_rds_master_instance";
    public static final String ZMS_PROP_AWS_RDS_PRIMARY_PORT       = "athenz.zms.aws_rds_master_port";
    public static final String ZMS_PROP_AWS_RDS_REPLICA_INSTANCE   = "athenz.zms.aws_rds_replica_instance";
    public static final String ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME = "athenz.zms.aws_rds_creds_refresh_time";

    public static final String DB_PROP_USER               = "user";
    public static final String DB_PROP_PASSWORD           = "password";
    public static final String DB_PROP_USE_SSL            = "useSSL";
    public static final String DB_PROP_VERIFY_SERVER_CERT = "verifyServerCertificate";
    public static final String DB_PROP_TLS_PROTOCOLS      = "enabledTLSProtocols";

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
        
        rdsUser = System.getProperty(ZMS_PROP_AWS_RDS_USER);
        rdsPrimary = System.getProperty(ZMS_PROP_AWS_RDS_PRIMARY_INSTANCE);
        rdsReplica = System.getProperty(ZMS_PROP_AWS_RDS_REPLICA_INSTANCE);
        rdsPort = Integer.parseInt(System.getProperty(ZMS_PROP_AWS_RDS_PRIMARY_PORT, "3306"));
        
        final String rdsEngine = System.getProperty(ZMS_PROP_AWS_RDS_ENGINE, "mysql");
        final String rdsDatabase = System.getProperty(ZMS_PROP_AWS_RDS_DATABASE, "zms_server");
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
        
        long credsRefreshTime = Integer.parseInt(System.getProperty(ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "300"));

        scheduledThreadPool = Executors.newScheduledThreadPool(1);
        scheduledThreadPool.scheduleAtFixedRate(new CredentialsUpdater(), credsRefreshTime,
                credsRefreshTime, TimeUnit.SECONDS);
        
        return new JDBCObjectStore(dataPrimarySource, dataReplicaSource);
    }

    public void stop() {
        scheduledThreadPool.shutdownNow();
    }

    void setConnectionProperties(Properties mysqlProperties, final String token) {
        mysqlProperties.setProperty(DB_PROP_VERIFY_SERVER_CERT,
                System.getProperty(ZMS_PROP_JDBC_VERIFY_SERVER_CERT, "true"));
        mysqlProperties.setProperty(DB_PROP_USE_SSL,
                System.getProperty(ZMS_PROP_JDBC_USE_SSL, "true"));
        mysqlProperties.setProperty(DB_PROP_TLS_PROTOCOLS,
                System.getProperty(ZMS_PROP_JDBC_TLS_VERSIONS, JDBC_TLS_VERSIONS));
        mysqlProperties.setProperty(DB_PROP_USER, rdsUser);
        mysqlProperties.setProperty(DB_PROP_PASSWORD, token);
    }

    Region getRegion() {
        return Utils.getAwsRegion(Region.US_EAST_1);
    }

    String getAuthToken(String hostname, int port, String rdsUser) {

        String authToken = null;
        try (RdsClient rdsClient = RdsClient.builder().region(getRegion())
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
            LOG.error("getAuthToken: unable to generate auth token", ex);
        }

        return authToken;
    }

    void updateCredentials(String hostname, Properties mysqlProperties) {
        
        // if we have no hostname specified then we have nothing to do
        
        if (hostname == null) {
            return;
        }
        
        // obtain iam role credentials and update the properties object

        final String rdsToken = getAuthToken(hostname, rdsPort, rdsUser);
        if (!StringUtil.isEmpty(rdsToken)) {
            mysqlProperties.setProperty(DB_PROP_PASSWORD, rdsToken);
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
