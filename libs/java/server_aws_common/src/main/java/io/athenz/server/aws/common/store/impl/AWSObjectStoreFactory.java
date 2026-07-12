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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import io.athenz.server.aws.common.utils.Utils;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.rds.RdsClient;
import software.amazon.awssdk.services.rds.RdsUtilities;
import software.amazon.awssdk.services.rds.model.GenerateAuthenticationTokenRequest;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.db.DataSourceFactory;
import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.common.server.db.SchemaMigrationRunner;
import com.yahoo.athenz.common.server.store.ObjectStore;
import com.yahoo.athenz.common.server.store.ObjectStoreFactory;
import com.yahoo.athenz.common.server.store.impl.JDBCConsts;
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
    /**
     * Comma-separated list of additional AWS regions to try signing IAM Auth tokens with.
     * If no additional regions are configured, only the local/default region will be used.
     */
    public static final String ZMS_PROP_AWS_RDS_CANDIDATE_REGIONS  = "athenz.zms.aws_rds_candidate_regions";

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
    private String rdsEngine;
    private String rdsDatabase;

    /**
     * Additionally configured AWS regions to try signing IAM Auth tokens with. Does not include the local/default region.
     */
    private List<Region> candidateRegions = Collections.emptyList();

    /**
     * Map of RDS hostname to the last region that successfully produced a working database connection.
     * In practice, one entry for the primary/writer instance and, if configured, one for the replica.
     * <p>
     * This is an optimization: without it, every credentials refresh could potentially retry regions that
     * fail, wasting a connection attempt every refresh cycle. Caching the region that last worked leans
     * on the fact that it is usually still the right one.
     */
    private final Map<String, Region> lastSuccessfulRegion = new ConcurrentHashMap<>();

    @Override
    public ObjectStore create(PrivateKeyStore keyStore) {

        rdsUser = System.getProperty(ZMS_PROP_AWS_RDS_USER);
        rdsPrimary = System.getProperty(ZMS_PROP_AWS_RDS_PRIMARY_INSTANCE);
        rdsReplica = System.getProperty(ZMS_PROP_AWS_RDS_REPLICA_INSTANCE);
        rdsPort = Integer.parseInt(System.getProperty(ZMS_PROP_AWS_RDS_PRIMARY_PORT, "3306"));
        candidateRegions = parseCandidateRegions(System.getProperty(ZMS_PROP_AWS_RDS_CANDIDATE_REGIONS));

        rdsEngine = System.getProperty(ZMS_PROP_AWS_RDS_ENGINE, "mysql");
        rdsDatabase = System.getProperty(ZMS_PROP_AWS_RDS_DATABASE, "zms_server");
        final String jdbcPrimaryStore = String.format("jdbc:%s://%s:%d/%s", rdsEngine,
                rdsPrimary, rdsPort, rdsDatabase);
        final String rdsPrimaryToken = getAuthTokenFromCandidateRegions(rdsPrimary, rdsPort, rdsUser);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Connecting to primary {} with auth token {}", jdbcPrimaryStore, rdsPrimaryToken);
        }

        setConnectionProperties(MYSQL_PRIMARY_CONNECTION_PROPERTIES, rdsPrimaryToken);
        PoolableDataSource dataPrimarySource = DataSourceFactory.create(jdbcPrimaryStore, MYSQL_PRIMARY_CONNECTION_PROPERTIES);

        SchemaMigrationRunner.migrateIfConfigured(dataPrimarySource,
                JDBCConsts.ZMS_PROP_JDBC_SCHEMA_MIGRATION_DIR, "athenz_schema_migration_zms");

        // now check to see if we also have a read-only replica jdbc store configured

        PoolableDataSource dataReplicaSource = null;
        if (rdsReplica != null) {

            final String jdbcReplicaStore = String.format("jdbc:%s://%s:%d/%s", rdsEngine,
                    rdsReplica, rdsPort, rdsDatabase);
            final String rdsReplicaToken = getAuthTokenFromCandidateRegions(rdsReplica, rdsPort, rdsUser);

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
        mysqlProperties.putAll(buildSslProperties());
        mysqlProperties.setProperty(DB_PROP_USER, rdsUser);
        mysqlProperties.setProperty(DB_PROP_PASSWORD, token);
    }

    Properties buildSslProperties() {
        Properties properties = new Properties();
        properties.setProperty(DB_PROP_VERIFY_SERVER_CERT,
                System.getProperty(ZMS_PROP_JDBC_VERIFY_SERVER_CERT, "true"));
        properties.setProperty(DB_PROP_USE_SSL,
                System.getProperty(ZMS_PROP_JDBC_USE_SSL, "true"));
        properties.setProperty(DB_PROP_TLS_PROTOCOLS,
                System.getProperty(ZMS_PROP_JDBC_TLS_VERSIONS, JDBC_TLS_VERSIONS));
        return properties;
    }

    Region getRegion() {
        return Utils.getAwsRegion(Region.US_EAST_1);
    }

    static List<Region> parseCandidateRegions(final String value) {

        if (StringUtil.isEmpty(value)) {
            return Collections.emptyList();
        }

        List<Region> regions = new ArrayList<>();
        for (String regionName : value.split(",")) {
            final String trimmedName = regionName.trim();
            if (!trimmedName.isEmpty()) {
                regions.add(Region.of(trimmedName));
            }
        }
        return regions;
    }

    String buildJdbcUrl(String hostname, int port) {
        return String.format("jdbc:%s://%s:%d/%s", rdsEngine, hostname, port, rdsDatabase);
    }

    String getAuthToken(String hostname, int port, String rdsUser) {
        return getAuthToken(hostname, port, rdsUser, getRegion());
    }

    String getAuthToken(String hostname, int port, String rdsUser, Region region) {

        String authToken = null;
        try (RdsClient rdsClient = RdsClient.builder().region(region)
                    .credentialsProvider(DefaultCredentialsProvider.create()).build()) {

            RdsUtilities utilities = rdsClient.utilities();

            GenerateAuthenticationTokenRequest tokenRequest = GenerateAuthenticationTokenRequest.builder()
                    .credentialsProvider(DefaultCredentialsProvider.create())
                    .username(rdsUser)
                    .port(port)
                    .hostname(hostname)
                    .build();

            authToken = utilities.generateAuthenticationToken(tokenRequest);

        } catch (Exception ex) {
            LOG.error("getAuthToken: unable to generate auth token for region {}", region, ex);
        }

        return authToken;
    }

    /**
     * Generates an RDS IAM auth token for the given host by trying, in order: the
     * last region known to work, the local/default region, and any additionally
     * configured candidate signing regions - verifying each with a real trial
     * connection until one succeeds. The local/default region is always part of
     * the candidate set. If no additional candidate regions are configured, this
     * is equivalent to a plain getAuthToken() call against the default region only.
     */
    String getAuthTokenFromCandidateRegions(String hostname, int port, String rdsUser) {

        if (hostname == null) {
            return null;
        }

        // if no additional candidate regions are configured, just use the default region
        if (candidateRegions.isEmpty()) {
            return getAuthToken(hostname, port, rdsUser);
        }

        final String jdbcUrl = buildJdbcUrl(hostname, port);
        String lastGeneratedToken = null;
        // try regions from the last known good, default, then any additional candidates
        for (Region region : getRegionsToTry(hostname)) {
            // build a token for the region
            final String token = getAuthToken(hostname, port, rdsUser, region);
            if (StringUtil.isEmpty(token)) {
                continue;
            }
            lastGeneratedToken = token;

            // test token with a real connection attempt
            if (verifyConnection(jdbcUrl, rdsUser, token)) {
                lastSuccessfulRegion.put(hostname, region);
                return token;
            }

            LOG.warn("getAuthTokenFromCandidateRegions: unable to connect to {} using region {}", hostname, region);
        }

        return lastGeneratedToken;
    }

    boolean verifyConnection(String jdbcUrl, String rdsUser, String token) {

        Properties properties = buildSslProperties();
        properties.setProperty(DB_PROP_USER, rdsUser);
        properties.setProperty(DB_PROP_PASSWORD, token);
        properties.setProperty("connectTimeout", "5000");
        properties.setProperty("socketTimeout", "5000");

        try (Connection connection = DriverManager.getConnection(jdbcUrl, properties)) {
            return connection != null;
        } catch (SQLException ex) {
            LOG.error("verifyConnection: unable to connect to {}: {}", jdbcUrl, ex.getMessage());
            return false;
        }
    }

    /**
     * Builds the set of regions to try for generating an RDS IAM auth token for the given hostname, in order:
     * the last region known to work, the local/default region, and any additionally configured candidate signing
     * regions.
     * @param hostname the RDS hostname for which to generate an auth token
     */
    Set<Region> getRegionsToTry(String hostname) {
        Set<Region> regionsToTry = new LinkedHashSet<>();
        final Region lastGoodRegion = lastSuccessfulRegion.get(hostname);
        if (lastGoodRegion != null) {
            regionsToTry.add(lastGoodRegion);
        }
        regionsToTry.add(getRegion());
        regionsToTry.addAll(candidateRegions);
        return regionsToTry;
    }

    void updateCredentials(String hostname, Properties mysqlProperties) {

        // if we have no hostname specified then we have nothing to do

        if (hostname == null) {
            return;
        }

        // obtain iam role credentials and update the properties object

        final String rdsToken = getAuthTokenFromCandidateRegions(hostname, rdsPort, rdsUser);
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
