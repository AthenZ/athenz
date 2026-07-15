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

import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.common.server.db.SchemaMigrationRunner;
import com.yahoo.athenz.common.server.store.ObjectStore;
import com.yahoo.athenz.common.server.store.impl.JDBCConsts;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import software.amazon.awssdk.regions.Region;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class AWSObjectStoreFactoryTest {

    static class TestAWSObjectStoreFactory extends AWSObjectStoreFactory {

        @Override
        String getAuthToken(final String hostname, int port, final String rdsUser) {
            if (rdsUser.equals("rds-user")) {
                return "token";
            }
            return null;
        }
    }

    @Test
    public void testCreate() {

        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_PRIMARY_INSTANCE, "instance");
        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_USER, "rds-user");
        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "1");

        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_REPLICA_INSTANCE);

        AWSObjectStoreFactory factory = new TestAWSObjectStoreFactory();
        ObjectStore store = factory.create(null);
        
        // sleep a couple of seconds for the updater to run
        try {
            Thread.sleep(2000);
        } catch (InterruptedException ignored) {
        }
        assertNotNull(store);
        factory.stop();

        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_PRIMARY_INSTANCE);
        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_USER);
        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME);
    }

    @Test
    public void testOriginalMethods() {

        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_PRIMARY_INSTANCE, "instance");
        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_USER, "rds-user");
        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "30000");

        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_REPLICA_INSTANCE);

        AWSObjectStoreFactory factory = new AWSObjectStoreFactory();

        try {
            factory.getRegion();
        } catch (Exception ignored) {
        }

        try {
            factory.getAuthToken("host", 3306, "user");
        } catch (Exception ignored) {
        }

        factory.stop();

        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_PRIMARY_INSTANCE);
        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_USER);
        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME);
    }

    @Test
    public void testCreateWithReplica() {

        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_PRIMARY_INSTANCE, "instance");
        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_REPLICA_INSTANCE, "replica");
        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_USER, "rds-user");
        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "1");

        AWSObjectStoreFactory factory = new TestAWSObjectStoreFactory();
        ObjectStore store = factory.create(null);

        // sleep a couple of seconds for the updater to run
        try {
            Thread.sleep(2000);
        } catch (InterruptedException ignored) {
        }
        assertNotNull(store);
        factory.stop();

        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_PRIMARY_INSTANCE);
        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_REPLICA_INSTANCE);
        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_USER);
        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME);
    }

    @DataProvider(name = "candidateRegionsProvider")
    public Object[][] candidateRegionsProvider() {
        return new Object[][] {
            { null, List.of() },
            { "", List.of() },
            { "  ", List.of() },
            { " us-west-2 , eu-west-1 ,,", List.of(Region.US_WEST_2, Region.EU_WEST_1) },
        };
    }

    @Test(dataProvider = "candidateRegionsProvider")
    public void testParseCandidateRegions(String input, List<Region> expected) {
        assertEquals(AWSObjectStoreFactory.parseCandidateRegions(input), expected);
    }

    @Test
    public void testGetAuthTokenFromCandidateRegionsNoneConfigured() {

        // with no additional candidate regions configured, getAuthTokenFromCandidateRegions
        // must behave exactly like the original single-region getAuthToken() call

        TestAWSObjectStoreFactory factory = new TestAWSObjectStoreFactory();
        assertEquals(factory.getAuthTokenFromCandidateRegions("host", 3306, "rds-user"), "token");
        assertNull(factory.getAuthTokenFromCandidateRegions("host", 3306, "other-user"));
    }

    @Test
    public void testGetAuthTokenFromCandidateRegionsNullHostname() {
        TestAWSObjectStoreFactory factory = new TestAWSObjectStoreFactory();
        assertNull(factory.getAuthTokenFromCandidateRegions(null, 3306, "rds-user"));
    }

    static class CandidateRegionTestFactory extends AWSObjectStoreFactory {

        private Region workingRegion;
        private Region noTokenRegion;
        final List<Region> regionsTried = new java.util.concurrent.CopyOnWriteArrayList<>();

        CandidateRegionTestFactory(Region workingRegion) {
            this.workingRegion = workingRegion;
        }

        void setWorkingRegion(Region workingRegion) {
            this.workingRegion = workingRegion;
        }

        void setNoTokenRegion(Region noTokenRegion) {
            this.noTokenRegion = noTokenRegion;
        }

        @Override
        Region getRegion() {
            return Region.US_EAST_1;
        }

        @Override
        String getAuthToken(String hostname, int port, String rdsUser, Region region) {
            regionsTried.add(region);
            if (region.equals(noTokenRegion)) {
                return null;
            }
            return "token-" + region.id();
        }

        @Override
        boolean verifyConnection(String jdbcUrl, String rdsUser, String token) {
            return token.equals("token-" + workingRegion.id());
        }
    }

    @Test
    public void testGetAuthTokenFromCandidateRegionsSkipsRegionWithNoToken() {

        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_PRIMARY_INSTANCE, "instance");
        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_USER, "rds-user");
        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "30000");
        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_CANDIDATE_REGIONS, "us-west-2,eu-west-1");
        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_REPLICA_INSTANCE);

        // us-west-2 fails to generate a token at all (e.g. a transient signing error) - the
        // factory must skip it and move on to the next candidate rather than treating a
        // null/empty token as terminal

        CandidateRegionTestFactory factory = new CandidateRegionTestFactory(Region.EU_WEST_1);
        factory.setNoTokenRegion(Region.US_WEST_2);
        ObjectStore store = factory.create(null);
        assertNotNull(store);

        assertEquals(factory.regionsTried, List.of(Region.US_EAST_1, Region.US_WEST_2, Region.EU_WEST_1));

        factory.stop();

        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_PRIMARY_INSTANCE);
        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_USER);
        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME);
        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_CANDIDATE_REGIONS);
    }

    @Test
    public void testVerifyConnectionRealImplementationFailsFast() {

        // exercises the real (non-overridden) verifyConnection() failure path with a
        // URL no registered driver accepts, so DriverManager fails synchronously
        // without attempting any real network I/O

        AWSObjectStoreFactory factory = new AWSObjectStoreFactory();
        assertFalse(factory.verifyConnection("not-a-valid-jdbc-url", "user", "token"));
    }

    /**
     * Minimal fake JDBC driver so tests can exercise verifyConnection()'s success path
     * without a live database. Only connect()/acceptsURL() matter; the returned Connection
     * is a no-op proxy since verifyConnection() only checks it for non-null before closing it.
     */
    static class FakeSuccessDriver implements java.sql.Driver {

        static final String URL = "jdbc:athenztest://fake/db";

        @Override
        public boolean acceptsURL(String url) {
            return URL.equals(url);
        }

        @Override
        public java.sql.Connection connect(String url, java.util.Properties info) {
            return (java.sql.Connection) java.lang.reflect.Proxy.newProxyInstance(
                    java.sql.Connection.class.getClassLoader(),
                    new Class<?>[] { java.sql.Connection.class },
                    (proxy, method, args) -> {
                        switch (method.getName()) {
                            case "isClosed":
                                return false;
                            case "equals":
                                return proxy == (args != null && args.length > 0 ? args[0] : null);
                            case "hashCode":
                                return System.identityHashCode(proxy);
                            case "toString":
                                return "FakeConnection";
                            default:
                                return null;
                        }
                    });
        }

        @Override
        public int getMajorVersion() {
            return 1;
        }

        @Override
        public int getMinorVersion() {
            return 0;
        }

        @Override
        public boolean jdbcCompliant() {
            return false;
        }

        @Override
        public java.util.logging.Logger getParentLogger() {
            throw new UnsupportedOperationException();
        }

        @Override
        public java.sql.DriverPropertyInfo[] getPropertyInfo(String url, java.util.Properties info) {
            return new java.sql.DriverPropertyInfo[0];
        }
    }

    @Test
    public void testVerifyConnectionRealImplementationSucceeds() throws java.sql.SQLException {

        // registers a minimal fake driver so the real (non-overridden) verifyConnection()
        // can exercise its success path (a real, non-null Connection) without a live database

        FakeSuccessDriver driver = new FakeSuccessDriver();
        java.sql.DriverManager.registerDriver(driver);
        try {
            AWSObjectStoreFactory factory = new AWSObjectStoreFactory();
            assertTrue(factory.verifyConnection(FakeSuccessDriver.URL, "user", "token"));
        } finally {
            java.sql.DriverManager.deregisterDriver(driver);
        }
    }

    @Test
    public void testGetAuthTokenFromCandidateRegionsFindsWorkingRegion() {

        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_PRIMARY_INSTANCE, "instance");
        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_USER, "rds-user");
        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "30000");
        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_CANDIDATE_REGIONS, "us-west-2,eu-west-1");
        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_REPLICA_INSTANCE);

        // the writer only accepts connections signed for eu-west-1 - the local/default
        // region (us-east-1) and the first additional candidate (us-west-2) must fail
        // before the second candidate (eu-west-1) is found to succeed

        CandidateRegionTestFactory factory = new CandidateRegionTestFactory(Region.EU_WEST_1);
        ObjectStore store = factory.create(null);
        assertNotNull(store);

        assertEquals(factory.regionsTried, List.of(Region.US_EAST_1, Region.US_WEST_2, Region.EU_WEST_1));

        // a subsequent token generation should try the cached last-good region
        // first and, since it still works, should not attempt any other region

        factory.regionsTried.clear();
        String token = factory.getAuthTokenFromCandidateRegions("instance", 3306, "rds-user");
        assertEquals(token, "token-eu-west-1");
        assertEquals(factory.regionsTried, List.of(Region.EU_WEST_1));

        // simulate a cross-region failover: the previously-good region stops
        // working and a different region is now the Aurora Global Database
        // writer - candidate region generation should re-scan and find it

        factory.regionsTried.clear();
        factory.setWorkingRegion(Region.US_WEST_2);
        token = factory.getAuthTokenFromCandidateRegions("instance", 3306, "rds-user");
        assertEquals(token, "token-us-west-2");
        assertEquals(factory.regionsTried, List.of(Region.EU_WEST_1, Region.US_EAST_1, Region.US_WEST_2));

        factory.stop();

        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_PRIMARY_INSTANCE);
        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_USER);
        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME);
        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_CANDIDATE_REGIONS);
    }

    @Test
    public void testGetAuthTokenFromCandidateRegionsAllRegionsFail() {

        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_PRIMARY_INSTANCE, "instance");
        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_USER, "rds-user");
        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "30000");
        System.setProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_CANDIDATE_REGIONS, "us-west-2,eu-west-1");
        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_REPLICA_INSTANCE);

        // none of the candidate regions (us-east-1 local/default, us-west-2, eu-west-1)
        // match the "working" region, so every verification fails - the factory must
        // not throw and must fall back to a best-effort (unverified) token rather
        // than blocking startup

        CandidateRegionTestFactory factory = new CandidateRegionTestFactory(Region.of("ap-southeast-1"));
        ObjectStore store = factory.create(null);
        assertNotNull(store);

        assertEquals(factory.regionsTried, List.of(Region.US_EAST_1, Region.US_WEST_2, Region.EU_WEST_1));

        factory.stop();

        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_PRIMARY_INSTANCE);
        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_USER);
        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME);
        System.clearProperty(AWSObjectStoreFactory.ZMS_PROP_AWS_RDS_CANDIDATE_REGIONS);
    }

    @AfterMethod
    public void tearDown() {
        System.clearProperty(JDBCConsts.ZMS_PROP_JDBC_SCHEMA_MIGRATION_DIR);
    }

    @Test
    public void testSchemaMigrationNotConfigured() {
        System.clearProperty(JDBCConsts.ZMS_PROP_JDBC_SCHEMA_MIGRATION_DIR);
        PoolableDataSource mockDs = Mockito.mock(PoolableDataSource.class);
        SchemaMigrationRunner.migrateIfConfigured(mockDs,
                JDBCConsts.ZMS_PROP_JDBC_SCHEMA_MIGRATION_DIR, "athenz_schema_migration_zms");
        Mockito.verifyNoInteractions(mockDs);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testSchemaMigrationInvalidDirectory() {
        System.setProperty(JDBCConsts.ZMS_PROP_JDBC_SCHEMA_MIGRATION_DIR, "/non/existent/dir");
        PoolableDataSource mockDs = Mockito.mock(PoolableDataSource.class);
        SchemaMigrationRunner.migrateIfConfigured(mockDs,
                JDBCConsts.ZMS_PROP_JDBC_SCHEMA_MIGRATION_DIR, "athenz_schema_migration_zms");
    }
}
