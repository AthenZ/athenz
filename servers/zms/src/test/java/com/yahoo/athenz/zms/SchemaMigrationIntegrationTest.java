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
package com.yahoo.athenz.zms;

import com.yahoo.athenz.common.server.db.DataSourceFactory;
import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.common.server.db.SchemaMigrationRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.shaded.org.apache.commons.io.FileUtils;
import org.testcontainers.utility.DockerImageName;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.*;
import java.time.Duration;
import java.util.Properties;

import static org.testng.Assert.*;

public class SchemaMigrationIntegrationTest {

    private static final Logger LOG = LoggerFactory.getLogger(SchemaMigrationIntegrationTest.class);

    private static final String DB_USER = "admin";
    private static final String DB_PASS = "unit-test";
    private static final String MIGRATION_DIR = "schema/updates";

    private static MySQLContainer<?> mysql;
    private PoolableDataSource dataSource;

    @BeforeClass
    public void setUp() throws Exception {
        String mysqlImage = System.getenv("ZMS_TEST_MYSQL_IMAGE");
        if (mysqlImage == null || mysqlImage.isEmpty()) {
            mysqlImage = "mysql/mysql-server:8.0";
        }

        FileUtils.copyFile(
                new File("schema/zms_server.sql"),
                new File("src/test/resources/mysql/zms_server.sql"));

        mysql = new MySQLContainer<>(DockerImageName.parse(mysqlImage).asCompatibleSubstituteFor("mysql"))
                .withDatabaseName("zms_server")
                .withUsername(DB_USER)
                .withPassword(DB_PASS)
                .withEnv("MYSQL_ROOT_PASSWORD", DB_PASS)
                .withInitScript("mysql/zms_server.sql")
                .withStartupTimeout(Duration.ofMinutes(2));
        mysql.start();
        mysql.followOutput(new Slf4jLogConsumer(LOG));

        Properties props = new Properties();
        props.setProperty("user", DB_USER);
        props.setProperty("password", DB_PASS);
        dataSource = DataSourceFactory.create(mysql.getJdbcUrl(), props);
    }

    @AfterClass
    public void tearDown() {
        if (mysql != null && mysql.isRunning()) {
            mysql.stop();
        }
    }

    @Test
    public void testMigrateAppliesAllFiles() throws Exception {

        assertTrue(Files.isDirectory(Path.of(MIGRATION_DIR)),
                "Migration directory must exist: " + MIGRATION_DIR);
        long fileCount;
        try (var stream = Files.list(Path.of(MIGRATION_DIR))) {
            fileCount = stream
                    .filter(p -> p.getFileName().toString().matches("update-\\d{8}\\.sql"))
                    .count();
        }
        assertTrue(fileCount > 0, "Expected migration files in " + MIGRATION_DIR);

        SchemaMigrationRunner runner = new SchemaMigrationRunner(dataSource, "test_migration_lock");
        runner.migrate(MIGRATION_DIR);

        // Verify schema_version table was created and populated
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(
                     "SELECT COUNT(*) AS cnt FROM schema_version WHERE success = 1")) {
            assertTrue(rs.next());
            long appliedCount = rs.getLong("cnt");
            assertEquals(appliedCount, fileCount,
                    "All migration files should be recorded in schema_version");
            LOG.info("Verified {} migrations recorded in schema_version", appliedCount);
        }
    }

    @Test(dependsOnMethods = "testMigrateAppliesAllFiles")
    public void testMigrateIsIdempotent() throws Exception {

        // Count existing records
        long countBefore;
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT COUNT(*) AS cnt FROM schema_version")) {
            assertTrue(rs.next());
            countBefore = rs.getLong("cnt");
        }

        // Run migrations again
        SchemaMigrationRunner runner = new SchemaMigrationRunner(dataSource, "test_migration_lock");
        runner.migrate(MIGRATION_DIR);

        // Verify no new records were added
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT COUNT(*) AS cnt FROM schema_version")) {
            assertTrue(rs.next());
            long countAfter = rs.getLong("cnt");
            assertEquals(countAfter, countBefore,
                    "Idempotent run should not add new records");
        }
    }

    @Test(dependsOnMethods = "testMigrateAppliesAllFiles")
    public void testSchemaVersionTableContents() throws Exception {

        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(
                     "SELECT version, script, execution_time_ms, success " +
                     "FROM schema_version ORDER BY version")) {
            int count = 0;
            String previousVersion = "";
            while (rs.next()) {
                String version = rs.getString("version");
                String script = rs.getString("script");
                boolean success = rs.getBoolean("success");

                assertTrue(version.matches("\\d{8}"), "Version should be YYYYMMDD: " + version);
                assertTrue(script.startsWith("update-"), "Script should start with 'update-': " + script);
                assertTrue(script.endsWith(".sql"), "Script should end with '.sql': " + script);
                assertTrue(success, "All migrations should be successful");
                assertTrue(version.compareTo(previousVersion) > 0,
                        "Versions should be in order: " + previousVersion + " < " + version);
                previousVersion = version;
                count++;
            }
            assertTrue(count > 0, "Should have at least one migration record");
            LOG.info("Verified {} schema_version records with correct format and ordering", count);
        }
    }
}
