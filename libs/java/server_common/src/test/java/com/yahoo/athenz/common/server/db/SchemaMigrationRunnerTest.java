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
package com.yahoo.athenz.common.server.db;

import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.*;
import java.util.List;
import java.util.Set;

import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class SchemaMigrationRunnerTest {

    private Path tempDir;
    private PoolableDataSource mockDataSource;
    private Connection mockConnection;
    private Statement mockStatement;
    private PreparedStatement mockPreparedStatement;
    private ResultSet mockResultSet;

    @BeforeMethod
    public void setUp() throws Exception {
        tempDir = Files.createTempDirectory("migration-test");
        mockDataSource = Mockito.mock(PoolableDataSource.class);
        mockConnection = Mockito.mock(Connection.class);
        mockStatement = Mockito.mock(Statement.class);
        mockPreparedStatement = Mockito.mock(PreparedStatement.class);
        mockResultSet = Mockito.mock(ResultSet.class);

        when(mockDataSource.getConnection()).thenReturn(mockConnection);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
    }

    @AfterMethod
    public void tearDown() throws Exception {
        if (tempDir != null) {
            Files.walk(tempDir)
                    .sorted(java.util.Comparator.reverseOrder())
                    .forEach(p -> {
                        try { Files.deleteIfExists(p); } catch (IOException ignored) {}
                    });
        }
    }

    @Test
    public void testParseStatementsSingleStatement() {
        List<String> stmts = SchemaMigrationRunner.parseStatements(
                "ALTER TABLE `zms_server`.`domain` ADD `cert_dns_domain` VARCHAR(256) NOT NULL DEFAULT '';\n");
        assertEquals(stmts.size(), 1);
        assertEquals(stmts.get(0),
                "ALTER TABLE `zms_server`.`domain` ADD `cert_dns_domain` VARCHAR(256) NOT NULL DEFAULT ''");
    }

    @Test
    public void testParseStatementsMultipleStatements() {
        String content = "ALTER TABLE `zms_server`.`quota` ADD `principal_group` INT;\n" +
                "ALTER TABLE `zms_server`.`quota` ADD `principal_group_member` INT;\n";
        List<String> stmts = SchemaMigrationRunner.parseStatements(content);
        assertEquals(stmts.size(), 2);
    }

    @Test
    public void testParseStatementsWithComments() {
        String content = "-- This is a comment\n" +
                "-- Another comment\n" +
                "ALTER TABLE `zms_server`.`domain` ADD `test` VARCHAR(256);\n";
        List<String> stmts = SchemaMigrationRunner.parseStatements(content);
        assertEquals(stmts.size(), 1);
        assertTrue(stmts.get(0).startsWith("ALTER TABLE"));
    }

    @Test
    public void testParseStatementsMultiLineStatement() {
        String content = "CREATE TABLE IF NOT EXISTS `zms_server`.`role_tags` (\n" +
                "  `role_id` INT UNSIGNED NOT NULL,\n" +
                "  `key` VARCHAR(64) NOT NULL,\n" +
                "  PRIMARY KEY (`role_id`, `key`)\n" +
                ") ENGINE = InnoDB;\n";
        List<String> stmts = SchemaMigrationRunner.parseStatements(content);
        assertEquals(stmts.size(), 1);
        assertTrue(stmts.get(0).startsWith("CREATE TABLE"));
        assertTrue(stmts.get(0).endsWith(") ENGINE = InnoDB"));
    }

    @Test
    public void testParseStatementsEmpty() {
        List<String> stmts = SchemaMigrationRunner.parseStatements("");
        assertTrue(stmts.isEmpty());
    }

    @Test
    public void testParseStatementsOnlyComments() {
        List<String> stmts = SchemaMigrationRunner.parseStatements("-- comment\n-- another\n");
        assertTrue(stmts.isEmpty());
    }

    @Test
    public void testParseStatementsNoTrailingSemicolon() {
        String content = "ALTER TABLE `zms_server`.`domain` ADD `test` VARCHAR(256)";
        List<String> stmts = SchemaMigrationRunner.parseStatements(content);
        assertEquals(stmts.size(), 1);
        assertEquals(stmts.get(0), "ALTER TABLE `zms_server`.`domain` ADD `test` VARCHAR(256)");
    }

    @Test
    public void testExtractVersion() {
        assertEquals(SchemaMigrationRunner.extractVersion("update-20260421.sql"), "20260421");
        assertEquals(SchemaMigrationRunner.extractVersion("update-20190107.sql"), "20190107");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testExtractVersionInvalidFilename() {
        SchemaMigrationRunner.extractVersion("not-a-migration.sql");
    }

    @Test
    public void testIsSafeErrorDuplicateColumn() {
        SQLException ex = new SQLException("Duplicate column name 'test'", "HY000", 1060);
        assertTrue(SchemaMigrationRunner.isSafeError(ex));
    }

    @Test
    public void testIsSafeErrorDuplicateKey() {
        SQLException ex = new SQLException("Duplicate key name 'idx'", "HY000", 1061);
        assertTrue(SchemaMigrationRunner.isSafeError(ex));
    }

    @Test
    public void testIsSafeErrorTableExists() {
        SQLException ex = new SQLException("Table already exists", "HY000", 1050);
        assertTrue(SchemaMigrationRunner.isSafeError(ex));
    }

    @Test
    public void testIsSafeErrorDuplicateEntry() {
        SQLException ex = new SQLException("Duplicate entry", "HY000", 1062);
        assertTrue(SchemaMigrationRunner.isSafeError(ex));
    }

    @Test
    public void testIsSafeErrorMultiplePrimaryKey() {
        SQLException ex = new SQLException("Multiple primary key defined", "HY000", 1068);
        assertTrue(SchemaMigrationRunner.isSafeError(ex));
    }

    @Test
    public void testIsSafeErrorUnsafeError() {
        SQLException ex = new SQLException("Syntax error", "HY000", 1064);
        assertFalse(SchemaMigrationRunner.isSafeError(ex));
    }

    @Test
    public void testTruncate() {
        assertEquals(SchemaMigrationRunner.truncate("short", 100), "short");
        String longStr = "a".repeat(200);
        String truncated = SchemaMigrationRunner.truncate(longStr, 10);
        assertEquals(truncated.length(), 13); // 10 + "..."
        assertTrue(truncated.endsWith("..."));
    }

    @Test
    public void testFindMigrationFiles() throws Exception {
        Files.writeString(tempDir.resolve("update-20190107.sql"), "SELECT 1;");
        Files.writeString(tempDir.resolve("update-20260421.sql"), "SELECT 2;");
        Files.writeString(tempDir.resolve("update-20200506.sql"), "SELECT 3;");
        Files.writeString(tempDir.resolve("not-a-migration.txt"), "ignored");
        Files.writeString(tempDir.resolve("update-bad.sql"), "also ignored");

        SchemaMigrationRunner runner = new SchemaMigrationRunner(mockDataSource);
        List<Path> files = runner.findMigrationFiles(tempDir);

        assertEquals(files.size(), 3);
        assertTrue(files.get(0).getFileName().toString().contains("20190107"));
        assertTrue(files.get(1).getFileName().toString().contains("20200506"));
        assertTrue(files.get(2).getFileName().toString().contains("20260421"));
    }

    @Test
    public void testFindMigrationFilesEmptyDir() throws Exception {
        SchemaMigrationRunner runner = new SchemaMigrationRunner(mockDataSource);
        List<Path> files = runner.findMigrationFiles(tempDir);
        assertTrue(files.isEmpty());
    }

    @Test
    public void testMigrateNoMigrationFiles() throws Exception {
        when(mockStatement.executeQuery(SchemaMigrationRunner.SELECT_APPLIED_VERSIONS))
                .thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(false);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.getInt(1)).thenReturn(1);

        SchemaMigrationRunner runner = new SchemaMigrationRunner(mockDataSource);
        runner.migrate(tempDir.toString());

        verify(mockConnection, never()).prepareStatement(SchemaMigrationRunner.INSERT_SCHEMA_VERSION);
    }

    @Test
    public void testMigrateAppliesPendingMigrations() throws Exception {
        Files.writeString(tempDir.resolve("update-20190107.sql"),
                "ALTER TABLE `test` ADD `col1` VARCHAR(256);\n");
        Files.writeString(tempDir.resolve("update-20200506.sql"),
                "ALTER TABLE `test` ADD `col2` VARCHAR(256);\n");

        ResultSet lockResultSet = Mockito.mock(ResultSet.class);
        when(lockResultSet.next()).thenReturn(true);
        when(lockResultSet.getInt(1)).thenReturn(1);

        PreparedStatement lockStmt = Mockito.mock(PreparedStatement.class);
        when(lockStmt.executeQuery()).thenReturn(lockResultSet);

        PreparedStatement releaseLockStmt = Mockito.mock(PreparedStatement.class);
        ResultSet releaseLockRs = Mockito.mock(ResultSet.class);
        when(releaseLockStmt.executeQuery()).thenReturn(releaseLockRs);

        PreparedStatement insertStmt = Mockito.mock(PreparedStatement.class);

        when(mockConnection.prepareStatement("SELECT GET_LOCK(?, ?)")).thenReturn(lockStmt);
        when(mockConnection.prepareStatement("SELECT RELEASE_LOCK(?)")).thenReturn(releaseLockStmt);
        when(mockConnection.prepareStatement(SchemaMigrationRunner.INSERT_SCHEMA_VERSION)).thenReturn(insertStmt);

        when(mockStatement.executeQuery(SchemaMigrationRunner.SELECT_APPLIED_VERSIONS))
                .thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(false);

        SchemaMigrationRunner runner = new SchemaMigrationRunner(mockDataSource);
        runner.migrate(tempDir.toString());

        verify(mockStatement, times(3)).execute(anyString());
        verify(insertStmt, times(2)).executeUpdate();
    }

    @Test
    public void testMigrateSkipsAlreadyApplied() throws Exception {
        Files.writeString(tempDir.resolve("update-20190107.sql"),
                "ALTER TABLE `test` ADD `col1` VARCHAR(256);\n");
        Files.writeString(tempDir.resolve("update-20200506.sql"),
                "ALTER TABLE `test` ADD `col2` VARCHAR(256);\n");

        ResultSet lockResultSet = Mockito.mock(ResultSet.class);
        when(lockResultSet.next()).thenReturn(true);
        when(lockResultSet.getInt(1)).thenReturn(1);

        PreparedStatement lockStmt = Mockito.mock(PreparedStatement.class);
        when(lockStmt.executeQuery()).thenReturn(lockResultSet);

        PreparedStatement releaseLockStmt = Mockito.mock(PreparedStatement.class);
        ResultSet releaseLockRs = Mockito.mock(ResultSet.class);
        when(releaseLockStmt.executeQuery()).thenReturn(releaseLockRs);

        PreparedStatement insertStmt = Mockito.mock(PreparedStatement.class);

        when(mockConnection.prepareStatement("SELECT GET_LOCK(?, ?)")).thenReturn(lockStmt);
        when(mockConnection.prepareStatement("SELECT RELEASE_LOCK(?)")).thenReturn(releaseLockStmt);
        when(mockConnection.prepareStatement(SchemaMigrationRunner.INSERT_SCHEMA_VERSION)).thenReturn(insertStmt);

        ResultSet appliedRs = Mockito.mock(ResultSet.class);
        when(mockStatement.executeQuery(SchemaMigrationRunner.SELECT_APPLIED_VERSIONS))
                .thenReturn(appliedRs);
        when(appliedRs.next()).thenReturn(true, false);
        when(appliedRs.getString("version")).thenReturn("20190107");

        SchemaMigrationRunner runner = new SchemaMigrationRunner(mockDataSource);
        runner.migrate(tempDir.toString());

        // schema_version table creation + 1 migration statement (only 20200506, not 20190107)
        verify(mockStatement, times(2)).execute(anyString());
        verify(insertStmt, times(1)).executeUpdate();
    }

    @Test
    public void testMigrateHandlesSafeErrors() throws Exception {
        Files.writeString(tempDir.resolve("update-20190107.sql"),
                "ALTER TABLE `test` ADD `col1` VARCHAR(256);\n");

        ResultSet lockResultSet = Mockito.mock(ResultSet.class);
        when(lockResultSet.next()).thenReturn(true);
        when(lockResultSet.getInt(1)).thenReturn(1);

        PreparedStatement lockStmt = Mockito.mock(PreparedStatement.class);
        when(lockStmt.executeQuery()).thenReturn(lockResultSet);

        PreparedStatement releaseLockStmt = Mockito.mock(PreparedStatement.class);
        ResultSet releaseLockRs = Mockito.mock(ResultSet.class);
        when(releaseLockStmt.executeQuery()).thenReturn(releaseLockRs);

        PreparedStatement insertStmt = Mockito.mock(PreparedStatement.class);

        when(mockConnection.prepareStatement("SELECT GET_LOCK(?, ?)")).thenReturn(lockStmt);
        when(mockConnection.prepareStatement("SELECT RELEASE_LOCK(?)")).thenReturn(releaseLockStmt);
        when(mockConnection.prepareStatement(SchemaMigrationRunner.INSERT_SCHEMA_VERSION)).thenReturn(insertStmt);

        when(mockStatement.executeQuery(SchemaMigrationRunner.SELECT_APPLIED_VERSIONS))
                .thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(false);

        Statement migrationStmt = Mockito.mock(Statement.class);
        // createStatement() is called for: schema_version table, getAppliedVersions, migration
        when(mockConnection.createStatement()).thenReturn(mockStatement, mockStatement, migrationStmt);
        doThrow(new SQLException("Duplicate column name 'col1'", "HY000", 1060))
                .when(migrationStmt).execute(anyString());

        SchemaMigrationRunner runner = new SchemaMigrationRunner(mockDataSource);
        runner.migrate(tempDir.toString());

        // Should still record the migration as successful
        verify(insertStmt, times(1)).executeUpdate();
        verify(insertStmt).setBoolean(4, true);
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testMigrateThrowsOnUnsafeError() throws Exception {
        Files.writeString(tempDir.resolve("update-20190107.sql"),
                "ALTER TABLE `test` ADD `col1` VARCHAR(256);\n");

        ResultSet lockResultSet = Mockito.mock(ResultSet.class);
        when(lockResultSet.next()).thenReturn(true);
        when(lockResultSet.getInt(1)).thenReturn(1);

        PreparedStatement lockStmt = Mockito.mock(PreparedStatement.class);
        when(lockStmt.executeQuery()).thenReturn(lockResultSet);

        PreparedStatement releaseLockStmt = Mockito.mock(PreparedStatement.class);
        ResultSet releaseLockRs = Mockito.mock(ResultSet.class);
        when(releaseLockStmt.executeQuery()).thenReturn(releaseLockRs);

        PreparedStatement insertStmt = Mockito.mock(PreparedStatement.class);

        when(mockConnection.prepareStatement("SELECT GET_LOCK(?, ?)")).thenReturn(lockStmt);
        when(mockConnection.prepareStatement("SELECT RELEASE_LOCK(?)")).thenReturn(releaseLockStmt);
        when(mockConnection.prepareStatement(SchemaMigrationRunner.INSERT_SCHEMA_VERSION)).thenReturn(insertStmt);

        when(mockStatement.executeQuery(SchemaMigrationRunner.SELECT_APPLIED_VERSIONS))
                .thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(false);

        Statement migrationStmt = Mockito.mock(Statement.class);
        when(mockConnection.createStatement()).thenReturn(mockStatement, mockStatement, migrationStmt);
        doThrow(new SQLException("Syntax error", "HY000", 1064))
                .when(migrationStmt).execute(anyString());

        SchemaMigrationRunner runner = new SchemaMigrationRunner(mockDataSource);
        runner.migrate(tempDir.toString());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testMigrateNonExistentDirectory() {
        SchemaMigrationRunner runner = new SchemaMigrationRunner(mockDataSource);
        runner.migrate("/non/existent/directory");
    }

    @Test(expectedExceptions = RuntimeException.class,
            expectedExceptionsMessageRegExp = ".*Failed to run schema migrations.*")
    public void testMigrateLockFailure() throws Exception {
        Files.writeString(tempDir.resolve("update-20190107.sql"), "SELECT 1;\n");

        ResultSet lockResultSet = Mockito.mock(ResultSet.class);
        when(lockResultSet.next()).thenReturn(true);
        when(lockResultSet.getInt(1)).thenReturn(0);

        PreparedStatement lockStmt = Mockito.mock(PreparedStatement.class);
        when(lockStmt.executeQuery()).thenReturn(lockResultSet);

        PreparedStatement releaseLockStmt = Mockito.mock(PreparedStatement.class);
        ResultSet releaseLockRs = Mockito.mock(ResultSet.class);
        when(releaseLockStmt.executeQuery()).thenReturn(releaseLockRs);

        when(mockConnection.prepareStatement("SELECT GET_LOCK(?, ?)")).thenReturn(lockStmt);
        when(mockConnection.prepareStatement("SELECT RELEASE_LOCK(?)")).thenReturn(releaseLockStmt);

        SchemaMigrationRunner runner = new SchemaMigrationRunner(mockDataSource);
        runner.migrate(tempDir.toString());
    }

    @Test
    public void testGetAppliedVersions() throws Exception {
        ResultSet rs = Mockito.mock(ResultSet.class);
        when(rs.next()).thenReturn(true, true, false);
        when(rs.getString("version")).thenReturn("20190107", "20200506");
        when(mockStatement.executeQuery(SchemaMigrationRunner.SELECT_APPLIED_VERSIONS)).thenReturn(rs);

        SchemaMigrationRunner runner = new SchemaMigrationRunner(mockDataSource);
        Set<String> versions = runner.getAppliedVersions(mockConnection);

        assertEquals(versions.size(), 2);
        assertTrue(versions.contains("20190107"));
        assertTrue(versions.contains("20200506"));
    }

    @Test
    public void testCreateSchemaVersionTable() throws Exception {
        SchemaMigrationRunner runner = new SchemaMigrationRunner(mockDataSource);
        runner.createSchemaVersionTable(mockConnection);

        verify(mockStatement).execute(SchemaMigrationRunner.CREATE_SCHEMA_VERSION_TABLE);
    }

    @Test
    public void testCustomLockName() throws Exception {
        SchemaMigrationRunner runner = new SchemaMigrationRunner(mockDataSource, "custom_lock");

        ResultSet lockResultSet = Mockito.mock(ResultSet.class);
        when(lockResultSet.next()).thenReturn(true);
        when(lockResultSet.getInt(1)).thenReturn(1);

        PreparedStatement lockStmt = Mockito.mock(PreparedStatement.class);
        when(lockStmt.executeQuery()).thenReturn(lockResultSet);
        when(mockConnection.prepareStatement("SELECT GET_LOCK(?, ?)")).thenReturn(lockStmt);

        runner.acquireLock(mockConnection);

        verify(lockStmt).setString(1, "custom_lock");
    }

    @Test
    public void testRecordMigrationUpsertOnRetry() throws Exception {
        PreparedStatement insertStmt = Mockito.mock(PreparedStatement.class);
        when(mockConnection.prepareStatement(SchemaMigrationRunner.INSERT_SCHEMA_VERSION)).thenReturn(insertStmt);

        SchemaMigrationRunner runner = new SchemaMigrationRunner(mockDataSource);

        runner.recordMigration(mockConnection, "20190107", "update-20190107.sql", 100, false);
        verify(insertStmt).setBoolean(4, false);

        runner.recordMigration(mockConnection, "20190107", "update-20190107.sql", 50, true);
        verify(insertStmt).setBoolean(4, true);

        verify(insertStmt, times(2)).executeUpdate();
    }

    @Test
    public void testMigrateIfConfiguredWithValidDir() throws Exception {
        Files.writeString(tempDir.resolve("update-20190107.sql"),
                "ALTER TABLE `test` ADD `col1` VARCHAR(256);\n");

        System.setProperty("test.migration.dir", tempDir.toString());

        ResultSet lockResultSet = Mockito.mock(ResultSet.class);
        when(lockResultSet.next()).thenReturn(true);
        when(lockResultSet.getInt(1)).thenReturn(1);

        PreparedStatement lockStmt = Mockito.mock(PreparedStatement.class);
        when(lockStmt.executeQuery()).thenReturn(lockResultSet);

        PreparedStatement releaseLockStmt = Mockito.mock(PreparedStatement.class);
        ResultSet releaseLockRs = Mockito.mock(ResultSet.class);
        when(releaseLockStmt.executeQuery()).thenReturn(releaseLockRs);

        PreparedStatement insertStmt = Mockito.mock(PreparedStatement.class);

        when(mockConnection.prepareStatement("SELECT GET_LOCK(?, ?)")).thenReturn(lockStmt);
        when(mockConnection.prepareStatement("SELECT RELEASE_LOCK(?)")).thenReturn(releaseLockStmt);
        when(mockConnection.prepareStatement(SchemaMigrationRunner.INSERT_SCHEMA_VERSION)).thenReturn(insertStmt);

        when(mockStatement.executeQuery(SchemaMigrationRunner.SELECT_APPLIED_VERSIONS))
                .thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(false);

        try {
            SchemaMigrationRunner.migrateIfConfigured(mockDataSource,
                    "test.migration.dir", "test_lock");
            verify(insertStmt, times(1)).executeUpdate();
        } finally {
            System.clearProperty("test.migration.dir");
        }
    }

    @Test
    public void testReleaseLockSuccess() throws Exception {
        PreparedStatement releaseLockStmt = Mockito.mock(PreparedStatement.class);
        ResultSet releaseLockRs = Mockito.mock(ResultSet.class);
        when(releaseLockStmt.executeQuery()).thenReturn(releaseLockRs);
        when(mockConnection.prepareStatement("SELECT RELEASE_LOCK(?)")).thenReturn(releaseLockStmt);

        SchemaMigrationRunner runner = new SchemaMigrationRunner(mockDataSource);
        runner.releaseLock(mockConnection);

        verify(releaseLockStmt).setString(1, SchemaMigrationRunner.DEFAULT_LOCK_NAME);
        verify(releaseLockStmt).executeQuery();
    }

    @Test
    public void testReleaseLockFailure() throws Exception {
        when(mockConnection.prepareStatement("SELECT RELEASE_LOCK(?)"))
                .thenThrow(new SQLException("connection closed"));

        SchemaMigrationRunner runner = new SchemaMigrationRunner(mockDataSource);
        runner.releaseLock(mockConnection);
    }
}
