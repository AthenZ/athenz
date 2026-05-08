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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.sql.DataSource;

import org.eclipse.jetty.util.StringUtil;

public class SchemaMigrationRunner {

    private static final Logger LOGGER = LoggerFactory.getLogger(SchemaMigrationRunner.class);

    static final String MIGRATION_FILE_PATTERN = "update-*.sql";
    static final Pattern VERSION_PATTERN = Pattern.compile("update-(\\d{8})\\.sql");
    static final String DEFAULT_LOCK_NAME = "athenz_schema_migration";
    static final int LOCK_TIMEOUT_SECONDS = 30;

    static final int MYSQL_ER_DUP_FIELDNAME = 1060;
    static final int MYSQL_ER_DUP_KEYNAME = 1061;
    static final int MYSQL_ER_TABLE_EXISTS = 1050;
    static final int MYSQL_ER_DUP_ENTRY = 1062;
    static final int MYSQL_ER_MULTIPLE_PRI_KEY = 1068;

    static final String CREATE_SCHEMA_VERSION_TABLE =
            "CREATE TABLE IF NOT EXISTS `schema_version` (" +
            "  `version` VARCHAR(64) NOT NULL," +
            "  `script` VARCHAR(256) NOT NULL," +
            "  `installed_on` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)," +
            "  `execution_time_ms` INT UNSIGNED NOT NULL DEFAULT 0," +
            "  `success` TINYINT(1) NOT NULL DEFAULT 1," +
            "  PRIMARY KEY (`version`)" +
            ") ENGINE = InnoDB";

    static final String SELECT_APPLIED_VERSIONS =
            "SELECT `version` FROM `schema_version` WHERE `success` = 1";

    static final String INSERT_SCHEMA_VERSION =
            "INSERT INTO `schema_version` (`version`, `script`, `execution_time_ms`, `success`) " +
            "VALUES (?, ?, ?, ?) " +
            "ON DUPLICATE KEY UPDATE `script` = VALUES(`script`), " +
            "`execution_time_ms` = VALUES(`execution_time_ms`), " +
            "`success` = VALUES(`success`), " +
            "`installed_on` = CURRENT_TIMESTAMP(3)";

    private final DataSource dataSource;
    private final String lockName;

    public SchemaMigrationRunner(DataSource dataSource) {
        this(dataSource, DEFAULT_LOCK_NAME);
    }

    public SchemaMigrationRunner(DataSource dataSource, String lockName) {
        this.dataSource = dataSource;
        this.lockName = lockName;
    }

    public static void migrateIfConfigured(DataSource dataSource, String propertyName, String lockName) {
        final String migrationDir = System.getProperty(propertyName);
        if (StringUtil.isEmpty(migrationDir)) {
            return;
        }
        LOGGER.info("Running schema migrations from: {}", migrationDir);
        new SchemaMigrationRunner(dataSource, lockName).migrate(migrationDir);
    }

    public void migrate(String migrationDirPath) {

        Path migrationDir = Paths.get(migrationDirPath);
        if (!Files.isDirectory(migrationDir)) {
            LOGGER.error("Schema migration directory does not exist: {}", migrationDirPath);
            throw new IllegalArgumentException("Schema migration directory does not exist: " + migrationDirPath);
        }

        List<Path> migrationFiles = findMigrationFiles(migrationDir);
        if (migrationFiles.isEmpty()) {
            LOGGER.info("No migration files found in: {}", migrationDirPath);
            return;
        }

        LOGGER.info("Found {} migration file(s) in: {}", migrationFiles.size(), migrationDirPath);

        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(true);

            acquireLock(conn);
            try {
                createSchemaVersionTable(conn);
                Set<String> appliedVersions = getAppliedVersions(conn);
                LOGGER.info("Schema version table has {} previously applied migration(s)", appliedVersions.size());

                int applied = 0;
                for (Path file : migrationFiles) {
                    String version = extractVersion(file.getFileName().toString());
                    if (appliedVersions.contains(version)) {
                        continue;
                    }
                    applyMigration(conn, file, version);
                    applied++;
                }

                if (applied > 0) {
                    LOGGER.info("Applied {} new migration(s)", applied);
                } else {
                    LOGGER.info("Schema is up to date, no new migrations to apply");
                }
            } finally {
                releaseLock(conn);
            }
        } catch (SQLException ex) {
            LOGGER.error("Failed to run schema migrations", ex);
            throw new RuntimeException("Failed to run schema migrations", ex);
        }
    }

    List<Path> findMigrationFiles(Path migrationDir) {
        List<Path> files = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(migrationDir, MIGRATION_FILE_PATTERN)) {
            for (Path entry : stream) {
                if (VERSION_PATTERN.matcher(entry.getFileName().toString()).matches()) {
                    files.add(entry);
                }
            }
        } catch (IOException ex) {
            LOGGER.error("Failed to scan migration directory: {}", migrationDir, ex);
            throw new RuntimeException("Failed to scan migration directory", ex);
        }
        Collections.sort(files);
        return files;
    }

    static String extractVersion(String filename) {
        Matcher matcher = VERSION_PATTERN.matcher(filename);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid migration filename: " + filename);
        }
        return matcher.group(1);
    }

    void createSchemaVersionTable(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            stmt.execute(CREATE_SCHEMA_VERSION_TABLE);
        }
    }

    Set<String> getAppliedVersions(Connection conn) throws SQLException {
        Set<String> versions = new HashSet<>();
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(SELECT_APPLIED_VERSIONS)) {
            while (rs.next()) {
                versions.add(rs.getString("version"));
            }
        }
        return versions;
    }

    void applyMigration(Connection conn, Path file, String version) throws SQLException {

        LOGGER.info("Applying migration: {} (version {})", file.getFileName(), version);

        String content;
        try {
            content = Files.readString(file, StandardCharsets.UTF_8);
        } catch (IOException ex) {
            LOGGER.error("Failed to read migration file: {}", file, ex);
            throw new RuntimeException("Failed to read migration file: " + file, ex);
        }

        List<String> statements = parseStatements(content);
        long startTime = System.currentTimeMillis();

        try (Statement stmt = conn.createStatement()) {
            for (String sql : statements) {
                try {
                    stmt.execute(sql);
                } catch (SQLException ex) {
                    if (!isSafeError(ex)) {
                        LOGGER.error("Migration {} failed on statement: {}", version, truncate(sql, 200), ex);
                        recordMigration(conn, version, file.getFileName().toString(),
                                System.currentTimeMillis() - startTime, false);
                        throw ex;
                    }
                    LOGGER.info("Migration {} statement already applied ({}): {}",
                            version, ex.getMessage(), truncate(sql, 100));
                }
            }
        }

        long duration = System.currentTimeMillis() - startTime;
        recordMigration(conn, version, file.getFileName().toString(), duration, true);
        LOGGER.info("Migration {} completed in {} ms", version, duration);
    }

    void recordMigration(Connection conn, String version, String script,
                         long executionTimeMs, boolean success) throws SQLException {
        try (PreparedStatement stmt = conn.prepareStatement(INSERT_SCHEMA_VERSION)) {
            stmt.setString(1, version);
            stmt.setString(2, script);
            stmt.setLong(3, executionTimeMs);
            stmt.setBoolean(4, success);
            stmt.executeUpdate();
        }
    }

    static List<String> parseStatements(String content) {
        List<String> statements = new ArrayList<>();
        StringBuilder current = new StringBuilder();

        for (String line : content.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("--")) {
                continue;
            }
            if (current.length() > 0) {
                current.append('\n');
            }
            current.append(line);
            if (trimmed.endsWith(";")) {
                addStatement(statements, current.toString());
                current.setLength(0);
            }
        }

        addStatement(statements, current.toString());
        return statements;
    }

    private static void addStatement(List<String> statements, String raw) {
        String sql = raw.trim();
        if (sql.endsWith(";")) {
            sql = sql.substring(0, sql.length() - 1).trim();
        }
        if (!sql.isEmpty()) {
            statements.add(sql);
        }
    }

    static boolean isSafeError(SQLException ex) {
        int errorCode = ex.getErrorCode();
        return errorCode == MYSQL_ER_DUP_FIELDNAME ||
               errorCode == MYSQL_ER_DUP_KEYNAME ||
               errorCode == MYSQL_ER_TABLE_EXISTS ||
               errorCode == MYSQL_ER_DUP_ENTRY ||
               errorCode == MYSQL_ER_MULTIPLE_PRI_KEY;
    }

    void acquireLock(Connection conn) throws SQLException {
        try (PreparedStatement stmt = conn.prepareStatement("SELECT GET_LOCK(?, ?)")) {
            stmt.setString(1, lockName);
            stmt.setInt(2, LOCK_TIMEOUT_SECONDS);
            try (ResultSet rs = stmt.executeQuery()) {
                if (!rs.next() || rs.getInt(1) != 1) {
                    throw new SQLException("Failed to acquire migration lock '" + lockName +
                            "' within " + LOCK_TIMEOUT_SECONDS + " seconds");
                }
            }
        }
        LOGGER.debug("Acquired migration lock: {}", lockName);
    }

    void releaseLock(Connection conn) {
        try (PreparedStatement stmt = conn.prepareStatement("SELECT RELEASE_LOCK(?)")) {
            stmt.setString(1, lockName);
            stmt.executeQuery();
            LOGGER.debug("Released migration lock: {}", lockName);
        } catch (SQLException ex) {
            LOGGER.warn("Failed to release migration lock: {}", lockName, ex);
        }
    }

    static String truncate(String str, int maxLen) {
        if (str.length() <= maxLen) {
            return str;
        }
        return str.substring(0, maxLen) + "...";
    }
}
