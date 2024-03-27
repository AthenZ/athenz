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
package com.yahoo.athenz.zms.store.impl.jdbc;

import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.zms.*;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.sql.*;

import static org.testng.Assert.*;

public class ResourceOwnershipTest {

    @Mock
    private PoolableDataSource mockDataSrc;
    @Mock private Statement mockStmt;
    @Mock private PreparedStatement mockPrepStmt;
    @Mock private Connection mockConn;
    @Mock private ResultSet mockResultSet;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        Mockito.doReturn(mockConn).when(mockDataSrc).getConnection();
        Mockito.doReturn(mockStmt).when(mockConn).createStatement();
        Mockito.doReturn(mockResultSet).when(mockStmt).executeQuery(ArgumentMatchers.isA(String.class));
        Mockito.doReturn(true).when(mockStmt).execute(ArgumentMatchers.isA(String.class));
        Mockito.doReturn(mockPrepStmt).when(mockConn).prepareStatement(ArgumentMatchers.isA(String.class));
        Mockito.doReturn(mockResultSet).when(mockPrepStmt).executeQuery();
    }

    @Test
    public void testSetResourcePolicyOwnership() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id

        // first update success, and second update - no changes
        Mockito.when(mockPrepStmt.executeUpdate()).thenReturn(1).thenReturn(0);
        assertTrue(jdbcConn.setResourcePolicyOwnership("domain", "policy", new ResourcePolicyOwnership()));
        assertFalse(jdbcConn.setResourcePolicyOwnership("domain", "policy", new ResourcePolicyOwnership()));
        jdbcConn.close();
    }

    @Test
    public void testSetResourcePolicyOwnershipDomainNotFound() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(0); // 0 indicates domain not found

        try {
            jdbcConn.setResourcePolicyOwnership("domain", "policy", new ResourcePolicyOwnership());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testSetResourcePolicyOwnershipException() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.setResourcePolicyOwnership("domain", "policy", new ResourcePolicyOwnership());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testSetResourceRoleOwnership() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id

        // first update success, and second update - no changes
        Mockito.when(mockPrepStmt.executeUpdate()).thenReturn(1).thenReturn(0);
        assertTrue(jdbcConn.setResourceRoleOwnership("domain", "role", new ResourceRoleOwnership()));
        assertFalse(jdbcConn.setResourceRoleOwnership("domain", "role", new ResourceRoleOwnership()));
        jdbcConn.close();
    }

    @Test
    public void testSetResourceRoleOwnershipDomainNotFound() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(0); // 0 indicates domain not found

        try {
            jdbcConn.setResourceRoleOwnership("domain", "role", new ResourceRoleOwnership());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testSetResourceRoleOwnershipException() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.setResourceRoleOwnership("domain", "role", new ResourceRoleOwnership());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testSetResourceGroupOwnership() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id

        // first update success, and second update - no changes
        Mockito.when(mockPrepStmt.executeUpdate()).thenReturn(1).thenReturn(0);
        assertTrue(jdbcConn.setResourceGroupOwnership("domain", "group", new ResourceGroupOwnership()));
        assertFalse(jdbcConn.setResourceGroupOwnership("domain", "group", new ResourceGroupOwnership()));
        jdbcConn.close();
    }

    @Test
    public void testSetResourceGroupOwnershipDomainNotFound() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(0); // 0 indicates domain not found

        try {
            jdbcConn.setResourceGroupOwnership("domain", "group", new ResourceGroupOwnership());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testSetResourceGroupOwnershipException() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.setResourceGroupOwnership("domain", "group", new ResourceGroupOwnership());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testSetResourceServiceOwnership() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id

        // first update success, and second update - no changes
        Mockito.when(mockPrepStmt.executeUpdate()).thenReturn(1).thenReturn(0);
        assertTrue(jdbcConn.setResourceServiceOwnership("domain", "service", new ResourceServiceIdentityOwnership()));
        assertFalse(jdbcConn.setResourceServiceOwnership("domain", "service", new ResourceServiceIdentityOwnership()));
        jdbcConn.close();
    }

    @Test
    public void testSetResourceServiceOwnershipDomainNotFound() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(0); // 0 indicates domain not found

        try {
            jdbcConn.setResourceServiceOwnership("domain", "service", new ResourceServiceIdentityOwnership());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testSetResourceServiceOwnershipException() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.setResourceServiceOwnership("domain", "service", new ResourceServiceIdentityOwnership());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testSetResourceDomainOwnership() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        // first update success, and second update - no changes
        Mockito.when(mockPrepStmt.executeUpdate()).thenReturn(1).thenReturn(0);
        assertTrue(jdbcConn.setResourceDomainOwnership("domain", new ResourceDomainOwnership()));
        assertFalse(jdbcConn.setResourceDomainOwnership("domain", new ResourceDomainOwnership()));
        jdbcConn.close();
    }

    @Test
    public void testSetResourceDomainOwnershipException() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.setResourceDomainOwnership("domain", new ResourceDomainOwnership());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }
}
