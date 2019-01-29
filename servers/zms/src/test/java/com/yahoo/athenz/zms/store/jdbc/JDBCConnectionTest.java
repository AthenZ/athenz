/*
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.zms.store.jdbc;

import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zms.store.AthenzDomain;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.UUID;

import java.sql.*;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.ArgumentMatchers;

import static org.mockito.Mockito.times;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.fail;

public class JDBCConnectionTest {
    
    @Mock private PoolableDataSource mockDataSrc;
    @Mock private Statement mockStmt;
    @Mock private PreparedStatement mockPrepStmt;
    @Mock private Connection mockConn;
    @Mock private ResultSet mockResultSet;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        Mockito.doReturn(mockConn).when(mockDataSrc).getConnection();
        Mockito.doReturn(mockStmt).when(mockConn).createStatement();
        Mockito.doReturn(mockResultSet).when(mockStmt).executeQuery(ArgumentMatchers.isA(String.class));
        Mockito.doReturn(true).when(mockStmt).execute(ArgumentMatchers.isA(String.class));
        Mockito.doReturn(mockPrepStmt).when(mockConn).prepareStatement(ArgumentMatchers.isA(String.class));
        Mockito.doReturn(mockResultSet).when(mockPrepStmt).executeQuery();
    }
    
    @Test
    public void testGetDomain() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn("my-domain").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_NAME);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);
        Mockito.doReturn(true).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_ENABLED);
        Mockito.doReturn(false).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_AUDIT_ENABLED);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_DESCRIPTION);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_ORG);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_UUID);
        Mockito.doReturn("12345").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_ACCOUNT);
        Mockito.doReturn(1001).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_PRODUCT_ID);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Domain domain = jdbcConn.getDomain("my-domain");
        assertNotNull(domain);
        assertEquals("my-domain", domain.getName());
        assertTrue(domain.getEnabled());
        assertFalse(domain.getAuditEnabled());
        assertNull(domain.getDescription());
        assertNull(domain.getOrg());
        assertNull(domain.getId());
        jdbcConn.close();
    }
    
    @Test
    public void testGetDomainNotFound() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Domain domain = jdbcConn.getDomain("my-domain");
        assertNull(domain);
        jdbcConn.close();
    }
    
    @Test
    public void testGetDomainId() throws Exception {

        // first time success from mysql, second time failure so
        // we can verify we get the value from our cache
        
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn(7).when(mockResultSet).getInt(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals(7, jdbcConn.getDomainId("my-domain"));
        assertEquals(7, jdbcConn.getDomainId("my-domain"));

        jdbcConn.close();
    }
    
    @Test
    public void testGetDomainIdException() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
            
        try {
            jdbcConn.getDomainId("my-domain");
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testGetRoleId() throws Exception {

        // first time success from mysql, second time failure so
        // we can verify we get the value from our cache
        
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn(9).when(mockResultSet).getInt(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals(9, jdbcConn.getRoleId(7, "role1"));
        assertEquals(9, jdbcConn.getRoleId(7, "role1"));

        jdbcConn.close();
    }
    
    @Test
    public void testGetRoleIdException() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
            
        try {
            jdbcConn.getRoleId(3, "role1");
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testGetPrincipalId() throws Exception {

        // first time success from mysql, second time failure so
        // we can verify we get the value from our cache
        
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn(7).when(mockResultSet).getInt(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals(7, jdbcConn.getPrincipalId("my-domain.user1"));
        assertEquals(7, jdbcConn.getPrincipalId("my-domain.user1"));

        jdbcConn.close();
    }
    
    @Test
    public void testGetPrincipalIdException() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
            
        try {
            jdbcConn.getPrincipalId("domain.user1");
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testGetLastInsertIdFailure() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(false);
        
        assertEquals(0, jdbcConn.getLastInsertId());
        jdbcConn.close();
    }
    
    @Test
    public void testGetLastInsertIdException() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
            
        try {
            jdbcConn.getLastInsertId();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testGetPolicyId() throws Exception {

        // first time success from mysql, second time failure so
        // we can verify we get the value from our cache
        
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn(9).when(mockResultSet).getInt(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals(9, jdbcConn.getPolicyId(7, "policy1"));
        assertEquals(9, jdbcConn.getPolicyId(7, "policy1"));

        jdbcConn.close();
    }
    
    @Test
    public void testGetPolicyIdException() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
            
        try {
            jdbcConn.getPolicyId(3, "policy1");
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testGetServiceId() throws Exception {

        // first time success from mysql, second time failure so
        // we can verify we get the value from our cache
        
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn(9).when(mockResultSet).getInt(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals(9, jdbcConn.getServiceId(7, "service1"));
        assertEquals(9, jdbcConn.getServiceId(7, "service1"));

        jdbcConn.close();
    }
    
    @Test
    public void testGetServiceIdException() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
            
        try {
            jdbcConn.getServiceId(3, "service1");
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testGetHostId() throws Exception {

        // first time success from mysql, second time failure so
        // we can verify we get the value from our cache
        
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn(9).when(mockResultSet).getInt(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals(9, jdbcConn.getHostId("host1"));
        assertEquals(9, jdbcConn.getHostId("host1"));

        jdbcConn.close();
    }
    
    @Test
    public void testGetHostIdException() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
            
        try {
            jdbcConn.getHostId("host1");
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testGetDomainAllFields() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn("my-domain").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_NAME);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);
        Mockito.doReturn(true).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_ENABLED);
        Mockito.doReturn(true).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_AUDIT_ENABLED);
        Mockito.doReturn("my own domain").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_DESCRIPTION);
        Mockito.doReturn("cloud_services").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_ORG);
        Mockito.doReturn("e5e97240-e94e-11e4-8163-6d083f3f473f").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_UUID);
        Mockito.doReturn("12345").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_ACCOUNT);
        Mockito.doReturn(1001).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_PRODUCT_ID);
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Domain domain = jdbcConn.getDomain("my-domain");
        assertNotNull(domain);
        assertEquals("my-domain", domain.getName());
        assertTrue(domain.getEnabled());
        assertTrue(domain.getAuditEnabled());
        assertEquals("my own domain", domain.getDescription());
        assertEquals("cloud_services", domain.getOrg());
        assertEquals(UUID.fromString("e5e97240-e94e-11e4-8163-6d083f3f473f"), domain.getId());
        jdbcConn.close();
    }
    
    @Test
    public void testGetDomainException() throws Exception {

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        try {
            jdbcConn.getDomain("my-domain");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Domain domain = new Domain().setName("my-domain")
                .setEnabled(true)
                .setAuditEnabled(false)
                .setDescription("my domain")
                .setId(UUID.fromString("e5e97240-e94e-11e4-8163-6d083f3f473f"))
                .setOrg("cloud_services");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.insertDomain(domain);
        assertTrue(requestSuccess);

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my_domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "my domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "cloud_services");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "e5e97240-e94e-11e4-8163-6d083f3f473f");
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(5, true);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(6, false);
        Mockito.verify(mockPrepStmt, times(1)).setString(7, "");
        Mockito.verify(mockPrepStmt, times(1)).setInt(8, 0);
        jdbcConn.close();
    }
    
    @Test
    public void testInsertDomainWithAccountInfo() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Domain domain = new Domain().setName("my-domain")
                .setEnabled(true)
                .setAuditEnabled(false)
                .setDescription("my domain")
                .setId(UUID.fromString("e5e97240-e94e-11e4-8163-6d083f3f473f"))
                .setOrg("cloud_services")
                .setAccount("123456789")
                .setYpmId(1011);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.insertDomain(domain);
        assertTrue(requestSuccess);

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my_domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "my domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "cloud_services");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "e5e97240-e94e-11e4-8163-6d083f3f473f");
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(5, true);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(6, false);
        Mockito.verify(mockPrepStmt, times(1)).setString(7, "123456789");
        Mockito.verify(mockPrepStmt, times(1)).setInt(8, 1011);
        jdbcConn.close();
    }
    
    @Test
    public void testInsertDomainNullFields() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Domain domain = new Domain().setName("my-domain")
                .setEnabled(true)
                .setAuditEnabled(false);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.insertDomain(domain);
        assertTrue(requestSuccess);

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my_domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "");
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(5, true);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(6, false);
        jdbcConn.close();
    }
    
    @Test
    public void testInsertDomainException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Domain domain = new Domain().setName("my-domain")
                .setEnabled(true)
                .setAuditEnabled(false)
                .setDescription("my domain")
                .setId(UUID.fromString("e5e97240-e94e-11e4-8163-6d083f3f473f"))
                .setOrg("cloud_services");
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.insertDomain(domain);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertDomainDashFailure() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Domain domain = new Domain().setName("sports-api")
                .setEnabled(true)
                .setAuditEnabled(false)
                .setDescription("my domain")
                .setId(UUID.fromString("e5e97240-e94e-11e4-8163-6d083f3f473f"))
                .setOrg("cloud_services");

        Mockito.when(mockResultSet.next())
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(false);
        Mockito.when(mockResultSet.getString(1))
                .thenReturn("sports_api")
                .thenReturn("sports-api");

        try {
            jdbcConn.insertDomain(domain);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("sports-api"));
        }

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "sports_api");
        jdbcConn.close();
    }

    @Test
    public void testInsertDomainDashException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Domain domain = new Domain().setName("my.test-domain")
                .setEnabled(true)
                .setAuditEnabled(false)
                .setDescription("my domain")
                .setId(UUID.fromString("e5e97240-e94e-11e4-8163-6d083f3f473f"))
                .setOrg("cloud_services");

        Mockito.doThrow(new SQLException("failed operation", "state", 1001)).when(mockPrepStmt).setString(1, "my_test_domain");
        try {
            jdbcConn.insertDomain(domain);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }

    @Test
    public void testUpdateDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Domain domain = new Domain().setName("my-domain")
                .setEnabled(true)
                .setAuditEnabled(false)
                .setDescription("my domain")
                .setId(UUID.fromString("e5e97240-e94e-11e4-8163-6d083f3f473f"))
                .setOrg("cloud_services")
                .setAccount("123456789")
                .setYpmId(1011)
                .setApplicationId("application_id")
                .setCertDnsDomain("athenz.cloud");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.updateDomain(domain);
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "cloud_services");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "e5e97240-e94e-11e4-8163-6d083f3f473f");
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(4, true);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(5, false);
        Mockito.verify(mockPrepStmt, times(1)).setString(6, "123456789");
        Mockito.verify(mockPrepStmt, times(1)).setInt(7, 1011);
        Mockito.verify(mockPrepStmt, times(1)).setString(8, "application_id");
        Mockito.verify(mockPrepStmt, times(1)).setString(9, "athenz.cloud");
        Mockito.verify(mockPrepStmt, times(1)).setString(10, "my-domain");
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateDomainNullFields() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Domain domain = new Domain().setName("my-domain")
                .setEnabled(true)
                .setAuditEnabled(false);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.updateDomain(domain);
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "");
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(4, true);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(5, false);
        Mockito.verify(mockPrepStmt, times(1)).setString(6, "");
        Mockito.verify(mockPrepStmt, times(1)).setInt(7, 0);
        Mockito.verify(mockPrepStmt, times(1)).setString(8, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(9, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(10, "my-domain");
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateDomainException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Domain domain = new Domain().setName("my-domain")
                .setEnabled(true)
                .setAuditEnabled(false)
                .setDescription("my domain")
                .setId(UUID.fromString("e5e97240-e94e-11e4-8163-6d083f3f473f"))
                .setOrg("cloud_services");
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.updateDomain(domain);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.deleteDomain("my-domain");
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateDomainModTimestampSuccess() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.updateDomainModTimestamp("my-domain");
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateDomainModTimestampFailure() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.updateDomainModTimestamp("my-domain");
        assertFalse(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateDomainModTimestampException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.updateDomainModTimestamp("my-domain");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteDomainException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.deleteDomain("my-domain");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testListDomains() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
            .thenReturn("zdomain")
            .thenReturn("adomain")
            .thenReturn("bdomain");

        List<String> domains = jdbcConn.listDomains(null, 0);
        
        // data back is sorted
        
        assertEquals(3, domains.size());
        assertEquals("adomain", domains.get(0));
        assertEquals("bdomain", domains.get(1));
        assertEquals("zdomain", domains.get(2));
        jdbcConn.close();
    }
    
    @Test
    public void testListDomainsException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.listDomains(null, 0);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testGetDomainModTimestampSuccess() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        long modTime = jdbcConn.getDomainModTimestamp("my-domain");
        assertEquals(1454358916, modTime);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        jdbcConn.close();
    }
    
    @Test
    public void testGetDomainModTimestampFailure() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        long modTime = jdbcConn.getDomainModTimestamp("my-domain");
        assertEquals(0, modTime);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        jdbcConn.close();
    }
    
    @Test
    public void testGetDomainModTimestampException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        assertEquals(0, jdbcConn.getDomainModTimestamp("my-domain"));
        jdbcConn.close();
    }
    
    @Test
    public void testGetRole() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn("role1").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_NAME);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_TRUST);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Role role = jdbcConn.getRole("my-domain", "role1");
        assertNotNull(role);
        assertEquals("my-domain:role.role1", role.getName());
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");
        jdbcConn.close();
    }
    
    @Test
    public void testGetRoleNotFound() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Role role = jdbcConn.getRole("my-domain", "role1");
        assertNull(role);
        jdbcConn.close();
    }
    
    @Test
    public void testGetRoleTrust() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn("role1").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_NAME);
        Mockito.doReturn("trust.domain").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_TRUST);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Role role = jdbcConn.getRole("my-domain", "role1");
        assertNotNull(role);
        assertEquals("my-domain:role.role1", role.getName());
        assertEquals("trust.domain", role.getTrust());
        jdbcConn.close();
    }
    
    @Test
    public void testGetRoleException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.getRole("my-domain", "role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(500, ex.getCode());
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertRole() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Role role = new Role().setName("my-domain:role.role1");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        boolean requestSuccess = jdbcConn.insertRole("my-domain", role);
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "role1");
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "");
        jdbcConn.close();
    }
    
    @Test
    public void testInsertRoleInvalidRoleDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Role role = new Role().setName("my-domain2:role.role1");
        
        try {
            jdbcConn.insertRole("my-domain", role);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertRoleInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Role role = new Role().setName("my-domain:role.role1");
        Mockito.when(mockResultSet.next()).thenReturn(false); // domain id failure

        try {
            jdbcConn.insertRole("my-domain", role);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertRoleWithTrust() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Role role = new Role().setName("my-domain:role.role1").setTrust("trust_domain");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain
        
        boolean requestSuccess = jdbcConn.insertRole("my-domain", role);
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "role1");
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "trust_domain");
        jdbcConn.close();
    }
    
    @Test
    public void testInsertRoleException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Role role = new Role().setName("my-domain:role.role1");

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.insertRole("my-domain", role);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateRole() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Role role = new Role().setName("my-domain:role.role1");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5) // return domain id
            .thenReturn(4); //role id
        
        boolean requestSuccess = jdbcConn.updateRole("my-domain", role);
        assertTrue(requestSuccess);
        
        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        // get role id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");
        // update role
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "");
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 4);
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateRoleWithTrust() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Role role = new Role().setName("my-domain:role.role1").setTrust("trust_domain");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // role id
        
        boolean requestSuccess = jdbcConn.updateRole("my-domain", role);
        assertTrue(requestSuccess);
        
        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        // get role id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");
        // update role
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "trust_domain");
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 7);
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateRoleInvalidRoleDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Role role = new Role().setName("my-domain2:role.role1");
        
        try {
            jdbcConn.updateRole("my-domain", role);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateRoleInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Role role = new Role().setName("my-domain:role.role1");
        Mockito.when(mockResultSet.next()).thenReturn(false); // domain id failure

        try {
            jdbcConn.updateRole("my-domain", role);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateRoleInvalidRoleId() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next())
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id
        
        Role role = new Role().setName("my-domain:role.role1");
        
        try {
            jdbcConn.updateRole("my-domain", role);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateRoleException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Role role = new Role().setName("my-domain:role.role1");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.updateRole("my-domain", role);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateRoleModTimestampSuccess() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // role id
        
        boolean requestSuccess = jdbcConn.updateRoleModTimestamp("my-domain", "role1");
        assertTrue(requestSuccess);
        
        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        // get role id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");
        // update role time-stamp
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateRoleModTimestampFailure() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // role id
        
        boolean requestSuccess = jdbcConn.updateRoleModTimestamp("my-domain", "role1");
        assertFalse(requestSuccess);
        
        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        // get role id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");
        // update role time-stamp
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateRoleModTimestampException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.updateRoleModTimestamp("my-domain", "role1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteRole() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id

        boolean requestSuccess = jdbcConn.deleteRole("my-domain", "role1");
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteRoleinvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(false);

        try {
            jdbcConn.deleteRole("my-domain", "role1");
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteRoleException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.deleteRole("my-domain", "role1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testListRoles() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getString(1))
            .thenReturn("zrole")
            .thenReturn("arole")
            .thenReturn("brole");
        
        List<String> roles = jdbcConn.listRoles("my-domain");
        
        // data back is sorted
        
        assertEquals(3, roles.size());
        assertEquals("arole", roles.get(0));
        assertEquals("brole", roles.get(1));
        assertEquals("zrole", roles.get(2));
        jdbcConn.close();
    }
    
    @Test
    public void testCountRoles() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7); // return domain/count
        
        Mockito.when(mockResultSet.next()).thenReturn(true);
        
        assertEquals(jdbcConn.countRoles("my-domain"), 7);
        jdbcConn.close();
    }
    
    @Test
    public void testCountRolesNoResult() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain/count
        
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        
        assertEquals(jdbcConn.countRoles("my-domain"), 0);
        jdbcConn.close();
    }
    
    @Test
    public void testCountRolesInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id
        
        try {
            jdbcConn.countRoles("my-domain");
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testCountRolesException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true); // this one is for domain id
        
        Mockito.when(mockPrepStmt.executeQuery())
            .thenReturn(mockResultSet)
            .thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.countRoles("my-domain");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testListRolesInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id
        
        try {
            jdbcConn.listRoles("my-domain");
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testListRolesException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true); // this one is for domain id
        
        Mockito.when(mockPrepStmt.executeQuery())
            .thenReturn(mockResultSet)
            .thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.listRoles("my-domain");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testExtractRoleName() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals("role1", jdbcConn.extractRoleName("my-domain1", "my-domain1:role.role1"));
        assertEquals("role1.role2", jdbcConn.extractRoleName("my-domain1", "my-domain1:role.role1.role2"));
        
        // invalid roles names
        assertNull(jdbcConn.extractRoleName("my-domain1", "my-domain1:role1"));
        assertNull(jdbcConn.extractRoleName("my-domain1", "my-domain2:role.role1"));
        assertNull(jdbcConn.extractRoleName("my-domain1", "my-domain11:role.role1"));
        assertNull(jdbcConn.extractRoleName("my-domain1", ":role.role1"));
        assertNull(jdbcConn.extractRoleName("my-domain1", "role1"));
        assertNull(jdbcConn.extractRoleName("my-domain1", "role1.role2"));
        jdbcConn.close();
    }
    
    @Test
    public void testCountRoleMembers() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7)
            .thenReturn(4); // return domain/role id/count
        
        Mockito.when(mockResultSet.next()).thenReturn(true);
        
        assertEquals(jdbcConn.countRoleMembers("my-domain", "role1"), 4);
        jdbcConn.close();
    }
    
    @Test
    public void testCountRoleMembersInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next())
            .thenReturn(false); // invalid domain
        
        try {
            jdbcConn.countRoleMembers("my-domain", "role1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testCountRoleMembersInvalidRole() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(false); // this one is for role id
        
        try {
            jdbcConn.countRoleMembers("my-domain", "role1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testCountRoleMembersException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7); // return domain id
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true); // this one is for role id
        
        Mockito.when(mockPrepStmt.executeQuery())
            .thenReturn(mockResultSet)
            .thenReturn(mockResultSet)
            .thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.countRoleMembers("my-domain", "role1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testCountRoleMembersNoResult() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7);
        
        Mockito.when(mockResultSet.next()).thenReturn(true)
            .thenReturn(true).thenReturn(false);
        
        assertEquals(jdbcConn.countRoleMembers("my-domain", "role1"), 0);
        jdbcConn.close();
    }
    
    @Test
    public void testListRoleMembers() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7); // return domain/role id
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for role id
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getString(1))
            .thenReturn("zdomain.user1")
            .thenReturn("adomain.storage")
            .thenReturn("bdomain.user2");
        Mockito.when(mockResultSet.getTimestamp(2))
            .thenReturn(new java.sql.Timestamp(System.currentTimeMillis() + 100))
            .thenReturn(new java.sql.Timestamp(System.currentTimeMillis() + 200))
            .thenReturn(null);
        
        List<RoleMember> roleMembers = jdbcConn.listRoleMembers("my-domain", "role1");
        
        // data back is sorted
        
        assertEquals(3, roleMembers.size());
        
        assertNotNull(roleMembers.get(0).getExpiration());
        assertNull(roleMembers.get(1).getExpiration());
        assertNotNull(roleMembers.get(2).getExpiration());

        assertEquals("adomain.storage", roleMembers.get(0).getMemberName());
        assertEquals("bdomain.user2", roleMembers.get(1).getMemberName());
        assertEquals("zdomain.user1", roleMembers.get(2).getMemberName());
        jdbcConn.close();
    }
    
    @Test
    public void testListRoleMembersInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next())
            .thenReturn(false); // invalid domain
        
        try {
            jdbcConn.listRoleMembers("my-domain", "role1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testListRoleMembersInvalidRole() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(false); // this one is for role id
        
        try {
            jdbcConn.listRoleMembers("my-domain", "role1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testListRoleMembersException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7); // return domain id
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true); // this one is for role id
        
        Mockito.when(mockPrepStmt.executeQuery())
            .thenReturn(mockResultSet)
            .thenReturn(mockResultSet)
            .thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.listRoleMembers("my-domain", "role1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testParseRoleMember() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        StringBuilder domain = new StringBuilder(512);
        StringBuilder name = new StringBuilder(512);
        assertTrue(jdbcConn.parsePrincipal("user.user", domain, name));
        assertEquals("user", domain.toString());
        assertEquals("user", name.toString());
        
        domain.setLength(0);
        name.setLength(0);
        assertTrue(jdbcConn.parsePrincipal("coretech.storage.service", domain, name));
        assertEquals("coretech.storage", domain.toString());
        assertEquals("service", name.toString());
        
        assertFalse(jdbcConn.parsePrincipal(".coretech", domain, name));
        assertFalse(jdbcConn.parsePrincipal("coretech.storage.service.", domain, name));
        assertFalse(jdbcConn.parsePrincipal("service", domain, name));
        assertFalse(jdbcConn.parsePrincipal("", domain, name));
        jdbcConn.close();
    }
    
    @Test
    public void testInsertRoleMember() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7) // role id
            .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for role id
            .thenReturn(true) // validate principle domain
            .thenReturn(true) // principal id
            .thenReturn(false); // member exists
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.insertRoleMember("my-domain", "role1",
                new RoleMember().setMemberName("user.user1"), "user.admin", "audit-ref");
        
        // this is combined for all operations above
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");
        
        // we need additional operation for the audit log
        // additional operation to check for roleMember exist using roleID and principal ID.
        Mockito.verify(mockPrepStmt, times(3)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(2)).setInt(2, 9);
        
        // the rest of the audit log details
        
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "ADD");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "audit-ref");

        assertTrue(requestSuccess);
        jdbcConn.close();
    }
    
    @Test
    public void testInsertRoleMemberUpdate() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7) // role id
            .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for role id
            .thenReturn(true) // validate principle domain
            .thenReturn(true) // principal id
            .thenReturn(true); // member exists
            
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        RoleMember roleMember = new RoleMember().setMemberName("user.user1");
        Timestamp expiration = Timestamp.fromCurrentTime();
        roleMember.setExpiration(expiration);
        java.sql.Timestamp javaExpiration = new java.sql.Timestamp(expiration.toDate().getTime());
        boolean requestSuccess = jdbcConn.insertRoleMember("my-domain", "role1",
                roleMember, "user.admin", "audit-ref");
        
        // this is combined for all operations above
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");
        
        // we need additional operation for the audit log
        Mockito.verify(mockPrepStmt, times(2)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 9);
        
        // update operation
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(1, javaExpiration);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(3, 9);
        
        // the rest of the audit log details
        
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "UPDATE");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "audit-ref");

        assertTrue(requestSuccess);
        jdbcConn.close();
    }
    
    @Test
    public void testInsertRoleMemberNewPrincipal() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7) // role id
            .thenReturn(8) // principal domain id
            .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for role id
            .thenReturn(true) // this one is for valid principal domain
            .thenReturn(false) // principal does not exist
            .thenReturn(true) // get last id (for new principal)
            .thenReturn(false); // role member exists
            
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.insertRoleMember("my-domain", "role1",
                new RoleMember().setMemberName("user.user1"),
                "user.admin", "audit-ref");
        
        // this is combined for all operations above
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user");

        // we're going to have 2 sets of operations for principal name
        
        Mockito.verify(mockPrepStmt, times(2)).setString(1, "user.user1");
        
        // we need additional operation for the audit log
        // additional operation to check for roleMember exist using roleID and principal ID.
        Mockito.verify(mockPrepStmt, times(3)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(2)).setInt(2, 9);
        
        // the rest of the audit log details
        
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "ADD");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "audit-ref");
        
        assertTrue(requestSuccess);
        jdbcConn.close();
    }
    
    @Test
    public void testInsertRoleMemberException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7) // role id
            .thenReturn(9) // member domain id
            .thenReturn(11); // principal id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for role id
            .thenReturn(true) // member domain id
            .thenReturn(true) // principal id
            .thenReturn(false); // role member exists
            
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(
                new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.insertRoleMember("my-domain", "role1", 
                    new RoleMember().setMemberName("user.user1"),
                    "user.admin", "audit-ref");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertRoleMemberNewPrincipalFailure() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7) // role id
            .thenReturn(8) // principal domain id
            .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for role id
            .thenReturn(true) // this one is for valid principal domain
            .thenReturn(false); // principal does not exist
        
        // principal add returns 0
        
        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.insertRoleMember("my-domain", "role1",
                    new RoleMember().setMemberName("user.user1"),
                    "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }

        jdbcConn.close();
    }
    
    @Test
    public void testGetRoleMemberYes() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true); // yes a member
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // role id
        
        Membership membership = jdbcConn.getRoleMember("my-domain", "role1", "user.user1");
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.user1");

        assertEquals(membership.getMemberName(), "user.user1");
        assertEquals(membership.getRoleName(), "my-domain:role.role1");
        assertTrue(membership.getIsMember());
        jdbcConn.close();
    }
    
    @Test
    public void testGetRoleMemberNo() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // domain id
            .thenReturn(true) // role id
            .thenReturn(false); // not a member
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // role id
        
        Membership membership = jdbcConn.getRoleMember("my-domain", "role1", "user.user1");
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.user1");

        assertEquals(membership.getMemberName(), "user.user1");
        assertEquals(membership.getRoleName(), "my-domain:role.role1");
        assertFalse(membership.getIsMember());
        jdbcConn.close();
    }
    
    @Test
    public void testGetRoleMemberInvalidPrincipal() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true); // yes a member
        
        try {
            jdbcConn.getRoleMember("my-domain", "role1", "user1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testGetRoleMemberException() throws Exception {

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        try {
            jdbcConn.getRoleMember("my-domain", "role1", "user.user1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteRoleMember()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7) // role id
            .thenReturn(9) // member domain id
            .thenReturn(11); // principal id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for role id
            .thenReturn(true) // member domain id
            .thenReturn(true); // principal id
            
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.deleteRoleMember("my-domain", "role1", "user.user1",
                "user.admin", "audit-ref");
        assertTrue(requestSuccess);
        
        // this is combined for all operations above
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");
        
        // we need additional operation for the audit log
        Mockito.verify(mockPrepStmt, times(2)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 9);
        
        // the rest of the audit log details
        
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "DELETE");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "audit-ref");
        
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteRoleMemberInvalidDomain()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id
            
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.deleteRoleMember("my-domain", "role1", "user.user1",
                    "user.admin", "audit-ref");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteRoleMemberInvalidRole()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(false); // this one is for role id
            
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.deleteRoleMember("my-domain", "role1", "user.user1",
                    "user.admin", "audit-ref");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteRoleMemberInvalidPrincipalId()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // role id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for role id
            .thenReturn(false); // principal id
            
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.deleteRoleMember("my-domain", "role1", "user.user1",
                    "user.admin", "audit-ref");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testGetPolicy() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn("policy1").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_NAME);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Policy policy = jdbcConn.getPolicy("my-domain", "policy1");
        assertNotNull(policy);
        assertEquals("my-domain:policy.policy1", policy.getName());
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "policy1");
        jdbcConn.close();
    }
    
    @Test
    public void testGetPolicyException() throws Exception {

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        try {
            jdbcConn.getPolicy("my-domain", "policy1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertPolicy() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Policy policy = new Policy().setName("my-domain:policy.policy1");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        boolean requestSuccess = jdbcConn.insertPolicy("my-domain", policy);
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "policy1");
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 5);
        jdbcConn.close();
    }
    
    @Test
    public void testInsertPolicyInvalidName() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Policy policy = new Policy().setName("policy1");

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        try {
            jdbcConn.insertPolicy("my-domain", policy);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertPolicyException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Policy policy = new Policy().setName("my-domain:policy.policy1");

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.insertPolicy("my-domain", policy);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testUpdatePolicy() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Policy policy = new Policy().setName("my-domain:policy.policy1");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5) // return domain id
            .thenReturn(4); //policy id
        
        boolean requestSuccess = jdbcConn.updatePolicy("my-domain", policy);
        assertTrue(requestSuccess);
        
        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        // get policy id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "policy1");
        // update policy
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "policy1");
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 4);
        jdbcConn.close();
    }
    
    @Test
    public void testUpdatePolicyInvalidName() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Policy policy = new Policy().setName("policy1");

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        try {
            jdbcConn.updatePolicy("my-domain", policy);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
        jdbcConn.close();
    }
    
    @Test
    public void testUpdatePolicyException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Policy policy = new Policy().setName("my-domain:policy.policy1");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.updatePolicy("my-domain", policy);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeletePolicy() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id

        boolean requestSuccess = jdbcConn.deletePolicy("my-domain", "policy1");
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "policy1");
        jdbcConn.close();
    }
    
    @Test
    public void testDeletePolicyException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.deletePolicy("my-domain", "policy1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testListPolicies() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getString(1))
            .thenReturn("zpolicy")
            .thenReturn("apolicy")
            .thenReturn("bpolicy");
        
        List<String> policies = jdbcConn.listPolicies("my-domain", null);
        
        // data back is sorted
        
        assertEquals(3, policies.size());
        assertEquals("apolicy", policies.get(0));
        assertEquals("bpolicy", policies.get(1));
        assertEquals("zpolicy", policies.get(2));
        jdbcConn.close();
    }
    
    @Test
    public void testCountPolicies() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id/same for count
        Mockito.when(mockResultSet.next()).thenReturn(true);
        
        assertEquals(jdbcConn.countPolicies("my-domain"), 5);
        jdbcConn.close();
    }
    
    @Test
    public void testCountPoliciesNoResult() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain/count
        
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        
        assertEquals(jdbcConn.countPolicies("my-domain"), 0);
        jdbcConn.close();
    }
    
    @Test
    public void testCountPoliciesInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id
        
        try {
            jdbcConn.countPolicies("my-domain");
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testCountPoliciesException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true); // this one is for domain id
        
        Mockito.when(mockPrepStmt.executeQuery())
            .thenReturn(mockResultSet)
            .thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.countPolicies("my-domain");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testExtractPolicyName() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals("policy1", jdbcConn.extractPolicyName("my-domain1", "my-domain1:policy.policy1"));
        assertEquals("policy1.policy2", jdbcConn.extractPolicyName("my-domain1", "my-domain1:policy.policy1.policy2"));
        
        // invalid policies names
        assertNull(jdbcConn.extractPolicyName("my-domain1", "my-domain1:policy1"));
        assertNull(jdbcConn.extractPolicyName("my-domain1", "my-domain2:policy.policy1"));
        assertNull(jdbcConn.extractPolicyName("my-domain1", "my-domain11:policy.policy1"));
        assertNull(jdbcConn.extractPolicyName("my-domain1", ":policy.policy1"));
        assertNull(jdbcConn.extractPolicyName("my-domain1", "policy1"));
        assertNull(jdbcConn.extractPolicyName("my-domain1", "policy1.policy2"));
        jdbcConn.close();
    }
    
    @Test
    public void testSkipAwsUserQuery() throws Exception {

        try (JDBCConnection jdbcConn = new JDBCConnection(mockConn, true)) {
            Map<String, String> map = new HashMap<String, String>() {
                private static final long serialVersionUID = -8689695626417810614L;
                {
                    put("zms", "domain1");
                }
                {
                    put("zms", "domain2");
                }
            };
            assertFalse(jdbcConn.skipAwsUserQuery(map, "queryP1", "zms", "zms"));
            jdbcConn.skipAwsUserQuery(map, null, "zms", "user");
        }
    }
    
    @Test
    public void testInsertAssertion() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Assertion assertion = new Assertion()
                .setAction("read")
                .setEffect(AssertionEffect.ALLOW)
                .setResource("my-domain:*")
                .setRole("my-domain:role.role1");

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // policy id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for policy id
            .thenReturn(false); // insertion is not found

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.insertAssertion("my-domain", "policy1", assertion);
        assertTrue(requestSuccess);

        // getting domain and policy ids
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "policy1");
        
        // assertion statement - twice once for checking if it exists
        // and second time for inserting
        
        Mockito.verify(mockPrepStmt, times(2)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(2)).setString(2, "role1");
        Mockito.verify(mockPrepStmt, times(2)).setString(3, "my-domain:*");
        Mockito.verify(mockPrepStmt, times(2)).setString(4, "read");
        Mockito.verify(mockPrepStmt, times(2)).setString(5, "ALLOW");
        jdbcConn.close();
    }

    @Test
    public void testInsertAssertionDuplicate() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Assertion assertion = new Assertion()
                .setAction("read")
                .setEffect(AssertionEffect.ALLOW)
                .setResource("my-domain:*")
                .setRole("my-domain:role.role1");

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // policy id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for policy id
            .thenReturn(true); // insertion is found
        
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.insertAssertion("my-domain", "policy1", assertion);
        assertTrue(requestSuccess);

        // getting domain and policy ids
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "policy1");
        
        // assertion statement
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "my-domain:*");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "read");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "ALLOW");
        jdbcConn.close();
    }
    @Test
    public void testInsertAssertionInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Assertion assertion = new Assertion()
                .setAction("read")
                .setEffect(AssertionEffect.ALLOW)
                .setResource("my-domain:*")
                .setRole("my-domain:role.role1");

        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id
        
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.insertAssertion("my-domain", "policy1", assertion);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertAssertionInvalidRoleName() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Assertion assertion = new Assertion()
                .setAction("read")
                .setEffect(AssertionEffect.ALLOW)
                .setResource("my-domain:*")
                .setRole("invalid_role");

        try {
            jdbcConn.insertAssertion("my-domain", "policy1", assertion);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertAssertionInvalidPolicy() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Assertion assertion = new Assertion()
                .setAction("read")
                .setEffect(AssertionEffect.ALLOW)
                .setResource("my-domain:*")
                .setRole("my-domain:role.role1");

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(false); // this one is for policy id
        
        try {
            jdbcConn.insertAssertion("my-domain", "policy1", assertion);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertAssertionException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Assertion assertion = new Assertion()
                .setAction("read")
                .setEffect(AssertionEffect.ALLOW)
                .setResource("my-domain:*")
                .setRole("my-domain:role.role1");

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // policy id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for policy id
            .thenReturn(false); // assume insertion is not found
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.insertAssertion("my-domain", "policy1", assertion);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteAssertion() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // policy id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true); // this one is for policy id
        
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.deleteAssertion("my-domain", "policy1", (long) 101);
        assertTrue(requestSuccess);

        // getting domain and policy ids
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "policy1");
        
        // assertion statement
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 101);
        jdbcConn.close();
    }

    @Test
    public void testDeleteAssertionInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id
        
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.deleteAssertion("my-domain", "policy1", (long) 101);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteAssertionInvalidPolicy() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(false); // this one is for policy id
        
        try {
            jdbcConn.deleteAssertion("my-domain", "policy1", (long) 101);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteAssertionException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // policy id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true); // this one is for policy id
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.deleteAssertion("my-domain", "policy1", (long) 101);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testGetServiceIdentity() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn("test description").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_DESCRIPTION);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_EXECTUABLE);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_SVC_GROUP);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_SVC_USER);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_PROVIDER_ENDPOINT);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        ServiceIdentity service = jdbcConn.getServiceIdentity("my-domain", "service1");
        assertNotNull(service);
        assertEquals("my-domain.service1", service.getName());
        assertNull(service.getExecutable());
        assertNull(service.getGroup());
        assertNull(service.getUser());
        assertNull(service.getProviderEndpoint());
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "service1");
        jdbcConn.close();
    }
    
    @Test
    public void testGetServiceIdentityNoMatch() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        ServiceIdentity service = jdbcConn.getServiceIdentity("my-domain", "service1");
        assertNull(service);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "service1");
        jdbcConn.close();
    }
    
    @Test
    public void testGetServiceIdentityAllFields() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn("test description").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_DESCRIPTION);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);
        Mockito.doReturn("/usr/bin64/athenz").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_EXECTUABLE);
        Mockito.doReturn("users").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_SVC_GROUP);
        Mockito.doReturn("root").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_SVC_USER);
        Mockito.doReturn("http://server.athenzcompany.com").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_PROVIDER_ENDPOINT);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        ServiceIdentity service = jdbcConn.getServiceIdentity("my-domain", "service1");
        assertNotNull(service);
        assertEquals("my-domain.service1", service.getName());
        assertEquals("/usr/bin64/athenz", service.getExecutable());
        assertEquals("users", service.getGroup());
        assertEquals("root", service.getUser());
        assertEquals("http://server.athenzcompany.com", service.getProviderEndpoint());
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "service1");
        jdbcConn.close();
    }
    
    @Test
    public void testGetServiceException() throws Exception {

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        try {
            jdbcConn.getServiceIdentity("my-domain", "service1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertServiceIdentity() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        ServiceIdentity service = new ServiceIdentity().setName("my-domain.service1");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id
        
        boolean requestSuccess = jdbcConn.insertServiceIdentity("my-domain", service);
        assertTrue(requestSuccess);
        
        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        // update service
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "service1");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "");
        jdbcConn.close();
    }
    
    @Test
    public void testInsertServiceIdentityInvalidName() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        ServiceIdentity service = new ServiceIdentity().setName("service1");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5) // return domain id
            .thenReturn(4); //service id
        
        try {
            jdbcConn.insertServiceIdentity("my-domain", service);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertServiceIdentityAllFields() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        ServiceIdentity service = new ServiceIdentity()
                .setName("my-domain.service1")
                .setDescription("test service")
                .setExecutable("/usr/bin64/test.sh")
                .setGroup("users")
                .setUser("root")
                .setProviderEndpoint("http://server.athenzcompany.com");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id
        
        boolean requestSuccess = jdbcConn.insertServiceIdentity("my-domain", service);
        assertTrue(requestSuccess);
        
        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        // update service
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "service1");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "test service");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "http://server.athenzcompany.com");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "/usr/bin64/test.sh");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "root");
        Mockito.verify(mockPrepStmt, times(1)).setString(6, "users");
        Mockito.verify(mockPrepStmt, times(1)).setInt(7, 5);
        jdbcConn.close();
    }
    
    @Test
    public void testInsertServiceException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        ServiceIdentity service = new ServiceIdentity().setName("my-domain.service1");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.insertServiceIdentity("my-domain", service);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateServiceIdentity() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        ServiceIdentity service = new ServiceIdentity().setName("my-domain.service1");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5) // return domain id
            .thenReturn(4); //service id
        
        boolean requestSuccess = jdbcConn.updateServiceIdentity("my-domain", service);
        assertTrue(requestSuccess);
        
        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        // get service id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "service1");
        // update service
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "");
        Mockito.verify(mockPrepStmt, times(1)).setInt(6, 4);
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateServiceIdentityInvalidName() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        ServiceIdentity service = new ServiceIdentity().setName("service1");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5) // return domain id
            .thenReturn(4); //service id
        
        try {
            jdbcConn.updateServiceIdentity("my-domain", service);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateServiceIdentityAllFields() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        ServiceIdentity service = new ServiceIdentity()
                .setName("my-domain.service1")
                .setDescription("test service")
                .setExecutable("/usr/bin64/test.sh")
                .setGroup("users")
                .setUser("root")
                .setProviderEndpoint("http://server.athenzcompany.com");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5) // return domain id
            .thenReturn(4); //service id
        
        boolean requestSuccess = jdbcConn.updateServiceIdentity("my-domain", service);
        assertTrue(requestSuccess);
        
        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        // get service id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "service1");
        // update service
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "test service");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "http://server.athenzcompany.com");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "/usr/bin64/test.sh");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "root");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "users");
        Mockito.verify(mockPrepStmt, times(1)).setInt(6, 4);
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateServiceIdentityException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        ServiceIdentity service = new ServiceIdentity().setName("my-domain.service1");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5) // return domain id
            .thenReturn(4); //service id
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.updateServiceIdentity("my-domain", service);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteServiceIdentity() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id

        boolean requestSuccess = jdbcConn.deleteServiceIdentity("my-domain", "service1");
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "service1");
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteServiceIdentityException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.deleteServiceIdentity("my-domain", "service1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testListServiceIdentities() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getString(1))
            .thenReturn("zservice")
            .thenReturn("aservice")
            .thenReturn("bservice");
        
        List<String> services = jdbcConn.listServiceIdentities("my-domain");
        
        // data back is sorted
        
        assertEquals(3, services.size());
        assertEquals("aservice", services.get(0));
        assertEquals("bservice", services.get(1));
        assertEquals("zservice", services.get(2));
        jdbcConn.close();
    }
    
    @Test
    public void testCountServiceIdentities() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id/count (same)
        Mockito.when(mockResultSet.next()).thenReturn(true);

        assertEquals(jdbcConn.countServiceIdentities("my-domain"), 5);
        jdbcConn.close();
    }
    
    @Test
    public void testCountServiceIdentitiesNoResult() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain/count
        
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        
        assertEquals(jdbcConn.countServiceIdentities("my-domain"), 0);
        jdbcConn.close();
    }
    
    @Test
    public void testCountServiceIdentitiesInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id
        
        try {
            jdbcConn.countServiceIdentities("my-domain");
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testCountServiceIdentitiesException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true); // this one is for domain id
        
        Mockito.when(mockPrepStmt.executeQuery())
            .thenReturn(mockResultSet)
            .thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.countServiceIdentities("my-domain");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testExtractServiceName() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals("service1", jdbcConn.extractServiceName("my-domain1", "my-domain1.service1"));
        assertEquals("service1", jdbcConn.extractServiceName("my-domain1.domain2", "my-domain1.domain2.service1"));
        
        // invalid service names
        assertNull(jdbcConn.extractServiceName("my-domain1", "my-domain1:service1"));
        assertNull(jdbcConn.extractServiceName("my-domain1", "my-domain2.service1"));
        assertNull(jdbcConn.extractServiceName("my-domain1", "my-domain11:service.service1"));
        assertNull(jdbcConn.extractServiceName("my-domain1", ".service1"));
        assertNull(jdbcConn.extractServiceName("my-domain1", "service1"));
        assertNull(jdbcConn.extractServiceName("my-domain1", "service1.service2"));
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateServiceModTimestampSuccess() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // service id
        
        boolean requestSuccess = jdbcConn.updateServiceIdentityModTimestamp("my-domain", "service1");
        assertTrue(requestSuccess);
        
        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        // get service id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "service1");
        // update service time-stamp
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateServiceModTimestampFailure() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // service id
        
        boolean requestSuccess = jdbcConn.updateServiceIdentityModTimestamp("my-domain", "service1");
        assertFalse(requestSuccess);
        
        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        // get service id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "service1");
        // update service time-stamp
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateServiceModTimestampException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.updateServiceIdentityModTimestamp("my-domain", "service1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testSaveValue() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals("test1", jdbcConn.saveValue("test1"));
        assertNull(jdbcConn.saveValue(""));
        jdbcConn.close();
    }
    
    @Test
    public void testSaveUriValue() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals("http://server.athenzcompany.com", jdbcConn.saveValue("http://server.athenzcompany.com"));
        assertNull(jdbcConn.saveValue(""));
        jdbcConn.close();
    }
    
    @Test
    public void testProcessInsertValue() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals("test1", jdbcConn.processInsertValue("test1"));
        assertEquals("", jdbcConn.processInsertValue((String) null));
        jdbcConn.close();
    }
    
    @Test
    public void testProcessInsertIntValue() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals(1001, jdbcConn.processInsertValue(1001));
        assertEquals(0, jdbcConn.processInsertValue((Integer) null));
        jdbcConn.close();
    }
    
    @Test
    public void testProcessInsertBooleanValue() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertTrue(jdbcConn.processInsertValue(Boolean.TRUE, false));
        assertFalse(jdbcConn.processInsertValue(null, false));
        jdbcConn.close();
    }
    
    @Test
    public void testProcessInsertAssertionAffect() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals("ALLOW", jdbcConn.processInsertValue(AssertionEffect.ALLOW));
        assertEquals("DENY", jdbcConn.processInsertValue(AssertionEffect.DENY));
        assertEquals("ALLOW", jdbcConn.processInsertValue((AssertionEffect) null));
        jdbcConn.close();
    }
    
    @Test
    public void testProcessInsertUriValue() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals("http://server.athenzcompany.com", jdbcConn.processInsertValue("http://server.athenzcompany.com"));
        assertEquals("", jdbcConn.processInsertValue((String) null));
        jdbcConn.close();
    }
    
    @Test
    public void testProcessInsertUuidValue() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals("e5e97240-e94e-11e4-8163-6d083f3f473f", jdbcConn.processInsertUuidValue(UUID.fromString("e5e97240-e94e-11e4-8163-6d083f3f473f")));
        assertEquals("", jdbcConn.processInsertUuidValue(null));
        jdbcConn.close();
    }
    
    @Test
    public void testListPublicKeys() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7); // return domain/service id
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for service id
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_KEY_ID))
            .thenReturn("zms1.zone1")
            .thenReturn("zms2.zone1")
            .thenReturn("zms3.zone1");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_KEY_VALUE))
            .thenReturn("Value1")
            .thenReturn("Value2")
            .thenReturn("Value3");
        
        List<PublicKeyEntry> publicKeys = jdbcConn.listPublicKeys("my-domain", "service1");
        
        // data back is sorted
        
        assertEquals(3, publicKeys.size());
        assertEquals("zms1.zone1", publicKeys.get(0).getId());
        assertEquals("Value1", publicKeys.get(0).getKey());
        assertEquals("zms2.zone1", publicKeys.get(1).getId());
        assertEquals("Value2", publicKeys.get(1).getKey());
        assertEquals("zms3.zone1", publicKeys.get(2).getId());
        assertEquals("Value3", publicKeys.get(2).getKey());
        jdbcConn.close();
    }
    
    @Test
    public void testCountPublicKeys() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7).thenReturn(2); 
            // return domain/service id/count
        
        Mockito.when(mockResultSet.next()).thenReturn(true);
        
        assertEquals(jdbcConn.countPublicKeys("my-domain", "service1"), 2);
        jdbcConn.close();
    }
    
    @Test
    public void testCountPublicKeysInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id

        try {
            jdbcConn.countPublicKeys("my-domain", "service1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testCountPublicKeysInvalidService() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next()).thenReturn(true) // this one is for domain id
            .thenReturn(false); // this one is for service id
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5);

        try {
            jdbcConn.countPublicKeys("my-domain", "service1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testCountPublicKeysNoResult() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next()).thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for service id
            .thenReturn(false); // no result for count
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7);

        assertEquals(jdbcConn.countPublicKeys("my-domain", "service1"), 0);
        jdbcConn.close();
    }
    
    @Test
    public void testCountPublicKeysException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7)
            .thenReturn(1); // return domain/service id/count
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true); // this one is for domain id
        
        Mockito.when(mockPrepStmt.executeQuery())
            .thenReturn(mockResultSet)
            .thenReturn(mockResultSet)
            .thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.countPublicKeys("my-domain", "service1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testListAssertions() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7); // return domain/policy id
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for policy id
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE))
            .thenReturn("role1")
            .thenReturn("role2");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_RESOURCE))
            .thenReturn("my-domain:*")
            .thenReturn("my-domain:service.*");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ACTION))
            .thenReturn("*")
            .thenReturn("read");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_EFFECT))
            .thenReturn("ALLOW")
            .thenReturn("DENY");
        
        List<Assertion> assertions = jdbcConn.listAssertions("my-domain", "policy1");
        
        assertEquals(2, assertions.size());
        assertEquals("my-domain:role.role1", assertions.get(0).getRole());
        assertEquals("my-domain:*", assertions.get(0).getResource());
        assertEquals("*", assertions.get(0).getAction());
        assertEquals("ALLOW", assertions.get(0).getEffect().toString());
        
        assertEquals("my-domain:role.role2", assertions.get(1).getRole());
        assertEquals("my-domain:service.*", assertions.get(1).getResource());
        assertEquals("read", assertions.get(1).getAction());
        assertEquals("DENY", assertions.get(1).getEffect().toString());
        jdbcConn.close();
    }
    
    @Test
    public void testListAssertionsInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id

        try {
            jdbcConn.listAssertions("my-domain", "policy1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testCountAssertions() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7)
            .thenReturn(1); // return domain/policy id/count
        Mockito.when(mockResultSet.next())
            .thenReturn(true);
        
        assertEquals(jdbcConn.countAssertions("my-domain", "policy1"), 1);
        jdbcConn.close();
    }
    
    @Test
    public void testCountAssertionsInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id

        try {
            jdbcConn.countAssertions("my-domain", "policy1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testCountAssertionsInvalidPolicy() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next()).thenReturn(true) // this one is for domain id
            .thenReturn(false); // this one is for policy id
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5);

        try {
            jdbcConn.countAssertions("my-domain", "policy1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testCountAssertionsNoResult() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next()).thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for policy id
            .thenReturn(false); // no result for count
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7);

        assertEquals(jdbcConn.countAssertions("my-domain", "policy1"), 0);
        jdbcConn.close();
    }
    
    @Test
    public void testCountAssertionsException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7)
            .thenReturn(1); // return domain/policy id/count
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true); // this one is for domain id
        
        Mockito.when(mockPrepStmt.executeQuery())
            .thenReturn(mockResultSet)
            .thenReturn(mockResultSet)
            .thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.countAssertions("my-domain", "policy1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testGetPublicKeyEntry() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // service id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for service id
            .thenReturn(true); // for key
        
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_KEY_VALUE))
            .thenReturn("Value1");
    
        PublicKeyEntry publicKey = jdbcConn.getPublicKeyEntry("my-domain", "service1", "zone1", false);
        assertNotNull(publicKey);
        assertEquals("Value1", publicKey.getKey());
        assertEquals("zone1", publicKey.getId());
        jdbcConn.close();
    }
    
    @Test
    public void testGetPublicKeyEntryInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id

        try {
            jdbcConn.getPublicKeyEntry("my-domain", "service1", "zone1", false);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testGetPublicKeyEntryInvalidServiceId() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(false); // this one is for service id

        try {
            jdbcConn.getPublicKeyEntry("my-domain", "service1", "zone1", false);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testGetPublicKeyEntryInvalidKeyId() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // service id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for service id
            .thenReturn(false); // for key

        PublicKeyEntry publicKey = jdbcConn.getPublicKeyEntry("my-domain", "service1", "zone1", false);
        assertNull(publicKey);
        jdbcConn.close();
    }
    
    @Test
    public void testGetPublicKeyEntryException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // service id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for service id
            .thenReturn(false); // for key

        Mockito.when(mockPrepStmt.executeQuery())
            .thenReturn(mockResultSet)
            .thenReturn(mockResultSet)
            .thenThrow(new SQLException("failed operation", "state", 1001));
        
        try {
            jdbcConn.getPublicKeyEntry("my-domain", "service1", "zone1", false);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertPublicKeyEntry() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        PublicKeyEntry publicKey = new PublicKeyEntry().setId("zms1").setKey("Value1");

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // service id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true); // this one is for service id
        
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.insertPublicKeyEntry("my-domain", "service1", publicKey);
        assertTrue(requestSuccess);

        // getting domain and service ids
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "service1");
        
        // public key entry statement
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "zms1");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "Value1");
        jdbcConn.close();
    }

    @Test
    public void testInsertPublicKeyEntryInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        PublicKeyEntry publicKey = new PublicKeyEntry().setId("zms1").setKey("Value1");

        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id
        
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.insertPublicKeyEntry("my-domain", "service1", publicKey);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertPublicKeyEntryInvalidService() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        PublicKeyEntry publicKey = new PublicKeyEntry().setId("zms1").setKey("Value1");

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(false); // this one is for service id
        
        try {
            jdbcConn.insertPublicKeyEntry("my-domain", "service1", publicKey);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertPublicKeyEntryException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        PublicKeyEntry publicKey = new PublicKeyEntry().setId("zms1").setKey("Value1");

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // service id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true); // this one is for service id
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.insertPublicKeyEntry("my-domain", "service1", publicKey);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }

    @Test
    public void testUpdatePublicKeyEntry() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        PublicKeyEntry publicKey = new PublicKeyEntry().setId("zms1").setKey("Value1");

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // service id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true); // this one is for service id
        
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.updatePublicKeyEntry("my-domain", "service1", publicKey);
        assertTrue(requestSuccess);

        // getting domain and service ids
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "service1");
        
        // public key entry statement
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "Value1");
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 7);
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "zms1");
        jdbcConn.close();
    }

    @Test
    public void testUpdatePublicKeyEntryInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        PublicKeyEntry publicKey = new PublicKeyEntry().setId("zms1").setKey("Value1");

        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id
        
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.updatePublicKeyEntry("my-domain", "service1", publicKey);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testUpdatePublicKeyEntryInvalidService() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        PublicKeyEntry publicKey = new PublicKeyEntry().setId("zms1").setKey("Value1");

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(false); // this one is for service id
        
        try {
            jdbcConn.updatePublicKeyEntry("my-domain", "service1", publicKey);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testUpdatePublicKeyEntryException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        PublicKeyEntry publicKey = new PublicKeyEntry().setId("zms1").setKey("Value1");

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // service id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true); // this one is for service id
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.updatePublicKeyEntry("my-domain", "service1", publicKey);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeletePublicKeyEntry() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // service id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true); // this one is for service id
        
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.deletePublicKeyEntry("my-domain", "service1", "zms1");
        assertTrue(requestSuccess);

        // getting domain and service ids
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "service1");
        
        // public key entry statement
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "zms1");
        jdbcConn.close();
    }

    @Test
    public void testDeletePublicKeyEntryInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id
        
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.deletePublicKeyEntry("my-domain", "service1", "zms1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeletePublicKeyEntryInvalidService() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(false); // this one is for service id
        
        try {
            jdbcConn.deletePublicKeyEntry("my-domain", "service1", "zms1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
   }
    
    @Test
    public void testDeletePublicKeyEntryException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // service id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true); // this one is for service id
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.deletePublicKeyEntry("my-domain", "service1", "zms1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertServiceHost() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7) // service id
            .thenReturn(9); // host id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for service id
            .thenReturn(true); // this on is for host id
            
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.insertServiceHost("my-domain", "service1", "host1");
        
        // this is combined for all operations above
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "service1");
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "host1");
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 9);
        
        assertTrue(requestSuccess);
        jdbcConn.close();
    }
    
    @Test
    public void testInsertServiceHostNewHost() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7) // service id
            .thenReturn(9); // host id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for service id
            .thenReturn(false) // this on is for host does not exist
            .thenReturn(true); // insert last id (for new host)
            
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.insertServiceHost("my-domain", "service1", "host1");
        
        // this is combined for all operations above
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "service1");
        
        // 2 times - one for lookup, second time for adding
        
        Mockito.verify(mockPrepStmt, times(2)).setString(1, "host1");
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 9);
        
        assertTrue(requestSuccess);
        jdbcConn.close();
    }
    
    @Test
    public void testInsertServiceHostInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id
            
        try {
            jdbcConn.insertServiceHost("my-domain", "service1", "host1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
   }
    
    @Test
    public void testInsertServiceHostInvalidService() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(false); // this one is for service id
            
        try {
            jdbcConn.insertServiceHost("my-domain", "service1", "host1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertServiceHostException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7) // service id
            .thenReturn(9); // host id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for service id
            .thenReturn(true); // this on is for host id
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.insertServiceHost("my-domain", "service1", "host1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteServiceHost() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7) // service id
            .thenReturn(9); // host id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for service id
            .thenReturn(true); // this on is for host id
            
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.deleteServiceHost("my-domain", "service1", "host1");
        
        // this is combined for all operations above
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "service1");
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "host1");
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 9);
        
        assertTrue(requestSuccess);
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteServiceHostInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id
            
        try {
            jdbcConn.deleteServiceHost("my-domain", "service1", "host1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteServiceHostInvalidService() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(false); // this one is for service id
            
        try {
            jdbcConn.deleteServiceHost("my-domain", "service1", "host1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteServiceHostInvalidHost() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // service ie
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for service id
            .thenReturn(false); // this one is for host id
        
        try {
            jdbcConn.deleteServiceHost("my-domain", "service1", "host1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteServiceHostException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7) // service id
            .thenReturn(9); // host id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for service id
            .thenReturn(true); // this on is for host id
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.deleteServiceHost("my-domain", "service1", "host1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testListServiceHosts() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
        .thenReturn(5) // domain id
        .thenReturn(7); // service id
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for service id
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
            .thenReturn("host1")
            .thenReturn("host3")
            .thenReturn("host2");
        
        List<String> serviceHosts = jdbcConn.listServiceHosts("my-domain", "service1");
        
        assertEquals(3, serviceHosts.size());
        assertEquals("host1", serviceHosts.get(0));
        assertEquals("host3", serviceHosts.get(1));
        assertEquals("host2", serviceHosts.get(2));
        jdbcConn.close();
    }
    
    @Test
    public void testInsertDomainTemplate() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
            .thenReturn(true); // this one is for domain id
            
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.insertDomainTemplate("my-domain", "platforms", null);
        
        // this is combined for all operations above
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "platforms");
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "platforms");
        
        assertTrue(requestSuccess);
        jdbcConn.close();
    }
    
    @Test
    public void testInsertDomainTemplateInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id
            
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        
        try {
            jdbcConn.insertDomainTemplate("my-domain", "platforms", null);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertDomainTemplateNewTemplate() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
            .thenReturn(true); // this one is for domain id
        
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.insertDomainTemplate("my-domain", "platforms", null);
        
        // this is combined for all operations above
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "platforms");
        
        assertTrue(requestSuccess);
        jdbcConn.close();
   }
    
    @Test
    public void testInsertDomainTemplateException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // template id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true); // this one is for template id
            
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.insertDomainTemplate("my-domain", "platforms", null);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteDomainTemplate() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
            .thenReturn(true); // this one is for domain id
            
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.deleteDomainTemplate("my-domain", "platforms", null);
        
        // this is combined for all operations above
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "platforms");
        
        assertTrue(requestSuccess);
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteDomainTemplateInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id
            
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        
        try {
            jdbcConn.deleteDomainTemplate("my-domain", "platforms", null);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteDomainTemplateException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // template id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true); // this one is for template id
            
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.deleteDomainTemplate("my-domain", "platforms", null);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testListDomainTemplates() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getString(1))
            .thenReturn("vipng")
            .thenReturn("platforms")
            .thenReturn("user_understanding");
        
        List<String> templates = jdbcConn.listDomainTemplates("my-domain");
        
        // data back is sorted
        
        assertEquals(3, templates.size());
        assertEquals("platforms", templates.get(0));
        assertEquals("user_understanding", templates.get(1));
        assertEquals("vipng", templates.get(2));
        jdbcConn.close();
    }
    
    @Test
    public void testListDomainTemplatesException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.listDomainTemplates("my-domain");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testPrepareDomainScanStatementPrefixNullModifiedZero() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        jdbcConn.prepareDomainScanStatement(null, 0);
        Mockito.verify(mockPrepStmt, times(0)).setString(Mockito.anyInt(), Mockito.isA(String.class));
        jdbcConn.close();
    }
    
    @Test
    public void testPrepareDomainScanStatementPrefixModifiedZero() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        jdbcConn.prepareDomainScanStatement("prefix", 0);
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "prefix");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "prefiy");
        jdbcConn.close();
    }
    
    @Test
    public void testPrepareDomainScanStatementPrefixModified() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        jdbcConn.prepareDomainScanStatement("prefix", 100);
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "prefix");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "prefiy");
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(ArgumentMatchers.eq(3), ArgumentMatchers.eq(new java.sql.Timestamp(100)), ArgumentMatchers.isA(Calendar.class));
        jdbcConn.close();
    }
    
    @Test
    public void testPrepareDomainScanStatementPrefixEmptyModifiedTime() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        jdbcConn.prepareDomainScanStatement("", 100);
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(ArgumentMatchers.eq(1), ArgumentMatchers.eq(new java.sql.Timestamp(100)), ArgumentMatchers.isA(Calendar.class));
        jdbcConn.close();
    }
    
    @Test
    public void testPrepareDomainScanStatementOnlyModifiedTime() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        jdbcConn.prepareDomainScanStatement(null, 100);
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(ArgumentMatchers.eq(1), ArgumentMatchers.eq(new java.sql.Timestamp(100)), ArgumentMatchers.isA(Calendar.class));
        jdbcConn.close();
    }
    
    @Test
    public void testPrepareScanByRoleStatement() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.prepareScanByRoleStatement("user.member", "name");
        Mockito.verify(mockPrepStmt, times(1)).setString(ArgumentMatchers.eq(1), ArgumentMatchers.eq("user.member"));
        Mockito.verify(mockPrepStmt, times(1)).setString(ArgumentMatchers.eq(2), ArgumentMatchers.eq("name"));
        jdbcConn.close();
    }
    
    @Test
    public void testPrepareScanByRoleStatementOnlyRoleNameNull() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.prepareScanByRoleStatement(null, "name");
        Mockito.verify(mockPrepStmt, times(1)).setString(ArgumentMatchers.eq(1), ArgumentMatchers.eq("name"));
        Mockito.verify(mockPrepStmt, times(0)).setString(ArgumentMatchers.eq(2), Mockito.isA(String.class));
        jdbcConn.close();
    }
    
    @Test
    public void testPrepareScanByRoleStatementOnlyRoleNameEmpty() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.prepareScanByRoleStatement("", "name");
        Mockito.verify(mockPrepStmt, times(1)).setString(ArgumentMatchers.eq(1), ArgumentMatchers.eq("name"));
        Mockito.verify(mockPrepStmt, times(0)).setString(ArgumentMatchers.eq(2), Mockito.isA(String.class));
        jdbcConn.close();
    }
    
    @Test
    public void testPrepareScanByRoleStatementOnlyRoleMemberNull() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.prepareScanByRoleStatement("user.member", null);
        Mockito.verify(mockPrepStmt, times(1)).setString(ArgumentMatchers.eq(1), ArgumentMatchers.eq("user.member"));
        Mockito.verify(mockPrepStmt, times(0)).setString(ArgumentMatchers.eq(2), Mockito.isA(String.class));
        jdbcConn.close();
    }
    
    @Test
    public void testPrepareScanByRoleStatementOnlyRoleMemberEmpty() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.prepareScanByRoleStatement("user.member", "");
        Mockito.verify(mockPrepStmt, times(1)).setString(ArgumentMatchers.eq(1), ArgumentMatchers.eq("user.member"));
        Mockito.verify(mockPrepStmt, times(0)).setString(ArgumentMatchers.eq(2), Mockito.isA(String.class));
        jdbcConn.close();
    }
    
    @Test
    public void testPrepareScanByRoleStatementEmptyRoleMember() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        jdbcConn.prepareScanByRoleStatement(null, null);
        Mockito.verify(mockPrepStmt, times(0)).setString(Mockito.anyInt(), Mockito.isA(String.class));
        
        jdbcConn.prepareScanByRoleStatement(null, "");
        Mockito.verify(mockPrepStmt, times(0)).setString(Mockito.anyInt(), Mockito.isA(String.class));
        
        jdbcConn.prepareScanByRoleStatement("", null);
        Mockito.verify(mockPrepStmt, times(0)).setString(Mockito.anyInt(), Mockito.isA(String.class));

        jdbcConn.prepareScanByRoleStatement("", "");
        Mockito.verify(mockPrepStmt, times(0)).setString(Mockito.anyInt(), Mockito.isA(String.class));

        jdbcConn.close();
    }
    
    @Test
    public void testListEntities() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getString(1))
            .thenReturn("z-entity")
            .thenReturn("a-entity")
            .thenReturn("b-entity");
        
        List<String> entities = jdbcConn.listEntities("my-domain");
        
        // data back is sorted
        
        assertEquals(3, entities.size());
        assertEquals("a-entity", entities.get(0));
        assertEquals("b-entity", entities.get(1));
        assertEquals("z-entity", entities.get(2));
        jdbcConn.close();
    }
    
    @Test
    public void testCountEntities() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id/same for count
        Mockito.when(mockResultSet.next()).thenReturn(true);
        
        assertEquals(jdbcConn.countEntities("my-domain"), 5);
        jdbcConn.close();
    }
    
    @Test
    public void testCountEntitiesNoResult() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain/count
        
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        
        assertEquals(jdbcConn.countEntities("my-domain"), 0);
        jdbcConn.close();
    }
    
    @Test
    public void testCountEntitiesInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id
        
        try {
            jdbcConn.countEntities("my-domain");
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testCountEntitiesException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true); // this one is for domain id
        
        Mockito.when(mockPrepStmt.executeQuery())
            .thenReturn(mockResultSet)
            .thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.countEntities("my-domain");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testGetEntity() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn("{\"value\":1}").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_VALUE);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // domain id
    
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Entity entity = jdbcConn.getEntity("my-domain", "entity1");
        assertNotNull(entity);
        assertEquals("entity1", entity.getName());
        assertEquals("{\"value\":1}", JSON.string(entity.getValue()));
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "entity1");
        jdbcConn.close();
    }
    
    @Test
    public void testGetEntityNotFound() throws Exception {

        Mockito.when(mockResultSet.next())
            .thenReturn(true) // for domain id
            .thenReturn(false);
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Entity entity = jdbcConn.getEntity("my-domain", "entity1");
        assertNull(entity);
        jdbcConn.close();
    }
    
    @Test
    public void testGetEntityDomainNotFound() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        try {
            jdbcConn.getEntity("my-domain", "entity1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testGetEntityException() throws Exception {

        Mockito.when(mockPrepStmt.executeQuery())
            .thenReturn(mockResultSet)
            .thenThrow(new SQLException("failed operation", "state", 1001));

        Mockito.when(mockResultSet.next())
            .thenReturn(true); // for domain id
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id
    
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        try {
            jdbcConn.getEntity("my-domain", "entity1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertEntity() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Entity entity = new Entity().setName("entity1").setValue(JSON.fromString("{\"value\":1}", Struct.class));

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        boolean requestSuccess = jdbcConn.insertEntity("my-domain", entity);
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "entity1");
        jdbcConn.close();
    }
    
    @Test
    public void testInsertEntityInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Entity entity = new Entity().setName("entity1").setValue(JSON.fromString("{\"value\":1}", Struct.class));
        Mockito.when(mockResultSet.next()).thenReturn(false);

        try {
            jdbcConn.insertEntity("my-domain", entity);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertEntityException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Entity entity = new Entity().setName("entity1").setValue(JSON.fromString("{\"value\":1}", Struct.class));

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.insertEntity("my-domain", entity);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateEntity() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Entity entity = new Entity().setName("entity1").setValue(JSON.fromString("{\"value\":1}", Struct.class));

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        boolean requestSuccess = jdbcConn.updateEntity("my-domain", entity);
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "{\"value\":1}");
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "entity1");
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateEntityInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Entity entity = new Entity().setName("entity1").setValue(JSON.fromString("{\"value\":1}", Struct.class));
        Mockito.when(mockResultSet.next()).thenReturn(false);

        try {
            jdbcConn.updateEntity("my-domain", entity);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateEntityException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Entity entity = new Entity().setName("entity1").setValue(JSON.fromString("{\"value\":1}", Struct.class));

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.updateEntity("my-domain", entity);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteEntity() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        boolean requestSuccess = jdbcConn.deleteEntity("my-domain", "entity1");
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "entity1");
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteEntityInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next()).thenReturn(false);

        try {
            jdbcConn.deleteEntity("my-domain", "entity1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteEntityException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.deleteEntity("my-domain", "entity1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertPrincipalAlreadyExists() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("already exists", "state", 1062));
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(101).when(mockResultSet).getInt(1);

        int value = jdbcConn.insertPrincipal("domain.user1");
        assertEquals(101, value);
        jdbcConn.close();
    }
    
    @Test
    public void testInsertPrincipalException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.insertPrincipal("domain.user1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertPrincipalZeroAffected() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenReturn(0);
        int value = jdbcConn.insertPrincipal("domain.user1");
        assertEquals(0, value);
        jdbcConn.close();
    }
    
    @Test
    public void testInsertHostException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.insertHost("host1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertHostZeroAffected() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenReturn(0);
        int value = jdbcConn.insertHost("host1");
        assertEquals(0, value);
        jdbcConn.close();
    }
    
    @Test
    public void testListModifiedDomains() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true) // 3 domains
            .thenReturn(true).thenReturn(true).thenReturn(false);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
            .thenReturn("domain1").thenReturn("domain2").thenReturn("domain3"); // 3 domains
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ACCOUNT))
                .thenReturn("acct1").thenReturn("acct2").thenReturn("acct3"); // 3 domains
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_PRODUCT_ID))
                .thenReturn("1234").thenReturn("1235").thenReturn("1236"); // 3 domains
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);

        DomainModifiedList list = jdbcConn.listModifiedDomains(1454358900);
        
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(ArgumentMatchers.eq(1),
                ArgumentMatchers.eq(new java.sql.Timestamp(1454358900)), ArgumentMatchers.isA(Calendar.class));
        
        assertEquals(3, list.getNameModList().size());
        boolean domain1Found = false;
        boolean domain2Found = false;
        boolean domain3Found = false;
        for (DomainModified dom : list.getNameModList()) {
            switch (dom.getName()) {
                case "domain1":
                    domain1Found = true;
                    break;
                case "domain2":
                    domain2Found = true;
                    break;
                case "domain3":
                    domain3Found = true;
                    break;
            }
        }
        assertTrue(domain1Found);
        assertTrue(domain2Found);
        assertTrue(domain3Found);
        
        jdbcConn.close();
    }
    
    @Test
    public void testListModifiedDomainsNoEntries() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(false); // no entries

        DomainModifiedList list = jdbcConn.listModifiedDomains(1454358900);
        assertEquals(0, list.getNameModList().size());
        
        jdbcConn.close();
    }
    
    @Test
    public void testListModifiedDomainsException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.listModifiedDomains(1454358900);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testGetAthenzDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        // one-domain, 2 roles, 2 members altogether
        // 2 policies, 2 assertions
        // 1 service, 1 public key
        Mockito.when(mockResultSet.next()).thenReturn(true) // domain
            .thenReturn(true).thenReturn(true).thenReturn(false) // 2 roles
            .thenReturn(true).thenReturn(true).thenReturn(false) // 1 member each
            .thenReturn(true).thenReturn(true).thenReturn(false) // 2 policies
            .thenReturn(true).thenReturn(true).thenReturn(false) // 1 assertion each
            .thenReturn(true).thenReturn(false) // 1 service
            .thenReturn(true).thenReturn(false) // 1 public key
            .thenReturn(true).thenReturn(false); // 1 host
        
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
            .thenReturn("role1").thenReturn("role2") // role names
            .thenReturn("policy1").thenReturn("policy2") // policy names
            .thenReturn("service1"); // service name
        
        Mockito.when(mockResultSet.getString(1))
            .thenReturn("role1").thenReturn("role2") // role names
            .thenReturn("policy1").thenReturn("policy2") // policy names
            .thenReturn("service1"); // service names 
            
        Mockito.when(mockResultSet.getString(2))
            .thenReturn("user").thenReturn("user") // member domain names
            .thenReturn("host1"); // service host name
        Mockito.when(mockResultSet.getString(3)).thenReturn("user1").thenReturn("user2"); // member local names

        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);
        Mockito.doReturn(true).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_ENABLED);
        Mockito.doReturn(false).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_AUDIT_ENABLED);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_DESCRIPTION);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_ORG);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_UUID);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_TRUST);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_ACCOUNT);
        Mockito.doReturn(0).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_PRODUCT_ID);
        Mockito.doReturn(5).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_DOMAIN_ID);
        Mockito.doReturn("/usr/bin64/athenz").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_EXECTUABLE);
        Mockito.doReturn("users").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_SVC_GROUP);
        Mockito.doReturn("root").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_SVC_USER);
        Mockito.doReturn("http://server.athenzcompany.com").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_PROVIDER_ENDPOINT);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE))
            .thenReturn("role1").thenReturn("role2");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_RESOURCE))
            .thenReturn("my-domain:*").thenReturn("my-domain:service.*");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ACTION))
            .thenReturn("*").thenReturn("read");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_EFFECT))
            .thenReturn("ALLOW").thenReturn("DENY");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_KEY_ID)).thenReturn("zms1.zone1");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_KEY_VALUE)).thenReturn("Value1");
        
        AthenzDomain athenzDomain = jdbcConn.getAthenzDomain("my-domain");
        assertNotNull(athenzDomain);
        assertEquals("my-domain", athenzDomain.getDomain().getName());
        assertEquals(2, athenzDomain.getRoles().size());
        assertEquals(1, athenzDomain.getRoles().get(0).getRoleMembers().size());
        assertEquals(1, athenzDomain.getRoles().get(1).getRoleMembers().size());
        assertEquals(2, athenzDomain.getPolicies().size());
        assertEquals(1, athenzDomain.getPolicies().get(0).getAssertions().size());
        assertEquals(1, athenzDomain.getPolicies().get(1).getAssertions().size());
        assertEquals(1, athenzDomain.getServices().size());
        assertEquals(1, athenzDomain.getServices().get(0).getPublicKeys().size());
        assertEquals("zms1.zone1", athenzDomain.getServices().get(0).getPublicKeys().get(0).getId());
        assertEquals("Value1", athenzDomain.getServices().get(0).getPublicKeys().get(0).getKey());
        assertEquals(1, athenzDomain.getServices().get(0).getHosts().size());
        assertEquals("host1", athenzDomain.getServices().get(0).getHosts().get(0));

        jdbcConn.close();
    }

    @Test
    public void testSetName() {
        AthenzDomain athenzDomain = new AthenzDomain("my-domain");
        try {
            athenzDomain.setName("my-domain");
        } catch (Exception ex) {
            fail();
        }
        assertTrue(true);
    }
    
    @Test
    public void testCommit() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, false);
        assertFalse(jdbcConn.transactionCompleted);
        Mockito.verify(mockConn, times(1)).setAutoCommit(false);
        
        jdbcConn.commitChanges();
        assertTrue(jdbcConn.transactionCompleted);
        Mockito.verify(mockConn, times(1)).commit();
        Mockito.verify(mockConn, times(1)).setAutoCommit(true);
        
        jdbcConn.close();
    }
    
    @Test
    public void testCommitException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, false);
        assertFalse(jdbcConn.transactionCompleted);
        Mockito.verify(mockConn, times(1)).setAutoCommit(false);
        
        Mockito.doThrow(new SQLException("failed operation", "state", 1001)).when(mockConn).commit();

        try {
            jdbcConn.commitChanges();
            fail();
        } catch (ResourceException ex) {
            assertTrue(jdbcConn.transactionCompleted);
            Mockito.verify(mockConn, times(1)).commit();
        }
        
        jdbcConn.close();
    }
    
    @Test
    public void testRollback() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, false);
        assertFalse(jdbcConn.transactionCompleted);
        Mockito.verify(mockConn, times(1)).setAutoCommit(false);
        
        jdbcConn.rollbackChanges();
        assertTrue(jdbcConn.transactionCompleted);
        Mockito.verify(mockConn, times(1)).rollback();
        Mockito.verify(mockConn, times(1)).setAutoCommit(true);
        
        jdbcConn.close();
    }
    
    @Test
    public void testRollbackException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, false);
        assertFalse(jdbcConn.transactionCompleted);
        Mockito.verify(mockConn, times(1)).setAutoCommit(false);
        
        Mockito.doThrow(new SQLException("failed operation", "state", 1001)).when(mockConn).rollback();

        jdbcConn.rollbackChanges();
        assertTrue(jdbcConn.transactionCompleted);
        Mockito.verify(mockConn, times(1)).rollback();
        Mockito.verify(mockConn, times(1)).setAutoCommit(true);
        
        jdbcConn.close();
    }
    
    @Test
    public void testValidatePrincipalDomainInvalidValue() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, false);
        assertFalse(jdbcConn.validatePrincipalDomain("coretech"));
        assertFalse(jdbcConn.validatePrincipalDomain(".coretech"));
        assertFalse(jdbcConn.validatePrincipalDomain("coretech."));
        assertFalse(jdbcConn.validatePrincipalDomain("coretech.test."));
        jdbcConn.close();
    }
    
    @Test
    public void testValidatePrincipalDomainInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, false);
        Mockito.when(mockResultSet.next()).thenReturn(false);
        
        assertFalse(jdbcConn.validatePrincipalDomain("coretech.storage"));
        assertFalse(jdbcConn.validatePrincipalDomain("coretech.storage.db"));
        jdbcConn.close();
    }
    
    @Test
    public void testValidatePrincipalDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, false);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5);
        
        assertTrue(jdbcConn.validatePrincipalDomain("coretech.storage"));
        assertTrue(jdbcConn.validatePrincipalDomain("coretech.storage.db"));
        assertTrue(jdbcConn.validatePrincipalDomain("user.user1"));
        assertTrue(jdbcConn.validatePrincipalDomain("*"));

        jdbcConn.close();
    }
    
    @Test
    public void testVerifyDomainAccountUniquenessEmptyAccount() throws Exception {

        // we are going to set the code to return exception so that we can
        // verify that we're returning before making any sql calls
        
        Mockito.when(mockResultSet.next()).thenReturn(false);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.verifyDomainAccountUniqueness("iaas.athenz", null, "unitTest");
        jdbcConn.verifyDomainAccountUniqueness("iaas.athenz", "", "unitTest");
        jdbcConn.close();
    }
    
    @Test
    public void testVerifyDomainAccountUniquenessPass() throws Exception {
        
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn("iaas.athenz").when(mockResultSet).getString(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.verifyDomainAccountUniqueness("iaas.athenz", "12345", "unitTest");
        jdbcConn.close();
    }
    
    @Test
    public void testVerifyDomainAccountUniquenessPassNoMatch() throws Exception {
        
        Mockito.when(mockResultSet.next()).thenReturn(false);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.verifyDomainAccountUniqueness("iaas.athenz", "12345", "unitTest");
        jdbcConn.close();
    }
    
    @Test
    public void testVerifyDomainAccountUniquenessFail() throws Exception {
        
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn("iaas.athenz.ci").when(mockResultSet).getString(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        try {
            jdbcConn.verifyDomainAccountUniqueness("iaas.athenz", "12345", "unitTest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("iaas.athenz.ci"));
        }
        jdbcConn.close();
    }
    
    @Test
    public void testVerifyDomainProductIdUniquenessEmptyId() throws Exception {

        // we are going to set the code to return exception so that we can
        // verify that we're returning before making any sql calls
        
        Mockito.when(mockResultSet.next()).thenReturn(false);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.verifyDomainProductIdUniqueness("iaas.athenz", null, "unitTest");
        jdbcConn.verifyDomainProductIdUniqueness("iaas.athenz", 0, "unitTest");
        jdbcConn.close();
    }
    
    @Test
    public void testVerifyDomainProductIdUniquenessPass() throws Exception {
        
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn("iaas.athenz").when(mockResultSet).getString(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.verifyDomainProductIdUniqueness("iaas.athenz", 1001, "unitTest");
        jdbcConn.close();
    }
    
    @Test
    public void testVerifyDomainProductIdUniquenessPassNoMatch() throws Exception {
        
        Mockito.when(mockResultSet.next()).thenReturn(false);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.verifyDomainProductIdUniqueness("iaas.athenz", 1001, "unitTest");
        jdbcConn.close();
    }
    
    @Test
    public void testVerifyDomainProductIdUniquenessFail() throws Exception {
        
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn("iaas.athenz.ci").when(mockResultSet).getString(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        try {
            jdbcConn.verifyDomainProductIdUniqueness("iaas.athenz", 1001, "unitTest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("iaas.athenz.ci"));
        }
        jdbcConn.close();
    }
    
    @Test
    public void testLookupDomainByAccount() throws Exception {
        
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn("iaas.athenz").when(mockResultSet).getString(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        String domainName = jdbcConn.lookupDomainById("1234", 0);
        assertEquals(domainName, "iaas.athenz");
        jdbcConn.close();
    }
    
    @Test
    public void testLookupDomainByProductId() throws Exception {
        
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn("iaas.athenz").when(mockResultSet).getString(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        String domainName = jdbcConn.lookupDomainById(null, 1001);
        assertEquals(domainName, "iaas.athenz");
        jdbcConn.close();
    }
    
    @Test
    public void testLookupDomainByRole() throws Exception {
        
        // 3 domain being returned
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
            .thenReturn("zdomain")
            .thenReturn("adomain")
            .thenReturn("bdomain");

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        List<String> domains = jdbcConn.lookupDomainByRole("user.user", "admin");
        assertEquals(3, domains.size());
        assertEquals("adomain", domains.get(0));
        assertEquals("bdomain", domains.get(1));
        assertEquals("zdomain", domains.get(2));
        jdbcConn.close();
    }
    
    @Test
    public void testLookupDomainByRoleDuplicateDomains() throws Exception {
        
        // 3 domain being returned but 2 are duplicates
        // so our end result must be the unique 2 only
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
            .thenReturn("zdomain")
            .thenReturn("adomain")
            .thenReturn("zdomain");

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        List<String> domains = jdbcConn.lookupDomainByRole("user.user", "admin");
        assertEquals(2, domains.size());
        assertEquals("adomain", domains.get(0));
        assertEquals("zdomain", domains.get(1));
        jdbcConn.close();
    }
    
    @Test
    public void testListRoleAuditLogsInvalidDomain() throws SQLException {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next())
            .thenReturn(false); // invalid domain
        
        try {
            jdbcConn.listRoleAuditLogs("my-domain", "role1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testListRoleAuditLogsInvalidRole() throws SQLException {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
            .thenReturn(true)   // domain id success
            .thenReturn(false); // role id failure
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id

        try {
            jdbcConn.listRoleAuditLogs("my-domain", "role1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testListRoleAuditLogsException() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
            .thenReturn(true)   // domain id success
            .thenReturn(true);  // role id success
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5)  // domain id
            .thenReturn(7); // role id
        Mockito.when(mockPrepStmt.executeQuery())
            .thenReturn(mockResultSet)
            .thenReturn(mockResultSet)
            .thenThrow(new SQLException("failed operation", "state", 1001));
        
        try {
            jdbcConn.listRoleAuditLogs("my-domain", "role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(500, ex.getCode());
        }
        jdbcConn.close();
    }
    
    @Test
    public void testListRoleAuditLogs() throws SQLException {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
            .thenReturn(true)   // domain id success
            .thenReturn(true)   // role id success
            .thenReturn(true)   // 2 log entries
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5)  // domain id
            .thenReturn(7); // role id
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ACTION))
            .thenReturn("ADD")
            .thenReturn("DELETE");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_MEMBER))
            .thenReturn("user.member1")
            .thenReturn("user.member2");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ADMIN))
            .thenReturn("user.admin1")
            .thenReturn("user.admin2");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_AUDIT_REF))
            .thenReturn("")
            .thenReturn("audit-ref");
        Mockito.doReturn(new java.sql.Timestamp(1454358916))
            .when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_CREATED);

        List<RoleAuditLog> logs = jdbcConn.listRoleAuditLogs("my-domain", "role1");
        assertNotNull(logs);
        assertEquals(2, logs.size());
        assertEquals("ADD", logs.get(0).getAction());
        assertEquals("user.admin1", logs.get(0).getAdmin());
        assertEquals("user.member1", logs.get(0).getMember());
        assertNull(logs.get(0).getAuditRef());
        assertEquals("DELETE", logs.get(1).getAction());
        assertEquals("user.admin2", logs.get(1).getAdmin());
        assertEquals("user.member2", logs.get(1).getMember());
        assertEquals("audit-ref", logs.get(1).getAuditRef());
        jdbcConn.close();
    }
    
    @Test
    public void testRoleIndex() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals("101:role1", jdbcConn.roleIndex("101", "role1"));
        jdbcConn.close();
    }

    @Test
    public void testPrepareRoleAssertionsStatementWithAction() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.prepareRoleAssertionsStatement("create");
        Mockito.verify(mockPrepStmt, times(1)).setString(ArgumentMatchers.eq(1), ArgumentMatchers.eq("create"));
        jdbcConn.close();
    }
    
    @Test
    public void testPrepareRoleAssertionsStatementEmptyAction() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.prepareRoleAssertionsStatement("");
        jdbcConn.prepareRoleAssertionsStatement(null);
        Mockito.verify(mockPrepStmt, times(0)).setString(ArgumentMatchers.isA(Integer.class), ArgumentMatchers.isA(String.class));
        jdbcConn.close();
    }
    
    @Test
    public void testPrepareRolePrinciaplsStatementWithPrincipal() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.prepareRolePrincipalsStatement("user.user1", "user", false);
        Mockito.verify(mockPrepStmt, times(1)).setString(ArgumentMatchers.eq(1), ArgumentMatchers.eq("user.user1"));
        jdbcConn.close();
    }
    
    @Test
    public void testPrepareRolePrinciaplsStatementEmptyPrincipal() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.prepareRolePrincipalsStatement("", "user", false);
        jdbcConn.prepareRolePrincipalsStatement(null, "user", false);
        Mockito.verify(mockPrepStmt, times(0)).setString(ArgumentMatchers.isA(Integer.class), ArgumentMatchers.isA(String.class));
        jdbcConn.close();
    }
    
    @Test
    public void testGetRoleAssertions() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
            .thenReturn("dom1")
            .thenReturn("dom1")
            .thenReturn("dom2");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_DOMAIN_ID))
            .thenReturn("101")
            .thenReturn("101")
            .thenReturn("102");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE))
            .thenReturn("role1")
            .thenReturn("role1")
            .thenReturn("role3");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_RESOURCE))
            .thenReturn("resource1")
            .thenReturn("resource2")
            .thenReturn("resource3");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ACTION))
            .thenReturn("update");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_EFFECT))
            .thenReturn("ALLOW");
        
        Map<String, List<Assertion>> roleAssertions = jdbcConn.getRoleAssertions("update", "getRoleAssertions");
        assertEquals(2, roleAssertions.size());
        
        List<Assertion> assertions = roleAssertions.get("101:role1");
        assertEquals(2, assertions.size());

        assertEquals("dom1:role.role1", assertions.get(0).getRole());
        assertEquals("resource1", assertions.get(0).getResource());
        assertEquals("update", assertions.get(0).getAction());
        assertEquals("ALLOW", assertions.get(0).getEffect().toString());
        
        assertEquals("dom1:role.role1", assertions.get(1).getRole());
        assertEquals("resource2", assertions.get(1).getResource());
        assertEquals("update", assertions.get(1).getAction());
        assertEquals("ALLOW", assertions.get(1).getEffect().toString());
        
        assertions = roleAssertions.get("102:role3");
        assertEquals(1, assertions.size());

        assertEquals("dom2:role.role3", assertions.get(0).getRole());
        assertEquals("resource3", assertions.get(0).getResource());
        assertEquals("update", assertions.get(0).getAction());
        assertEquals("ALLOW", assertions.get(0).getEffect().toString());
        
        jdbcConn.close();
    }
    
    @Test
    public void testGetRolePrincipals() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
            .thenReturn("user.user1")
            .thenReturn("user.user2")
            .thenReturn("user.user3");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_DOMAIN_ID))
            .thenReturn("101")
            .thenReturn("101")
            .thenReturn("102");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE_NAME))
            .thenReturn("role1")
            .thenReturn("role1")
            .thenReturn("role3");
        
        Map<String, List<String>> rolePrincipals = jdbcConn.getRolePrincipals(null, false,
                "user", "getRolePrincipals");
        assertEquals(2, rolePrincipals.size());
        
        List<String> principals = rolePrincipals.get("101:role1");
        assertEquals(2, principals.size());

        assertEquals("user.user1", principals.get(0));
        assertEquals("user.user2", principals.get(1));
        
        principals = rolePrincipals.get("102:role3");
        assertEquals(1, principals.size());

        assertEquals("user.user3", principals.get(0));
        
        jdbcConn.close();
    }
    
    @Test
    public void testGetTrustedRoles() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
            .thenReturn("trole1")
            .thenReturn("trole2")
            .thenReturn("trole3");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_DOMAIN_ID))
            .thenReturn("101")
            .thenReturn("102")
            .thenReturn("103");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE))
            .thenReturn("role1")
            .thenReturn("role1")
            .thenReturn("role3");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ASSERT_DOMAIN_ID))
            .thenReturn("101")
            .thenReturn("101")
            .thenReturn("103");
        
        Map<String, List<String>> trustedRoles = jdbcConn.getTrustedRoles("getTrustedRoles");
        assertEquals(2, trustedRoles.size());
        
        List<String> roles = trustedRoles.get("101:role1");
        assertEquals(2, roles.size());

        assertEquals("101:trole1", roles.get(0));
        assertEquals("102:trole2", roles.get(1));
        
        roles = trustedRoles.get("103:role3");
        assertEquals(1, roles.size());

        assertEquals("103:trole3", roles.get(0));
        
        jdbcConn.close();
    }
    
    @Test
    public void testGetAwsDomains() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
            .thenReturn("dom1")
            .thenReturn("dom2")
            .thenReturn("dom3");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ACCOUNT))
            .thenReturn("101")
            .thenReturn("102")
            .thenReturn("103");
        
        Map<String, String> awsDomains = jdbcConn.getAwsDomains("getAwsDomains");
        assertEquals(3, awsDomains.size());
        
        assertEquals("101", awsDomains.get("dom1"));
        assertEquals("102", awsDomains.get("dom2"));
        assertEquals("103", awsDomains.get("dom3"));
        
        jdbcConn.close();
    }

    @Test
    public void testAddRoleAssertionsEmptyList() throws SQLException {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        List<Assertion> principalAssertions = new ArrayList<>();
        
        jdbcConn.addRoleAssertions(principalAssertions, null, null);
        assertEquals(0, principalAssertions.size());
        
        jdbcConn.addRoleAssertions(principalAssertions, new ArrayList<>(), null);
        assertEquals(0, principalAssertions.size());
        
        jdbcConn.close();
    }
    
    @Test
    public void testAddRoleAssertionsAwsDomainListEmpty() throws SQLException {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        List<Assertion> principalAssertions = new ArrayList<>();
        
        List<Assertion> roleAssertions = new ArrayList<>();
        Assertion assertion = new Assertion().setAction("update").setResource("dom1:resource").setRole("role");
        roleAssertions.add(assertion);
        
        jdbcConn.addRoleAssertions(principalAssertions, roleAssertions, null);
        assertEquals(1, principalAssertions.size());
        
        principalAssertions.clear();
        jdbcConn.addRoleAssertions(principalAssertions, roleAssertions, new HashMap<>());
        assertEquals(1, principalAssertions.size());
        
        jdbcConn.close();
    }
    
    @Test
    public void testAddRoleAssertions() throws SQLException {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        List<Assertion> principalAssertions = new ArrayList<>();
        
        List<Assertion> roleAssertions = new ArrayList<>();
        Assertion assertion = new Assertion().setAction("update").setResource("dom1:resource").setRole("role");
        roleAssertions.add(assertion);
        
        assertion = new Assertion().setAction("update").setResource("dom2:resource1").setRole("role");
        roleAssertions.add(assertion);
        
        assertion = new Assertion().setAction("update").setResource("resource3").setRole("role");
        roleAssertions.add(assertion);
        
        Map<String, String> awsDomains = new HashMap<>();
        awsDomains.put("dom1", "12345");
        
        // we're going to skip 2 invalid assertions - no aws domains
        
        jdbcConn.addRoleAssertions(principalAssertions, roleAssertions, awsDomains);
        assertEquals(1, principalAssertions.size());
        assertEquals("arn:aws:iam::12345:role/resource", principalAssertions.get(0).getResource());
        
        jdbcConn.close();
    }
    
    @Test
    public void testSqlError() throws SQLException {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        SQLException ex = new SQLException("sql-reason", "08S01", 9999);
        ResourceException rEx = (ResourceException) jdbcConn.sqlError(ex, "sqlError");
        assertEquals(ResourceException.CONFLICT, rEx.getCode());
        
        ex = new SQLException("sql-reason", "40001", 9999);
        rEx = (ResourceException) jdbcConn.sqlError(ex, "sqlError");
        assertEquals(ResourceException.CONFLICT, rEx.getCode());
        
        ex = new SQLException("sql-reason", "sql-state", 1290);
        rEx = (ResourceException) jdbcConn.sqlError(ex, "sqlError");
        assertEquals(ResourceException.GONE, rEx.getCode());
        
        ex = new SQLException("sql-reason", "sql-state", 1062);
        rEx = (ResourceException) jdbcConn.sqlError(ex, "sqlError");
        assertEquals(ResourceException.BAD_REQUEST, rEx.getCode());

        ex = new SQLTimeoutException("sql-reason", "sql-state", 1001);
        rEx = (ResourceException) jdbcConn.sqlError(ex, "sqlError");
        assertEquals(ResourceException.SERVICE_UNAVAILABLE, rEx.getCode());
        jdbcConn.close();
    }
    
    @Test
    public void testListResourceAccessNotRegisteredRolePrincipals() throws SQLException {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        // no role principals
        
        Mockito.when(mockResultSet.next())
            .thenReturn(false);
        
        // we must get back 404 since the user doesn't exist in system

        try {
            jdbcConn.listResourceAccess("user.user1", "update", "user");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.NOT_FOUND, ex.getCode());
        }
        
        jdbcConn.close();
    }
    
    @Test
    public void testListResourceAccessRegisteredRolePrincipals() throws SQLException {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        // no role principals
        
        Mockito.when(mockResultSet.next())
            .thenReturn(false) // no role principal return
            .thenReturn(true); // valid principal id
        Mockito.doReturn(7).when(mockResultSet).getInt(1);

        ResourceAccessList resourceAccessList = jdbcConn.listResourceAccess("user.user1", "update", "user");
        
        // we should get an empty assertion set for the principal
        
        List<ResourceAccess> resources = resourceAccessList.getResources();
        assertEquals(1, resources.size());
        ResourceAccess rsrcAccess = resources.get(0);
        assertEquals("user.user1", rsrcAccess.getPrincipal());
        List<Assertion> assertions = rsrcAccess.getAssertions();
        assertTrue(assertions.isEmpty());
        
        jdbcConn.close();
    }
    
    @Test
    public void testListResourceAccessEmptyRoleAssertions() throws SQLException {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false) // up to here is role principals
            .thenReturn(false); // we have no role assertions
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
            .thenReturn("user.user1")
            .thenReturn("user.user2")
            .thenReturn("user.user3");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_DOMAIN_ID))
            .thenReturn("101")
            .thenReturn("101")
            .thenReturn("102");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE_NAME))
            .thenReturn("role1")
            .thenReturn("role1")
            .thenReturn("role3");
        
        ResourceAccessList resourceAccessList = jdbcConn.listResourceAccess("user.user1", "update", "user");
        
        // we should get an empty assertion set for the principal
        
        List<ResourceAccess> resources = resourceAccessList.getResources();
        assertEquals(1, resources.size());
        ResourceAccess rsrcAccess = resources.get(0);
        assertEquals("user.user1", rsrcAccess.getPrincipal());
        List<Assertion> assertions = rsrcAccess.getAssertions();
        assertTrue(assertions.isEmpty());
        
        jdbcConn.close();
    }
    
    @Test
    public void testListResourceAccess() throws SQLException {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false) // up to here is role principals
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false) // up to here is role assertions
            .thenReturn(false); // no trusted role
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
            .thenReturn("user.user1")
            .thenReturn("user.user2")
            .thenReturn("user.user3") // up to here is role principals
            .thenReturn("dom1")
            .thenReturn("dom1")
            .thenReturn("dom2");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_DOMAIN_ID))
            .thenReturn("101")
            .thenReturn("101")
            .thenReturn("102") // up to here is role principals
            .thenReturn("101")
            .thenReturn("101")
            .thenReturn("102");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE_NAME))
            .thenReturn("role1")
            .thenReturn("role1")
            .thenReturn("role3");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE))
            .thenReturn("role1")
            .thenReturn("role1")
            .thenReturn("role3");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_RESOURCE))
            .thenReturn("resource1")
            .thenReturn("resource2")
            .thenReturn("resource3");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ACTION))
            .thenReturn("update");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_EFFECT))
            .thenReturn("ALLOW");
        
        ResourceAccessList resourceAccessList = jdbcConn.listResourceAccess(null, "update", "user");
        List<ResourceAccess> resources = resourceAccessList.getResources();
        assertEquals(3, resources.size());
        
        boolean userUser1 = false;
        boolean userUser2 = false;
        boolean userUser3 = false;
        for (ResourceAccess rsrcAccess : resources) {
            
            switch (rsrcAccess.getPrincipal()) {
                case "user.user1":
                    userUser1 = true;
                    assertEquals(2, rsrcAccess.getAssertions().size());
                    break;
                case "user.user2":
                    userUser2 = true;
                    assertEquals(2, rsrcAccess.getAssertions().size());
                    break;
                case "user.user3":
                    userUser3 = true;
                    assertEquals(1, rsrcAccess.getAssertions().size());
                    break;
            }
        }
        assertTrue(userUser1);
        assertTrue(userUser2);
        assertTrue(userUser3);
        jdbcConn.close();
    }
    
    @Test
    public void testListResourceAccessAws() throws SQLException {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false) // up to here is role principals
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false) // up to here is role assertions
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false) // up to here standard trusted roles
            .thenReturn(false) // up to here wildcard trusted roles
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false); // up to here is aws domains
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
            .thenReturn("user.user1")
            .thenReturn("user.user2")
            .thenReturn("user.user3.service") // up to here is role principals
            .thenReturn("dom1")
            .thenReturn("dom2")
            .thenReturn("dom3") // up to here is role assertions
            .thenReturn("trole1")
            .thenReturn("trole2")
            .thenReturn("trole3") // up to here trusted roles
            .thenReturn("dom1")
            .thenReturn("dom2");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_DOMAIN_ID))
            .thenReturn("101")
            .thenReturn("102")
            .thenReturn("103") // up to here is role principals
            .thenReturn("101")
            .thenReturn("102")
            .thenReturn("103") // up to here role assertions
            .thenReturn("101")
            .thenReturn("102")
            .thenReturn("103"); // up to here trusted roles
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE_NAME))
            .thenReturn("role1")
            .thenReturn("role2")
            .thenReturn("role3");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE))
            .thenReturn("role1")
            .thenReturn("role2")
            .thenReturn("role3") // up to here role assertions
            .thenReturn("role1")
            .thenReturn("role2")
            .thenReturn("role3"); // up to here trusted roles
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_RESOURCE))
            .thenReturn("dom1:role1")
            .thenReturn("dom2:role2")
            .thenReturn("resource3");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ACTION))
            .thenReturn("assume_aws_role");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_EFFECT))
            .thenReturn("ALLOW");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ACCOUNT))
            .thenReturn("12345")
            .thenReturn("12346");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ASSERT_DOMAIN_ID))
            .thenReturn("101")
            .thenReturn("102")
            .thenReturn("103");
        
        ResourceAccessList resourceAccessList = jdbcConn.listResourceAccess(null, "assume_aws_role", "user");
        List<ResourceAccess> resources = resourceAccessList.getResources();
        assertEquals(2, resources.size());
        
        boolean userUser1 = false;
        boolean userUser2 = false;
        boolean userUser3 = false; // must be skipped
        for (ResourceAccess rsrcAccess : resources) {
            
            switch (rsrcAccess.getPrincipal()) {
                case "user.user1":
                    userUser1 = true;
                    assertEquals(1, rsrcAccess.getAssertions().size());
                    assertEquals("arn:aws:iam::12345:role/role1", rsrcAccess.getAssertions().get(0).getResource());
                    break;
                case "user.user2":
                    userUser2 = true;
                    assertEquals(1, rsrcAccess.getAssertions().size());
                    assertEquals("arn:aws:iam::12346:role/role2", rsrcAccess.getAssertions().get(0).getResource());
                    break;
                case "user.user3.service":
                    userUser3 = true;
                    break;
            }
        }
        assertTrue(userUser1);
        assertTrue(userUser2);
        assertFalse(userUser3);
        jdbcConn.close();
    }
    
    @Test
    public void testGetResourceAccessObject() throws SQLException {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        ResourceAccess rsrcAccess = jdbcConn.getResourceAccessObject("user.user1", null);
        assertEquals("user.user1", rsrcAccess.getPrincipal());
        List<Assertion> assertions = rsrcAccess.getAssertions();
        assertTrue(assertions.isEmpty());
        
        List<Assertion> roleAssertions = new ArrayList<>();
        Assertion assertion = new Assertion().setAction("update").setRole("role").setResource("resource");
        roleAssertions.add(assertion);
        
        rsrcAccess = jdbcConn.getResourceAccessObject("user.user2", roleAssertions);
        assertEquals("user.user2", rsrcAccess.getPrincipal());
        assertions = rsrcAccess.getAssertions();
        assertEquals(1, assertions.size());
        Assertion testAssertion = assertions.get(0);
        assertEquals("update", testAssertion.getAction());
        assertEquals("role", testAssertion.getRole());
        assertEquals("resource", testAssertion.getResource());
        
        jdbcConn.close();
    }
    
    @Test
    public void testUpdatePolicyModTimestampSuccess() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // policy id
        
        boolean requestSuccess = jdbcConn.updatePolicyModTimestamp("my-domain", "policy1");
        assertTrue(requestSuccess);
        
        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        // get policy id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "policy1");
        // update policy time-stamp
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        jdbcConn.close();
    }
    
    @Test
    public void testUpdatePolicyModTimestampFailure() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // policy id
        
        boolean requestSuccess = jdbcConn.updatePolicyModTimestamp("my-domain", "policy1");
        assertFalse(requestSuccess);
        
        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        // get policy id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "policy1");
        // update policy time-stamp
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        jdbcConn.close();
    }
    
    @Test
    public void testUpdatePolicyModTimestampException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.updatePolicyModTimestamp("my-domain", "policy1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testGetAssertion() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE))
            .thenReturn("role1");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_RESOURCE))
            .thenReturn("my-domain:*");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ACTION))
            .thenReturn("*");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_EFFECT))
            .thenReturn("ALLOW");
        
        Assertion assertion = jdbcConn.getAssertion("my-domain", "policy1", 101L);
        
        assertEquals("my-domain:role.role1", assertion.getRole());
        assertEquals("my-domain:*", assertion.getResource());
        assertEquals("*", assertion.getAction());
        assertEquals("ALLOW", assertion.getEffect().toString());
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 101);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "policy1");
        
        jdbcConn.close();
    }
    
    @Test
    public void testGetAssertionNoMatch() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
            .thenReturn(false);

        Assertion assertion = jdbcConn.getAssertion("my-domain", "policy1", 101L);
        assertNull(assertion);
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 101);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "policy1");
        
        jdbcConn.close();
    }
    
    @Test
    public void testGetAssertionException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.getAssertion("my-domain", "policy1", 101L);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testPreparePrincipalScanStatementNoPrefix() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        jdbcConn.preparePrincipalScanStatement(null);
        Mockito.verify(mockPrepStmt, times(0)).setString(Mockito.anyInt(), Mockito.isA(String.class));
        jdbcConn.close();
    }
    
    @Test
    public void testPreparePrincipalScanStatementPrefix() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        jdbcConn.preparePrincipalScanStatement("athenz");
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "athenz.%");
        jdbcConn.close();
    }
    
    @Test
    public void testListPrincipals() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
            .thenReturn("user.joe")
            .thenReturn("user.jane")
            .thenReturn("user.doe")
            .thenReturn("user.jack");
        
        List<String> principals = jdbcConn.listPrincipals("user");
        
        assertEquals(4, principals.size());
        assertTrue(principals.contains("user.joe"));
        assertTrue(principals.contains("user.jane"));
        assertTrue(principals.contains("user.doe"));
        assertTrue(principals.contains("user.jack"));
        jdbcConn.close();
    }
    
    @Test
    public void testListPrincipalsException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));
        
        try {
            jdbcConn.listPrincipals("user");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testListPrincipalRolesForAllDomains() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // principal id
        
        // principal roles
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // get principal id
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
            .thenReturn("coretech")
            .thenReturn("sports")
            .thenReturn("sports")
            .thenReturn("weather");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE_NAME))
            .thenReturn("admin")
            .thenReturn("reader")
            .thenReturn("writer")
            .thenReturn("reader");
        
        List<PrincipalRole> roles = jdbcConn.listPrincipalRoles(null, "user.joe");
        
        assertEquals(4, roles.size());
        
        // get principal id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.joe");
        // get role list
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        
        boolean coretech_admin = false;
        boolean sports_reader = false;
        boolean sports_writer = false;
        boolean weather_reader = false;
        for (PrincipalRole role : roles) {
            if (role.getDomainName().equals("coretech") && role.getRoleName().equals("admin")) {
                coretech_admin = true;
            } else if (role.getDomainName().equals("sports") && role.getRoleName().equals("reader")) {
                sports_reader = true;
            } else if (role.getDomainName().equals("sports") && role.getRoleName().equals("writer")) {
                sports_writer = true;
            } else if (role.getDomainName().equals("weather") && role.getRoleName().equals("reader")) {
                weather_reader = true;
            }
        }
        assertTrue(coretech_admin);
        assertTrue(sports_reader);
        assertTrue(sports_writer);
        assertTrue(weather_reader);
        
        jdbcConn.close();
    }

    @Test
    public void testListPrincipalRolesForAllDomainsInvalidPrincipal() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.listPrincipalRoles(null, "user.joe");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        jdbcConn.close();
    }

    @Test
    public void testListPrincipalRolesForAllDomainsException() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockPrepStmt.executeQuery())
            .thenReturn(mockResultSet)
            .thenThrow(new SQLException("failed operation", "state", 1001));
        
        Mockito.when(mockResultSet.next())
            .thenReturn(true); // get principal id
        
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // principal id
        
        try {
            jdbcConn.listPrincipalRoles(null, "user.joe");
            fail();
        } catch (Exception ignored) {
        }
        
        // get principal id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.joe");
        // get role list
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        
        jdbcConn.close();
    }

    @Test
    public void testListPrincipalRolesForOneDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(3) // domain id
                .thenReturn(5); //principal id

        // principal roles
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // get domain id
                .thenReturn(true) // get principal id
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(false);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE_NAME))
                .thenReturn("admin")
                .thenReturn("reader")
                .thenReturn("writer");

        List<PrincipalRole> roles = jdbcConn.listPrincipalRoles("athenz", "user.joe");

        assertEquals(3, roles.size());

        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "athenz");
        // get principal id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.joe");
        // get role list
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 3);

        boolean role_admin = false;
        boolean role_reader = false;
        boolean role_writer = false;
        for (PrincipalRole role : roles) {
            switch (role.getRoleName()) {
                case "admin":
                    role_admin = true;
                    break;
                case "reader":
                    role_reader = true;
                    break;
                case "writer":
                    role_writer = true;
                    break;
            }
        }
        assertTrue(role_admin);
        assertTrue(role_reader);
        assertTrue(role_writer);

        jdbcConn.close();
    }

    @Test
    public void testListPrincipalRolesForOneDomainInvalidPrincipal() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenReturn(mockResultSet)
                .thenThrow(new SQLException("failed operation", "state", 1001));
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(7).when(mockResultSet).getInt(1); // domain id

        try {
            jdbcConn.listPrincipalRoles("athenz", "user.joe");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        jdbcConn.close();
    }

    @Test
    public void testListPrincipalRolesForOneDomainInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.listPrincipalRoles("athenz", "user.joe");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        jdbcConn.close();
    }

    @Test
    public void testListPrincipalRolesForOneDomainException() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery())
                .thenReturn(mockResultSet)
                .thenReturn(mockResultSet)
                .thenThrow(new SQLException("failed operation", "state", 1001));

        Mockito.when(mockResultSet.next())
                .thenReturn(true); // get domain/principal id

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(3)  // domain id
                .thenReturn(5); // principal id

        try {
            jdbcConn.listPrincipalRoles("athenz", "user.joe");
            fail();
        } catch (Exception ignored) {
        }

        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "athenz");
        // get principal id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.joe");
        // get role list
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 3);

        jdbcConn.close();
    }

    @Test
    public void testDeletePrincipalNoSubDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);

        boolean requestSuccess = jdbcConn.deletePrincipal("user.jake", false);
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.jake");
        Mockito.verify(mockPrepStmt, times(0)).setString(1, "user.jake.%");
        jdbcConn.close();
    }
    
    @Test
    public void testDeletePrincipalWithSubDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);

        boolean requestSuccess = jdbcConn.deletePrincipal("user.jake", true);
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.jake");
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.jake.%");
        jdbcConn.close();
    }
    
    @Test
    public void testDeletePrincipalDomainFailure() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        // domain delete is failure, but sub-domain is success
        // thus the result must be successful
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenReturn(0).thenReturn(1);
        Mockito.when(mockResultSet.next()).thenReturn(true);

        boolean requestSuccess = jdbcConn.deletePrincipal("user.jake", true);
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.jake");
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.jake.%");
        jdbcConn.close();
    }
    
    @Test
    public void testDeletePrincipalSubDomainFailure() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        // domain delete is success, but sub-domain is failure
        // thus the result must be successful
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenReturn(1).thenReturn(0);
        Mockito.when(mockResultSet.next()).thenReturn(true);

        boolean requestSuccess = jdbcConn.deletePrincipal("user.jake", true);
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.jake");
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.jake.%");
        jdbcConn.close();
    }
    
    @Test
    public void testDeletePrincipalFailure() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        // both delete requests as failure
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenReturn(0);
        Mockito.when(mockResultSet.next()).thenReturn(true);

        boolean requestSuccess = jdbcConn.deletePrincipal("user.jake", true);
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.jake");
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.jake.%");
        jdbcConn.close();
    }
    
    @Test
    public void testDeletePrincipalDomainException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockPrepStmt.executeUpdate())
            .thenThrow(new SQLException("failed operation", "state", 1001));
        
        try {
            jdbcConn.deletePrincipal("user.jake", true);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeletePrincipalSubDomainException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        
        Mockito.when(mockPrepStmt.executeUpdate())
            .thenReturn(1)
            .thenThrow(new SQLException("failed operation", "state", 1001));
        
        try {
            jdbcConn.deletePrincipal("user.jake", true);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testGetQuota() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(7).when(mockResultSet).getInt(1); // domain id
        Mockito.doReturn(10).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_ASSERTION);
        Mockito.doReturn(11).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_ROLE);
        Mockito.doReturn(12).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_ROLE_MEMBER);
        Mockito.doReturn(13).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_POLICY);
        Mockito.doReturn(14).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_SERVICE);
        Mockito.doReturn(15).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_SERVICE_HOST);
        Mockito.doReturn(16).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_PUBLIC_KEY);
        Mockito.doReturn(17).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_ENTITY);
        Mockito.doReturn(18).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_SUBDOMAIN);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Quota quota = jdbcConn.getQuota("athenz");
        assertNotNull(quota);
        assertEquals(quota.getAssertion(), 10);
        assertEquals(quota.getRole(), 11);
        assertEquals(quota.getRoleMember(), 12);
        assertEquals(quota.getPolicy(), 13);
        assertEquals(quota.getService(), 14);
        assertEquals(quota.getServiceHost(), 15);
        assertEquals(quota.getPublicKey(), 16);
        assertEquals(quota.getEntity(), 17);
        assertEquals(quota.getSubdomain(), 18);
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "athenz");
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        jdbcConn.close();
    }
    
    @Test
    public void testGetQuotaNull() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn(7).when(mockResultSet).getInt(1); // domain id

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Quota quota = jdbcConn.getQuota("athenz");
        assertNull(quota);
        jdbcConn.close();
    }
    
    @Test
    public void testGetQuotaException() throws Exception {

        Mockito.when(mockPrepStmt.executeQuery()).thenReturn(mockResultSet)
            .thenThrow(new SQLException("failed operation", "state", 1001));
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(7).when(mockResultSet).getInt(1); // domain id

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        try {
            jdbcConn.getQuota("athenz");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertQuota() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Quota quota = new Quota().setName("athenz")
                .setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13)
                .setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17)
                .setSubdomain(18);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        boolean requestSuccess = jdbcConn.insertQuota("athenz", quota);
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "athenz");
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 14);
        Mockito.verify(mockPrepStmt, times(1)).setInt(3, 15);
        Mockito.verify(mockPrepStmt, times(1)).setInt(4, 12);
        Mockito.verify(mockPrepStmt, times(1)).setInt(5, 10);
        Mockito.verify(mockPrepStmt, times(1)).setInt(6, 16);
        Mockito.verify(mockPrepStmt, times(1)).setInt(7, 17);
        Mockito.verify(mockPrepStmt, times(1)).setInt(8, 13);
        Mockito.verify(mockPrepStmt, times(1)).setInt(9, 11);
        Mockito.verify(mockPrepStmt, times(1)).setInt(10, 18);
        jdbcConn.close();
    }
    
    @Test
    public void testInsertQuotaInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Quota quota = new Quota().setName("athenz")
                .setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13)
                .setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17)
                .setSubdomain(18);
        
        Mockito.when(mockResultSet.next()).thenReturn(false);
        
        try {
            jdbcConn.insertQuota("athenz", quota);
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        jdbcConn.close();
    }
    
    @Test
    public void testInsertQuotaException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Quota quota = new Quota().setName("athenz")
                .setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13)
                .setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17)
                .setSubdomain(18);

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        try {
            jdbcConn.insertQuota("athenz", quota);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateQuota() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Quota quota = new Quota().setName("athenz")
                .setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13)
                .setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17)
                .setSubdomain(18);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        boolean requestSuccess = jdbcConn.updateQuota("athenz", quota);
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "athenz");
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 14);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 15);
        Mockito.verify(mockPrepStmt, times(1)).setInt(3, 12);
        Mockito.verify(mockPrepStmt, times(1)).setInt(4, 10);
        Mockito.verify(mockPrepStmt, times(1)).setInt(5, 16);
        Mockito.verify(mockPrepStmt, times(1)).setInt(6, 17);
        Mockito.verify(mockPrepStmt, times(1)).setInt(7, 13);
        Mockito.verify(mockPrepStmt, times(1)).setInt(8, 11);
        Mockito.verify(mockPrepStmt, times(1)).setInt(9, 18);
        Mockito.verify(mockPrepStmt, times(1)).setInt(10, 5); // domain id
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateQuotaInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Quota quota = new Quota().setName("athenz")
                .setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13)
                .setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17)
                .setSubdomain(18);
        
        Mockito.when(mockResultSet.next()).thenReturn(false);
        
        try {
            jdbcConn.updateQuota("athenz", quota);
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateQuotaException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Quota quota = new Quota().setName("athenz")
                .setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13)
                .setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17)
                .setSubdomain(18);

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        try {
            jdbcConn.updateQuota("athenz", quota);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteQuota() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id

        boolean requestSuccess = jdbcConn.deleteQuota("athenz");
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "athenz");
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteQuotaInvalidDomain() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(false);
        
        try {
            jdbcConn.deleteQuota("athenz");
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        jdbcConn.close();
    }
    
    @Test
    public void testDeleteQuotaException() throws Exception {
        
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id
        
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.deleteQuota("athenz");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        jdbcConn.close();
    }

    @Test
    public void testListDomainRoleMembersInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.listDomainRoleMembers("athenz");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        jdbcConn.close();
    }

    @Test
    public void testListDomainRoleMembersException() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery())
                .thenReturn(mockResultSet)
                .thenThrow(new SQLException("failed operation", "state", 1001));

        Mockito.when(mockResultSet.next())
                .thenReturn(true); // get domain id

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id

        try {
            jdbcConn.listDomainRoleMembers("athenz");
            fail();
        } catch (Exception ignored) {
        }

        // get principal id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "athenz");
        // get role list
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);

        jdbcConn.close();
    }

    @Test
    public void testListDomainRoleMembers() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(3); // domain id

        // domain role members
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // get domain id
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(false);

        Mockito.when(mockResultSet.getString(1))
                .thenReturn("admin")
                .thenReturn("reader")
                .thenReturn("writer");
        Mockito.when(mockResultSet.getString(2))
                .thenReturn("user.joe")
                .thenReturn("user.jane")
                .thenReturn("user.joe");
        Mockito.when(mockResultSet.getTimestamp(3))
                .thenReturn(new java.sql.Timestamp(1454358916))
                .thenReturn(null)
                .thenReturn(null);

        DomainRoleMembers domainRoleMembers = jdbcConn.listDomainRoleMembers("athenz");
        List<DomainRoleMember> members = domainRoleMembers.getMembers();
        assertEquals(2, members.size());

        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "athenz");
        // get role list
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 3);

        ZMSTestUtils.verifyDomainRoleMember(members, "user.joe", "admin", "writer");
        ZMSTestUtils.verifyDomainRoleMember(members, "user.jane", "reader");
        ZMSTestUtils.verifyDomainRoleMemberExpiry(members, "user.joe", "admin", Timestamp.fromMillis(1454358916000L));

        jdbcConn.close();
    }

    @Test
    public void testListDomainRoleMembersNoEntries() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(3); // domain id

        // domain role members
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // get domain id
                .thenReturn(false);

        DomainRoleMembers domainRoleMembers = jdbcConn.listDomainRoleMembers("athenz");
        assertNull(domainRoleMembers.getMembers());

        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "athenz");
        // get role list
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 3);

        jdbcConn.close();
    }
}
