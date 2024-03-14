/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
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
import com.yahoo.athenz.zms.store.AthenzDomain;
import com.yahoo.athenz.zms.store.ObjectStoreConnection;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.UUID;
import org.hamcrest.CoreMatchers;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.sql.*;
import java.util.Date;
import java.util.*;
import java.util.function.Function;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.testng.Assert.*;

public class JDBCConnectionTest {

    @Mock private PoolableDataSource mockDataSrc;
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
    public void testGetDomain() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(true).thenReturn(false);
        Mockito.doReturn("my-domain").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_NAME);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);
        Mockito.doReturn(true).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_ENABLED);
        Mockito.doReturn(false).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_AUDIT_ENABLED);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_DESCRIPTION);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_ORG);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_UUID);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_CERT_DNS_DOMAIN);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_APPLICATION_ID);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_SIGN_ALGORITHM);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_FILTER);
        Mockito.doReturn("12345").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_ACCOUNT);
        Mockito.doReturn(1001).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_YPM_ID);
        Mockito.doReturn(90).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_MEMBER_PURGE_EXPIRY_DAYS);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_AZURE_SUBSCRIPTION);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_GCP_PROJECT_ID);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_GCP_PROJECT_NUMBER);
        Mockito.doReturn("service1").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_BUSINESS_SERVICE);
        Mockito.doReturn("tag-key").when(mockResultSet).getString(1);
        Mockito.doReturn("tag-val").when(mockResultSet).getString(2);
        Mockito.doReturn("abcd-1234").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_PRODUCT_ID);
        Mockito.doReturn("production").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_ENVIRONMENT);
        Mockito.doReturn(3).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_FEATURE_FLAGS);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Domain domain = jdbcConn.getDomain("my-domain");
        assertNotNull(domain);
        assertEquals("my-domain", domain.getName());
        assertTrue(domain.getEnabled());
        assertFalse(domain.getAuditEnabled());
        assertNull(domain.getDescription());
        assertNull(domain.getOrg());
        assertNull(domain.getId());
        assertNull(domain.getUserAuthorityFilter());
        assertEquals("service1", domain.getBusinessService());
        assertEquals(domain.getMemberPurgeExpiryDays(), 90);
        assertEquals(domain.getProductId(), "abcd-1234");
        assertEquals(domain.getTags(), Collections.singletonMap("tag-key", new TagValueList().setList(Collections.singletonList("tag-val"))));
        assertEquals(domain.getFeatureFlags(), 3);
        assertEquals(domain.getEnvironment(), "production");
        jdbcConn.close();
    }

    @Test
    public void testGetDomainWithAuditEnabled() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(true).thenReturn(false);
        Mockito.doReturn("my-domain").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_NAME);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);
        Mockito.doReturn(true).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_ENABLED);
        Mockito.doReturn(true).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_AUDIT_ENABLED);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_DESCRIPTION);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_ORG);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_UUID);
        Mockito.doReturn("12345").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_ACCOUNT);
        Mockito.doReturn(1001).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_YPM_ID);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_CERT_DNS_DOMAIN);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_APPLICATION_ID);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_SIGN_ALGORITHM);
        Mockito.doReturn("OnShore").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_FILTER);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_AZURE_SUBSCRIPTION);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_GCP_PROJECT_ID);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_GCP_PROJECT_NUMBER);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_BUSINESS_SERVICE);
        Mockito.doReturn("tag-key").when(mockResultSet).getString(1);
        Mockito.doReturn("tag-val").when(mockResultSet).getString(2);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_PRODUCT_ID);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_ENVIRONMENT);
        Mockito.doReturn(0).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_FEATURE_FLAGS);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Domain domain = jdbcConn.getDomain("my-domain");
        assertNotNull(domain);
        assertEquals("my-domain", domain.getName());
        assertTrue(domain.getEnabled());
        assertTrue(domain.getAuditEnabled());
        assertNull(domain.getDescription());
        assertNull(domain.getOrg());
        assertNull(domain.getId());
        assertEquals("OnShore", domain.getUserAuthorityFilter());
        assertNull(domain.getProductId());
        assertNull(domain.getFeatureFlags());
        assertEquals(domain.getTags(), Collections.singletonMap("tag-key", new TagValueList().setList(Collections.singletonList("tag-val"))));
        assertNull(domain.getEnvironment());

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

        assertEquals(jdbcConn.getDomainId("my-domain"), 0);
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

        assertEquals(jdbcConn.getRoleId(3, "role1"), 0);
        jdbcConn.close();
    }

    @Test
    public void testGetGroupId() throws Exception {

        // first time success from mysql, second time failure so
        // we can verify we get the value from our cache

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn(9).when(mockResultSet).getInt(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals(9, jdbcConn.getGroupId(7, "group1"));
        assertEquals(9, jdbcConn.getGroupId(7, "group1"));

        jdbcConn.close();
    }

    @Test
    public void testGetGroupIdException() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        assertEquals(jdbcConn.getGroupId(3, "group1"), 0);
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

        assertEquals(jdbcConn.getPrincipalId("domain.user1"), 0);
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

        assertEquals(jdbcConn.getLastInsertId(), 0);
        jdbcConn.close();
    }

    @Test
    public void testGetPolicyId() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn(9).when(mockResultSet).getInt(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals(jdbcConn.getPolicyId(7, "policy1", null), 9);

        jdbcConn.close();
    }

    @Test
    public void testGetPolicyIdVersion() throws Exception {

        // first time success from mysql, second time failure so
        // we can verify we get the value from our cache

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn(9).when(mockResultSet).getInt(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertEquals(jdbcConn.getPolicyId(7, "policy1", "from-version"), 9);
        assertEquals(jdbcConn.getPolicyId(7, "policy1", "from-version"), 9);

        jdbcConn.close();
    }

    @Test
    public void testGetPolicyIdException() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        assertEquals(jdbcConn.getPolicyId(3, "policy1", null), 0);
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

        assertEquals(jdbcConn.getServiceId(3, "service1"), 0);
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

        assertEquals(jdbcConn.getHostId("host1"), 0);
        jdbcConn.close();
    }

    @Test
    public void testGetDomainAllFields() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(true).thenReturn(false);
        Mockito.doReturn("my-domain").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_NAME);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);
        Mockito.doReturn(true).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_ENABLED);
        Mockito.doReturn(true).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_AUDIT_ENABLED);
        Mockito.doReturn("my own domain").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_DESCRIPTION);
        Mockito.doReturn("cloud_services").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_ORG);
        Mockito.doReturn("e5e97240-e94e-11e4-8163-6d083f3f473f").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_UUID);
        Mockito.doReturn("12345").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_ACCOUNT);
        Mockito.doReturn(1001).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_YPM_ID);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_CERT_DNS_DOMAIN);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_APPLICATION_ID);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_SIGN_ALGORITHM);
        Mockito.doReturn("OnShore").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_FILTER);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_AZURE_SUBSCRIPTION);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_GCP_PROJECT_ID);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_GCP_PROJECT_NUMBER);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_BUSINESS_SERVICE);
        Mockito.doReturn("tag-key").when(mockResultSet).getString(1);
        Mockito.doReturn("tag-val").when(mockResultSet).getString(2);
        Mockito.doReturn("abcd-1234").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_PRODUCT_ID);
        Mockito.doReturn("production").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_ENVIRONMENT);
        Mockito.doReturn(1).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_FEATURE_FLAGS);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Domain domain = jdbcConn.getDomain("my-domain");
        assertNotNull(domain);
        assertEquals("my-domain", domain.getName());
        assertTrue(domain.getEnabled());
        assertTrue(domain.getAuditEnabled());
        assertEquals("my own domain", domain.getDescription());
        assertEquals("cloud_services", domain.getOrg());
        assertEquals(UUID.fromString("e5e97240-e94e-11e4-8163-6d083f3f473f"), domain.getId());
        assertEquals(domain.getUserAuthorityFilter(), "OnShore");
        assertEquals(domain.getProductId(), "abcd-1234");
        assertEquals(domain.getTags(), Collections.singletonMap("tag-key", new TagValueList().setList(Collections.singletonList("tag-val"))));
        assertEquals(domain.getFeatureFlags(), 1);
        assertEquals(domain.getEnvironment(), "production");

        jdbcConn.close();
    }

    @Test
    public void testGetDomainException() throws Exception {

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        try {
            jdbcConn.getDomain("my-domain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
                .setYpmId(1011)
                .setAzureSubscription("1234")
                .setGcpProject("gcp")
                .setGcpProjectNumber("1234")
                .setProductId("abcd-1234")
                .setFeatureFlags(3);

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
        Mockito.verify(mockPrepStmt, times(1)).setString(19, "1234");
        Mockito.verify(mockPrepStmt, times(1)).setString(22, "gcp");
        Mockito.verify(mockPrepStmt, times(1)).setString(23, "1234");
        Mockito.verify(mockPrepStmt, times(1)).setString(24, "abcd-1234");
        Mockito.verify(mockPrepStmt, times(1)).setInt(25, 3);
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
        Mockito.verify(mockPrepStmt, times(1)).setString(19, "");
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
                .setCertDnsDomain("athenz.cloud")
                .setMemberExpiryDays(45)
                .setServiceExpiryDays(50)
                .setGroupExpiryDays(55)
                .setTokenExpiryMins(10)
                .setServiceCertExpiryMins(20)
                .setRoleCertExpiryMins(30)
                .setSignAlgorithm("ec")
                .setUserAuthorityFilter("OnShore")
                .setAzureSubscription("azure")
                .setBusinessService("service1")
                .setMemberPurgeExpiryDays(90)
                .setGcpProject("gcp")
                .setGcpProjectNumber("1235")
                .setProductId("abcd-1234")
                .setFeatureFlags(3)
                .setEnvironment("production");

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
        Mockito.verify(mockPrepStmt, times(1)).setInt(10, 45);
        Mockito.verify(mockPrepStmt, times(1)).setInt(11, 10);
        Mockito.verify(mockPrepStmt, times(1)).setInt(12, 20);
        Mockito.verify(mockPrepStmt, times(1)).setInt(13, 30);
        Mockito.verify(mockPrepStmt, times(1)).setString(14, "ec");
        Mockito.verify(mockPrepStmt, times(1)).setInt(15, 50);
        Mockito.verify(mockPrepStmt, times(1)).setString(16, "OnShore");
        Mockito.verify(mockPrepStmt, times(1)).setInt(17, 55);
        Mockito.verify(mockPrepStmt, times(1)).setString(18, "azure");
        Mockito.verify(mockPrepStmt, times(1)).setString(19, "service1");
        Mockito.verify(mockPrepStmt, times(1)).setInt(20, 90);
        Mockito.verify(mockPrepStmt, times(1)).setString(21, "gcp");
        Mockito.verify(mockPrepStmt, times(1)).setString(22, "1235");
        Mockito.verify(mockPrepStmt, times(1)).setString(23, "abcd-1234");
        Mockito.verify(mockPrepStmt, times(1)).setInt(24, 3);
        Mockito.verify(mockPrepStmt, times(1)).setString(25, "production");
        Mockito.verify(mockPrepStmt, times(1)).setString(26, "my-domain");
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
        Mockito.verify(mockPrepStmt, times(1)).setInt(10, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(11, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(12, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(13, 0);
        Mockito.verify(mockPrepStmt, times(1)).setString(14, "");
        Mockito.verify(mockPrepStmt, times(1)).setInt(15, 0);
        Mockito.verify(mockPrepStmt, times(1)).setString(16, "");
        Mockito.verify(mockPrepStmt, times(1)).setInt(17, 0);
        Mockito.verify(mockPrepStmt, times(1)).setString(18, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(19, "");
        Mockito.verify(mockPrepStmt, times(1)).setInt(20, 0);
        Mockito.verify(mockPrepStmt, times(1)).setString(21, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(22, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(23, "");
        Mockito.verify(mockPrepStmt, times(1)).setInt(24, 0);
        Mockito.verify(mockPrepStmt, times(1)).setString(25, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(26, "my-domain");
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testGetAllExpiredRoleMembers() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(false);

        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_AS_DOMAIN_NAME))
                .thenReturn("dom1")
                .thenReturn("dom2");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_AS_ROLE_NAME))
                .thenReturn("role1")
                .thenReturn("role2");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_AS_PRINCIPAL_NAME))
                .thenReturn("user.test1")
                .thenReturn("user.test2");
        Mockito.when(mockResultSet.getTimestamp(ZMSConsts.DB_COLUMN_EXPIRATION))
                .thenReturn(new java.sql.Timestamp(123456))
                .thenReturn(new java.sql.Timestamp(654321));

        List<ExpiryMember> expectedMembers = jdbcConn.getAllExpiredRoleMembers(ZMSConsts.ZMS_PURGE_TASK_LIMIT_PER_CALL_DEF, 0, 180);

        ExpiryMember expectedMember1 = new ExpiryMember()
                .setDomainName("dom1")
                .setCollectionName("role1")
                .setPrincipalName("user.test1").setExpiration(Timestamp.fromMillis(123456));
        ExpiryMember expectedMember2 = new ExpiryMember()
                .setDomainName("dom2")
                .setCollectionName("role2")
                .setPrincipalName("user.test2").setExpiration(Timestamp.fromMillis(654321));

        assertEquals(2, expectedMembers.size());
        assertEquals(expectedMembers.get(0), expectedMember1);
        assertEquals(expectedMembers.get(1), expectedMember2);
        jdbcConn.close();
    }

    @Test
    public void testGetAllExpiredRoleMembersException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.getAllExpiredRoleMembers(ZMSConsts.ZMS_PURGE_TASK_LIMIT_PER_CALL_DEF, 0, 180);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testGetAllExpiredGroupMembers() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(false);

        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_AS_DOMAIN_NAME))
                .thenReturn("dom1")
                .thenReturn("dom2");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_AS_GROUP_NAME))
                .thenReturn("group1")
                .thenReturn("group2");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_AS_PRINCIPAL_NAME))
                .thenReturn("user.test1")
                .thenReturn("user.test2");
        Mockito.when(mockResultSet.getTimestamp(ZMSConsts.DB_COLUMN_EXPIRATION))
                .thenReturn(new java.sql.Timestamp(123456))
                .thenReturn(new java.sql.Timestamp(654321));

        List<ExpiryMember> expectedMembers = jdbcConn.getAllExpiredGroupMembers(ZMSConsts.ZMS_PURGE_TASK_LIMIT_PER_CALL_DEF, 0, 180);

        ExpiryMember expectedMember1 = new ExpiryMember()
                .setDomainName("dom1")
                .setCollectionName("group1")
                .setPrincipalName("user.test1").setExpiration(Timestamp.fromMillis(123456));
        ExpiryMember expectedMember2 = new ExpiryMember()
                .setDomainName("dom2")
                .setCollectionName("group2")
                .setPrincipalName("user.test2").setExpiration(Timestamp.fromMillis(654321));

        assertEquals(2, expectedMembers.size());
        assertEquals(expectedMembers.get(0), expectedMember1);
        assertEquals(expectedMembers.get(1), expectedMember2);
        jdbcConn.close();
    }

    @Test
    public void testGetAllExpiredGroupMembersException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.getAllExpiredGroupMembers(ZMSConsts.ZMS_PURGE_TASK_LIMIT_PER_CALL_DEF, 0, 180);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
        Mockito.doReturn("ec").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_SIGN_ALGORITHM);
        Mockito.doReturn(true).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_AUDIT_ENABLED);
        Mockito.doReturn(true).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_SELF_SERVE);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet)
                .getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);
        Mockito.doReturn(new java.sql.Timestamp(1454358917)).when(mockResultSet)
                .getTimestamp(ZMSConsts.DB_COLUMN_LAST_REVIEWED_TIME);
        Mockito.doReturn(true).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_REVIEW_ENABLED);
        Mockito.doReturn("role1,role2").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_NOTIFY_ROLES);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_EXPIRATION);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_FILTER);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_DESCRIPTION);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Role role = jdbcConn.getRole("my-domain", "role1");
        assertNotNull(role);
        assertEquals("my-domain:role.role1", role.getName());
        assertTrue(role.getAuditEnabled());
        assertTrue(role.getSelfServe());
        assertNull(role.getMemberExpiryDays());
        assertNull(role.getServiceExpiryDays());
        assertNull(role.getMemberReviewDays());
        assertNull(role.getServiceReviewDays());
        assertNull(role.getGroupReviewDays());
        assertNull(role.getUserAuthorityExpiration());
        assertNull(role.getUserAuthorityFilter());
        assertNull(role.getDescription());
        assertEquals(role.getSignAlgorithm(), "ec");
        assertEquals(role.getNotifyRoles(), "role1,role2");
        assertTrue(role.getReviewEnabled());
        assertEquals(role.getLastReviewedDate(), Timestamp.fromMillis(1454358917));

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");
        jdbcConn.close();
    }

    @Test
    public void testGetRoleWithDueDates() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn("role1").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_NAME);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_TRUST);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_SIGN_ALGORITHM);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_SIGN_ALGORITHM);
        Mockito.doReturn(true).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_AUDIT_ENABLED);
        Mockito.doReturn(true).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_SELF_SERVE);
        Mockito.doReturn(30).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_MEMBER_EXPIRY_DAYS);
        Mockito.doReturn(40).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_SERVICE_EXPIRY_DAYS);
        Mockito.doReturn(70).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_MEMBER_REVIEW_DAYS);
        Mockito.doReturn(80).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_SERVICE_REVIEW_DAYS);
        Mockito.doReturn(90).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_GROUP_REVIEW_DAYS);

        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet)
                .getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);
        Mockito.doReturn(new java.sql.Timestamp(1454358917)).when(mockResultSet)
                .getTimestamp(ZMSConsts.DB_COLUMN_LAST_REVIEWED_TIME);
        Mockito.doReturn(true).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_REVIEW_ENABLED);
        Mockito.doReturn("role1,role2").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_NOTIFY_ROLES);
        Mockito.doReturn("expiry").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_EXPIRATION);
        Mockito.doReturn("filter").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_FILTER);
        Mockito.doReturn("description").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_DESCRIPTION);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Role role = jdbcConn.getRole("my-domain", "role1");
        assertNotNull(role);
        assertEquals("my-domain:role.role1", role.getName());
        assertTrue(role.getAuditEnabled());
        assertTrue(role.getSelfServe());
        assertTrue(role.getReviewEnabled());
        assertEquals(role.getMemberExpiryDays(), Integer.valueOf(30));
        assertEquals(role.getServiceExpiryDays(), Integer.valueOf(40));
        assertEquals(role.getUserAuthorityExpiration(), "expiry");
        assertEquals(role.getUserAuthorityFilter(), "filter");
        assertEquals(role.getDescription(), "description");
        assertEquals(role.getMemberReviewDays(), Integer.valueOf(70));
        assertEquals(role.getServiceReviewDays(), Integer.valueOf(80));
        assertEquals(role.getGroupReviewDays(), Integer.valueOf(90));

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");
        jdbcConn.close();
    }

    @Test
    public void testGetRoleWithoutSelfServe() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn("role1").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_NAME);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_TRUST);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_SIGN_ALGORITHM);
        Mockito.doReturn(true).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_AUDIT_ENABLED);
        Mockito.doReturn(false).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_SELF_SERVE);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet)
                .getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);
        Mockito.doReturn(new java.sql.Timestamp(1454358917)).when(mockResultSet)
                .getTimestamp(ZMSConsts.DB_COLUMN_LAST_REVIEWED_TIME);
        Mockito.doReturn(false).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_REVIEW_ENABLED);
        Mockito.doReturn("role1,role2").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_NOTIFY_ROLES);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_EXPIRATION);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_FILTER);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_DESCRIPTION);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Role role = jdbcConn.getRole("my-domain", "role1");
        assertNotNull(role);
        assertEquals("my-domain:role.role1", role.getName());
        assertTrue(role.getAuditEnabled());
        assertNull(role.getSelfServe());
        assertNull(role.getUserAuthorityExpiration());
        assertNull(role.getUserAuthorityFilter());
        assertNull(role.getDescription());

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
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_SIGN_ALGORITHM);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet)
                .getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);
        Mockito.doReturn(new java.sql.Timestamp(1454358917)).when(mockResultSet)
                .getTimestamp(ZMSConsts.DB_COLUMN_LAST_REVIEWED_TIME);
        Mockito.doReturn(true).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_REVIEW_ENABLED);
        Mockito.doReturn("role1,role2").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_NOTIFY_ROLES);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_EXPIRATION);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_FILTER);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_DESCRIPTION);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Role role = jdbcConn.getRole("my-domain", "role1");
        assertNotNull(role);
        assertEquals("my-domain:role.role1", role.getName());
        assertEquals("trust.domain", role.getTrust());
        assertNull(role.getUserAuthorityExpiration());
        assertNull(role.getUserAuthorityFilter());

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
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertRole() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Role role = new Role().setName("my-domain:role.role1").setAuditEnabled(true)
                .setSelfServe(true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id

        boolean requestSuccess = jdbcConn.insertRole("my-domain", role);
        assertTrue(requestSuccess);

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "role1");
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "");
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(4, true);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(5, true);
        Mockito.verify(mockPrepStmt, times(1)).setInt(6, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(7, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(8, 0);
        Mockito.verify(mockPrepStmt, times(1)).setString(9, "");
        Mockito.verify(mockPrepStmt, times(1)).setInt(10, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(11, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(12, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(13, 0);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(14, false);
        Mockito.verify(mockPrepStmt, times(1)).setString(15, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(16, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(17, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(18, "");
        Mockito.verify(mockPrepStmt, times(1)).setInt(19, 0);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(20, false);
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(21, null);
        Mockito.verify(mockPrepStmt, times(1)).setInt(22, 0);

        jdbcConn.close();
    }

    @Test
    public void testInsertRoleWithDueDates() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Role role = new Role().setName("my-domain:role.role1").setAuditEnabled(true)
                .setSelfServe(true).setMemberExpiryDays(45).setMemberReviewDays(70).setServiceReviewDays(80)
                .setGroupReviewDays(90)
                .setReviewEnabled(true).setNotifyRoles("role1,role2")
                .setUserAuthorityFilter("filter").setUserAuthorityExpiration("expiry")
                .setDescription("description").setDeleteProtection(true)
                .setMaxMembers(3);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id

        boolean requestSuccess = jdbcConn.insertRole("my-domain", role);
        assertTrue(requestSuccess);

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "role1");
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "");
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(4, true);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(5, true);
        Mockito.verify(mockPrepStmt, times(1)).setInt(6, 45);
        Mockito.verify(mockPrepStmt, times(1)).setInt(7, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(8, 0);
        Mockito.verify(mockPrepStmt, times(1)).setString(9, "");
        Mockito.verify(mockPrepStmt, times(1)).setInt(10, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(11, 70);
        Mockito.verify(mockPrepStmt, times(1)).setInt(12, 80);
        Mockito.verify(mockPrepStmt, times(1)).setInt(13, 90);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(14, true);
        Mockito.verify(mockPrepStmt, times(1)).setString(15, "role1,role2");
        Mockito.verify(mockPrepStmt, times(1)).setString(16, "filter");
        Mockito.verify(mockPrepStmt, times(1)).setString(17, "expiry");
        Mockito.verify(mockPrepStmt, times(1)).setString(18, "description");
        Mockito.verify(mockPrepStmt, times(1)).setInt(19, 0);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(20, true);
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(21, null);
        Mockito.verify(mockPrepStmt, times(1)).setInt(22, 3);

        jdbcConn.close();
    }

    @Test
    public void testInsertRoleInvalidRoleDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Role role = new Role().setName("my-domain2:role.role1");

        try {
            jdbcConn.insertRole("my-domain", role);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(4, false);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(5, false);
        Mockito.verify(mockPrepStmt, times(1)).setInt(6, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(7, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(8, 0);
        Mockito.verify(mockPrepStmt, times(1)).setString(9, "");
        Mockito.verify(mockPrepStmt, times(1)).setInt(10, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(11, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(12, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(13, 0);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(14, false);
        Mockito.verify(mockPrepStmt, times(1)).setString(15, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(16, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(17, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(18, "");
        Mockito.verify(mockPrepStmt, times(1)).setInt(19, 0);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(20, false);
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(21, null);
        Mockito.verify(mockPrepStmt, times(1)).setInt(22, 0);

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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testUpdateRole() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Role role = new Role().setName("my-domain:role.role1").setAuditEnabled(true)
                .setSelfServe(true).setMemberExpiryDays(30).setTokenExpiryMins(10)
                .setCertExpiryMins(20).setSignAlgorithm("ec").setServiceExpiryDays(45)
                .setMemberReviewDays(70).setServiceReviewDays(80).setGroupExpiryDays(50)
                .setGroupReviewDays(90).setDeleteProtection(true)
                .setReviewEnabled(true).setNotifyRoles("role1,role2")
                .setUserAuthorityFilter("filter").setUserAuthorityExpiration("expiry")
                .setDescription("description").setLastReviewedDate(Timestamp.fromMillis(100))
                .setMaxMembers(10).setSelfRenew(true).setSelfRenewMins(99);

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
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(2, true);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(3, true);
        Mockito.verify(mockPrepStmt, times(1)).setInt(4, 30);
        Mockito.verify(mockPrepStmt, times(1)).setInt(5, 10);
        Mockito.verify(mockPrepStmt, times(1)).setInt(6, 20);
        Mockito.verify(mockPrepStmt, times(1)).setString(7, "ec");
        Mockito.verify(mockPrepStmt, times(1)).setInt(8, 45);
        Mockito.verify(mockPrepStmt, times(1)).setInt(9, 70);
        Mockito.verify(mockPrepStmt, times(1)).setInt(10, 80);
        Mockito.verify(mockPrepStmt, times(1)).setInt(11, 90);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(12, true);
        Mockito.verify(mockPrepStmt, times(1)).setString(13, "role1,role2");
        Mockito.verify(mockPrepStmt, times(1)).setString(14, "filter");
        Mockito.verify(mockPrepStmt, times(1)).setString(15, "expiry");
        Mockito.verify(mockPrepStmt, times(1)).setString(16, "description");
        Mockito.verify(mockPrepStmt, times(1)).setInt(17, 50);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(18, true);
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(19, new java.sql.Timestamp(100));
        Mockito.verify(mockPrepStmt, times(1)).setInt(20, 10);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(21, true);
        Mockito.verify(mockPrepStmt, times(1)).setInt(22, 99);
        Mockito.verify(mockPrepStmt, times(1)).setInt(23, 4);
        jdbcConn.close();
    }

    @Test
    public void testUpdateRoleWithTrust() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Role role = new Role().setName("my-domain:role.role1").setTrust("trust_domain")
                .setSignAlgorithm("rsa");

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
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(2, false);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(3, false);
        Mockito.verify(mockPrepStmt, times(1)).setInt(4, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(5, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(6, 0);
        Mockito.verify(mockPrepStmt, times(1)).setString(7, "rsa");
        Mockito.verify(mockPrepStmt, times(1)).setInt(8, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(9, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(10, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(11, 0);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(12, false);
        Mockito.verify(mockPrepStmt, times(1)).setString(13, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(14, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(15, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(16, "");
        Mockito.verify(mockPrepStmt, times(1)).setInt(17, 0);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(18, false);
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(19, null);
        Mockito.verify(mockPrepStmt, times(1)).setInt(20, 0);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(21, false);
        Mockito.verify(mockPrepStmt, times(1)).setInt(22, 0);
        Mockito.verify(mockPrepStmt, times(1)).setInt(23, 7);
        jdbcConn.close();
    }

    @Test
    public void testUpdateRoleInvalidRoleDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Role role = new Role().setName("my-domain2:role.role1");

        try {
            jdbcConn.updateRole("my-domain", role);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
    public void testUpdateRoleModTimestampFailureInvalidRole() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(true)
                .thenReturn(false);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id

        try {
            jdbcConn.updateRoleModTimestamp("my-domain", "role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdateRoleModTimestampException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.updateRoleModTimestamp("my-domain", "role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
    public void testDeleteRoleInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(false);

        try {
            jdbcConn.deleteRole("my-domain", "role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testListTrustedRolesWithWildcardsException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery())
                .thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.listTrustedRolesWithWildcards("*", "*-qa-test", "trust-domain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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

        List<RoleMember> roleMembers = jdbcConn.listRoleMembers("my-domain", "role1", false);

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
            jdbcConn.listRoleMembers("my-domain", "role1", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
            jdbcConn.listRoleMembers("my-domain", "role1", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
            jdbcConn.listRoleMembers("my-domain", "role1", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
        Mockito.verify(mockPrepStmt, times(1)).setString(6, "audit-ref");

        Mockito.verify(mockPrepStmt, times(1)).setString(5, "audit-ref");

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testInsertRoleMemberInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        try {
            jdbcConn.insertRoleMember("my-domain", "role1",
                    new RoleMember().setMemberName("user.user1"), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("my-domain"));
        }

        jdbcConn.close();
    }

    @Test
    public void testInsertRoleMemberInvalidRole() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(false);// this one is for role id

        try {
            jdbcConn.insertRoleMember("my-domain", "role1",
                    new RoleMember().setMemberName("user.user1"), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("role1"));
        }

        jdbcConn.close();
    }

    @Test
    public void testInsertRoleMemberInvalidPrincipal() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // role id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for role id
                .thenReturn(false); // validate principle domain

        try {
            jdbcConn.insertRoleMember("my-domain", "role1",
                    new RoleMember().setMemberName("user.user1"), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("user.user1"));
        }

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
        Timestamp reviewReminder = Timestamp.fromCurrentTime();
        roleMember.setReviewReminder(reviewReminder);
        java.sql.Timestamp javaReviewReminder = new java.sql.Timestamp(reviewReminder.toDate().getTime());
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
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(2, javaReviewReminder);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(3, true);
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "audit-ref");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setInt(6, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(7, 9);

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
        Mockito.verify(mockPrepStmt, times(1)).setString(6, "audit-ref");

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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
            .thenReturn(false) // principal does not exist
            .thenReturn(false); // last id returns 0

        // principal add returns success but unable to
        // fetch last id resulting principal id of 0

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.insertRoleMember("my-domain", "role1",
                    new RoleMember().setMemberName("user.user1"),
                    "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }

        jdbcConn.close();
    }

    @Test
    public void testInsertPendingRoleMember() throws Exception {

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
                new RoleMember().setApproved(false).setMemberName("user.user1"), "user.admin", "audit-ref");

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        // additional operation to check for roleMember exist using roleID and principal ID.
        Mockito.verify(mockPrepStmt, times(2)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(2)).setInt(2, 9);

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testInsertPendingRoleMemberException() throws Exception {

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

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(
                new SQLException("failed operation", "state", 1001));

        try {
             jdbcConn.insertRoleMember("my-domain", "role1",
                    new RoleMember().setApproved(false).setMemberName("user.user1"), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }

        jdbcConn.close();
    }

    @Test
    public void testInsertPendingRoleMemberUpdate() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // role id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.getString(1))
                        .thenReturn("ADD"); // pending state
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for role id
                .thenReturn(true) // validate principle domain
                .thenReturn(true) // principal id
                .thenReturn(true) // member exists
                .thenReturn(true); // this one is for pending state
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        long now = System.currentTimeMillis();
        boolean requestSuccess = jdbcConn.insertRoleMember("my-domain", "role1",
                new RoleMember()
                        .setApproved(false)
                        .setMemberName("user.user1")
                        .setExpiration(Timestamp.fromMillis(now))
                        .setReviewReminder(Timestamp.fromMillis(now))
                        .setPendingState("ADD"),
                "user.admin", "audit-ref");

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(1, new java.sql.Timestamp(now));
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(2, new java.sql.Timestamp(now));
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "audit-ref");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setInt(5, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(6, 9);

        // operation to check for roleMember exist using roleID and principal ID.
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 9);

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testInsertPendingRoleMemberUpdateException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // role id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.getString(1))
                .thenReturn("ADD"); // pending state
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for role id
                .thenReturn(true) // validate principle domain
                .thenReturn(true) // principal id
                .thenReturn(true) // member exists
                .thenReturn(true); // this one is for pending state
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(
                new SQLException("failed operation", "state", 1001));

        long now = System.currentTimeMillis();
        try {
            jdbcConn.insertRoleMember("my-domain", "role1",
                    new RoleMember()
                            .setApproved(false)
                            .setMemberName("user.user1")
                            .setExpiration(Timestamp.fromMillis(now))
                            .setReviewReminder(Timestamp.fromMillis(now))
                            .setPendingState("ADD"),
                    "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
    }

    @Test
    public void testGetRoleMemberYes() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true); // yes a member
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7); // role id

        Membership membership = jdbcConn.getRoleMember("my-domain", "role1", "user.user1", 0, false);

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.user1");

        assertEquals(membership.getMemberName(), "user.user1");
        assertEquals(membership.getRoleName(), "my-domain:role.role1");
        assertTrue(membership.getIsMember());
        assertTrue(membership.getApproved());
        jdbcConn.close();
    }

    @Test
    public void testGetRoleMemberPendingNoUser() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true); // yes a member
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // role id

        Membership membership = jdbcConn.getRoleMember("my-domain", "role1", "user.user1", 0, true);

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.user1");

        assertEquals(membership.getMemberName(), "user.user1");
        assertEquals(membership.getRoleName(), "my-domain:role.role1");
        assertTrue(membership.getIsMember());
        assertFalse(membership.getApproved());
        jdbcConn.close();
    }

    @Test
    public void testGetRoleMemberInvalidRole() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(true) //lookup domain
                .thenReturn(false); //lookup role;
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id

        try {
            jdbcConn.getRoleMember("my-domain", "role1", "user.user1", 0, false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("role1"));
        }

        jdbcConn.close();
    }

    @Test
    public void testGetRoleMemberYesWithExpirationAndReviewDate() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next())
                .thenReturn(true); // yes a member
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // role id
        long now = System.currentTimeMillis();
        long reviewDate = now + 1000;
        Mockito.when(mockResultSet.getTimestamp(ZMSConsts.DB_COLUMN_EXPIRATION))
                .thenReturn(new java.sql.Timestamp(now));
        Mockito.when(mockResultSet.getTimestamp(ZMSConsts.DB_COLUMN_REVIEW_REMINDER))
                .thenReturn(new java.sql.Timestamp(reviewDate));

        Membership membership = jdbcConn.getRoleMember("my-domain", "role1", "user.user1", now, false);

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(3, new java.sql.Timestamp(now));

        assertEquals(membership.getMemberName(), "user.user1");
        assertEquals(membership.getRoleName(), "my-domain:role.role1");
        assertEquals(membership.getExpiration(), Timestamp.fromMillis(now));
        assertEquals(membership.getReviewReminder(), Timestamp.fromMillis(reviewDate));
        assertTrue(membership.getIsMember());
        assertTrue(membership.getApproved());
        jdbcConn.close();
    }

    @Test
    public void testGetRoleMemberPendingYesWithExpirationAndReview() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // domain id
                .thenReturn(true) // role id
                .thenReturn(false) // not a regular member
                .thenReturn(true); // pending member
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // role id
        long now = System.currentTimeMillis();
        long reviewDate = now + 1000;

        Mockito.when(mockResultSet.getTimestamp(ZMSConsts.DB_COLUMN_EXPIRATION))
                .thenReturn(new java.sql.Timestamp(now));
        Mockito.when(mockResultSet.getTimestamp(ZMSConsts.DB_COLUMN_REVIEW_REMINDER))
                .thenReturn(new java.sql.Timestamp(reviewDate));

        Membership membership = jdbcConn.getRoleMember("my-domain", "role1", "user.user1", now, false);

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");

        Mockito.verify(mockPrepStmt, times(2)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(2)).setString(2, "user.user1");
        Mockito.verify(mockPrepStmt, times(2)).setTimestamp(3, new java.sql.Timestamp(now));

        assertEquals(membership.getMemberName(), "user.user1");
        assertEquals(membership.getRoleName(), "my-domain:role.role1");
        assertEquals(membership.getExpiration(), Timestamp.fromMillis(now));
        assertEquals(membership.getReviewReminder(), Timestamp.fromMillis(reviewDate));
        assertTrue(membership.getIsMember());
        assertFalse(membership.getApproved());
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

        Membership membership = jdbcConn.getRoleMember("my-domain", "role1", "user.user1", 0, false);

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");

        Mockito.verify(mockPrepStmt, times(2)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(2)).setString(2, "user.user1");

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
            jdbcConn.getRoleMember("my-domain", "role1", "user1", 0, false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testGetRoleMemberException() throws Exception {

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        try {
            jdbcConn.getRoleMember("my-domain", "role1", "user.user1", 0, false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteRoleMember()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5) // domain id
            .thenReturn(7) // role id
            .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for role id
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteExpiredRoleMember()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // role id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for role id
                .thenReturn(true) // principal id
                .thenReturn(true); // this for expiration

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.deleteExpiredRoleMember("my-domain", "role1", "user.user1",
                "user.admin", Timestamp.fromMillis(10000), "audit-ref");
        assertTrue(requestSuccess);

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        // we need additional operation for the audit log
        Mockito.verify(mockPrepStmt, times(2)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 9);

        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(3, new java.sql.Timestamp(10000));

        // the rest of the audit log details

        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "DELETE");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "audit-ref");

        jdbcConn.close();
    }

    @Test
    public void testDeleteExpiredRoleMemberInvalidDomain()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.deleteExpiredRoleMember("my-domain", "role1", "user.user1",
                    "user.admin", Timestamp.fromMillis(10000), "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteExpiredRoleMemberInvalidRole()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(false); // this one is for role id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.deleteExpiredRoleMember("my-domain", "role1", "user.user1",
                    "user.admin", Timestamp.fromMillis(10000), "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteExpiredRoleMemberInvalidPrincipalId()  throws Exception {
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
            jdbcConn.deleteExpiredRoleMember("my-domain", "role1", "user.user1",
                    "user.admin", Timestamp.fromMillis(10000), "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testGetPolicy() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn("policy1").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_NAME);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Policy policy = jdbcConn.getPolicy("my-domain", "policy1", null);
        assertNotNull(policy);
        assertEquals("my-domain:policy.policy1", policy.getName());

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "policy1");
        jdbcConn.close();
    }

    @Test
    public void testGetPolicyNotFound() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Policy policy = jdbcConn.getPolicy("my-domain", "policy1", null);
        assertNull(policy);

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "policy1");
        jdbcConn.close();
    }

    @Test
    public void testGetPolicyException() throws Exception {

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        try {
            jdbcConn.getPolicy("my-domain", "policy1", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
    public void testInsertPolicyInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Policy policy = new Policy().setName("my-domain:policy.policy1");

        Mockito.when(mockResultSet.next()).thenReturn(false);

        try {
            jdbcConn.insertPolicy("my-domain", policy);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
    public void testUpdatePolicyInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Policy policy = new Policy().setName("my-domain:policy.policy1");

        Mockito.when(mockResultSet.next()).thenReturn(false);

        try {
            jdbcConn.updatePolicy("my-domain", policy);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testUpdatePolicyInvalidPolicy() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Policy policy = new Policy().setName("my-domain:policy.policy1");

        Mockito.when(mockResultSet.next())
                .thenReturn(true)
                .thenReturn(false);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // return domain id

        try {
            jdbcConn.updatePolicy("my-domain", policy);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
    public void testDeletePolicyInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(false);

        try {
            jdbcConn.deletePolicy("my-domain", "policy1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
    public void testListPoliciesInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        try {
            jdbcConn.listPolicies("my-domain", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

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
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
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

        boolean requestSuccess = jdbcConn.insertAssertion("my-domain", "policy1", null, assertion);
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

        boolean requestSuccess = jdbcConn.insertAssertion("my-domain", "policy1", null, assertion);
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
            jdbcConn.insertAssertion("my-domain", "policy1", null, assertion);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
            jdbcConn.insertAssertion("my-domain", "policy1", null, assertion);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
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
            jdbcConn.insertAssertion("my-domain", "policy1", null, assertion);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
            jdbcConn.insertAssertion("my-domain", "policy1", null, assertion);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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

        boolean requestSuccess = jdbcConn.deleteAssertion("my-domain", "policy1", null, (long) 101);
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
            jdbcConn.deleteAssertion("my-domain", "policy1", null, (long) 101);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
            jdbcConn.deleteAssertion("my-domain", "policy1", null, (long) 101);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
            jdbcConn.deleteAssertion("my-domain", "policy1", null, (long) 101);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testGetServiceIdentity() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn("test description").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_DESCRIPTION);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_EXECUTABLE);
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
        Mockito.doReturn("/usr/bin64/athenz").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_EXECUTABLE);
        Mockito.doReturn("users").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_SVC_GROUP);
        Mockito.doReturn("root").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_SVC_USER);
        Mockito.doReturn("https://server.athenzcompany.com").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_PROVIDER_ENDPOINT);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        ServiceIdentity service = jdbcConn.getServiceIdentity("my-domain", "service1");
        assertNotNull(service);
        assertEquals("my-domain.service1", service.getName());
        assertEquals("/usr/bin64/athenz", service.getExecutable());
        assertEquals("users", service.getGroup());
        assertEquals("root", service.getUser());
        assertEquals("https://server.athenzcompany.com", service.getProviderEndpoint());

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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
    public void testInsertServiceIdentityInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        ServiceIdentity service = new ServiceIdentity().setName("my-domain.service1");

        Mockito.when(mockResultSet.next()).thenReturn(false);

        try {
            jdbcConn.insertServiceIdentity("my-domain", service);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
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
                .setProviderEndpoint("https://server.athenzcompany.com");

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
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "https://server.athenzcompany.com");
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
    public void testUpdateServiceIdentityInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        ServiceIdentity service = new ServiceIdentity().setName("my-domain.service1");

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // for domain id

        try {
            jdbcConn.updateServiceIdentity("my-domain", service);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testUpdateServiceIdentityInvalidService() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        ServiceIdentity service = new ServiceIdentity().setName("my-domain.service1");

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // for domain id
                .thenReturn(false); // for service id
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id

        try {
            jdbcConn.updateServiceIdentity("my-domain", service);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
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
                .setProviderEndpoint("https://server.athenzcompany.com");

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
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "https://server.athenzcompany.com");
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
    public void testDeleteServiceIdentityInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next()).thenReturn(false);

        try {
            jdbcConn.deleteServiceIdentity("my-domain", "service1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
    public void testListServiceIdentitiesInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        try {
            jdbcConn.listServiceIdentities("my-domain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

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
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
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
    public void testUpdateServiceModTimestampFailureInvalidService() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(true)
                .thenReturn(false);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id

        try {
            jdbcConn.updateServiceIdentityModTimestamp("my-domain", "service1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdateServiceModTimestampException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.updateServiceIdentityModTimestamp("my-domain", "service1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        assertEquals("https://server.athenzcompany.com", jdbcConn.saveValue("https://server.athenzcompany.com"));
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
        assertEquals("https://server.athenzcompany.com", jdbcConn.processInsertValue("https://server.athenzcompany.com"));
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
    public void testListPublicKeysInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        try {
            jdbcConn.listPublicKeys("my-domain", "service1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        jdbcConn.close();
    }

    @Test
    public void testListPublicKeysInvalidService() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(false); // this one is for service id

        try {
            jdbcConn.listPublicKeys("my-domain", "service1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testListAssertions() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7);

        Mockito.when(mockResultSet.next())
            .thenReturn(true) // this one is for domain id
            .thenReturn(true) // this one is for policy id
            .thenReturn(true) // for first assertion
            .thenReturn(true) // for second assertion
            .thenReturn(false) // for assertion
            .thenReturn(false); // for assertion condition
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
        Mockito.when(mockResultSet.getInt(ZMSConsts.DB_COLUMN_ASSERT_ID))
                .thenReturn(11)
                .thenReturn(12);

        List<Assertion> assertions = jdbcConn.listAssertions("my-domain", "policy1", null);

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
    public void testListAssertionsWithAssertionConditions() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7);

        Mockito.when(mockResultSet.next())
                .thenReturn(true)  // this one is for domain id
                .thenReturn(true)  // this one is for policy id
                .thenReturn(true)  // for first assertion
                .thenReturn(true)  // for second assertion
                .thenReturn(false) // for assertion
                .thenReturn(true)  // for first assertion condition
                .thenReturn(true)  // for second assertion condition
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
        int assertionId1 = 11;
        int assertionId2 = 12;
        Mockito.when(mockResultSet.getInt(ZMSConsts.DB_COLUMN_ASSERT_ID))
                .thenReturn(assertionId1)
                .thenReturn(assertionId2);

        Mockito.when(mockResultSet.getLong(ZMSConsts.DB_COLUMN_ASSERT_ID))
                .thenReturn((long) assertionId1)
                .thenReturn((long) assertionId2);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_KEY))
                .thenReturn("key1")
                .thenReturn("key2");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_OPERATOR))
                .thenReturn("EQUALS")
                .thenReturn("EQUALS");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_VALUE))
                .thenReturn("value1")
                .thenReturn("value2");
        Mockito.when(mockResultSet.getInt(ZMSConsts.DB_COLUMN_CONDITION_ID))
                .thenReturn(1)
                .thenReturn(2);

        List<Assertion> assertions = jdbcConn.listAssertions("my-domain", "policy1", null);

        assertEquals(2, assertions.size());
        assertEquals("my-domain:role.role1", assertions.get(0).getRole());
        assertEquals("my-domain:*", assertions.get(0).getResource());
        assertEquals("*", assertions.get(0).getAction());
        assertEquals("ALLOW", assertions.get(0).getEffect().toString());

        assertEquals(assertions.get(0).getConditions().getConditionsList().size(), 1);
        AssertionCondition ac1 = new AssertionCondition().setId(1);
        Map<String, AssertionConditionData> m1 = new HashMap<>();
        m1.put("key1", new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value1"));
        ac1.setConditionsMap(m1);
        assertEquals(assertions.get(0).getConditions().getConditionsList().get(0), ac1);

        assertEquals("my-domain:role.role2", assertions.get(1).getRole());
        assertEquals("my-domain:service.*", assertions.get(1).getResource());
        assertEquals("read", assertions.get(1).getAction());
        assertEquals("DENY", assertions.get(1).getEffect().toString());

        assertEquals(assertions.get(1).getConditions().getConditionsList().size(), 1);
        AssertionCondition ac2 = new AssertionCondition().setId(2);
        Map<String, AssertionConditionData> m2 = new HashMap<>();
        m2.put("key2", new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value2"));
        ac2.setConditionsMap(m2);
        assertEquals(assertions.get(1).getConditions().getConditionsList().get(0), ac2);

        jdbcConn.close();
    }

    @Test
    public void testListAssertionsInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id

        try {
            jdbcConn.listAssertions("my-domain", "policy1", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testListAssertionsInvalidPolicy() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(false); // this is for policy id

        try {
            jdbcConn.listAssertions("my-domain", "policy1", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }
    @Test
    public void testListAssertionsException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7);

        Mockito.when(mockPrepStmt.executeQuery())
                .thenReturn(mockResultSet) // this one is for domain id
                .thenReturn(mockResultSet) // this one is for policy id
                .thenThrow(new SQLException("failed operation", "state", 1001)); // for assertion conditions query

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for policy id

        try {
            jdbcConn.listAssertions("my-domain", "policy1", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }
    @Test
    public void testListAssertionsAssertionConditionsException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7);

        Mockito.when(mockPrepStmt.executeQuery())
                .thenReturn(mockResultSet) // this one is for domain id
                .thenReturn(mockResultSet) // this one is for policy id
                .thenReturn(mockResultSet) // for assertion query
                .thenThrow(new SQLException("failed operation", "state", 1001)); // for assertion conditions query

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for policy id
                .thenReturn(true) // for first assertion
                .thenReturn(false);

        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE))
                .thenReturn("role1");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_RESOURCE))
                .thenReturn("my-domain:*");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ACTION))
                .thenReturn("*");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_EFFECT))
                .thenReturn("ALLOW");
        Mockito.when(mockResultSet.getInt(ZMSConsts.DB_COLUMN_ASSERT_ID))
                .thenReturn(100);

        try {
            jdbcConn.listAssertions("my-domain", "policy1", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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

        assertEquals(jdbcConn.countAssertions("my-domain", "policy1", null), 1);
        jdbcConn.close();
    }

    @Test
    public void testCountAssertionsInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
            .thenReturn(false); // this one is for domain id

        try {
            jdbcConn.countAssertions("my-domain", "policy1", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
            jdbcConn.countAssertions("my-domain", "policy1", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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

        assertEquals(jdbcConn.countAssertions("my-domain", "policy1", null), 0);
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
            jdbcConn.countAssertions("my-domain", "policy1", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteServiceTags() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // service id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for service id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));

        assertTrue(jdbcConn.deleteServiceTags("service", "domain", tagKeys));

        // domain
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "domain");
        // service
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "service");
        // tag
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "tagKey");

        jdbcConn.close();
    }


    @Test
    public void testDeleteServiceTagsExceptions() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(0) // domain id
                .thenReturn(7) // domain id
                .thenReturn(0) //service id
                .thenReturn(20); //service id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for service id
        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();

        Mockito.when(mockConn.prepareStatement(ArgumentMatchers.isA(String.class)))
                .thenReturn(mockPrepStmt)
                .thenReturn(mockPrepStmt)
                .thenReturn(mockPrepStmt)
                .thenReturn(mockPrepStmt)
                .thenThrow(SQLException.class);

        Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));

        try {
            jdbcConn.deleteServiceTags("service", "domain", tagKeys);
            fail();
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
            assertEquals(e.getMessage(), "ResourceException (404): {code: 404, message: \"unknown domain - domain\"}");
        }

        try {
            jdbcConn.deleteServiceTags("service", "domain", tagKeys);
            fail();
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
            assertEquals(e.getMessage(), "ResourceException (404): {code: 404, message: \"unknown service - domain.service\"}");
        }
        try {
            jdbcConn.deleteServiceTags("service", "domain", tagKeys);
            fail();
        } catch (RuntimeException e) {
            assertEquals(e.getMessage(), "ResourceException (500): {code: 500, message: \"null, state: null, code: 0\"}");
        }


        jdbcConn.close();
    }

    @Test
    public void testDeleteServiceTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // service id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for service id
        Mockito.when(mockPrepStmt.executeUpdate())
                .thenThrow(new SQLException("sql error"));
        try {
            Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));
            jdbcConn.deleteServiceTags("service", "domain", tagKeys);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetServiceTags() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getString(1))
                .thenReturn("tagKey");
        Mockito.when(mockResultSet.getString(2))
                .thenReturn("tagVal1", "tagVal2");

        Mockito.when(mockResultSet.next())
                .thenReturn(true, true, false);

        Map<String, TagValueList> serviceTags = jdbcConn.getServiceTags("domain", "service");
        assertNotNull(serviceTags);

        TagValueList tagValues = serviceTags.get("tagKey");

        assertNotNull(tagValues);
        assertTrue(tagValues.getList().containsAll(Arrays.asList("tagVal1", "tagVal2")));

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "service");

        jdbcConn.close();
    }

    @Test
    public void testGetServiceTagsEmpty() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(false);

        Map<String, TagValueList> serviceTags = jdbcConn.getServiceTags("domain", "service");
        assertNull(serviceTags);
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "service");

        jdbcConn.close();
    }

    @Test
    public void testGetServiceTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(true).thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getServiceTags("domain", "service");
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
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
    public void testListServiceHostsInvalidService() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(false); // this one is for service id

        try {
            jdbcConn.listServiceHosts("my-domain", "service1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        jdbcConn.close();
    }

    @Test
    public void testListServiceHostsInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        try {
            jdbcConn.listServiceHosts("my-domain", "service1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testUpdateDomainTemplate() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        TemplateMetaData templateMetaData = new TemplateMetaData();
        templateMetaData.setLatestVersion(4);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
                .thenReturn(true); // this one is for domain id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.updateDomainTemplate("test-domain", "aws", templateMetaData);

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "test-domain");
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 4);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "aws");

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testUpdateDomainTemplateWithInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        TemplateMetaData templateMetaData = new TemplateMetaData();
        templateMetaData.setLatestVersion(4);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.updateDomainTemplate("test-domain", "aws_bastion", templateMetaData);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testListDomainTemplates() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
            .thenReturn(true) // domain id
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false);
        Mockito.when(mockResultSet.getString(1))
            .thenReturn("vipng")
            .thenReturn("platforms")
            .thenReturn("user_understanding");
        Mockito.when(mockResultSet.getInt(1)).thenReturn(1); // domain id

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

        Mockito.when(mockPrepStmt.executeQuery())
                .thenReturn(mockResultSet)
                .thenThrow(new SQLException("failed operation", "state", 1001));

        // return domain id for my-domain
        Mockito.doReturn(5).when(mockResultSet).getInt(1);
        Mockito.when(mockResultSet.next()).thenReturn(true);

        try {
            jdbcConn.listDomainTemplates("my-domain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
    public void testListEntitiesInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        try {
            jdbcConn.listEntities("my-domain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

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
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
        assertEquals("my-domain:entity.entity1", entity.getName());
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertEntity() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Entity entity = new Entity().setName("my-domain:entity.entity1")
                .setValue(JSON.fromString("{\"value\":1}", Struct.class));

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

        Entity entity = new Entity().setName("my-domain:entity.entity1")
                .setValue(JSON.fromString("{\"value\":1}", Struct.class));
        Mockito.when(mockResultSet.next()).thenReturn(false);

        try {
            jdbcConn.insertEntity("my-domain", entity);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertEntityException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Entity entity = new Entity().setName("my-domain:entity.entity1")
                .setValue(JSON.fromString("{\"value\":1}", Struct.class));

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.insertEntity("my-domain", entity);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testUpdateEntity() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Entity entity = new Entity().setName("my-domain:entity.entity1")
                .setValue(JSON.fromString("{\"value\":1}", Struct.class));

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

        Entity entity = new Entity().setName("my-domain:entity.entity1")
                .setValue(JSON.fromString("{\"value\":1}", Struct.class));
        Mockito.when(mockResultSet.next()).thenReturn(false);

        try {
            jdbcConn.updateEntity("my-domain", entity);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testUpdateEntityException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Entity entity = new Entity().setName("my-domain:entity.entity1")
                .setValue(JSON.fromString("{\"value\":1}", Struct.class));

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.updateEntity("my-domain", entity);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
    public void testInsertPrincipalAlreadyExistsWithDeadlock() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        // first we're going to throw already exists exception
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("already exists", "state", 1062));
        // when we look up th id againt we're going to return no response
        Mockito.when(mockResultSet.next()).thenReturn(false);

        try {
            jdbcConn.insertPrincipal("domain.user1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertPrincipalException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.insertPrincipal("domain.user1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertPrincipalZeroAffected() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeUpdate()).thenReturn(0);

        try {
            jdbcConn.insertPrincipal("domain.user1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertPrincipalZeroAffectedWithRetryOK() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeUpdate()).thenReturn(0);

        // when we try to read the principal id again, it will return success

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(101).when(mockResultSet).getInt(1);

        assertEquals(101, jdbcConn.insertPrincipal("domain.user1"));
        jdbcConn.close();
    }

    @Test
    public void testInsertHostException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.insertHost("host1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
        Mockito.when(mockResultSet.next()).thenReturn(true) // 3 domains without tags
            .thenReturn(true).thenReturn(true).thenReturn(false);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
            .thenReturn("domain1").thenReturn("domain2").thenReturn("domain3"); // 3 domains
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ACCOUNT))
                .thenReturn("acct1").thenReturn("acct2").thenReturn("acct3"); // 3 domains
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_YPM_ID))
                .thenReturn("1234").thenReturn("1235").thenReturn("1236"); // 3 domains
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_DESCRIPTION)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ORG)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_UUID)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_DESCRIPTION)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_SIGN_ALGORITHM)).thenReturn("rsa");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_CERT_DNS_DOMAIN)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_APPLICATION_ID)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NOTIFY_ROLES)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_FILTER)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_AZURE_SUBSCRIPTION)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_GCP_PROJECT_ID)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_GCP_PROJECT_NUMBER)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_BUSINESS_SERVICE)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_PRODUCT_ID)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ENVIRONMENT)).thenReturn("");

        DomainMetaList list = jdbcConn.listModifiedDomains(1454358900);

        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(ArgumentMatchers.eq(1),
                ArgumentMatchers.eq(new java.sql.Timestamp(1454358900)), ArgumentMatchers.isA(Calendar.class));

        assertEquals(3, list.getDomains().size());
        boolean domain1Found = false;
        boolean domain2Found = false;
        boolean domain3Found = false;
        for (Domain dom : list.getDomains()) {
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

        DomainMetaList list = jdbcConn.listModifiedDomains(1454358900);
        assertEquals(0, list.getDomains().size());

        jdbcConn.close();
    }

    @Test
    public void testListModifiedDomainsException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.listModifiedDomains(1454358900);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testGetAthenzDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        // one-domain, 2 roles, 2 members altogether
        // 2 group with 2 member
        // 2 policies, 2 assertions
        // 1 service, 1 public key
        Mockito.when(mockResultSet.next()).thenReturn(true) // domain
            .thenReturn(true).thenReturn(false) // domain with 1 tag
            .thenReturn(true).thenReturn(false) // domain with 1 contact
            .thenReturn(true).thenReturn(true).thenReturn(false) // 2 roles
            .thenReturn(true).thenReturn(true).thenReturn(false) // 1 member each
            .thenReturn(true).thenReturn(true).thenReturn(false)// roles tags
            .thenReturn(true).thenReturn(true).thenReturn(false) // 2 groups
            .thenReturn(true).thenReturn(true).thenReturn(false) // 1 member each
            .thenReturn(true).thenReturn(true).thenReturn(false)// groups tags
            .thenReturn(true).thenReturn(true).thenReturn(false) // 2 policies
            // 1 assertion each. true for first assertion, false for assertion condition for that assertion
            // true for second assertion, false for assertion condition for second assertion, last false to get out
            .thenReturn(true).thenReturn(true).thenReturn(false).thenReturn(false)
            .thenReturn(false) // no conditions
            .thenReturn(true).thenReturn(false) // 1 service
            .thenReturn(true).thenReturn(false) // 1 public key
            .thenReturn(true).thenReturn(false); // 1 host

        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_TYPE))
                .thenReturn("security-contact");

        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
            .thenReturn("user.joe") // contact name
            .thenReturn("role1").thenReturn("role2") // role names
            .thenReturn("group1").thenReturn("group2") // group names
            .thenReturn("service1"); // service name

        Mockito.when(mockResultSet.getString(1))
            .thenReturn("tag-key")  // tag key
            .thenReturn("role1").thenReturn("role2") // role names
            .thenReturn("role1").thenReturn( "role2") // roles tags
            .thenReturn("group1").thenReturn("group2") // group names
            .thenReturn("group1").thenReturn( "group2") // groups tags
            .thenReturn("service1"); // service names

        Mockito.when(mockResultSet.getInt(ZMSConsts.DB_COLUMN_POLICY_ID))
            .thenReturn(10001).thenReturn(10002) // policy ids
            .thenReturn(10001).thenReturn(10002);

        Mockito.when(mockResultSet.getString(2))
            .thenReturn("tag-val")  // tag value
            .thenReturn("user").thenReturn("user") // role member domain names
            .thenReturn("role1-tag-key").thenReturn("role2-tag-key") // roles tags
            .thenReturn("user").thenReturn("user") // group member domain names
            .thenReturn("group1-tag-key").thenReturn("group2-tag-key") // group tags
            .thenReturn("host1"); // service host name

        Mockito.when(mockResultSet.getString(3))
            .thenReturn("role1-tag-val").thenReturn("role2-tag-val") //tag values
            .thenReturn("group1-tag-val").thenReturn("group2-tag-val"); //tag values

        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);
        Mockito.doReturn(true).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_ENABLED);
        Mockito.doReturn(false).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_AUDIT_ENABLED);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_DESCRIPTION);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_ORG);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_UUID);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_TRUST);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_ACCOUNT);
        Mockito.doReturn(0).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_YPM_ID);
        Mockito.doReturn(5).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_DOMAIN_ID);
        Mockito.doReturn("/usr/bin64/athenz").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_EXECUTABLE);
        Mockito.doReturn("users").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_SVC_GROUP);
        Mockito.doReturn("root").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_SVC_USER);
        Mockito.doReturn("https://server.athenzcompany.com").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_PROVIDER_ENDPOINT);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE))
            .thenReturn("role1").thenReturn("role2");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_PRINCIPAL_GROUP))
                .thenReturn("group1").thenReturn("group2");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_RESOURCE))
            .thenReturn("my-domain:*").thenReturn("my-domain:service.*");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ACTION))
            .thenReturn("*").thenReturn("read");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_EFFECT))
            .thenReturn("ALLOW").thenReturn("DENY");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_KEY_ID)).thenReturn("zms1.zone1");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_KEY_VALUE)).thenReturn("Value1");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_KEY_VALUE)).thenReturn("Value1");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_SIGN_ALGORITHM)).thenReturn("rsa");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_CERT_DNS_DOMAIN)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_APPLICATION_ID)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NOTIFY_ROLES)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_FILTER)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_EXPIRATION)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_AZURE_SUBSCRIPTION)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_GCP_PROJECT_ID)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_GCP_PROJECT_NUMBER)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_BUSINESS_SERVICE)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_PRODUCT_ID)).thenReturn("");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ENVIRONMENT)).thenReturn("");

        AthenzDomain athenzDomain = jdbcConn.getAthenzDomain("my-domain");
        assertNotNull(athenzDomain);
        assertEquals("my-domain", athenzDomain.getDomain().getName());
        assertEquals(athenzDomain.getDomain().getSignAlgorithm(), "rsa");
        assertEquals(athenzDomain.getDomain().getContacts().size(), 1);
        assertEquals(athenzDomain.getDomain().getContacts().get("security-contact"), "user.joe");
        assertEquals(2, athenzDomain.getRoles().size());
        assertEquals(1, athenzDomain.getRoles().get(0).getRoleMembers().size());
        assertEquals(1, athenzDomain.getRoles().get(1).getRoleMembers().size());
        assertEquals(2, athenzDomain.getGroups().size());
        assertEquals(1, athenzDomain.getGroups().get(0).getGroupMembers().size());
        assertEquals(1, athenzDomain.getGroups().get(1).getGroupMembers().size());
        assertEquals(2, athenzDomain.getPolicies().size());
        assertEquals(1, athenzDomain.getPolicies().get(0).getAssertions().size());
        assertEquals(1, athenzDomain.getPolicies().get(1).getAssertions().size());
        assertEquals(1, athenzDomain.getServices().size());
        assertEquals(1, athenzDomain.getServices().get(0).getPublicKeys().size());
        assertEquals("zms1.zone1", athenzDomain.getServices().get(0).getPublicKeys().get(0).getId());
        assertEquals("Value1", athenzDomain.getServices().get(0).getPublicKeys().get(0).getKey());
        assertEquals(1, athenzDomain.getServices().get(0).getHosts().size());
        assertEquals("host1", athenzDomain.getServices().get(0).getHosts().get(0));

        assertEquals(athenzDomain.getRoles().get(0).getTags().get("role1-tag-key").getList().get(0), "role1-tag-val");
        assertEquals(athenzDomain.getRoles().get(1).getTags().get("role2-tag-key").getList().get(0), "role2-tag-val");

        assertEquals(athenzDomain.getGroups().get(0).getTags().get("group2-tag-key").getList().get(0), "group2-tag-val");
        assertEquals(athenzDomain.getGroups().get(1).getTags().get("group1-tag-key").getList().get(0), "group1-tag-val");

        jdbcConn.close();
    }

    @Test
    public void testGetAthenzDomainNotFound() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next()).thenReturn(false); // domain

        try {
            jdbcConn.getAthenzDomain("my-domain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

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
    public void testVerifyDomainSubscriptionUniquenessEmptyAccount() throws Exception {

        // we are going to set the code to return exception so that we can
        // verify that we're returning before making any sql calls

        Mockito.when(mockResultSet.next()).thenReturn(false);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.verifyDomainAzureSubscriptionUniqueness("iaas.athenz", null, "unitTest");
        jdbcConn.verifyDomainAzureSubscriptionUniqueness("iaas.athenz", "", "unitTest");
        jdbcConn.close();
    }

    @Test
    public void testVerifyDomainSubscriptionUniquenessFail() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn("iaas.athenz.ci").when(mockResultSet).getString(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        try {
            jdbcConn.verifyDomainAzureSubscriptionUniqueness("iaas.athenz", "azure-123", "unitTest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("iaas.athenz.ci"));
        }

        // turn off the check and verify it passes

        DomainOptions domainOptions = new DomainOptions();
        domainOptions.setEnforceUniqueAzureSubscriptions(false);
        jdbcConn.setDomainOptions(domainOptions);
        jdbcConn.verifyDomainAzureSubscriptionUniqueness("iaas.athenz", "azure-123", "unitTest");

        jdbcConn.close();
    }

    @Test
    public void testVerifyDomainProjectUniquenessEmptyAccount() throws Exception {

        // we are going to set the code to return exception so that we can
        // verify that we're returning before making any sql calls

        Mockito.when(mockResultSet.next()).thenReturn(false);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.verifyDomainGcpProjectUniqueness("iaas.athenz", null, "unitTest");
        jdbcConn.verifyDomainGcpProjectUniqueness("iaas.athenz", "", "unitTest");
        jdbcConn.close();
    }

    @Test
    public void testVerifyDomainProjectUniquenessFail() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn("iaas.athenz.ci").when(mockResultSet).getString(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        try {
            jdbcConn.verifyDomainGcpProjectUniqueness("iaas.athenz", "gcp-123", "unitTest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("iaas.athenz.ci"));
        }

        // turn off the check and verify it passes

        DomainOptions domainOptions = new DomainOptions();
        domainOptions.setEnforceUniqueGCPProjects(false);
        jdbcConn.setDomainOptions(domainOptions);
        jdbcConn.verifyDomainGcpProjectUniqueness("iaas.athenz", "gcp-123", "unitTest");

        jdbcConn.close();
    }

    @Test
    public void testVerifyDomainAccountUniquenessEmptyAccount() throws Exception {

        // we are going to set the code to return exception so that we can
        // verify that we're returning before making any sql calls

        Mockito.when(mockResultSet.next()).thenReturn(false);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.verifyDomainAwsAccountUniqueness("iaas.athenz", null, "unitTest");
        jdbcConn.verifyDomainAwsAccountUniqueness("iaas.athenz", "", "unitTest");
        jdbcConn.close();
    }

    @Test
    public void testVerifyDomainAccountUniquenessPass() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn("iaas.athenz").when(mockResultSet).getString(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.verifyDomainAwsAccountUniqueness("iaas.athenz", "12345", "unitTest");
        jdbcConn.close();
    }

    @Test
    public void testVerifyDomainAccountUniquenessPassNoMatch() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.verifyDomainAwsAccountUniqueness("iaas.athenz", "12345", "unitTest");
        jdbcConn.close();
    }

    @Test
    public void testVerifyDomainAccountUniquenessFail() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn("iaas.athenz.ci").when(mockResultSet).getString(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        try {
            jdbcConn.verifyDomainAwsAccountUniqueness("iaas.athenz", "12345", "unitTest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("iaas.athenz.ci"));
        }

        // turn off the check and verify it passes

        DomainOptions domainOptions = new DomainOptions();
        domainOptions.setEnforceUniqueAWSAccounts(false);
        jdbcConn.setDomainOptions(domainOptions);
        jdbcConn.verifyDomainAwsAccountUniqueness("iaas.athenz", "12345", "unitTest");

        jdbcConn.close();
    }

    @Test
    public void testVerifyDomainProductIdNumberUniquenessEmptyId() throws Exception {

        // we are going to set the code to return exception so that we can
        // verify that we're returning before making any sql calls

        Mockito.when(mockResultSet.next()).thenReturn(false);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.verifyDomainProductIdUniqueness("iaas.athenz", (Integer) null, "unitTest");
        jdbcConn.verifyDomainProductIdUniqueness("iaas.athenz", 0, "unitTest");
        jdbcConn.close();
    }

    @Test
    public void testVerifyDomainProductIdNumberUniquenessPass() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn("iaas.athenz").when(mockResultSet).getString(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.verifyDomainProductIdUniqueness("iaas.athenz", 1001, "unitTest");
        jdbcConn.close();
    }

    @Test
    public void testVerifyDomainProductIdNumberUniquenessPassNoMatch() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.verifyDomainProductIdUniqueness("iaas.athenz", 1001, "unitTest");
        jdbcConn.close();
    }

    @Test
    public void testVerifyDomainProductIdNumberUniquenessFail() throws Exception {

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

        // turn off the check and verify it passes

        DomainOptions domainOptions = new DomainOptions();
        domainOptions.setEnforceUniqueProductIds(false);
        jdbcConn.setDomainOptions(domainOptions);
        jdbcConn.verifyDomainProductIdUniqueness("iaas.athenz", 1001, "unitTest");

        jdbcConn.close();
    }

    @Test
    public void testVerifyDomainProductIdUniquenessEmptyId() throws Exception {

        // we are going to set the code to return exception so that we can
        // verify that we're returning before making any sql calls

        Mockito.when(mockResultSet.next()).thenReturn(false);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.verifyDomainProductIdUniqueness("iaas.athenz", (String) null, "unitTest");
        jdbcConn.verifyDomainProductIdUniqueness("iaas.athenz", "", "unitTest");
        jdbcConn.close();
    }

    @Test
    public void testVerifyDomainProductIdUniquenessPass() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn("iaas.athenz").when(mockResultSet).getString(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.verifyDomainProductIdUniqueness("iaas.athenz", "abcd-1001", "unitTest");
        jdbcConn.close();
    }

    @Test
    public void testVerifyDomainProductIdUniquenessPassNoMatch() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.verifyDomainProductIdUniqueness("iaas.athenz", "abcd-1001", "unitTest");
        jdbcConn.close();
    }

    @Test
    public void testVerifyDomainProductIdUniquenessFail() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn("iaas.athenz.ci").when(mockResultSet).getString(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        try {
            jdbcConn.verifyDomainProductIdUniqueness("iaas.athenz", "abcd-1001", "unitTest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("iaas.athenz.ci"));
        }
        // turn off the check and verify it passes

        DomainOptions domainOptions = new DomainOptions();
        domainOptions.setEnforceUniqueProductIds(false);
        jdbcConn.setDomainOptions(domainOptions);
        jdbcConn.verifyDomainProductIdUniqueness("iaas.athenz", "abcd-1001", "unitTest");
        jdbcConn.close();
    }

    @Test
    public void testLookupDomainByAwsAccount() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn("iaas.athenz").when(mockResultSet).getString(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        final String domainName = jdbcConn.lookupDomainByCloudProvider(ObjectStoreConnection.PROVIDER_AWS, "1234");
        assertEquals(domainName, "iaas.athenz");
        jdbcConn.close();
    }

    @Test
    public void testLookupDomainByAzureSubscription() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn("iaas.athenz").when(mockResultSet).getString(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        final String domainName = jdbcConn.lookupDomainByCloudProvider(ObjectStoreConnection.PROVIDER_AZURE, "azure");
        assertEquals(domainName, "iaas.athenz");
        jdbcConn.close();
    }

    @Test
    public void testLookupDomainByGcpProject() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn("iaas.athenz").when(mockResultSet).getString(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        final String domainName = jdbcConn.lookupDomainByCloudProvider(ObjectStoreConnection.PROVIDER_GCP, "gcp");
        assertEquals(domainName, "iaas.athenz");
        jdbcConn.close();
    }

    @Test
    public void testDomainByCloudProviderFailure() throws Exception {
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertNull(jdbcConn.lookupDomainByCloudProvider(null, "iaas.athenz"));
        assertNull(jdbcConn.lookupDomainByCloudProvider("unknown", "iaas.athenz"));
        assertNull(jdbcConn.lookupDomainByCloudProvider("aws", null));

        try {
            jdbcConn.lookupDomainByCloudProvider("aws", "iaas.athenz");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
    }

    @Test
    public void testLookupDomainByBusinessService() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn("iaas.athenz").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_NAME);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        List<String> domains = jdbcConn.lookupDomainByBusinessService("service");
        assertNotNull(domains);
        assertEquals(domains.size(), 1);
        assertEquals(domains.get(0), "iaas.athenz");
        jdbcConn.close();
    }

    @Test
    public void testLookupDomainByBusinessServiceException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.lookupDomainByBusinessService("service");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testLookupDomainByProductIdNumber() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn("iaas.athenz").when(mockResultSet).getString(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        String domainName = jdbcConn.lookupDomainByProductId(1001);
        assertEquals(domainName, "iaas.athenz");
        jdbcConn.close();
    }

    @Test
    public void testLookupDomainByProductIdNumberException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.lookupDomainByProductId(1001);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testLookupDomainByProductId() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.doReturn("iaas.athenz").when(mockResultSet).getString(1);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        String domainName = jdbcConn.lookupDomainByProductId("abcd-1001");
        assertEquals(domainName, "iaas.athenz");
        jdbcConn.close();
    }

    @Test
    public void testLookupDomainByProductIdException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.lookupDomainByProductId("abcd-1001");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
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
    public void testLookupDomainByRoleException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.lookupDomainByRole("user.user", "admin");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
            .thenReturn("user.user1")
            .thenReturn("user.user1");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_DOMAIN_ID))
            .thenReturn("101")
            .thenReturn("101")
            .thenReturn("102");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE_NAME))
            .thenReturn("role1")
            .thenReturn("role1")
            .thenReturn("role3");

        Set<String> rolePrincipals = jdbcConn.getRolePrincipals("user.user1", "getRolePrincipals");
        assertEquals(2, rolePrincipals.size());

        assertTrue(rolePrincipals.contains("101:role1"));
        assertTrue(rolePrincipals.contains("102:role3"));

        jdbcConn.close();
    }

    @Test
    public void testGetTrustedRoles() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.resetTrustRolesMap();

        Mockito.when(mockResultSet.next())
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false)
            .thenReturn(false) // end of first call
            .thenReturn(true)  // for timestamp lookup
            .thenReturn(true)  // single entry returned
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
        long now = System.currentTimeMillis();
        Mockito.when(mockResultSet.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED))
            .thenReturn(new java.sql.Timestamp(now + 30000));

        Map<String, List<String>> trustedRoles = jdbcConn.getTrustedRoles("getTrustedRoles");
        assertEquals(2, trustedRoles.size());

        List<String> roles = trustedRoles.get("101:role1");
        assertEquals(2, roles.size());

        assertEquals("101:trole1", roles.get(0));
        assertEquals("102:trole2", roles.get(1));

        roles = trustedRoles.get("103:role3");
        assertEquals(1, roles.size());

        assertEquals("103:trole3", roles.get(0));

        trustedRoles = jdbcConn.getTrustedRoles("getTrustedRoles");
        assertEquals(1, trustedRoles.size());

        roles = trustedRoles.get("103:role3");
        assertEquals(1, roles.size());

        assertEquals("103:trole3", roles.get(0));

        // when we call the update trust map with timestamp in the past, it should return
        // right away without making any mysql calls

        jdbcConn.updateTrustRolesMap(now - 30000, false, "trustMapTest");

        // second time calling the api should now give us an empty map
        // since our values will no longer match

        jdbcConn.updateTrustRolesMap(now + 60000, false, "trustMapTest");
        assertTrue(jdbcConn.getTrustedRoles("getTrustedRoles").isEmpty());

        // specifying timeout update with a second difference should not
        // trigger an update

        jdbcConn.updateTrustRolesMap(now + 60001, true, "trustMapTest");
        jdbcConn.close();
    }

    @Test
    public void testListDomainsByCloudProviderAWS() throws Exception {

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

        Map<String, String> awsDomains = jdbcConn.listDomainsByCloudProvider("aws");
        assertEquals(3, awsDomains.size());

        assertEquals("101", awsDomains.get("dom1"));
        assertEquals("102", awsDomains.get("dom2"));
        assertEquals("103", awsDomains.get("dom3"));

        jdbcConn.close();
    }

    @Test
    public void testListDomainsByCloudProviderGCP() throws Exception {

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
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_GCP_PROJECT_ID))
                .thenReturn("101")
                .thenReturn("102")
                .thenReturn("103");

        Map<String, String> gcpDomains = jdbcConn.listDomainsByCloudProvider("gcp");
        assertEquals(3, gcpDomains.size());

        assertEquals("101", gcpDomains.get("dom1"));
        assertEquals("102", gcpDomains.get("dom2"));
        assertEquals("103", gcpDomains.get("dom3"));

        jdbcConn.close();
    }

    @Test
    public void testListDomainsByCloudProviderAzure() throws Exception {

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
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_AZURE_SUBSCRIPTION))
                .thenReturn("101")
                .thenReturn("102")
                .thenReturn("103");

        Map<String, String> azureDomains = jdbcConn.listDomainsByCloudProvider("azure");
        assertEquals(3, azureDomains.size());

        assertEquals("101", azureDomains.get("dom1"));
        assertEquals("102", azureDomains.get("dom2"));
        assertEquals("103", azureDomains.get("dom3"));

        jdbcConn.close();
    }

    @Test
    public void testListDomainsByCloudProviderException() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("sql error"));

        try {
            jdbcConn.listDomainsByCloudProvider("aws");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testListDomainsByCloudProviderUnknown() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        assertNull(jdbcConn.listDomainsByCloudProvider("unknown"));
        jdbcConn.close();
    }

    @Test
    public void testAddRoleAssertionsEmptyList() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        List<Assertion> principalAssertions = new ArrayList<>();

        jdbcConn.addRoleAssertions(principalAssertions, null);
        assertEquals(0, principalAssertions.size());

        jdbcConn.addRoleAssertions(principalAssertions, new ArrayList<>());
        assertEquals(0, principalAssertions.size());

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

        jdbcConn.addRoleAssertions(principalAssertions, roleAssertions);
        assertEquals(3, principalAssertions.size());
        assertEquals("dom1:resource", principalAssertions.get(0).getResource());
        assertEquals("dom2:resource1", principalAssertions.get(1).getResource());
        assertEquals("resource3", principalAssertions.get(2).getResource());

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
        jdbcConn.resetTrustRolesMap();

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
        jdbcConn.resetTrustRolesMap();

        // no role principals

        Mockito.when(mockResultSet.next())
            .thenReturn(false) // no role principal return
            .thenReturn(false) // no groups principal return
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
        jdbcConn.resetTrustRolesMap();

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
        jdbcConn.resetTrustRolesMap();

        Mockito.when(mockResultSet.next())
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false) // up to here is role principals
            .thenReturn(false) // no groups
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false) // up to here is role assertions
            .thenReturn(false); // no trusted role
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
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
            .thenReturn("role2")
            .thenReturn("role3");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE))
            .thenReturn("role1")
            .thenReturn("role2")
            .thenReturn("role3")
            .thenReturn("role4");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_RESOURCE))
            .thenReturn("resource1")
            .thenReturn("resource2")
            .thenReturn("resource3")
            .thenReturn("resource4");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ACTION))
            .thenReturn("update");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_EFFECT))
            .thenReturn("ALLOW");

        ResourceAccessList resourceAccessList = jdbcConn.listResourceAccess("user.user1", "update", "user");
        List<ResourceAccess> resources = resourceAccessList.getResources();
        assertEquals(1, resources.size());

        ResourceAccess rsrcAccess = resources.get(0);
        assertEquals(rsrcAccess.getPrincipal(), "user.user1");

        assertEquals(rsrcAccess.getAssertions().size(), 3);
        Set<String> resourceStrings = new HashSet<>();
        for (Assertion assertion : rsrcAccess.getAssertions()) {
            resourceStrings.add(assertion.getResource());
        }
        assertTrue(resourceStrings.contains("resource1"));
        assertTrue(resourceStrings.contains("resource2"));
        assertTrue(resourceStrings.contains("resource3"));

        jdbcConn.close();
    }

    @Test
    public void testListResourceAccessAws() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        jdbcConn.resetTrustRolesMap();

        Mockito.when(mockResultSet.next())
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false) // up to here is role principals
            .thenReturn(false) // no groups
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false) // up to here is role assertions
            .thenReturn(true) // this is for last modified timestamp
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false) // up to here standard trusted roles
            .thenReturn(false) // up to here wildcard trusted roles
            .thenReturn(true)
            .thenReturn(true)
            .thenReturn(false); // up to here is aws domains
        Mockito.when(mockResultSet.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED))
            .thenReturn(new java.sql.Timestamp(1454358916));
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
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

        ResourceAccessList resourceAccessList = jdbcConn.listResourceAccess("user.user1", "assume_aws_role", "user");
        List<ResourceAccess> resources = resourceAccessList.getResources();
        assertEquals(1, resources.size());

        ResourceAccess rsrcAccess = resources.get(0);
        assertEquals(rsrcAccess.getPrincipal(), "user.user1");

        assertEquals(rsrcAccess.getAssertions().size(), 3);

        assertEquals("resource3", rsrcAccess.getAssertions().get(0).getResource());
        assertEquals("dom3:role.role3", rsrcAccess.getAssertions().get(0).getRole());

        assertEquals("dom1:role1", rsrcAccess.getAssertions().get(1).getResource());
        assertEquals("dom1:role.role1", rsrcAccess.getAssertions().get(1).getRole());

        assertEquals("dom2:role2", rsrcAccess.getAssertions().get(2).getResource());
        assertEquals("dom2:role.role2", rsrcAccess.getAssertions().get(2).getRole());

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

        boolean requestSuccess = jdbcConn.updatePolicyModTimestamp("my-domain", "policy1", null);
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
    public void testUpdatePolicyModTimestampInvalidPolicy() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(true)
                .thenReturn(false);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id

        try {
            jdbcConn.updatePolicyModTimestamp("my-domain", "policy1", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

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

        boolean requestSuccess = jdbcConn.updatePolicyModTimestamp("my-domain", "policy1", null);
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
            jdbcConn.updatePolicyModTimestamp("my-domain", "policy1", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
    public void testGetPrincipalRolesForAllDomainsInvalidPrincipal() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.getPrincipalRoles("user.joe", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        jdbcConn.close();
    }

    @Test
    public void testGetPrincipalRolesForAllDomainsException() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery())
            .thenReturn(mockResultSet)
            .thenThrow(new SQLException("failed operation", "state", 1001));

        Mockito.when(mockResultSet.next())
            .thenReturn(true); // get principal id

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // principal id

        try {
            jdbcConn.getPrincipalRoles("user.joe", null);
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
    public void testGetPrincipalRolesForOneDomainInvalidPrincipal() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenReturn(mockResultSet)
                .thenThrow(new SQLException("failed operation", "state", 1001));
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(7).when(mockResultSet).getInt(1); // domain id

        try {
            jdbcConn.getPrincipalRoles("user.joe", "athenz");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        jdbcConn.close();
    }

    @Test
    public void testGetPrincipalRolesForOneDomainInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.getPrincipalRoles("user.joe", "athenz");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        jdbcConn.close();
    }

    @Test
    public void testGetPrincipalRolesForOneDomainException() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery())
                .thenReturn(mockResultSet)
                .thenReturn(mockResultSet)
                .thenThrow(new SQLException("failed operation", "state", 1001));

        Mockito.when(mockResultSet.next())
                .thenReturn(true); // get domain/principal id

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5)  // principal id
                .thenReturn(3); // domain id

        try {
            jdbcConn.getPrincipalRoles("user.joe", "athenz");
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
    public void testGetQuotaInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next()).thenReturn(false); // for domain id

        try {
            jdbcConn.getQuota("athenz");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
                .setSubdomain(18).setGroup(19).setGroupMember(20);

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
        Mockito.verify(mockPrepStmt, times(1)).setInt(11, 19);
        Mockito.verify(mockPrepStmt, times(1)).setInt(12, 20);
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
                .setSubdomain(18).setGroup(19).setGroupMember(20);

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
        Mockito.verify(mockPrepStmt, times(1)).setInt(10, 19);
        Mockito.verify(mockPrepStmt, times(1)).setInt(11, 20);
        Mockito.verify(mockPrepStmt, times(1)).setInt(12, 5); // domain id
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
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
        } catch (Exception ignored) {
        }
        jdbcConn.close();
    }

    @Test
    public void testListOverdueReviewRoleMembersInvalidDomain() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        domainRoleMembersInvalidDomain(jdbcConn::listOverdueReviewRoleMembers);
        jdbcConn.close();
    }

    @Test
    public void testListOverdueReviewRoleMembersException() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        domainRoleMembersException(jdbcConn::listOverdueReviewRoleMembers);
        jdbcConn.close();
    }

    @Test
    public void testListOverdueReviewRoleMembersNoEntries() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        domainRoleMembersNoEntries(jdbcConn::listOverdueReviewRoleMembers);
        jdbcConn.close();
    }

    @Test
    public void testListOverdueReviewRoleMembers() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        domainRoleMembers(jdbcConn::listOverdueReviewRoleMembers, MemberRole::getReviewReminder);
        jdbcConn.close();
    }

    @Test
    public void testListDomainRoleMembersInvalidDomain() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        domainRoleMembersInvalidDomain((jdbcConn::listDomainRoleMembers));
        jdbcConn.close();
    }

    @Test
    public void testListDomainRoleMembersException() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        domainRoleMembersException(jdbcConn::listDomainRoleMembers);
        jdbcConn.close();
    }

    @Test
    public void testListDomainRoleMembersNoEntries() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        domainRoleMembersNoEntries(jdbcConn::listDomainRoleMembers);
        jdbcConn.close();
    }

    @Test
    public void testListDomainRoleMembers() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        domainRoleMembers(jdbcConn::listDomainRoleMembers,
                MemberRole::getExpiration);
        jdbcConn.close();
    }

    @Test
    public void testGetPrincipalRoles() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(1);  // Principal id will be 1

        // domain role members
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // True for getting principal_id
                .thenReturn(true) // True for the returned members (6 total)
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(false);

        Mockito.when(mockResultSet.getString(1)) // role names
                .thenReturn("role1")  // role1 in domain1
                .thenReturn("role1")  // role1 in domain2
                .thenReturn("role2")  // role2 in domain1
                .thenReturn("role2")  // role2 in domain3
                .thenReturn("role3")  // role3 in domain3
                .thenReturn("role4"); // role4 in domain3

        Mockito.when(mockResultSet.getString(2)) // domain names
                .thenReturn("domain1")
                .thenReturn("domain2")
                .thenReturn("domain1")
                .thenReturn("domain3")
                .thenReturn("domain3")
                .thenReturn("domain3");

        java.sql.Timestamp testTimestamp = new java.sql.Timestamp(1454358916);
        Mockito.when(mockResultSet.getTimestamp(3)) // expiration
                .thenReturn(testTimestamp)
                .thenReturn(testTimestamp)
                .thenReturn(null)
                .thenReturn(null)
                .thenReturn(null)
                .thenReturn(testTimestamp);

        Mockito.when(mockResultSet.getTimestamp(4)) // review reminder
                .thenReturn(null)
                .thenReturn(testTimestamp)
                .thenReturn(testTimestamp)
                .thenReturn(null)
                .thenReturn(null)
                .thenReturn(null);

        Mockito.when(mockResultSet.getInt(5)) // System disabled
                .thenReturn(0)
                .thenReturn(0)
                .thenReturn(1)
                .thenReturn(1)
                .thenReturn(0)
                .thenReturn(0);

        String principalName = "user.testUser";
        MemberRole memberRole0 = new MemberRole();
        memberRole0.setRoleName("role1");
        memberRole0.setDomainName("domain1");
        memberRole0.setExpiration(Timestamp.fromMillis(testTimestamp.getTime()));
        memberRole0.setReviewReminder(null);

        MemberRole memberRole1 = new MemberRole();
        memberRole1.setRoleName("role1");
        memberRole1.setDomainName("domain2");
        memberRole1.setExpiration(Timestamp.fromMillis(testTimestamp.getTime()));
        memberRole1.setReviewReminder(Timestamp.fromMillis(testTimestamp.getTime()));

        MemberRole memberRole2 = new MemberRole();
        memberRole2.setRoleName("role2");
        memberRole2.setDomainName("domain1");
        memberRole2.setExpiration(null);
        memberRole2.setReviewReminder(Timestamp.fromMillis(testTimestamp.getTime()));
        memberRole2.setSystemDisabled(1);

        MemberRole memberRole3 = new MemberRole();
        memberRole3.setRoleName("role2");
        memberRole3.setDomainName("domain3");
        memberRole3.setExpiration(null);
        memberRole3.setReviewReminder(null);
        memberRole3.setSystemDisabled(1);

        MemberRole memberRole4 = new MemberRole();
        memberRole4.setRoleName("role3");
        memberRole4.setDomainName("domain3");
        memberRole4.setExpiration(null);
        memberRole4.setReviewReminder(null);

        MemberRole memberRole5 = new MemberRole();
        memberRole5.setRoleName("role4");
        memberRole5.setDomainName("domain3");
        memberRole5.setExpiration(Timestamp.fromMillis(testTimestamp.getTime()));
        memberRole5.setReviewReminder(null);

        DomainRoleMember roleMember = jdbcConn.getPrincipalRoles(principalName, null);
        assertEquals(roleMember.getMemberName(), principalName);
        assertEquals(roleMember.getMemberRoles().size(), 6);
        assertEquals(roleMember.getMemberRoles().get(0), memberRole0);
        assertEquals(roleMember.getMemberRoles().get(1), memberRole1);
        assertEquals(roleMember.getMemberRoles().get(2), memberRole2);
        assertEquals(roleMember.getMemberRoles().get(3), memberRole3);
        assertEquals(roleMember.getMemberRoles().get(4), memberRole4);
        assertEquals(roleMember.getMemberRoles().get(5), memberRole5);
    }

    @Test
    public void testGetPrincipalRolesDomain() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(1)  // Principal id will be 1
                .thenReturn(1); // Domain id will be 1

        // domain role members
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // True for getting principal_id
                .thenReturn(true) // True for getting domain_id
                .thenReturn(true) // True for the returned members (3 total)
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(false);

        Mockito.when(mockResultSet.getString(1)) // role names
                .thenReturn("role2")  // role2 in domain3
                .thenReturn("role3")  // role3 in domain3
                .thenReturn("role4"); // role4 in domain3

        Mockito.when(mockResultSet.getString(2)) // domain names
                .thenReturn("domain3")
                .thenReturn("domain3")
                .thenReturn("domain3");

        java.sql.Timestamp testTimestamp = new java.sql.Timestamp(1454358916);
        Mockito.when(mockResultSet.getTimestamp(3)) // expiration
                .thenReturn(null)
                .thenReturn(null)
                .thenReturn(testTimestamp);

        Mockito.when(mockResultSet.getTimestamp(4)) // review reminder
                .thenReturn(null)
                .thenReturn(null)
                .thenReturn(null);

        Mockito.when(mockResultSet.getInt(5)) // System disabled
                .thenReturn(1)
                .thenReturn(0)
                .thenReturn(0);

        String principalName = "user.testUser";

        MemberRole memberRole3 = new MemberRole();
        memberRole3.setRoleName("role2");
        memberRole3.setDomainName("domain3");
        memberRole3.setExpiration(null);
        memberRole3.setReviewReminder(null);
        memberRole3.setSystemDisabled(1);

        MemberRole memberRole4 = new MemberRole();
        memberRole4.setRoleName("role3");
        memberRole4.setDomainName("domain3");
        memberRole4.setExpiration(null);
        memberRole4.setReviewReminder(null);

        MemberRole memberRole5 = new MemberRole();
        memberRole5.setRoleName("role4");
        memberRole5.setDomainName("domain3");
        memberRole5.setExpiration(Timestamp.fromMillis(testTimestamp.getTime()));
        memberRole5.setReviewReminder(null);

        DomainRoleMember roleMember = jdbcConn.getPrincipalRoles(principalName, "domain3");
        assertEquals(roleMember.getMemberName(), principalName);
        assertEquals(roleMember.getMemberRoles().size(), 3);
        assertEquals(roleMember.getMemberRoles().get(0), memberRole3);
        assertEquals(roleMember.getMemberRoles().get(1), memberRole4);
        assertEquals(roleMember.getMemberRoles().get(2), memberRole5);
    }

    @Test
    public void testGetPrincipalRolesInvalidDomain() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(1); // Principal id will be 1

        // domain role members
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // True for getting principal_id
                .thenThrow(new SQLException("error getting domain_id")); // Throw exception when trying to get domain_id

        String principalName = "user.testUser";

        try {
            jdbcConn.getPrincipalRoles(principalName, "unknownDomain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertEquals(ex.getData().toString(), "{code: 404, message: \"unknown domain - unknownDomain\"}");
        }
    }

    @Test
    public void testGetPrincipalRolesInvalidPrincipal() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        try {
            jdbcConn.getPrincipalRoles("johndoe", null);
            fail();
        } catch (ResourceException exception) {
            assertEquals(exception.getCode(), ResourceException.NOT_FOUND);
            assertEquals(exception.getData().toString(), "{code: 404, message: \"unknown principal - johndoe\"}");
        }
    }

    @Test
    public void testGetPrincipalRolesException() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(1);  // Principal id will be 1

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // True for getting principal_id
                .thenThrow(new SQLTimeoutException("failed operation - timeout", "state", 1001));

        try {
            jdbcConn.getPrincipalRoles("johndoe", null);
            fail();
        } catch (ResourceException exception) {
            assertEquals(exception.getCode(), 503);
            assertEquals(exception.getData().toString(), "{code: 503, message: \"Statement cancelled due to timeout\"}");

        }
    }

    @Test
    public void testGetPrincipalRolesNoRuleMembers() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(1);  // Principal id will be 1
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // True for getting principal_id
                .thenReturn(false); // Not member of any roles

        DomainRoleMember domainRoleMember = jdbcConn.getPrincipalRoles("johndoe", null);
        assertEquals(domainRoleMember.getMemberName(), "johndoe");
        assertEquals(domainRoleMember.getMemberRoles().size(), 0);
    }

    private void domainRoleMembers(Function<String, DomainRoleMembers> jdbcFunc,
                                   Function<MemberRole, Timestamp> timestampGetter) throws Exception {
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
                .thenReturn(new java.sql.Timestamp(1454358916000L))
                .thenReturn(null)
                .thenReturn(null);
        Mockito.when(mockResultSet.getTimestamp(4))
                .thenReturn(new java.sql.Timestamp(1454358916000L))
                .thenReturn(null)
                .thenReturn(null);

        DomainRoleMembers domainRoleMembers = jdbcFunc.apply("athenz");
        List<DomainRoleMember> members = domainRoleMembers.getMembers();
        assertEquals(2, members.size());

        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "athenz");
        // get role list
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 3);

        assertTrue(ZMSTestUtils.verifyDomainRoleMember(members, "user.joe", "admin", "writer"));
        assertTrue(ZMSTestUtils.verifyDomainRoleMember(members, "user.jane", "reader"));
        assertTrue(ZMSTestUtils.verifyDomainRoleMemberTimestamp(members, "user.joe", "admin",
                Timestamp.fromMillis(1454358916000L), timestampGetter));
    }

    private void domainRoleMembersException(Function<String, DomainRoleMembers> jdbcFunc) throws SQLException {
        Mockito.when(mockPrepStmt.executeQuery())
                .thenReturn(mockResultSet)
                .thenThrow(new SQLException("failed operation", "state", 1001));

        Mockito.when(mockResultSet.next())
                .thenReturn(true); // get domain id

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id

        try {
            jdbcFunc.apply("athenz");
            fail();
        } catch (Exception ignored) {
        }

        // get principal id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "athenz");
        // get role list
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
    }

    private void domainRoleMembersInvalidDomain(Function<String, DomainRoleMembers> jdbcFunc) throws Exception {
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcFunc.apply("athenz");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
    }

    private void domainRoleMembersNoEntries(Function<String, DomainRoleMembers> jdbcFunc) throws Exception {
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(3); // domain id

        // domain role members
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // get domain id
                .thenReturn(false);

        DomainRoleMembers domainRoleMembers = jdbcFunc.apply("athenz");
        assertNull(domainRoleMembers.getMembers());

        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "athenz");
        // get role list
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 3);
    }

    @Test
    public void testGetRoleDefaultAuditEnabledAsNull() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn("role1").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_NAME);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_TRUST);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_SIGN_ALGORITHM);
        Mockito.doReturn(false).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_AUDIT_ENABLED);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet)
                .getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);
        Mockito.doReturn(false).when(mockResultSet).getBoolean(ZMSConsts.DB_COLUMN_REVIEW_ENABLED);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_NOTIFY_ROLES);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_EXPIRATION);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_FILTER);
        Mockito.doReturn("").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_DESCRIPTION);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Role role = jdbcConn.getRole("my-domain", "role1");
        assertNotNull(role);
        assertEquals("my-domain:role.role1", role.getName());
        assertNull(role.getAuditEnabled());
        assertNull(role.getSignAlgorithm());
        assertNull(role.getReviewEnabled());
        assertNull(role.getLastReviewedDate());
        assertNull(role.getNotifyRoles());
        assertNull(role.getUserAuthorityExpiration());
        assertNull(role.getUserAuthorityFilter());
        assertNull(role.getDescription());

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");
        jdbcConn.close();
    }

    @Test
    public void testNullIfDefaultValue() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        assertNull(jdbcConn.nullIfDefaultValue(false, false));
        assertTrue(jdbcConn.nullIfDefaultValue(true, false));

        assertNull(jdbcConn.nullIfDefaultValue(0, 0));
        assertNull(jdbcConn.nullIfDefaultValue(1, 1));
        assertEquals(jdbcConn.nullIfDefaultValue(10, 0), Integer.valueOf(10));
        jdbcConn.close();
    }

    @Test
    public void testConfirmRoleMemberApprove() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        String pendingState = ZMSConsts.PENDING_REQUEST_ADD_STATE;
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // role id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.getString(1))
                        .thenReturn(pendingState);
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for role id
                .thenReturn(true) // principal id
                .thenReturn(true) // this one is for pending state
                .thenReturn(false); // member does not exist in std table
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.confirmRoleMember("my-domain", "role1",
                new RoleMember().setMemberName("user.user1").setActive(true).setApproved(true),
                "user.admin", "audit-ref");

        // this is combined for all operations above

        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        // get role id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");

        //get principal
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        //get pending state
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.user1");


        Mockito.verify(mockPrepStmt, times(5)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(3)).setInt(2, 9);

        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(3, null);
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(4, null);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(5, true);
        Mockito.verify(mockPrepStmt, times(1)).setString(6, "audit-ref");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "audit-ref");


        // the rest of the audit log details

        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "APPROVE");

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testConfirmRoleMemberApproveWithExpiry() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // role id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.getString(1))
                .thenReturn("ADD"); // pending state
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for role id
                .thenReturn(true) // principal id
                .thenReturn(true) // this one is for pending state
                .thenReturn(false); // member does not exist in std table
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        Timestamp expiration = Timestamp.fromCurrentTime();
        java.sql.Timestamp javaExpiration = new java.sql.Timestamp(expiration.toDate().getTime());
        boolean requestSuccess = jdbcConn.confirmRoleMember("my-domain", "role1",
                new RoleMember().setMemberName("user.user1").setActive(true)
                        .setApproved(true).setExpiration(expiration), "user.admin", "audit-ref");

        // this is combined for all operations above

        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        // get role id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");

        //get principal
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        //get pending state
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.user1");

        Mockito.verify(mockPrepStmt, times(5)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(3)).setInt(2, 9);

        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(3, javaExpiration);
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(4, null);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(5, true);
        Mockito.verify(mockPrepStmt, times(1)).setString(6, "audit-ref");

        Mockito.verify(mockPrepStmt, times(1)).setString(5, "audit-ref");

        // the rest of the audit log details

        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "APPROVE");

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testConfirmRoleMemberApproveWithReview() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // role id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.getString(1))
                .thenReturn("ADD"); // pending state
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for role id
                .thenReturn(true) // principal id
                .thenReturn(true) // this one is for pending state
                .thenReturn(false); // member does not exist in std table
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        Timestamp reviewReminder = Timestamp.fromCurrentTime();
        java.sql.Timestamp javaReviewReminder = new java.sql.Timestamp(reviewReminder.toDate().getTime());
        boolean requestSuccess = jdbcConn.confirmRoleMember("my-domain", "role1",
                new RoleMember().setMemberName("user.user1").setActive(true)
                        .setApproved(true).setReviewReminder(reviewReminder), "user.admin", "audit-ref");

        // this is combined for all operations above

        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        // get role id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");

        //get principal
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        //get pending state
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.user1");

        Mockito.verify(mockPrepStmt, times(5)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(3)).setInt(2, 9);

        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(3, null);
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(4, javaReviewReminder);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(5, true);
        Mockito.verify(mockPrepStmt, times(1)).setString(6, "audit-ref");

        Mockito.verify(mockPrepStmt, times(1)).setString(5, "audit-ref");

        // the rest of the audit log details

        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "APPROVE");

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testConfirmRoleMemberReject() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // role id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.getString(1))
                .thenReturn("DELETE"); //pendingState
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for role id
                .thenReturn(true) // validate principle domain
                .thenReturn(true) // principal id
                .thenReturn(true); // member exists
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.confirmRoleMember("my-domain", "role1",
                new RoleMember().setMemberName("user.user1").setActive(false), "user.admin", "audit-ref");

        // this is combined for all operations above

        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        // get role id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");

        //get principal
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        // we need additional operation for the audit log
        // additional operation to check for roleMember exist using roleID and principal ID.
        Mockito.verify(mockPrepStmt, times(3)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 9);

        // the rest of the audit log details

        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "REJECT");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "audit-ref");

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testConfirmRoleMemberErrors() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(0); // domain id

        try {
            jdbcConn.confirmRoleMember("my-domain", "role", new RoleMember()
                    .setMemberName("user.user1").setActive(false), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException rx) {
            assertEquals(rx.getCode(), 404);
            assertTrue(rx.getMessage().contains("unknown domain"));
        }

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(0); // role id
        Mockito.when(mockResultSet.next())
                .thenReturn(true);

        try {
            jdbcConn.confirmRoleMember("my-domain1", "role1", new RoleMember()
                    .setMemberName("user.user1").setActive(false), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException rx) {
            assertEquals(rx.getCode(), 404);
            assertTrue(rx.getMessage().contains("unknown role"));
        }

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // role id
                .thenReturn(0); // principal id

        try {
            jdbcConn.confirmRoleMember("my-domain2", "role2", new RoleMember()
                    .setMemberName("user1").setActive(false), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException rx) {
            assertEquals(rx.getCode(), 404);
            assertTrue(rx.getMessage().contains("unknown principal"));
        }

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // role id
                .thenReturn(0); // principal id

        try {
            jdbcConn.confirmRoleMember("my-domain3", "role3", new RoleMember()
                    .setMemberName("user.user1").setActive(false), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException rx) {
            assertEquals(rx.getCode(), 404);
            assertTrue(rx.getMessage().contains("unknown principal"));
        }

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // role id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.getString(1))
                        .thenReturn("ADD");
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for role id
                .thenReturn(true) // validate principle domain
                .thenReturn(true) // principal id
                .thenReturn(false); // member exists

        assertFalse(jdbcConn.confirmRoleMember("my-domain4", "role4", new RoleMember()
                    .setMemberName("user.user1").setActive(true), "user.admin", "audit-ref"));

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

        Mockito.doThrow(new SQLException("conflict", "08S01", 409)).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.confirmRoleMember("my-domain5", "role5", new RoleMember()
                    .setMemberName("user.user1").setActive(true), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException rx) {
            assertEquals(rx.getCode(), 409);
        }

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

        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();

        boolean result = jdbcConn.confirmRoleMember("my-domain6", "role6", new RoleMember()
                .setMemberName("user.user1").setActive(true), "user.admin", "audit-ref");
        assertFalse(result);

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

        Mockito.doThrow(new SQLException("conflict", "08S01", 409)).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.confirmRoleMember("my-domain7", "role7", new RoleMember()
                    .setMemberName("user.user1").setActive(false), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException rx) {
            assertEquals(rx.getCode(), 409);
        }

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

        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();

        result = jdbcConn.confirmRoleMember("my-domain8", "role8", new RoleMember()
                .setMemberName("user.user1").setActive(false), "user.admin", "audit-ref");
        assertFalse(result);

        jdbcConn.close();
    }

    @Test
    public void testInsertRoleMemberDefaultActive() throws Exception {

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

        Mockito.verify(mockPrepStmt, times(1)).setBoolean(5, true);

        // the rest of the audit log details

        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "ADD");
        Mockito.verify(mockPrepStmt, times(1)).setString(6, "audit-ref");

        Mockito.verify(mockPrepStmt, times(1)).setString(5, "audit-ref");

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testInsertRoleMemberNotActiveByFlag() throws Exception {

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
                new RoleMember().setMemberName("user.user1").setActive(false), "user.admin", "audit-ref");

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        // we need additional operation for the audit log
        // additional operation to check for roleMember exist using roleID and principal ID.
        Mockito.verify(mockPrepStmt, times(3)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(2)).setInt(2, 9);

        Mockito.verify(mockPrepStmt, times(1)).setBoolean(5, false);

        // the rest of the audit log details

        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "ADD");
        Mockito.verify(mockPrepStmt, times(1)).setString(6, "audit-ref");

        Mockito.verify(mockPrepStmt, times(1)).setString(5, "audit-ref");

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testConfirmRoleMemberPrincipalIdNotFound() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // role id
                .thenReturn(0); // principal id
        Mockito.when(mockResultSet.next()).thenReturn(true);
        try {
            jdbcConn.confirmRoleMember("my-domain", "role1", new RoleMember()
                    .setMemberName("user.user1").setActive(false), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException rx){
            assertEquals(rx.getCode(), 404);
            assertTrue(rx.getMessage().contains("unknown principal"));
        }

        jdbcConn.close();
    }

    @Test
    public void testConfirmRoleMemberPrincipalNotExists() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // role id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next()).thenReturn(true,true,true,false);
        try {
            jdbcConn.confirmRoleMember("my-domain", "role1", new RoleMember()
                    .setMemberName("user.user1").setActive(false), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException rx){
            assertEquals(rx.getCode(), 404);
            assertTrue(rx.getMessage().contains("unknown principal"));
        }
        jdbcConn.close();
    }

    @Test
    public void testConfirmRoleMemberPrincipalSqlError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // role id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next()).thenReturn(true,true,true).thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.confirmRoleMember("my-domain", "role1", new RoleMember()
                    .setMemberName("user.user1").setActive(false), "user.admin", "audit-ref");
            fail();
        }catch (RuntimeException rx){
            assertTrue(rx.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetPendingDomainRoleMembersList() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(9) // principal id
                .thenReturn(5) // sys.auth.audit.org domain id
                .thenReturn(7); // sys.auth.audit.domain domain id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for principal id
                .thenReturn(true) // this one is for sys.auth.audit.org domain id
                .thenReturn(true) // for the domain1, first member found user.member1
                .thenReturn(true) // for the domain1, second member found user.member2
                .thenReturn(true) // for the domain1, third member found user.member3
                .thenReturn(true) // for domain2 first member found user.member2
                .thenReturn(true) // for domain21 first member found user.member21
                .thenReturn(false) // moving to domain approvers
                .thenReturn(true) // this one is for sys.auth.audit.domain domain id
                .thenReturn(true) // for the domain21, second member found user.member21
                .thenReturn(true) // for the domain21, third member found user.member31
                .thenReturn(true) // for domain22 first member found user.member21
                .thenReturn(true) // for domain21 duplicate member found user.member21 -- new
                .thenReturn(false) // moving to self serve
                .thenReturn(true) // for the domain22, duplicate member found selfserve
                .thenReturn(true) // for the domain22, duplicate member found selfserve
                .thenReturn(false);

        Mockito.doReturn("domain1", "domain1", "domain1", "domain2", "domain21", "domain21", "domain21", "domain22", "domain21", "domain22", "domain22").when(mockResultSet).getString(1);
        Mockito.doReturn("role1", "role11", "role111", "role2", "role3", "role31", "role311", "role4", "role311", "role4", "role4").when(mockResultSet).getString(2);
        Mockito.doReturn("user.member1", "user.member2", "user.member3", "user.member2", "user.member11", "user.member21", "user.member31", "user.member21", "user.member31", "user.member21", "user.member21").when(mockResultSet).getString(3);
        Mockito.doReturn(new java.sql.Timestamp(1454358916), new java.sql.Timestamp(1454358916), null, null, new java.sql.Timestamp(1454358916), new java.sql.Timestamp(1454358916), null, null, null, null, null).when(mockResultSet).getTimestamp(4);
        Mockito.doReturn(new java.sql.Timestamp(1454358916), new java.sql.Timestamp(1454358916), null, null, new java.sql.Timestamp(1454358916), new java.sql.Timestamp(1454358916), null, null, null, null, null).when(mockResultSet).getTimestamp(5);
        Mockito.doReturn("required for proj1", null, "self serve audit-ref", null, "required for proj 2", null, "self serve audit-ref 2", null, "self serve audit-ref 2", null, null).when(mockResultSet).getString(6);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(7);
        Mockito.doReturn("user.req1").when(mockResultSet).getString(8);

        Map<String, List<DomainRoleMember>> domainRoleMembersMap = jdbcConn.getPendingDomainRoleMembersByPrincipal("user.user1");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "sys.auth.audit.org");
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "sys.auth.audit.domain");
        Mockito.verify(mockPrepStmt, times(3)).setInt(1, 9); // twice for audit enabled roles, one for selfserve roles
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 5);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 7);

        assertNotNull(domainRoleMembersMap);
        assertEquals(domainRoleMembersMap.size(), 4);

        assertNotNull(domainRoleMembersMap.get("domain1"));
        List<DomainRoleMember> domainRoleMembers = domainRoleMembersMap.get("domain1");
        assertNotNull(domainRoleMembers);
        assertEquals(domainRoleMembers.size(), 3);

        assertEquals(domainRoleMembers.get(0).getMemberName(), "user.member1");
        assertEquals(domainRoleMembers.get(0).getMemberRoles().size(), 1);
        assertEquals(domainRoleMembers.get(0).getMemberRoles().get(0).getRoleName(), "role1");
        assertEquals(domainRoleMembers.get(0).getMemberRoles().get(0).getAuditRef(), "required for proj1");
        assertEquals(domainRoleMembers.get(0).getMemberRoles().get(0).getRequestPrincipal(), "user.req1");
        assertEquals(domainRoleMembers.get(0).getMemberRoles().get(0).getRequestTime(), Timestamp.fromMillis(1454358916));

        assertEquals(domainRoleMembers.get(1).getMemberName(), "user.member2");
        assertEquals(domainRoleMembers.get(1).getMemberRoles().size(), 1);
        assertEquals(domainRoleMembers.get(1).getMemberRoles().get(0).getRoleName(), "role11");
        assertNull(domainRoleMembers.get(1).getMemberRoles().get(0).getAuditRef());
        assertEquals(domainRoleMembers.get(1).getMemberRoles().get(0).getRequestPrincipal(), "user.req1");
        assertEquals(domainRoleMembers.get(1).getMemberRoles().get(0).getRequestTime(), Timestamp.fromMillis(1454358916));

        assertEquals(domainRoleMembers.get(2).getMemberName(), "user.member3");
        assertEquals(domainRoleMembers.get(2).getMemberRoles().size(), 1);
        assertEquals(domainRoleMembers.get(2).getMemberRoles().get(0).getRoleName(), "role111");
        assertEquals(domainRoleMembers.get(2).getMemberRoles().get(0).getAuditRef(), "self serve audit-ref");

        assertNotNull(domainRoleMembersMap.get("domain2"));
        domainRoleMembers = domainRoleMembersMap.get("domain2");
        assertNotNull(domainRoleMembers);
        assertEquals(domainRoleMembers.size(), 1);
        assertEquals(domainRoleMembers.get(0).getMemberName(), "user.member2");
        assertEquals(domainRoleMembers.get(0).getMemberRoles().size(), 1);
        assertEquals(domainRoleMembers.get(0).getMemberRoles().get(0).getRoleName(), "role2");
        assertNull(domainRoleMembers.get(0).getMemberRoles().get(0).getAuditRef());

        // selfserve roles retrieved using SQL_PENDING_DOMAIN_SELFSERVE_ROLE_MEMBER_LIST
        assertNotNull(domainRoleMembersMap.get("domain21"));
        domainRoleMembers = domainRoleMembersMap.get("domain21");
        assertNotNull(domainRoleMembers);
        assertEquals(domainRoleMembers.size(), 3);

        assertEquals(domainRoleMembers.get(0).getMemberName(), "user.member11");
        assertEquals(domainRoleMembers.get(0).getMemberRoles().size(), 1);
        assertEquals(domainRoleMembers.get(0).getMemberRoles().get(0).getRoleName(), "role3");
        assertEquals(domainRoleMembers.get(0).getMemberRoles().get(0).getAuditRef(), "required for proj 2");

        assertEquals(domainRoleMembers.get(1).getMemberName(), "user.member21");
        assertEquals(domainRoleMembers.get(1).getMemberRoles().size(), 1);
        assertEquals(domainRoleMembers.get(1).getMemberRoles().get(0).getRoleName(), "role31");
        assertNull(domainRoleMembers.get(1).getMemberRoles().get(0).getAuditRef());

        assertEquals(domainRoleMembers.get(2).getMemberName(), "user.member31");
        assertEquals(domainRoleMembers.get(2).getMemberRoles().size(), 1);
        assertEquals(domainRoleMembers.get(2).getMemberRoles().get(0).getRoleName(), "role311");
        assertEquals(domainRoleMembers.get(2).getMemberRoles().get(0).getAuditRef(), "self serve audit-ref 2");

        assertNotNull(domainRoleMembersMap.get("domain22"));
        domainRoleMembers = domainRoleMembersMap.get("domain22");
        assertNotNull(domainRoleMembers);
        assertEquals(domainRoleMembers.size(), 1);
        assertEquals(domainRoleMembers.get(0).getMemberName(), "user.member21");
        assertEquals(domainRoleMembers.get(0).getMemberRoles().size(), 1);
        assertEquals(domainRoleMembers.get(0).getMemberRoles().get(0).getRoleName(), "role4");
        assertNull(domainRoleMembers.get(0).getMemberRoles().get(0).getAuditRef());

        jdbcConn.close();
    }

    @Test
    public void testGetPendingDomainRoleMembersListByDomain() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(12345); // domain id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // for the domain1, first member found user.member1
                .thenReturn(true) // for the domain1, second member found user.member2
                .thenReturn(true) // for the domain1, third member found user.member3
                .thenReturn(false);

        Mockito.doReturn("domain1").when(mockResultSet).getString(1);
        Mockito.doReturn("role1", "role11", "role111").when(mockResultSet).getString(2);
        Mockito.doReturn("user.member1", "user.member2", "user.member3").when(mockResultSet).getString(3);
        Mockito.doReturn(new java.sql.Timestamp(1454358916), new java.sql.Timestamp(1454358916), null).when(mockResultSet).getTimestamp(4);
        Mockito.doReturn(new java.sql.Timestamp(1454358916), new java.sql.Timestamp(1454358916), null).when(mockResultSet).getTimestamp(5);
        Mockito.doReturn("required for proj1", null, "self serve audit-ref").when(mockResultSet).getString(6);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(7);
        Mockito.doReturn("user.req1").when(mockResultSet).getString(8);

        Map<String, List<DomainRoleMember>> domainRoleMembersMap = jdbcConn.getPendingDomainRoleMembersByDomain("domain1");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 12345);

        assertNotNull(domainRoleMembersMap);
        assertEquals(domainRoleMembersMap.size(), 1);

        assertNotNull(domainRoleMembersMap.get("domain1"));
        List<DomainRoleMember> domainRoleMembers = domainRoleMembersMap.get("domain1");
        assertNotNull(domainRoleMembers);
        assertEquals(domainRoleMembers.size(), 3);

        assertEquals(domainRoleMembers.get(0).getMemberName(), "user.member1");
        assertEquals(domainRoleMembers.get(0).getMemberRoles().size(), 1);
        assertEquals(domainRoleMembers.get(0).getMemberRoles().get(0).getRoleName(), "role1");
        assertEquals(domainRoleMembers.get(0).getMemberRoles().get(0).getAuditRef(), "required for proj1");
        assertEquals(domainRoleMembers.get(0).getMemberRoles().get(0).getRequestPrincipal(), "user.req1");
        assertEquals(domainRoleMembers.get(0).getMemberRoles().get(0).getRequestTime(), Timestamp.fromMillis(1454358916));

        assertEquals(domainRoleMembers.get(1).getMemberName(), "user.member2");
        assertEquals(domainRoleMembers.get(1).getMemberRoles().size(), 1);
        assertEquals(domainRoleMembers.get(1).getMemberRoles().get(0).getRoleName(), "role11");
        assertNull(domainRoleMembers.get(1).getMemberRoles().get(0).getAuditRef());
        assertEquals(domainRoleMembers.get(1).getMemberRoles().get(0).getRequestPrincipal(), "user.req1");
        assertEquals(domainRoleMembers.get(1).getMemberRoles().get(0).getRequestTime(), Timestamp.fromMillis(1454358916));

        assertEquals(domainRoleMembers.get(2).getMemberName(), "user.member3");
        assertEquals(domainRoleMembers.get(2).getMemberRoles().size(), 1);
        assertEquals(domainRoleMembers.get(2).getMemberRoles().get(0).getRoleName(), "role111");
        assertEquals(domainRoleMembers.get(2).getMemberRoles().get(0).getAuditRef(), "self serve audit-ref");
        jdbcConn.close();
    }

    @Test
    public void testGetPendingDomainRoleMembersListByDomainAllDomains() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // for the domain1, first member found user.member1
                .thenReturn(true) // for the domain1, second member found user.member2
                .thenReturn(true) // for the domain1, third member found user.member3
                .thenReturn(false);

        Mockito.doReturn("domain1").when(mockResultSet).getString(1);
        Mockito.doReturn("role1", "role11", "role111").when(mockResultSet).getString(2);
        Mockito.doReturn("user.member1", "user.member2", "user.member3").when(mockResultSet).getString(3);
        Mockito.doReturn(new java.sql.Timestamp(1454358916), new java.sql.Timestamp(1454358916), null).when(mockResultSet).getTimestamp(4);
        Mockito.doReturn(new java.sql.Timestamp(1454358916), new java.sql.Timestamp(1454358916), null).when(mockResultSet).getTimestamp(5);
        Mockito.doReturn("required for proj1", null, "self serve audit-ref").when(mockResultSet).getString(6);
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(7);
        Mockito.doReturn("user.req1").when(mockResultSet).getString(8);

        Map<String, List<DomainRoleMember>> domainRoleMembersMap = jdbcConn.getPendingDomainRoleMembersByDomain("*");

        assertNotNull(domainRoleMembersMap);
        assertEquals(domainRoleMembersMap.size(), 1);

        assertNotNull(domainRoleMembersMap.get("domain1"));
        List<DomainRoleMember> domainRoleMembers = domainRoleMembersMap.get("domain1");
        assertNotNull(domainRoleMembers);
        assertEquals(domainRoleMembers.size(), 3);

        assertEquals(domainRoleMembers.get(0).getMemberName(), "user.member1");
        assertEquals(domainRoleMembers.get(0).getMemberRoles().size(), 1);
        assertEquals(domainRoleMembers.get(0).getMemberRoles().get(0).getRoleName(), "role1");
        assertEquals(domainRoleMembers.get(0).getMemberRoles().get(0).getAuditRef(), "required for proj1");
        assertEquals(domainRoleMembers.get(0).getMemberRoles().get(0).getRequestPrincipal(), "user.req1");
        assertEquals(domainRoleMembers.get(0).getMemberRoles().get(0).getRequestTime(), Timestamp.fromMillis(1454358916));

        assertEquals(domainRoleMembers.get(1).getMemberName(), "user.member2");
        assertEquals(domainRoleMembers.get(1).getMemberRoles().size(), 1);
        assertEquals(domainRoleMembers.get(1).getMemberRoles().get(0).getRoleName(), "role11");
        assertNull(domainRoleMembers.get(1).getMemberRoles().get(0).getAuditRef());
        assertEquals(domainRoleMembers.get(1).getMemberRoles().get(0).getRequestPrincipal(), "user.req1");
        assertEquals(domainRoleMembers.get(1).getMemberRoles().get(0).getRequestTime(), Timestamp.fromMillis(1454358916));

        assertEquals(domainRoleMembers.get(2).getMemberName(), "user.member3");
        assertEquals(domainRoleMembers.get(2).getMemberRoles().size(), 1);
        assertEquals(domainRoleMembers.get(2).getMemberRoles().get(0).getRoleName(), "role111");
        assertEquals(domainRoleMembers.get(2).getMemberRoles().get(0).getAuditRef(), "self serve audit-ref");
        jdbcConn.close();
    }

    @Test
    public void testGetPendingDomainRoleMembersListSqlError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(9) // principal id
                .thenReturn(5); // sys.auth.audit.org domain id
        Mockito.when(mockResultSet.next()).thenReturn(true,true).thenThrow(new SQLException("sql error"));

        try {
            jdbcConn.getPendingDomainRoleMembersByPrincipal("user.user1");
            fail();
        }catch (RuntimeException rx){
            assertTrue(rx.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetPendingDomainRoleMembersInvalidDomain() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        try {
            jdbcConn.getPendingDomainRoleMembersByDomain("invalid-domain");
            fail();
        }catch (ResourceException ex){
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("invalid-domain"));
        }
    }

    @Test
    public void testGetPendingDomainGroupMembersInvalidDomain() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        try {
            jdbcConn.getPendingDomainGroupMembersByDomain("invalid-domain");
            fail();
        }catch (ResourceException ex){
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("invalid-domain"));
        }
    }

    @Test
    public void testGetPendingDomainRoleMembersByDomainAllDomainsSqlError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenThrow(new SQLException("sql error"));

        try {
            jdbcConn.getPendingDomainRoleMembersByDomain("*");
            fail();
        }catch (RuntimeException rx){
            assertTrue(rx.getMessage().contains("sql error"));
        }

        jdbcConn.close();
    }

    @Test
    public void testGetPendingDomainRoleMembersByDomainSqlError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(1232);
        Mockito.when(mockResultSet.next()).thenReturn(true).thenThrow(new SQLException("sql error"));

        try {
            jdbcConn.getPendingDomainRoleMembersByDomain("testdomain");
            fail();
        }catch (RuntimeException rx){
            assertTrue(rx.getMessage().contains("sql error"));
        }

        jdbcConn.close();
    }

    @Test
    public void testGetPendingDomainGroupMembersByDomainAllDomainsSqlError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenThrow(new SQLException("sql error"));

        try {
            jdbcConn.getPendingDomainGroupMembersByDomain("*");
            fail();
        }catch (RuntimeException rx){
            assertTrue(rx.getMessage().contains("sql error"));
        }

        jdbcConn.close();
    }

    @Test
    public void testGetPendingDomainGroupMembersByDomainSqlError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(1232);
        Mockito.when(mockResultSet.next()).thenReturn(true).thenThrow(new SQLException("sql error"));

        try {
            jdbcConn.getPendingDomainGroupMembersByDomain("testdomain");
            fail();
        }catch (RuntimeException rx){
            assertTrue(rx.getMessage().contains("sql error"));
        }

        jdbcConn.close();
    }

    @Test
    public void testGetPendingDomainRoleMembersListSqlErrorSelfServe() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(9) // principal id
                .thenReturn(5) // sys.auth.audit.org domain id
                .thenReturn(7); // sys.auth.audit.domain domain id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // principal
                .thenReturn(true) // sys.auth.audit.org domain look up
                .thenReturn(false) // no pending members
                .thenReturn(true) // sys.auth.audit.domain look up
                .thenReturn(false) // no pending members
                .thenThrow(new SQLException("sql error"));//for selfserve roles;
        try {

            jdbcConn.getPendingDomainRoleMembersByPrincipal("user.user1");

        }catch (RuntimeException rx){
            assertTrue(rx.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetPendingDomainRoleMembersListPrincipalNotExists() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(0); // principal id

        Mockito.when(mockResultSet.next()).thenReturn(false);
        try {
            jdbcConn.getPendingDomainRoleMembersByPrincipal("user.user1");
            fail();
        }catch (ResourceException rx){
            assertEquals(rx.getCode(), 404);
            assertTrue(rx.getMessage().contains("unknown principal"));
        }
        jdbcConn.close();
    }

    @Test
    public void testListRoleMembersWithPending() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7); // return domain/role id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for role id
                .thenReturn(true) // first std user
                .thenReturn(false) // end of standard role members
                .thenReturn(true) // pending members
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(false);

        // since our data is returned as sorted, we're going
        // to return data in sorted order
        Mockito.when(mockResultSet.getString(1))
                .thenReturn("a-domain.stduser1")
                .thenReturn("b-domain.pendinguser1")
                .thenReturn("c-domain.pendinguser2")
                .thenReturn("d-domain.pendinguser3");
        Mockito.when(mockResultSet.getTimestamp(2))
                .thenReturn(new java.sql.Timestamp(System.currentTimeMillis() + 100))
                .thenReturn(new java.sql.Timestamp(System.currentTimeMillis() + 200))
                .thenReturn(null);
        Mockito.when(mockResultSet.getTimestamp(3))
                .thenReturn(new java.sql.Timestamp(System.currentTimeMillis() + 100))
                .thenReturn(new java.sql.Timestamp(System.currentTimeMillis() + 200))
                .thenReturn(null);
        Mockito.when(mockResultSet.getTimestamp(4))
                .thenReturn(new java.sql.Timestamp(System.currentTimeMillis() + 100))
                .thenReturn(new java.sql.Timestamp(System.currentTimeMillis() + 200))
                .thenReturn(null);
        Mockito.when(mockResultSet.getBoolean(3))
                .thenReturn(true);

        List<RoleMember> roleMembers = jdbcConn.listRoleMembers("my-domain", "role1", true);

        // data back is sorted

        assertEquals(4, roleMembers.size());

        assertNotNull(roleMembers.get(0).getExpiration());
        assertNotNull(roleMembers.get(1).getExpiration());
        assertNull(roleMembers.get(2).getExpiration());
        assertNull(roleMembers.get(3).getExpiration());

        assertNotNull(roleMembers.get(0).getReviewReminder());
        assertNotNull(roleMembers.get(1).getReviewReminder());
        assertNull(roleMembers.get(2).getReviewReminder());
        assertNull(roleMembers.get(3).getReviewReminder());

        assertEquals("a-domain.stduser1", roleMembers.get(0).getMemberName());
        assertEquals("b-domain.pendinguser1", roleMembers.get(1).getMemberName());
        assertEquals("c-domain.pendinguser2", roleMembers.get(2).getMemberName());
        assertEquals("d-domain.pendinguser3", roleMembers.get(3).getMemberName());

        assertTrue(roleMembers.get(0).getApproved());
        assertFalse(roleMembers.get(1).getApproved());
        assertFalse(roleMembers.get(2).getApproved());
        assertFalse(roleMembers.get(3).getApproved());

        assertNull(roleMembers.get(0).getRequestTime());
        assertNotNull(roleMembers.get(1).getRequestTime());
        assertNotNull(roleMembers.get(2).getRequestTime());
        assertNull(roleMembers.get(3).getRequestTime());

        jdbcConn.close();
    }

    @Test
    public void testGetPendingMembershipApproverRoles() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(true)//domain id lookup for sys.auth.audit.org
                .thenReturn(true)//domain id lookup for sys.auth.audit.domain
                .thenReturn(true)//org org1
                .thenReturn(true)//org1 role id lookup
                .thenReturn(true)//dom1 lookup
                .thenReturn(true)//null org
                .thenReturn(true)//dom1 lookup
                .thenReturn(true)//null org
                .thenReturn(true)//dom1 lookup
                .thenReturn(true)//empty org
                .thenReturn(true)//dom1 lookup
                .thenReturn(false)//org loop ends
                .thenReturn(true)//one self serve role found
                .thenReturn(false);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(7) // sys.auth.audit.org domain
                .thenReturn(9) // sys.auth.audit.domain domain
                .thenReturn(11) // org1 role id
                .thenReturn(0); // dom1 - not found
        Mockito.when(mockResultSet.getString(1))
                .thenReturn("org1", null, null, "", "mytestdomain");
        Mockito.when(mockResultSet.getString(2))
                .thenReturn("dom1");

        long timestamp = new Date().getTime();
        java.sql.Timestamp ts = new java.sql.Timestamp(timestamp);

        Set<String> roles = jdbcConn.getPendingMembershipApproverRoles("localhost", timestamp);

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(4)).setInt(1, 9);

        Mockito.verify(mockPrepStmt, times(2)).setTimestamp(1, ts);
        Mockito.verify(mockPrepStmt, times(2)).setString(2, "localhost");

        assertNotNull(roles);
        assertEquals(roles.size(), 2);

        assertTrue(roles.contains("sys.auth.audit.org:role.org1"));
        assertTrue(roles.contains("mytestdomain:role.admin"));

        jdbcConn.close();
    }

    @Test
    public void testGetPendingMembershipApproverRolesDomain() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(true)//domain id lookup for sys.auth.audit.org
                .thenReturn(true)//domain id lookup for sys.auth.audit.domain
                .thenReturn(true)//org org1
                .thenReturn(false)//org1 no role
                .thenReturn(true)//dom1 lookup
                .thenReturn(true)//null org
                .thenReturn(true)//dom1 lookup
                .thenReturn(false)//org loop ends
                .thenReturn(true)//one self serve role found
                .thenReturn(false);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(7) // sys.auth.audit.org domain
                .thenReturn(9) // sys.auth.audit.domain domain
                .thenReturn(0) // org1 role id
                .thenReturn(13); // dom1 role id
        Mockito.when(mockResultSet.getString(1))
                .thenReturn("org1", null, "mytestdomain");
        Mockito.when(mockResultSet.getString(2))
                .thenReturn("mytestdomain");

        long timestamp = new Date().getTime();
        java.sql.Timestamp ts = new java.sql.Timestamp(timestamp);

        Set<String> roles = jdbcConn.getPendingMembershipApproverRoles("localhost", timestamp);

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(2)).setInt(1, 9);

        Mockito.verify(mockPrepStmt, times(2)).setTimestamp(1, ts);
        Mockito.verify(mockPrepStmt, times(2)).setString(2, "localhost");

        assertNotNull(roles);
        assertEquals(roles.size(), 2);

        assertTrue(roles.contains("sys.auth.audit.domain:role.mytestdomain"));
        assertTrue(roles.contains("mytestdomain:role.admin"));

        jdbcConn.close();
    }

    @Test
    public void testGetPendingMembershipApproverRolesOrgError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true).thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getPendingMembershipApproverRoles("localhost", 0L);
            fail();
        } catch (RuntimeException rx) {
            assertTrue(rx.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetPendingMembershipApproverRolesAuditEnabledError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true, true, true)
                .thenThrow(new SQLException("sql error"));
        Mockito.when(mockResultSet.getInt(1)).thenReturn(7);
        Mockito.when(mockResultSet.getString(1)).thenReturn("org1", null, null, "", "mytestdomain");
        try {
            jdbcConn.getPendingMembershipApproverRoles("localhost", 0L);
            fail();
        } catch (RuntimeException rx) {
            assertTrue(rx.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetPendingMembershipApproverRolesSelfServeError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(true)//domain id lookup for sys.auth.audit.org
                .thenReturn(true)//domain id lookup for sys.auth.audit.domain
                .thenReturn(true)//org org1
                .thenReturn(true)//org1 role id lookup
                .thenReturn(true)//dom1 lookup
                .thenReturn(true)//null org
                .thenReturn(true)//dom1 lookup
                .thenReturn(true)//null org
                .thenReturn(true)//dom1 lookup
                .thenReturn(true)//empty org
                .thenReturn(true)//dom1 lookup
                .thenReturn(false)//org loop ends
                .thenThrow(new SQLException("sql error"));
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(7) // sys.auth.audit.org domain
                .thenReturn(9) // sys.auth.audit.domain domain
                .thenReturn(11) // org1 role id
                .thenReturn(0); // dom1 - not found
        Mockito.when(mockResultSet.getString(1))
                .thenReturn("org1", null, null, "", "mytestdomain");
        Mockito.when(mockResultSet.getString(2))
                .thenReturn("dom1");

        try {
            jdbcConn.getPendingMembershipApproverRoles("localhost", 0L);
            fail();
        } catch (RuntimeException rx) {
            assertTrue(rx.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetExpiredPendingMembers() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // first pending member found
                .thenReturn(true) // second pending member found
                .thenReturn(false);
        Mockito.when(mockResultSet.getString(1))
                .thenReturn("dom1") //first pending member domain
                .thenReturn("dom2"); // second pending member domain
        Mockito.when(mockResultSet.getString(2))
                .thenReturn("role1") //first pending member role
                .thenReturn("role2"); // second pending member role
        Mockito.when(mockResultSet.getString(3))
                .thenReturn("user.user1") //first pending
                .thenReturn("user.user2"); // second pending
        Mockito.when(mockResultSet.getTimestamp(4))
                .thenReturn(null);
        Mockito.when(mockResultSet.getString(5))
                .thenReturn("ref1") //first pending member audit-reference
                .thenReturn("ref2"); // second pending member audit-reference

        Map<String, List<DomainRoleMember>> memberList = jdbcConn.getExpiredPendingDomainRoleMembers(40);
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 40);

        assertNotNull(memberList);
        assertEquals(memberList.size(), 2);

        List<DomainRoleMember> domainRoleMembers = memberList.get("dom1");
        assertNotNull(domainRoleMembers);
        assertEquals(domainRoleMembers.size(), 1);
        DomainRoleMember domainRoleMember = domainRoleMembers.get(0);
        assertEquals(domainRoleMember.getMemberName(), "user.user1");
        List<MemberRole> memberRoles = domainRoleMember.getMemberRoles();
        assertEquals(memberRoles.size(), 1);
        MemberRole memberRole = memberRoles.get(0);
        assertEquals(memberRole.getRoleName(), "role1");

        domainRoleMembers = memberList.get("dom2");
        assertNotNull(domainRoleMembers);
        assertEquals(domainRoleMembers.size(), 1);
        domainRoleMember = domainRoleMembers.get(0);
        assertEquals(domainRoleMember.getMemberName(), "user.user2");
        memberRoles = domainRoleMember.getMemberRoles();
        assertEquals(memberRoles.size(), 1);
        memberRole = memberRoles.get(0);
        assertEquals(memberRole.getRoleName(), "role2");

        jdbcConn.close();
    }

    @Test
    public void testProcessExpiredPendingMembersError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // first pending member found
                .thenReturn(true) // second pending member found
                .thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getExpiredPendingDomainRoleMembers(30);
            fail();
        } catch (RuntimeException rx) {
            assertTrue(rx.getMessage().contains("sql error"));
        }

        jdbcConn.close();
    }

    @Test
    public void testProcessDeletePendingMembersDeleteError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // first pending member found
                .thenThrow(new SQLException("sql error"));
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(4)//first role id
                .thenReturn(6);//second role id
        Mockito.when(mockResultSet.getString(2))
                .thenReturn("user.user1") //first pending
                .thenReturn("user.user2"); // second pending

        try {
            jdbcConn.getExpiredPendingDomainRoleMembers(40);
            fail();
        } catch (RuntimeException rx) {
            assertTrue(rx.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testExecuteDeletePendingRoleMemberDeleteFail() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeUpdate())
                .thenReturn(1) // delete with audit
                .thenReturn(0) // audit insert
                .thenReturn(1) // delete without audit successful
                .thenReturn(0); // delete fail

        assertFalse(jdbcConn.executeDeletePendingRoleMember(5, 7, "", "", "", true, ""));
        assertTrue(jdbcConn.executeDeletePendingRoleMember(5, 7, "", "", "", false, ""));
        assertFalse(jdbcConn.executeDeletePendingRoleMember(5, 7, "", "", "", false, ""));
        jdbcConn.close();
    }

    @Test
    public void testDeletePendingRoleMemberDeleteSqlError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeUpdate())
                .thenThrow(new SQLException("sql error"));

        try {
            jdbcConn.executeDeletePendingRoleMember(5, 7, "", "", "", true, "");
            fail();
        } catch (RuntimeException rx) {
            assertTrue(rx.getMessage().contains("sql error"));
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdatePendingRoleMembersNotificationTimestamp() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeUpdate())
                .thenReturn(3); // 3 members updated
        long timestamp = new Date().getTime();
        boolean result = jdbcConn.updatePendingRoleMembersNotificationTimestamp("localhost", timestamp, 0);
        java.sql.Timestamp ts = new java.sql.Timestamp(timestamp);
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(1, ts);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "localhost");
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(3, ts);
        assertTrue(result);
        jdbcConn.close();
    }

    @Test
    public void testUpdatePendingRoleMembersNotificationTimestampError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeUpdate())
                .thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.updatePendingRoleMembersNotificationTimestamp("localhost", 0L, 0);
            fail();
        } catch (RuntimeException rx) {
            assertTrue(rx.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testDeletePendingRoleMember()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // role id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for role id
                .thenReturn(true); // principal id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.deletePendingRoleMember("my-domain", "role1", "user.user1",
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
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "REJECT");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "audit-ref");

        jdbcConn.close();
    }

    @Test
    public void testDeletePendingRoleMemberInvalidDomain()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        try {
            jdbcConn.deletePendingRoleMember("my-domain", "role1", "user.user1",
                    "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("my-domain"));
        }

        jdbcConn.close();
    }

    @Test
    public void testDeletePendingRoleMemberInvalidRole()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(false); // this one is for role id

        try {
            jdbcConn.deletePendingRoleMember("my-domain", "role1", "user.user1",
                    "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("role1"));
        }

        jdbcConn.close();
    }

    @Test
    public void testDeletePendingRoleMemberInvalidPrincipal()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // role id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for role id
                .thenReturn(false); // principal id

        try {
            jdbcConn.deletePendingRoleMember("my-domain", "role1", "user.user1",
                    "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("user.user1"));
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdateRoleMemberExpirationNotificationTimestamp() throws Exception {
        testUpdateRoleMemberNotificationTimestamp(true);
    }

    @Test
    public void testUpdateRoleMemberReviewNotificationTimestamp() throws Exception {
        testUpdateRoleMemberNotificationTimestamp(false);
    }

    private void testUpdateRoleMemberNotificationTimestamp(boolean isRoleExpire) throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeUpdate())
                .thenReturn(3); // 3 members updated
        long timestamp = System.currentTimeMillis();
        boolean result = isRoleExpire ?
                jdbcConn.updateRoleMemberExpirationNotificationTimestamp("localhost", timestamp, 1) :
                jdbcConn.updateRoleMemberReviewNotificationTimestamp("localhost", timestamp, 1);
        java.sql.Timestamp ts = new java.sql.Timestamp(timestamp);
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(1, ts);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "localhost");
        assertTrue(result);
        jdbcConn.close();
    }

    @Test
    public void testUpdateRoleMemberExpirationNotificationTimestampError() throws Exception {
        testUpdateRoleMemberNotificationTimestampError(true);
    }

    @Test
    public void testUpdateRoleMemberReviewNotificationTimestampError() throws Exception {
        testUpdateRoleMemberNotificationTimestampError(false);
    }

    private void testUpdateRoleMemberNotificationTimestampError(boolean isRoleExpire) throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeUpdate())
                .thenThrow(new SQLException("sql error"));
        try {
            if (isRoleExpire) {
                jdbcConn.updateRoleMemberExpirationNotificationTimestamp("localhost", System.currentTimeMillis(), 1);
            } else {
                jdbcConn.updateRoleMemberReviewNotificationTimestamp("localhost", System.currentTimeMillis(), 1);
            }
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetNotifyTemporaryRoleMembers() throws Exception {
        testGetNotifyRoleMembers(true);
    }

    @Test
    public void testGetNotifyReviewRoleMembers() throws Exception {
        testGetNotifyRoleMembers(false);
    }

    private void testGetNotifyRoleMembers(boolean isRoleExpire) throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_PRINCIPAL_NAME))
                .thenReturn("user.joe")
                .thenReturn("user.joe")
                .thenReturn("user.jane");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE_NAME))
                .thenReturn("role1")
                .thenReturn("rols2")
                .thenReturn("role3");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_DOMAIN_NAME))
                .thenReturn("athenz1")
                .thenReturn("athenz1")
                .thenReturn("athenz2");
        java.sql.Timestamp ts = new java.sql.Timestamp(System.currentTimeMillis());
        Mockito.when(mockResultSet.getTimestamp(ZMSConsts.DB_COLUMN_EXPIRATION))
                .thenReturn(ts);
        Mockito.when(mockResultSet.getTimestamp(ZMSConsts.DB_COLUMN_REVIEW_REMINDER))
                .thenReturn(ts);
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for user.joe in athenz1
                .thenReturn(true) // this one is for user.joe in athenz2
                .thenReturn(true) // this one is for user.jane in athenz2
                .thenReturn(false); // end

        long timestamp = System.currentTimeMillis();
        Map<String, DomainRoleMember> memberMap = isRoleExpire ?
                jdbcConn.getNotifyTemporaryRoleMembers("localhost", timestamp) :
                jdbcConn.getNotifyReviewRoleMembers("localhost", timestamp);
        assertNotNull(memberMap);
        assertEquals(memberMap.size(), 2);
        assertTrue(memberMap.containsKey("user.joe"));
        assertTrue(memberMap.containsKey("user.jane"));
        jdbcConn.close();
    }

    @Test
    public void testGetNotifyTemporaryRoleMembersError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeQuery())
                .thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getNotifyTemporaryRoleMembers("localhost", System.currentTimeMillis());
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetNotifyReviewRoleMembersError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeQuery())
                .thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getNotifyReviewRoleMembers("localhost", System.currentTimeMillis());
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testUpdateRoleReviewTimestampSuccess() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // role id

        boolean requestSuccess = jdbcConn.updateRoleReviewTimestamp("my-domain", "role1");
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
    public void testUpdateRoleReviewTimestampFailure() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // role id

        boolean requestSuccess = jdbcConn.updateRoleReviewTimestamp("my-domain", "role1");
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
    public void testUpdateRoleReviewTimestampFailureInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(true)
                .thenReturn(false);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(0); // domain id

        try {
            jdbcConn.updateRoleReviewTimestamp("my-domain", "role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdateRoleReviewTimestampFailureInvalidRole() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(true)
                .thenReturn(false);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id

        try {
            jdbcConn.updateRoleReviewTimestamp("my-domain", "role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdateRoleReviewTimestampException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // role id
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.updateRoleReviewTimestamp("my-domain", "role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testGetDomainTemplates() throws Exception {
        Mockito.when(mockResultSet.next())
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(false);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // domain id
        Mockito.doReturn(12345).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_DOMAIN_ID);
        Mockito.doReturn("vipng").when(mockResultSet).getString(ZMSConsts.DB_COLUMN_TEMPLATE_NAME);
        Mockito.doReturn(100).when(mockResultSet).getInt(ZMSConsts.DB_COLUMN_TEMPLATE_VERSION);

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        List<TemplateMetaData> templateDomainMappingList  = jdbcConn.getDomainTemplates("vipng");
        assertNotNull(templateDomainMappingList);
        for (TemplateMetaData meta:templateDomainMappingList) {
            assertEquals(100,meta.getCurrentVersion().intValue());
        }
        jdbcConn.close();
    }

    @Test
    public void testListRolesWithUserAuthorityRestrictions() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        // we have 3 entries being returned
        Mockito.when(mockResultSet.next())
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(false);
        Mockito.when(mockResultSet.getString("domain_name"))
                .thenReturn("athenz")
                .thenReturn("athenz.subdomain")
                .thenReturn("sports");
        Mockito.when(mockResultSet.getString("role_name"))
                .thenReturn("admin")
                .thenReturn("readers")
                .thenReturn("readers");
        Mockito.when(mockResultSet.getString("domain_user_authority_filter"))
                .thenReturn("OnShore-US")
                .thenReturn("")
                .thenReturn("");

        List<PrincipalRole> roles = jdbcConn.listRolesWithUserAuthorityRestrictions();

        // data back is sorted

        assertEquals(3, roles.size());
        assertEquals("athenz", roles.get(0).getDomainName());
        assertEquals("admin", roles.get(0).getRoleName());
        assertEquals("OnShore-US", roles.get(0).getDomainUserAuthorityFilter());

        assertEquals("athenz.subdomain", roles.get(1).getDomainName());
        assertEquals("readers", roles.get(1).getRoleName());
        assertTrue(roles.get(1).getDomainUserAuthorityFilter().isEmpty());

        assertEquals("sports", roles.get(2).getDomainName());
        assertEquals("readers", roles.get(2).getRoleName());
        assertTrue(roles.get(2).getDomainUserAuthorityFilter().isEmpty());

        jdbcConn.close();
    }

    @Test
    public void testListRolesWithUserAuthorityRestrictionsException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.listRolesWithUserAuthorityRestrictions();
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetDomainFromTemplateName() throws Exception {
        Map<String, Integer> templateDetails = new HashMap<>();
        templateDetails.put("aws", 1);
        templateDetails.put("aws_bastion", 2);
        String domainName = "testdom";
        String templateName1 = "testtemplate";
        String templateName2 = "testtemplate2";

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getString("name"))
                .thenReturn(domainName); // domain name
        Mockito.when(mockResultSet.getString("template"))
                .thenReturn(templateName1); // template name
        Mockito.when(mockResultSet.getString("name"))
                .thenReturn(domainName);
        Mockito.when(mockResultSet.getString("template"))
                .thenReturn(templateName2);

        Mockito.when(mockResultSet.next())
                .thenReturn(true).thenReturn(true).thenReturn(false);

        Mockito.when(mockPrepStmt.executeQuery())
                .thenReturn(mockResultSet);

        Map<String, List<String>> domainTemplateMapping = jdbcConn.getDomainFromTemplateName(templateDetails);
        assertEquals(domainTemplateMapping.size(), 1);

        jdbcConn.close();

    }

    @Test
    public void testGetDomainFromTemplateNameException() throws Exception {

        Map<String, Integer> templateDetails = new HashMap<>();
        String templateName1 = "aws";
        String templateName2 = "aws_bastion";
        templateDetails.put(templateName1, 1);
        templateDetails.put(templateName2, 2);
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getDomainFromTemplateName(templateDetails);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGenerateDomainTemplateVersionQuery() throws SQLException {
        Map<String, Integer> templateDetails = new HashMap<>();
        String templateName1 = "aws";
        String templateName2 = "aws_bastion";
        templateDetails.put(templateName1, 1);
        templateDetails.put(templateName2, 2);
        String expectedQuery = "SELECT domain.name, domain_template.template FROM domain_template JOIN domain ON domain_template.domain_id=domain.domain_id WHERE" +
                " (domain_template.template = 'aws_bastion' and current_version < 2) OR (domain_template.template = 'aws' and current_version < 1);";
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        String generatedQuery = jdbcConn.generateDomainTemplateVersionQuery(templateDetails);
        assertNotNull(generatedQuery);
        assertEquals(generatedQuery, expectedQuery);
    }

    @Test
    public void testUpdateRoleMemberDisabledStateEnable()  throws Exception {
        testUpdateRoleMemberDisableState(0, "ENABLE");
    }

    @Test
    public void testUpdateRoleMemberDisabledStateDisable()  throws Exception {
        testUpdateRoleMemberDisableState(1, "DISABLE");
    }

    private void testUpdateRoleMemberDisableState(int state, final String operation) throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // role id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for role id
                .thenReturn(true); // principal id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.updateRoleMemberDisabledState("my-domain", "role1", "user.user1",
                "user.admin", state, "audit-ref");
        assertTrue(requestSuccess);

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        // attributes set for disabling

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, state);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "audit-ref");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setInt(4, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(5, 9);

        // the rest of the audit log details

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, operation);
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "audit-ref");

        jdbcConn.close();
    }

    @Test
    public void testUpdateRoleMemberDisableStateInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.updateRoleMemberDisabledState("my-domain", "role1", "user.user1",
                    "user.admin", 0, "audit-ref");
            fail();
        } catch (ResourceException rx) {
            assertEquals(rx.getCode(), 404);
            assertTrue(rx.getMessage().contains("unknown domain"));
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdateRoleMemberDisableStateInvalidRole() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(false); // this one is for role id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.updateRoleMemberDisabledState("my-domain", "role1", "user.user1",
                    "user.admin", 0, "audit-ref");
            fail();
        } catch (ResourceException rx) {
            assertEquals(rx.getCode(), 404);
            assertTrue(rx.getMessage().contains("unknown role"));
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdateRoleMemberDisableStateInvalidPrincipal() throws Exception {

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
            jdbcConn.updateRoleMemberDisabledState("my-domain", "role1", "user.user1",
                    "user.admin", 0, "audit-ref");
            fail();
        } catch (ResourceException rx) {
            assertEquals(rx.getCode(), 404);
            assertTrue(rx.getMessage().contains("unknown principal"));
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdateRoleMemberDisableStateFailedUpdate() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // role id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for role id
                .thenReturn(true); // principal id

        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.updateRoleMemberDisabledState("my-domain", "role1", "user.user1",
                "user.admin", 1, "audit-ref");
        assertFalse(requestSuccess);

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        // attributes set for disabling

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 1);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "audit-ref");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setInt(4, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(5, 9);

        // no audit logs since we didn't get a successful response

        Mockito.verify(mockPrepStmt, times(0)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(0)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(0)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(0)).setString(4, "DISABLE");
        Mockito.verify(mockPrepStmt, times(0)).setString(5, "audit-ref");

        jdbcConn.close();
    }

    @Test
    public void testUpdateRoleMemberDisableStateFailedUpdateException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // role id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for role id
                .thenReturn(true); // principal id

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.updateRoleMemberDisabledState("my-domain", "role1", "user.user1",
                    "user.admin", 1, "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role1");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        // attributes set for disabling

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 1);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "audit-ref");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setInt(4, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(5, 9);

        // no audit logs since we didn't get a successful response

        Mockito.verify(mockPrepStmt, times(0)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(0)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(0)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(0)).setString(4, "DISABLE");
        Mockito.verify(mockPrepStmt, times(0)).setString(5, "audit-ref");

        jdbcConn.close();
    }

    @Test
    public void testGetExpiredPendingGroupMembers() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // first pending member found
                .thenReturn(true) // second pending member found
                .thenReturn(false);
        Mockito.when(mockResultSet.getString(1))
                .thenReturn("dom1") //first pending member domain
                .thenReturn("dom2"); // second pending member domain
        Mockito.when(mockResultSet.getString(2))
                .thenReturn("group1") //first pending member group
                .thenReturn("group2"); // second pending member group
        Mockito.when(mockResultSet.getString(3))
                .thenReturn("user.user1") //first pending
                .thenReturn("user.user2"); // second pending
        Mockito.when(mockResultSet.getTimestamp(4))
                .thenReturn(null);
        Mockito.when(mockResultSet.getString(5))
                .thenReturn("ref1") //first pending member audit-reference
                .thenReturn("ref2"); // second pending member audit-reference

        Map<String, List<DomainGroupMember>> memberList = jdbcConn.getExpiredPendingDomainGroupMembers(40);
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 40);

        assertNotNull(memberList);
        assertEquals(memberList.size(), 2);

        List<DomainGroupMember> domainGroupMembers = memberList.get("dom1");
        assertNotNull(domainGroupMembers);
        assertEquals(domainGroupMembers.size(), 1);
        DomainGroupMember domainGroupMember = domainGroupMembers.get(0);
        assertEquals(domainGroupMember.getMemberName(), "user.user1");
        List<GroupMember> memberGroups = domainGroupMember.getMemberGroups();
        assertEquals(memberGroups.size(), 1);
        GroupMember groupMember = memberGroups.get(0);
        assertEquals(groupMember.getGroupName(), "group1");

        domainGroupMembers = memberList.get("dom2");
        assertNotNull(domainGroupMembers);
        assertEquals(domainGroupMembers.size(), 1);
        domainGroupMember = domainGroupMembers.get(0);
        assertEquals(domainGroupMember.getMemberName(), "user.user2");
        memberGroups = domainGroupMember.getMemberGroups();
        assertEquals(memberGroups.size(), 1);
        groupMember = memberGroups.get(0);
        assertEquals(groupMember.getGroupName(), "group2");

        jdbcConn.close();
    }

    @Test
    public void testProcessExpiredPendingGroupMembersError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // first pending member found
                .thenReturn(true) // second pending member found
                .thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getExpiredPendingDomainGroupMembers(30);
            fail();
        } catch (RuntimeException rx) {
            assertTrue(rx.getMessage().contains("sql error"));
        }

        jdbcConn.close();
    }

    @Test
    public void testProcessDeletePendingGroupMembersDeleteError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // first pending member found
                .thenThrow(new SQLException("sql error"));
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(4)//first group id
                .thenReturn(6);//second group id
        Mockito.when(mockResultSet.getString(2))
                .thenReturn("user.user1") // first pending
                .thenReturn("user.user2"); // second pending

        try {
            jdbcConn.getExpiredPendingDomainGroupMembers(40);
            fail();
        } catch (RuntimeException rx) {
            assertTrue(rx.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testExecuteDeletePendingGroupMemberDeleteFail() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeUpdate())
                .thenReturn(1) // delete with audit
                .thenReturn(0) // audit insert
                .thenReturn(1) // delete without audit successful
                .thenReturn(0); // delete fail

        assertFalse(jdbcConn.executeDeletePendingGroupMember(5, 7, "", "", "", true, ""));
        assertTrue(jdbcConn.executeDeletePendingGroupMember(5, 7, "", "", "", false, ""));
        assertFalse(jdbcConn.executeDeletePendingGroupMember(5, 7, "", "", "", false, ""));
        jdbcConn.close();
    }

    @Test
    public void testDeletePendingGroupMemberDeleteSqlError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeUpdate())
                .thenThrow(new SQLException("sql error"));

        try {
            jdbcConn.executeDeletePendingGroupMember(5, 7, "", "", "", true, "");
            fail();
        } catch (RuntimeException rx) {
            assertTrue(rx.getMessage().contains("sql error"));
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdatePendingGroupMembersNotificationTimestamp() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeUpdate())
                .thenReturn(3); // 3 members updated
        long timestamp = new Date().getTime();
        boolean result = jdbcConn.updatePendingGroupMembersNotificationTimestamp("localhost", timestamp, 0);
        java.sql.Timestamp ts = new java.sql.Timestamp(timestamp);
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(1, ts);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "localhost");
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(3, ts);
        assertTrue(result);
        jdbcConn.close();
    }

    @Test
    public void testUpdatePendingGroupMembersNotificationTimestampError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeUpdate())
                .thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.updatePendingGroupMembersNotificationTimestamp("localhost", 0L, 0);
            fail();
        } catch (RuntimeException rx) {
            assertTrue(rx.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testDeletePendingGroupMember()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true); // principal id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.deletePendingGroupMember("my-domain", "group1", "user.user1",
                "user.admin", "audit-ref");
        assertTrue(requestSuccess);

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group1");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        // we need additional operation for the audit log
        Mockito.verify(mockPrepStmt, times(2)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 9);

        // the rest of the audit log details

        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "REJECT");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "audit-ref");

        jdbcConn.close();
    }

    @Test
    public void testDeletePendingGroupMemberInvalidDomain()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        try {
            jdbcConn.deletePendingGroupMember("my-domain", "group1", "user.user1",
                    "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("my-domain"));
        }

        jdbcConn.close();
    }

    @Test
    public void testDeletePendingGroupMemberInvalidGroup()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(false); // this one is for group id

        try {
            jdbcConn.deletePendingGroupMember("my-domain", "group1", "user.user1",
                    "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("group1"));
        }

        jdbcConn.close();
    }

    @Test
    public void testDeletePendingGroupMemberInvalidPrincipal()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // group id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(false); // principal id

        try {
            jdbcConn.deletePendingGroupMember("my-domain", "group1", "user.user1",
                    "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("user.user1"));
        }

        jdbcConn.close();
    }

    @Test
    public void testInsertGroupMember() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true) // validate principle domain
                .thenReturn(true) // principal id
                .thenReturn(false); // member exists
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.insertGroupMember("my-domain", "group1",
                new GroupMember().setMemberName("user.user1"), "user.admin", "audit-ref");

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group1");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        // we need additional operation for the audit log
        // additional operation to check for groupMember exist using groupID and principal ID.
        Mockito.verify(mockPrepStmt, times(3)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(2)).setInt(2, 9);

        // the rest of the audit log details

        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "ADD");
        Mockito.verify(mockPrepStmt, times(2)).setString(5, "audit-ref");

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testInsertGroupMemberInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        try {
            jdbcConn.insertGroupMember("my-domain", "group1",
                    new GroupMember().setMemberName("user.user1"), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("my-domain"));
        }

        jdbcConn.close();
    }

    @Test
    public void testInsertGroupMemberInvalidGroup() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(false);// this one is for group id

        try {
            jdbcConn.insertGroupMember("my-domain", "group1",
                    new GroupMember().setMemberName("user.user1"), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("group1"));
        }

        jdbcConn.close();
    }

    @Test
    public void testInsertGroupMemberInvalidPrincipal() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // group id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(false); // validate principle domain

        try {
            jdbcConn.insertGroupMember("my-domain", "group1",
                    new GroupMember().setMemberName("user.user1"), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("user.user1"));
        }

        jdbcConn.close();
    }

    @Test
    public void testInsertGroupMemberUpdate() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true) // validate principle domain
                .thenReturn(true) // principal id
                .thenReturn(true); // member exists

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        GroupMember groupMember = new GroupMember().setMemberName("user.user1");
        Timestamp expiration = Timestamp.fromCurrentTime();
        groupMember.setExpiration(expiration);
        java.sql.Timestamp javaExpiration = new java.sql.Timestamp(expiration.toDate().getTime());
        boolean requestSuccess = jdbcConn.insertGroupMember("my-domain", "group1",
                groupMember, "user.admin", "audit-ref");

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group1");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        // we need additional operation for the audit log
        Mockito.verify(mockPrepStmt, times(2)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 9);

        // update operation
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(1, javaExpiration);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(2, true);
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "audit-ref");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setInt(5, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(6, 9);

        // the rest of the audit log details

        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "UPDATE");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "audit-ref");

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testInsertGroupMemberNewPrincipal() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(8) // principal domain id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true) // this one is for valid principal domain
                .thenReturn(false) // principal does not exist
                .thenReturn(true) // get last id (for new principal)
                .thenReturn(false); // group member exists

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.insertGroupMember("my-domain", "group1",
                new GroupMember().setMemberName("user.user1"),
                "user.admin", "audit-ref");

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group1");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user");

        // we're going to have 2 sets of operations for principal name

        Mockito.verify(mockPrepStmt, times(2)).setString(1, "user.user1");

        // we need additional operation for the audit log
        // additional operation to check for groupMember exist using groupID and principal ID.
        Mockito.verify(mockPrepStmt, times(3)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(2)).setInt(2, 9);

        // the rest of the audit log details

        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "ADD");
        Mockito.verify(mockPrepStmt, times(2)).setString(5, "audit-ref");

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testInsertGroupMemberException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(9) // member domain id
                .thenReturn(11); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true) // member domain id
                .thenReturn(true) // principal id
                .thenReturn(false); // group member exists

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(
                new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.insertGroupMember("my-domain", "group1",
                    new GroupMember().setMemberName("user.user1"),
                    "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertGroupMemberNewPrincipalFailure() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(8) // principal domain id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true) // this one is for valid principal domain
                .thenReturn(false) // principal does not exist
                .thenReturn(false); // last id returns 0

        // principal add returns success but unable to
        // fetch last id resulting principal id of 0

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.insertGroupMember("my-domain", "group1",
                    new GroupMember().setMemberName("user.user1"),
                    "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }

        jdbcConn.close();
    }

    @Test
    public void testInsertPendingGroupMember() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true) // validate principle domain
                .thenReturn(true) // principal id
                .thenReturn(false); // member exists
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.insertGroupMember("my-domain", "group1",
                new GroupMember().setApproved(false).setMemberName("user.user1"), "user.admin", "audit-ref");

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group1");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        // additional operation to check for groupMember exist using groupID and principal ID.
        Mockito.verify(mockPrepStmt, times(2)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(2)).setInt(2, 9);

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testInsertPendingGroupMemberUpdate() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true) // validate principle domain
                .thenReturn(true) // principal id
                .thenReturn(true); // member exists
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        long now = System.currentTimeMillis();
        boolean requestSuccess = jdbcConn.insertGroupMember("my-domain", "group1",
                new GroupMember()
                        .setApproved(false)
                        .setMemberName("user.user1")
                        .setExpiration(Timestamp.fromMillis(now)),
                "user.admin", "audit-ref");

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group1");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(1, new java.sql.Timestamp(now));
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "audit-ref");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setInt(4, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(5, 9);

        // operation to check for groupMember exist using groupID and principal ID.
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 9);

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testDeleteGroupMember()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true); // principal id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.deleteGroupMember("my-domain", "group1", "user.user1",
                "user.admin", "audit-ref");
        assertTrue(requestSuccess);

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group1");

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
    public void testDeleteGroupMemberInvalidDomain()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.deleteGroupMember("my-domain", "group1", "user.user1",
                    "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteGroupMemberInvalidGroup()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(false); // this one is for group id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.deleteGroupMember("my-domain", "group1", "user.user1",
                    "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteGroupMemberInvalidPrincipalId()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // group id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(false); // principal id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.deleteGroupMember("my-domain", "group1", "user.user1",
                    "user.admin", "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteExpiredGroupMember()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true) // principal id
                .thenReturn(true); // expiration
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.deleteExpiredGroupMember("my-domain", "group1", "user.user1",
                "user.admin", Timestamp.fromMillis(10000), "audit-ref");
        assertTrue(requestSuccess);

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group1");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(3, new java.sql.Timestamp(10000));

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
    public void testDeleteExpiredGroupMemberInvalidDomain()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.deleteExpiredGroupMember("my-domain", "group1", "user.user1",
                    "user.admin", Timestamp.fromMillis(10000), "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteExpiredGroupMemberInvalidGroup()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(false); // this one is for group id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.deleteExpiredGroupMember("my-domain", "group1", "user.user1",
                    "user.admin", Timestamp.fromMillis(10000), "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteExpiredGroupMemberInvalidPrincipalId()  throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // group id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(false); // principal id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.deleteExpiredGroupMember("my-domain", "group1", "user.user1",
                    "user.admin", Timestamp.fromMillis(10000), "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertGroupInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Group group = new Group().setName("my-domain2:group.group1");

        // domain mismatch - 400

        try {
            jdbcConn.insertGroup("my-domain", group);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }

        // domain not found - 404

        try {
            jdbcConn.insertGroup("my-domain2", group);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdateGroupInvalidGroupDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Group group = new Group().setName("my-domain2:group.group1");

        try {
            jdbcConn.updateGroup("my-domain", group);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }
        jdbcConn.close();
    }

    @Test
    public void testUpdateGroupInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Group group = new Group().setName("my-domain:group.group1");
        Mockito.when(mockResultSet.next()).thenReturn(false); // domain id failure

        try {
            jdbcConn.updateGroup("my-domain", group);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testUpdateGroupInvalidGroupId() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next())
                .thenReturn(true)
                .thenReturn(false);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id

        Group group = new Group().setName("my-domain:group.group1");

        try {
            jdbcConn.updateGroup("my-domain", group);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testUpdateGroupException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Group group = new Group().setName("my-domain:group.group1");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.updateGroup("my-domain", group);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testUpdateGroupModTimestampSuccess() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // group id

        boolean requestSuccess = jdbcConn.updateGroupModTimestamp("my-domain", "group1");
        assertTrue(requestSuccess);

        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        // get group id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group1");
        // update group time-stamp
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        jdbcConn.close();
    }

    @Test
    public void testUpdateGroupModTimestampFailure() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // group id

        boolean requestSuccess = jdbcConn.updateGroupModTimestamp("my-domain", "group1");
        assertFalse(requestSuccess);

        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        // get group id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group1");
        // update group time-stamp
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        jdbcConn.close();
    }

    @Test
    public void testUpdateGroupModTimestampFailureInvalidGroup() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(true)
                .thenReturn(false);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id

        try {
            jdbcConn.updateGroupModTimestamp("my-domain", "group1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdateGroupModTimestampException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.updateGroupModTimestamp("my-domain", "group1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteGroupInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(false);

        try {
            jdbcConn.deleteGroup("my-domain", "group1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteGroupException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.deleteGroup("my-domain", "group1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testCountGroups() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7); // return domain/count

        Mockito.when(mockResultSet.next()).thenReturn(true);

        assertEquals(jdbcConn.countGroups("my-domain"), 7);
        jdbcConn.close();
    }

    @Test
    public void testCountGroupsNoResult() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain/count

        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);

        assertEquals(jdbcConn.countGroups("my-domain"), 0);
        jdbcConn.close();
    }

    @Test
    public void testCountGroupsInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        try {
            jdbcConn.countGroups("my-domain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testCountGroupsException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id

        Mockito.when(mockResultSet.next())
                .thenReturn(true); // this one is for domain id

        Mockito.when(mockPrepStmt.executeQuery())
                .thenReturn(mockResultSet)
                .thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.countGroups("my-domain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testListGroupAuditLogsInvalidDomain() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // invalid domain

        try {
            jdbcConn.listGroupAuditLogs("my-domain", "group1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testListGroupAuditLogsInvalidGroup() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(true)   // domain id success
                .thenReturn(false); // group id failure
        Mockito.doReturn(5).when(mockResultSet).getInt(1); // return domain id

        try {
            jdbcConn.listGroupAuditLogs("my-domain", "group1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testListGroupAuditLogsException() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(true)   // domain id success
                .thenReturn(true);  // group id success
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5)  // domain id
                .thenReturn(7); // group id
        Mockito.when(mockPrepStmt.executeQuery())
                .thenReturn(mockResultSet)
                .thenReturn(mockResultSet)
                .thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.listGroupAuditLogs("my-domain", "group1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testListGroupMembersInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // invalid domain

        try {
            jdbcConn.listGroupMembers("my-domain", "group1", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testListGroupMembersInvalidGroup() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(false); // this one is for group id

        try {
            jdbcConn.listGroupMembers("my-domain", "group1", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testListGroupMembersException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7); // return domain id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for group id

        Mockito.when(mockPrepStmt.executeQuery())
                .thenReturn(mockResultSet)
                .thenReturn(mockResultSet)
                .thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.listGroupMembers("my-domain", "group1", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testCountGroupMembers() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7)
                .thenReturn(4); // return domain/group id/count

        Mockito.when(mockResultSet.next()).thenReturn(true);

        assertEquals(jdbcConn.countGroupMembers("my-domain", "group1"), 4);
        jdbcConn.close();
    }

    @Test
    public void testCountGroupMembersInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // invalid domain

        try {
            jdbcConn.countGroupMembers("my-domain", "group1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testCountGroupMembersInvalidGroup() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(false); // this one is for group id

        try {
            jdbcConn.countGroupMembers("my-domain", "group1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testCountGroupMembersException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7); // return domain id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for group id

        Mockito.when(mockPrepStmt.executeQuery())
                .thenReturn(mockResultSet)
                .thenReturn(mockResultSet)
                .thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.countGroupMembers("my-domain", "group1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testCountGroupMembersNoResult() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(7);

        Mockito.when(mockResultSet.next()).thenReturn(true)
                .thenReturn(true).thenReturn(false);

        assertEquals(jdbcConn.countGroupMembers("my-domain", "group1"), 0);
        jdbcConn.close();
    }

    @Test
    public void testUpdateGroupReviewTimestampFailure() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // group id

        boolean requestSuccess = jdbcConn.updateGroupReviewTimestamp("my-domain", "group1");
        assertFalse(requestSuccess);

        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");
        // get group id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group1");
        // update group time-stamp
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        jdbcConn.close();
    }

    @Test
    public void testUpdateGroupReviewTimestampFailureInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(true)
                .thenReturn(false);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(0); // domain id

        try {
            jdbcConn.updateGroupReviewTimestamp("my-domain", "group1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdateGroupReviewTimestampFailureInvalidGroup() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(true)
                .thenReturn(false);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id

        try {
            jdbcConn.updateGroupReviewTimestamp("my-domain", "group1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdateGroupReviewTimestampException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // group id
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.updateGroupReviewTimestamp("my-domain", "group1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testUpdateGroupMemberDisabledStateEnable()  throws Exception {
        testUpdateGroupMemberDisableState(0, "ENABLE");
    }

    @Test
    public void testUpdateGroupMemberDisabledStateDisable()  throws Exception {
        testUpdateGroupMemberDisableState(1, "DISABLE");
    }

    private void testUpdateGroupMemberDisableState(int state, final String operation) throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true); // principal id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.updateGroupMemberDisabledState("my-domain", "group1", "user.user1",
                "user.admin", state, "audit-ref");
        assertTrue(requestSuccess);

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group1");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        // attributes set for disabling

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, state);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "audit-ref");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setInt(4, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(5, 9);

        // the rest of the audit log details

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, operation);
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "audit-ref");

        jdbcConn.close();
    }

    @Test
    public void testUpdateGroupMemberDisableStateInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.updateGroupMemberDisabledState("my-domain", "group1", "user.user1",
                    "user.admin", 0, "audit-ref");
            fail();
        } catch (ResourceException rx) {
            assertEquals(rx.getCode(), 404);
            assertTrue(rx.getMessage().contains("unknown domain"));
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdateGroupMemberDisableStateInvalidGroup() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(false); // this one is for group id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.updateGroupMemberDisabledState("my-domain", "group1", "user.user1",
                    "user.admin", 0, "audit-ref");
            fail();
        } catch (ResourceException rx) {
            assertEquals(rx.getCode(), 404);
            assertTrue(rx.getMessage().contains("unknown group"));
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdateGroupMemberDisableStateInvalidPrincipal() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // group id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(false); // principal id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.updateGroupMemberDisabledState("my-domain", "group1", "user.user1",
                    "user.admin", 0, "audit-ref");
            fail();
        } catch (ResourceException rx) {
            assertEquals(rx.getCode(), 404);
            assertTrue(rx.getMessage().contains("unknown principal"));
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdateGroupMemberDisableStateFailedUpdate() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true); // principal id

        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.updateGroupMemberDisabledState("my-domain", "group1", "user.user1",
                "user.admin", 1, "audit-ref");
        assertFalse(requestSuccess);

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group1");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        // attributes set for disabling

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 1);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "audit-ref");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setInt(4, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(5, 9);

        // no audit logs since we didn't get a successful response

        Mockito.verify(mockPrepStmt, times(0)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(0)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(0)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(0)).setString(4, "DISABLE");
        Mockito.verify(mockPrepStmt, times(0)).setString(5, "audit-ref");

        jdbcConn.close();
    }

    @Test
    public void testUpdateGroupMemberDisableStateFailedUpdateException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true); // principal id

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.updateGroupMemberDisabledState("my-domain", "group1", "user.user1",
                    "user.admin", 1, "audit-ref");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group1");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        // attributes set for disabling

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 1);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "audit-ref");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setInt(4, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(5, 9);

        // no audit logs since we didn't get a successful response

        Mockito.verify(mockPrepStmt, times(0)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(0)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(0)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(0)).setString(4, "DISABLE");
        Mockito.verify(mockPrepStmt, times(0)).setString(5, "audit-ref");

        jdbcConn.close();
    }

    @Test
    public void testConfirmGroupMemberApprove() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.getString(1))
                .thenReturn(ZMSConsts.PENDING_REQUEST_ADD_STATE);
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true) // principal id
                .thenReturn(true) // this one is for pending state
                .thenReturn(false); // member does not exist in std table
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.confirmGroupMember("my-domain", "group1",
                new GroupMember().setMemberName("user.user1").setActive(true).setApproved(true),
                "user.admin", "audit-ref");

        // this is combined for all operations above

        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        // get group id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group1");

        //get principal
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        //get pending state
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.user1");

        Mockito.verify(mockPrepStmt, times(5)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(3)).setInt(2, 9);

        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(3, null);
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(4, true);
        Mockito.verify(mockPrepStmt, times(2)).setString(5, "audit-ref");

        // the rest of the audit log details

        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "APPROVE");

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testConfirmGroupMemberReject() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.getString(1))
                .thenReturn(ZMSConsts.PENDING_REQUEST_DELETE_STATE);
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true) // validate principle domain
                .thenReturn(true) // principal id
                .thenReturn(true); // member exists
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.confirmGroupMember("my-domain", "group1",
                new GroupMember().setMemberName("user.user1").setActive(false), "user.admin", "audit-ref");

        // this is combined for all operations above

        // get domain id
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        // get group id
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group1");

        //get principal
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.user1");

        // we need additional operation for the audit log
        // additional operation to check for groupMember exist using groupID and principal ID.
        Mockito.verify(mockPrepStmt, times(3)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 9);

        // the rest of the audit log details

        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.admin");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.user1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "REJECT");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "audit-ref");

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testConfirmGroupMemberErrors() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(0); // domain id

        Mockito.when(mockResultSet.getString(1))
                .thenReturn(ZMSConsts.PENDING_REQUEST_ADD_STATE);

        try {
            jdbcConn.confirmGroupMember("my-domain", "group", new GroupMember()
                    .setMemberName("user.user1").setActive(false), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException rx) {
            assertEquals(rx.getCode(), 404);
            assertTrue(rx.getMessage().contains("unknown domain"));
        }

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(0); // group id
        Mockito.when(mockResultSet.next())
                .thenReturn(true);

        try {
            jdbcConn.confirmGroupMember("my-domain1", "group1", new GroupMember()
                    .setMemberName("user.user1").setActive(false), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException rx) {
            assertEquals(rx.getCode(), 404);
            assertTrue(rx.getMessage().contains("unknown group"));
        }

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(0); // principal id

        try {
            jdbcConn.confirmGroupMember("my-domain2", "group2", new GroupMember()
                    .setMemberName("user1").setActive(false), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException rx) {
            assertEquals(rx.getCode(), 404);
            assertTrue(rx.getMessage().contains("unknown principal"));
        }

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(0); // principal id

        try {
            jdbcConn.confirmGroupMember("my-domain3", "group3", new GroupMember()
                    .setMemberName("user.user1").setActive(false), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException rx) {
            assertEquals(rx.getCode(), 404);
            assertTrue(rx.getMessage().contains("unknown principal"));
        }

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true) // validate principle domain
                .thenReturn(true) // principal id
                .thenReturn(false); // member exists

        assertFalse(jdbcConn.confirmGroupMember("my-domain4", "group4", new GroupMember()
                    .setMemberName("user.user1").setActive(true), "user.admin", "audit-ref"));

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true) // validate principle domain
                .thenReturn(true) // principal id
                .thenReturn(true); // member exists

        Mockito.doThrow(new SQLException("conflict", "08S01", 409)).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.confirmGroupMember("my-domain5", "group5", new GroupMember()
                    .setMemberName("user.user1").setActive(true), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException rx) {
            assertEquals(rx.getCode(), 409);
        }

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true) // validate principle domain
                .thenReturn(true) // principal id
                .thenReturn(true); // member exists

        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();

        boolean result = jdbcConn.confirmGroupMember("my-domain6", "group6", new GroupMember()
                .setMemberName("user.user1").setActive(true), "user.admin", "audit-ref");
        assertFalse(result);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true) // validate principle domain
                .thenReturn(true) // principal id
                .thenReturn(true); // member exists

        Mockito.doThrow(new SQLException("conflict", "08S01", 409)).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.confirmGroupMember("my-domain7", "group7", new GroupMember()
                    .setMemberName("user.user1").setActive(false), "user.admin", "audit-ref");
            fail();
        } catch (ResourceException rx) {
            assertEquals(rx.getCode(), 409);
        }

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7) // group id
                .thenReturn(9); // principal id
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for group id
                .thenReturn(true) // validate principle domain
                .thenReturn(true) // principal id
                .thenReturn(true); // member exists

        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();

        result = jdbcConn.confirmGroupMember("my-domain8", "group8", new GroupMember()
                .setMemberName("user.user1").setActive(false), "user.admin", "audit-ref");
        assertFalse(result);

        jdbcConn.close();
    }

    @Test
    public void testGetPrincipalGroupsInvalidDomain() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(1); // Principal id will be 1

        // domain group members
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // True for getting principal_id
                .thenThrow(new SQLException("error getting domain_id")); // Throw exception when trying to get domain_id

        String principalName = "user.testUser";

        try {
            jdbcConn.getPrincipalGroups(principalName, "unknownDomain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertEquals(ex.getData().toString(), "{code: 404, message: \"unknown domain - unknownDomain\"}");
        }
    }

    @Test
    public void testGetPrincipalGroupsInvalidPrincipal() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        try {
            jdbcConn.getPrincipalGroups("johndoe", null);
            fail();
        } catch (ResourceException exception) {
            assertEquals(exception.getCode(), ResourceException.NOT_FOUND);
            assertEquals(exception.getData().toString(), "{code: 404, message: \"unknown principal - johndoe\"}");
        }
    }

    @Test
    public void testGetPrincipalGroupsException() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(1);  // Principal id will be 1

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // True for getting principal_id
                .thenThrow(new SQLTimeoutException("failed operation - timeout", "state", 1001));

        try {
            jdbcConn.getPrincipalGroups("johndoe", null);
            fail();
        } catch (ResourceException exception) {
            assertEquals(exception.getCode(), 503);
            assertEquals(exception.getData().toString(), "{code: 503, message: \"Statement cancelled due to timeout\"}");

        }
    }

    @Test
    public void testGetPrincipalGroupsNoRuleMembers() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(1);  // Principal id will be 1
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // True for getting principal_id
                .thenReturn(false); // Not member of any groups

        DomainGroupMember domainGroupMember = jdbcConn.getPrincipalGroups("johndoe", null);
        assertEquals(domainGroupMember.getMemberName(), "johndoe");
        assertEquals(domainGroupMember.getMemberGroups().size(), 0);
    }

    @Test
    public void testGetGroupMemberInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); //lookup domain

        try {
            jdbcConn.getGroupMember("my-domain", "group1", "user.user1", 0, false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("my-domain"));
        }

        jdbcConn.close();
    }

    @Test
    public void testGetGroupMemberInvalidGroup() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(true) //lookup domain
                .thenReturn(false); //lookup group
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id

        try {
            jdbcConn.getRoleMember("my-domain", "group1", "user.user1", 0, false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("group1"));
        }

        jdbcConn.close();
    }

    @Test
    public void testListGroupsWithUserAuthorityRestrictions() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        // we have 3 entries being returned
        Mockito.when(mockResultSet.next())
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(false);
        Mockito.when(mockResultSet.getString("domain_name"))
                .thenReturn("athenz")
                .thenReturn("athenz.subdomain")
                .thenReturn("sports");
        Mockito.when(mockResultSet.getString("group_name"))
                .thenReturn("admin")
                .thenReturn("readers")
                .thenReturn("readers");
        Mockito.when(mockResultSet.getString("domain_user_authority_filter"))
                .thenReturn("OnShore-US")
                .thenReturn("")
                .thenReturn("");

        List<PrincipalGroup> groups = jdbcConn.listGroupsWithUserAuthorityRestrictions();

        // data back is sorted

        assertEquals(3, groups.size());
        assertEquals("athenz", groups.get(0).getDomainName());
        assertEquals("admin", groups.get(0).getGroupName());
        assertEquals("OnShore-US", groups.get(0).getDomainUserAuthorityFilter());

        assertEquals("athenz.subdomain", groups.get(1).getDomainName());
        assertEquals("readers", groups.get(1).getGroupName());
        assertTrue(groups.get(1).getDomainUserAuthorityFilter().isEmpty());

        assertEquals("sports", groups.get(2).getDomainName());
        assertEquals("readers", groups.get(2).getGroupName());
        assertTrue(groups.get(2).getDomainUserAuthorityFilter().isEmpty());

        jdbcConn.close();
    }

    @Test
    public void testListGroupsWithUserAuthorityRestrictionsException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.listGroupsWithUserAuthorityRestrictions();
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetNotifyGroupMembers() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_PRINCIPAL_NAME))
                .thenReturn("user.joe")
                .thenReturn("user.joe")
                .thenReturn("user.jane");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_AS_GROUP_NAME))
                .thenReturn("group1")
                .thenReturn("group2")
                .thenReturn("group3");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_DOMAIN_NAME))
                .thenReturn("athenz1")
                .thenReturn("athenz1")
                .thenReturn("athenz2");
        java.sql.Timestamp ts = new java.sql.Timestamp(System.currentTimeMillis());
        Mockito.when(mockResultSet.getTimestamp(ZMSConsts.DB_COLUMN_EXPIRATION))
                .thenReturn(ts);
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for user.joe in athenz1
                .thenReturn(true) // this one is for user.joe in athenz2
                .thenReturn(true) // this one is for user.jane in athenz2
                .thenReturn(false); // end

        long timestamp = System.currentTimeMillis();
        Map<String, DomainGroupMember> memberMap = jdbcConn.getNotifyTemporaryGroupMembers("localhost", timestamp);

        assertNotNull(memberMap);
        assertEquals(memberMap.size(), 2);
        assertTrue(memberMap.containsKey("user.joe"));
        assertTrue(memberMap.containsKey("user.jane"));
        jdbcConn.close();
    }

    @Test
    public void testGetNotifyTemporaryGroupMembersError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeQuery())
                .thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getNotifyTemporaryGroupMembers("localhost", System.currentTimeMillis());
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testUpdatePrincipal() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.updatePrincipal("user.user1", 1);
        assertTrue(requestSuccess);

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 1);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.user1");
        jdbcConn.close();
    }

    @Test
    public void testUpdatePrincipalInvalid() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();
        assertFalse(jdbcConn.updatePrincipal("user.user1", 1));
        jdbcConn.close();
    }

    @Test
    public void testUpdatePrincipalError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeUpdate())
                .thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.updatePrincipal("user.user1", 1);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetPrincipal() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(true).thenReturn(false);
        Mockito.doReturn("user.user1").when(mockResultSet).getString(1);
        Mockito.doReturn("user.user2").when(mockResultSet).getString(1);

        List<String> principals = jdbcConn.getPrincipals(1);
        assertFalse(principals.isEmpty());
        assertEquals(principals.size(), 2);
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 1);

        jdbcConn.close();
    }

    @Test
    public void testGetPrincipalEmpty() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(false);

        List<String> principals = jdbcConn.getPrincipals(1);
        assertTrue(principals.isEmpty());
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 1);

        jdbcConn.close();
    }

    @Test
    public void testGetPrincipalError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true).thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getPrincipals(1);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetRoleTags() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getString(1))
                .thenReturn("tagKey");
        Mockito.when(mockResultSet.getString(2))
                .thenReturn("tagVal1", "tagVal2");

        Mockito.when(mockResultSet.next())
                .thenReturn(true, true, false);

        Map<String, TagValueList> roleTags = jdbcConn.getRoleTags("domain", "role");
        assertNotNull(roleTags);

        TagValueList tagValues = roleTags.get("tagKey");

        assertNotNull(tagValues);
        assertTrue(tagValues.getList().containsAll(Arrays.asList("tagVal1", "tagVal2")));

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role");

        jdbcConn.close();
    }

    @Test
    public void testGetRoleTagsEmpty() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(false);

        Map<String, TagValueList> roleTags = jdbcConn.getRoleTags("domain", "role");
        assertNull(roleTags);
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role");

        jdbcConn.close();
    }

    @Test
    public void testGetRoleTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(true).thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getRoleTags("domain", "role");
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetRoleTagsCountError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getRoleTagsCount(101);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertRoleTags() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // role id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for role id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        Map<String, TagValueList> roleTags = Collections.singletonMap(
                "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
        );

        assertTrue(jdbcConn.insertRoleTags("role", "domain", roleTags));

        // domain
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "domain");
        // role
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role");
        // tag
        Mockito.verify(mockPrepStmt, times(2)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "tagKey");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "tagVal");

        jdbcConn.close();
    }

    @Test
    public void testInsertRoleTagsInvalid() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // role id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for role id

        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();
        Map<String, TagValueList> roleTags = Collections.singletonMap(
                "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
        );
        assertFalse(jdbcConn.insertRoleTags("role", "domain", roleTags));
        jdbcConn.close();
    }

    @Test
    public void testInsertRoleTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // role id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for role id
        Mockito.when(mockPrepStmt.executeUpdate())
                .thenThrow(new SQLException("sql error"));
        try {
            Map<String, TagValueList> roleTags = Collections.singletonMap(
                    "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
            );
            jdbcConn.insertRoleTags("role", "domain", roleTags);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertRoleTagsInvalidDomain() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id
        try {
            Map<String, TagValueList> roleTags = Collections.singletonMap(
                    "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
            );
            jdbcConn.insertRoleTags("role", "domain", roleTags);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertRoleTagsInvalidRole() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // domain id
        Mockito.when(mockResultSet.next()).thenReturn(true, false);
        try {
            Map<String, TagValueList> roleTags = Collections.singletonMap(
                    "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
            );
            jdbcConn.insertRoleTags("role", "domain", roleTags);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteRoleTags() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // role id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for role id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));

        assertTrue(jdbcConn.deleteRoleTags("role", "domain", tagKeys));

        // domain
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "domain");
        // role
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "role");
        // tag
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "tagKey");

        jdbcConn.close();
    }

    @Test
    public void testDeleteRoleTagsInvalid() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // role id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for role id
        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();
        Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));
        assertFalse(jdbcConn.deleteRoleTags("role", "domain", tagKeys));
        jdbcConn.close();
    }

    @Test
    public void testDeleteRoleTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // role id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for role id
        Mockito.when(mockPrepStmt.executeUpdate())
                .thenThrow(new SQLException("sql error"));
        try {
            Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));
            jdbcConn.deleteRoleTags("role", "domain", tagKeys);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteRoleTagsInvalidDomain() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id
        try {
            Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));
            jdbcConn.deleteRoleTags("role", "domain", tagKeys);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteRoleTagsInvalidRole() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // domain id
        Mockito.when(mockResultSet.next()).thenReturn(true, false);
        try {
            Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));
            jdbcConn.deleteRoleTags("role", "domain", tagKeys);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testGetDomainRoleTags() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getString(1))
                .thenReturn("role");
        Mockito.when(mockResultSet.getString(2))
                .thenReturn("tagKey");
        Mockito.when(mockResultSet.getString(3))
                .thenReturn("tagVal1", "tagVal2");

        Mockito.when(mockResultSet.next())
                .thenReturn(true, true, false);

        Map<String, Map<String, TagValueList>> domainRoleTags = jdbcConn.getDomainRoleTags("sys.auth");
        assertNotNull(domainRoleTags);

        Map<String, TagValueList> roleTags = domainRoleTags.get("role");
        TagValueList tagValues = roleTags.get("tagKey");

        assertNotNull(tagValues);
        assertTrue(tagValues.getList().containsAll(Arrays.asList("tagVal1", "tagVal2")));

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "sys.auth");

        jdbcConn.close();
    }

    @Test
    public void testGetDomainRoleTagsEmpty() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(false);

        Map<String, Map<String, TagValueList>> domainRoleTags = jdbcConn.getDomainRoleTags("sys.auth");
        assertNull(domainRoleTags);
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "sys.auth");

        jdbcConn.close();
    }

    @Test
    public void testGetDomainRoleTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(true).thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getDomainRoleTags("sys.auth");
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testLookupDomainByTags() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME))
            .thenReturn("domain-key-val").thenReturn("domain-key-only");

        Mockito.when(mockResultSet.next())
            .thenReturn(true, false, true, false);

        List<String> domains = jdbcConn.lookupDomainByTags("tagKey", "tagVal");
        assertEquals(domains.get(0), "domain-key-val");

        domains = jdbcConn.lookupDomainByTags("tagKey", null);
        assertEquals(domains.get(0), "domain-key-only");

        Mockito.verify(mockPrepStmt, times(2)).setString(1, "tagKey");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "tagVal");

        jdbcConn.close();
    }

    @Test
    public void testLookupDomainByTagsEmpty() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
            .thenReturn(false);

        List<String> domains = jdbcConn.lookupDomainByTags("tagKey", "tagVal");
        assertTrue(domains.isEmpty());

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "tagKey");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "tagVal");

        jdbcConn.close();
    }

    @Test
    public void testLookupDomainByTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
            .thenReturn(true).thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.lookupDomainByTags("tagKey", "tagVal");
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetDomainTags() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getString(1))
            .thenReturn("tagKey");
        Mockito.when(mockResultSet.getString(2))
            .thenReturn("tagVal1", "tagVal2");

        Mockito.when(mockResultSet.next())
            .thenReturn(true, true, false);

        Map<String, TagValueList> domainTags = jdbcConn.getDomainTags(5);
        assertNotNull(domainTags);

        TagValueList tagValues = domainTags.get("tagKey");

        assertNotNull(tagValues);
        assertTrue(tagValues.getList().containsAll(Arrays.asList("tagVal1", "tagVal2")));

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);

        jdbcConn.close();
    }

    @Test
    public void testGetDomainTagsEmpty() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
            .thenReturn(false);

        Map<String, TagValueList> domainTags = jdbcConn.getDomainTags(5);
        assertNull(domainTags);
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);

        jdbcConn.close();
    }

    @Test
    public void testGetDomainTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
            .thenReturn(true).thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getDomainTags(5);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertDomainTags() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id

        Mockito.when(mockResultSet.next())
            .thenReturn(true); // this one is for domain id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        Map<String, TagValueList> domainTags = Collections.singletonMap(
            "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
        );

        assertTrue(jdbcConn.insertDomainTags("domain", domainTags));

        // tag
        Mockito.verify(mockPrepStmt, times(2)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "tagKey");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "tagVal");

        jdbcConn.close();
    }

    @Test
    public void testInsertDomainTagsInvalid() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id

        Mockito.when(mockResultSet.next())
            .thenReturn(true); // this one is for domain id

        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();
        Map<String, TagValueList> domainTags = Collections.singletonMap(
            "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
        );
        assertFalse(jdbcConn.insertDomainTags("domain", domainTags));
        jdbcConn.close();
    }

    @Test
    public void testInsertDomainTagsUnknownDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(false); // this one is for domain id

        Map<String, TagValueList> domainTags = Collections.singletonMap(
                "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
        );
        try {
            jdbcConn.insertDomainTags("unknown-domain", domainTags);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        jdbcConn.close();
    }

    @Test
    public void testInsertDomainTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id

        Mockito.when(mockResultSet.next())
            .thenReturn(true); // this one is for domain id

        Mockito.when(mockPrepStmt.executeUpdate())
            .thenThrow(new SQLException("sql error"));
        try {
            Map<String, TagValueList> domainTags = Collections.singletonMap(
                "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
            );
            jdbcConn.insertDomainTags("domain",  domainTags);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteDomainTags() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id

        Mockito.when(mockResultSet.next())
            .thenReturn(true); // this one is for domain id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));

        assertTrue(jdbcConn.deleteDomainTags("domain", tagKeys));

        // tag
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "tagKey");

        jdbcConn.close();
    }

    @Test
    public void testDeleteDomainTagsUnknownDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(false); // this one is for domain id

        Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));
        try {
            jdbcConn.deleteDomainTags("unknown-domain", tagKeys);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        jdbcConn.close();
    }

    @Test
    public void testDeleteDomainTagsInvalid() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id

        Mockito.when(mockResultSet.next())
            .thenReturn(true); // this one is for domain id

        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();
        Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));
        assertFalse(jdbcConn.deleteDomainTags("domain", tagKeys));
        jdbcConn.close();
    }

    @Test
    public void testDeleteDomainTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
            .thenReturn(5); // domain id

        Mockito.when(mockResultSet.next())
            .thenReturn(true); // this one is for domain id

        Mockito.when(mockPrepStmt.executeUpdate())
            .thenThrow(new SQLException("sql error"));
        try {
            Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));
            jdbcConn.deleteDomainTags("domain", tagKeys);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetGroupTags() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getString(1))
                .thenReturn("tagKey");
        Mockito.when(mockResultSet.getString(2))
                .thenReturn("tagVal1", "tagVal2");

        Mockito.when(mockResultSet.next())
                .thenReturn(true, true, false);

        Map<String, TagValueList> groupTags = jdbcConn.getGroupTags("domain", "group");
        assertNotNull(groupTags);

        TagValueList tagValues = groupTags.get("tagKey");

        assertNotNull(tagValues);
        assertTrue(tagValues.getList().containsAll(Arrays.asList("tagVal1", "tagVal2")));

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group");

        jdbcConn.close();
    }

    @Test
    public void testGetGroupTagsEmpty() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(false);

        Map<String, TagValueList> groupTags = jdbcConn.getGroupTags("domain", "group");
        assertNull(groupTags);
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group");

        jdbcConn.close();
    }

    @Test
    public void testGetGroupTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(true).thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getGroupTags("domain", "group");
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertGroupTags() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // group id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for group id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        Map<String, TagValueList> groupTags = Collections.singletonMap(
                "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
        );

        assertTrue(jdbcConn.insertGroupTags("group", "domain", groupTags));

        // domain
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "domain");
        // group
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group");
        // tag
        Mockito.verify(mockPrepStmt, times(2)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "tagKey");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "tagVal");

        jdbcConn.close();
    }

    @Test
    public void testInsertGroupTagsInvalid() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // group id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for group id

        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();
        Map<String, TagValueList> groupTags = Collections.singletonMap(
                "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
        );
        assertFalse(jdbcConn.insertGroupTags("group", "domain", groupTags));
        jdbcConn.close();
    }

    @Test
    public void testInsertGroupTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // group id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for group id
        Mockito.when(mockPrepStmt.executeUpdate())
                .thenThrow(new SQLException("sql error"));
        try {
            Map<String, TagValueList> groupTags = Collections.singletonMap(
                    "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
            );
            jdbcConn.insertGroupTags("group", "domain", groupTags);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteGroupTags() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // group id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for group id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));

        assertTrue(jdbcConn.deleteGroupTags("group", "domain", tagKeys));

        // domain
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "domain");
        // role
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "group");
        // tag
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "tagKey");

        jdbcConn.close();
    }

    @Test
    public void testDeleteGroupTagsInvalid() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // group id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for group id
        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();
        Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));
        assertFalse(jdbcConn.deleteGroupTags("group", "domain", tagKeys));
        jdbcConn.close();
    }

    @Test
    public void testDeleteGroupTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // group id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for group id
        Mockito.when(mockPrepStmt.executeUpdate())
                .thenThrow(new SQLException("sql error"));
        try {
            Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));
            jdbcConn.deleteGroupTags("group", "domain", tagKeys);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetDomainGroupTags() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getString(1))
                .thenReturn("group");
        Mockito.when(mockResultSet.getString(2))
                .thenReturn("tagKey");
        Mockito.when(mockResultSet.getString(3))
                .thenReturn("tagVal1", "tagVal2");

        Mockito.when(mockResultSet.next())
                .thenReturn(true, true, false);

        Map<String, Map<String, TagValueList>> domainGroupTags = jdbcConn.getDomainGroupTags("sys.auth");
        assertNotNull(domainGroupTags);

        Map<String, TagValueList> groupTags = domainGroupTags.get("group");
        TagValueList tagValues = groupTags.get("tagKey");

        assertNotNull(tagValues);
        assertTrue(tagValues.getList().containsAll(Arrays.asList("tagVal1", "tagVal2")));

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "sys.auth");

        jdbcConn.close();
    }

    @Test
    public void testGetDomainGroupTagsEmpty() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(false);

        Map<String, Map<String, TagValueList>> domainGroupTags = jdbcConn.getDomainGroupTags("sys.auth");
        assertNull(domainGroupTags);
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "sys.auth");

        jdbcConn.close();
    }

    @Test
    public void testGetDomainGroupTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(true).thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getDomainGroupTags("sys.auth");
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetTrustedSubTypeRolesException() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("sql error"));

        try {
            Map<String, List<String>> trustedRoles = new HashMap<>();
            jdbcConn.getTrustedSubTypeRoles("SELECT * FROM assertion", trustedRoles, "test");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
    }

    @Test
    public void testGetRolesForPrincipalException() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("sql error"));

        try {
            jdbcConn.getRolesForPrincipal("user.user1", "test");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
    }

    @Test
    public void testGetGroupsForPrincipalException() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("sql error"));

        try {
            jdbcConn.getGroupsForPrincipal("user.user1", "test");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
    }

    @Test
    public void testUpdatePrincipalRoleGroupMembershipException() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("sql error"));

        try {
            jdbcConn.updatePrincipalRoleGroupMembership(Collections.emptySet(), Collections.emptySet(),
                    "user.user1", "test");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
    }

    @Test
    public void testGetRoleAssertionsException() throws SQLException {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("sql error"));

        try {
            jdbcConn.getRoleAssertions("update", "test");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
    }

    @Test
    public void testCountAssertionConditions() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true, false);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5);
        assertEquals(jdbcConn.countAssertionConditions(4), 5);
        jdbcConn.close();

        jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.countAssertionConditions(4);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetAssertionConditions() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true, false);

        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_KEY)).thenReturn("key1");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_OPERATOR)).thenReturn("EQUALS");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_VALUE)).thenReturn("value1");
        Mockito.when(mockResultSet.getInt(ZMSConsts.DB_COLUMN_CONDITION_ID)).thenReturn(1);
        AssertionCondition ac = new AssertionCondition().setId(1);
        Map<String, AssertionConditionData> m1 = new HashMap<>();
        m1.put("key1", new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value1"));
        ac.setConditionsMap(m1);
        List<AssertionCondition> actualList = jdbcConn.getAssertionConditions(4);
        org.hamcrest.MatcherAssert.assertThat(actualList, CoreMatchers.hasItems(ac));
        jdbcConn.close();

        jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getAssertionConditions(4);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetAssertionCondition() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true, false);

        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_KEY)).thenReturn("key1");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_OPERATOR)).thenReturn("EQUALS");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_VALUE)).thenReturn("value1");
        Mockito.when(mockResultSet.getInt(ZMSConsts.DB_COLUMN_CONDITION_ID)).thenReturn(1);
        AssertionCondition ac = new AssertionCondition().setId(1);
        Map<String, AssertionConditionData> m1 = new HashMap<>();
        m1.put("key1", new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value1"));
        ac.setConditionsMap(m1);

        assertEquals(jdbcConn.getAssertionCondition(4, 1), ac);
        jdbcConn.close();

        jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getAssertionCondition(4, 1);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertAssertionConditions() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        AssertionConditions assertionConditions = new AssertionConditions();
        AssertionCondition ac1 = new AssertionCondition().setId(1);
        Map<String, AssertionConditionData> m1 = new HashMap<>();
        m1.put("key1", new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value1"));
        ac1.setConditionsMap(m1);
        assertionConditions.setConditionsList(Collections.singletonList(ac1));

        Mockito.when(mockPrepStmt.executeQuery())
                .thenReturn(mockResultSet) // happy path
                .thenReturn(mockResultSet) // happy path 2
                .thenThrow(new SQLException("sql error")) // next condition id fail
                .thenReturn(mockResultSet); // insert assertion condition fail
        Mockito.when(mockResultSet.next()).thenReturn(true, true, false, false);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5).thenReturn(5);
        Mockito.when(mockPrepStmt.executeBatch()).thenReturn(new int[]{1}).thenReturn(new int[]{0}).thenThrow(new SQLException("sql error"));
        assertTrue(jdbcConn.insertAssertionConditions(4, assertionConditions));
        assertFalse(jdbcConn.insertAssertionConditions(4, assertionConditions));
        try {
            // fail to get next condition id
            jdbcConn.insertAssertionConditions(4, assertionConditions);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        try {
            // fail to insert assertion conditions
            jdbcConn.insertAssertionConditions(4, assertionConditions);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteAssertionConditions() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeUpdate()).thenReturn(2).thenReturn(0).thenThrow(new SQLException("sql error"));
        assertTrue(jdbcConn.deleteAssertionConditions(4));
        assertFalse(jdbcConn.deleteAssertionConditions(4));
        try {
            // fail to delete assertion conditions
            jdbcConn.deleteAssertionConditions(4);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteAssertionCondition() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeUpdate()).thenReturn(1).thenReturn(0).thenThrow(new SQLException("sql error"));
        assertTrue(jdbcConn.deleteAssertionCondition(4, 1));
        assertFalse(jdbcConn.deleteAssertionCondition(4, 1));
        try {
            // fail to delete assertion condition
            jdbcConn.deleteAssertionCondition(4, 1);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetNextAssertionCondition() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeQuery()).thenReturn(mockResultSet).thenThrow(new SQLException("sql error"));
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(1);
        assertEquals(jdbcConn.getNextConditionId(1, "caller"), 1);
        try {
            jdbcConn.getNextConditionId(1, "caller");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetAthenzDomainPolicies() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true, false, true, false, true, false);

        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME)).thenReturn("pol1");
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);

        Mockito.when(mockResultSet.getString(1)).thenReturn("pol1");

        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE)).thenReturn("role1");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_RESOURCE)).thenReturn("dom1:*");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ACTION)).thenReturn("*");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_EFFECT)).thenReturn("ALLOW");
        Mockito.when(mockResultSet.getLong(ZMSConsts.DB_COLUMN_ASSERT_ID)).thenReturn(1L);

        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_KEY)).thenReturn("key1");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_OPERATOR)).thenReturn("EQUALS");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_VALUE)).thenReturn("value1");
        Mockito.when(mockResultSet.getInt(ZMSConsts.DB_COLUMN_CONDITION_ID)).thenReturn(1);

        AthenzDomain athenzDomain = new AthenzDomain("dom1");
        jdbcConn.getAthenzDomainPolicies("dom1", 1, athenzDomain);
        assertNotNull(athenzDomain.getPolicies().get(0).getAssertions().get(0).getConditions());
        AssertionCondition ac1 = new AssertionCondition().setId(1);
        Map<String, AssertionConditionData> m1 = new HashMap<>();
        m1.put("key1", new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value1"));
        ac1.setConditionsMap(m1);
        org.hamcrest.MatcherAssert.assertThat(athenzDomain.getPolicies().get(0).getAssertions().get(0).getConditions().getConditionsList(),
                CoreMatchers.hasItems(ac1));
        jdbcConn.close();

        jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeQuery()).thenReturn(mockResultSet).thenThrow(new SQLException("sql error")).thenThrow(new SQLException("sql error"));
        Mockito.when(mockResultSet.next()).thenReturn(true, false);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME)).thenReturn("pol1");
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);

        try {
            // fail to get assertion conditions
            jdbcConn.getAthenzDomainPolicies("dom1", 1, athenzDomain);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetAthenzDomainPoliciesError() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        AthenzDomain athenzDomain = new AthenzDomain("dom1");
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("sql error"));
        try {
            // fail to get assertion conditions
            jdbcConn.getAthenzDomainPolicies("dom1", 1, athenzDomain);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetAthenzDomainPoliciesAssertionConditionsError() throws SQLException {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        AthenzDomain athenzDomain = new AthenzDomain("dom1");
        Mockito.when(mockResultSet.next()).thenReturn(true, false, true, false, false);
        Mockito.when(mockPrepStmt.executeQuery()).thenReturn(mockResultSet).thenReturn(mockResultSet).thenThrow(new SQLException("sql error"));
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_NAME)).thenReturn("pol1");
        Mockito.doReturn(new java.sql.Timestamp(1454358916)).when(mockResultSet).getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED);
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ROLE)).thenReturn("role1");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_RESOURCE)).thenReturn("resource");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_ACTION)).thenReturn("action");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_EFFECT)).thenReturn("ALLOW");
        Mockito.when(mockResultSet.getLong(ZMSConsts.DB_COLUMN_ASSERT_ID)).thenReturn(1L);
        try {
            // fail to get assertion conditions
            jdbcConn.getAthenzDomainPolicies("dom1", 1, athenzDomain);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }


    @Test
    public void testGetPendingRoleMemberState() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, false);
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.when(mockResultSet.getString(1)).thenReturn(ZMSConsts.PENDING_REQUEST_ADD_STATE);
        String pendingState = jdbcConn.getPendingRoleMemberState(123, "user.jon");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 123);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.jon");
        assertEquals(pendingState, ZMSConsts.PENDING_REQUEST_ADD_STATE);

        jdbcConn.con.close();
    }

    @Test
    public void testGetPendingRoleMemberStateNotFound() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, false);
        Mockito.when(mockResultSet.next()).thenReturn(false);
        String pendingState = jdbcConn.getPendingRoleMemberState(123, "user.jon");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 123);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "user.jon");
        assertNull(pendingState);

        jdbcConn.con.close();
    }
    @Test
    public void testGetPendingRoleMemberStateException() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));
        try {
            jdbcConn.getPendingRoleMemberState(123, "user.jon");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testGetObjectSystemCount() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(false).thenThrow(new SQLException("sql error"));

        assertEquals(jdbcConn.getObjectSystemCount("role"), 0);
        try {
            jdbcConn.getObjectSystemCount("role");
            fail();
        } catch (RuntimeException rx){
            assertTrue(rx.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetObjectDomainCount() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(false).thenThrow(new SQLException("sql error"));

        assertEquals(jdbcConn.getObjectDomainCount("role", 101), 0);
        try {
            jdbcConn.getObjectDomainCount("role", 101);
            fail();
        } catch (RuntimeException rx){
            assertTrue(rx.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetObjectDomainComponentCount() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(false).thenThrow(new SQLException("sql error"));

        assertEquals(jdbcConn.getObjectDomainComponentCount("select count (*) from role where domain_id=?", 101), 0);
        try {
            jdbcConn.getObjectDomainComponentCount("select count (*) from role where domain_id=?", 101);
            fail();
        } catch (RuntimeException rx){
            assertTrue(rx.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetSubdomainPrefixCount() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(false).thenThrow(new SQLException("sql error"));

        assertEquals(jdbcConn.getSubdomainPrefixCount("stats"), 0);
        try {
            jdbcConn.getSubdomainPrefixCount("stats");
            fail();
        } catch (RuntimeException rx){
            assertTrue(rx.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetCloudProviderLookupDomainSQLCommand() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        assertNull(jdbcConn.getCloudProviderLookupDomainSQLCommand(null));
        assertNull(jdbcConn.getCloudProviderLookupDomainSQLCommand(""));
        assertNull(jdbcConn.getCloudProviderLookupDomainSQLCommand("unknown"));

        assertEquals(jdbcConn.getCloudProviderLookupDomainSQLCommand("aws"), "SELECT name FROM domain WHERE account=?;");
        assertEquals(jdbcConn.getCloudProviderLookupDomainSQLCommand("AWS"), "SELECT name FROM domain WHERE account=?;");
        assertEquals(jdbcConn.getCloudProviderLookupDomainSQLCommand("azure"), "SELECT name FROM domain WHERE azure_subscription=?;");
        assertEquals(jdbcConn.getCloudProviderLookupDomainSQLCommand("gcp"), "SELECT name FROM domain WHERE gcp_project=?;");
        jdbcConn.close();
    }

    @Test
    public void testGetCloudProviderListDomainsSQLCommand() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        assertNull(jdbcConn.getCloudProviderListDomainsSQLCommand(null));
        assertNull(jdbcConn.getCloudProviderListDomainsSQLCommand(""));
        assertNull(jdbcConn.getCloudProviderListDomainsSQLCommand("unknown"));

        assertEquals(jdbcConn.getCloudProviderListDomainsSQLCommand("aws"), "SELECT name, account FROM domain WHERE account!='';");
        assertEquals(jdbcConn.getCloudProviderListDomainsSQLCommand("azure"), "SELECT name, azure_subscription FROM domain WHERE azure_subscription!='';");
        assertEquals(jdbcConn.getCloudProviderListDomainsSQLCommand("gcp"), "SELECT name, gcp_project FROM domain WHERE gcp_project!='';");
        jdbcConn.close();
    }

    @Test
    public void testGetCloudProviderColumnName() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        assertNull(jdbcConn.getCloudProviderColumnName(null));
        assertNull(jdbcConn.getCloudProviderColumnName(""));
        assertNull(jdbcConn.getCloudProviderColumnName("unknown"));

        assertEquals(jdbcConn.getCloudProviderColumnName("aws"), "account");
        assertEquals(jdbcConn.getCloudProviderColumnName("AWS"), "account");
        assertEquals(jdbcConn.getCloudProviderColumnName("azure"), "azure_subscription");
        assertEquals(jdbcConn.getCloudProviderColumnName("gcp"), "gcp_project");
        jdbcConn.close();
    }


    @Test
    public void testInsertServiceTags() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7);

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for service id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        Map<String, TagValueList> serviceTags = Collections.singletonMap(
                "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
        );

        assertTrue(jdbcConn.insertServiceTags("service", "domain", serviceTags));

        // domain
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "domain");
        // role
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "service");
        // tag
        Mockito.verify(mockPrepStmt, times(2)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "tagKey");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "tagVal");

        jdbcConn.close();
    }

    @Test
    public void testInsertServiceTagsExceptions() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(0) // first call domain id
                .thenReturn(5) // second call domain id
                .thenReturn(0) // second call for service
                .thenReturn(20); // third call for service id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for service id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        Mockito.when(mockConn.prepareStatement(ArgumentMatchers.isA(String.class)))
                        .thenReturn(mockPrepStmt)
                        .thenReturn(mockPrepStmt)
                        .thenReturn(mockPrepStmt)
                        .thenReturn(mockPrepStmt)
                        .thenReturn(mockPrepStmt)
                        .thenThrow(SQLException.class);

//        Mockito.doThrow(SQLException.class).when(mockConn).prepareStatement(ArgumentMatchers.isA(String.class));


        Map<String, TagValueList> serviceTags = Collections.singletonMap(
                "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
        );

        try {
            jdbcConn.insertServiceTags("service", "domain", serviceTags);
            fail();
        } catch (ResourceException e) {
           assertEquals(e.getCode(), 404);
            assertEquals(e.getMessage(), "ResourceException (404): {code: 404, message: \"unknown domain - domain\"}");
        }

        try {
            jdbcConn.insertServiceTags("service", "domain", serviceTags);
            fail();
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
            assertEquals(e.getMessage(), "ResourceException (404): {code: 404, message: \"unknown service - domain.service\"}");
        }

        try {
            jdbcConn.insertServiceTags("service", "domain", serviceTags);
            fail();
        } catch (RuntimeException e) {
            assertEquals(e.getMessage(), "ResourceException (500): {code: 500, message: \"null, state: null, code: 0\"}");
        }

        jdbcConn.close();
    }

    @Test
    public void testDeleteGroupTagsExceptions() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(0) // domain id
                .thenReturn(7) // domain id
                .thenReturn(0) //group id
                .thenReturn(20); //group id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for group id
        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();

        Mockito.when(mockConn.prepareStatement(ArgumentMatchers.isA(String.class)))
                .thenReturn(mockPrepStmt)
                .thenReturn(mockPrepStmt)
                .thenReturn(mockPrepStmt)
                .thenReturn(mockPrepStmt)
                .thenThrow(SQLException.class);

        Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));

        try {
            jdbcConn.deleteGroupTags("group", "domain", tagKeys);
            fail();
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
            assertEquals(e.getMessage(), "ResourceException (404): {code: 404, message: \"unknown domain - domain\"}");
        }

        try {
            jdbcConn.deleteGroupTags("group", "domain", tagKeys);
            fail();
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
            assertEquals(e.getMessage(), "ResourceException (404): {code: 404, message: \"unknown group - domain:group.group\"}");
        }
        try {
            jdbcConn.deleteGroupTags("group", "domain", tagKeys);
            fail();
        } catch (RuntimeException e) {
            assertEquals(e.getMessage(), "ResourceException (500): {code: 500, message: \"null, state: null, code: 0\"}");
        }


        jdbcConn.close();
    }

    @Test
    public void testInsertGroupTagsExceptions() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(0) // first call domain id
                .thenReturn(5) // second call domain id
                .thenReturn(0) // second call for group
                .thenReturn(20); // third call for group id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for group id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        Mockito.when(mockConn.prepareStatement(ArgumentMatchers.isA(String.class)))
                .thenReturn(mockPrepStmt)
                .thenReturn(mockPrepStmt)
                .thenReturn(mockPrepStmt)
                .thenReturn(mockPrepStmt)
                .thenReturn(mockPrepStmt)
                .thenThrow(SQLException.class);

        Map<String, TagValueList> groupTags = Collections.singletonMap(
                "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
        );

        try {
            jdbcConn.insertGroupTags("group", "domain", groupTags);
            fail();
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
            assertEquals(e.getMessage(), "ResourceException (404): {code: 404, message: \"unknown domain - domain\"}");
        }

        try {
            jdbcConn.insertGroupTags("group", "domain", groupTags);
            fail();
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
            assertEquals(e.getMessage(), "ResourceException (404): {code: 404, message: \"unknown group - domain:group.group\"}");
        }

        try {
            jdbcConn.insertGroupTags("group", "domain", groupTags);
            fail();
        } catch (RuntimeException e) {
            assertEquals(e.getMessage(), "ResourceException (500): {code: 500, message: \"null, state: null, code: 0\"}");
        }

        jdbcConn.close();
    }

    @Test
    public void testDeletePolicyTags() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // policy id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for policy id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));

        assertTrue(jdbcConn.deletePolicyTags("policy", "domain", tagKeys, any()));

        // domain
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "domain");
        // policy
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "policy");
        // tag
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 7);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "tagKey");

        jdbcConn.close();
    }


    @Test
    public void testDeletePolicyTagsExceptions() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(0) // domain id
                .thenReturn(7) // domain id
                .thenReturn(0) // policy id
                .thenReturn(20); // policy id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for policy id
        Mockito.doReturn(0).when(mockPrepStmt).executeUpdate();

        Mockito.when(mockConn.prepareStatement(ArgumentMatchers.isA(String.class)))
                .thenReturn(mockPrepStmt)
                .thenReturn(mockPrepStmt)
                .thenReturn(mockPrepStmt)
                .thenReturn(mockPrepStmt)
                .thenThrow(SQLException.class);

        Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));

        try {
            jdbcConn.deletePolicyTags("policy", "domain", tagKeys, any());
            fail();
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
            assertEquals(e.getMessage(), "ResourceException (404): {code: 404, message: \"unknown domain - domain\"}");
        }

        try {
            jdbcConn.deletePolicyTags("policy", "domain", tagKeys, any());
            fail();
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
            assertEquals(e.getMessage(), "ResourceException (404): {code: 404, message: \"unknown policy - domain:policy.policy\"}");
        }
        try {
            jdbcConn.deletePolicyTags("policy", "domain", tagKeys, any());
            fail();
        } catch (RuntimeException e) {
            assertEquals(e.getMessage(), "ResourceException (500): {code: 500, message: \"null, state: null, code: 0\"}");
        }


        jdbcConn.close();
    }

    @Test
    public void testDeletePolicyTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // policy id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for policy id
        Mockito.when(mockPrepStmt.executeUpdate())
                .thenThrow(new SQLException("sql error"));
        try {
            Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));
            jdbcConn.deletePolicyTags("policy", "domain", tagKeys, any());
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetPolicyTags() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1)).thenReturn(5);

        Mockito.when(mockResultSet.getString(1))
                .thenReturn("tagKey");
        Mockito.when(mockResultSet.getString(2))
                .thenReturn("tagVal1", "tagVal2");

        Mockito.when(mockResultSet.next())
                .thenReturn(true, true, true, true, false);

        Map<String, TagValueList> policyTags = jdbcConn.getPolicyTags("domain", "policy", "1");
        assertNotNull(policyTags);

        TagValueList tagValues = policyTags.get("tagKey");

        assertNotNull(tagValues);
        assertTrue(tagValues.getList().containsAll(Arrays.asList("tagVal1", "tagVal2")));

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "policy");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "1");

        jdbcConn.close();
    }

    @Test
    public void testGetPolicyTagsEmpty() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5);

        Mockito.when(mockResultSet.next())
                .thenReturn(true, true, false);

        Map<String, TagValueList> policyTags = jdbcConn.getPolicyTags("domain", "policy", "0");
        assertNull(policyTags);
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "domain");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "policy");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "0");

        jdbcConn.close();
    }

    @Test
    public void testGetPolicyTagInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        try {
            jdbcConn.getPolicyTags("domain", "policy", "0");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testGetPolicyTagInvalidPolicy() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // return domain id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(false); // this is for policy id

        try {
            jdbcConn.getPolicyTags("domain", "policy", "0");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testGetPolicyTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true) // this one is for policy id
                .thenThrow(new SQLException("sql error"));
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5);

        try {
            jdbcConn.getPolicyTags("domain", "policy", "0");
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetDomainResourceTags() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getString(1))
                .thenReturn("policy");
        Mockito.when(mockResultSet.getString(2))
                .thenReturn("tagKey");
        Mockito.when(mockResultSet.getString(3))
                .thenReturn("tagVal1", "tagVal2");
        Mockito.when(mockResultSet.getString(4))
                .thenReturn("1");

        Mockito.when(mockResultSet.next())
                .thenReturn(true, true, false);

        Map<String, Map<String, TagValueList>> domainPolicyTags = jdbcConn.getDomainPolicyTags("sys.auth");
        assertNotNull(domainPolicyTags);

        Map<String, TagValueList> roleTags = domainPolicyTags.get("policy:1");
        TagValueList tagValues = roleTags.get("tagKey");

        assertNotNull(tagValues);
        assertTrue(tagValues.getList().containsAll(Arrays.asList("tagVal1", "tagVal2")));

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "sys.auth");

        jdbcConn.close();
    }

    @Test
    public void testGetDomainResourceTagsEmpty() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(false);

        Map<String, Map<String, TagValueList>> domainRoleTags = jdbcConn.getDomainRoleTags("sys.auth");
        assertNull(domainRoleTags);
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "sys.auth");

        jdbcConn.close();
    }

    @Test
    public void testGetDomainResourceTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(true).thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getDomainRoleTags("sys.auth");
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertPolicyTagsInvalidDomain() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id
        try {
            Map<String, TagValueList> policyTags = Collections.singletonMap(
                    "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
            );
            jdbcConn.insertPolicyTags("policy", "domain", policyTags, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertPolicyTagsInvalidRole() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // domain id
        Mockito.when(mockResultSet.next()).thenReturn(true, false);
        try {
            Map<String, TagValueList> policyTags = Collections.singletonMap(
                    "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
            );
            jdbcConn.insertPolicyTags("policy", "domain", policyTags, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertPolicyTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5) // domain id
                .thenReturn(7); // role id

        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for domain id
                .thenReturn(true); // this one is for policy id
        Mockito.when(mockPrepStmt.executeUpdate())
                .thenThrow(new SQLException("sql error"));
        try {
            Map<String, TagValueList> policyTags = Collections.singletonMap(
                    "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
            );
            jdbcConn.insertPolicyTags("policy", "domain", policyTags, null);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testDeletePolicyTagsInvalidDomain() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id
        try {
            Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));
            jdbcConn.deletePolicyTags("policy", "domain", tagKeys, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testDeletePolicyTagsInvalidRole() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(5); // domain id
        Mockito.when(mockResultSet.next()).thenReturn(true, false);
        try {
            Set<String> tagKeys = new HashSet<>(Collections.singletonList("tagKey"));
            jdbcConn.deletePolicyTags("policy", "domain", tagKeys, "0");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testPolicyRoleTagsCountError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getPolicyTagsCount(101);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testDomainTagsCountError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getDomainTagsCount(101);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetServiceTagsCountError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getServiceTagsCount(101);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetGroupTagsCountError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getGroupTagsCount(101);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetDomainPolicyTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getDomainPolicyTags("domain");
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetServiceResourceTagsError() throws Exception {
        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next())
                .thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.getServiceResourceTags("domain");
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testIsLastNotifyTimeWithinSpecifiedDays() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true);

        // timestamp return values: > 1 day, < 1 day, exception
        Mockito.when(mockResultSet.getTimestamp(1))
                .thenReturn(new java.sql.Timestamp(System.currentTimeMillis() - 24 * 60 * 60 * 1000 - 10000))
                .thenReturn(new java.sql.Timestamp(System.currentTimeMillis() - 24 * 60 * 60 * 1000 + 10000))
                .thenThrow(new SQLException("sql error"));

        assertFalse(jdbcConn.isLastNotifyTimeWithinSpecifiedDays("test-sql-cmd", 1));
        assertTrue(jdbcConn.isLastNotifyTimeWithinSpecifiedDays("test-sql-cmd", 1));
        assertFalse(jdbcConn.isLastNotifyTimeWithinSpecifiedDays("test-sql-cmd", 1));

        jdbcConn.close();
    }

    @Test
    public void testUpdateRoleMemberExpirationNotificationTimestampLastDay() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);

        // timestamp return value < 1 day
        Mockito.when(mockResultSet.getTimestamp(1))
                .thenReturn(new java.sql.Timestamp(System.currentTimeMillis() - 24 * 60 * 60 * 1000 + 10000));

        assertFalse(jdbcConn.updateRoleMemberExpirationNotificationTimestamp("server", 0, 1));
        jdbcConn.close();
    }

    @Test
    public void testUpdateRoleMemberReviewNotificationTimestampLastDay() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);

        // timestamp return value < 1 day
        Mockito.when(mockResultSet.getTimestamp(1))
                .thenReturn(new java.sql.Timestamp(System.currentTimeMillis() - 24 * 60 * 60 * 1000 + 10000));

        assertFalse(jdbcConn.updateRoleMemberReviewNotificationTimestamp("server", 0, 1));
        jdbcConn.close();
    }

    @Test
    public void testUpdateGroupMemberExpirationNotificationTimestampLastDay() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(false);

        // timestamp return value < 1 day
        Mockito.when(mockResultSet.getTimestamp(1))
                .thenReturn(new java.sql.Timestamp(System.currentTimeMillis() - 24 * 60 * 60 * 1000 + 10000));

        assertFalse(jdbcConn.updateGroupMemberExpirationNotificationTimestamp("server", 0, 1));
        jdbcConn.close();
    }

    @Test
    public void testDependencyExceptions() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("sql1 error"));
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("sql2 error"));
        try {
            jdbcConn.deleteDomainDependency("domain", "service");
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql1 error"));
        }
        try {
            jdbcConn.insertDomainDependency("domain", "service");
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql1 error"));
        }
        try {
            jdbcConn.listDomainDependencies("service");
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql2 error"));
        }
        try {
            jdbcConn.listServiceDependencies("domain");
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql2 error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetRolesForReview() throws SQLException {

        // first result set is for principal id lookup
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(true).thenReturn(true).thenReturn(false);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(10); // for principal id
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_DOMAIN_NAME)).thenReturn("domain1").thenReturn("domain2");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_AS_ROLE_NAME)).thenReturn("role1").thenReturn("role2");
        Mockito.when(mockResultSet.getInt(ZMSConsts.DB_COLUMN_MEMBER_EXPIRY_DAYS)).thenReturn(11).thenReturn(12);
        Mockito.when(mockResultSet.getInt(ZMSConsts.DB_COLUMN_SERVICE_EXPIRY_DAYS)).thenReturn(21).thenReturn(22);
        Mockito.when(mockResultSet.getInt(ZMSConsts.DB_COLUMN_GROUP_EXPIRY_DAYS)).thenReturn(31).thenReturn(32);
        Mockito.when(mockResultSet.getInt(ZMSConsts.DB_COLUMN_MEMBER_REVIEW_DAYS)).thenReturn(41).thenReturn(42);
        Mockito.when(mockResultSet.getInt(ZMSConsts.DB_COLUMN_SERVICE_REVIEW_DAYS)).thenReturn(51).thenReturn(52);
        Mockito.when(mockResultSet.getInt(ZMSConsts.DB_COLUMN_GROUP_REVIEW_DAYS)).thenReturn(61).thenReturn(62);
        Mockito.when(mockResultSet.getTimestamp(ZMSConsts.DB_COLUMN_LAST_REVIEWED_TIME))
                .thenReturn(new java.sql.Timestamp(101)).thenReturn(null);
        Mockito.when(mockResultSet.getTimestamp(ZMSConsts.DB_COLUMN_CREATED))
                .thenReturn(new java.sql.Timestamp(102));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        ReviewObjects reviewObjects = jdbcConn.getRolesForReview("user.joe");
        assertNotNull(reviewObjects);
        List<ReviewObject> objects = reviewObjects.getList();
        assertNotNull(objects);
        assertEquals(objects.size(), 2);

        ReviewObject object1 = new ReviewObject().setDomainName("domain1").setName("role1").setMemberExpiryDays(11)
                .setServiceExpiryDays(21).setGroupExpiryDays(31).setMemberReviewDays(41).setServiceReviewDays(51)
                .setGroupReviewDays(61).setLastReviewedDate(Timestamp.fromMillis(101))
                .setCreated(Timestamp.fromMillis(102));
        assertEquals(objects.get(0), object1);

        ReviewObject object2 = new ReviewObject().setDomainName("domain2").setName("role2").setMemberExpiryDays(12)
                .setServiceExpiryDays(22).setGroupExpiryDays(32).setMemberReviewDays(42).setServiceReviewDays(52)
                .setGroupReviewDays(62).setCreated(Timestamp.fromMillis(102));
        assertEquals(objects.get(1), object2);
    }

    @Test
    public void testGetRolesForReviewInvalidPrincipal() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        // first query is for the principal id
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.getRolesForReview("user.joe");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        jdbcConn.close();
    }

    @Test
    public void testGetRolesForReviewFailure() throws Exception {

        // first result set is for principal id lookup
        Mockito.when(mockResultSet.next()).thenReturn(true)
                .thenThrow(new SQLException("failed operation", "state", 1001));
        Mockito.when(mockResultSet.getInt(1)).thenReturn(10); // for principal id

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        try {
            jdbcConn.getRolesForReview("user.joe");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }

        jdbcConn.close();
    }

    @Test
    public void testGetGroupsForReview() throws SQLException {

        // first result set is for principal id lookup
        Mockito.when(mockResultSet.next()).thenReturn(true).thenReturn(true).thenReturn(true).thenReturn(false);
        Mockito.when(mockResultSet.getInt(1)).thenReturn(10); // for principal id
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_DOMAIN_NAME)).thenReturn("domain1").thenReturn("domain2");
        Mockito.when(mockResultSet.getString(ZMSConsts.DB_COLUMN_AS_GROUP_NAME)).thenReturn("group1").thenReturn("group2");
        Mockito.when(mockResultSet.getInt(ZMSConsts.DB_COLUMN_MEMBER_EXPIRY_DAYS)).thenReturn(11).thenReturn(12);
        Mockito.when(mockResultSet.getInt(ZMSConsts.DB_COLUMN_SERVICE_EXPIRY_DAYS)).thenReturn(21).thenReturn(22);
        Mockito.when(mockResultSet.getTimestamp(ZMSConsts.DB_COLUMN_LAST_REVIEWED_TIME))
                .thenReturn(new java.sql.Timestamp(101)).thenReturn(null);
        Mockito.when(mockResultSet.getTimestamp(ZMSConsts.DB_COLUMN_CREATED))
                .thenReturn(new java.sql.Timestamp(102));

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        ReviewObjects reviewObjects = jdbcConn.getGroupsForReview("user.joe");
        assertNotNull(reviewObjects);
        List<ReviewObject> objects = reviewObjects.getList();
        assertNotNull(objects);
        assertEquals(objects.size(), 2);

        ReviewObject object1 = new ReviewObject().setDomainName("domain1").setName("group1").setMemberExpiryDays(11)
                .setServiceExpiryDays(21).setLastReviewedDate(Timestamp.fromMillis(101))
                .setCreated(Timestamp.fromMillis(102));
        assertEquals(objects.get(0), object1);

        ReviewObject object2 = new ReviewObject().setDomainName("domain2").setName("group2").setMemberExpiryDays(12)
                .setServiceExpiryDays(22).setCreated(Timestamp.fromMillis(102));
        assertEquals(objects.get(1), object2);
    }

    @Test
    public void testGetGroupsForReviewInvalidPrincipal() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        // first query is for the principal id
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.getGroupsForReview("user.joe");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        jdbcConn.close();
    }

    @Test
    public void testGetGroupsForReviewFailure() throws Exception {

        // first result set is for principal id lookup
        Mockito.when(mockResultSet.next()).thenReturn(true)
                .thenThrow(new SQLException("failed operation", "state", 1001));
        Mockito.when(mockResultSet.getInt(1)).thenReturn(10); // for principal id

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        try {
            jdbcConn.getGroupsForReview("user.joe");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }

        jdbcConn.close();
    }

    @Test
    public void testInsertDomainContact() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
                .thenReturn(true); // this one is for domain id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.insertDomainContact("my-domain", "security-contact", "user.joe");

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "security-contact");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "user.joe");

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testInsertDomainContactInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.insertDomainContact("my-domain", "security-contact", "user.joe");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertDomainContactException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
                .thenReturn(true); // this one is for domain id

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.insertDomainContact("my-domain", "security-contact", "user.joe");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testUpdateDomainContact() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        TemplateMetaData templateMetaData = new TemplateMetaData();
        templateMetaData.setLatestVersion(4);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
                .thenReturn(true); // this one is for domain id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.updateDomainContact("my-domain", "security-contact", "user.joe");

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "user.joe");
        Mockito.verify(mockPrepStmt, times(1)).setInt(2, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "security-contact");

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testUpdateDomainContactWithInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        TemplateMetaData templateMetaData = new TemplateMetaData();
        templateMetaData.setLatestVersion(4);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.updateDomainContact("my-domain", "security-contact", "user.joe");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testUpdateDomainContactException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
                .thenReturn(true); // this one is for domain id

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.updateDomainContact("my-domain", "security-contact", "user.joe");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteDomainContact() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
                .thenReturn(true); // this one is for domain id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        boolean requestSuccess = jdbcConn.deleteDomainContact("my-domain", "security-contact");

        // this is combined for all operations above

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "my-domain");

        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 5);
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "security-contact");

        assertTrue(requestSuccess);
        jdbcConn.close();
    }

    @Test
    public void testDeleteDomainContactInvalidDomain() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(false); // this one is for domain id

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.deleteDomainContact("my-domain", "security-contact");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        jdbcConn.close();
    }

    @Test
    public void testDeleteDomainContactException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.getInt(1))
                .thenReturn(5); // domain id
        Mockito.when(mockResultSet.next())
                .thenReturn(true); // this one is for domain id

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.deleteDomainContact("my-domain", "security-contact");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testListContactDomains() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockResultSet.next())
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(false);
        Mockito.when(mockResultSet.getString(1))
                .thenReturn("coretech")
                .thenReturn("coretech")
                .thenReturn("weather");
        Mockito.when(mockResultSet.getString(2))
                .thenReturn("security-contact")
                .thenReturn("se-contact")
                .thenReturn("security-contact");

        Map<String, List<String>> contactDomains = jdbcConn.listContactDomains("user.joe");

        // data back is sorted

        assertEquals(contactDomains.size(), 2);
        assertEquals(contactDomains.get("coretech").size(), 2);
        assertEquals(contactDomains.get("coretech").get(0), "security-contact");
        assertEquals(contactDomains.get("coretech").get(1), "se-contact");
        assertEquals(contactDomains.get("weather").size(), 1);
        assertEquals(contactDomains.get("weather").get(0), "security-contact");
        jdbcConn.close();
    }

    @Test
    public void testListContactDomainsException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.listContactDomains("user.joe");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testGetDomainContactsException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);

        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));

        try {
            jdbcConn.getDomainContacts(5);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        jdbcConn.close();
    }

    @Test
    public void testLastTrustRoleUpdatesTimestampException() throws Exception {

        JDBCConnection jdbcConn = new JDBCConnection(mockConn, true);
        Mockito.when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("failed operation", "state", 1001));
        assertEquals(jdbcConn.lastTrustRoleUpdatesTimestamp(), 0);
        jdbcConn.close();
    }
}
