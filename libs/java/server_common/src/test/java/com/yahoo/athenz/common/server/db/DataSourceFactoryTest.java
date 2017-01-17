/**
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
package com.yahoo.athenz.common.server.db;

import static org.testng.Assert.*;

import org.apache.commons.pool2.impl.BaseObjectPoolConfig;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import org.testng.annotations.Test;

import com.yahoo.athenz.common.server.db.DataSourceFactory;
import com.yahoo.athenz.common.server.db.PoolableDataSource;

public class DataSourceFactoryTest {

    static final String ZMS_DBPOOL_PROP1 = "athenz.zms.db_pool_test_prop";
    
    @Test
    public void testCrateDataSourceWithMysqlUrl() {
        
        PoolableDataSource src = DataSourceFactory.create("jdbc:mysql:localhost:3306/athenz",
                "user", "password");
        assertNotNull(src);
    }
    
    @Test
    public void testCreateDataSourceWithUnknownUrl() {
        
        try {
            DataSourceFactory.create("jdbc:tdb:localhost:11080", "user", "password");
            fail();
        } catch (RuntimeException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testCreateDataSourceWithFactory() {
        
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_TTL, "10000");

        MockConnectionFactory connectionFactory = new MockConnectionFactory();
        PoolableDataSource src = DataSourceFactory.create(connectionFactory);
        assertNotNull(src);
        
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_TTL);
    }
    
    @Test
    public void testCreateDataSourceWithFactoryInvalidTTL() {
        
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_TTL, "abc");

        // we ignore the invalid ttl and everything else should work fine
        
        MockConnectionFactory connectionFactory = new MockConnectionFactory();
        PoolableDataSource src = DataSourceFactory.create(connectionFactory);
        assertNotNull(src);
        
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_TTL);
    }
    
    @Test
    public void testPoolConfigDefaultValues() {
       
        GenericObjectPoolConfig config = DataSourceFactory.setupPoolConfig();
        assertNotNull(config);
        assertEquals(config.getMaxTotal(), GenericObjectPoolConfig.DEFAULT_MAX_TOTAL);
        assertEquals(config.getMaxIdle(), GenericObjectPoolConfig.DEFAULT_MAX_IDLE);
        assertEquals(config.getMinIdle(), GenericObjectPoolConfig.DEFAULT_MIN_IDLE);
        assertEquals(config.getMaxWaitMillis(), GenericObjectPoolConfig.DEFAULT_MAX_WAIT_MILLIS);
        assertEquals(config.getMinEvictableIdleTimeMillis(), BaseObjectPoolConfig.DEFAULT_MIN_EVICTABLE_IDLE_TIME_MILLIS);
        assertEquals(config.getTimeBetweenEvictionRunsMillis(), BaseObjectPoolConfig.DEFAULT_MIN_EVICTABLE_IDLE_TIME_MILLIS);
        assertTrue(config.getTestWhileIdle());
        assertTrue(config.getTestOnBorrow());
    }

    @Test
    public void testPoolConfigSpecifiedValues() {
       
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_TOTAL, "10");
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_IDLE, "20");
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MIN_IDLE, "30");
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_WAIT, "40");
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_EVICT_IDLE_TIMEOUT, "50");
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_EVICT_IDLE_INTERVAL, "60");
        
        GenericObjectPoolConfig config = DataSourceFactory.setupPoolConfig();
        assertNotNull(config);
        assertEquals(config.getMaxTotal(), 10);
        assertEquals(config.getMaxIdle(), 20);
        assertEquals(config.getMinIdle(), 30);
        assertEquals(config.getMaxWaitMillis(), 40);
        assertEquals(config.getMinEvictableIdleTimeMillis(), 50);
        assertEquals(config.getTimeBetweenEvictionRunsMillis(), 60);
        assertTrue(config.getTestWhileIdle());
        assertTrue(config.getTestOnBorrow());
        
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_TOTAL);
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_IDLE);
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MIN_IDLE);
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_WAIT);
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_EVICT_IDLE_TIMEOUT);
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_EVICT_IDLE_INTERVAL);
    }
    
    @Test
    public void testPoolConfigInvalidValues() {
       
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_TOTAL, "a");
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_IDLE, "b");
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MIN_IDLE, "c");
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_WAIT, "d");
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_EVICT_IDLE_TIMEOUT, "e");
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_EVICT_IDLE_INTERVAL, "f");
        
        GenericObjectPoolConfig config = DataSourceFactory.setupPoolConfig();
        assertNotNull(config);
        
        assertEquals(config.getMaxTotal(), GenericObjectPoolConfig.DEFAULT_MAX_TOTAL);
        assertEquals(config.getMaxIdle(), GenericObjectPoolConfig.DEFAULT_MAX_IDLE);
        assertEquals(config.getMinIdle(), GenericObjectPoolConfig.DEFAULT_MIN_IDLE);
        assertEquals(config.getMaxWaitMillis(), GenericObjectPoolConfig.DEFAULT_MAX_WAIT_MILLIS);
        assertEquals(config.getMinEvictableIdleTimeMillis(), BaseObjectPoolConfig.DEFAULT_MIN_EVICTABLE_IDLE_TIME_MILLIS);
        assertEquals(config.getTimeBetweenEvictionRunsMillis(), BaseObjectPoolConfig.DEFAULT_MIN_EVICTABLE_IDLE_TIME_MILLIS);
        assertTrue(config.getTestWhileIdle());
        assertTrue(config.getTestOnBorrow());
        
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_TOTAL);
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_IDLE);
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MIN_IDLE);
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_WAIT);
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_EVICT_IDLE_TIMEOUT);
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_EVICT_IDLE_INTERVAL);
    }

    @Test
    public void testPoolConfigZeroValues() {
       
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_TOTAL, "0");
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_IDLE, "0");
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MIN_IDLE, "0");
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_WAIT, "0");
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_EVICT_IDLE_TIMEOUT, "0");
        System.setProperty(DataSourceFactory.ZMS_PROP_DBPOOL_EVICT_IDLE_INTERVAL, "0");
        
        GenericObjectPoolConfig config = DataSourceFactory.setupPoolConfig();
        assertNotNull(config);
        
        // MaxTotal and MaxIdle are set to -1 if the value is 0
        assertEquals(config.getMaxTotal(), -1);
        assertEquals(config.getMaxIdle(), -1);
        assertEquals(config.getMinIdle(), 0);
        assertEquals(config.getMaxWaitMillis(), 0);
        assertEquals(config.getMinEvictableIdleTimeMillis(), 0);
        assertEquals(config.getTimeBetweenEvictionRunsMillis(), 0);
        assertTrue(config.getTestWhileIdle());
        assertTrue(config.getTestOnBorrow());
        
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_TOTAL);
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_IDLE);
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MIN_IDLE);
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_MAX_WAIT);
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_EVICT_IDLE_TIMEOUT);
        System.clearProperty(DataSourceFactory.ZMS_PROP_DBPOOL_EVICT_IDLE_INTERVAL);
    }
    
    @Test
    public void testRetrieveConfigSettingLong() {
        
        System.setProperty(ZMS_DBPOOL_PROP1, "100");
        assertEquals(DataSourceFactory.retrieveConfigSetting(ZMS_DBPOOL_PROP1, 20L), 100L);

        System.setProperty(ZMS_DBPOOL_PROP1, "0");
        assertEquals(DataSourceFactory.retrieveConfigSetting(ZMS_DBPOOL_PROP1, 20L), 0);
        
        System.setProperty(ZMS_DBPOOL_PROP1, "-100");
        assertEquals(DataSourceFactory.retrieveConfigSetting(ZMS_DBPOOL_PROP1, 20L), -100L);
        
        System.clearProperty(ZMS_DBPOOL_PROP1);
    }
    
    @Test
    public void testRetrieveConfigSettingLongNull() {
        System.clearProperty(ZMS_DBPOOL_PROP1);
        assertEquals(DataSourceFactory.retrieveConfigSetting(ZMS_DBPOOL_PROP1, 25L), 25L);
    }
    
    @Test
    public void testRetrieveConfigSettingLongInvalid() {
        System.setProperty(ZMS_DBPOOL_PROP1, "abc");
        assertEquals(DataSourceFactory.retrieveConfigSetting(ZMS_DBPOOL_PROP1, 20L), 20L);
        System.clearProperty(ZMS_DBPOOL_PROP1);
    }

    @Test
    public void testRetrieveConfigSettingInt() {
        
        System.setProperty(ZMS_DBPOOL_PROP1, "100");
        assertEquals(DataSourceFactory.retrieveConfigSetting(ZMS_DBPOOL_PROP1, 20), 100);

        System.setProperty(ZMS_DBPOOL_PROP1, "0");
        assertEquals(DataSourceFactory.retrieveConfigSetting(ZMS_DBPOOL_PROP1, 20), 0);
        
        System.setProperty(ZMS_DBPOOL_PROP1, "-100");
        assertEquals(DataSourceFactory.retrieveConfigSetting(ZMS_DBPOOL_PROP1, 20), -100);
        
        System.clearProperty(ZMS_DBPOOL_PROP1);
    }
    
    @Test
    public void testRetrieveConfigSettingIntNull() {
        System.clearProperty(ZMS_DBPOOL_PROP1);
        assertEquals(DataSourceFactory.retrieveConfigSetting(ZMS_DBPOOL_PROP1, 25), 25);
    }
    
    @Test
    public void testRetrieveConfigSettingIntInvalid() {
        System.setProperty(ZMS_DBPOOL_PROP1, "abc");
        assertEquals(DataSourceFactory.retrieveConfigSetting(ZMS_DBPOOL_PROP1, 20), 20);
        System.clearProperty(ZMS_DBPOOL_PROP1);
    }
}
