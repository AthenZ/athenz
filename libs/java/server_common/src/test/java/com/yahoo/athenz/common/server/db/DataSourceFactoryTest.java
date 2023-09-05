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

import static org.testng.Assert.*;

import java.time.Duration;
import java.util.Properties;

import org.apache.commons.pool2.impl.BaseObjectPoolConfig;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import org.testng.annotations.Test;

public class DataSourceFactoryTest {

    private static final String ATHENZ_DBPOOL_PROP1 = "athenz.zms.db_pool_test_prop";
    
    @Test
    public void testCrateDataSourceWithMysqlUrl() {
        
        Properties props = new Properties();
        props.setProperty("user", "user");
        props.setProperty("password", "password");

        PoolableDataSource src = DataSourceFactory.create("jdbc:mysql:localhost:3306/athenz",
                props);
        assertNotNull(src);
    }
    
    @Test
    public void testCreateDataSourceWithUnknownUrl() {
        
        Properties props = new Properties();
        props.setProperty("user", "user");
        props.setProperty("password", "password");
        
        try {
            DataSourceFactory.create("jdbc:tdb:localhost:11080", props);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testCreateDataSourceWithFactory() {
        
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_TTL, "10000");

        MockConnectionFactory connectionFactory = new MockConnectionFactory();
        PoolableDataSource src = DataSourceFactory.create(connectionFactory);
        assertNotNull(src);
        
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_TTL);
    }
    
    @Test
    public void testCreateDataSourceWithFactoryInvalidTTL() {
        
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_TTL, "abc");

        // we ignore the invalid ttl and everything else should work fine
        
        MockConnectionFactory connectionFactory = new MockConnectionFactory();
        PoolableDataSource src = DataSourceFactory.create(connectionFactory);
        assertNotNull(src);
        
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_TTL);
    }
    
    @Test
    public void testPoolConfigDefaultValues() {
       
        GenericObjectPoolConfig config = DataSourceFactory.setupPoolConfig();
        assertNotNull(config);
        assertEquals(config.getMaxTotal(), GenericObjectPoolConfig.DEFAULT_MAX_TOTAL);
        assertEquals(config.getMaxIdle(), GenericObjectPoolConfig.DEFAULT_MAX_IDLE);
        assertEquals(config.getMinIdle(), GenericObjectPoolConfig.DEFAULT_MIN_IDLE);
        assertEquals(config.getMaxWaitDuration(), GenericObjectPoolConfig.DEFAULT_MAX_WAIT);
        assertEquals(config.getMinEvictableIdleDuration(), BaseObjectPoolConfig.DEFAULT_MIN_EVICTABLE_IDLE_DURATION);
        assertEquals(config.getDurationBetweenEvictionRuns(), BaseObjectPoolConfig.DEFAULT_MIN_EVICTABLE_IDLE_DURATION);
        assertTrue(config.getTestWhileIdle());
        assertTrue(config.getTestOnBorrow());
    }

    @Test
    public void testPoolConfigSpecifiedValues() {
       
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_TOTAL, "10");
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_IDLE, "20");
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MIN_IDLE, "30");
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_WAIT, "40");
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_EVICT_IDLE_TIMEOUT, "50");
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_EVICT_IDLE_INTERVAL, "60");
        
        GenericObjectPoolConfig config = DataSourceFactory.setupPoolConfig();
        assertNotNull(config);
        assertEquals(config.getMaxTotal(), 10);
        assertEquals(config.getMaxIdle(), 20);
        assertEquals(config.getMinIdle(), 30);
        assertEquals(config.getMaxWaitDuration(), Duration.ofMillis(40));
        assertEquals(config.getMinEvictableIdleDuration(), Duration.ofMillis(50));
        assertEquals(config.getDurationBetweenEvictionRuns(), Duration.ofMillis(60));
        assertTrue(config.getTestWhileIdle());
        assertTrue(config.getTestOnBorrow());
        
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_TOTAL);
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_IDLE);
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MIN_IDLE);
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_WAIT);
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_EVICT_IDLE_TIMEOUT);
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_EVICT_IDLE_INTERVAL);
    }
    
    @Test
    public void testPoolConfigInvalidValues() {
       
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_TOTAL, "a");
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_IDLE, "b");
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MIN_IDLE, "c");
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_WAIT, "d");
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_EVICT_IDLE_TIMEOUT, "e");
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_EVICT_IDLE_INTERVAL, "f");
        
        GenericObjectPoolConfig config = DataSourceFactory.setupPoolConfig();
        assertNotNull(config);
        
        assertEquals(config.getMaxTotal(), GenericObjectPoolConfig.DEFAULT_MAX_TOTAL);
        assertEquals(config.getMaxIdle(), GenericObjectPoolConfig.DEFAULT_MAX_IDLE);
        assertEquals(config.getMinIdle(), GenericObjectPoolConfig.DEFAULT_MIN_IDLE);
        assertEquals(config.getMaxWaitDuration(), GenericObjectPoolConfig.DEFAULT_MAX_WAIT);
        assertEquals(config.getMinEvictableIdleDuration(), BaseObjectPoolConfig.DEFAULT_MIN_EVICTABLE_IDLE_DURATION);
        assertEquals(config.getDurationBetweenEvictionRuns(), BaseObjectPoolConfig.DEFAULT_MIN_EVICTABLE_IDLE_DURATION);
        assertTrue(config.getTestWhileIdle());
        assertTrue(config.getTestOnBorrow());
        
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_TOTAL);
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_IDLE);
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MIN_IDLE);
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_WAIT);
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_EVICT_IDLE_TIMEOUT);
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_EVICT_IDLE_INTERVAL);
    }

    @Test
    public void testPoolConfigZeroValues() {
       
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_TOTAL, "0");
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_IDLE, "0");
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MIN_IDLE, "0");
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_WAIT, "0");
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_EVICT_IDLE_TIMEOUT, "0");
        System.setProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_EVICT_IDLE_INTERVAL, "0");
        
        GenericObjectPoolConfig config = DataSourceFactory.setupPoolConfig();
        assertNotNull(config);
        
        // MaxTotal and MaxIdle are set to -1 if the value is 0
        assertEquals(config.getMaxTotal(), -1);
        assertEquals(config.getMaxIdle(), -1);
        assertEquals(config.getMinIdle(), 0);
        assertEquals(config.getMaxWaitDuration(), Duration.ofMillis(0));
        assertEquals(config.getMinEvictableIdleDuration(), Duration.ofMillis(0));
        assertEquals(config.getDurationBetweenEvictionRuns(), Duration.ofMillis(0));
        assertTrue(config.getTestWhileIdle());
        assertTrue(config.getTestOnBorrow());
        
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_TOTAL);
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_IDLE);
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MIN_IDLE);
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_MAX_WAIT);
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_EVICT_IDLE_TIMEOUT);
        System.clearProperty(DataSourceFactory.ATHENZ_PROP_DBPOOL_EVICT_IDLE_INTERVAL);
    }
    
    @Test
    public void testRetrieveConfigSettingLong() {
        
        System.setProperty(ATHENZ_DBPOOL_PROP1, "100");
        assertEquals(DataSourceFactory.retrieveConfigSetting(ATHENZ_DBPOOL_PROP1, 20L), 100L);

        System.setProperty(ATHENZ_DBPOOL_PROP1, "0");
        assertEquals(DataSourceFactory.retrieveConfigSetting(ATHENZ_DBPOOL_PROP1, 20L), 0);
        
        System.setProperty(ATHENZ_DBPOOL_PROP1, "-100");
        assertEquals(DataSourceFactory.retrieveConfigSetting(ATHENZ_DBPOOL_PROP1, 20L), -100L);
        
        System.clearProperty(ATHENZ_DBPOOL_PROP1);
    }
    
    @Test
    public void testRetrieveConfigSettingLongNull() {
        System.clearProperty(ATHENZ_DBPOOL_PROP1);
        assertEquals(DataSourceFactory.retrieveConfigSetting(ATHENZ_DBPOOL_PROP1, 25L), 25L);
    }
    
    @Test
    public void testRetrieveConfigSettingLongInvalid() {
        System.setProperty(ATHENZ_DBPOOL_PROP1, "abc");
        assertEquals(DataSourceFactory.retrieveConfigSetting(ATHENZ_DBPOOL_PROP1, 20L), 20L);
        System.clearProperty(ATHENZ_DBPOOL_PROP1);
    }

    @Test
    public void testRetrieveConfigSettingInt() {
        
        System.setProperty(ATHENZ_DBPOOL_PROP1, "100");
        assertEquals(DataSourceFactory.retrieveConfigSetting(ATHENZ_DBPOOL_PROP1, 20), 100);

        System.setProperty(ATHENZ_DBPOOL_PROP1, "0");
        assertEquals(DataSourceFactory.retrieveConfigSetting(ATHENZ_DBPOOL_PROP1, 20), 0);
        
        System.setProperty(ATHENZ_DBPOOL_PROP1, "-100");
        assertEquals(DataSourceFactory.retrieveConfigSetting(ATHENZ_DBPOOL_PROP1, 20), -100);
        
        System.clearProperty(ATHENZ_DBPOOL_PROP1);
    }
    
    @Test
    public void testRetrieveConfigSettingIntNull() {
        System.clearProperty(ATHENZ_DBPOOL_PROP1);
        assertEquals(DataSourceFactory.retrieveConfigSetting(ATHENZ_DBPOOL_PROP1, 25), 25);
    }
    
    @Test
    public void testRetrieveConfigSettingIntInvalid() {
        System.setProperty(ATHENZ_DBPOOL_PROP1, "abc");
        assertEquals(DataSourceFactory.retrieveConfigSetting(ATHENZ_DBPOOL_PROP1, 20), 20);
        System.clearProperty(ATHENZ_DBPOOL_PROP1);
    }

    @Test
    public void testWrongDbClass() {
        System.setProperty(DataSourceFactory.DRIVER_CLASS_NAME, "testDbDriverClass");
        Properties props = new Properties();
        props.setProperty("user", "user");
        props.setProperty("password", "password");

        assertThrows(RuntimeException.class, () -> DataSourceFactory.create("jdbc:mysql:localhost:3306/athenz", props));
        System.clearProperty(DataSourceFactory.DRIVER_CLASS_NAME);
    }
}
