/*
 * Copyright The Athenz Authors.
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

package com.yahoo.athenz.zts;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.ehcache.Cache;
import org.ehcache.CacheManager;
import org.ehcache.config.CacheConfiguration;
import org.ehcache.config.builders.CacheConfigurationBuilder;
import org.ehcache.config.builders.CacheManagerBuilder;
import org.ehcache.impl.copy.ReadWriteCopier;
import org.ehcache.spi.serialization.Serializer;
import org.ehcache.spi.serialization.SerializerException;
import org.ehcache.xml.XmlConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

/**
 * Provides optional caching for {@link ZTSClient}. <br>
 * This class is designed to support multiple caches - but is currently only support a
 *  cache from {domain+principal} to {@link RoleAccess} - see
 *  {@link com.yahoo.athenz.zts.ZTSClient#getRoleAccess(java.lang.String, java.lang.String)}.  <br><br>
 *
 * Ehcache XML config file links: <ul>
 *      <li> Documentation: https://www.ehcache.org/documentation/3.8/xml.html
 *      <li> XSD:           http://www.ehcache.org/ehcache.xml
 *      <li> Example:       https://www.ehcache.org/documentation/3.0/examples.html#xml-with-107-extension
 * </ul><br><br>
 *
 * To enable caching, set the system-property {@link #ZTS_CLIENT_PROP_EHCACHE_XML_PATH_ROLE_ACCESS}
 *  to an ehcache config XML file like this example: <pre>{@code
 *      <config xmlns="http://www.ehcache.org/v3">
 *          <cache-template name="role-access">
 *              <expiry><ttl unit="minutes">10</ttl></expiry>
 *              <heap unit="entries">10000</heap>
 *          </cache-template>
 *      </config>
 * }</pre>
 */
public class ZTSClientCache {

    public static final String ZTS_CLIENT_PROP_CACHE_CLASS                  = "athenz.zts.client.cache_class";
    public static final String ZTS_CLIENT_PROP_EHCACHE_XML_PATH_ROLE_ACCESS = "athenz.zts.client.ehcache_xml_path";

    // Note: caches might be null !
    private Cache<DomainAndPrincipal, RoleAccess> roleAccessCache;
    // ...more to come?

    private File ehcacheConfigXmlFile;
    private XmlConfiguration xmlConfiguration;
    private CacheManagerBuilder<CacheManager> cacheManagerBuilder;
    private CacheManager cacheManager;

    private static final Logger LOG = LoggerFactory.getLogger(ZTSClientCache.class);

    /**
     * Get the singleton instance - which is usually a ZTSClientCache.
     * However, another class could be used (usually for tests) - by providing its class-name in the system-property {@link #ZTS_CLIENT_PROP_CACHE_CLASS}
     * @return the singleton instance
     */
    public static ZTSClientCache getInstance() {
        return SingletonHolder.INSTANCE;
    }

    public Cache<DomainAndPrincipal, RoleAccess> getRoleAccessCache() {
        return roleAccessCache;
    }

    /** The correct way to implement singleton: see https://en.wikipedia.org/wiki/Double-checked_locking#Usage_in_Java */
    private static class SingletonHolder {
        public static final ZTSClientCache INSTANCE = createZTSClientCache();
    }

    /** Construct a ZTSClientCache using the configured class */
    private static ZTSClientCache createZTSClientCache() throws ExceptionInInitializerError {
        String ztsClientCacheClass = System.getProperty(ZTS_CLIENT_PROP_CACHE_CLASS, ZTSClientCache.class.getName());
        try {
            return (ZTSClientCache) Class.forName(ztsClientCacheClass).getConstructor().newInstance();
        } catch (Exception exception) {
            throw new ExceptionInInitializerError(exception);
        }
    }

    public ZTSClientCache() {
        // Find the config file.
        String ehcacheConfigXmlFileName = System.getProperty(ZTS_CLIENT_PROP_EHCACHE_XML_PATH_ROLE_ACCESS);
        if ((ehcacheConfigXmlFileName == null) || ehcacheConfigXmlFileName.isEmpty()) {
            LOG.info("ZTSClient cache is disabled: system-property \"{}\" is not set", ZTS_CLIENT_PROP_EHCACHE_XML_PATH_ROLE_ACCESS);
            return;
        }

        // Check if the config file exists.
        ehcacheConfigXmlFile = new File(ehcacheConfigXmlFileName);
        if (! ehcacheConfigXmlFile.isFile()) {
            LOG.info("ZTSClient cache is disabled: system-property \"{}\" doesn't reference a file", ZTS_CLIENT_PROP_EHCACHE_XML_PATH_ROLE_ACCESS);
            xmlConfiguration = null;
            return;
        }

        // Load the config file.
        LOG.info("ZTSClient cache is initializing (system-property \"{}\" references the file \"{}\")", ZTS_CLIENT_PROP_EHCACHE_XML_PATH_ROLE_ACCESS, ehcacheConfigXmlFile.getAbsoluteFile());
        try {
            xmlConfiguration = new XmlConfiguration(ehcacheConfigXmlFile.toURI().toURL());
        } catch (Exception exception) {
            LOG.error("ZTSClient cache is disabled: system-property \"{}\" references the file \"{}\" - which has errors: ", ZTS_CLIENT_PROP_EHCACHE_XML_PATH_ROLE_ACCESS, ehcacheConfigXmlFile.getAbsoluteFile(), exception);
            return;
        }

        // We have multiple caches, but we want to use a single CacheManager:
        // Phase 1: build a CacheManager, after preparing all cache-configurations into it's builder.
        cacheManagerBuilder = CacheManagerBuilder.newCacheManagerBuilder();
        List<Runnable> phase2Executions = prepareAllCaches();
        try {
            cacheManager = cacheManagerBuilder.build(true);
        } catch (Exception exception) {
            LOG.error("ZTSClient cache is disabled: system-property \"{}\" references the file \"{}\" - which has build errors: ", ZTS_CLIENT_PROP_EHCACHE_XML_PATH_ROLE_ACCESS, ehcacheConfigXmlFile.getAbsoluteFile(), exception);
            return;
        }

        // Phase 2: build actual caches, and assign them to members.
        for (Runnable phase2Execution : phase2Executions) {
            if (phase2Execution != null) {
                phase2Execution.run();
            }
        }
    }

    /** Call {@link #prepareCache} per each cache */
    private List<Runnable> prepareAllCaches() {
        return Arrays.asList(
                prepareCache("role-access", DomainAndPrincipal.class, RoleAccess.class, null, RoleAccessCopierAndSerializer.class, cache -> roleAccessCache = cache)
                // ...more to come?
            );
    }

    /**
     * Prepare an ehcache CacheConfiguration from one &lt;ehcache:cache&gt; element in the config xml file.
     * Returns a function that should be executed after cacheManagerBuilder is fully initialized, and cacheManager is built.
     */
    private <K, V> Runnable prepareCache(
            String cacheName,
            Class<K> keyClass,
            Class<V> valueClass,
            Class<? extends CopierAndSerializer<K>> keyCopierAndSerializerClass,
            Class<? extends CopierAndSerializer<V>> valueCopierAndSerializerClass,
            Consumer<Cache<K, V>> cacheIsReady) {

        // Get our cache's configuration from the config file, and apply the value-serializer.
        CacheConfiguration<K, V> cacheConfiguration;
        try {
            CacheConfigurationBuilder<K, V> configurationBuilder = xmlConfiguration.newCacheConfigurationBuilderFromTemplate(cacheName, keyClass, valueClass);
            if (configurationBuilder == null) {
                LOG.info("ZTSClient \"{}\" cache is disabled: system-property \"{}\" references the file \"{}\" - which has errors in the <ehcache:cache alias=\"{}\"> element.", cacheName, ZTS_CLIENT_PROP_EHCACHE_XML_PATH_ROLE_ACCESS, ehcacheConfigXmlFile.getAbsoluteFile(), cacheName);
                return null;
            }
            if (keyCopierAndSerializerClass != null) {
                configurationBuilder = configurationBuilder
                        .withKeySerializer(keyCopierAndSerializerClass)
                        .withKeyCopier(keyCopierAndSerializerClass);
            }
            if (valueCopierAndSerializerClass != null) {
                configurationBuilder = configurationBuilder
                        .withValueSerializer(valueCopierAndSerializerClass)
                        .withValueCopier(valueCopierAndSerializerClass);
            }
            cacheConfiguration = configurationBuilder.build();
        } catch (Exception exception) {
            LOG.info("ZTSClient \"{}\" cache is disabled: system-property \"{}\" references the file \"{}\" - which has errors in the <ehcache:cache alias=\"{}\"> element: ", cacheName, ZTS_CLIENT_PROP_EHCACHE_XML_PATH_ROLE_ACCESS, ehcacheConfigXmlFile.getAbsoluteFile(), cacheName, exception);
            return null;
        }

        // Store this cache's configuration - so it is available to the to-be-built cacheManager.
        cacheManagerBuilder = cacheManagerBuilder.withCache(cacheName, cacheConfiguration);

        // This will be executed after cacheManagerBuilder is fully initialized, and cacheManager is built.
        return () -> {
            Cache<K, V> cache = cacheManager.getCache(cacheName, keyClass, valueClass);
            if (cache == null) {
                LOG.info("ZTSClient \"{}\" cache is disabled: system-property \"{}\" references the file \"{}\" - which has errors in the <ehcache:cache alias=\"{}\"> element: unknown error", cacheName, ZTS_CLIENT_PROP_EHCACHE_XML_PATH_ROLE_ACCESS, ehcacheConfigXmlFile.getAbsoluteFile(), cacheName);
            } else {
                LOG.info("ZTSClient \"{}\" cache is enabled", cacheName);
                cacheIsReady.accept(cache);
            }
        };
    }

    /**
     * This class holds a domain and a principal - and served as a cache-key.
     * This class relies on {@link AbstractMap.SimpleEntry} for equals, hashCode, and serialization.
     */
    public static class DomainAndPrincipal extends AbstractMap.SimpleEntry<String, String> {
        public DomainAndPrincipal(String domain, String principal) {
            super(domain, principal);
        }
    }

    /** A combination of both {@link ReadWriteCopier} and {@link Serializer} */
    public static abstract class CopierAndSerializer<T> extends ReadWriteCopier<T> implements Serializer<T> {
    }

    /** Allows ehcache to copy/serialize {@link RoleAccess} instances */
    public static class RoleAccessCopierAndSerializer extends CopierAndSerializer<RoleAccess> {

        private static final TypeReference<RoleAccess> MAP_STRING_STRING = new TypeReference<RoleAccess>() { };

        /** This constructor is required by {@link ReadWriteCopier} */
        public RoleAccessCopierAndSerializer() {
        }

        /**
         * This constructor is required by {@link Serializer}
         * @param classLoader ignored
         */
        public RoleAccessCopierAndSerializer(ClassLoader classLoader) {
        }

        /** To support off-heap */
        @Override
        public ByteBuffer serialize(RoleAccess roleAccess) throws SerializerException {
            CharsetEncoder encoder = StandardCharsets.UTF_8.newEncoder();   // not thread-safe
            try {
                String json = OBJECT_MAPPER.writeValueAsString(roleAccess);
                return encoder.encode(CharBuffer.wrap(json));
            } catch (Exception exception) {
                throw new SerializerException(exception);
            }
        }

        /** To support off-heap */
        @Override
        public RoleAccess read(ByteBuffer binary) throws SerializerException {
            CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();   // not thread-safe
            try {
                String json = decoder.decode(binary).toString();
                return OBJECT_MAPPER.readValue(json, MAP_STRING_STRING);
            } catch (Exception exception) {
                throw new SerializerException(exception);
            }
        }

        /** Extra safe - clone on both read and write */
        @Override
        public RoleAccess copy(RoleAccess roleAccess) {
            RoleAccess clone = new RoleAccess();
            clone.setRoles(roleAccess.getRoles());
            return clone;
        }

        @Override
        public boolean equals(RoleAccess roleAccess, ByteBuffer binary) throws SerializerException {
            return roleAccess.equals(read(binary));
        }
    }

    // To be used for Serializer implementations:
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
}
