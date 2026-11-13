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
package com.yahoo.athenz.zts.store;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.PolicyBundle;
import com.yahoo.athenz.zms.PolicyBundleFile;
import com.yahoo.athenz.zts.ZTSTestUtils;
import com.yahoo.athenz.zts.cache.DataCache;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.*;

public class DataStorePolicyBundleTest {

    private static final String ZTS_DATA_STORE_PATH = "/tmp/zts_server_unit_tests/zts_root";

    private PrivateKey zmsPrivateKey;
    private Metric metric;
    private DataStore store;

    @BeforeMethod
    public void setup() throws Exception {

        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));

        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair keyPair = gen.generateKeyPair();
        zmsPrivateKey = keyPair.getPrivate();

        metric = Mockito.mock(Metric.class);
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore(ZTS_DATA_STORE_PATH, zmsPrivateKey, "0");
        store = new DataStore(clogStore, null, metric);
        store.zmsPublicKeyCache.put("0", keyPair.getPublic());
    }

    private PolicyBundleFile file(String path, String content) {
        return new PolicyBundleFile().setPath(path).setContent(content)
                .setSha256(java.util.HexFormat.of().formatHex(
                        Crypto.sha256(content.getBytes(StandardCharsets.UTF_8))));
    }

    private PolicyBundle bundle(String domain, String name) {
        return new PolicyBundle().setName(domain + ":bundle." + name).setEngine("rego").setVersion("v1")
                .setFiles(new ArrayList<>(Collections.singletonList(file("p.rego", "package " + name))));
    }

    @Test
    public void testValidatePolicyBundleFiles() {

        PolicyBundle bundle = bundle("sports", "api");
        assertTrue(store.validatePolicyBundleFiles(bundle));

        // two files

        bundle.getFiles().add(file("q.rego", "package q"));
        assertTrue(store.validatePolicyBundleFiles(bundle));

        // digest mismatch

        bundle.getFiles().get(1).setContent("package other");
        assertFalse(store.validatePolicyBundleFiles(bundle));

        // null content

        bundle.getFiles().get(1).setContent(null);
        assertFalse(store.validatePolicyBundleFiles(bundle));

        // null digest

        bundle.getFiles().get(1).setContent("package q").setSha256(null);
        assertFalse(store.validatePolicyBundleFiles(bundle));

        // no files

        bundle.setFiles(new ArrayList<>());
        assertFalse(store.validatePolicyBundleFiles(bundle));
        bundle.setFiles(null);
        assertFalse(store.validatePolicyBundleFiles(bundle));
    }

    @Test
    public void testProcessDomainPolicyBundlesNoBundles() {

        // no bundles at all

        DomainData domainData = new DomainData().setName("sports");
        DataCache cache = new DataCache();
        store.processDomainPolicyBundles(domainData, cache);
        assertTrue(cache.getPolicyBundles().isEmpty());

        // empty list

        domainData.setPolicyBundles(new ArrayList<>());
        store.processDomainPolicyBundles(domainData, cache);
        assertTrue(cache.getPolicyBundles().isEmpty());

        Mockito.verifyNoInteractions(metric);
    }

    @Test
    public void testProcessDomainPolicyBundles() {

        PolicyBundle active1 = bundle("sports", "api");
        PolicyBundle active2 = bundle("sports", "api.v2").setActive(Boolean.TRUE);
        PolicyBundle inactive = bundle("sports", "old").setActive(Boolean.FALSE);
        PolicyBundle otherDomain = bundle("weather", "foreign");
        PolicyBundle noName = bundle("sports", "x").setName(null);
        PolicyBundle badFiles = bundle("sports", "bad");
        badFiles.getFiles().get(0).setContent("tampered");

        DomainData domainData = new DomainData().setName("sports");
        domainData.setPolicyBundles(new ArrayList<>(Arrays.asList(active1, active2, inactive, otherDomain, noName, badFiles)));

        DataCache cache = new DataCache();
        store.processDomainPolicyBundles(domainData, cache);

        assertEquals(new ArrayList<>(cache.getPolicyBundles().keySet()), Arrays.asList("api", "api.v2"));
        assertSame(cache.getPolicyBundle("api"), active1);
        assertSame(cache.getPolicyBundle("api.v2"), active2);
        assertNull(cache.getPolicyBundle("old"));
        assertNull(cache.getPolicyBundle("bad"));

        // only the bundle with the file digest mismatch is reported

        Mockito.verify(metric, Mockito.times(1)).increment("bundle_validation_failure", "sports");
    }

    @Test
    public void testProcessDomainDataWithBundles() {

        DomainData domainData = new DomainData().setName("sports");
        domainData.setPolicyBundles(new ArrayList<>(Collections.singletonList(bundle("sports", "api"))));
        store.processDomainData(domainData);

        DataCache cache = store.getDataCache("sports");
        assertNotNull(cache);
        assertNotNull(cache.getPolicyBundle("api"));
        assertEquals(cache.getPolicyBundle("api").getEngine(), "rego");

        // domain without bundles is still processed

        store.processDomainData(new DomainData().setName("weather"));
        cache = store.getDataCache("weather");
        assertNotNull(cache);
        assertTrue(cache.getPolicyBundles().isEmpty());
    }

    @Test
    public void testProcessDomainDataFailedBundleDigestKeepsDomain() {

        PolicyBundle bundle = bundle("sports", "api");
        bundle.getFiles().get(0).setContent("tampered");
        DomainData domainData = new DomainData().setName("sports")
                .setPolicyBundles(new ArrayList<>(Collections.singletonList(bundle)));
        store.processDomainData(domainData);

        DataCache cache = store.getDataCache("sports");
        assertNotNull(cache);
        assertTrue(cache.getPolicyBundles().isEmpty());
    }

    @Test
    public void testProcessDomainDataLegacyIgnoresBundles() {

        // bundles are not covered by the legacy signed domain signature
        // so they are ignored unless the domain came from a jws payload

        DomainData domainData = new DomainData().setName("sports");
        domainData.setPolicyBundles(new ArrayList<>(Collections.singletonList(bundle("sports", "api"))));
        store.processDomainData(domainData, false);

        DataCache cache = store.getDataCache("sports");
        assertNotNull(cache);
        assertTrue(cache.getPolicyBundles().isEmpty());

        // no bundles in a legacy domain

        store.processDomainData(new DomainData().setName("weather"), false);
        assertTrue(store.getDataCache("weather").getPolicyBundles().isEmpty());
        store.processDomainData(new DomainData().setName("rain").setPolicyBundles(new ArrayList<>()), false);
        assertTrue(store.getDataCache("rain").getPolicyBundles().isEmpty());

        // jws domains accept them

        store.processDomainData(domainData, true);
        assertNotNull(store.getDataCache("sports").getPolicyBundle("api"));
    }
}
