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
package com.yahoo.athenz.zts.cert.impl;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.function.Function;
import com.google.common.io.Resources;
import com.yahoo.athenz.zts.ZTSConsts;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class KeyStoreCertSignerFactoryTest {

    private BooleanSupplier getSysPropRestoreLambda(String... propNames) {
        final Map<String, String> restoreMap = new HashMap<>();
        for (String propName: propNames) {
            restoreMap.put(propName, System.getProperty(propName));
        }

        return () -> {
            restoreMap.forEach((name, value) -> {
                if (value != null) {
                    System.setProperty(name, value);
                }
            });
            return true;
        };
    }

    private BooleanSupplier sysPropRestoreFunc = null;
    @BeforeClass
    public void setSysPropRestoreFunc() {
        this.sysPropRestoreFunc = this.getSysPropRestoreLambda(
            "athenz.zts.keystore_signer.keystore_password",
            "athenz.zts.keystore_signer.keystore_path",
            "athenz.zts.keystore_signer.keystore_type",
            "athenz.zts.keystore_signer.keystore_ca_alias",
            ZTSConsts.ZTS_PROP_CERTSIGN_MAX_EXPIRY_TIME
        );
    }
    @AfterClass
    public void restoreSysProp() {
        this.sysPropRestoreFunc.getAsBoolean();
    }

    @Test(expectedExceptions = { IllegalArgumentException.class }, expectedExceptionsMessageRegExp = "Failed to get keyStorePassword from athenz.zts.keystore_signer.keystore_password property.")
    public void testCreateEmptyPath() {
        final BooleanSupplier sysPropRestoreFunc = this.getSysPropRestoreLambda(
            "athenz.zts.keystore_signer.keystore_password"
        );

        // test main
        System.clearProperty("athenz.zts.keystore_signer.keystore_password");
        try (KeyStoreCertSigner keyStoreCertSigner = (KeyStoreCertSigner) new KeyStoreCertSignerFactory().create()) {
        } finally {
            sysPropRestoreFunc.getAsBoolean();
        }
    }

    @Test(expectedExceptions = { IllegalArgumentException.class }, expectedExceptionsMessageRegExp = "Failed to get keyStorePath from athenz.zts.keystore_signer.keystore_path property.")
    public void testCreateEmptyPassword() {
        final BooleanSupplier sysPropRestoreFunc = this.getSysPropRestoreLambda(
            "athenz.zts.keystore_signer.keystore_password",
            "athenz.zts.keystore_signer.keystore_path"
        );

        // test main
        System.setProperty("athenz.zts.keystore_signer.keystore_password", "dummy");
        System.clearProperty("athenz.zts.keystore_signer.keystore_path");
        try (KeyStoreCertSigner keyStoreCertSigner = (KeyStoreCertSigner) new KeyStoreCertSignerFactory().create()) {
        } finally {
            sysPropRestoreFunc.getAsBoolean();
        }
    }

    @Test(expectedExceptions = { RuntimeException.class, FileNotFoundException.class }, expectedExceptionsMessageRegExp = ".*/keystore.pkcs12.not_exist \\(No such file or directory\\)")
    public void testCreateFileNotFound() {
        final BooleanSupplier sysPropRestoreFunc = this.getSysPropRestoreLambda(
            "athenz.zts.keystore_signer.keystore_password",
            "athenz.zts.keystore_signer.keystore_path"
        );

        // test main
        String filePath = Resources.getResource("keystore.pkcs12").getFile();
        System.setProperty("athenz.zts.keystore_signer.keystore_password", "dummy");
        System.setProperty("athenz.zts.keystore_signer.keystore_path", filePath + ".not_exist");
        try (KeyStoreCertSigner keyStoreCertSigner = (KeyStoreCertSigner) new KeyStoreCertSignerFactory().create()) {
        } finally {
            sysPropRestoreFunc.getAsBoolean();
        }
    }

    @Test(expectedExceptions = { RuntimeException.class, IOException.class }, expectedExceptionsMessageRegExp = ".* keystore password was incorrect")
    public void testCreateWrongPassword() {
        final BooleanSupplier sysPropRestoreFunc = this.getSysPropRestoreLambda(
            "athenz.zts.keystore_signer.keystore_password",
            "athenz.zts.keystore_signer.keystore_path"
        );

        // test main
        String filePath = Resources.getResource("keystore.pkcs12").getFile();
        System.setProperty("athenz.zts.keystore_signer.keystore_password", "dummy");
        System.setProperty("athenz.zts.keystore_signer.keystore_path", filePath);
        try (KeyStoreCertSigner keyStoreCertSigner = (KeyStoreCertSigner) new KeyStoreCertSignerFactory().create()) {
        } finally {
            sysPropRestoreFunc.getAsBoolean();
        }
    }

    @Test(expectedExceptions = { RuntimeException.class, IllegalArgumentException.class }, expectedExceptionsMessageRegExp = ".* Failed to get caPrivateKey/caCertificate from athenz.zts.keystore_signer.keystore_ca_alias property.")
    public void testCreateAliasNotFound() {
        final BooleanSupplier sysPropRestoreFunc = this.getSysPropRestoreLambda(
            "athenz.zts.keystore_signer.keystore_password",
            "athenz.zts.keystore_signer.keystore_path",
            "athenz.zts.keystore_signer.keystore_ca_alias"
        );

        // test main
        String filePath = Resources.getResource("keystore.pkcs12").getFile();
        System.setProperty("athenz.zts.keystore_signer.keystore_password", "123456");
        System.setProperty("athenz.zts.keystore_signer.keystore_path", filePath);
        System.setProperty("athenz.zts.keystore_signer.keystore_ca_alias", "dummy");
        try (KeyStoreCertSigner keyStoreCertSigner = (KeyStoreCertSigner) new KeyStoreCertSignerFactory().create()) {
        } finally {
            sysPropRestoreFunc.getAsBoolean();
        }
    }

    @Test
    public void testCreate() {
        final BooleanSupplier sysPropRestoreFunc = this.getSysPropRestoreLambda(
            "athenz.zts.keystore_signer.keystore_password",
            "athenz.zts.keystore_signer.keystore_path",
            "athenz.zts.keystore_signer.keystore_type",
            "athenz.zts.keystore_signer.keystore_ca_alias",
            ZTSConsts.ZTS_PROP_CERTSIGN_MAX_EXPIRY_TIME
        );

        // test main
        String filePath = Resources.getResource("keystore.pkcs12").getFile();
        System.setProperty("athenz.zts.keystore_signer.keystore_password", "123456");
        System.setProperty("athenz.zts.keystore_signer.keystore_path", filePath);
        System.setProperty("athenz.zts.keystore_signer.keystore_type", "JKS");
        System.setProperty("athenz.zts.keystore_signer.keystore_ca_alias", "unit");
        System.setProperty(ZTSConsts.ZTS_PROP_CERTSIGN_MAX_EXPIRY_TIME, "36000");
        try (KeyStoreCertSigner keyStoreCertSigner = (KeyStoreCertSigner) new KeyStoreCertSignerFactory().create()) {
            // assertion
            Function<String, Object> getFieldValue = (String fieldName) -> {
                try {
                    Field field = keyStoreCertSigner.getClass().getDeclaredField(fieldName);
                    field.setAccessible(true);
                    return field.get(keyStoreCertSigner);
                } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
                    return null;
                }
            };
            Assert.assertEquals(((X509Certificate) getFieldValue.apply("caCertificate")).getIssuerX500Principal().getName(), "CN=unit.test.athenz,OU=Athenz,O=Oath,L=PlayaVista,ST=CA,C=US");
            Assert.assertNotNull(getFieldValue.apply("caPrivateKey"));
            Assert.assertEquals(getFieldValue.apply("maxCertExpiryTimeMins"), 36000);
        } finally {
            sysPropRestoreFunc.getAsBoolean();
        }
    }

}
