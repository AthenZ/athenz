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
package com.yahoo.athenz.common.server.util.config;

import com.yahoo.athenz.common.server.util.Utils;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfig;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigCsv;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigDouble;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigDuration;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigFloat;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigInteger;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigLong;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigString;
import com.yahoo.athenz.common.server.util.config.providers.ConfigProviderFile;
import org.testng.annotations.Test;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import static org.testng.Assert.*;

public class DynamicConfigTest {

    @Test
    public void testStatic() throws IOException {

        File configFile = File.createTempFile("ConfigProviderFileTest.testStatic", ".conf");

        writeFile(configFile,
                "string-key-ok: string-value\n" +
                "\n" +
                "int-key-ok: 100\n" +
                "int-key-too-big: 10000000000\n" +
                "int-key-invalid-1: x100\n" +
                "int-key-invalid-2: 100x\n" +
                "\n" +
                "long-key-ok: 100\n" +
                "long-key-too-big: 100000000000000000000\n" +
                "long-key-invalid-1: x100\n" +
                "long-key-invalid-2: 100x\n" +
                "\n" +
                "float-key-ok-1: 100\n" +
                "float-key-ok-2: 12.34\n" +
                "float-key-invalid-1: x100\n" +
                "float-key-invalid-2: 100x\n" +
                "\n" +
                "double-key-ok-1: 100\n" +
                "double-key-ok-2: 12.34\n" +
                "double-key-invalid-1: x100\n" +
                "double-key-invalid-2: 100x\n" +
                "\n" +
                "boolean-key-true:    true\n" +
                "boolean-key-yes:     yes\n" +
                "boolean-key-on:      on\n" +
                "boolean-key-false:   false\n" +
                "boolean-key-no:      no\n" +
                "boolean-key-off:     off\n" +
                "boolean-key-invalid: hmm...\n" +
                "\n" +
                "duration-key-reload: 10\n" +
                "duration-key-short: 100\n" +
                "duration-key-long: 100000\n" +
                "duration-key-too-big: 100000000000000000000\n" +
                "duration-key-invalid-1: x100\n" +
                "duration-key-invalid-2: 100x\n" +
                "\n" +
                "csv-key-ok: aaa,111,1234567890123456789,12.34,bbb\n");

        try (ConfigManager configManager = new ConfigManager("duration-key-reload", 10, TimeUnit.MILLISECONDS)
                    .addProvider(new ConfigProviderFile())
                    .addConfigSource("prop-file://" + configFile)) {

            DynamicConfigString   dynamicConfigStringOk             = new DynamicConfigString(   configManager, "string-key-ok",          "default-value");
            DynamicConfigString   dynamicConfigStringMissing        = new DynamicConfigString(   configManager, "string-key-missing",     "default-value");
            DynamicConfigString   dynamicConfigStringFixed          = new DynamicConfigString("default-value");

            DynamicConfigInteger  dynamicConfigIntegerOk            = new DynamicConfigInteger(  configManager, "int-key-ok",             123456, 10,   1000);
            DynamicConfigInteger  dynamicConfigIntegerOverflow      = new DynamicConfigInteger(  configManager, "int-key-ok",             123456, 0,    10);
            DynamicConfigInteger  dynamicConfigIntegerUnderflow     = new DynamicConfigInteger(  configManager, "int-key-ok",             123456, 1000, 10000);
            DynamicConfigInteger  dynamicConfigIntegerTooBig        = new DynamicConfigInteger(  configManager, "int-key-too-big",        123456);
            DynamicConfigInteger  dynamicConfigIntegerInvalid1      = new DynamicConfigInteger(  configManager, "int-key-invalid-1",      123456);
            DynamicConfigInteger  dynamicConfigIntegerInvalid2      = new DynamicConfigInteger(  configManager, "int-key-invalid-2",      123456);
            DynamicConfigInteger  dynamicConfigIntegerMissing       = new DynamicConfigInteger(  configManager, "int-key-missing",        123456);
            DynamicConfigInteger  dynamicConfigIntegerFixed         = new DynamicConfigInteger(123456);

            DynamicConfigLong     dynamicConfigLongOk               = new DynamicConfigLong(     configManager, "long-key-ok",            123456L, 10L,   1000L);
            DynamicConfigLong     dynamicConfigLongOverflow         = new DynamicConfigLong(     configManager, "long-key-ok",            123456L, 0L,    10L);
            DynamicConfigLong     dynamicConfigLongUnderflow        = new DynamicConfigLong(     configManager, "long-key-ok",            123456L, 1000L, 10000L);
            DynamicConfigLong     dynamicConfigLongTooBig           = new DynamicConfigLong(     configManager, "long-key-too-big",       123456L);
            DynamicConfigLong     dynamicConfigLongInvalid1         = new DynamicConfigLong(     configManager, "long-key-invalid-1",     123456L);
            DynamicConfigLong     dynamicConfigLongInvalid2         = new DynamicConfigLong(     configManager, "long-key-invalid-2",     123456L);
            DynamicConfigLong     dynamicConfigLongMissing          = new DynamicConfigLong(     configManager, "long-key-missing",       123456L);
            DynamicConfigLong     dynamicConfigLongFixed            = new DynamicConfigLong(123456L);

            DynamicConfigFloat    dynamicConfigFloatOk1             = new DynamicConfigFloat(    configManager, "float-key-ok-1",         1.23F, 10F,   1000F);
            DynamicConfigFloat    dynamicConfigFloatOk2             = new DynamicConfigFloat(    configManager, "float-key-ok-2",         1.23F);
            DynamicConfigFloat    dynamicConfigFloatOverflow        = new DynamicConfigFloat(    configManager, "float-key-ok-1",         1.23F, 0F,    10F);
            DynamicConfigFloat    dynamicConfigFloatUnderflow       = new DynamicConfigFloat(    configManager, "float-key-ok-1",         1.23F, 1000F, 10000F);
            DynamicConfigFloat    dynamicConfigFloatInvalid1        = new DynamicConfigFloat(    configManager, "float-key-invalid-1",    1.23F);
            DynamicConfigFloat    dynamicConfigFloatInvalid2        = new DynamicConfigFloat(    configManager, "float-key-invalid-2",    1.23F);
            DynamicConfigFloat    dynamicConfigFloatMissing         = new DynamicConfigFloat(    configManager, "float-key-missing",      1.23F);
            DynamicConfigFloat    dynamicConfigFloatFixed           = new DynamicConfigFloat(1.23F);

            DynamicConfigDouble   dynamicConfigDoubleOk1            = new DynamicConfigDouble(   configManager, "double-key-ok-1",        123.456, 10.0, 1000.0);
            DynamicConfigDouble   dynamicConfigDoubleOk2            = new DynamicConfigDouble(   configManager, "double-key-ok-2",        123.456);
            DynamicConfigDouble   dynamicConfigDoubleOverflow       = new DynamicConfigDouble(   configManager, "double-key-ok-1",        123.456, 0.0,    10.0);
            DynamicConfigDouble   dynamicConfigDoubleUnderflow      = new DynamicConfigDouble(   configManager, "double-key-ok-1",        123.456, 1000.0, 10000.0);
            DynamicConfigDouble   dynamicConfigDoubleInvalid1       = new DynamicConfigDouble(   configManager, "double-key-invalid-1",   123.456);
            DynamicConfigDouble   dynamicConfigDoubleInvalid2       = new DynamicConfigDouble(   configManager, "double-key-invalid-2",   123.456);
            DynamicConfigDouble   dynamicConfigDoubleMissing        = new DynamicConfigDouble(   configManager, "double-key-missing",     123.456);
            DynamicConfigDouble   dynamicConfigDoubleFixed          = new DynamicConfigDouble(123.456);

            DynamicConfigBoolean  dynamicConfigBooleanTrueTrue      = new DynamicConfigBoolean(  configManager, "boolean-key-true",       true);
            DynamicConfigBoolean  dynamicConfigBooleanTrueYes       = new DynamicConfigBoolean(  configManager, "boolean-key-yes",        true);
            DynamicConfigBoolean  dynamicConfigBooleanTrueOn        = new DynamicConfigBoolean(  configManager, "boolean-key-on",         true);
            DynamicConfigBoolean  dynamicConfigBooleanTrueFalse     = new DynamicConfigBoolean(  configManager, "boolean-key-false",      true);
            DynamicConfigBoolean  dynamicConfigBooleanTrueNo        = new DynamicConfigBoolean(  configManager, "boolean-key-no",         true);
            DynamicConfigBoolean  dynamicConfigBooleanTrueOff       = new DynamicConfigBoolean(  configManager, "boolean-key-off",        true);
            DynamicConfigBoolean  dynamicConfigBooleanTrueInvalid   = new DynamicConfigBoolean(  configManager, "boolean-key-invalid",    true);
            DynamicConfigBoolean  dynamicConfigBooleanTrueMissing   = new DynamicConfigBoolean(  configManager, "boolean-key-missing",    true);
            DynamicConfigBoolean  dynamicConfigBooleanTrueFixed     = new DynamicConfigBoolean(true);

            DynamicConfigBoolean  dynamicConfigBooleanFalseTrue     = new DynamicConfigBoolean(  configManager, "boolean-key-true",       false);
            DynamicConfigBoolean  dynamicConfigBooleanFalseYes      = new DynamicConfigBoolean(  configManager, "boolean-key-yes",        false);
            DynamicConfigBoolean  dynamicConfigBooleanFalseOn       = new DynamicConfigBoolean(  configManager, "boolean-key-on",         false);
            DynamicConfigBoolean  dynamicConfigBooleanFalseFalse    = new DynamicConfigBoolean(  configManager, "boolean-key-false",      false);
            DynamicConfigBoolean  dynamicConfigBooleanFalseNo       = new DynamicConfigBoolean(  configManager, "boolean-key-no",         false);
            DynamicConfigBoolean  dynamicConfigBooleanFalseOff      = new DynamicConfigBoolean(  configManager, "boolean-key-off",        false);
            DynamicConfigBoolean  dynamicConfigBooleanFalseInvalid  = new DynamicConfigBoolean(  configManager, "boolean-key-invalid",    false);
            DynamicConfigBoolean  dynamicConfigBooleanFalseMissing  = new DynamicConfigBoolean(  configManager, "boolean-key-missing",    false);
            DynamicConfigBoolean  dynamicConfigBooleanFalseFixed    = new DynamicConfigBoolean(false);

            DynamicConfigDuration dynamicConfigDurationShort        = new DynamicConfigDuration( configManager, "duration-key-short",     123456, TimeUnit.SECONDS);
            DynamicConfigDuration dynamicConfigDurationLong         = new DynamicConfigDuration( configManager, "duration-key-long",      123456, TimeUnit.SECONDS);
            DynamicConfigDuration dynamicConfigDurationTooBig       = new DynamicConfigDuration( configManager, "duration-key-too-big",   123456, TimeUnit.SECONDS);
            DynamicConfigDuration dynamicConfigDurationInvalid1     = new DynamicConfigDuration( configManager, "duration-key-invalid-1", 123456, TimeUnit.SECONDS);
            DynamicConfigDuration dynamicConfigDurationInvalid2     = new DynamicConfigDuration( configManager, "duration-key-invalid-2", 123456, TimeUnit.SECONDS);
            DynamicConfigDuration dynamicConfigDurationMissing      = new DynamicConfigDuration( configManager, "duration-key-missing",   123456, TimeUnit.SECONDS);
            DynamicConfigDuration dynamicConfigDurationFixed        = new DynamicConfigDuration(123456, TimeUnit.SECONDS);

            DynamicConfigCsv      dynamicConfigCsvOk                = new DynamicConfigCsv(      configManager, "csv-key-ok",             "default-value-a,default-value-b");
            DynamicConfigCsv      dynamicConfigCsvMissing           = new DynamicConfigCsv(      configManager, "csv-key-missing",        "default-value-a,default-value-b");
            DynamicConfigCsv      dynamicConfigCsvFixed             = new DynamicConfigCsv(      "fixed-value-a,fixed-value-b");

            assertEquals("string-value",  dynamicConfigStringOk.toString());
            assertEquals("string-value",  dynamicConfigStringOk.get());
            assertEquals("default-value", dynamicConfigStringMissing.get());
            assertEquals("default-value", dynamicConfigStringFixed.get());

            assertEquals("100",            dynamicConfigIntegerOk.toString());
            assertEquals(Integer.valueOf(100),    dynamicConfigIntegerOk.get());
            assertEquals(Integer.valueOf(123456), dynamicConfigIntegerOverflow.get());
            assertEquals(Integer.valueOf(123456), dynamicConfigIntegerUnderflow.get());
            assertEquals(Integer.valueOf(123456), dynamicConfigIntegerTooBig.get());
            assertEquals(Integer.valueOf(123456), dynamicConfigIntegerInvalid1.get());
            assertEquals(Integer.valueOf(123456), dynamicConfigIntegerInvalid2.get());
            assertEquals(Integer.valueOf(123456), dynamicConfigIntegerMissing.get());
            assertEquals(Integer.valueOf(123456), dynamicConfigIntegerFixed.get());

            assertEquals("100",          dynamicConfigLongOk.toString());
            assertEquals(Long.valueOf(100L),    dynamicConfigLongOk.get());
            assertEquals(Long.valueOf(123456L), dynamicConfigLongOverflow.get());
            assertEquals(Long.valueOf(123456L), dynamicConfigLongUnderflow.get());
            assertEquals(Long.valueOf(123456L), dynamicConfigLongTooBig.get());
            assertEquals(Long.valueOf(123456L), dynamicConfigLongInvalid1.get());
            assertEquals(Long.valueOf(123456L), dynamicConfigLongInvalid2.get());
            assertEquals(Long.valueOf(123456L), dynamicConfigLongMissing.get());
            assertEquals(Long.valueOf(123456L), dynamicConfigLongFixed.get());

            assertEquals("12.34",        dynamicConfigFloatOk2.toString());
            assertEquals(Float.valueOf(100F),   dynamicConfigFloatOk1.get());
            assertEquals(Float.valueOf(12.34F), dynamicConfigFloatOk2.get());
            assertEquals(Float.valueOf(1.23F),  dynamicConfigFloatOverflow.get());
            assertEquals(Float.valueOf(1.23F),  dynamicConfigFloatUnderflow.get());
            assertEquals(Float.valueOf(1.23F),  dynamicConfigFloatInvalid1.get());
            assertEquals(Float.valueOf(1.23F),  dynamicConfigFloatInvalid2.get());
            assertEquals(Float.valueOf(1.23F),  dynamicConfigFloatMissing.get());
            assertEquals(Float.valueOf(1.23F),  dynamicConfigFloatFixed.get());

            assertEquals("12.34",          dynamicConfigDoubleOk2.toString());
            assertEquals(Double.valueOf(100.0),   dynamicConfigDoubleOk1.get());
            assertEquals(Double.valueOf(12.34),   dynamicConfigDoubleOk2.get());
            assertEquals(Double.valueOf(123.456), dynamicConfigDoubleOverflow.get());
            assertEquals(Double.valueOf(123.456), dynamicConfigDoubleUnderflow.get());
            assertEquals(Double.valueOf(123.456), dynamicConfigDoubleInvalid1.get());
            assertEquals(Double.valueOf(123.456), dynamicConfigDoubleInvalid2.get());
            assertEquals(Double.valueOf(123.456), dynamicConfigDoubleMissing.get());
            assertEquals(Double.valueOf(123.456), dynamicConfigDoubleFixed.get());

            assertEquals("true", dynamicConfigBooleanTrueTrue.toString());
            assertEquals(Boolean.TRUE,  dynamicConfigBooleanTrueTrue.get());
            assertEquals(Boolean.TRUE,  dynamicConfigBooleanTrueYes.get());
            assertEquals(Boolean.TRUE,  dynamicConfigBooleanTrueOn.get());
            assertEquals(Boolean.FALSE, dynamicConfigBooleanTrueFalse.get());
            assertEquals(Boolean.FALSE, dynamicConfigBooleanTrueNo.get());
            assertEquals(Boolean.FALSE, dynamicConfigBooleanTrueOff.get());
            assertEquals(Boolean.TRUE,  dynamicConfigBooleanTrueInvalid.get());
            assertEquals(Boolean.TRUE,  dynamicConfigBooleanTrueMissing.get());
            assertEquals(Boolean.TRUE,  dynamicConfigBooleanTrueFixed.get());

            assertEquals(Boolean.TRUE,  dynamicConfigBooleanFalseTrue.get());
            assertEquals(Boolean.TRUE,  dynamicConfigBooleanFalseYes.get());
            assertEquals(Boolean.TRUE,  dynamicConfigBooleanFalseOn.get());
            assertEquals(Boolean.FALSE, dynamicConfigBooleanFalseFalse.get());
            assertEquals(Boolean.FALSE, dynamicConfigBooleanFalseNo.get());
            assertEquals(Boolean.FALSE, dynamicConfigBooleanFalseOff.get());
            assertEquals(Boolean.FALSE, dynamicConfigBooleanFalseInvalid.get());
            assertEquals(Boolean.FALSE, dynamicConfigBooleanFalseMissing.get());
            assertEquals(Boolean.FALSE, dynamicConfigBooleanFalseFixed.get());

            assertEquals(100_000L,    dynamicConfigDurationShort.getMilliseconds());
            assertEquals(100000_000L, dynamicConfigDurationLong.getMilliseconds());
            assertEquals(123456_000L, dynamicConfigDurationTooBig.getMilliseconds());
            assertEquals(123456_000L, dynamicConfigDurationInvalid1.getMilliseconds());
            assertEquals(123456_000L, dynamicConfigDurationInvalid2.getMilliseconds());
            assertEquals(123456_000L, dynamicConfigDurationMissing.getMilliseconds());
            assertEquals(123456_000L, dynamicConfigDurationFixed.getMilliseconds());

            assertEquals("[\"aaa\",\"111\",\"1234567890123456789\",\"12.34\",\"bbb\"]", Utils.jsonSerializeForLog(dynamicConfigCsvOk.getStringsList()));
            assertEquals("[111.0,1.23456789012345677E18,12.34]",                        Utils.jsonSerializeForLog(dynamicConfigCsvOk.getDoublesList()));
            assertEquals("[111.0,1.23456794E18,12.34]",                                 Utils.jsonSerializeForLog(dynamicConfigCsvOk.getFloatsList()));
            assertEquals("[111,1234567890123456789]",                                   Utils.jsonSerializeForLog(dynamicConfigCsvOk.getLongsList()));
            assertEquals("[111]",                                                       Utils.jsonSerializeForLog(dynamicConfigCsvOk.getIntegersList()));
            assertEquals("[\"default-value-a\",\"default-value-b\"]",                   Utils.jsonSerializeForLog(dynamicConfigCsvMissing.getStringsList()));
            assertEquals("[\"fixed-value-a\",\"fixed-value-b\"]",                       Utils.jsonSerializeForLog(dynamicConfigCsvFixed.getStringsList()));
            assertTrue(dynamicConfigCsvOk.hasItem("aaa"));
            assertFalse(dynamicConfigCsvOk.hasItem("ccc"));
            assertTrue(dynamicConfigCsvOk.hasItem(12.34));
            assertFalse(dynamicConfigCsvOk.hasItem(23.45));
            assertTrue(dynamicConfigCsvOk.hasItem(12.34f));
            assertFalse(dynamicConfigCsvOk.hasItem(23.45f));
            assertTrue(dynamicConfigCsvOk.hasItem(1234567890123456789L));
            assertFalse(dynamicConfigCsvOk.hasItem(222L));
            assertTrue(dynamicConfigCsvOk.hasItem(111));
            assertFalse(dynamicConfigCsvOk.hasItem(222));
        }

        @SuppressWarnings("unused") boolean deleted = configFile.delete();
    }

    @Test
    public void testDynamic() throws IOException, InterruptedException {

        File configFile = File.createTempFile("ConfigProviderFileTest.testDynamic", ".conf");

        writeFile(configFile, "" +
                "string-key: value-1\n" +
                "duration-key-reload: 50\n");

        // Our config-manager translates all config-values to upper-case.
        try (ConfigManager configManager = new ConfigManager("duration-key-reload", 10000000000L, TimeUnit.MILLISECONDS) {
                        @Override
                        protected String translateConfigValue(@Nonnull String configKey, @Nullable String configValue) {
                            return (configValue == null)
                                    ? null
                                    : configValue.toUpperCase();
                        }
                    }
                    .addProvider(new ConfigProviderFile())
                    .addConfigSource("prop-file://" + configFile)) {

            DynamicConfigTester dynamicConfig = new DynamicConfigTester(configManager, "string-key", "default-value");

            // Add a change-callback that always throw.
            // This shouldn't prevent the next change-callback to be called.
            DynamicConfig.ChangeCallback<String> throwingChangeCallback = (newValue, oldValue, _dynamicConfig) -> {
                throw new RuntimeException("DynamicConfigTest.testDynamic.throwingChangeCallback");
            };
            dynamicConfig.registerChangeCallback(throwingChangeCallback);

            // Add a "normal" change-callback.
            DynamicConfig.ChangeCallback<String> normalChangeCallback = (newValue, oldValue, _dynamicConfig) -> {
                assertEquals(dynamicConfig, _dynamicConfig);
                assertEquals("VALUE-1", oldValue);
                assertEquals("VALUE-2", newValue);
                dynamicChangedCount++;
            };
            dynamicConfig.registerChangeCallback(normalChangeCallback);

            assertEquals("VALUE-1",  dynamicConfig.get());

            // Make a config-change - that cause DynamicConfigTester to throw.
            writeFile(configFile, "" +
                    "string-key: THROWING_VALUE\n" +
                    "duration-key-reload: 10\n");

            long startTime = System.currentTimeMillis();
            while (! dynamicConfig.didThrow) {
                if ((System.currentTimeMillis() - startTime) > 2000) {
                    fail("No refresh for THROWING_VALUE");
                }
                Thread.sleep(1);
            }

            // Make a proper config-change.
            writeFile(configFile, "" +
                    "string-key: value-2\n" +
                    "duration-key-reload: 10\n");

            startTime = System.currentTimeMillis();
            while (! dynamicConfig.get().equals("VALUE-2")) {
                if ((System.currentTimeMillis() - startTime) > 2000) {
                    fail("No refresh for VALUE-2");
                }
                Thread.sleep(1);
            }

            // No more updates
            configManager.close();

            writeFile(configFile, "" +
                    "string-key: value-3\n" +
                    "duration-key-reload: 10\n");

            Thread.sleep(500);

            assertEquals("VALUE-2",  dynamicConfig.get());

            assertTrue(dynamicConfig.unregisterChangeCallback(normalChangeCallback));
            assertFalse(dynamicConfig.unregisterChangeCallback(normalChangeCallback));
            assertEquals(1, dynamicChangedCount);
        }

        @SuppressWarnings("unused") boolean deleted = configFile.delete();
    }

    @Test
    public void testDurationSleep() throws IOException, InterruptedException {

        File configFile = File.createTempFile("ConfigProviderFileTest.testDurationSleep", ".conf");

        writeFile(configFile, "duration: 1000000\n");

        long save = DynamicConfigDuration.SHORT_SLEEP_DURATION_MILLISECONDS;
        DynamicConfigDuration.SHORT_SLEEP_DURATION_MILLISECONDS = 0;

        try (ConfigManager configManager = new ConfigManager()
                .addProvider(new ConfigProviderFile())
                .addConfigSource("prop-file://" + configFile)) {
            DynamicConfigDuration dynamicConfig = new DynamicConfigDuration(configManager, "duration", 1000000000, TimeUnit.MILLISECONDS);

            Thread updater = new Thread(() -> {
                try {
                    Thread.sleep(200);
                    writeFile(configFile, "duration: 300\n");
                    configManager.reloadAllConfigs();
                } catch (Exception ignore) {
                }
            });
            updater.setName("DynamicConfigTest.testDurationSleep");
            updater.setDaemon(true);
            updater.start();

            durationSleep(dynamicConfig, 300, 1000, null);

            // Change config file - but close dynamicConfig so it can't change.
            dynamicConfig.close();
            writeFile(configFile, "duration: 1000000\n");
            configManager.reloadAllConfigs();

            durationSleep(dynamicConfig, 300, 1000, null);

            // Test translateSleepTime.
            durationSleep(dynamicConfig, 0, 250, sleepMilliseconds -> 50L);

            // Test short sleep durations.
            DynamicConfigDuration.SHORT_SLEEP_DURATION_MILLISECONDS = 1000;
            durationSleep(dynamicConfig, 300, 1000, null);

        } finally {
            DynamicConfigDuration.SHORT_SLEEP_DURATION_MILLISECONDS = save;
        }

        @SuppressWarnings("unused") boolean deleted = configFile.delete();
    }

    /** Just like {@link DynamicConfigString} - only throw when value is "THROWING_VALUE" */
    private static class DynamicConfigTester extends DynamicConfigString {

        final static String THROWING_VALUE = "THROWING_VALUE";

        boolean didThrow = false;

        public DynamicConfigTester(ConfigManager configManager, String configKey, @Nullable String defaultValue) {
            super(configManager, configKey, defaultValue);
        }

        @Override
        protected @Nullable String convertValue(@Nullable String stringValue) {
            if (THROWING_VALUE.equals(stringValue)) {
                didThrow = true;
                throw new RuntimeException("DynamicConfigTest.DynamicConfigTester.convertValue(THROWING_VALUE)");
            }
            return super.convertValue(stringValue);
        }
    }

    private void durationSleep(DynamicConfigDuration dynamicConfig, long minSleep, long maxSleep, @Nullable Function<Long, Long> translateSleepTime) throws InterruptedException {
        long startTime = System.currentTimeMillis();
        if (translateSleepTime == null) {
            dynamicConfig.sleep();
        } else {
            dynamicConfig.sleep(translateSleepTime);
        }
        long sleptTime = System.currentTimeMillis() - startTime;

        assertTrue(sleptTime >= minSleep, "Slept too little: " + sleptTime);
        assertTrue(sleptTime <= maxSleep, "Slept too much: " + sleptTime);
    }

    private void writeFile(File file, String text) throws FileNotFoundException {
        try (PrintWriter out = new PrintWriter(file)) {
            out.print(text);
        }
    }

    private int dynamicChangedCount = 0;
}