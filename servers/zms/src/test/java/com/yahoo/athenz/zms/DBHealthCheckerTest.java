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
package com.yahoo.athenz.zms;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Collections;

import static org.testng.Assert.*;

public class DBHealthCheckerTest {

    @Mock private DBService dbService;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        System.setProperty(ZMSConsts.ZMS_PROP_DB_HEALTH_CHECK_DISABLE_TIMER, "true");
    }

    @AfterMethod
    public void tearDown() {
        System.clearProperty(ZMSConsts.ZMS_PROP_DB_HEALTH_CHECK_DISABLE_TIMER);
        System.clearProperty(ZMSConsts.ZMS_PROP_DB_HEALTH_CHECK_FREQUENCY_SECONDS);
    }

    @Test
    public void testDomainsAvailable() {

        Mockito.when(dbService.listDomains("sys.auth", 0, false))
                .thenReturn(Collections.singletonList("sys.auth"));

        DBHealthChecker checker = new DBHealthChecker(dbService);
        assertTrue(checker.isDomainsAvailable());

        checker.shutdown();
    }

    @Test
    public void testDomainsNotAvailableEmptyList() {

        Mockito.when(dbService.listDomains("sys.auth", 0, false))
                .thenReturn(Collections.emptyList());

        DBHealthChecker checker = new DBHealthChecker(dbService);
        assertFalse(checker.isDomainsAvailable());

        checker.shutdown();
    }

    @Test
    public void testDomainsNotAvailableDbException() {

        Mockito.when(dbService.listDomains("sys.auth", 0, false))
                .thenThrow(new ResourceException(500, "DB Error"));

        DBHealthChecker checker = new DBHealthChecker(dbService);
        assertFalse(checker.isDomainsAvailable());

        checker.shutdown();
    }

    @Test
    public void testCheckDomainsAvailabilityStateTransition() {

        Mockito.when(dbService.listDomains("sys.auth", 0, false))
                .thenReturn(Collections.singletonList("sys.auth"))
                .thenReturn(Collections.emptyList())
                .thenReturn(Collections.singletonList("sys.auth"));

        DBHealthChecker checker = new DBHealthChecker(dbService);
        assertTrue(checker.isDomainsAvailable());

        // second check returns empty list - flag should turn false

        checker.checkDomainsAvailability();
        assertFalse(checker.isDomainsAvailable());

        // third check returns a domain again - flag should turn true

        checker.checkDomainsAvailability();
        assertTrue(checker.isDomainsAvailable());

        checker.shutdown();
    }

    @Test
    public void testTimerTaskEnabled() {

        // enable the timer task with a short frequency to exercise the init path

        System.clearProperty(ZMSConsts.ZMS_PROP_DB_HEALTH_CHECK_DISABLE_TIMER);
        System.setProperty(ZMSConsts.ZMS_PROP_DB_HEALTH_CHECK_FREQUENCY_SECONDS, "1");

        Mockito.when(dbService.listDomains("sys.auth", 0, false))
                .thenReturn(Collections.singletonList("sys.auth"));

        DBHealthChecker checker = new DBHealthChecker(dbService);
        assertTrue(checker.isDomainsAvailable());

        checker.shutdown();
    }

    @Test
    public void testShutdownWithoutTimer() {

        Mockito.when(dbService.listDomains("sys.auth", 0, false))
                .thenReturn(Collections.singletonList("sys.auth"));

        DBHealthChecker checker = new DBHealthChecker(dbService);

        // shutdown should be a no-op when the scheduler was never started
        // and safe to call multiple times

        checker.shutdown();
        checker.shutdown();
    }
}
