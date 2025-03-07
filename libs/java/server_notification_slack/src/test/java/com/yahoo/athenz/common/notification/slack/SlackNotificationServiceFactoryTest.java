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

package com.yahoo.athenz.common.notification.slack;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.notification.NotificationService;
import org.testng.annotations.Test;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class SlackNotificationServiceFactoryTest {
    @Test
    public void testCreate() {
        SlackNotificationServiceFactory factory = new SlackNotificationServiceFactory();
        PrivateKeyStore mockPrivateKeyStore = mock(PrivateKeyStore.class);
        when(mockPrivateKeyStore.getSecret(anyString(), anyString(), anyString())).thenReturn("secret".toCharArray());
        NotificationService svc = factory.create(mockPrivateKeyStore);

        assertNotNull(svc);
        assertTrue(svc instanceof SlackNotificationService);
    }
}
