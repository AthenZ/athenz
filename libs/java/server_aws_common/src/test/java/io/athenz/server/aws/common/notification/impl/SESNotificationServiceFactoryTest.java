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

package io.athenz.server.aws.common.notification.impl;

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.notification.NotificationService;
import com.yahoo.athenz.common.server.notification.NotificationServiceFactory;
import com.yahoo.athenz.common.server.notification.impl.EmailNotificationService;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class SESNotificationServiceFactoryTest {

    @Test
    public void testCreate() throws ServerResourceException {
        NotificationServiceFactory factory = new SESNotificationServiceFactory();
        NotificationService svc = factory.create(null);

        assertNotNull(svc);
        assertTrue(svc instanceof EmailNotificationService);
    }
}