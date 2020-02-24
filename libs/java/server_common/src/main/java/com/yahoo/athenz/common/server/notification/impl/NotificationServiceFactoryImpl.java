/*
 * Copyright 2019 Oath Holdings Inc.
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

package com.yahoo.athenz.common.server.notification.impl;

import com.yahoo.athenz.common.server.notification.NotificationService;
import com.yahoo.athenz.common.server.notification.NotificationServiceFactory;

/*
 * This is a reference implementation.
 */
public class NotificationServiceFactoryImpl implements NotificationServiceFactory {

    @Override
    public NotificationService create() {
        return new EmailNotificationService(new AWSEmailProvider());
    }
}
