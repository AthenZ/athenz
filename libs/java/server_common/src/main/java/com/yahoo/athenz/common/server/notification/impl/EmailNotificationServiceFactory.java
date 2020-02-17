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

import com.mysql.cj.util.StringUtils;
import com.yahoo.athenz.common.server.notification.EmailProvider;
import com.yahoo.athenz.common.server.notification.NotificationService;
import com.yahoo.athenz.common.server.notification.NotificationServiceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/*
 * This is a reference implementation.
 */
public class EmailNotificationServiceFactory implements NotificationServiceFactory {
    private static final Logger LOGGER = LoggerFactory.getLogger(EmailNotificationServiceFactory.class);

    @Override
    public NotificationService create(String providerName) {
        if (StringUtils.isNullOrEmpty(providerName)) {
            LOGGER.warn("Missing providerName. Failed to instantiate NotificationService");
            return null;
        }

        EmailProvider provider = null;
        switch (providerName) {
            case "AWS":
                provider = new AWSEmailProvider();
                break;
            case "Sonic":
                provider = new SonicEmailProvider();
                break;
            default:
                LOGGER.warn("Unknown Email Provider: " + providerName + ". Failed to instantiate NotificationService");
                return null;
        }

        return new EmailNotificationService(provider);
    }
}
