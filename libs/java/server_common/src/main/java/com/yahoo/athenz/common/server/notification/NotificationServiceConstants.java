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

package com.yahoo.athenz.common.server.notification;

public final class NotificationServiceConstants {
    public static final String NOTIFICATION_PROP_SERVICE_FACTORY_CLASS = "athenz.zms.notification_service_factory_class";

    public static final String NOTIFICATION_DETAILS_DOMAIN              = "domain";
    public static final String NOTIFICATION_DETAILS_ROLE                = "role";
    public static final String NOTIFICATION_DETAILS_GROUP               = "group";
    public static final String NOTIFICATION_DETAILS_MEMBER              = "member";
    public static final String NOTIFICATION_DETAILS_REASON              = "reason";
    public static final String NOTIFICATION_DETAILS_REQUESTER           = "requester";
    public static final String NOTIFICATION_DETAILS_ROLES_LIST          = "rolesList";
    public static final String NOTIFICATION_DETAILS_MEMBERS_LIST        = "membersList";
    public static final String NOTIFICATION_DETAILS_UNREFRESHED_CERTS   = "unrefreshedCerts";
    public static final String NOTIFICATION_DETAILS_AWS_ZTS_HEALTH      = "awsZtsHealth";
    public static final String NOTIFICATION_DETAILS_AFFECTED_ZTS        = "affectedZts";

    public static final String HTML_LOGO_CID_PLACEHOLDER = "<logo>";
    public static final String CHARSET_UTF_8 = "UTF-8";

    private NotificationServiceConstants() {
    }
}
