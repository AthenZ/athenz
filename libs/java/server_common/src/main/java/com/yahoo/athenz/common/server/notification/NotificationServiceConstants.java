/*
 * Copyright 2020 Verizon Media
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

    public static final String NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL           = "MEMBERSHIP_APPROVAL";
    public static final String NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL_REMINDER  = "MEMBERSHIP_APPROVAL_REMINDER";
    public static final String NOTIFICATION_TYPE_PRINCIPAL_EXPIRY_REMINDER     = "PRINCIPAL_EXPIRY_REMINDER";
    public static final String NOTIFICATION_TYPE_DOMAIN_MEMBER_EXPIRY_REMINDER = "DOMAIN_MEMBER_EXPIRY_REMINDER";
    public static final String NOTIFICATION_TYPE_UNREFRESHED_CERTS             = "UNREFRESHED_CERTS";
    public static final String NOTIFICATION_TYPE_PRINCIPAL_REVIEW_REMINDER     = "PRINCIPAL_REVIEW_REMINDER";
    public static final String NOTIFICATION_TYPE_DOMAIN_MEMBER_REVIEW_REMINDER = "DOMAIN_MEMBER_REVIEW_REMINDER";

    public static final String NOTIFICATION_DETAILS_DOMAIN              = "domain";
    public static final String NOTIFICATION_DETAILS_ROLE                = "role";
    public static final String NOTIFICATION_DETAILS_MEMBER              = "member";
    public static final String NOTIFICATION_DETAILS_REASON              = "reason";
    public static final String NOTIFICATION_DETAILS_REQUESTER           = "requester";
    public static final String NOTIFICATION_DETAILS_EXPIRY_ROLES        = "expiryRoles";
    public static final String NOTIFICATION_DETAILS_EXPIRY_MEMBERS      = "expiryMembers";
    public static final String NOTIFICATION_DETAILS_UNREFRESHED_CERTS   = "unrefreshedCerts";

    public static final String HTML_LOGO_CID_PLACEHOLDER = "<logo>";
    public static final String CHARSET_UTF_8 = "UTF-8";

    private NotificationServiceConstants() {
    }
}
