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

package com.yahoo.athenz.common.server.notification;

public interface NotificationService {

    String NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL           = "MEMBERSHIP_APPROVAL";
    String NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL_REMINDER  = "MEMBERSHIP_APPROVAL_REMINDER";
    String NOTIFICATION_TYPE_PRINCIPAL_EXPIRY_REMINDER     = "PRINCIPAL_EXPIRY_REMINDER";
    String NOTIFICATION_TYPE_DOMAIN_MEMBER_EXPIRY_REMINDER = "DOMAIN_MEMBER_EXPIRY_REMINDER";

    String NOTIFICATION_DETAILS_DOMAIN         = "domain";
    String NOTIFICATION_DETAILS_ROLE           = "role";
    String NOTIFICATION_DETAILS_MEMBER         = "member";
    String NOTIFICATION_DETAILS_REASON         = "reason";
    String NOTIFICATION_DETAILS_REQUESTER      = "requester";
    String NOTIFICATION_DETAILS_EXPIRY_ROLES   = "expiryRoles";
    String NOTIFICATION_DETAILS_EXPIRY_MEMBERS = "expiryMembers";

    /**
     * send out the notification
     * @param notification - notification to be sent containing notification type, recipients and additional details
     * @return status of sent notification
     */
    boolean notify (Notification notification);
}
