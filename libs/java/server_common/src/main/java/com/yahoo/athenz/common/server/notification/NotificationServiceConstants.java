package com.yahoo.athenz.common.server.notification;

public final class NotificationServiceConstants {
    public static final String PROP_NOTIFICATION_EMAIL_PROVIDER                = "athenz.notification.email_provider";
    public static final String NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL           = "MEMBERSHIP_APPROVAL";
    public static final String NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL_REMINDER  = "MEMBERSHIP_APPROVAL_REMINDER";
    public static final String NOTIFICATION_TYPE_PRINCIPAL_EXPIRY_REMINDER     = "PRINCIPAL_EXPIRY_REMINDER";
    public static final String NOTIFICATION_TYPE_DOMAIN_MEMBER_EXPIRY_REMINDER = "DOMAIN_MEMBER_EXPIRY_REMINDER";

    public static final String NOTIFICATION_DETAILS_DOMAIN         = "domain";
    public static final String NOTIFICATION_DETAILS_ROLE           = "role";
    public static final String NOTIFICATION_DETAILS_MEMBER         = "member";
    public static final String NOTIFICATION_DETAILS_REASON         = "reason";
    public static final String NOTIFICATION_DETAILS_REQUESTER      = "requester";
    public static final String NOTIFICATION_DETAILS_EXPIRY_ROLES   = "expiryRoles";
    public static final String NOTIFICATION_DETAILS_EXPIRY_MEMBERS = "expiryMembers";

    public static final String HTML_LOGO_CID_PLACEHOLDER = "<logo>";
    public static final String CHARSET_UTF_8 = "UTF-8";

    private NotificationServiceConstants() {
    }
}
