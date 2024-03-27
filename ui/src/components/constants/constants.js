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

export const MODAL_TIME_OUT = 2000;
export const GROUP_NAME_REGEX =
    '([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*';
export const GROUP_MEMBER_NAME_REGEX =
    '([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*';
export const MICROSEGMENTATION_SERVICE_NAME_REGEX =
    '\\*|([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*';
export const GROUP_ROLES_CATEGORY = 'group-roles';
export const USER_DOMAIN = process.env.NEXT_PUBLIC_USER_DOMAIN || 'user';
export const GROUP_MEMBER_PLACEHOLDER = `${USER_DOMAIN}.<userid> or <domain>.<service>`;
export const DISPLAY_SPACE = '\u23b5';

export const SERVICE_TYPE_DYNAMIC = 'dynamic';
export const SERVICE_TYPE_STATIC = 'static';
export const SERVICE_TYPE_MICROSEGMENTATION = 'microsegmentation';
export const SERVICE_TYPE_MICROSEGMENTATION_LABEL = 'Microsegmentation';
export const SERVICE_TYPE_DYNAMIC_LABEL = 'Dynamic Instances';
export const SERVICE_TYPE_STATIC_LABEL = 'Static Instances';
export const SEGMENTATION_TYPE_OUTBOUND = 'outbound';
export const SEGMENTATION_TYPE_INBOUND = 'inbound';
export const SEGMENTATION_TYPE_OUTBOUND_LABEL = 'Outbound';
export const SEGMENTATION_TYPE_INBOUND_LABEL = 'Inbound';
export const TOTAL_DYNAMIC_INSTANCES_DESC =
    'List of all dynamic instances(Both Active and Dormant).';
export const TOTAL_STATIC_INSTANCES_DESC = 'List of all static instances.';
export const TOTAL_HEALTHY_DYNAMIC_INSTANCES_LABEL =
    'Total Healthy Dynamic Instances';
export const TOTAL_STATIC_INSTANCES_LABEL = 'Total Static Instances';
export const TOTAL_HEALTHY_DYNAMIC_INSTANCES_DESC =
    'List of only active dynamic instances(i.e. instances refreshed certs within last 7 days).';
export const TOTAL_DYNAMIC_INSTANCES_LABEL = 'Total Dynamic Instances';
export const SERVICE_NAME_LABEL = 'Service Name';
export const SOURCE_NAME_LABEL = 'SOURCE NAME';
export const DESTINATION_NAME_LABEL = 'DESTINATION NAME';
export const PRINCIPAL_REQUESTING_ACCESS = 'PRINCIPAL REQUESTING ACCESS';
export const DESTINATION_DOMAIN_LABEL = 'DESTINATION DOMAIN';
export const DOMAIN_NAME_LABEL = 'DOMAIN NAME';
export const IDENTIFIER_LABEL = 'Identifier';
export const PROTOCOL_LABEL = 'Protocol';
export const DESTINATION_PORTS_LABEL = 'DESTINATION PORT(S)';
export const SOURCE_PORTS_LABEL = 'SOURCE PORT(S)';

export const SERVICE_TABS = [
    {
        label: SERVICE_TYPE_STATIC_LABEL,
        name: SERVICE_TYPE_STATIC,
    },
    {
        label: SERVICE_TYPE_DYNAMIC_LABEL,
        name: SERVICE_TYPE_DYNAMIC,
    },
    {
        label: 'Tags',
        name: 'tags',
    },
    {
        label: SERVICE_TYPE_MICROSEGMENTATION_LABEL,
        name: SERVICE_TYPE_MICROSEGMENTATION,
    },
];

export const SEGMENTATION_CATEGORIES = [
    {
        label: SEGMENTATION_TYPE_INBOUND_LABEL,
        name: SEGMENTATION_TYPE_INBOUND,
    },
    {
        label: SEGMENTATION_TYPE_OUTBOUND_LABEL,
        name: SEGMENTATION_TYPE_OUTBOUND,
    },
];

export const SEGMENTATION_PROTOCOL_TYPE_TCP = 'TCP';
export const SEGMENTATION_PROTOCOL_TYPE_UDP = 'UDP';
export const SEGMENTATION_PROTOCOL_TYPE_ICMP = 'ICMP';
export const SEGMENTATION_PROTOCOL_TYPE_ICMPV6 = 'ICMPV6';
export const SEGMENTATION_PROTOCOL_TYPE_AH = 'AH';
export const SEGMENTATION_PROTOCOL_TYPE_ESP = 'ESP';
export const SEGMENTATION_PROTOCOL_TYPE_GRE = 'GRE';
export const SEGMENTATION_PROTOCOL_TYPE_IPV6_FRAGMENT = 'IPv6 Fragment';

export const SEGMENTATION_PROTOCOL = [
    {
        name: SEGMENTATION_PROTOCOL_TYPE_TCP,
        value: SEGMENTATION_PROTOCOL_TYPE_TCP,
    },
    {
        name: SEGMENTATION_PROTOCOL_TYPE_UDP,
        value: SEGMENTATION_PROTOCOL_TYPE_UDP,
    },
];

export const DELETE_AUDIT_REFERENCE = 'deleted using Athenz UI';

// VIP -> VIP name -> FQDN (represents a virtual ip construct)
// ENTERPRISE_APPLIANCE -> pes short id -> random string only contains characters, numbers, _ and : (represents generic network devices which can not be bootstrapped with an identity due to limitations)
// CLOUD_LB -> FQDN (represents a public cloud load balancer)
// CLOUD_NAT -> IP or CIDR (represents a public cloud NAT gateway)
// EXTERNAL_APPLIANCE -> IP or CIDR (Appliance present outside of enterprise deployment locations. For SaaS / Third Party / Vendor use cases)
// CLOUD_MANAGED -> FQDN (represents a cloud managed service or endpoint)
// SERVICE_SUBNET -> IPV4 RFC1918 CIDR (represents subnet for a given service, would be almost always a RFC1918 CIDR)
// NOTE: all IP/CIDR values are for IPv4 only currently since adding IPv6 support would require a much longer regex, which is bad for maintainability
export const StaticWorkloadType = [
    {
        name: 'VIP',
        value: 'VIP',
        pattern: '([a-zA-Z0-9][a-zA-Z0-9-]*\\.)*[a-zA-Z0-9][a-zA-Z0-9-]*',
    },
    {
        name: 'Enterprise Appliance',
        value: 'ENTERPRISE_APPLIANCE',
        pattern: '[A-Za-z_0-9:]+',
    },
    {
        name: 'Cloud Load Balancer',
        value: 'CLOUD_LB',
        pattern: '([a-zA-Z0-9][a-zA-Z0-9-]*\\.)*[a-zA-Z0-9][a-zA-Z0-9-]*',
    },
    {
        name: 'Cloud NAT Gateway',
        value: 'CLOUD_NAT',
        pattern:
            '^(?=.*[^.]$)((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).?){4}(\\/([0-9]|[12][0-9]|3[012]))?$',
    },
    {
        name: 'External Appliance',
        value: 'EXTERNAL_APPLIANCE',
        pattern:
            '^(?=.*[^.]$)((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).?){4}(\\/([0-9]|[12][0-9]|3[012]))?$',
    },
    {
        name: 'Cloud Managed',
        value: 'CLOUD_MANAGED',
        pattern: '([a-zA-Z0-9][a-zA-Z0-9-]*\\.)*[a-zA-Z0-9][a-zA-Z0-9-]*',
    },
    {
        name: 'Service Subnet',
        value: 'SERVICE_SUBNET',
        pattern:
            '^(10(\\.(([0-9]?[0-9])|(1[0-9]?[0-9])|(2[0-4]?[0-9])|(25[0-5]))){3}/([8-9]|(1[0-9])|(2[0-9])|(3[0-1])))|(172\\.((1[6-9])|(2[0-9])|(3[0-1]))(\\.(([0-9]?[0-9])|(1[0-9]?[0-9])|(2[0-4]?[0-9])|(25[0-5]))){2}/((1[2-9])|(2[0-9])|(3[0-1])))|(192\\.168(\\.(([0-9]?[0-9])|(1[0-9]?[0-9])|(2[0-4]?[0-9])|(25[0-5]))){2}/((1[6-9])|(2[0-9])|(3[0-1])))|(127(\\.(([0-9]?[0-9])|(1[0-9]?[0-9])|(2[0-4]?[0-9])|(25[0-5]))){3}/([8-9]|(1[0-9])|(2[0-9])|(3[0-1])))$',
    },
];

export const ADD_GROUP_AUDIT_ENABLED_TOOLTIP =
    'Audit Enabled Group must not contain members during creation';
export const ADD_ROLE_AUDIT_ENABLED_TOOLTIP =
    'Audit Enabled Role must not contain members during creation';
export const ADD_ROLE_REVIEW_ENABLED_TOOLTIP =
    'Review Enabled Role must not contain members during creation';
export const ADD_ROLE_AUDIT_DESC =
    'Flag indicates whether or not role updates require explicit auditing approval process';
export const ADD_ROLE_REVIEW_DESC =
    'Flag indicates whether or not role updates require another review and approval';
export const ADD_ROLE_SELF_SERVICE_DESC =
    'Flag indicates whether or not role allows self service';
export const ADD_ROLE_SELF_RENEW_DESC =
    'Flag indicates whether or not role allows self renew';
export const SELF_RENEW_MINS_DESC =
    'Number of minutes members can renew their membership if self review option is enabled';
export const ADD_ROLE_MAX_MEMBERS_DESC =
    'Maximum number of members allowed in the role';
export const ADD_ROLE_MEMBER_EXPIRY_DAYS_DESC =
    'All user members in the role will have specified max expiry days';
export const ADD_ROLE_MEMBER_REVIEW_DAYS_DESC =
    'All user members in the role will have specified review days';
export const ADD_ROLE_GROUP_EXPIRY_DAYS_DESC =
    'All group members in the role will have specified max expiry days';
export const ADD_ROLE_GROUP_REVIEW_DAYS_DESC =
    'All groups in the role will have specified max review days';
export const ADD_ROLE_SERVICE_EXPIRY_DAYS_DESC =
    'All services in the role will have specified max expiry days';
export const ADD_ROLE_SERVICE_REVIEW_DAYS_DESC =
    'All service members in the role will have specified review days';
export const ADD_ROLE_TOKEN_MAX_TIMEOUT_MINS_DESC =
    'Tokens issued for this role will have specified max timeout in mins';
export const ADD_ROLE_CERT_MAX_TIMEOUT_MINS_DESC =
    'Certs issued for this role will have specified max timeout in mins';
export const ADD_ROLE_AUTHORITY_FILTER_DESC =
    'membership filtered based on user authority configured attributes';
export const ADD_ROLE_AUTHORITY_EXPIRY_DESC =
    'expiration enforced by a user authority configured attribute';
export const ADD_ROLE_JUSTIFICATION_PLACEHOLDER = 'Enter justification here';
export const ADD_ROLE_AUTHORITY_FILTER_PLACEHOLDER = 'User Authority Filter';
export const ADD_ROLE_AUTHORITY_EXPIRY_PLACEHOLDER =
    'User Authority Expiration';
export const ADD_ROLE_AUTHORITY_ROLE_NAME_PLACEHOLDER = 'Enter New Role Name';
export const ADD_ROLE_MEMBER_PLACEHOLDER = `${USER_DOMAIN}.<userid> or <domain>.<service> or <domain>:group.<group>`;
export const ADD_ROLE_EXPIRATION_PLACEHOLDER = 'Expiration (Optional)';
export const ADD_ROLE_REMINDER_PLACEHOLDER = 'Reminder (Optional)';
export const ADD_ROLE_DESCRIPTION = 'Description (Optional)';
export const ADD_ROLE_DELEGATED_DOMAIN_PLACEHOLDER =
    'Enter Domain for Delegate Role';
export const MICROSEG_CONDITION_DELETE_JUSTIFICATION =
    'Microsegmentation Assertion Condition deletion';
export const MICROSEG_TRANSPORT_RULE_DELETE_JUSTIFICATION =
    'Microsegmentation Transport Rule deletion';
export const WORKFLOW_PENDING_MEMBERS_APPROVAL_ADMIN_VIEW_TAB =
    'Pending Members Approval (Admin View)';
export const WORKFLOW_PENDING_MEMBERS_APPROVAL_DOMAIN_VIEW_TAB =
    'Pending Members Approval (Domain View)';
export const WORKFLOW_DOMAIN_VIEW_TAB = 'Domain Member Approval';
export const WORKFLOW_ROLE_REVIEW = 'Role Review';
export const WORKFLOW_GROUP_REVIEW = 'Group Review';
export const WORKFLOW_TITLE = 'Action Required';
export const WORKFLOW_DOMAIN_VIEW_DROPDOWN_PLACEHOLDER =
    'Select a Domain to View Pending Members';
export const VIEW_PENDING_MEMBERS_BY_DOMAIN_TITLE =
    'View Pending Members by Domain';
export const ADD_ROLE_DELETE_PROTECTION_DESC =
    'Flag indicates whether or not the role will be protected from accidental deletions';
export const ADD_GROUP_DELETE_PROTECTION_DESC =
    'Flag indicates whether or not the group will be protected from accidental deletions';
export const WORKFLOW_TABS = [
    {
        label: WORKFLOW_PENDING_MEMBERS_APPROVAL_ADMIN_VIEW_TAB,
        name: 'admin',
    },
    {
        label: WORKFLOW_PENDING_MEMBERS_APPROVAL_DOMAIN_VIEW_TAB,
        name: 'domain',
    },
    {
        label: WORKFLOW_ROLE_REVIEW,
        name: 'roleReview',
    },
    {
        label: WORKFLOW_GROUP_REVIEW,
        name: 'groupReview',
    },
];

export const DATE_BEFORE_CURRENT_TIME_ERROR_MESSAGE =
    'Expiry/Review date selected cannot be before current date.';

export const PENDING_APPROVAL_TYPE_ENUM = Object.freeze({
    EXPIRY: 'expiry',
    REVIEW: 'review',
});
export const PENDING_APPROVAL_KEY_ENUM = Object.freeze({
    SELECTALL: 'SelectAll',
});
export const EDITABLE_DATE_ENUM = Object.freeze({
    EXPIRATION: 'Expiration',
    REMINDER: 'Reminder',
});
export const PENDING_STATE_ENUM = Object.freeze({
    ADD: 'ADD',
    DELETE: 'DELETE',
});
export const REVIEW_CARDS_SIZE = 5;

export const ENVIRONMENT_DROPDOWN_OPTIONS = [
    { value: 'production', name: 'PRODUCTION' },
    { value: 'integration', name: 'INTEGRATION' },
    { value: 'staging', name: 'STAGING' },
    { value: 'sandbox', name: 'SANDBOX' },
    { value: 'qa', name: 'QA' },
    { value: 'development', name: 'DEVELOPMENT' },
];
