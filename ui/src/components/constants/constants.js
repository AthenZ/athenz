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

export const MODAL_TIME_OUT = 2000;
export const GROUP_NAME_REGEX =
    '([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*';
export const GROUP_MEMBER_NAME_REGEX =
    '([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*';
export const MICROSEGMENTATION_SERVICE_NAME_REGEX =
    '\\*|([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*';
export const GROUP_ROLES_CATEGORY = 'group-roles';
export const GROUP_MEMBER_PLACEHOLDER = 'user.<userid> or <domain>.<service>';
export const DISPLAY_SPACE = '\u23b5';

export const SERVICE_TYPE_DYNAMIC = 'dynamic';
export const SERVICE_TYPE_STATIC = 'static';
export const SERVICE_TYPE_DYNAMIC_LABEL = 'Dynamic';
export const SERVICE_TYPE_STATIC_LABEL = 'Static';
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
        pattern: '([a-zA-Z0-9][a-zA-Z0-9-]*\\.)*[a-zA-Z0-9][a-zA-Z0-9-]*',
    },
    {
        name: 'External Appliance',
        value: 'EXTERNAL_APPLIANCE',
        pattern: '^(?=.*[^.]$)((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).?){4}$',
    },
];

export const ADD_ROLE_REVIEW_ENABLED_TOOLTIP =
    'Review Enabled Role must not contain members during creation';
export const ADD_ROLE_REVIEW_DESC =
    'Flag indicates whether or not role updates require another review and approval';
export const ADD_ROLE_SELF_SERVICE_DESC =
    'Flag indicates whether or not role allows self service';
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
export const ADD_ROLE_MEMBER_PLACEHOLDER =
    'user.<userid> or <domain>.<service> or <domain>:group.<group>';
export const ADD_ROLE_REMINDER_PLACEHOLDER = 'Reminder (Optional)';
export const ADD_ROLE_DELEGATED_DOMAIN_PLACEHOLDER =
    'Enter Domain for Delegate Role';
export const MICROSEG_CONDITION_DELETE_JUSTIFICATION =
    'Microsegmentation Assertion Condition deletion';
export const MICROSEG_TRANSPORT_RULE_DELETE_JUSTIFICATION =
    'Microsegmentation Transport Rule deletion';
export const WORKFLOW_ADMIN_VIEW_TAB = 'Admin View';
export const WORKFLOW_DOMAIN_VIEW_TAB = 'Domain View';
export const WORKFLOW_DOMAIN_VIEW_DROPDOWN_PLACEHOLDER =
    'Select a Domain to View Pending Members';
export const VIEW_PENDING_MEMBERS_BY_DOMAIN_TITLE =
    'View Pending Members by Domain';
export const WORKFLOW_TABS = [
    {
        label: WORKFLOW_ADMIN_VIEW_TAB,
        name: 'admin',
    },
    {
        label: WORKFLOW_DOMAIN_VIEW_TAB,
        name: 'domain',
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
