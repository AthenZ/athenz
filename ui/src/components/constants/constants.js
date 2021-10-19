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
