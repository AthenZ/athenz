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
import { apiAssertionConditions, modified } from '../../config/config.test';

describe('Policy Config', () => {
    it('should get default config', () => {
        expect(singleApiPolicy).not.toBeNull();
    });
});

export const singleApiPolicy = {
    name: 'dom:policy.singlePolicy',
    modified: modified,
    assertions: [
        {
            role: 'dom:role.singleRole',
            resource: 'dom:*',
            action: '*',
            effect: 'ALLOW',
            id: 17409,
        },
    ],
    version: '0',
    active: true,
};

export const apiPolicies = [
    {
        name: 'dom:policy.admin',
        modified: modified,
        assertions: [
            {
                role: 'dom:role.admin',
                resource: 'dom:*',
                action: '*',
                effect: 'ALLOW',
                id: 17100,
            },
        ],
        version: '0',
        active: true,
    },
    {
        name: 'dom:policy.acl.ows.inbound',
        modified: modified,
        assertions: [
            {
                role: 'dom:role.acl.ows.inbound-test1',
                resource: 'dom:ows',
                action: 'TCP-IN:1024-65535:4443-4443',
                effect: 'ALLOW',
                id: 34567,
                conditions: apiAssertionConditions,
            },
            {
                role: 'dom:role.role1',
                resource: 'dom:test',
                action: '*',
                effect: 'ALLOW',
                id: 98765,
            },
        ],
        version: '0',
        active: true,
    },
    {
        name: 'dom:policy.acl.ows.outbound',
        modified: modified,
        tags: {
            tag: {
                list: ['tag1'],
            },
            tag2: {
                list: ['tag3'],
            },
        },
        assertions: [
            {
                role: 'dom:role.acl.ows.outbound-test2',
                resource: 'dom:ows',
                action: 'TCP-OUT:1024-65535:4443-4443',
                effect: 'ALLOW',
                id: 76543,
                conditions: apiAssertionConditions,
            },
        ],
        version: '0',
        active: true,
    },
    {
        name: 'dom:policy.policy1',
        modified: modified,
        assertions: [
            {
                role: 'dom:role.role1',
                resource: 'dom:test',
                action: '*',
                effect: 'ALLOW',
                id: 17326,
            },
        ],
        version: '1',
        active: true,
    },
    {
        name: 'dom:policy.policy1',
        modified: modified,
        tags: { tag: { list: ['tag1', 'tag2'] }, tag2: { list: ['tag3'] } },
        assertions: [
            {
                role: 'dom:role.role2',
                resource: 'dom:test2',
                action: '*',
                effect: 'DENY',
                id: 17379,
            },
        ],
        version: '2',
        active: false,
    },
    {
        name: 'dom:policy.policy2',
        modified: modified,
        assertions: [
            {
                role: 'dom:role.role3',
                resource: 'dom:testing',
                action: '*',
                effect: 'DENY',
                id: 17380,
            },
            {
                role: 'dom:role.role4',
                resource: 'dom:resource2',
                action: '*',
                effect: 'DENY',
                id: 17390,
            },
        ],
        version: '0',
        active: false,
    },
];

export const configStorePolicies = {
    'dom:policy.admin:0': {
        name: 'dom:policy.admin',
        modified: modified,
        assertions: {
            17100: {
                role: 'dom:role.admin',
                resource: 'dom:*',
                action: '*',
                effect: 'ALLOW',
                id: 17100,
            },
        },
        version: '0',
        active: true,
    },
    'dom:policy.acl.ows.inbound:0': {
        name: 'dom:policy.acl.ows.inbound',
        modified: modified,
        assertions: {
            34567: {
                role: 'dom:role.acl.ows.inbound-test1',
                resource: 'dom:ows',
                action: 'TCP-IN:1024-65535:4443-4443',
                effect: 'ALLOW',
                id: 34567,
                conditions: apiAssertionConditions,
            },
            98765: {
                role: 'dom:role.role1',
                resource: 'dom:test',
                action: '*',
                effect: 'ALLOW',
                id: 98765,
            },
        },
        version: '0',
        active: true,
    },
    'dom:policy.acl.ows.outbound:0': {
        name: 'dom:policy.acl.ows.outbound',
        tags: { tag: { list: ['tag1'] }, tag2: { list: ['tag3'] } },
        modified: modified,
        assertions: {
            76543: {
                role: 'dom:role.acl.ows.outbound-test2',
                resource: 'dom:ows',
                action: 'TCP-OUT:1024-65535:4443-4443',
                effect: 'ALLOW',
                id: 76543,
                conditions: apiAssertionConditions,
            },
        },
        version: '0',
        active: true,
    },
    'dom:policy.policy1:1': {
        name: 'dom:policy.policy1',
        modified: modified,
        assertions: {
            17326: {
                role: 'dom:role.role1',
                resource: 'dom:test',
                action: '*',
                effect: 'ALLOW',
                id: 17326,
            },
        },
        version: '1',
        active: true,
    },
    'dom:policy.policy1:2': {
        name: 'dom:policy.policy1',
        modified: modified,
        tags: { tag: { list: ['tag1', 'tag2'] }, tag2: { list: ['tag3'] } },
        assertions: {
            17379: {
                role: 'dom:role.role2',
                resource: 'dom:test2',
                action: '*',
                effect: 'DENY',
                id: 17379,
            },
        },
        version: '2',
        active: false,
    },
    'dom:policy.policy2:0': {
        name: 'dom:policy.policy2',
        modified: modified,
        assertions: {
            17380: {
                role: 'dom:role.role3',
                resource: 'dom:testing',
                action: '*',
                effect: 'DENY',
                id: 17380,
            },
            17390: {
                role: 'dom:role.role4',
                resource: 'dom:resource2',
                action: '*',
                effect: 'DENY',
                id: 17390,
            },
        },
        version: '0',
        active: false,
    },
};

export const singleStorePolicy = {
    name: 'dom:policy.singlePolicy',
    modified: modified,
    assertions: {
        17409: {
            role: 'dom:role.singleRole',
            resource: 'dom:*',
            action: '*',
            effect: 'ALLOW',
            id: 17409,
        },
    },
    version: '0',
    active: true,
};

export const singleStorePolicyWithAssertionConditions = {
    name: 'dom:policy.acl.ows.inbound',
    modified: modified,
    assertions: {
        34567: {
            role: 'dom:role.acl.ows.role1-test1',
            resource: 'dom:ows',
            action: 'TCP-IN:1024-65535:4443-4443',
            effect: 'ALLOW',
            id: 34567,
            conditions: apiAssertionConditions,
        },
    },
    version: '1',
    active: true,
};

export const apiAssertion = {
    role: 'dom:role.singleRole',
    resource: 'test:*',
    action: '*',
    effect: 'ALLOW',
    id: 12345,
};

export const storeAssertion = {
    12345: {
        role: 'dom:role.singleRole',
        resource: 'test:*',
        action: '*',
        effect: 'ALLOW',
        id: 12345,
    },
};
