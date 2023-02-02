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
import { deepFreezeObject } from '../../../redux/utils';
import { modified, expiry, domainName } from '../../config/config.test';
import { PENDING_STATE_ENUM } from '../../../components/constants/constants';

describe('Role Config', () => {
    it('should get default config', () => {
        expect(apiRoles).not.toBeNull();
    });
});
export const singleGroupAsARoleMember = {
    memberName: 'sys.auth.tests:group.redux1',
    approved: true,
    auditRef: 'added using Athenz UI',
    memberFullName: null,
    groupMembers: [
        {
            memberName: 'user.olevi',
            approved: true,
            auditRef: 'added using Athenz UI',
            memberFullName: null,
        },
        {
            memberName: 'user.relbaum',
            approved: true,
            auditRef: 'ggg',
            memberFullName: null,
        },
    ],
};

export const singleApiRoleMember = {
    memberName: 'user.olevi',
    isMember: true,
    roleName: 'sys.auth.tests:role.redux',
    expiration: '2022-12-29T12:49:48.131Z',
    approved: true,
    requestPrincipal: 'user.relbaum',
    memberFullName: null,
};

export const apiRoles = [
    {
        name: 'dom:rolexxe1',
        modified: modified,
        roleMembers: [
            {
                memberName: 'user.user1',
                expiration: expiry,
                principalType: 1,
                memberFullName: 'user.user1',
            },
            {
                memberName: 'user.user2',
                expiration: expiry,
                principalType: 1,
                memberFullName: 'user.user2',
            },
        ],
        lastReviewedDate: '2022-07-18T13:42:54.907Z',
    },
    {
        tags: { tag: { list: ['tag1'] } },
        name: 'dom:role.admin',
        modified: modified,
        roleMembers: [
            {
                memberName: 'user.user2',
                expiration: expiry,
                principalType: 1,
                memberFullName: null,
            },
            {
                memberName: 'user.user7',
                expiration: expiry,
                principalType: 1,
                memberFullName: null,
            },
        ],
    },
    {
        name: 'dom:role.empty',
        modified: modified,
        roleMembers: [],
    },
    {
        memberExpiryDays: 100,
        reviewEnabled: true,
        tags: { tag: { list: ['tag1', 'tag2'] } },
        name: 'dom:role.expiration',
        modified: modified,
        roleMembers: [
            {
                memberName: 'user.user4',
                expiration: expiry,
                principalType: 1,
                memberFullName: null,
            },
            {
                memberName: 'user.user6',
                expiration: expiry,
                principalType: 1,
                memberFullName: null,
            },
            {
                memberName: 'user.user2',
                expiration: expiry,
                principalType: 1,
                memberFullName: null,
            },
        ],
    },
];

export const configRole1 = {
    name: 'dom:role.role1',
    modified: modified,
    roleMembers: {
        'user.user1': {
            memberName: 'user.user1',
            expiration: expiry,
            principalType: 1,
            memberFullName: 'user.user1',
        },
        'user.user2': {
            memberName: 'user.user2',
            expiration: expiry,
            principalType: 1,
            memberFullName: 'user.user2',
        },
    },
    lastReviewedDate: '2022-07-18T13:42:54.907Z',
};

export const configStoreRoles = {
    'dom:role.role1': {
        name: 'dom:role.role1',
        modified: modified,
        roleMembers: {
            'user.user1': {
                memberName: 'user.user1',
                expiration: expiry,
                principalType: 1,
                memberFullName: 'user.user1',
            },
            'user.user2': {
                memberName: 'user.user2',
                expiration: expiry,
                principalType: 1,
                memberFullName: 'user.user2',
            },
        },
        rolePendingMembers: {
            'user.user3': {
                active: false,
                approved: false,
                auditRef: 'added using Athenz UI',
                expiration: expiry,
                memberFullName: 'user.user3',
                requestedTime: expiry,
                pendingState: PENDING_STATE_ENUM.ADD,
            },
        },
        lastReviewedDate: '2022-07-18T13:42:54.907Z',
    },
    'dom:role.acl.ows.inbound-test1': {
        modified: modified,
        roleMembers: {
            'yamas.api': {
                memberName: 'yamas.api',
                principalType: 1,
                memberFullName: null,
            },
        },
        rolePendingMembers: {},
    },
    'dom:role.acl.ows.outbound-test2': {
        modified: modified,
        roleMembers: {
            'sys.auth': {
                memberName: 'sys.auth',
                principalType: 1,
                memberFullName: null,
            },
        },
        rolePendingMembers: {},
    },
    'dom:role.admin': {
        tags: { tag: { list: ['tag1'] } },
        name: 'dom:role.admin',
        modified: modified,
        roleMembers: {
            'user.user2': {
                memberName: 'user.user2',
                expiration: expiry,
                principalType: 1,
                memberFullName: null,
            },
            'user.user3': {
                memberName: 'user.user7',
                expiration: expiry,
                principalType: 1,
                memberFullName: null,
            },
        },
        rolePendingMembers: {},
    },
    'dom:role.empty': {
        name: 'dom:role.empty',
        modified: modified,
        auditLog: 'for test',
        roleMembers: {},
        rolePendingMembers: {},
    },
    'dom:role.expiration': {
        memberExpiryDays: 100,
        reviewEnabled: true,
        tags: { tag: { list: ['tag1', 'tag2'] } },
        name: 'dom:role.expiration',
        modified: modified,
        rolePendingMembers: {
            'user.user4': {
                memberName: 'user.user4',
                expiration: expiry,
                approved: false,
                principalType: 1,
                memberFullName: null,
                pendingState: PENDING_STATE_ENUM.ADD,
            },
            'user.user6': {
                memberName: 'user.user6',
                expiration: null,
                approved: false,
                principalType: 1,
                memberFullName: null,
                pendingState: PENDING_STATE_ENUM.DELETE,
            },
        },
        roleMembers: {
            'user.user6': {
                memberName: 'user.user6',
                expiration: expiry,
                principalType: 1,
                memberFullName: null,
            },
            'user.user2': {
                memberName: 'user.user2',
                expiration: expiry,
                principalType: 1,
                memberFullName: null,
            },
        },
    },
};

export const singleApiRole = {
    tags: { tag: { list: ['tag1'] } },
    name: 'dom:role.singlerole',
    modified: modified,
    roleMembers: [
        {
            memberName: 'user.user3',
            expiration: expiry,
            approved: true,
            auditRef: 'Updated domain Meta using Athenz UI',
            memberFullName: null,
        },
        {
            memberName: 'user.user1',
            expiration: expiry,
            approved: true,
            auditRef: 'Updated domain Meta using Athenz UI',
            memberFullName: null,
        },
    ],
    auditLog: [
        {
            member: 'user.user1',
            admin: 'user.user1',
            created: '2022-06-29T12:17:03.000Z',
            action: 'ADD',
            memberFullName: null,
            adminFullName: null,
        },
        {
            member: 'user.user1',
            admin: 'user.user1',
            created: '2022-06-30T14:17:24.000Z',
            action: 'UPDATE',
            auditRef: 'Updated domain Meta using Athenz UI',
            memberFullName: null,
            adminFullName: null,
        },
    ],
};

export const singleStoreRole = {
    tags: { tag: { list: ['tag1'] } },
    name: 'dom:role.singlerole',
    modified: modified,
    roleMembers: {
        'user.user3': {
            memberName: 'user.user3',
            expiration: expiry,
            approved: true,
            auditRef: 'Updated domain Meta using Athenz UI',
            memberFullName: null,
        },
        'user.user1': {
            memberName: 'user.user1',
            expiration: expiry,
            approved: true,
            auditRef: 'Updated domain Meta using Athenz UI',
            memberFullName: null,
        },
    },
    rolePendingMembers: {},
    auditLog: [
        {
            member: 'user.user1',
            admin: 'user.user1',
            created: '2022-06-29T12:17:03.000Z',
            action: 'ADD',
            memberFullName: null,
            adminFullName: null,
        },
        {
            member: 'user.user1',
            admin: 'user.user1',
            created: '2022-06-30T14:17:24.000Z',
            action: 'UPDATE',
            auditRef: 'Updated domain Meta using Athenz UI',
            memberFullName: null,
            adminFullName: null,
        },
    ],
};

export const singleMember = {
    memberName: 'user.user10',
    expiration: expiry,
    approved: true,
    auditRef: 'Updated domain Meta using Athenz UI',
    memberFullName: null,
};

deepFreezeObject(singleApiRole);
