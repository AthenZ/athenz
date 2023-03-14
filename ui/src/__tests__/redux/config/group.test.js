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
import { modified, expiry, domainName } from '../../config/config.test';
import { PENDING_STATE_ENUM } from '../../../components/constants/constants';

describe('Groups Config', () => {
    it('should get default config', () => {
        expect(singleApiGroup).not.toBeNull();
    });
});

export const singleApiGroupMember = {
    memberName: 'user.singleMember1',
    isMember: true,
    groupName: 'dom:group.group1',
    approved: true,
    requestPrincipal: 'user.user1',
    memberFullName: null,
};

export const groupAuditLog = [
    {
        member: 'user.user4',
        admin: 'user.user1',
        created: '2022-07-06T15:39:23.000Z',
        action: 'ADD',
        memberFullName: null,
        adminFullName: null,
    },
    {
        member: 'user.user1',
        admin: 'user.user1',
        created: '2022-07-06T15:39:23.000Z',
        action: 'ADD',
        memberFullName: null,
        adminFullName: null,
    },
];
export const singleApiGroup = {
    memberExpiryDays: 50,
    tags: { tag: { list: ['tag1', 'tag2'] } },
    name: 'dom:group.singlegroup',
    modified: modified,
    groupMembers: [
        {
            memberName: 'user.user4',
            expiration: '2022-08-25T15:39:23.701Z',
            approved: true,
            memberFullName: null,
        },
        {
            memberName: 'user.user1',
            expiration: '2022-08-25T15:39:23.701Z',
            approved: true,
            memberFullName: null,
        },
    ],
    auditLog: groupAuditLog,
};

export const singleStoreGroup = {
    memberExpiryDays: 50,
    name: 'dom:group.singlegroup',
    tags: { tag: { list: ['tag1', 'tag2'] } },
    modified: modified,
    groupMembers: {
        'user.user1': {
            memberName: 'user.user1',
            expiration: '2022-08-25T15:39:23.701Z',
            approved: true,
            memberFullName: null,
        },
        'user.user4': {
            memberName: 'user.user4',
            expiration: '2022-08-25T15:39:23.701Z',
            approved: true,
            memberFullName: null,
        },
    },
    groupPendingMembers: {},
    auditLog: [
        {
            member: 'user.user4',
            admin: 'user.user1',
            created: '2022-07-06T15:39:23.000Z',
            action: 'ADD',
            memberFullName: null,
            adminFullName: null,
        },
        {
            member: 'user.user1',
            admin: 'user.user1',
            created: '2022-07-06T15:39:23.000Z',
            action: 'ADD',
            memberFullName: null,
            adminFullName: null,
        },
    ],
};

export const configApiGroups = [
    {
        name: 'dom:group.group1',
        modified: modified,
        groupMembers: [
            {
                memberName: 'user.user4',
                groupName: 'dom:group.group1',
                expiration: '2022-09-02T08:14:08.131Z',
            },
            {
                memberName: 'user.user1',
                groupName: 'dom:group.group1',
                expiration: '2022-09-02T08:14:08.131Z',
            },
        ],
    },
    {
        memberExpiryDays: 50,
        tags: { tag: { list: ['tag1', 'tag2'] } },
        name: 'dom:group.expiration',
        modified: modified,
        groupMembers: [
            {
                memberName: 'user.user4',
                groupName: 'dom:group.group2',
                expiration: '2022-08-25T15:39:23.701Z',
            },
            {
                memberName: 'user.user1',
                groupName: 'dom:group.group2',
                expiration: '2022-08-25T15:39:23.701Z',
            },
        ],
        lastReviewedDate: '2022-07-18T14:20:45.836Z',
    },
];

export const configStoreGroups = {
    'dom:group.group1': {
        name: 'dom:group.group1',
        modified: modified,
        auditLog: 'for test',
        groupMembers: {
            'user.user4': {
                memberName: 'user.user4',
                groupName: 'dom:group.group1',
                expiration: '2022-09-02T08:14:08.131Z',
            },
            'user.user1': {
                memberName: 'user.user1',
                groupName: 'dom:group.group1',
                expiration: '2022-09-02T08:14:08.131Z',
            },
        },
        groupPendingMembers: {},
    },
    'dom:group.expiration': {
        memberExpiryDays: 50,
        tags: { tag: { list: ['tag1', 'tag2'] }, tag2: { list: ['tag3'] } },
        name: 'dom:group.expiration',
        modified: modified,
        groupMembers: {
            'user.user4': {
                memberName: 'user.user4',
                groupName: 'dom:group.expiration',
                expiration: '2022-08-25T15:39:23.701Z',
            },
            'user.user1': {
                memberName: 'user.user1',
                groupName: 'dom:group.expiration',
                expiration: '2022-08-25T15:39:23.701Z',
            },
        },
        groupPendingMembers: {},
        lastReviewedDate: '2022-07-18T14:20:45.836Z',
        expiry: 1658408002704,
    },
};

export const configStoreGroupsWithPendingMembers = {
    'dom:group.group1': {
        name: 'dom:group.group1',
        modified: modified,
        auditLog: 'for test',
        groupMembers: {
            'user.user1': {
                memberName: 'user.user1',
                groupName: 'dom:group.group1',
                expiration: '2022-09-02T08:14:08.131Z',
            },
            'user.user6': {
                memberName: 'user.user6',
                groupName: 'dom:group.group1',
                expiration: '2022-09-02T08:14:08.131Z',
            },
        },
        groupPendingMembers: {
            'user.user4': {
                pendingState: PENDING_STATE_ENUM.ADD,
                approved: false,
                memberName: 'user.user4',
                groupName: 'dom:group.group1',
                expiration: '2022-09-02T08:14:08.131Z',
            },
            'user.user6': {
                pendingState: PENDING_STATE_ENUM.DELETE,
                approved: false,
                memberName: 'user.user6',
                groupName: 'dom:group.group1',
                expiration: '2022-09-02T08:14:08.131Z',
            },
        },
    },
};
