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
'use strict';
import { deepFreezeObject } from '../../redux/utils';

const config = require('../../config/config')();
describe('Config', () => {
    it('should get default config', () => {
        expect(config).not.toBeNull();
        expect(config.envLabel).toMatch(/unittest/);
    });
});
let mshneorson_1 = 'user3';
let relbaum_1 = 'user1';
let dguttman_1 = 'user2';
let olevi_1 = 'user4';
let pgote_1 = 'user5';

export const domainName = 'dom';
export const expiry = '2022-07-18T14:37:49.671Z';
export const modified = '2022-10-02T14:37:49.573Z';
export const singleStoreRole = {
    tags: { tag: { list: ['tag1'] } },
    name: 'dom:role.singlerole',
    modified: modified,
    roleMembers: {
        'user.user3': {
            memberName: 'user.user3',
            expiration: '2022-10-02T14:37:10.600Z',
            approved: true,
            auditRef: 'Updated domain Meta using Athenz UI',
            memberFullName: null,
        },
        'user.user1': {
            memberName: 'user.user1',
            expiration: '2022-08-19T14:17:35.267Z',
            approved: true,
            auditRef: 'Updated domain Meta using Athenz UI',
            memberFullName: null,
        },
    },
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
    expiry: 1658399499525,
};
export const singleApiRole = {
    tags: { tag: { list: ['tag1'] } },
    name: 'dom:role.singlerole',
    modified: modified,
    roleMembers: [
        {
            memberName: 'user.user3',
            expiration: '2022-10-02T14:37:10.600Z',
            approved: true,
            auditRef: 'Updated domain Meta using Athenz UI',
            memberFullName: null,
        },
        {
            memberName: 'user.user1',
            expiration: '2022-08-19T14:17:35.267Z',
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
                expiration: '2022-10-02T14:37:10.600Z',
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
                expiration: '2022-08-19T14:17:35.267Z',
                principalType: 1,
                memberFullName: null,
            },
            {
                memberName: 'user.user7',
                expiration: '2022-10-02T14:37:10.600Z',
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
                expiration: '2022-10-22T07:48:59.105Z',
                principalType: 1,
                memberFullName: null,
            },
            {
                memberName: 'user.user6',
                expiration: '2022-10-22T07:50:04.579Z',
                principalType: 1,
                memberFullName: null,
            },
            {
                memberName: 'user.user2',
                expiration: '2022-10-22T07:48:59.105Z',
                principalType: 1,
                memberFullName: null,
            },
        ],
    },
];

export const storeRoles = {
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
                expiration: '2022-10-02T14:37:10.600Z',
                principalType: 1,
                memberFullName: 'user.user2',
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
    },
    'dom:role.admin': {
        tags: { tag: { list: ['tag1'] } },
        name: 'dom:role.admin',
        modified: modified,
        roleMembers: {
            'user.user2': {
                memberName: 'user.user2',
                expiration: '2022-08-19T14:17:35.267Z',
                principalType: 1,
                memberFullName: null,
            },
            'user.user3': {
                memberName: 'user.user7',
                expiration: '2022-10-02T14:37:10.600Z',
                principalType: 1,
                memberFullName: null,
            },
        },
    },
    'dom:role.empty': {
        name: 'dom:role.empty',
        modified: modified,
        auditLog: 'for test',
        roleMembers: {},
    },
    'dom:role.expiration': {
        memberExpiryDays: 100,
        reviewEnabled: true,
        tags: { tag: { list: ['tag1', 'tag2'] } },
        name: 'dom:role.expiration',
        modified: modified,
        roleMembers: {
            'user.user4': {
                memberName: 'user.user4',
                expiration: '2022-10-22T07:48:59.105Z',
                principalType: 1,
                memberFullName: null,
            },
            'user.user6': {
                memberName: 'user.user6',
                expiration: '2022-10-22T07:50:04.579Z',
                principalType: 1,
                memberFullName: null,
            },
            'user.user2': {
                memberName: 'user.user6',
                expiration: '2022-10-22T07:48:59.105Z',
                principalType: 1,
                memberFullName: null,
            },
        },
    },
};

deepFreezeObject(storeRoles);

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

export const singleStoreGroup = {
    memberExpiryDays: 50,
    tags: { tag: { list: ['tag1', 'tag2'] } },
    name: 'dom:group.singlegroup',
    modified: modified,
    groupMembers: {
        'user.user4': {
            memberName: 'user.user4',
            expiration: '2022-08-25T15:39:23.701Z',
            approved: true,
            memberFullName: null,
        },
        'user.user1': {
            memberName: 'user.user1',
            expiration: '2022-08-25T15:39:23.701Z',
            approved: true,
            memberFullName: null,
        },
    },
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
    expiry: 1658409358451,
};

export const apiGroups = [
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

export const storeGroups = {
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
        expiry: 1658408002704,
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
        lastReviewedDate: '2022-07-18T14:20:45.836Z',
        expiry: 1658408002704,
    },
};
export const singleStoreService = {
    name: 'dom.singleService',
    description: 'for testing',
    keyId: '1',
    keyValue:
        'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF6WkNVaExjM1Rwdk9iaGpkWThIYgovMHprZldBWVNYTFhhQzlPMVM4QVhvTTcvTDcwWFkrOUtMKzFJeTd4WURUcmJaQjB0Y29sTHdubldIcTVnaVptClV3M3U2RkdTbDVsZDR4cHlxQjAyaUsrY0ZTcVM3S09MTEgwcDlnWFJmeFhpYXFSaVYycktGMFRoenJHb3gyY20KRGYvUW9abGxOZHdJRkdxa3VSY0VEdkJuUlRMV2xFVlYrMVUxMmZ5RXNBMXl2VmI0RjlSc2NaRFltaVBSYmhBKwpjTHpxSEt4WDUxZGw2ZWsxeDdBdlVJTThqczZXUElFZmVseVRSaVV6WHdPZ0laYnF2UkhTUG1GRzBaZ1pEakczCkxsZnkvRThLMFF0Q2sza2kxeThUZ2EySTVrMmhmZngzRHJITW5yMTRaajNCcjBUOVJ3aXFKRDdGb3lUaUQvdGkKeFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t',
};
export const apiServices = [
    {
        name: 'dom.service1',
        publicKeys: [
            {
                key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF6WkNVaExjM1Rwdk9iaGpkWThIYgovMHprZldBWVNYTFhhQzlPMVM4QVhvTTcvTDcwWFkrOUtMKzFJeTd4WURUcmJaQjB0Y29sTHdubldIcTVnaVptClV3M3U2RkdTbDVsZDR4cHlxQjAyaUsrY0ZTcVM3S09MTEgwcDlnWFJmeFhpYXFSaVYycktGMFRoenJHb3gyY20KRGYvUW9abGxOZHdJRkdxa3VSY0VEdkJuUlRMV2xFVlYrMVUxMmZ5RXNBMXl2VmI0RjlSc2NaRFltaVBSYmhBKwpjTHpxSEt4WDUxZGw2ZWsxeDdBdlVJTThqczZXUElFZmVseVRSaVV6WHdPZ0laYnF2UkhTUG1GRzBaZ1pEakczCkxsZnkvRThLMFF0Q2sza2kxeThUZ2EySTVrMmhmZngzRHJITW5yMTRaajNCcjBUOVJ3aXFKRDdGb3lUaUQvdGkKeFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t',
                id: '1',
            },
            {
                key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBb1BqVm5UdXhkOGRwMC9ZTWh6TXIKOURpS0pUUXdrNWphdktKR2RHY29wQ2Ura1lWMHRFQnpGL1VCRWpjYVpuNnd4eGRjZU5wZkhuSVN6SG5abVNFKwpjRGUwY09yc3BPZ1c5d1VGdE9BcGpJZ2krUmxiOC93ck1iMmF1YXV2NUxoRW9ORm9ueCs3TVdSRnptUmZvaG91Cm9pd1h2czJ2V2x4Z0JXelo4UHVHSUlsTERNK3ltWlFxamlPbERjOWF2ZVpraXpUZFJBMG9veTFoRUZyK3ZNRWMKK2ZYY29aQ0F0S0J2aHNuKzFhb2ZPMU9pZ2ljYS9WaCtSSm1ieUNBem1tVFpia0I4emJUaE1vK1cxNmhXeUl0dQpJM1VoMlhHYTZ4dVhyQ0FBQ1FLVVR5TDdGRkl2OXhLUExtVWRXYkdYd3NTZ0FBazZjV2x3WTZJcW4zUHJQSmpTCmNRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ--',
                id: '2',
            },
        ],
        modified: modified,
    },
    {
        name: 'dom.service2',
        publicKeys: [
            {
                key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF6WkNVaExjM1Rwdk9iaGpkWThIYgovMHprZldBWVNYTFhhQzlPMVM4QVhvTTcvTDcwWFkrOUtMKzFJeTd4WURUcmJaQjB0Y29sTHdubldIcTVnaVptClV3M3U2RkdTbDVsZDR4cHlxQjAyaUsrY0ZTcVM3S09MTEgwcDlnWFJmeFhpYXFSaVYycktGMFRoenJHb3gyY20KRGYvUW9abGxOZHdJRkdxa3VSY0VEdkJuUlRMV2xFVlYrMVUxMmZ5RXNBMXl2VmI0RjlSc2NaRFltaVBSYmhBKwpjTHpxSEt4WDUxZGw2ZWsxeDdBdlVJTThqczZXUElFZmVseVRSaVV6WHdPZ0laYnF2UkhTUG1GRzBaZ1pEakczCkxsZnkvRThLMFF0Q2sza2kxeThUZ2EySTVrMmhmZngzRHJITW5yMTRaajNCcjBUOVJ3aXFKRDdGb3lUaUQvdGkKeFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t',
                id: '1',
            },
        ],
        modified: modified,
    },
];

export const storeServices = {
    'dom.service1': {
        name: 'dom.service1',
        description: 'service for test',
        publicKeys: {
            1: {
                key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF6WkNVaExjM1Rwdk9iaGpkWThIYgovMHprZldBWVNYTFhhQzlPMVM4QVhvTTcvTDcwWFkrOUtMKzFJeTd4WURUcmJaQjB0Y29sTHdubldIcTVnaVptClV3M3U2RkdTbDVsZDR4cHlxQjAyaUsrY0ZTcVM3S09MTEgwcDlnWFJmeFhpYXFSaVYycktGMFRoenJHb3gyY20KRGYvUW9abGxOZHdJRkdxa3VSY0VEdkJuUlRMV2xFVlYrMVUxMmZ5RXNBMXl2VmI0RjlSc2NaRFltaVBSYmhBKwpjTHpxSEt4WDUxZGw2ZWsxeDdBdlVJTThqczZXUElFZmVseVRSaVV6WHdPZ0laYnF2UkhTUG1GRzBaZ1pEakczCkxsZnkvRThLMFF0Q2sza2kxeThUZ2EySTVrMmhmZngzRHJITW5yMTRaajNCcjBUOVJ3aXFKRDdGb3lUaUQvdGkKeFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t',
                id: '1',
            },
            2: {
                key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBb1BqVm5UdXhkOGRwMC9ZTWh6TXIKOURpS0pUUXdrNWphdktKR2RHY29wQ2Ura1lWMHRFQnpGL1VCRWpjYVpuNnd4eGRjZU5wZkhuSVN6SG5abVNFKwpjRGUwY09yc3BPZ1c5d1VGdE9BcGpJZ2krUmxiOC93ck1iMmF1YXV2NUxoRW9ORm9ueCs3TVdSRnptUmZvaG91Cm9pd1h2czJ2V2x4Z0JXelo4UHVHSUlsTERNK3ltWlFxamlPbERjOWF2ZVpraXpUZFJBMG9veTFoRUZyK3ZNRWMKK2ZYY29aQ0F0S0J2aHNuKzFhb2ZPMU9pZ2ljYS9WaCtSSm1ieUNBem1tVFpia0I4emJUaE1vK1cxNmhXeUl0dQpJM1VoMlhHYTZ4dVhyQ0FBQ1FLVVR5TDdGRkl2OXhLUExtVWRXYkdYd3NTZ0FBazZjV2x3WTZJcW4zUHJQSmpTCmNRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ--',
                id: '2',
            },
        },
        modified: modified,
    },
    'dom.service2': {
        name: 'dom.service2',
        publicKeys: {
            1: {
                key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF6WkNVaExjM1Rwdk9iaGpkWThIYgovMHprZldBWVNYTFhhQzlPMVM4QVhvTTcvTDcwWFkrOUtMKzFJeTd4WURUcmJaQjB0Y29sTHdubldIcTVnaVptClV3M3U2RkdTbDVsZDR4cHlxQjAyaUsrY0ZTcVM3S09MTEgwcDlnWFJmeFhpYXFSaVYycktGMFRoenJHb3gyY20KRGYvUW9abGxOZHdJRkdxa3VSY0VEdkJuUlRMV2xFVlYrMVUxMmZ5RXNBMXl2VmI0RjlSc2NaRFltaVBSYmhBKwpjTHpxSEt4WDUxZGw2ZWsxeDdBdlVJTThqczZXUElFZmVseVRSaVV6WHdPZ0laYnF2UkhTUG1GRzBaZ1pEakczCkxsZnkvRThLMFF0Q2sza2kxeThUZ2EySTVrMmhmZngzRHJITW5yMTRaajNCcjBUOVJ3aXFKRDdGb3lUaUQvdGkKeFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t',
                id: '1',
            },
        },
        modified: modified,
        provider: {
            aws_lambda_instance_launch_provider: 'allow',
            openstack_instance_launch_provider: 'not',
            secureboot_instance_launch_provider: 'not',
            aws_ecs_instance_launch_provider: 'allow',
            zts_instance_launch_provider: 'not',
            vespa_instance_launch_provider: 'not',
            ybiip_instance_launch_provider: 'not',
            azure_instance_launch_provider: 'not',
            k8s_omega_instance_launch_provider: 'not',
            aws_instance_launch_provider: 'allow',
        },
    },
};

export const singleApiPolicy = {
    name: 'dom:policy.singlePolicy',
    modified: modified,
    assertions: [
        {
            role: 'dom:role.singleRole',
            resource: 'test:*',
            action: '*',
            effect: 'ALLOW',
            id: 17409,
        },
    ],
    version: '0',
    active: true,
};

export const storeDomainData = {
    enabled: true,
    auditEnabled: false,
    ypmId: 0,
    memberExpiryDays: 76,
    tags: {
        tag1: { list: ['tagValue1', 'tagValue2'] },
        tag2: { list: ['tagValue3'] },
    },
    name: 'dom',
    modified: '2022-07-25T13:43:05.183Z',
    id: '62bb4f70-f7a5-11ec-8202-e7ae4e1596ac',
    isAWSTemplateApplied: false,
    headerDetails: {
        userData: {
            userIcon:
                'https://directory.ouryahoo.com/emp_photos/vzm/r/test.jpg',
            userMail: 'test@yahooinc.com',
            userLink: {
                title: 'User Profile',
                url: 'https://thestreet.ouryahoo.com/thestreet/directory?email=test@yahooinc.com',
                target: '_blank',
            },
        },
        headerLinks: [
            {
                title: 'User Guide',
                url: 'https://git.ouryahoo.com/pages/athens/athenz-guide/',
                target: '_blank',
            },
            {
                title: 'Follow us on Street',
                url: 'https://thestreet.ouryahoo.com/thestreet/ls/community/athenz',
                target: '_blank',
            },
            {
                title: 'Support',
                url: 'https://jira.ouryahoo.com/secure/CreateIssue.jspa?pid=10388&issuetype=10100',
                target: '_blank',
            },
        ],
        userId: 'testId',
        createDomainMessage:
            'Athenz top level domain creation will be manual until it is integrated with an updated Yahoo product taxonomy. \n If your product does not have a top level domain already registered in Athenz, you can file a JIRA ticket in the JIRA ATHENS queue. \n Please provide the Product ID for your product from "Product Master", a short and descriptive domain name and list of administrators identified by their Okta Short IDs. \n',
        productMasterLink: {
            title: 'Product ID',
            url: 'https://productmaster.ouryahoo.com/engineering/product/',
            target: '_blank',
        },
    },
    pendingMembersList: {
        'domuser.user1role1': {
            category: 'role',
            domainName: 'dom',
            memberName: 'user.user1',
            memberNameFull: null,
            roleName: 'role1',
            userComment: 'added using Athenz UI',
            auditRef: '',
            requestPrincipal: 'user.user2',
            requestPrincipalFull: null,
            requestTime: '2022-07-12T14:29:08.384Z',
            expiryDate: '2022-09-25T14:29:08.374Z',
        },
        'domuser.user3role2': {
            category: 'role',
            domainName: 'dom',
            memberName: 'user.user3',
            memberNameFull: null,
            roleName: 'role2',
            userComment: 'added using Athenz UI',
            auditRef: '',
            requestPrincipal: 'user.user2',
            requestPrincipalFull: null,
            requestTime: '2022-07-12T13:14:57.267Z',
            expiryDate: '2022-09-25T13:14:57.257Z',
        },
    },
    featureFlag: true,
    authorityAttributes: {
        attributes: {
            date: { values: ['ElevatedClearance'] },
            bool: { values: ['OnShore-US'] },
        },
    },
    businessServices: [],
};

export const apiServiceDependenciesData = [
    { service: 'dom1.service1', domain: 'dom' },
    {
        service: 'paranoids.service1',
        domain: 'dom',
        resourceGroups: [
            'resourcegroup.tenant.dom.res_group.test_2.workers',
            'resourcegroup.tenant.dom.res_group.test_res_grp1.readers',
            'resourcegroup.tenant.dom.res_group.test_res_grp1.writers',
        ],
    },
];

export const apiAssertionConditions = {
    conditionsList: [
        {
            id: 1,
            conditionsMap: {
                instance: {
                    operator: 'EQUAL',
                    value: 'test.com',
                },
                id: {
                    operator: 'EQUAL',
                    value: '1',
                },
                enforcementstate: {
                    operator: 'EQUAL',
                    value: 'report',
                },
            },
        },
    ],
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

export const storePolicies = {
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
            resource: 'test:*',
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

export const storeInboundOutboundList = {
    inbound: [
        {
            layer: 'TCP',
            source_port: '1024-65535',
            destination_port: '4443-4443',
            conditionsList: [
                {
                    instances: 'test.com',
                    id: 1,
                    enforcementstate: 'report',
                    assertionId: 17389,
                    policyName: 'dom:policy.acl.openhouse.inbound',
                },
            ],
            destination_service: 'openhouse',
            source_services: ['yamas.api'],
            assertionIdx: 17389,
            identifier: 'test',
        },
        {
            layer: 'TCP',
            source_port: '1024-65535',
            destination_port: '4443-4443',
            conditionsList: [
                {
                    instances: 'test.com',
                    id: 1,
                    enforcementstate: 'report',
                    assertionId: 17417,
                    policyName: 'dom:policy.acl.ows.inbound',
                },
            ],
            destination_service: 'ows',
            source_services: ['yamas.api'],
            assertionIdx: 17417,
            identifier: 'test',
        },
    ],
    outbound: [
        {
            layer: 'TCP',
            source_port: '1024-65535',
            destination_port: '1024-65535',
            conditionsList: [
                {
                    instances: 'test.com',
                    id: 1,
                    enforcementstate: 'report',
                    assertionId: 17418,
                    policyName: 'dom:policy.acl.openhouse.outbound',
                },
            ],
            source_service: 'openhouse',
            destination_services: ['yamas.api'],
            assertionIdx: 17418,
            identifier: 'test',
        },
    ],
};

export const apiBusinessServicesAll = {
    validValues: [
        '0031636013124f40c0eebb722244b043:Search > Hot Search > Atomics > Database',
        '0031636013124f40c0eebb722244b044:IIOps > Name Space Management > Namer',
        '0031636013124f40c0eebb722244b045:CERT: Netflow',
    ],
};
export const storeBusinessServicesAll = [
    {
        value: '0031636013124f40c0eebb722244b043',
        name: 'Search > Hot Search > Atomics > Database',
    },
    {
        value: '0031636013124f40c0eebb722244b044',
        name: 'IIOps > Name Space Management > Namer',
    },
    {
        value: '0031636013124f40c0eebb722244b045',
        name: 'CERT: Netflow',
    },
];
