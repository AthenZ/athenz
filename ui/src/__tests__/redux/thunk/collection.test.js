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
import MockApi from '../../../mock/MockApi';
import sinon from 'sinon';
import {
    getExpiryTime,
    mapToList,
    membersListToMaps,
} from '../../../redux/utils';
import { _ } from 'lodash';
import {
    addMemberToStore,
    addPendingMemberToStore,
    deleteMemberFromStore,
    updateSettingsToStore,
    updateTagsToStore,
} from '../../../redux/actions/collections';
import {
    addMember,
    deleteMember,
    updateSettings,
    updateTags,
} from '../../../redux/thunks/collections';
import { singleApiGroupMember, singleStoreGroup } from '../config/group.test';
import {
    singleApiRole,
    singleApiRoleMember,
    singleGroupAsARoleMember,
    singleStoreRole,
} from '../config/role.test';
import AppUtils from '../../../components/utils/AppUtils';
import {
    loadingInProcess,
    loadingSuccess,
} from '../../../redux/actions/loading';
import { loadRole } from '../../../redux/actions/roles';
import { PENDING_STATE_ENUM } from '../../../components/constants/constants';
import { updateBellPendingMember } from '../../../redux/actions/domain-data';
import { expiry, modified } from '../../config/config.test';

const groupsThunk = require('../../../redux/thunks/groups');
const rolesThunk = require('../../../redux/thunks/roles');
const groupSelector = require('../../../redux/selectors/groups');
const roleSelector = require('../../../redux/selectors/roles');
const domainName = 'dom';
const utils = require('../../../redux/utils');

describe('deleteMember method', () => {
    beforeAll(() => {
        jest.spyOn(utils, 'getExpiryTime').mockReturnValue(5);
        jest.spyOn(groupsThunk, 'getGroup').mockReturnValue(true);
        jest.spyOn(rolesThunk, 'getRole').mockReturnValue(true);
    });

    afterAll(() => {
        jest.spyOn(utils, 'getExpiryTime').mockRestore();
        jest.spyOn(groupsThunk, 'getGroup').mockRestore();
        jest.spyOn(rolesThunk, 'getRole').mockRestore();
    });

    afterEach(() => {
        MockApi.cleanMockApi();
        jest.spyOn(utils, 'isExpired').mockRestore();
        jest.spyOn(groupSelector, 'thunkSelectGroup').mockRestore();
        jest.spyOn(roleSelector, 'thunkSelectRole').mockRestore();
        jest.spyOn(roleSelector, 'thunkSelectRoleMember').mockRestore();
    });

    it('group category and get exception because member doesnt exist', async () => {
        const getState = () => {};

        jest.spyOn(groupSelector, 'thunkSelectGroup').mockReturnValue({
            groupMembers: {},
        });

        let myApiMock = {
            deleteMember: jest.fn().mockReturnValue(Promise.resolve([])),
        };
        MockApi.setMockApi(myApiMock);
        sinon.spy(myApiMock, 'deleteMember');

        const fakeDispatch = sinon.spy();
        try {
            await deleteMember(
                domainName,
                'group1',
                'group',
                'member1'
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toEqual(404);
            expect(e.body.message).toEqual('Member member1 doesnt exist');
        }

        expect(fakeDispatch.getCall(0)).toBeTruthy();
        expect(myApiMock.deleteMember.getCall(0)).toBeNull();
    });

    it('role category and get exception because member doesnt exist', async () => {
        const getState = () => {};

        jest.spyOn(roleSelector, 'thunkSelectRole').mockReturnValue({
            roleMembers: {},
        });

        let myApiMock = {
            deleteMember: jest.fn().mockReturnValue(Promise.resolve([])),
        };
        MockApi.setMockApi(myApiMock);
        sinon.spy(myApiMock, 'deleteMember');

        const fakeDispatch = sinon.spy();
        try {
            await deleteMember(
                domainName,
                'role1',
                'role',
                'member1'
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toEqual(404);
            expect(e.body.message).toEqual('Member member1 doesnt exist');
        }

        expect(fakeDispatch.getCall(0)).toBeTruthy();
        expect(myApiMock.deleteMember.getCall(0)).toBeNull();
    });

    it('group category successfully delete a member', async () => {
        const getState = () => {};

        jest.spyOn(groupSelector, 'thunkSelectGroup').mockReturnValue({
            groupMembers: { member1: {} },
        });

        let myApiMock = {
            deleteMember: jest.fn().mockReturnValue(Promise.resolve([])),
        };
        MockApi.setMockApi(myApiMock);
        sinon.spy(myApiMock, 'deleteMember');

        const fakeDispatch = sinon.spy();
        await deleteMember(
            domainName,
            'group1',
            'group',
            'member1',
            'auditRef',
            false,
            'csrf'
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0)).toBeTruthy();
        expect(
            myApiMock.deleteMember
                .getCall(0)
                .calledWith(
                    domainName,
                    'group1',
                    'member1',
                    'auditRef',
                    false,
                    'group',
                    'csrf'
                )
        ).toBeTruthy();
        expect(fakeDispatch.getCall(1).args[0]).toEqual(
            deleteMemberFromStore('member1', 'group', 'dom:group.group1')
        );
    });
    it('role category successfully delete a member', async () => {
        const getState = () => {};

        jest.spyOn(roleSelector, 'thunkSelectRole').mockReturnValue({
            roleMembers: { member1: {} },
        });

        let myApiMock = {
            deleteMember: jest.fn().mockReturnValue(Promise.resolve([])),
        };
        MockApi.setMockApi(myApiMock);
        sinon.spy(myApiMock, 'deleteMember');

        const fakeDispatch = sinon.spy();
        await deleteMember(
            domainName,
            'role1',
            'role',
            'member1',
            'auditRef',
            false,
            'csrf'
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0)).toBeTruthy();
        expect(
            myApiMock.deleteMember
                .getCall(0)
                .calledWith(
                    domainName,
                    'role1',
                    'member1',
                    'auditRef',
                    false,
                    'role',
                    'csrf'
                )
        ).toBeTruthy();
        expect(fakeDispatch.getCall(1).args[0]).toEqual(
            deleteMemberFromStore('member1', 'role', 'dom:role.role1')
        );
    });
});

it('role category successfully add a pending member with delete state', async () => {
    const getState = () => {};
    let member = {
        roleName: 'role1',
        memberName: 'user.mjames',
        approved: true,
        active: true,
        memberFullName: 'Mary James',
    };
    jest.spyOn(roleSelector, 'thunkSelectRole').mockReturnValue({
        deleteProtection: true,
        reviewEnabled: true,
        roleMembers: {
            'user.mjames': member,
        },
    });

    jest.spyOn(roleSelector, 'thunkSelectRoleMember').mockReturnValue({
        ...member,
    });

    let myApiMock = {
        deleteMember: jest.fn().mockReturnValue(Promise.resolve([])),
    };
    MockApi.setMockApi(myApiMock);
    sinon.spy(myApiMock, 'deleteMember');

    const fakeDispatch = sinon.spy();
    await deleteMember(
        domainName,
        'role1',
        'role',
        'user.mjames',
        'auditRef',
        false,
        'csrf'
    )(fakeDispatch, getState);

    expect(fakeDispatch.getCall(0)).toBeTruthy();
    expect(
        myApiMock.deleteMember
            .getCall(0)
            .calledWith(
                domainName,
                'role1',
                'user.mjames',
                'auditRef',
                false,
                'role',
                'csrf'
            )
    ).toBeTruthy();
    const expectedMember = {
        ...member,
        pendingState: PENDING_STATE_ENUM.DELETE,
        active: false,
        approved: false,
    };
    expect(fakeDispatch.getCall(1).args[0]).toEqual(
        addPendingMemberToStore(expectedMember, 'role', 'dom:role.role1')
    );
    expect(fakeDispatch.getCall(2).args[0]).toEqual(
        updateBellPendingMember(expectedMember.memberName, 'dom:role.role1')
    );
});

it('group category successfully add a pending member with delete state', async () => {
    const getState = () => {};
    let member = {
        groupName: 'group1',
        memberName: 'user.mjames',
        approved: true,
        active: true,
        memberFullName: 'Mary James',
    };
    jest.spyOn(groupSelector, 'thunkSelectGroup').mockReturnValue({
        deleteProtection: true,
        reviewEnabled: true,
        groupMembers: {
            'user.mjames': member,
        },
    });

    jest.spyOn(groupSelector, 'thunkSelectGroupMember').mockReturnValue({
        ...member,
    });

    let myApiMock = {
        deleteMember: jest.fn().mockReturnValue(Promise.resolve([])),
    };
    MockApi.setMockApi(myApiMock);
    sinon.spy(myApiMock, 'deleteMember');

    const fakeDispatch = sinon.spy();
    await deleteMember(
        domainName,
        'group1',
        'group',
        'user.mjames',
        'auditRef',
        false,
        'csrf'
    )(fakeDispatch, getState);

    expect(fakeDispatch.getCall(0)).toBeTruthy();
    expect(
        myApiMock.deleteMember
            .getCall(0)
            .calledWith(
                domainName,
                'group1',
                'user.mjames',
                'auditRef',
                false,
                'group',
                'csrf'
            )
    ).toBeTruthy();
    const expectedMember = {
        ...member,
        pendingState: PENDING_STATE_ENUM.DELETE,
        active: false,
        approved: false,
    };
    expect(fakeDispatch.getCall(1).args[0]).toEqual(
        addPendingMemberToStore(expectedMember, 'group', 'dom:group.group1')
    );
    expect(fakeDispatch.getCall(2).args[0]).toEqual(
        updateBellPendingMember(expectedMember.memberName, 'dom:group.group1')
    );
});

describe('updateTags method', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('successfully update group tag', async () => {
        let collectionName = 'group1';
        let detail = {
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
        };
        let auditRef = 'auditRef';
        let _csrf = 'csrf';
        let category = 'group';

        const getState = () => {};

        let myApiMock = {
            putMeta: jest.fn().mockReturnValue(Promise.resolve([])),
        };
        MockApi.setMockApi(myApiMock);
        sinon.spy(myApiMock, 'putMeta');

        const fakeDispatch = sinon.spy();
        await updateTags(
            domainName,
            collectionName,
            detail,
            auditRef,
            _csrf,
            category
        )(fakeDispatch, getState);

        expect(
            myApiMock.putMeta
                .getCall(0)
                .calledWith(
                    domainName,
                    collectionName,
                    detail,
                    auditRef,
                    _csrf,
                    category
                )
        ).toBeTruthy();
        expect(fakeDispatch.getCall(0).args[0]).toEqual(
            updateTagsToStore(
                domainName + ':group.' + collectionName,
                detail,
                category
            )
        );
    });
    it('successfully update role tag', async () => {
        let collectionName = 'admin';
        let detail = {
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
        };
        let auditRef = 'auditRef';
        let _csrf = 'csrf';
        let category = 'role';

        const getState = () => {};
        let myApiMock = {
            putMeta: jest.fn().mockReturnValue(Promise.resolve([])),
        };
        MockApi.setMockApi(myApiMock);
        sinon.spy(myApiMock, 'putMeta');

        const fakeDispatch = sinon.spy();
        await updateTags(
            domainName,
            collectionName,
            detail,
            auditRef,
            _csrf,
            category
        )(fakeDispatch, getState);

        expect(
            myApiMock.putMeta
                .getCall(0)
                .calledWith(
                    domainName,
                    collectionName,
                    detail,
                    auditRef,
                    _csrf,
                    category
                )
        ).toBeTruthy();
        expect(fakeDispatch.getCall(0).args[0]).toEqual(
            updateTagsToStore(
                domainName + ':role.' + collectionName,
                detail,
                category
            )
        );
    });
    it('successfully update policy tag', async () => {
        let collectionName = 'policy1';
        let detail = {
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
        };
        let auditRef = 'auditRef';
        let _csrf = 'csrf';
        let category = 'policy';

        const getState = () => {};
        let myApiMock = {
            putMeta: jest.fn().mockReturnValue(Promise.resolve([])),
        };
        MockApi.setMockApi(myApiMock);
        sinon.spy(myApiMock, 'putMeta');

        const fakeDispatch = sinon.spy();
        await updateTags(
            domainName,
            collectionName,
            detail,
            auditRef,
            _csrf,
            category
        )(fakeDispatch, getState);

        expect(
            myApiMock.putMeta
                .getCall(0)
                .calledWith(
                    domainName,
                    collectionName,
                    detail,
                    auditRef,
                    _csrf,
                    category
                )
        ).toBeTruthy();
        expect(fakeDispatch.getCall(0).args[0]).toEqual(
            updateTagsToStore(
                domainName + ':policy.' + collectionName,
                detail,
                category
            )
        );
    });
});

it('successfully update service tag', async () => {
    let collectionName = 'service1';
    let detail = {
        tags: { tag: { list: ['tag1'] } },
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
    };

    let auditRef = 'auditRef';
    let _csrf = 'csrf';
    let category = 'service';

    const getState = () => {};
    let myApiMock = {
        putMeta: jest.fn().mockReturnValue(Promise.resolve([])),
    };
    MockApi.setMockApi(myApiMock);
    sinon.spy(myApiMock, 'putMeta');

    const fakeDispatch = sinon.spy();
    await updateTags(
        domainName,
        collectionName,
        detail,
        auditRef,
        _csrf,
        category
    )(fakeDispatch, getState);

    expect(
        myApiMock.putMeta
            .getCall(0)
            .calledWith(
                domainName,
                collectionName,
                detail,
                auditRef,
                _csrf,
                category
            )
    ).toBeTruthy();
    expect(fakeDispatch.getCall(0).args[0]).toEqual(
        updateTagsToStore(domainName + '.' + collectionName, detail, category)
    );
});

describe('updateSettings method', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('successfully update group settings', async () => {
        let collectionName = 'group1';
        let detail = {};
        let auditRef = 'Updated domain Meta using Athenz UI';
        let _csrf = 'csrf';
        let category = 'group';

        const getState = () => {};

        let myApiMock = {
            putMeta: jest.fn().mockReturnValue(Promise.resolve([])),
        };
        MockApi.setMockApi(myApiMock);
        sinon.spy(myApiMock, 'putMeta');

        const fakeDispatch = sinon.spy();
        await updateSettings(
            domainName,
            detail,
            collectionName,
            _csrf,
            category
        )(fakeDispatch, getState);

        expect(
            myApiMock.putMeta
                .getCall(0)
                .calledWith(
                    domainName,
                    collectionName,
                    detail,
                    auditRef,
                    _csrf,
                    category
                )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                updateSettingsToStore(
                    domainName + ':group.' + collectionName,
                    detail,
                    category
                )
            )
        ).toBeTruthy();
    });
    it('successfully update role settings', async () => {
        let collectionName = 'role1';
        let detail = {};
        let auditRef = 'Updated domain Meta using Athenz UI';
        let _csrf = 'csrf';
        let category = 'role';

        const getState = () => {};
        let myApiMock = {
            putMeta: jest.fn().mockReturnValue(Promise.resolve([])),
        };
        MockApi.setMockApi(myApiMock);
        sinon.spy(myApiMock, 'putMeta');

        const fakeDispatch = sinon.spy();
        await updateSettings(
            domainName,
            detail,
            collectionName,
            _csrf,
            category
        )(fakeDispatch, getState);

        expect(
            myApiMock.putMeta
                .getCall(0)
                .calledWith(
                    domainName,
                    collectionName,
                    detail,
                    auditRef,
                    _csrf,
                    category
                )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                updateSettingsToStore(
                    domainName + ':role.' + collectionName,
                    detail,
                    category
                )
            )
        ).toBeTruthy();
    });
});

describe('addMember method', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('successfully add member to a group', async () => {
        let domainName = 'dom';
        let collectionName = 'group1';
        let category = 'group';
        let member = { memberName: 'member1' };
        let auditRef = 'auditRef';
        let _csrf = 'csrf';

        const getState = () => {};

        jest.spyOn(groupSelector, 'thunkSelectGroup').mockReturnValue(
            singleStoreGroup
        );

        let myApiMock = {
            addMember: jest
                .fn()
                .mockReturnValue(Promise.resolve(singleApiGroupMember)),
        };
        MockApi.setMockApi(myApiMock);
        sinon.spy(myApiMock, 'addMember');

        const fakeDispatch = sinon.spy();
        await addMember(
            domainName,
            collectionName,
            category,
            member,
            auditRef,
            _csrf,
            true
        )(fakeDispatch, getState);
        let check = myApiMock.addMember.getCall(0);
        expect(
            myApiMock.addMember
                .getCall(0)
                .calledWith(
                    domainName,
                    collectionName,
                    member.memberName,
                    member,
                    auditRef,
                    category,
                    _csrf,
                    true
                )
        ).toBeTruthy();
        expect(fakeDispatch.getCall(0).args[0]).toEqual(
            addMemberToStore(
                singleApiGroupMember,
                category,
                domainName + ':group.' + collectionName
            )
        );
    });
    it('successfully add member to a role', async () => {
        let domainName = 'dom';
        let collectionName = 'role1';
        let category = 'role';
        let member = { memberName: 'member1' };
        let auditRef = 'auditRef';
        let _csrf = 'csrf';

        const getState = () => {};

        jest.spyOn(roleSelector, 'thunkSelectRole').mockReturnValue(
            singleStoreRole
        );

        let myApiMock = {
            addMember: jest
                .fn()
                .mockReturnValue(Promise.resolve(singleApiRoleMember)),
        };
        MockApi.setMockApi(myApiMock);
        sinon.spy(myApiMock, 'addMember');

        const fakeDispatch = sinon.spy();
        await addMember(
            domainName,
            collectionName,
            category,
            member,
            auditRef,
            _csrf,
            true
        )(fakeDispatch, getState);
        expect(
            myApiMock.addMember
                .getCall(0)
                .calledWith(
                    domainName,
                    collectionName,
                    member.memberName,
                    member,
                    auditRef,
                    category,
                    _csrf,
                    true
                )
        ).toBeTruthy();
        expect(fakeDispatch.getCall(1).args[0]).toEqual(
            addMemberToStore(
                singleApiRoleMember,
                category,
                domainName + ':role.' + collectionName
            )
        );
    });
    it('successfully add group as a member to a role', async () => {
        let domainName = 'dom';
        let collectionName = 'role1';
        let category = 'role';
        let member = { memberName: 'dom1:group.group1' };
        let auditRef = 'auditRef';
        let _csrf = 'csrf';

        const getState = () => {};

        jest.spyOn(roleSelector, 'thunkSelectRole').mockReturnValue(
            singleStoreRole
        );
        let extendRole = AppUtils.deepClone(singleApiRole);
        extendRole.roleMembers.push(singleGroupAsARoleMember);
        let myApiMock = {
            addMember: jest
                .fn()
                .mockReturnValue(Promise.resolve(singleApiRoleMember)),
            getRole: jest.fn().mockReturnValue(Promise.resolve(extendRole)),
        };
        MockApi.setMockApi(myApiMock);
        sinon.spy(myApiMock, 'addMember');
        sinon.spy(myApiMock, 'getRole');

        const fakeDispatch = sinon.spy();
        await addMember(
            domainName,
            collectionName,
            category,
            member,
            auditRef,
            _csrf,
            true
        )(fakeDispatch, getState);
        expect(
            myApiMock.addMember
                .getCall(0)
                .calledWith(
                    domainName,
                    collectionName,
                    member.memberName,
                    member,
                    auditRef,
                    category,
                    _csrf,
                    true
                )
        ).toBeTruthy();

        expect(
            myApiMock.getRole
                .getCall(0)
                .calledWith(domainName, collectionName, true, false, true)
        ).toBeTruthy();

        expect(fakeDispatch.getCall(1).args[0]).toEqual(
            loadingInProcess('getRole')
        );
        expect(fakeDispatch.getCall(2).args[0]).toEqual(
            loadRole(extendRole, domainName + ':role.' + collectionName)
        );
        expect(fakeDispatch.getCall(3).args[0]).toEqual(
            loadingSuccess('getRole')
        );
    });
});

it('failed to add group as a member to admin role', async () => {
    let domainName = 'dom';
    let collectionName = 'admin';
    let category = 'role';
    let member = { memberName: 'dom1:group.group1' };
    let auditRef = 'auditRef';
    let _csrf = 'csrf';

    const getState = () => {};

    jest.spyOn(roleSelector, 'thunkSelectRole').mockReturnValue({
        name: 'dom:role.admin',
        roleMembers: {
            'user.user3': {
                memberName: 'user.user3',
                approved: true,
                auditRef: 'Updated domain Meta using Athenz UI',
                memberFullName: null,
            },
        },
    });
    let extendRole = AppUtils.deepClone(singleStoreRole);
    extendRole.roleMembers[singleGroupAsARoleMember.memberName] =
        singleGroupAsARoleMember;

    const fakeDispatch = sinon.spy();
    try {
        await addMember(
            domainName,
            collectionName,
            category,
            member,
            auditRef,
            _csrf,
            true
        )(fakeDispatch, getState);
    } catch (e) {
        expect(e.statusCode).toBe(400);
        expect(e.body.message).toEqual(
            'Group principals are not allowed in the admin role'
        );
    }
});
