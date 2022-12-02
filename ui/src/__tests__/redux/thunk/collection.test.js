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
import { getExpiryTime } from '../../../redux/utils';
import { _ } from 'lodash';
import {
    addMemberToStore,
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

const groupsThunk = require('../../../redux/thunks/groups');
const rolesThunk = require('../../../redux/thunks/roles');
const groupSelector = require('../../../redux/selectors/group');
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
        expect(fakeDispatch.getCall(2).args[0]).toEqual(
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
        expect(fakeDispatch.getCall(2).args[0]).toEqual(
            deleteMemberFromStore('member1', 'role', 'dom:role.role1')
        );
    });
});

describe('updateTags method', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('successfully update group tag', async () => {
        let collectionName = 'group1';
        let detail = { tags: ['tag1', 'tag2'] };
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
        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                updateTagsToStore(
                    domainName + ':group.' + collectionName,
                    detail.tags,
                    category
                )
            )
        ).toBeTruthy();
    });
    it('successfully update role tag', async () => {
        let collectionName = 'role1';
        let detail = { tags: ['tag1', 'tag2'] };
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
        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                updateTagsToStore(
                    domainName + ':role.' + collectionName,
                    detail.tags,
                    category
                )
            )
        ).toBeTruthy();
    });
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
        let extendRole = AppUtils.deepClone(singleStoreRole);
        extendRole.roleMembers[singleGroupAsARoleMember.memberName] =
            singleGroupAsARoleMember;

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

    jest.spyOn(roleSelector, 'thunkSelectRole').mockReturnValue(
        {
            name: 'dom:role.admin',
            roleMembers: {
                'user.user3': {
                    memberName: 'user.user3',
                    approved: true,
                    auditRef: 'Updated domain Meta using Athenz UI',
                    memberFullName: null,
                },
            }
        }
    );
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
        )(fakeDispatch, getState)
    } catch (e) {
        expect(e.statusCode).toBe(400)
        expect(e.body.message).toEqual('Group principals are not allowed in the admin role')
    }
});
