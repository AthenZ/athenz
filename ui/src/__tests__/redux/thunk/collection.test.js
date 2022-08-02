import MockApi from '../../../mock/MockApi';
import sinon from 'sinon';
import { getExpiryTime } from '../../../redux/utils';
import { _ } from 'lodash';
import {
    deleteMemberFromStore,
    updateSettingsToStore,
    updateTagsToStore,
} from '../../../redux/actions/collections';
import {
    deleteMember,
    updateSettings,
    updateTags,
} from '../../../redux/thunks/collections';

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
            'member1'
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0)).toBeTruthy();
        expect(
            myApiMock.deleteMember
                .getCall(0)
                .calledWith(
                    domainName,
                    'group1',
                    'member1',
                    undefined,
                    false,
                    'group'
                )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                deleteMemberFromStore('member1', 'group', 'dom:group.group1')
            )
        ).toBeTruthy();
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
            'member1'
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0)).toBeTruthy();
        expect(
            myApiMock.deleteMember
                .getCall(0)
                .calledWith(
                    domainName,
                    'role1',
                    'member1',
                    undefined,
                    false,
                    'role'
                )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                deleteMemberFromStore('member1', 'role', 'dom:role.role1')
            )
        ).toBeTruthy();
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
