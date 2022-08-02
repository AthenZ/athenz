import {
    ADD_ROLE_TAGS_TO_STORE,
    ADD_ROLE_TO_STORE,
    DELETE_ROLE_FROM_STORE,
    LOAD_ROLE,
    LOAD_ROLES,
    MAKE_ROLES_EXPIRES,
    RETURN_ROLES,
} from '../../../redux/actions/roles';
import { roles } from '../../../redux/reducers/roles';
import { _ } from 'lodash';
import {
    domainName,
    expiry,
    singleStoreRole,
    storeRoles,
} from '../../config/config.test';
import AppUtils from '../../../components/utils/AppUtils';
import {
    ADD_MEMBER_TO_STORE,
    DELETE_MEMBER_FROM_STORE,
    UPDATE_SETTING_TO_STORE,
    UPDATE_TAGS_TO_STORE,
} from '../../../redux/actions/collections';
import { PROCESS_PENDING_MEMBERS_TO_STORE } from '../../../redux/actions/domains';

const utils = require('../../../redux/utils');

const member = {
    memberName: 'user.user4',
    expiration: '',
    reviewReminder: '',
    approved: true,
};

const roleSetting = {
    reviewEnabled: true,
    selfServe: false,
    memberExpiryDays: '50',
    memberReviewDays: '20',
    groupExpiryDays: '',
    groupReviewDays: '',
    serviceExpiryDays: '30',
    serviceReviewDays: '',
    tokenExpiryMins: '',
    certExpiryMins: '',
    roleCertExpiryMins: '',
    userAuthorityFilter: '',
    userAuthorityExpiration: '',
};

describe('Roles Reducer', () => {
    afterAll(() => {
        jest.spyOn(utils, 'getExpiredTime').mockRestore();
    });
    it('should load the roles into the store', () => {
        const initialState = {};
        const action = {
            type: LOAD_ROLES,
            payload: {
                roles: storeRoles,
                domainName: domainName,
                expiry: expiry,
            },
        };
        const expectedState = {
            roles: storeRoles,
            domainName: domainName,
            expiry: expiry,
        };
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should load a role into the store', () => {
        const initialState = {
            roles: {},
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: LOAD_ROLE,
            payload: {
                roleData: singleStoreRole,
                roleName: 'singlerole',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.roles['singlerole'] = singleStoreRole;
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should add role to the store', () => {
        const initialState = {
            roles: storeRoles,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: ADD_ROLE_TO_STORE,
            payload: {
                roleData: singleStoreRole,
                roleName: 'singlerole',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.roles['singlerole'] = singleStoreRole;
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete role', () => {
        const initialState = {
            roles: storeRoles,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: DELETE_ROLE_FROM_STORE,
            payload: {
                roleName: 'dom:role.role1',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        delete expectedState.roles['dom:role.role1'];
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should edit tags from expiration', () => {
        const initialState = {
            roles: storeRoles,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_TAGS_TO_STORE,
            payload: {
                collectionName: 'dom:role.expiration',
                collectionTags: { tag: { list: ['tag4', 'tag5'] } },
                category: 'role',
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        expectedState.roles['dom:role.expiration'].tags = {
            tag: { list: ['tag4', 'tag5'] },
        };
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should add role tag the store', () => {
        const initialState = {
            roles: storeRoles,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_TAGS_TO_STORE,
            payload: {
                collectionName: 'dom:role.role1',
                collectionTags: { tag: { list: ['tag1', 'tag2'] } },
                category: 'role',
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        expectedState.roles['dom:role.role1'].tags = {
            tag: { list: ['tag1', 'tag2'] },
        };
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete and edit role tag from store', () => {
        const initialState = {
            roles: storeRoles,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_TAGS_TO_STORE,
            payload: {
                collectionName: 'dom:role.expiration',
                collectionTags: { tag: { list: ['tag1'] } },
                category: 'role',
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        expectedState.roles['dom:role.expiration'].tags = {
            tag: { list: ['tag1'] },
        };
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should update role setting to store', () => {
        const initialState = {
            roles: storeRoles,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_SETTING_TO_STORE,
            payload: {
                collectionName: 'dom:role.expiration',
                collectionSettings: roleSetting,
                category: 'role',
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        expectedState.roles['dom:role.expiration'] = {
            ...expectedState.roles['dom:role.expiration'],
            ...roleSetting,
        };
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should add member to role1 in the store', () => {
        const initialState = {
            roles: storeRoles,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: ADD_MEMBER_TO_STORE,
            payload: {
                member: member,
                category: 'role',
                collectionName: 'dom:role.role1',
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        expectedState.roles['dom:role.role1'].roleMembers['user.user4'] =
            member;
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete member from role1 from the store', () => {
        const initialState = {
            roles: storeRoles,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: DELETE_MEMBER_FROM_STORE,
            payload: {
                memberName: 'user.user1',
                category: 'role',
                collectionName: 'dom:role.role1',
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        delete expectedState.roles['dom:role.role1'].roleMembers['user.user1'];
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    // TODO roy - finish it whn we fix the function
    // it('should review role1 from the store', () => {
    //     const initialState = {
    //         roles: storeRoles,
    //         domainName: domainName,
    //         expiry: expiry,
    //     };
    //     const action = {
    //         type: DELETE_MEMBER_FROM_STORE,
    //         payload: {
    //             memberName: 'user.user1',
    //             category: 'role',
    //             collectionName: 'dom:role.role1',
    //         },
    //     };
    //     let expectedState = AppUtils.deepClone(initialState);
    //     delete expectedState.roles['dom:role.role1'].roleMembers['user.user1'];
    //     const newState = roles(initialState, action);
    //     expect(_.isEqual(newState, expectedState)).toBeTruthy();
    // });
    it('should approve pending member user.user4 from expiration role', () => {
        let memberShip = {
            approved: true,
            expiration: '2022-09-27T10:10:33.431Z',
            memberName: 'user.user4',
            reviewReminder: undefined,
        };
        const initialState = {
            roles: storeRoles,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: PROCESS_PENDING_MEMBERS_TO_STORE,
            payload: {
                roleName: 'dom:role.expiration',
                member: memberShip,
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        expectedState.roles['dom:role.expiration'].roleMembers[
            'user.user4'
        ].approved = true;
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should deny pending member user.user4 from expiration role', () => {
        let memberShip = {
            approved: false,
            expiration: '2022-09-27T10:10:33.431Z',
            memberName: 'user.user4',
            reviewReminder: undefined,
        };
        const initialState = {
            roles: storeRoles,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: PROCESS_PENDING_MEMBERS_TO_STORE,
            payload: {
                roleName: 'dom:role.expiration',
                member: memberShip,
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        delete expectedState.roles['dom:role.expiration'].roleMembers[
            'user.user4'
        ];
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should make roles expires', () => {
        jest.spyOn(utils, 'getExpiredTime').mockReturnValue(-1);
        const initialState = {
            roles: storeRoles,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: MAKE_ROLES_EXPIRES,
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.expiry = -1;
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should return same state', () => {
        const initialState = {
            roles: storeRoles,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: RETURN_ROLES,
        };
        const expectedState = AppUtils.deepClone(initialState);
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
});
