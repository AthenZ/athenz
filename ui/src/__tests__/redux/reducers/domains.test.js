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
import { _ } from 'lodash';
import {
    ADD_DOMAIN_TO_USER_DOMAINS_LIST,
    DELETE_DOMAIN_FROM_USER_DOMAINS_LIST,
    LOAD_ALL_DOMAINS_LIST,
    LOAD_AUTHORITY_ATTRIBUTES,
    LOAD_BUSINESS_SERVICES_ALL,
    LOAD_FEATURE_FLAG,
    LOAD_HEADER_DETAILS,
    LOAD_PENDING_DOMAIN_MEMBERS_LIST,
    LOAD_USER_DOMAINS_LIST,
    PROCESS_ROLE_PENDING_MEMBERS_TO_STORE,
    STORE_DOMAIN_DATA,
    STORE_GROUPS,
    STORE_POLICIES,
    STORE_ROLES,
    STORE_SERVICE_DEPENDENCIES,
    STORE_SERVICES,
} from '../../../redux/actions/domains';
import { singleStorePolicy, configStorePolicies } from '../config/policy.test';
import { domains } from '../../../redux/reducers/domains';
import AppUtils from '../../../components/utils/AppUtils';
import { singleStoreGroup, configStoreGroups } from '../config/group.test';
import {
    singleStoreService,
    configStoreServices,
} from '../config/service.test';
import { apiServiceDependenciesData } from '../../config/config.test';

import { singleStoreRole, configStoreRoles } from '../config/role.test';
import { UPDATE_BELL_PENDING_MEMBERS } from '../../../redux/actions/domain-data';
import {
    configAuthorityAttributes,
    configHeaderDetails,
} from '../config/domains.test';
import { storeDomainData } from '../config/domainData.test';

const userDomains = [
    { name: 'userDomain1', adminDomain: true },
    { name: 'UserDomain2', adminDomain: false },
];
describe('Domains Reducer', () => {
    it('should load the user domains', () => {
        const initialState = {};
        const action = {
            type: LOAD_USER_DOMAINS_LIST,
            payload: {
                domainsList: userDomains,
            },
        };
        const expectedState = {
            domainsList: userDomains,
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should load all Business Services', () => {
        const businessServicesAll = [
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
            {
                value: '00332fa013124f40c0eebb722244b0ce',
                name: 'MapQuest > Search > SDI > Database Hosts',
            },
            {
                value: '00361d370ff95b8023cf3b5be1050ec5',
                name: 'Oath > AWS > aws-oath-dragonfly-dev',
            },
            { value: '003faeb9139a0300c0eebb722244b081', name: 'set' },
        ];
        const initialState = {};
        const action = {
            type: LOAD_BUSINESS_SERVICES_ALL,
            payload: {
                businessServicesAll,
            },
        };
        const expectedState = {
            businessServicesAll,
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should add domain to the user domains list', () => {
        const initialState = { domainsList: userDomains };
        const action = {
            type: ADD_DOMAIN_TO_USER_DOMAINS_LIST,
            payload: {
                name: 'userDomain3',
                adminDomain: false,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.domainsList.push({
            name: 'userDomain3',
            adminDomain: false,
        });
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should create the domainList and add domain to it', () => {
        const initialState = {};
        const action = {
            type: ADD_DOMAIN_TO_USER_DOMAINS_LIST,
            payload: {
                name: 'userDomain3',
                adminDomain: false,
            },
        };
        const expectedState = { domainsList: [] };
        expectedState.domainsList.push({
            name: 'userDomain3',
            adminDomain: false,
        });
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete domain from the user domains list', () => {
        const initialState = { domainsList: userDomains };
        const action = {
            type: DELETE_DOMAIN_FROM_USER_DOMAINS_LIST,
            payload: {
                domainName: 'userDomain1',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.domainsList = expectedState.domainsList.filter(
            (domain) => domain.name !== 'userDomain1'
        );
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should load all domains list', () => {
        const initialState = {};
        const action = {
            type: LOAD_ALL_DOMAINS_LIST,
            payload: {
                allDomainsList: userDomains,
            },
        };
        const expectedState = {
            allDomainsList: userDomains,
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should replace the original roles with new roles', () => {
        const initialState = {
            domain1: {
                roles: { domainName: 'domain2', roles: singleStoreRole },
            },
        };
        let myStoreRoles = {
            domainName: 'domain1',
            roles: configStoreRoles,
        };
        const action = {
            type: STORE_ROLES,
            payload: {
                rolesData: myStoreRoles,
            },
        };
        const expectedState = {
            domain1: {
                roles: { domainName: 'domain1', roles: configStoreRoles },
            },
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should store the role in a non exiting domain', () => {
        const initialState = {};
        let myStoreRoles = {
            domainName: 'domain1',
            roles: configStoreRoles,
        };
        const action = {
            type: STORE_ROLES,
            payload: {
                rolesData: myStoreRoles,
            },
        };
        const expectedState = {
            domain1: {
                roles: { domainName: 'domain1', roles: configStoreRoles },
            },
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should replace the original domainData with new domainData', () => {
        const initialState = {
            domain1: {
                domainData: {
                    domainName: 'domain1',
                    domainData: { data: 'somedata' },
                },
            },
        };
        let myStoreDomainData = {
            domainName: 'domain1',
            domainData: storeDomainData,
        };
        const action = {
            type: STORE_DOMAIN_DATA,
            payload: {
                domainData: myStoreDomainData,
            },
        };
        const expectedState = {
            domain1: {
                domainData: {
                    domainName: 'domain1',
                    domainData: storeDomainData,
                },
            },
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should store the domainData in a non exiting domain', () => {
        const initialState = {};
        let myStoreDomainData = {
            domainName: 'domain1',
            domainData: storeDomainData,
        };
        const action = {
            type: STORE_DOMAIN_DATA,
            payload: {
                domainData: myStoreDomainData,
            },
        };
        const expectedState = {
            domain1: {
                domainData: {
                    domainName: 'domain1',
                    domainData: storeDomainData,
                },
            },
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should replace the original groups with new groups', () => {
        const initialState = {
            domain1: {
                groups: { domainName: 'domain1', groups: singleStoreGroup },
            },
        };
        let myStoreGroups = {
            domainName: 'domain1',
            groups: configStoreGroups,
        };
        const action = {
            type: STORE_GROUPS,
            payload: {
                groupsData: myStoreGroups,
            },
        };
        const expectedState = {
            domain1: {
                groups: { domainName: 'domain1', groups: configStoreGroups },
            },
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should store the groups in a non exiting domain', () => {
        const initialState = {};
        let myStoreGroups = {
            domainName: 'domain1',
            groups: configStoreGroups,
        };
        const action = {
            type: STORE_GROUPS,
            payload: {
                groupsData: myStoreGroups,
            },
        };
        const expectedState = {
            domain1: {
                groups: { domainName: 'domain1', groups: configStoreGroups },
            },
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should replace the original services with new services', () => {
        const initialState = {
            domain1: {
                services: {
                    domainName: 'domain1',
                    services: singleStoreService,
                },
            },
        };
        let myStoreServices = {
            domainName: 'domain1',
            services: configStoreServices,
        };
        const action = {
            type: STORE_SERVICES,
            payload: {
                servicesData: myStoreServices,
            },
        };
        const expectedState = {
            domain1: {
                services: {
                    domainName: 'domain1',
                    services: configStoreServices,
                },
            },
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should store the services in a non exiting domain', () => {
        const initialState = {};
        let myStoreServices = {
            domainName: 'domain1',
            services: configStoreServices,
        };
        const action = {
            type: STORE_SERVICES,
            payload: {
                servicesData: myStoreServices,
            },
        };
        const expectedState = {
            domain1: {
                services: {
                    domainName: 'domain1',
                    services: configStoreServices,
                },
            },
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should replace the original policies with new policies', () => {
        const initialState = {
            domain1: {
                policies: {
                    domainName: 'domain1',
                    policies: singleStorePolicy,
                },
            },
        };
        let myStorePolicies = {
            domainName: 'domain1',
            policies: configStorePolicies,
        };
        const action = {
            type: STORE_POLICIES,
            payload: {
                policiesData: myStorePolicies,
            },
        };
        const expectedState = {
            domain1: {
                policies: {
                    domainName: 'domain1',
                    policies: configStorePolicies,
                },
            },
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should store the policies in a non exiting domain', () => {
        const initialState = {};
        let myStorePolicies = {
            domainName: 'domain1',
            policies: configStorePolicies,
        };
        const action = {
            type: STORE_POLICIES,
            payload: {
                policiesData: myStorePolicies,
            },
        };
        const expectedState = {
            domain1: {
                policies: {
                    domainName: 'domain1',
                    policies: configStorePolicies,
                },
            },
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should replace the original serviceDependenciesData with new serviceDependenciesData', () => {
        const initialState = {
            domain1: {
                serviceDependenciesData: {
                    domainName: 'domain1',
                    serviceDependenciesData: {
                        data: 'someServiceDependenciesData',
                    },
                },
            },
        };
        let myStoreServiceDependenciesData = {
            domainName: 'domain1',
            serviceDependenciesData: apiServiceDependenciesData,
        };
        const action = {
            type: STORE_SERVICE_DEPENDENCIES,
            payload: {
                serviceDependenciesData: myStoreServiceDependenciesData,
            },
        };
        const expectedState = {
            domain1: {
                serviceDependenciesData: {
                    domainName: 'domain1',
                    serviceDependenciesData: apiServiceDependenciesData,
                },
            },
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should store the serviceDependenciesData in a non exiting domain', () => {
        const initialState = {};
        let myStoreServiceDependenciesData = {
            domainName: 'domain1',
            serviceDependenciesData: apiServiceDependenciesData,
        };
        const action = {
            type: STORE_SERVICE_DEPENDENCIES,
            payload: {
                serviceDependenciesData: myStoreServiceDependenciesData,
            },
        };
        const expectedState = {
            domain1: {
                serviceDependenciesData: {
                    domainName: 'domain1',
                    serviceDependenciesData: apiServiceDependenciesData,
                },
            },
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should store the domain pending member list in a non exiting domain', () => {
        const initialState = {};
        let pendingMembers = {
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
        };
        const action = {
            type: LOAD_PENDING_DOMAIN_MEMBERS_LIST,
            payload: {
                pendingDomainMembersList: pendingMembers,
                domainName: 'domain1',
            },
        };
        const expectedState = {
            domain1: {
                domainData: {
                    pendingMembersList: { ...pendingMembers },
                },
            },
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete a pending member from the pending member list', () => {
        let pendingMembers = {
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
        };
        const initialState = {
            dom: {
                domainData: {
                    pendingMembersList: { ...pendingMembers },
                },
            },
        };
        const action = {
            type: PROCESS_ROLE_PENDING_MEMBERS_TO_STORE,
            payload: {
                member: { memberName: 'user.user1' },
                domainName: 'dom',
                roleName: 'role1',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        delete expectedState.dom.domainData.pendingMembersList[
            'domuser.user1role1'
        ];
        const newState = domains(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should delete a bell pending member', () => {
        let bellPendingMembers = {
            'dom1:role.redux1user.user1': true,
            'dom2:role.redux2user.user2': true,
        };
        const initialState = {
            dom1: {
                domainData: {
                    bellPendingMembers: { ...bellPendingMembers },
                },
            },
        };
        const action = {
            type: UPDATE_BELL_PENDING_MEMBERS,
            payload: {
                memberName: 'user.user1',
                collection: 'dom1:role.redux1',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        delete expectedState.dom1.domainData.bellPendingMembers[
            'dom1:role.redux1user.user1'
        ];
        const newState = domains(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should add a bell pending member', () => {
        let bellPendingMembers = {
            'dom1:role.redux1user.user1': true,
            'dom2:role.redux2user.user2': true,
        };
        const initialState = {
            dom1: {
                domainData: {
                    bellPendingMembers: { ...bellPendingMembers },
                },
            },
        };
        const action = {
            type: UPDATE_BELL_PENDING_MEMBERS,
            payload: {
                memberName: 'user.user3',
                collection: 'dom1:role.redux3',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.dom1.domainData.bellPendingMembers[
            'dom1:role.redux3user.user3'
        ] = true;
        const newState = domains(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should load header details', () => {
        const initialState = {
            dom1: {
                domainData: {
                    bellPendingMembers: {},
                },
            },
        };
        const action = {
            type: LOAD_HEADER_DETAILS,
            payload: {
                headerDetails: configHeaderDetails,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.headerDetails = configHeaderDetails;
        const newState = domains(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should load authority attributes', () => {
        const initialState = {
            dom1: {
                domainData: {
                    bellPendingMembers: {},
                },
            },
        };
        const action = {
            type: LOAD_AUTHORITY_ATTRIBUTES,
            payload: {
                authorityAttributes: configAuthorityAttributes,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.authorityAttributes = configAuthorityAttributes;
        const newState = domains(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should load feature flag', () => {
        const initialState = {
            dom1: {
                domainData: {
                    bellPendingMembers: {},
                },
            },
        };
        const action = {
            type: LOAD_FEATURE_FLAG,
            payload: {
                featureFlag: true,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.featureFlag = true;
        const newState = domains(initialState, action);
        expect(newState).toEqual(expectedState);
    });
});
