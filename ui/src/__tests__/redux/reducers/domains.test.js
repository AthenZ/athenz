import { _ } from 'lodash';
import {
    ADD_DOMAIN_TO_USER_DOMAINS_LIST,
    DELETE_DOMAIN_FROM_USER_DOMAINS_LIST,
    LOAD_ALL_DOMAINS_LIST,
    LOAD_BUSINESS_SERVICES_ALL,
    LOAD_PENDING_DOMAIN_MEMBERS_LIST,
    LOAD_USER_DOMAINS_LIST,
    PROCESS_PENDING_MEMBERS_TO_STORE,
    STORE_DOMAIN_DATA,
    STORE_GROUPS,
    STORE_POLICIES,
    STORE_ROLES,
    STORE_SERVICE_DEPENDENCIES,
    STORE_SERVICES,
} from '../../../redux/actions/domains';
import { domains } from '../../../redux/reducers/domains';
import AppUtils from '../../../components/utils/AppUtils';
import {
    apiServiceDependenciesData,
    singleStoreGroup,
    singleStorePolicy,
    singleStoreRole,
    singleStoreService,
    storeDomainData,
    storeGroups,
    storePolicies,
    storeRoles,
    storeServices,
} from '../../config/config.test';

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
            roles: storeRoles,
        };
        const action = {
            type: STORE_ROLES,
            payload: {
                rolesData: myStoreRoles,
            },
        };
        const expectedState = {
            domain1: { roles: { domainName: 'domain1', roles: storeRoles } },
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should store the role in a non exiting domain', () => {
        const initialState = {};
        let myStoreRoles = {
            domainName: 'domain1',
            roles: storeRoles,
        };
        const action = {
            type: STORE_ROLES,
            payload: {
                rolesData: myStoreRoles,
            },
        };
        const expectedState = {
            domain1: { roles: { domainName: 'domain1', roles: storeRoles } },
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
            groups: storeGroups,
        };
        const action = {
            type: STORE_GROUPS,
            payload: {
                groupsData: myStoreGroups,
            },
        };
        const expectedState = {
            domain1: {
                groups: { domainName: 'domain1', groups: storeGroups },
            },
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should store the groups in a non exiting domain', () => {
        const initialState = {};
        let myStoreGroups = {
            domainName: 'domain1',
            groups: storeGroups,
        };
        const action = {
            type: STORE_GROUPS,
            payload: {
                groupsData: myStoreGroups,
            },
        };
        const expectedState = {
            domain1: {
                groups: { domainName: 'domain1', groups: storeGroups },
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
            services: storeServices,
        };
        const action = {
            type: STORE_SERVICES,
            payload: {
                servicesData: myStoreServices,
            },
        };
        const expectedState = {
            domain1: {
                services: { domainName: 'domain1', services: storeServices },
            },
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should store the services in a non exiting domain', () => {
        const initialState = {};
        let myStoreServices = {
            domainName: 'domain1',
            services: storeServices,
        };
        const action = {
            type: STORE_SERVICES,
            payload: {
                servicesData: myStoreServices,
            },
        };
        const expectedState = {
            domain1: {
                services: { domainName: 'domain1', services: storeServices },
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
            policies: storePolicies,
        };
        const action = {
            type: STORE_POLICIES,
            payload: {
                policiesData: myStorePolicies,
            },
        };
        const expectedState = {
            domain1: {
                policies: { domainName: 'domain1', policies: storePolicies },
            },
        };
        const newState = domains(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should store the policies in a non exiting domain', () => {
        const initialState = {};
        let myStorePolicies = {
            domainName: 'domain1',
            policies: storePolicies,
        };
        const action = {
            type: STORE_POLICIES,
            payload: {
                policiesData: myStorePolicies,
            },
        };
        const expectedState = {
            domain1: {
                policies: { domainName: 'domain1', policies: storePolicies },
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
            type: PROCESS_PENDING_MEMBERS_TO_STORE,
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
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
});
