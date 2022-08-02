import { domainName } from '../../config/config.test';
import {
    selectAllDomainsList,
    selectBusinessServicesAll,
    selectPersonalDomain,
    selectUserDomains,
    thunkSelectPendingDomainMembersList,
} from '../../../redux/selectors/domains';

describe('test domains selectors', () => {
    const stateWithDomainsData = {
        domains: {
            domainsList: [
                { name: 'userDomain1', adminDomain: true },
                { name: 'UserDomain2', adminDomain: false },
            ],
            allDomainsList: [
                { name: 'userDomain1', userDomain: true },
                { name: 'UserDomain2', userDomain: false },
                { name: 'UserDomain3', userDomain: false },
            ],
            businessServicesAll: [
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
            ],
            [domainName]: {
                domainData: {
                    pendingDomainMembersList: {
                        'domuser.user2role1': {
                            category: 'role',
                            domainName: 'dom',
                            memberName: 'user.user2',
                            memberNameFull: null,
                            roleName: 'role1',
                            userComment: 'test',
                            auditRef: '',
                            requestPrincipal: 'user.user3',
                            requestPrincipalFull: null,
                            requestTime: '2022-07-17T14:37:48.248Z',
                            expiryDate: null,
                        },
                        'domuser.user3role1': {
                            category: 'role',
                            domainName: 'dom',
                            memberName: 'user.user3',
                            memberNameFull: null,
                            roleName: 'role1',
                            userComment: 'test',
                            auditRef: '',
                            requestPrincipal: 'user.user3',
                            requestPrincipalFull: null,
                            requestTime: '2022-07-17T14:37:20.725Z',
                            expiryDate: null,
                        },
                    },
                },
            },
        },
    };
    const stateWithoutDomainsData = {
        domains: {},
    };
    describe('test thunkSelectPendingDomainMembersList selector', () => {
        it('should return user domains', () => {
            const pendingDomainMembersList = {
                'domuser.user2role1': {
                    category: 'role',
                    domainName: 'dom',
                    memberName: 'user.user2',
                    memberNameFull: null,
                    roleName: 'role1',
                    userComment: 'test',
                    auditRef: '',
                    requestPrincipal: 'user.user3',
                    requestPrincipalFull: null,
                    requestTime: '2022-07-17T14:37:48.248Z',
                    expiryDate: null,
                },
                'domuser.user3role1': {
                    category: 'role',
                    domainName: 'dom',
                    memberName: 'user.user3',
                    memberNameFull: null,
                    roleName: 'role1',
                    userComment: 'test',
                    auditRef: '',
                    requestPrincipal: 'user.user3',
                    requestPrincipalFull: null,
                    requestTime: '2022-07-17T14:37:20.725Z',
                    expiryDate: null,
                },
            };
            expect(
                thunkSelectPendingDomainMembersList(
                    stateWithDomainsData,
                    domainName
                )
            ).toEqual(pendingDomainMembersList);
        });
        it('should return undefined', () => {
            expect(
                thunkSelectPendingDomainMembersList(stateWithoutDomainsData)
            ).toEqual(undefined);
        });
    });
    describe('test selectUserDomains selector', () => {
        it('should return user domains', () => {
            expect(selectUserDomains(stateWithDomainsData)).toEqual([
                { name: 'userDomain1', adminDomain: true },
                { name: 'UserDomain2', adminDomain: false },
            ]);
        });
        it('should return empty list', () => {
            expect(selectUserDomains(stateWithoutDomainsData)).toEqual([]);
        });
    });
    describe('test selectPersonalDomain selector', () => {
        it('should return personal domain', () => {
            expect(
                selectPersonalDomain(stateWithDomainsData, 'userDomain1')
            ).toEqual({
                name: 'userDomain1',
                adminDomain: true,
            });
        });
        it('should return undefined', () => {
            expect(selectPersonalDomain(stateWithoutDomainsData)).toEqual(
                undefined
            );
        });
    });
    describe('test selectBusinessServicesAll selector', () => {
        it('should return all business services', () => {
            const businessServicesAll = [
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
            ];
            expect(selectBusinessServicesAll(stateWithDomainsData)).toEqual(
                businessServicesAll
            );
        });
        it('should return empty list', () => {
            expect(selectBusinessServicesAll(stateWithoutDomainsData)).toEqual(
                []
            );
        });
    });
    describe('test selectAllDomainsList selector', () => {
        it('should return all domains', () => {
            expect(selectAllDomainsList(stateWithDomainsData)).toEqual([
                { name: 'userDomain1', userDomain: true },
                { name: 'UserDomain2', userDomain: false },
                { name: 'UserDomain3', userDomain: false },
            ]);
        });
        it('should return empty list', () => {
            expect(selectAllDomainsList(stateWithoutDomainsData)).toEqual([]);
        });
    });
});
