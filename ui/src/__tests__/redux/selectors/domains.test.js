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
import { domainName } from '../../config/config.test';
import {
    selectAllDomainsList,
    selectBusinessServicesAll,
    selectPersonalDomain,
    selectUserDomains,
    selectAuthorityAttributes,
    selectFeatureFlag,
    selectShowInstances,
    selectShowProviders,
    selectShowMicrosegmentation,
    selectShowCloudAccountDetails,
    selectUserLink,
    selectHeaderDetails,
    selectProductMasterLink,
    selectPendingMembersList,
} from '../../../redux/selectors/domains';
import {
    configDom,
    configDom1,
    configHeaderDetails,
    configStoreDomains,
} from '../config/domains.test';

describe('test domains selectors', () => {
    const stateWithDomainsData = {
        domainName: domainName,
        domains: { ...configStoreDomains.domains },
    };
    const stateWithoutDomainsData = {
        domains: {},
    };
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
    describe('test selectAuthorityAttributes selector', () => {
        it('should return authority attributes', () => {
            const authorityAttributes = {
                attributes: {
                    date: { values: ['ElevatedClearance'] },
                    bool: { values: ['OnShore-US'] },
                },
            };
            expect(selectAuthorityAttributes(stateWithDomainsData)).toEqual(
                authorityAttributes
            );
        });
        it('should return empty object', () => {
            expect(selectAuthorityAttributes(stateWithoutDomainsData)).toEqual(
                {}
            );
        });
    });
    describe('test selectFeatureFlag selector', () => {
        it('should return true for boolean featureFlag', () => {
            expect(selectFeatureFlag(stateWithDomainsData)).toEqual(true);
        });
        it('should return enabled value for object featureFlag', () => {
            const state = {
                domains: {
                    featureFlag: { enabled: true, showInstances: false },
                },
            };
            expect(selectFeatureFlag(state)).toEqual(true);
        });
        it('should return false', () => {
            expect(selectFeatureFlag(stateWithoutDomainsData)).toEqual(false);
        });
    });
    describe('test selectShowInstances selector', () => {
        it('should return true by default', () => {
            expect(selectShowInstances(stateWithDomainsData)).toEqual(true);
        });
        it('should return false when explicitly disabled', () => {
            const state = {
                domains: {
                    featureFlag: { enabled: true, showInstances: false },
                },
            };
            expect(selectShowInstances(state)).toEqual(false);
        });
        it('should return true when not set in object', () => {
            const state = {
                domains: { featureFlag: { enabled: true } },
            };
            expect(selectShowInstances(state)).toEqual(true);
        });
    });
    describe('test selectShowProviders selector', () => {
        it('should return true by default', () => {
            expect(selectShowProviders(stateWithDomainsData)).toEqual(true);
        });
        it('should return false when explicitly disabled', () => {
            const state = {
                domains: {
                    featureFlag: { enabled: true, showProviders: false },
                },
            };
            expect(selectShowProviders(state)).toEqual(false);
        });
    });
    describe('test selectShowMicrosegmentation selector', () => {
        it('should return true by default', () => {
            expect(selectShowMicrosegmentation(stateWithDomainsData)).toEqual(
                true
            );
        });
        it('should return false when explicitly disabled', () => {
            const state = {
                domains: {
                    featureFlag: {
                        enabled: true,
                        showMicrosegmentation: false,
                    },
                },
            };
            expect(selectShowMicrosegmentation(state)).toEqual(false);
        });
    });
    describe('test selectShowCloudAccountDetails selector', () => {
        it('should return true by default', () => {
            expect(
                selectShowCloudAccountDetails(stateWithDomainsData)
            ).toEqual(true);
        });
        it('should return false when explicitly disabled', () => {
            const state = {
                domains: {
                    featureFlag: {
                        enabled: true,
                        showCloudAccountDetails: false,
                    },
                },
            };
            expect(selectShowCloudAccountDetails(state)).toEqual(false);
        });
        it('should return true when not set in object', () => {
            const state = {
                domains: { featureFlag: { enabled: true } },
            };
            expect(selectShowCloudAccountDetails(state)).toEqual(true);
        });
    });
    describe('test selectUserLink selector', () => {
        it('should return user link', () => {
            const userLink = {
                title: 'User Profile',
                url: 'https://thestreet.ouryahoo.com/thestreet/directory?email=test@yahooinc.com',
                target: '_blank',
            };
            expect(selectUserLink(stateWithDomainsData)).toEqual(userLink);
        });
        it('should return empty object', () => {
            expect(selectUserLink(stateWithoutDomainsData)).toEqual({});
        });
    });
    describe('test selectHeaderDetails selector', () => {
        it('should return header details', () => {
            expect(selectHeaderDetails(stateWithDomainsData)).toEqual(
                configHeaderDetails
            );
        });
        it('should return empty object', () => {
            expect(selectHeaderDetails(stateWithoutDomainsData)).toEqual({});
        });
    });

    describe('test selectProductMasterLink selector', () => {
        it('should return product master link', () => {
            const productMasterLink = {
                title: 'Product ID',
                url: 'https://productmaster.ouryahoo.com/engineering/product/',
                target: '_blank',
            };
            expect(selectProductMasterLink(stateWithDomainsData)).toEqual(
                productMasterLink
            );
        });
        it('should return empty object', () => {
            expect(selectProductMasterLink(stateWithoutDomainsData)).toEqual(
                {}
            );
        });
    });
    describe('test selectPendingMembersList selector', () => {
        it('should return domain pending members list for current domain', () => {
            expect(
                selectPendingMembersList(
                    stateWithDomainsData,
                    domainName,
                    'domain'
                )
            ).toEqual(configDom.domainData.pendingMembersList);
        });
        it('should return domain pending members list for another domain', () => {
            const state = {
                domainData: {
                    domainName,
                },
                domains: { ...configStoreDomains.domains },
            };
            expect(selectPendingMembersList(state, 'dom1', 'domain')).toEqual(
                configDom1.domainData.pendingMembersList
            );
        });
        it('should return all pending members list', () => {
            let userPendingMembers = {
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
                'domuser.user4role1': {
                    category: 'role',
                    domainName: 'dom',
                    memberName: 'user.user4',
                    memberNameFull: null,
                    roleName: 'role1',
                    userComment: 'test',
                    auditRef: '',
                    requestPrincipal: 'user.user3',
                    requestPrincipalFull: null,
                    requestTime: '2022-07-17T14:37:34.665Z',
                    expiryDate: null,
                },
                'dom.dom2user.user2role2': {
                    category: 'role',
                    domainName: 'dom.dom2',
                    memberName: 'user.user2',
                    memberNameFull: null,
                    roleName: 'role2',
                    userComment: 'added using Athenz UI',
                    auditRef: '',
                    requestPrincipal: 'user.user1',
                    requestPrincipalFull: null,
                    requestTime: '2022-07-12T14:29:08.384Z',
                    expiryDate: '2022-09-25T14:29:08.374Z',
                },
            };
            const state = {
                user: { pendingMembers: userPendingMembers },
            };
            expect(selectPendingMembersList(state, null, 'admin')).toEqual(
                userPendingMembers
            );
        });
        it('should return empty object', () => {
            expect(
                selectPendingMembersList(stateWithoutDomainsData, domainName)
            ).toEqual({});
        });
    });
});
