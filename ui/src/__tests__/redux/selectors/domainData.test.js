import { expiry, domainName, storeDomainData } from '../../config/config.test';
import {
    selectAuthorityAttributes,
    selectDomainAuditEnabled,
    selectDomainData,
    selectDomainTags,
    selectFeatureFlag,
    selectHeaderDetails,
    selectHistoryRows,
    selectPendingMembersList,
    selectProductMasterLink,
    selectUserLink,
} from '../../../redux/selectors/domainData';

describe('test domain data selectors', () => {
    const stateWithDomainData = {
        domainData: {
            domainName,
            expiry,
            domainData: storeDomainData,
        },
    };
    const stateWithoutDomainData = {
        domainData: {
            domainName,
        },
    };
    describe('test selectDomainData selector', () => {
        it('should return domain data', () => {
            expect(selectDomainData(stateWithDomainData)).toEqual(
                storeDomainData
            );
        });
        it('should return empty object', () => {
            expect(selectDomainData(stateWithoutDomainData)).toEqual({});
        });
    });
    describe('test selectDomainAuditEnabled selector', () => {
        it('should return audit enabled', () => {
            let auditEnabled = false;
            expect(selectDomainAuditEnabled(stateWithDomainData)).toEqual(
                auditEnabled
            );
        });
    });
    describe('test selectHeaderDetails selector', () => {
        it('should return header details', () => {
            const headerDetails = {
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
            };
            expect(selectHeaderDetails(stateWithDomainData)).toEqual(
                headerDetails
            );
        });
        it('should return empty object', () => {
            expect(selectHeaderDetails(stateWithoutDomainData)).toEqual({});
        });
    });
    describe('test selectProductMasterLink selector', () => {
        it('should return product master link', () => {
            const productMasterLink = {
                title: 'Product ID',
                url: 'https://productmaster.ouryahoo.com/engineering/product/',
                target: '_blank',
            };
            expect(selectProductMasterLink(stateWithDomainData)).toEqual(
                productMasterLink
            );
        });
        it('should return empty object', () => {
            expect(selectProductMasterLink(stateWithoutDomainData)).toEqual({});
        });
    });
    describe('test selectUserLink selector', () => {
        it('should return user link', () => {
            const userLink = {
                title: 'User Profile',
                url: 'https://thestreet.ouryahoo.com/thestreet/directory?email=test@yahooinc.com',
                target: '_blank',
            };
            expect(selectUserLink(stateWithDomainData)).toEqual(userLink);
        });
        it('should return empty object', () => {
            expect(selectUserLink(stateWithoutDomainData)).toEqual({});
        });
    });
    describe('test selectPendingMembersList selector', () => {
        const domainPendingMembersList = {
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
        it('should return domain pending members list for current domain', () => {
            expect(
                selectPendingMembersList(stateWithDomainData, domainName)
            ).toEqual(domainPendingMembersList);
        });
        it('should return domain pending members list for another domain', () => {
            const state = {
                domainData: {
                    domainName,
                },
                domains: {
                    dom1: {
                        domainData: storeDomainData,
                    },
                },
            };
            expect(selectPendingMembersList(state, 'dom1')).toEqual(
                domainPendingMembersList
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
            expect(selectPendingMembersList(state)).toEqual(userPendingMembers);
        });
        it('should return empty object', () => {
            expect(
                selectPendingMembersList(stateWithoutDomainData, domainName)
            ).toEqual({});
        });
    });
    describe('test selectDomainTags selector', () => {
        it('should return tags', () => {
            const tags = {
                tag1: { list: ['tagValue1', 'tagValue2'] },
                tag2: { list: ['tagValue3'] },
            };
            expect(selectDomainTags(stateWithDomainData)).toEqual(tags);
        });
        it('should return empty object', () => {
            expect(selectDomainTags(stateWithoutDomainData)).toEqual({});
        });
    });
    describe('test selectFeatureFlag selector', () => {
        it('should return true', () => {
            const featureFlag = true;
            expect(selectFeatureFlag(stateWithDomainData)).toEqual(featureFlag);
        });
        it('should return false', () => {
            expect(selectFeatureFlag(stateWithoutDomainData)).toEqual(false);
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
            expect(selectAuthorityAttributes(stateWithDomainData)).toEqual(
                authorityAttributes
            );
        });
        it('should return empty object', () => {
            expect(selectAuthorityAttributes(stateWithoutDomainData)).toEqual(
                {}
            );
        });
    });
});
