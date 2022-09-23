describe('Domains Config', () => {
    it('should get default config', () => {
        expect(configDom1).not.toBeNull();
    });
});

export const configDom1 = {
    domainData: {
        pendingMembersList: {
            'dom1user.user2role1': {
                category: 'role',
                domainName: 'dom1',
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
            'dom1user.user3role1': {
                category: 'role',
                domainName: 'dom1',
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
};

export const configDom = {
    domainData: {
        pendingMembersList: {
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
};

export const configHeaderDetails = {
    userData: {
        userIcon: 'https://directory.ouryahoo.com/emp_photos/vzm/r/test.jpg',
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

export const configAuthorityAttributes = {
    attributes: {
        date: { values: ['ElevatedClearance'] },
        bool: { values: ['OnShore-US'] },
    },
};

export const configStoreDomains = {
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
        authorityAttributes: configAuthorityAttributes,
        featureFlag: true,
        headerDetails: configHeaderDetails,
        dom: configDom,
        dom1: configDom1,
    },
};
