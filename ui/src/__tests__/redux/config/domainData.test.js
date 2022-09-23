describe('Domain Data Config', () => {
    it('should get default config', () => {
        expect(storeDomainData).not.toBeNull();
    });
});

export const configDomainHistory = [
    {
        action: 'putrolemeta',
        who: 'user.user1',
        whoFull: 'user1',
        whatEntity: 'dom.user1',
        when: '2022-09-12T05:59:10.965Z',
        details:
            '{"name": "redux", "selfServe": "false", "memberExpiryDays": "null", "serviceExpiryDays": "null", "groupExpiryDays": "null", "tokenExpiryMins": "null", "certExpiryMins": "null", "memberReviewDays": "null", "serviceReviewDays": "null", "groupReviewDays": "null", "reviewEnabled": "true", "notifyRoles": "null", "signAlgorithm": "null", "userAuthorityFilter": "", "userAuthorityExpiration": ""}',
        epoch: 1662962350965,
        why: 'Updated domain Meta using Athenz UI',
    },
    {
        action: 'putrole',
        who: 'user.user1',
        whoFull: 'user1',
        whatEntity: 'redux',
        when: '2022-09-08T10:26:56.582Z',
        details:
            '{"name": "redux", "trust": "null", "added-members": [{"member": "home.user1:group.redux2", "approved": true, "system-disabled": 0}]}',
        epoch: 1662632816582,
        why: 'null',
    },
];

export const storeDomainData = {
    enabled: true,
    auditEnabled: false,
    ypmId: 0,
    memberExpiryDays: 76,
    tags: {
        tag1: { list: ['tagValue1', 'tagValue2'] },
        tag2: { list: ['tagValue3'] },
    },
    name: 'dom',
    modified: '2022-07-25T13:43:05.183Z',
    id: '62bb4f70-f7a5-11ec-8202-e7ae4e1596ac',
    isAWSTemplateApplied: false,
    pendingMembersList: {
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
    },
    businessServices: [],
    history: configDomainHistory,
    bellPendingMembers: {
        'dom1:role.redux1user.user1': true,
        'dom2:role.redux2user.user2': true,
    },
};
