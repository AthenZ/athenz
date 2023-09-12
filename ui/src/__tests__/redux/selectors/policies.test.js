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
import {
    apiAssertionConditions,
    domainName,
    expiry,
    modified,
} from '../../config/config.test';
import { configStorePolicies } from '../config/policy.test';
import { _ } from 'lodash';

import {
    selectActivePoliciesOnly,
    selectPolicies,
    selectPoliciesThunk,
    selectPolicy,
    selectPolicyAssertions,
    selectPolicyTags,
    selectPolicyThunk,
    selectPolicyVersion,
    selectPolicyVersionThunk,
} from '../../../redux/selectors/policies';
import { selectRoleTags } from '../../../redux/selectors/roles';

const stateWithPolicies = {
    policies: {
        domainName,
        expiry,
        policies: configStorePolicies,
    },
};
const stateWithoutPolicies = {
    policies: {},
};

const policyList = [
    {
        name: 'dom:policy.admin',
        modified: modified,
        assertions: {
            17100: {
                role: 'dom:role.admin',
                resource: 'dom:*',
                action: '*',
                effect: 'ALLOW',
                id: 17100,
            },
        },
        version: '0',
        active: true,
    },
    {
        name: 'dom:policy.acl.ows.inbound',
        modified: modified,
        assertions: {
            34567: {
                role: 'dom:role.acl.ows.inbound-test1',
                resource: 'dom:ows',
                action: 'TCP-IN:1024-65535:4443-4443',
                effect: 'ALLOW',
                id: 34567,
                conditions: apiAssertionConditions,
            },
            98765: {
                role: 'dom:role.role1',
                resource: 'dom:test',
                action: '*',
                effect: 'ALLOW',
                id: 98765,
            },
        },
        version: '0',
        active: true,
    },
    {
        name: 'dom:policy.acl.ows.outbound',
        modified: modified,
        tags: { tag: { list: ['tag1'] }, tag2: { list: ['tag3'] } },
        assertions: {
            76543: {
                role: 'dom:role.acl.ows.outbound-test2',
                resource: 'dom:ows',
                action: 'TCP-OUT:1024-65535:4443-4443',
                effect: 'ALLOW',
                id: 76543,
                conditions: apiAssertionConditions,
            },
        },
        version: '0',
        active: true,
    },
    {
        name: 'dom:policy.policy1',
        modified: modified,
        assertions: {
            17326: {
                role: 'dom:role.role1',
                resource: 'dom:test',
                action: '*',
                effect: 'ALLOW',
                id: 17326,
            },
        },
        version: '1',
        active: true,
    },
    {
        name: 'dom:policy.policy1',
        modified: modified,
        tags: { tag: { list: ['tag1', 'tag2'] }, tag2: { list: ['tag3'] } },
        assertions: {
            17379: {
                role: 'dom:role.role2',
                resource: 'dom:test2',
                action: '*',
                effect: 'DENY',
                id: 17379,
            },
        },
        version: '2',
        active: false,
    },
    {
        name: 'dom:policy.policy2',
        modified: modified,
        assertions: {
            17380: {
                role: 'dom:role.role3',
                resource: 'dom:testing',
                action: '*',
                effect: 'DENY',
                id: 17380,
            },
            17390: {
                role: 'dom:role.role4',
                resource: 'dom:resource2',
                action: '*',
                effect: 'DENY',
                id: 17390,
            },
        },
        version: '0',
        active: false,
    },
];

const activePoliciesOnly = [
    {
        name: 'dom:policy.admin',
        modified: modified,
        assertions: {
            17100: {
                role: 'dom:role.admin',
                resource: 'dom:*',
                action: '*',
                effect: 'ALLOW',
                id: 17100,
            },
        },
        version: '0',
        active: true,
    },
    {
        name: 'dom:policy.acl.ows.inbound',
        modified: modified,
        assertions: {
            34567: {
                role: 'dom:role.acl.ows.inbound-test1',
                resource: 'dom:ows',
                action: 'TCP-IN:1024-65535:4443-4443',
                effect: 'ALLOW',
                id: 34567,
                conditions: apiAssertionConditions,
            },
            98765: {
                role: 'dom:role.role1',
                resource: 'dom:test',
                action: '*',
                effect: 'ALLOW',
                id: 98765,
            },
        },
        version: '0',
        active: true,
    },
    {
        name: 'dom:policy.acl.ows.outbound',
        modified: modified,
        tags: { tag: { list: ['tag1'] }, tag2: { list: ['tag3'] } },
        assertions: {
            76543: {
                role: 'dom:role.acl.ows.outbound-test2',
                resource: 'dom:ows',
                action: 'TCP-OUT:1024-65535:4443-4443',
                effect: 'ALLOW',
                id: 76543,
                conditions: apiAssertionConditions,
            },
        },
        version: '0',
        active: true,
    },
    {
        name: 'dom:policy.policy1',
        modified: modified,
        assertions: {
            17326: {
                role: 'dom:role.role1',
                resource: 'dom:test',
                action: '*',
                effect: 'ALLOW',
                id: 17326,
            },
        },
        version: '1',
        active: true,
    },
];

describe('test selectPoliciesThunk', () => {
    it('should select policies as object', () => {
        expect(
            _.isEqual(
                selectPoliciesThunk(stateWithPolicies),
                configStorePolicies
            )
        ).toBeTruthy();
    });
    it('should return empty object', () => {
        expect(
            _.isEqual(selectPoliciesThunk(stateWithoutPolicies), {})
        ).toBeTruthy();
    });
});

describe('test selectPolicies', () => {
    it('should select policies as list', () => {
        expect(selectPolicies(stateWithPolicies)).toEqual(policyList);
    });
    it('should return empty list', () => {
        expect(selectPolicies(stateWithoutPolicies)).toEqual([]);
    });
});

describe('test selectOnlyActivePolicies', () => {
    it('should select active policies only', () => {
        expect(selectActivePoliciesOnly(stateWithPolicies)).toEqual(
            activePoliciesOnly
        );
    });
});

describe('test selectPolicy', () => {
    it('should select policy', () => {
        const policy = {
            name: 'dom:policy.policy1',
            modified: modified,
            assertions: [
                {
                    role: 'dom:role.role1',
                    resource: 'dom:test',
                    action: '*',
                    effect: 'ALLOW',
                    id: 17326,
                },
            ],
            version: '1',
            active: true,
        };
        expect(
            _.isEqual(
                selectPolicy(stateWithPolicies, domainName, 'policy1'),
                policy
            )
        ).toBeTruthy();
    });
    it('should return null', () => {
        expect(
            _.isEqual(
                selectPolicy(stateWithPolicies, domainName, 'not_exists'),
                null
            )
        ).toBeTruthy();
    });
});

describe('test selectPolicyThunk', () => {
    it('should return policy', () => {
        const policy = {
            name: 'dom:policy.policy1',
            modified: modified,
            assertions: {
                17326: {
                    role: 'dom:role.role1',
                    resource: 'dom:test',
                    action: '*',
                    effect: 'ALLOW',
                    id: 17326,
                },
            },
            version: '1',
            active: true,
        };
        expect(
            _.isEqual(
                selectPolicyThunk(stateWithPolicies, domainName, 'policy1'),
                policy
            )
        ).toBeTruthy();
    });
    it('should return null', () => {
        expect(
            _.isEqual(
                selectPolicyThunk(stateWithPolicies, domainName, 'not_exists'),
                null
            )
        ).toBeTruthy();
    });
});

describe('test selectPolicyVersion', () => {
    it('should return policy', () => {
        const policy = {
            name: 'dom:policy.policy1',
            tags: { tag: { list: ['tag1', 'tag2'] }, tag2: { list: ['tag3'] } },
            modified: modified,
            assertions: [
                {
                    role: 'dom:role.role2',
                    resource: 'dom:test2',
                    action: '*',
                    effect: 'DENY',
                    id: 17379,
                },
            ],
            version: '2',
            active: false,
        };
        expect(
            selectPolicyVersion(stateWithPolicies, domainName, 'policy1', '2')
        ).toEqual(policy);
    });
    it('should return null', () => {
        expect(
            _.isEqual(
                selectPolicyVersion(
                    stateWithPolicies,
                    domainName,
                    'policy1',
                    'not_exists'
                ),
                null
            )
        ).toBeTruthy();
    });
});

describe('test selectPolicyVersionThunk', () => {
    it('should return policy', () => {
        const policy = {
            name: 'dom:policy.policy1',
            modified: modified,
            tags: { tag: { list: ['tag1', 'tag2'] }, tag2: { list: ['tag3'] } },
            assertions: {
                17379: {
                    role: 'dom:role.role2',
                    resource: 'dom:test2',
                    action: '*',
                    effect: 'DENY',
                    id: 17379,
                },
            },
            version: '2',
            active: false,
        };
        expect(
            selectPolicyVersionThunk(
                stateWithPolicies,
                domainName,
                'policy1',
                '2'
            )
        ).toEqual(policy);
    });
    it('should return null', () => {
        expect(
            _.isEqual(
                selectPolicyVersionThunk(
                    stateWithPolicies,
                    domainName,
                    'policy1',
                    'not_exists'
                ),
                null
            )
        ).toBeTruthy();
    });
});

describe('test selectPolicyAssertions', () => {
    it('should return assertions', () => {
        const assertions = [
            {
                role: 'dom:role.admin',
                resource: 'dom:*',
                action: '*',
                effect: 'ALLOW',
                id: 17100,
            },
        ];
        expect(
            _.isEqual(
                selectPolicyAssertions(stateWithPolicies, domainName, 'admin'),
                assertions
            )
        ).toBeTruthy();
    });
    it('should return empty list', () => {
        expect(
            selectPolicyAssertions(stateWithoutPolicies, domainName, 'admin')
        ).toEqual([]);
    });
});
describe('test selectPolicyTags selector', () => {
    it('should return policy with version tags', () => {
        const expectedRoleTags = {
            tag: { list: ['tag1', 'tag2'] },
            tag2: { list: ['tag3'] },
        };
        expect(
            selectPolicyTags(stateWithPolicies, domainName, 'policy1', '2')
        ).toEqual(expectedRoleTags);
    });
    it('should return without version tags', () => {
        const expectedRoleTags = {
            tag: { list: ['tag1'] },
            tag2: { list: ['tag3'] },
        };
        expect(
            selectPolicyTags(stateWithPolicies, domainName, 'acl.ows.outbound')
        ).toEqual(expectedRoleTags);
    });
    it('should return empty object', () => {
        expect(
            selectPolicyTags(stateWithPolicies, domainName, 'admin')
        ).toEqual([]);
    });
});
