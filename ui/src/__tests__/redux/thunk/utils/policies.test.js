import {
    getPolicyFullName,
    isPolicyContainsAssertion,
    isPolicyContainsAssertionCondition,
    isPolicyContainsAssertionConditions,
} from '../../../../redux/thunks/utils/policies';
import { apiAssertionConditions, modified } from '../../../config/config.test';

const policy = {
    name: 'dom:policy.acl.ows.inbound',
    modified: modified,
    assertions: {
        34567: {
            role: 'dom:role.acl.ows.role1-test1',
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
};

describe('test policies thunk utils', () => {
    it('should return policy full name', () => {
        const domain = 'dom';
        const policyName = 'test';
        expect(getPolicyFullName(domain, policyName)).toEqual(
            domain + ':policy.' + policyName
        );
    });
    describe('test isPolicyContainsAssertion func', () => {
        it('should return true', () => {
            expect(isPolicyContainsAssertion(policy, 98765)).toBe(true);
        });
        it('should return false', () => {
            expect(isPolicyContainsAssertion(policy, 10101)).toBe(false);
        });
    });
    describe('test isPolicyContainsAssertionConditions func', () => {
        it('should return true', () => {
            expect(isPolicyContainsAssertionConditions(policy, 34567)).toBe(
                true
            );
        });
        it('should return false', () => {
            expect(isPolicyContainsAssertionConditions(policy, 98765)).toBe(
                false
            );
        });
    });
    describe('test isPolicyContainsAssertionCondition func', () => {
        it('should return true', () => {
            expect(isPolicyContainsAssertionCondition(policy, 34567, 1)).toBe(
                true
            );
        });
        it('should return false', () => {
            expect(isPolicyContainsAssertionCondition(policy, 34567, 11)).toBe(
                false
            );
        });
    });
});
