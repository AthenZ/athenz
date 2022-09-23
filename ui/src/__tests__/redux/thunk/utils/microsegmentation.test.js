import {
    buildInboundOutbound,
    editMicrosegmentationHandler,
    getCategoryFromPolicyName,
} from '../../../../redux/thunks/utils/microsegmentation';
import { configStorePolicies } from '../../config/policy.test';
import {
    apiAssertionConditions,
    domainName,
    modified,
} from '../../../config/config.test';
import sinon from 'sinon';
import { configStoreRoles } from '../../config/role.test';
const policiesSelectors = require('../../../../redux/selectors/policies');
const policiesThunk = require('../../../../redux/thunks/policies');
const rolesThunk = require('../../../../redux/thunks/roles');

describe('test microsegmentation thunk utils', () => {
    it('should return category from policy name', () => {
        const policyName = 'dom:policy.acl.ows.inbound';
        expect(getCategoryFromPolicyName(policyName)).toEqual('inbound');
    });
    it('should return inboundOutbound list', () => {
        const state = {
            policies: {
                domainName,
                policies: configStorePolicies,
            },
            roles: {
                domainName,
                roles: configStoreRoles,
            },
        };
        const expectedInboundOutboundList = {
            inbound: [
                {
                    layer: 'TCP',
                    source_port: '1024-65535',
                    destination_port: '4443-4443',
                    conditionsList: [
                        {
                            instance: 'test.com',
                            id: 1,
                            enforcementstate: 'report',
                            assertionId: 34567,
                            policyName: 'dom:policy.acl.ows.inbound',
                        },
                    ],
                    destination_service: 'ows',
                    source_services: ['yamas.api'],
                    assertionIdx: 34567,
                    identifier: 'test1',
                },
            ],
            outbound: [
                {
                    layer: 'TCP',
                    source_port: '1024-65535',
                    destination_port: '4443-4443',
                    conditionsList: [
                        {
                            instance: 'test.com',
                            id: 1,
                            enforcementstate: 'report',
                            assertionId: 76543,
                            policyName: 'dom:policy.acl.ows.outbound',
                        },
                    ],
                    source_service: 'ows',
                    destination_services: ['sys.auth'],
                    assertionIdx: 76543,
                    identifier: 'test2',
                },
            ],
        };
        expect(buildInboundOutbound(domainName, state)).toEqual(
            expectedInboundOutboundList
        );
    });
    describe('test editMicrosegmentationHandler', () => {
        beforeAll(() => {
            jest.spyOn(rolesThunk, 'addRole').mockReturnValue({
                type: 'addRole',
            });
            jest.spyOn(policiesThunk, 'getPolicies').mockReturnValue({
                type: 'getPolicies',
            });
            jest.spyOn(policiesThunk, 'addAssertion').mockReturnValue({
                type: 'addAssertion',
            });
            jest.spyOn(policiesThunk, 'deleteAssertion').mockReturnValue({
                type: 'deleteAssertion',
            });
            jest.spyOn(
                policiesThunk,
                'deleteAssertionConditions'
            ).mockReturnValue({
                type: 'deleteAssertionConditions',
            });
            jest.spyOn(policiesThunk, 'addAssertionConditions').mockReturnValue(
                {
                    type: 'addAssertionConditions',
                }
            );
        });
        afterEach(() => {
            jest.spyOn(policiesSelectors, 'selectPolicy').mockRestore();
        });
        afterAll(() => {
            jest.restoreAllMocks();
        });
        it('should success edit inbound data - role and assertion condition changed', async () => {
            const fakeDispatch = sinon.spy();
            const data = {
                category: 'inbound',
                destination_service: 'ows',
                identifier: 'role1-test1',
                layer: 'TCP',
                source_port: '1024-65535',
                destination_port: '4443-4443',
                source_services: ['sys.auth.zms'],
                conditionsList: [
                    {
                        instance: 'test.com',
                        id: 1,
                        enforcementstate: 'enforcement',
                    },
                ],
                assertionIdx: 34567,
            };
            await editMicrosegmentationHandler(
                domainName,
                true,
                false,
                true,
                data,
                null,
                fakeDispatch,
                {}
            );
            expect(fakeDispatch.getCall(0).args[0]).toEqual({
                type: 'addRole',
            });
            expect(fakeDispatch.getCall(1).args[0]).toEqual({
                type: 'deleteAssertionConditions',
            });
            expect(fakeDispatch.getCall(2).args[0]).toEqual({
                type: 'addAssertionConditions',
            });
        });
        it('should success edit inbound data - assertion changed', async () => {
            const policyToReturn = {
                name: 'dom:policy.acl.ows.inbound',
                modified: modified,
                assertions: [
                    {
                        role: 'dom:role.acl.ows.inbound-test1',
                        resource: 'dom:ows',
                        action: 'TCP-IN:1024-65535:4443-4443',
                        effect: 'ALLOW',
                        id: 34567,
                        conditions: apiAssertionConditions,
                    },
                    {
                        role: 'dom:role.role1',
                        resource: 'dom:test',
                        action: '*',
                        effect: 'ALLOW',
                        id: 98765,
                    },
                ],
                version: '0',
                active: true,
            };
            const assertionToReturn = policyToReturn.assertions[0];
            jest.spyOn(policiesSelectors, 'selectPolicy').mockReturnValue(
                policyToReturn
            );
            const fakeDispatch = sinon.spy();
            const dispatchWrapper = (func) => {
                fakeDispatch(func);
                if (func.type === 'addAssertion') {
                    return assertionToReturn;
                }
            };
            const data = {
                category: 'inbound',
                destination_service: 'ows',
                identifier: 'test1',
                layer: 'UDP',
                source_port: '1024-65535',
                destination_port: '4443-4443',
                source_services: ['yamas.api'],
                conditionsList: [
                    {
                        instance: 'test.com',
                        id: 1,
                        enforcementstate: 'report',
                    },
                ],
                assertionIdx: 34567,
            };
            await editMicrosegmentationHandler(
                domainName,
                false,
                true,
                false,
                data,
                null,
                dispatchWrapper,
                {}
            );
            expect(fakeDispatch.getCall(0).args[0]).toEqual({
                type: 'getPolicies',
            });
            expect(fakeDispatch.getCall(1).args[0]).toEqual({
                type: 'addAssertion',
            });
            expect(fakeDispatch.getCall(2).args[0]).toEqual({
                type: 'addAssertionConditions',
            });
            expect(fakeDispatch.getCall(3).args[0]).toEqual({
                type: 'deleteAssertion',
            });
        });
        it('should fail edit inbound data due foundAssertionMatch', async () => {
            const fakeDispatch = sinon.spy();
            const policyToReturn = {
                name: 'dom:policy.acl.ows.inbound',
                modified: modified,
                assertions: [
                    {
                        role: 'dom:role.acl.ows.inbound-test1',
                        resource: 'dom:ows',
                        action: 'TCP-IN:1024-65535:4443-4443',
                        effect: 'ALLOW',
                        id: 34567,
                        conditions: apiAssertionConditions,
                    },
                    {
                        role: 'dom:role.role1',
                        resource: 'dom:test',
                        action: '*',
                        effect: 'ALLOW',
                        id: 98765,
                    },
                ],
                version: '0',
                active: true,
            };
            jest.spyOn(policiesSelectors, 'selectPolicy').mockReturnValue(
                policyToReturn
            );
            const data = {
                category: 'inbound',
                destination_service: 'ows',
                identifier: 'test1',
                layer: 'TCP',
                source_port: '1024-65535',
                destination_port: '4443-4443',
                source_services: ['yamas.api'],
                conditionsList: [
                    {
                        instance: 'test.com',
                        id: 1,
                        enforcementstate: 'report',
                    },
                ],
                assertionIdx: 34567,
            };
            try {
                await editMicrosegmentationHandler(
                    domainName,
                    false,
                    true,
                    false,
                    data,
                    null,
                    fakeDispatch,
                    {}
                );
                fail();
            } catch (e) {
                expect(e.status).toBe('500');
                expect(e.message.message).toEqual(
                    'Policy with the assertion already exists'
                );
            }
        });
        it('should throw err due deleteAssertionConditions', async () => {
            jest.spyOn(
                policiesThunk,
                'deleteAssertionConditions'
            ).mockReturnValue({
                type: 'deleteAssertionConditions',
            });
            const fakeDispatch = sinon.spy();
            const dispatchWrapper = (func) => {
                fakeDispatch(func);
                if (func.type === 'deleteAssertionConditions') {
                    throw {
                        status: 400,
                    };
                }
            };
            const data = {
                category: 'inbound',
                destination_service: 'ows',
                identifier: 'test1',
                layer: 'TCP',
                source_port: '1024-65535',
                destination_port: '4443-4443',
                source_services: ['yamas.api'],
                conditionsList: [
                    {
                        instance: 'test.com',
                        id: 1,
                        enforcementstate: 'report',
                    },
                ],
                assertionIdx: 34567,
            };
            try {
                await editMicrosegmentationHandler(
                    domainName,
                    false,
                    false,
                    true,
                    data,
                    null,
                    dispatchWrapper,
                    {}
                );
                fail();
            } catch (e) {
                expect(e.status).toBe(400);
            }
        });
        it('should success edit outbound data - role and assertion condition changed', async () => {
            const fakeDispatch = sinon.spy();
            const data = {
                category: 'outbound',
                destination_services: ['yamas.api'],
                identifier: 'test2',
                layer: 'TCP',
                source_port: '1024-65535',
                destination_port: '4443-4443',
                source_service: 'aws',
                conditionsList: [
                    {
                        instance: 'test.com',
                        id: 1,
                        enforcementstate: 'enforcement',
                    },
                ],
                assertionIdx: 76543,
            };
            await editMicrosegmentationHandler(
                domainName,
                true,
                false,
                true,
                data,
                null,
                fakeDispatch,
                {}
            );
            expect(fakeDispatch.getCall(0).args[0]).toEqual({
                type: 'addRole',
            });
            expect(fakeDispatch.getCall(1).args[0]).toEqual({
                type: 'deleteAssertionConditions',
            });
            expect(fakeDispatch.getCall(2).args[0]).toEqual({
                type: 'addAssertionConditions',
            });
        });
    });
});
