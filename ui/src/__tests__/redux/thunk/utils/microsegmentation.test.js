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

    it('should handle service names containing inbound/outbound words correctly', () => {
        const stateWithProblematicServices = {
            policies: {
                domainName,
                policies: {
                    'dom:policy.acl.outbound-api-service.outbound:0': {
                        name: 'dom:policy.acl.outbound-api-service.outbound',
                        assertions: {
                            12345: {
                                id: 12345,
                                action: 'TCP-OUT:1024-65535:4443-4443',
                                role: 'dom:role.acl.outbound-api-service.outbound-to-database',
                                resource: 'dom:outbound-api-service',
                            },
                        },
                        version: '0',
                        active: true,
                    },
                    'dom:policy.acl.internal-inbound-service.outbound:0': {
                        name: 'dom:policy.acl.internal-inbound-service.outbound',
                        assertions: {
                            67890: {
                                id: 67890,
                                action: 'TCP-OUT:1024-65535:4443-4443',
                                role: 'dom:role.acl.internal-inbound-service.outbound-to-external-api',
                                resource: 'dom:internal-inbound-service',
                            },
                        },
                        version: '0',
                        active: true,
                    },
                },
            },
            roles: {
                domainName,
                roles: {
                    'dom:role.acl.outbound-api-service.outbound-to-database': {
                        roleMembers: [{ memberName: 'sys.auth' }],
                    },
                    'dom:role.acl.internal-inbound-service.outbound-to-external-api':
                        {
                            roleMembers: [{ memberName: 'sys.auth' }],
                        },
                },
            },
        };

        const result = buildInboundOutbound(
            domainName,
            stateWithProblematicServices
        );

        // Both policies should be categorized as outbound (not inbound)
        expect(result.inbound).toHaveLength(0);
        expect(result.outbound).toHaveLength(2);

        // Check first policy (outbound-api-service)
        expect(result.outbound[0]).toEqual({
            layer: 'TCP',
            source_port: '1024-65535',
            destination_port: '4443-4443',
            source_service: 'outbound-api-service',
            destination_services: ['sys.auth'],
            assertionIdx: 12345,
            identifier: 'to-database',
        });

        // Check second policy (internal-inbound-service)
        expect(result.outbound[1]).toEqual({
            layer: 'TCP',
            source_port: '1024-65535',
            destination_port: '4443-4443',
            source_service: 'internal-inbound-service',
            destination_services: ['sys.auth'],
            assertionIdx: 67890,
            identifier: 'to-external-api',
        });
    });
});
