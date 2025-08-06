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
import { _ } from 'lodash';
import { domainName, storeInboundOutboundList } from '../../config/config.test';
import { singleStorePolicyWithAssertionConditions } from '../config/policy.test';
import sinon from 'sinon';
import {
    deleteInboundFromStore,
    deleteOutboundFromStore,
    loadMicrosegmentation,
} from '../../../redux/actions/microsegmentation';
import {
    deleteTransportRule,
    editMicrosegmentation,
    getInboundOutbound,
} from '../../../redux/thunks/microsegmentation';
import {
    loadingFailed,
    loadingInProcess,
    loadingSuccess,
} from '../../../redux/actions/loading';
import MockApi from '../../../mock/MockApi';
import { deleteAssertionPolicyVersionFromStore } from '../../../redux/actions/policies';
import { getPolicyFullName } from '../../../redux/thunks/utils/policies';
import { deleteRoleFromStore } from '../../../redux/actions/roles';
import { getFullName } from '../../../redux/utils';
import { roleDelimiter } from '../../../redux/config';

const microsegmentationUtils = require('../../../redux/thunks/utils/microsegmentation');
const microsegmentationThunk = require('../../../redux/thunks/microsegmentation');
const policiesThunk = require('../../../redux/thunks/policies');
const rolesThunk = require('../../../redux/thunks/roles');
const servicesThunk = require('../../../redux/thunks/services');
const policiesSelectors = require('../../../redux/selectors/policies');

describe('test getInboundOutbound thunk', () => {
    const getState = () => {};
    beforeAll(() => {
        jest.spyOn(
            microsegmentationUtils,
            'buildInboundOutbound'
        ).mockReturnValue(storeInboundOutboundList);
        jest.spyOn(policiesThunk, 'getPolicies').mockReturnValue(true);
        jest.spyOn(rolesThunk, 'getRoles').mockReturnValue(true);
    });
    afterAll(() => {
        jest.spyOn(
            microsegmentationUtils,
            'buildInboundOutbound'
        ).mockRestore();
        jest.spyOn(policiesThunk, 'getPolicies').mockRestore();
        jest.spyOn(rolesThunk, 'getRoles').mockRestore();
    });

    afterEach(() => {
        jest.spyOn(servicesThunk, 'getServices').mockRestore();
    });

    it('should success load inboundOutboundList', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(servicesThunk, 'getServices').mockReturnValue(true);
        const loadingInProcessAction = loadingInProcess('getInboundOutbound');
        const loadingSuccessAction = loadingSuccess('getInboundOutbound');
        const loadMicrosegmentationAction = loadMicrosegmentation(
            storeInboundOutboundList,
            domainName
        );
        await getInboundOutbound(domainName)(fakeDispatch, getState);
        expect(
            _.isEqual(fakeDispatch.getCall(0).args[0], loadingInProcessAction)
        ).toBeTruthy();
        expect(fakeDispatch.getCall(1).args[0]).toBeTruthy();
        expect(fakeDispatch.getCall(2).args[0]).toBeTruthy();
        expect(fakeDispatch.getCall(3).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(4).args[0],
                loadMicrosegmentationAction
            )
        ).toBeTruthy();
        expect(
            _.isEqual(fakeDispatch.getCall(5).args[0], loadingSuccessAction)
        ).toBeTruthy();
    });
    it('should fail load inboundOutboundList', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(servicesThunk, 'getServices').mockImplementation(() => {
            throw 'failed';
        });
        try {
            await getInboundOutbound(domainName)(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e).toEqual('failed');
        }
    });
});

describe('test editMicrosegmentation thunk', () => {
    const getState = () => {};
    afterEach(() => {
        jest.spyOn(
            microsegmentationUtils,
            'editMicrosegmentationHandler'
        ).mockRestore();
    });
    it('should success edit Microsegmentation', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(
            microsegmentationUtils,
            'editMicrosegmentationHandler'
        ).mockReturnValue(Promise.resolve());
        const loadingInProcessAction = loadingInProcess(
            'editMicrosegmentation'
        );
        const loadingSuccessAction = loadingSuccess('editMicrosegmentation');
        await editMicrosegmentation(
            'dom',
            true,
            true,
            true
        )(fakeDispatch, getState);
        expect(
            _.isEqual(fakeDispatch.getCall(0).args[0], loadingInProcessAction)
        ).toBeTruthy();
        expect(
            _.isEqual(fakeDispatch.getCall(1).args[0], loadingSuccessAction)
        ).toBeTruthy();
    });
    it('should fail edit Microsegmentation', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(
            microsegmentationUtils,
            'editMicrosegmentationHandler'
        ).mockReturnValue(Promise.reject('failed'));
        try {
            await editMicrosegmentation(
                'dom',
                true,
                true,
                true
            )(fakeDispatch, getState);
        } catch (e) {
            expect(e).toEqual('failed');
        }
    });
});

describe('test deleteTransportRule thunk', () => {
    const inboundPolicyName = 'acl.ows.inbound';
    const roleName = 'acl.ows.role1-test1';
    const inboundPolicyFullName = getPolicyFullName(
        domainName,
        inboundPolicyName
    );
    const roleFullName = getFullName(domainName, roleDelimiter, roleName);
    const assertionId = 34567;
    const getState = () => {};
    beforeAll(() => {
        jest.spyOn(policiesThunk, 'getPolicies').mockReturnValue(true);
        jest.spyOn(rolesThunk, 'getRoles').mockReturnValue(true);
    });
    afterAll(() => {
        jest.spyOn(policiesThunk, 'getPolicies').mockRestore();
        jest.spyOn(rolesThunk, 'getRoles').mockRestore();
    });
    afterEach(() => {
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockRestore();
        MockApi.cleanMockApi();
    });
    it('should success delete Transport Rule inbound case', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            singleStorePolicyWithAssertionConditions
        );
        MockApi.setMockApi({
            deleteTransportRule: jest.fn().mockReturnValue(Promise.resolve()),
        });
        const deleteAssertionPolicyVersionAction =
            deleteAssertionPolicyVersionFromStore(
                inboundPolicyFullName,
                '1',
                assertionId
            );
        const deleteRoleAction = deleteRoleFromStore(roleFullName);
        const deleteInboundAction = deleteInboundFromStore(assertionId);
        await deleteTransportRule(
            domainName,
            inboundPolicyName,
            assertionId,
            roleName
        )(fakeDispatch, getState);
        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(fakeDispatch.getCall(1).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                deleteAssertionPolicyVersionAction
            )
        ).toBeTruthy();
        expect(
            _.isEqual(fakeDispatch.getCall(3).args[0], deleteRoleAction)
        ).toBeTruthy();
        expect(
            _.isEqual(fakeDispatch.getCall(4).args[0], deleteInboundAction)
        ).toBeTruthy();
    });
    it('should throw err - policy does not exists', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            null
        );
        try {
            await deleteTransportRule(
                domainName,
                inboundPolicyName,
                assertionId,
                roleName
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(404);
        }
    });
    it('should success delete Transport Rule outbound case', async () => {
        const outboundPolicyName = 'acl.ows.outbound';
        const fakeDispatch = sinon.spy();
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            singleStorePolicyWithAssertionConditions
        );
        MockApi.setMockApi({
            deleteTransportRule: jest.fn().mockReturnValue(Promise.resolve()),
        });
        const deleteAssertionPolicyVersionAction =
            deleteAssertionPolicyVersionFromStore(
                getPolicyFullName(domainName, outboundPolicyName),
                '1',
                assertionId
            );
        const deleteRoleAction = deleteRoleFromStore(roleFullName);
        const deleteOutboundAction = deleteOutboundFromStore(assertionId);
        await deleteTransportRule(
            domainName,
            outboundPolicyName,
            assertionId,
            roleName
        )(fakeDispatch, getState);
        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(fakeDispatch.getCall(1).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                deleteAssertionPolicyVersionAction
            )
        ).toBeTruthy();
        expect(
            _.isEqual(fakeDispatch.getCall(3).args[0], deleteRoleAction)
        ).toBeTruthy();
        expect(
            _.isEqual(fakeDispatch.getCall(4).args[0], deleteOutboundAction)
        ).toBeTruthy();
    });
    it('should throw err - policy does not exists', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            null
        );
        try {
            await deleteTransportRule(
                domainName,
                inboundPolicyName,
                assertionId,
                roleName
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(404);
        }
    });
    it('should throw err from server', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            singleStorePolicyWithAssertionConditions
        );
        MockApi.setMockApi({
            deleteTransportRule: jest.fn().mockReturnValue(
                Promise.reject({
                    body: { message: 'Policy acl.ows.inbound doesnt exist' },
                })
            ),
        });
        try {
            await deleteTransportRule(
                domainName,
                inboundPolicyName,
                assertionId,
                roleName
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.body.message).toEqual(
                'Policy acl.ows.inbound doesnt exist'
            );
        }
    });
});

describe('test createOrUpdateTransportPolicy', () => {
    const getState = () => {};
    const data = {
        category: 'inbound',
        serviceName: 'svc',
        protocol: 'TCP',
        destinationPort: '443',
    };
    const _csrf = 'csrf-token';
    const roleName = 'role1';
    const policyName = 'policy1';
    const domainName = 'dom';

    afterEach(() => {
        jest.spyOn(rolesThunk, 'getRole').mockRestore();
        jest.spyOn(policiesThunk, 'getPolicy').mockRestore();
        jest.spyOn(microsegmentationThunk, 'getInboundOutbound').mockRestore();
        MockApi.cleanMockApi();
    });

    it('should dispatch loading and call dependent thunks on success', async () => {
        const fakeDispatch = sinon.spy();

        // Mock API
        MockApi.setMockApi({
            createOrUpdateTransportPolicy: jest
                .fn()
                .mockResolvedValue({ success: true }),
        });

        // Mock dependent thunks
        jest.spyOn(rolesThunk, 'getRole').mockReturnValue(() =>
            Promise.resolve()
        );
        jest.spyOn(policiesThunk, 'getPolicy').mockReturnValue(() =>
            Promise.resolve()
        );
        jest.spyOn(
            microsegmentationThunk,
            'getInboundOutbound'
        ).mockReturnValue(() => Promise.resolve());

        await microsegmentationThunk.createOrUpdateTransportPolicy(
            domainName,
            data,
            _csrf,
            roleName,
            policyName
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toEqual(
            loadingInProcess('createOrUpdateTransportPolicy')
        );
        expect(fakeDispatch.getCall(4).args[0]).toEqual(
            loadingSuccess('createOrUpdateTransportPolicy')
        );
        expect(rolesThunk.getRole).toHaveBeenCalledWith(
            domainName,
            roleName,
            false,
            true
        );
        expect(policiesThunk.getPolicy).toHaveBeenCalledWith(
            domainName,
            policyName,
            true
        );
    });

    it('should dispatch loadingFailed on API error and not call dependent thunks', async () => {
        const fakeDispatch = sinon.spy();
        const error = new Error('fail');
        MockApi.setMockApi({
            createOrUpdateTransportPolicy: jest.fn().mockRejectedValue(error),
        });

        jest.spyOn(rolesThunk, 'getRole').mockReturnValue(() =>
            Promise.resolve()
        );
        jest.spyOn(policiesThunk, 'getPolicy').mockReturnValue(() =>
            Promise.resolve()
        );
        jest.spyOn(
            microsegmentationThunk,
            'getInboundOutbound'
        ).mockReturnValue(() => Promise.resolve());

        let err;
        try {
            await microsegmentationThunk.createOrUpdateTransportPolicy(
                domainName,
                data,
                _csrf,
                roleName,
                policyName
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            err = e;
            expect(e).toBe(error);
            expect(fakeDispatch.getCall(0).args[0]).toEqual(
                loadingInProcess('createOrUpdateTransportPolicy')
            );
            expect(fakeDispatch.getCall(1).args[0]).toEqual(
                loadingFailed('createOrUpdateTransportPolicy')
            );
            expect(rolesThunk.getRole).not.toHaveBeenCalled();
            expect(policiesThunk.getPolicy).not.toHaveBeenCalled();
        }
        if (!err) {
            throw new Error('Expected error to be thrown');
        }
    });
});

describe('test deleteTransportPolicy', () => {
    const getState = () => {};
    const data = {
        category: 'inbound',
        serviceName: 'svc',
        protocol: 'TCP',
        destinationPort: '443',
    };
    const _csrf = 'csrf-token';
    const domainName = 'dom';
    const serviceName = 'svc';
    const assertionId = 12345;
    const auditRef = 'audit-ref';

    afterEach(() => {
        jest.spyOn(microsegmentationThunk, 'getInboundOutbound').mockRestore();
        MockApi.cleanMockApi();
    });

    it('should successfully call api and resolve without an error', async () => {
        const fakeDispatch = sinon.spy();

        // Mock API
        MockApi.setMockApi({
            deleteTransportPolicy: jest
                .fn()
                .mockResolvedValue({ success: true }),
        });

        jest.spyOn(
            microsegmentationThunk,
            'getInboundOutbound'
        ).mockReturnValue(() => Promise.resolve());

        await microsegmentationThunk.deleteTransportPolicy(
            domainName,
            serviceName,
            assertionId,
            auditRef,
            _csrf
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toEqual(
            loadingInProcess('deleteTransportPolicy')
        );
        expect(fakeDispatch.getCall(2).args[0]).toEqual(
            loadingSuccess('deleteTransportPolicy')
        );
    });

    it('should dispatch loadingFailed on API error', async () => {
        const fakeDispatch = sinon.spy();
        const error = new Error('fail');
        MockApi.setMockApi({
            deleteTransportPolicy: jest.fn().mockRejectedValue(error),
        });

        jest.spyOn(
            microsegmentationThunk,
            'getInboundOutbound'
        ).mockReturnValue(() => Promise.resolve());

        let err;
        try {
            await microsegmentationThunk.deleteTransportPolicy(
                domainName,
                serviceName,
                assertionId,
                auditRef,
                _csrf
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            err = e;
            expect(e).toBe(error);
            expect(fakeDispatch.getCall(0).args[0]).toEqual(
                loadingInProcess('deleteTransportPolicy')
            );
            expect(fakeDispatch.getCall(1).args[0]).toEqual(
                loadingFailed('deleteTransportPolicy')
            );
        }
        if (!err) {
            throw new Error('Expected error to be thrown');
        }
    });
});

describe('test validateMicrosegmentationPolicy', () => {
    const getState = () => {};
    const domainName = 'dom';
    const data = {
        category: 'inbound',
        serviceName: 'svc',
        protocol: 'TCP',
        destinationPort: '443',
    };
    const _csrf = 'csrf-token';

    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('should dispatch loading and success on valid policy', async () => {
        const fakeDispatch = sinon.spy();

        MockApi.setMockApi({
            validateMicrosegmentationPolicy: jest
                .fn()
                .mockResolvedValue({ valid: true }),
        });

        await microsegmentationThunk.validateMicrosegmentationPolicy(
            domainName,
            data,
            _csrf
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toEqual(
            loadingInProcess('validateMicrosegmentationPolicy')
        );
        expect(fakeDispatch.getCall(1).args[0]).toEqual(
            loadingSuccess('validateMicrosegmentationPolicy')
        );
    });

    it('should dispatch loadingFailed on API error', async () => {
        const fakeDispatch = sinon.spy();
        const error = new Error('fail');
        MockApi.setMockApi({
            validateMicrosegmentationPolicy: jest.fn().mockRejectedValue(error),
        });

        let err;
        try {
            await microsegmentationThunk.validateMicrosegmentationPolicy(
                domainName,
                data,
                _csrf
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            err = e;
            expect(e).toBe(error);
            expect(fakeDispatch.getCall(0).args[0]).toEqual(
                loadingInProcess('validateMicrosegmentationPolicy')
            );
            expect(fakeDispatch.getCall(1).args[0]).toEqual(
                loadingFailed('validateMicrosegmentationPolicy')
            );
        }
        if (!err) {
            throw new Error('Expected error to be thrown');
        }
    });
});
