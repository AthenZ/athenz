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
