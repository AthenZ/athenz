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
    domainName,
    expiry,
    storeInboundOutboundList,
} from '../../config/config.test';
import { _ } from 'lodash';
import {
    DELETE_INBOUND,
    DELETE_OUTBOUND,
    LOAD_MICROSEGMENTATION,
    RETURN_MICROSEGMENTATION,
} from '../../../redux/actions/microsegmentation';
import AppUtils from '../../../components/utils/AppUtils';
import { microsegmentation } from '../../../redux/reducers/microsegmentation';

describe('Microsegmentation Reducer', () => {
    it('should load the microsegmentation in', () => {
        const initialState = {};
        const action = {
            type: LOAD_MICROSEGMENTATION,
            payload: {
                inboundOutboundList: storeInboundOutboundList,
                domainName: domainName,
            },
        };
        const expectedState = {
            inboundOutboundList: storeInboundOutboundList,
            domainName: domainName,
        };
        const newState = microsegmentation(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete inbound', () => {
        const initialState = {
            inboundOutboundList: storeInboundOutboundList,
            domainName: domainName,
        };
        const action = {
            type: DELETE_INBOUND,
            payload: {
                assertionIdx: 17389,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.inboundOutboundList.inbound =
            expectedState.inboundOutboundList.inbound.filter(
                (inbound) => inbound.assertionIdx !== 17389
            );
        const newState = microsegmentation(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete outbound', () => {
        const initialState = {
            inboundOutboundList: storeInboundOutboundList,
            domainName: domainName,
        };
        const action = {
            type: DELETE_OUTBOUND,
            payload: {
                assertionIdx: 17418,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.inboundOutboundList.outbound =
            expectedState.inboundOutboundList.outbound.filter(
                (inbound) => inbound.assertionIdx !== 17418
            );
        const newState = microsegmentation(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should return same state', () => {
        const initialState = {
            inboundOutboundList: storeInboundOutboundList,
            domainName: domainName,
        };
        const action = {
            type: RETURN_MICROSEGMENTATION,
        };
        const expectedState = AppUtils.deepClone(initialState);
        const newState = microsegmentation(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
});
