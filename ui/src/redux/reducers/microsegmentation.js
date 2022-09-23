/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import {
    DELETE_INBOUND,
    DELETE_OUTBOUND,
    LOAD_MICROSEGMENTATION,
    RETURN_MICROSEGMENTATION,
} from '../actions/microsegmentation';
import produce from 'immer';

export const microsegmentation = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_MICROSEGMENTATION: {
            const { inboundOutboundList, domainName } = payload;
            return {
                domainName: domainName,
                inboundOutboundList: inboundOutboundList,
            };
        }
        case DELETE_INBOUND: {
            const { assertionIdx } = payload;
            const newState = produce(state, (draft) => {
                draft.inboundOutboundList.inbound =
                    draft.inboundOutboundList.inbound.filter(
                        (inbound) => inbound.assertionIdx !== assertionIdx
                    );
            });
            return newState;
        }
        case DELETE_OUTBOUND: {
            const { assertionIdx } = payload;
            const newState = produce(state, (draft) => {
                draft.inboundOutboundList.outbound =
                    draft.inboundOutboundList.outbound.filter(
                        (outbound) => outbound.assertionIdx !== assertionIdx
                    );
            });
            return newState;
        }
        case RETURN_MICROSEGMENTATION:
        default:
            return state;
    }
};
