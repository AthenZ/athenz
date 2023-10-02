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

import AppUtils from '../../components/utils/AppUtils';

export const selectInboundOutboundList = (state) => {
    return state.microsegmentation.inboundOutboundList
        ? AppUtils.deepClone(state.microsegmentation.inboundOutboundList)
        : [];
};

export const selectInboundOutboundListWithFilter = (state, serviceName) => {
    let inboundOutboundList = selectInboundOutboundList(state);

    if (inboundOutboundList === []) {
        return inboundOutboundList;
    }

    let inbound = inboundOutboundList.inbound?.filter(
        (inbound) => inbound.destination_service === serviceName
    );
    let outbound = inboundOutboundList.outbound?.filter(
        (outbound) => outbound.source_service === serviceName
    );
    return { inbound, outbound };
};
