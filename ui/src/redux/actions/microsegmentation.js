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

export const LOAD_MICROSEGMENTATION = 'LOAD_MICROSEGMENTATION';
export const loadMicrosegmentation = (inboundOutboundList, domainName) => ({
    type: LOAD_MICROSEGMENTATION,
    payload: { inboundOutboundList, domainName },
});

export const RETURN_MICROSEGMENTATION = 'RETURN_MICROSEGMENTATION';
export const returnMicrosegmentation = () => ({
    type: RETURN_MICROSEGMENTATION,
});

export const DELETE_INBOUND = 'DELETE_INBOUND';
export const deleteInboundFromStore = (assertionIdx) => ({
    type: DELETE_INBOUND,
    payload: { assertionIdx },
});

export const DELETE_OUTBOUND = 'DELETE_OUTBOUND';
export const deleteOutboundFromStore = (assertionIdx) => ({
    type: DELETE_OUTBOUND,
    payload: { assertionIdx },
});
