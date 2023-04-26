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
    UPDATE_BELL_PENDING_MEMBERS,
    LOAD_DOMAIN_DATA,
    LOAD_DOMAIN_HISTORY_TO_STORE,
    RETURN_DOMAIN_DATA,
    UPDATE_BUSINESS_SERVICE_IN_STORE,
} from '../actions/domain-data';
import produce from 'immer';
import {
    UPDATE_SETTING_TO_STORE,
    UPDATE_TAGS_TO_STORE,
} from '../actions/collections';

export const domainData = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_DOMAIN_DATA: {
            const { domainData, domainName, expiry } = payload;
            return { domainData, domainName, expiry };
        }
        case UPDATE_SETTING_TO_STORE: {
            const { collectionSettings, category } = payload;
            let newState = state;
            if (category === 'domain') {
                newState = produce(state, (draft) => {
                    draft.domainData = {
                        ...draft.domainData,
                        ...collectionSettings,
                    };
                });
            }
            return newState;
        }
        case UPDATE_TAGS_TO_STORE: {
            const { collectionTags, category } = payload;
            let newState = state;
            if (category === 'domain') {
                newState = produce(state, (draft) => {
                    draft.domainData.tags = collectionTags;
                });
            }
            return newState;
        }
        case UPDATE_BELL_PENDING_MEMBERS: {
            const { memberName, collection } = payload;
            let domainName = collection.split(':')[0];
            let newState = produce(state, (draft) => {
                if (domainName === draft.domainName) {
                    if (!draft.domainData.bellPendingMembers) {
                        draft.domainData.bellPendingMembers = {};
                    }
                    if (
                        draft.domainData.bellPendingMembers[
                            collection + memberName
                        ]
                    ) {
                        delete draft.domainData.bellPendingMembers[
                            collection + memberName
                        ];
                    } else {
                        draft.domainData.bellPendingMembers[
                            collection + memberName
                        ] = true;
                    }
                }
            });
            return newState;
        }
        case LOAD_DOMAIN_HISTORY_TO_STORE: {
            const { history } = payload;
            const newState = produce(state, (draft) => {
                if (draft.domainData) {
                    draft.domainData.history = history;
                }
            });
            return newState;
        }
        case UPDATE_BUSINESS_SERVICE_IN_STORE: {
            const { businessServiceName } = payload;
            const newState = produce(state, (draft) => {
                if (draft.domainData) {
                    draft.domainData.businessService = businessServiceName;
                }
            });
            return newState;
        }
        case RETURN_DOMAIN_DATA:
        default:
            return state;
    }
};
