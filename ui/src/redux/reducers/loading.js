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
    LOADING_FAILED,
    LOADING_IN_PROCESS,
    LOADING_SUCCESS,
} from '../actions/loading.js';

export const loading = (state = [], action) => {
    const { type, payload } = action;
    switch (type) {
        case LOADING_IN_PROCESS: {
            const { funcName } = payload;
            return state.concat(funcName);
        }
        case LOADING_SUCCESS: {
            const { funcName } = payload;
            return state.filter((func) => func !== funcName);
        }
        case LOADING_FAILED:
            const { funcName } = payload;
            return state.filter((func) => func !== funcName);
        default:
            return state;
    }
};
