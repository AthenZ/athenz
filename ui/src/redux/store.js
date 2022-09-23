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

import { combineReducers } from 'redux';
import { groups } from './reducers/groups';
import { roles } from './reducers/roles';
import { user } from './reducers/user';
import { domainData } from './reducers/domain-data';
import { domains } from './reducers/domains';
import thunk from 'redux-thunk';
import { services } from './reducers/services';
import { policies } from './reducers/policies';
import { serviceDependencies } from './reducers/visibility';
import { microsegmentation } from './reducers/microsegmentation';
import { createWrapper, HYDRATE } from 'next-redux-wrapper';
import { loading } from './reducers/loading';
import { configureStore } from '@reduxjs/toolkit';

const combinedReducer = combineReducers({
    services,
    domains,
    domainData,
    roles,
    groups,
    policies,
    serviceDependencies,
    microsegmentation,
    loading,
    user,
});

const reducer = (state, action) => {
    return combinedReducer(state, action);
};

export const initStore = (preloadedState) =>
    configureStore({
        reducer,
        middleware: (getDefaultMiddleware) =>
            getDefaultMiddleware().concat(thunk),
        devTools: process.env.NODE_ENV !== 'production',
        preloadedState,
    });

export const wrapper = createWrapper(initStore);
