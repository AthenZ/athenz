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

import { loadServiceDependencies } from '../../actions/visibility';
import {
    loadingFailed,
    loadingInProcess,
    loadingSuccess,
} from '../../actions/loading';
import { getExpiryTime } from '../../utils';
import API from '../../../api';

export const getServiceDependenciesApiCall = async (domainName, dispatch) => {
    dispatch(loadingInProcess('getServiceDependencies'));
    try {
        const serviceDependencies = await API().getServiceDependencies(
            domainName
        );
        const expiry = getExpiryTime();
        dispatch(
            loadServiceDependencies(serviceDependencies, domainName, expiry)
        );
        dispatch(loadingSuccess('getServiceDependencies'));
    } catch (e) {
        dispatch(loadingFailed('getServiceDependencies'));
        throw e;
    }
};
