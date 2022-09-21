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
    loadingFailed,
    loadingInProcess,
    loadingSuccess,
} from '../../actions/loading';
import { getExpiryTime, listToMap } from '../../utils';
import API from '../../../api';
import { loadServices } from '../../actions/services';

export const getServicesApiCall = async (domainName, dispatch) => {
    dispatch(loadingInProcess('getServices'));
    try {
        const serviceList = await API().getServices(domainName, true, true);
        const expiry = getExpiryTime();
        for (let service of serviceList) {
            service.publicKeys = service.publicKeys
                ? listToMap(service.publicKeys, 'id')
                : {};
        }
        let serviceMap = listToMap(serviceList, 'name');
        dispatch(loadServices(serviceMap, domainName, expiry));
        dispatch(loadingSuccess('getServices'));
    } catch (e) {
        dispatch(loadingFailed('getServices'));
        throw e;
    }
};
