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

import { loadMicrosegmentation } from '../actions/microsegmentation';
import { buildInboundOutbound } from './utils/microsegmentation';
import { getRole, getRoles } from './roles';
import { getPolicies, getPolicy } from './policies';
import {
    loadingFailed,
    loadingInProcess,
    loadingSuccess,
} from '../actions/loading';
import { getServices } from './services';
import API from '../../api';

export const getInboundOutbound =
    (domainName, force = false) =>
    async (dispatch, getState) => {
        try {
            dispatch(loadingInProcess('getInboundOutbound'));
            await Promise.all([
                dispatch(getServices(domainName)),
                dispatch(getRoles(domainName, force)),
                dispatch(getPolicies(domainName, force)),
            ]);
            const inboundOutboundList = buildInboundOutbound(
                domainName,
                getState()
            );
            dispatch(loadMicrosegmentation(inboundOutboundList, domainName));
            dispatch(loadingSuccess('getInboundOutbound'));
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const createOrUpdateTransportPolicy =
    (domainName, data, _csrf, roleName, policyName) =>
    async (dispatch, getState) => {
        try {
            dispatch(loadingInProcess('createOrUpdateTransportPolicy'));
            await API().createOrUpdateTransportPolicy(data, _csrf);
            await dispatch(getRole(domainName, roleName, false, true));
            await dispatch(getPolicy(domainName, policyName, true));
            await dispatch(getInboundOutbound(domainName));
            dispatch(loadingSuccess('createOrUpdateTransportPolicy'));
            return Promise.resolve();
        } catch (e) {
            dispatch(loadingFailed('createOrUpdateTransportPolicy'));
            return Promise.reject(e);
        }
    };

export const deleteTransportPolicy =
    (domainName, serviceName, assertionId, auditRef, _csrf) =>
    async (dispatch, getState) => {
        const params = {
            domainName,
            serviceName,
            id: assertionId,
            auditRef,
        };
        try {
            dispatch(loadingInProcess('deleteTransportPolicy'));
            await API().deleteTransportPolicy(params, _csrf);
            await dispatch(getInboundOutbound(domainName, true));
            dispatch(loadingSuccess('deleteTransportPolicy'));
            return Promise.resolve();
        } catch (e) {
            console.log('=== deleteTransportPolicy error', e);
            dispatch(loadingFailed('deleteTransportPolicy'));
            return Promise.reject(e);
        }
    };

export const validateMicrosegmentationPolicy =
    (
        category,
        roleMembers,
        inboundDestinationService,
        outboundSourceService,
        sourcePort,
        destinationPort,
        protocol,
        domainName,
        assertionId,
        _csrf
    ) =>
    async (dispatch, getState) => {
        try {
            dispatch(loadingInProcess('validateMicrosegmentationPolicy'));
            await API().validateMicrosegmentationPolicy(
                category,
                roleMembers,
                inboundDestinationService,
                outboundSourceService,
                sourcePort,
                destinationPort,
                protocol,
                domainName,
                assertionId,
                _csrf
            );
            dispatch(loadingSuccess('validateMicrosegmentationPolicy'));
            return Promise.resolve();
        } catch (e) {
            dispatch(loadingFailed('validateMicrosegmentationPolicy'));
            return Promise.reject(e);
        }
    };
