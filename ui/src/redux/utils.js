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

// problem need to do it on all subList as well need to know them.§
import * as debugConsole from 'next/dist/build/output/log';
import { expiryTimeInMilliseconds } from './config';
import produce from 'immer';
import { getFullCollectionName } from './thunks/utils/collection';
import { SERVICE_TYPE_DYNAMIC } from '../components/constants/constants';

export const listToMap = (list, keyVal = 'name', delimiter) => {
    let newMap = { list: list ? list : [] };
    newMap = produce(newMap, (draft) => {
        for (let i = 0; i < draft.list.length; i++) {
            draft[draft.list[i][keyVal]] = draft.list[i];
        }
        delete draft.list;
    });
    return newMap;
};

export const membersListToMaps = (list, keyVal = 'memberName', delimiter) => {
    let members = [];
    let pendingMembers = [];
    if (list) {
        members = list.filter((m) => m.approved !== false);
        pendingMembers = list.filter((m) => m.approved === false);
    }
    return {
        members: listToMap(members, keyVal, delimiter),
        pendingMembers: listToMap(pendingMembers, keyVal, delimiter),
    };
};

export const mapToList = (map) => {
    let newList = [];
    let convertMap = map ? map : {};
    for (const [, value] of Object.entries(convertMap)) {
        newList.push(value);
    }
    return newList;
};

export const membersMapsToList = (membersMap, pendingMembersMap) => {
    return [...mapToList(membersMap), ...mapToList(pendingMembersMap)];
};

export const buildPolicyMapKey = (policyFullName, version) => {
    return policyFullName + ':' + version;
};

export const policyListToMap = (list) => {
    let policyMap = {};
    for (let i = 0; i < list.length; i++) {
        let key = buildPolicyMapKey(list[i]['name'], list[i]['version']);
        policyMap[key] = list[i];
        policyMap[key].assertions = listToMap(list[i].assertions, 'id');
    }
    return policyMap;
};

// Calls Object.freeze() on an object and all its properties recursively.
export function deepFreezeObject(object, frozenObjects = new Set(), nest = 0) {
    if (
        !object ||
        (typeof object !== 'object' && typeof object !== 'function') ||
        frozenObjects.has(object)
    ) {
        return;
    }

    if (nest > 100) {
        debugConsole.warn(
            "deepFreezeObject: deep nesting - probably state contains an object it shouldn't have..."
        );
    }

    Object.freeze(object);
    frozenObjects.add(object); // prevent infinite loop upon cyclic-referencing

    for (const key of Object.getOwnPropertyNames(object)) {
        deepFreezeObject(object[key], frozenObjects, nest + 1);
    }
}

export const getExpiryTime = () => {
    return Date.now() + expiryTimeInMilliseconds;
};

export const getExpiredTime = () => {
    return Date.now() - expiryTimeInMilliseconds;
};

export const isExpired = (expiryTime) => {
    return !(typeof expiryTime === 'number') || Date.now() >= expiryTime;
};

export const getCurrentTime = () => {
    return new Date(Date.now()).toISOString();
};

export const getFullName = (domainName, delimiter = ':', collection = '') => {
    return domainName + delimiter + collection.toLowerCase();
};

export const buildErrorForDoesntExistCase = (
    collection,
    collectionName = ''
) => {
    const message = collectionName
        ? `${collection} ${collectionName} doesnt exist`
        : `${collection} doesnt exist`;
    return {
        body: { message },
        statusCode: 404,
    };
};

export const buildErrorForDuplicateCase = (collection, collectionName = '') => {
    const message = collectionName
        ? `${collection} ${collectionName} already exists`
        : `${collection} already exists`;
    return {
        statusCode: 409,
        body: { message },
    };
};

export const createBellPendingMembers = (pendingMembers) => {
    let bellPendingList = {};
    for (const [, value] of Object.entries(pendingMembers)) {
        let fullName = getFullCollectionName(
            value.domainName,
            value.roleName,
            value.category
        );
        bellPendingList[fullName + value.memberName] = true;
    }
    return bellPendingList;
};

export const deleteInstanceFromWorkloadDataDraft = (
    workLoadData,
    instanceId,
    category
) => {
    let originalLen = workLoadData.length;
    let indexToDelete = -1;
    let instanceIdKey = category === SERVICE_TYPE_DYNAMIC ? 'uuid' : 'name';
    for (let i = 0; i < originalLen; i++) {
        if (workLoadData[i][instanceIdKey] === instanceId) {
            indexToDelete = i;
        }
    }
    if (indexToDelete != -1) {
        workLoadData.splice(indexToDelete, 1);
    }
};
