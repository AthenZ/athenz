// problem need to do it on all subList as well need to know them.§
import * as debugConsole from 'next/dist/build/output/log';
import { expiryTimeInMilliseconds } from './config';

export const listToMap = (list, keyVal = 'name', delimiter) => {
    let newMap = {};
    let convertList = list ? list : [];
    for (let i = 0; i < convertList.length; i++) {
        newMap[convertList[i][keyVal]] = convertList[i];
    }
    return newMap;
};

export const mapToList = (map) => {
    let newList = [];
    let convertMap = map ? map : {};
    for (const [, value] of Object.entries(convertMap)) {
        newList.push(value);
    }
    return newList;
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
    // deepFreezeObject(policyMap);
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
        debugger;
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

export const getFullName = (domainName, delimiter = ':', collection) => {
    return domainName + delimiter + collection;
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
