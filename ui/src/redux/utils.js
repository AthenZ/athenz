// problem need to do it on all subList as well need to know them.
import policyList from '../components/policy/PolicyList';
import { object } from 'prop-types';

export const listToMap = (list, keyVal = 'name', delimiter) => {
    let newMap = {};
    let convertList = list ? list : [];
    for (let i = 0; i < convertList.length; i++) {
        if (delimiter) {
            newMap[convertList[i][keyVal].split(delimiter)[1]] = convertList[i];
        } else {
            newMap[convertList[i][keyVal]] = convertList[i];
        }
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

export const buildPolicyMapKey = (policyName, version) => {
    if (policyName.includes(':policy.')) {
        policyName = policyName.split(':policy.')[1];
    }
    return policyName + ':' + version;
};

export const policyListToMap = (list) => {
    let policyMap = {};
    for (let i = 0; i < list.length; i++) {
        let key = buildPolicyMapKey(list[i]['name'], list[i]['version']);
        policyMap[key] = list[i];
        if (list[i].assertions) {
            policyMap[key].assertions = listToMap(list[i].assertions, 'id');
        }
    }
    // deepFreezeObject(policyMap);
    return policyMap;
};

export const policyMapToList = (policyMap) => {
    let policyList = mapToList(policyMap);
    for (let i = 0; i < policyList.length; i++) {
        if (policyList[i]['assertions']) {
            policyList[i]['assertions'] = mapToList(
                policyList[i]['assertions']
            );
        }
    }
    return policyList;
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
    return 5;
};

export const getCurrentTime = () => {
    return new Date(Date.now()).toISOString();
};

export const additionsToAddCollection = (
    collection,
    domainName,
    nameDelimiter,
    listToMapKey,
    mapDelimiter
) => {
    collection.expiry = getExpiryTime();
    collection.modified = getCurrentTime();
    collection.name = domainName + nameDelimiter + collection.name;
    collection[listToMapKey] = listToMap(
        collection[listToMapKey],
        mapDelimiter
    );
};
