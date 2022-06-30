import { thunkSelectGroup } from '../selectors/group';
import { addMemberApiCall, addTagsApiCall } from './utils/collections';
import { getGroup } from './groups';
import { getRole } from './roles';
import { thunkSelectRole } from '../selectors/roles';
import { deleteMemberApiCall } from './utils/collections';

export const addMember =
    (
        domainName,
        collectionName,
        category,
        member,
        auditRef,
        _csrf,
        onSuccess,
        onFail
    ) =>
    async (dispatch, getState) => {
        let data = {};
        console.log('category', category);
        if (category === 'group') {
            console.log('getGroup');
            await dispatch(getGroup(domainName, collectionName));
            data = thunkSelectGroup(getState(), collectionName);
        } else if (category === 'role') {
            // await dispatch(getGroup(domainName, collectionName));
            // data = thunkSelectGroup(getState(), collectionName);
            await dispatch(getRole(domainName, collectionName));
            data = thunkSelectRole(getState(), collectionName);
        }
        await addMemberApiCall(
            domainName,
            collectionName,
            category,
            data,
            member,
            auditRef,
            _csrf,
            onSuccess,
            onFail,
            dispatch
        );
    };

export const deleteMember =
    (
        domainName,
        collectionName,
        category,
        memberName,
        auditRef,
        pending,
        _csrf,
        onSuccess,
        onFail
    ) =>
    async (dispatch, getState) => {
        let data = {};
        if (category === 'group') {
            await dispatch(getGroup(domainName, collectionName));
            data = thunkSelectGroup(getState(), collectionName);
        } else if (category === 'role') {
            await dispatch(getRole(domainName, collectionName));
            data = thunkSelectRole(getState(), collectionName);
        }
        await deleteMemberApiCall(
            domainName,
            collectionName,
            category,
            data,
            memberName,
            auditRef,
            pending,
            _csrf,
            onSuccess,
            onFail,
            dispatch
        );
    };

export const addTags =
    (
        domain,
        collectionName,
        detail,
        auditRef,
        _csrf,
        category,
        onSuccess,
        onFail
    ) =>
    async (dispatch, getState) => {
        await addTagsApiCall(
            domain,
            collectionName,
            detail,
            auditRef,
            _csrf,
            category,
            dispatch,
            onSuccess,
            onFail
        );
    };
