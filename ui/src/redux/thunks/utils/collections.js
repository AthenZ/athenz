import { addMemberToStore } from '../../actions/collections';
import API from '../../../api';
import { deleteMemberFromStore } from '../../actions/collections';
import { addDomainTagToStore } from '../../actions/domain-data';
import { addGroupTagsToStore } from '../../actions/groups';
import { addRoleTagsToStore } from '../../actions/roles';

const api = API();

export const addMemberApiCall = async (
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
) => {
    console.log('addMemberApiCall', data, member, auditRef, _csrf);
    if (member.memberName in data[category + 'Members']) {
        onFail({
            body: { message: 'Member already exists' },
            statusCode: 409,
        });
    } else {
        api.addMember(
            domainName,
            collectionName,
            member.memberName,
            member,
            auditRef,
            category,
            _csrf
        )
            .then(() => {
                // is it right for every member addition to mark it as approved?
                member.approved = true;
                member.expiration = data.memberExpiryDays
                    ? new Date(
                          Date.now() +
                              data.memberExpiryDays * 24 * 60 * 60 * 1000
                      )
                    : null;
                dispatch(addMemberToStore(member, category, collectionName));
                onSuccess();
            })
            .catch((err) => {
                onFail(err);
            });
    }
};

export const deleteMemberApiCall = async (
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
) => {
    console.log(onFail);
    if (memberName in data[category + 'Members']) {
        api.deleteMember(
            domainName,
            collectionName,
            memberName,
            auditRef,
            pending,
            category,
            _csrf
        )
            .then(() => {
                dispatch(
                    deleteMemberFromStore(memberName, category, collectionName)
                );
                onSuccess();
            })
            .catch((err) => {
                onFail(err);
            });
    } else {
        onFail({
            body: { message: 'Member does not exist' },
            statusCode: 404,
        });
    }
};

export const addTagsApiCall = async (
    domain,
    collectionName,
    detail,
    auditRef,
    _csrf,
    category,
    dispatch,
    onSuccess,
    onFail
) => {
    await api
        .putMeta(domain, collectionName, detail, auditRef, _csrf, category)
        .then(() => {
            if (category === 'domain') {
                console.log('addDomainTagToStore', detail);
                dispatch(addDomainTagToStore(detail.tags));
            } else if (category === 'group') {
                dispatch(addGroupTagsToStore(collectionName, detail.tags));
            } else if (category === 'role') {
                dispatch(addRoleTagsToStore(collectionName, detail.tags));
            }
            onSuccess();
        })
        .catch((e) => {
            onFail(e);
        });
};
