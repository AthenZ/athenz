export const ADD_MEMBER_TO_STORE = 'ADD_MEMBER_TO_STORE';
export const addMemberToStore = (member, category, collectionName) => ({
    type: ADD_MEMBER_TO_STORE,
    payload: {
        member,
        category,
        collectionName,
    },
});

export const DELETE_MEMBER_TO_STORE = 'DELETE_MEMBER_TO_STORE';
export const deleteMemberFromStore = (
    memberName,
    category,
    collectionName
) => ({
    type: DELETE_MEMBER_TO_STORE,
    payload: {
        memberName,
        category,
        collectionName,
    },
});
