export const LOAD_PENDING_MEMBERS = 'LOAD_PENDING_MEMBERS';
export const loadUserPendingMembers = (pendingMembers, expiry) => ({
    type: LOAD_PENDING_MEMBERS,
    payload: {
        pendingMembers,
        expiry,
    },
});
