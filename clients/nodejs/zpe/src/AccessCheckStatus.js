'use strict';

module.exports = {
    ALLOW: 'Access Check was explicitly allowed',
    DENY: 'Access Check was explicitly denied',
    DENY_NO_MATCH:
        'Access denied due to no match to any of the assertions defined in domain policy file',
    DENY_ROLETOKEN_EXPIRED: 'Access denied due to expired RoleToken',
    DENY_ROLETOKEN_INVALID: 'Access denied due to invalid RoleToken',
    DENY_DOMAIN_MISMATCH:
        'Access denied due to domain mismatch between Resource and RoleToken',
    DENY_DOMAIN_NOT_FOUND:
        'Access denied due to domain not found in library cache',
    DENY_DOMAIN_EXPIRED: 'Access denied due to expired domain policy file',
    DENY_DOMAIN_EMPTY: 'Access denied due to no policies in the domain file',
    DENY_INVALID_PARAMETERS:
        'Access denied due to invalid/empty action/resource values',
};
