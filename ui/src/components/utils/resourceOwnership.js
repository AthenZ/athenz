/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations
 * under the License.
 */

import { cliDeleteRole } from './zmsCliCommands';

/**
 * True when ZMS reports an owner for this field (any non-empty SimpleName).
 * The actual principal name is deployment-specific; UI treats any non-blank owner as externally managed (label/icon from resourceOwnershipUi config).
 */
export function hasResourceOwner(simpleName) {
    if (simpleName === undefined || simpleName === null) {
        return false;
    }
    return String(simpleName).trim() !== '';
}

export function isRoleResourceMetaManaged(resourceOwnership) {
    if (!resourceOwnership) {
        return false;
    }
    return (
        hasResourceOwner(resourceOwnership.objectOwner) ||
        hasResourceOwner(resourceOwnership.metaOwner)
    );
}

export function isRoleResourceMembersManaged(resourceOwnership) {
    if (!resourceOwnership) {
        return false;
    }
    return hasResourceOwner(resourceOwnership.membersOwner);
}

/** True when any role ownership field is set (for list/header icons). */
export function isRoleResourceListManaged(resourceOwnership) {
    return (
        isRoleResourceMetaManaged(resourceOwnership) ||
        isRoleResourceMembersManaged(resourceOwnership)
    );
}

export function isPolicyResourceManaged(resourceOwnership) {
    if (!resourceOwnership) {
        return false;
    }
    return (
        hasResourceOwner(resourceOwnership.objectOwner) ||
        hasResourceOwner(resourceOwnership.assertionsOwner)
    );
}

export function isServiceResourceObjectManaged(resourceOwnership) {
    if (!resourceOwnership) {
        return false;
    }
    return hasResourceOwner(resourceOwnership.objectOwner);
}

export function isServiceResourcePublicKeysManaged(resourceOwnership) {
    if (!resourceOwnership) {
        return false;
    }
    return hasResourceOwner(resourceOwnership.publicKeysOwner);
}

function extractErrMessage(err) {
    if (!err) {
        return '';
    }
    if (err.body && err.body.message) {
        return String(err.body.message);
    }
    if (err.output && err.output.message) {
        return String(err.output.message);
    }
    return '';
}

/**
 * ZMS resource-ownership conflict messages from
 * libs/java/server_common/.../ResourceOwnership.java
 */
const RESOURCE_OWNERSHIP_ERROR_PATTERNS = [
    /has a resource owner:/i,
    /invalid resource owner for (domain|role|group|policy|service|object):/i,
    /invalid members owner for (role|group):/i,
    /invalid meta owner for (role|group):/i,
    /invalid resource meta owner for (role|group):/i,
    /invalid resource member owner for (role|group|policy|service):/i,
    /invalid assertions owner for policy:/i,
    /invalid public-keys owner for service:/i,
    /invalid hosts owner for service:/i,
];

/** When true, show zms-cli hint even if ownership was not loaded in the UI. */
export function errorMessageSuggestsResourceOwnership(err) {
    const m = extractErrMessage(err);
    if (!m) {
        return false;
    }
    return RESOURCE_OWNERSHIP_ERROR_PATTERNS.some((pattern) => pattern.test(m));
}

/**
 * Show copy-paste CLI when we know the resource is externally managed, or the error text indicates an ownership denial.
 */
export function shouldOfferResourceOwnershipCli(isResourceManaged, err) {
    return !!(isResourceManaged || errorMessageSuggestsResourceOwnership(err));
}

/**
 * Build a zms-cli command for modal error feedback when ownership blocks a UI mutation.
 * @param {boolean} isResourceManaged - from resourceOwnership helpers for the relevant field
 * @param {*} err - API error
 * @param {() => (string|null|undefined)} buildCommand - returns command when CLI hint applies
 * @param {{ when?: boolean }} [options] - set when: false to skip (e.g. missing assertion row)
 */
export function resolveResourceOwnershipCliOnError(
    isResourceManaged,
    err,
    buildCommand,
    options = {}
) {
    const when = options.when !== false;
    if (
        !when ||
        !shouldOfferResourceOwnershipCli(isResourceManaged, err) ||
        typeof buildCommand !== 'function'
    ) {
        return null;
    }
    const cmd = buildCommand();
    return cmd === undefined || cmd === null || cmd === '' ? null : cmd;
}

/** zms-cli command state for role delete modals blocked by resource ownership. */
export function resolveRoleDeleteResourceOwnershipCli(
    resourceOwnership,
    err,
    domain,
    roleName,
    auditRef
) {
    return resolveResourceOwnershipCliOnError(
        isRoleResourceListManaged(resourceOwnership),
        err,
        () => cliDeleteRole(domain, roleName, auditRef)
    );
}
