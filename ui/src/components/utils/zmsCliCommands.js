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

import NameUtils from './NameUtils';
import { resolveZmsCliUrl } from './url';

/**
 * zms-cli `-r` value: `ignore` skips resource-owner enforcement for the command.
 */
export const ZMS_CLI_RESOURCE_OWNER_FLAG = 'ignore';

/** Shell-safe token for displayed zms-cli lines (bash/zsh copy-paste). */
export function shellQuote(str) {
    if (str === undefined || str === null) {
        return '';
    }
    const s = String(str);
    if (/^[a-zA-Z0-9./_-]+$/.test(s)) {
        return s;
    }
    return "'" + s.replace(/'/g, "'\\''") + "'";
}

function base(domain, auditRef, zmsUrl) {
    const resolvedZmsUrl = resolveZmsCliUrl(zmsUrl);
    let cmd = 'zms-cli';
    if (resolvedZmsUrl) {
        cmd += ` -z ${shellQuote(resolvedZmsUrl)}`;
    }
    cmd += ` -d ${shellQuote(domain)} -r ${shellQuote(
        ZMS_CLI_RESOURCE_OWNER_FLAG
    )}`;
    if (auditRef) {
        cmd += ` -a ${shellQuote(auditRef)}`;
    }
    return cmd;
}

export function cliAddRoleMember(
    domain,
    roleName,
    memberName,
    auditRef,
    zmsUrl
) {
    return `${base(domain, auditRef, zmsUrl)} add-member ${shellQuote(
        roleName
    )} ${shellQuote(memberName)}`;
}

export function cliAddTemporaryRoleMember(
    domain,
    roleName,
    memberName,
    expirationRdl,
    reviewRdl,
    auditRef,
    zmsUrl
) {
    const b = base(domain, auditRef, zmsUrl);
    if (expirationRdl && reviewRdl) {
        return `${b} add-temporary-member ${shellQuote(roleName)} ${shellQuote(
            memberName
        )} ${shellQuote(expirationRdl)} ${shellQuote(reviewRdl)}`;
    }
    if (expirationRdl) {
        return `${b} add-temporary-member ${shellQuote(roleName)} ${shellQuote(
            memberName
        )} ${shellQuote(expirationRdl)}`;
    }
    if (reviewRdl) {
        return `${b} add-reviewed-member ${shellQuote(roleName)} ${shellQuote(
            memberName
        )} ${shellQuote(reviewRdl)}`;
    }
    return cliAddRoleMember(domain, roleName, memberName, auditRef, zmsUrl);
}

export function cliDeleteRoleMember(
    domain,
    roleName,
    memberName,
    auditRef,
    zmsUrl
) {
    return `${base(domain, auditRef, zmsUrl)} delete-member ${shellQuote(
        roleName
    )} ${shellQuote(memberName)}`;
}

export function cliDeleteRole(domain, roleName, auditRef, zmsUrl) {
    return `${base(domain, auditRef, zmsUrl)} delete-role ${shellQuote(
        roleName
    )}`;
}

export function cliDeleteService(domain, serviceName, auditRef, zmsUrl) {
    return `${base(domain, auditRef, zmsUrl)} delete-service ${shellQuote(
        serviceName
    )}`;
}

export function cliDeletePolicy(domain, policyName, auditRef, zmsUrl) {
    return `${base(domain, auditRef, zmsUrl)} delete-policy ${shellQuote(
        policyName
    )}`;
}

export function cliDeletePolicyVersion(
    domain,
    policyName,
    version,
    auditRef,
    zmsUrl
) {
    return `${base(
        domain,
        auditRef,
        zmsUrl
    )} delete-policy-version ${shellQuote(policyName)} ${shellQuote(version)}`;
}

export function cliAddPolicyVersion(
    domain,
    policyName,
    sourceVersion,
    newVersion,
    auditRef,
    zmsUrl
) {
    return `${base(domain, auditRef, zmsUrl)} add-policy-version ${shellQuote(
        policyName
    )} ${shellQuote(sourceVersion)} ${shellQuote(newVersion)}`;
}

export function cliAddAssertion(
    domain,
    policyName,
    assertionWords,
    auditRef,
    caseSensitive,
    zmsUrl
) {
    let cmd = `${base(domain, auditRef, zmsUrl)} add-assertion ${shellQuote(
        policyName
    )} ${assertionWords}`;
    if (caseSensitive) {
        cmd += ' true';
    }
    return cmd;
}

export function cliDeleteAssertion(
    domain,
    policyName,
    assertionWords,
    auditRef,
    zmsUrl
) {
    return `${base(domain, auditRef, zmsUrl)} delete-assertion ${shellQuote(
        policyName
    )} ${assertionWords}`;
}

export function cliDeleteAssertionPolicyVersion(
    domain,
    policyName,
    version,
    assertionWords,
    auditRef,
    zmsUrl
) {
    return `${base(
        domain,
        auditRef,
        zmsUrl
    )} delete-assertion-policy-version ${shellQuote(policyName)} ${shellQuote(
        version
    )} ${assertionWords}`;
}

export function cliAddAssertionPolicyVersion(
    domain,
    policyName,
    version,
    assertionWords,
    auditRef,
    caseSensitive,
    zmsUrl
) {
    let cmd = `${base(
        domain,
        auditRef,
        zmsUrl
    )} add-assertion-policy-version ${shellQuote(policyName)} ${shellQuote(
        version
    )} ${assertionWords}`;
    if (caseSensitive) {
        cmd += ' true';
    }
    return cmd;
}

/** Builds zms-cli assertion token sequence (effect action to role on resource). */
export function formatAssertionWords(domain, assertion) {
    const role = NameUtils.getShortName(domain + ':role.', assertion.role);
    const res = NameUtils.getShortName(domain + ':', assertion.resource);
    const eff =
        String(assertion.effect || '').toUpperCase() === 'DENY'
            ? 'deny'
            : 'grant';
    return `${eff} ${shellQuote(assertion.action)} to ${shellQuote(
        role
    )} on ${shellQuote(res)}`;
}

export function cliAddPolicy(
    domain,
    policyName,
    assertionWords,
    auditRef,
    caseSensitive,
    zmsUrl
) {
    let cmd = `${base(domain, auditRef, zmsUrl)} add-policy ${shellQuote(
        policyName
    )} ${assertionWords}`;
    if (caseSensitive) {
        cmd += ' true';
    }
    return cmd;
}

export function cliDeletePublicKey(
    domain,
    serviceName,
    keyId,
    auditRef,
    zmsUrl
) {
    return `${base(domain, auditRef, zmsUrl)} delete-public-key ${shellQuote(
        serviceName
    )} ${shellQuote(keyId)}`;
}

export function cliAddPublicKey(
    domain,
    serviceName,
    keyId,
    keyValuePathHint,
    auditRef,
    zmsUrl
) {
    let cmd = `${base(domain, auditRef, zmsUrl)} add-public-key ${shellQuote(
        serviceName
    )} ${shellQuote(keyId)}`;
    if (keyValuePathHint) {
        cmd += ` ${shellQuote(keyValuePathHint)}`;
    }
    return cmd;
}

function boolStr(v) {
    return v ? 'true' : 'false';
}

/**
 * Builds set-role-* commands for fields that differ between original and updated
 * (shape from SettingTable setCollectionDetails for roles).
 */
export function cliRoleMetaDiff(
    domain,
    roleName,
    original,
    updated,
    auditRef,
    zmsUrl
) {
    if (!original || !updated) {
        return null;
    }
    const b = base(domain, auditRef, zmsUrl);
    const parts = [];
    const role = shellQuote(roleName);

    const push = (fragment) => parts.push(`${b} ${fragment}`);

    if (original.description !== updated.description) {
        push(
            `set-role-description ${role} ${shellQuote(
                updated.description || ''
            )}`
        );
    }
    if (original.reviewEnabled !== updated.reviewEnabled) {
        push(
            `set-role-review-enabled ${role} ${boolStr(updated.reviewEnabled)}`
        );
    }
    if (original.auditEnabled !== updated.auditEnabled) {
        push(`set-role-audit-enabled ${role} ${boolStr(updated.auditEnabled)}`);
    }
    if (original.deleteProtection !== updated.deleteProtection) {
        push(
            `set-role-delete-protection ${role} ${boolStr(
                updated.deleteProtection
            )}`
        );
    }
    if (original.selfServe !== updated.selfServe) {
        push(`set-role-self-serve ${role} ${boolStr(updated.selfServe)}`);
    }
    if (original.selfRenew !== updated.selfRenew) {
        push(`set-role-self-renew ${role} ${boolStr(updated.selfRenew)}`);
    }
    if (original.memberExpiryDays !== updated.memberExpiryDays) {
        push(
            `set-role-member-expiry-days ${role} ${shellQuote(
                updated.memberExpiryDays || '0'
            )}`
        );
    }
    if (original.memberReviewDays !== updated.memberReviewDays) {
        push(
            `set-role-member-review-days ${role} ${shellQuote(
                updated.memberReviewDays || '0'
            )}`
        );
    }
    if (original.groupExpiryDays !== updated.groupExpiryDays) {
        push(
            `set-role-group-expiry-days ${role} ${shellQuote(
                updated.groupExpiryDays || '0'
            )}`
        );
    }
    if (original.groupReviewDays !== updated.groupReviewDays) {
        push(
            `set-role-group-review-days ${role} ${shellQuote(
                updated.groupReviewDays || '0'
            )}`
        );
    }
    if (original.serviceExpiryDays !== updated.serviceExpiryDays) {
        push(
            `set-role-service-expiry-days ${role} ${shellQuote(
                updated.serviceExpiryDays || '0'
            )}`
        );
    }
    if (original.serviceReviewDays !== updated.serviceReviewDays) {
        push(
            `set-role-service-review-days ${role} ${shellQuote(
                updated.serviceReviewDays || '0'
            )}`
        );
    }
    if (original.selfRenewMins !== updated.selfRenewMins) {
        push(
            `set-role-self-renew-mins ${role} ${shellQuote(
                updated.selfRenewMins || '0'
            )}`
        );
    }
    if (original.maxMembers !== updated.maxMembers) {
        push(
            `set-role-max-members ${role} ${shellQuote(
                updated.maxMembers || '0'
            )}`
        );
    }
    if (original.userAuthorityFilter !== updated.userAuthorityFilter) {
        push(
            `set-role-user-authority-filter ${role} ${shellQuote(
                updated.userAuthorityFilter || ''
            )}`
        );
    }
    if (original.userAuthorityExpiration !== updated.userAuthorityExpiration) {
        push(
            `set-role-user-authority-expiration ${role} ${shellQuote(
                updated.userAuthorityExpiration || ''
            )}`
        );
    }
    if (original.principalDomainFilter !== updated.principalDomainFilter) {
        push(
            `set-role-principal-domain-filter ${role} ${shellQuote(
                updated.principalDomainFilter || ''
            )}`
        );
    }
    if (original.tokenExpiryMins !== updated.tokenExpiryMins) {
        push(
            `set-role-token-expiry-mins ${role} ${shellQuote(
                updated.tokenExpiryMins || '0'
            )}`
        );
    }
    if (original.certExpiryMins !== updated.certExpiryMins) {
        push(
            `set-role-cert-expiry-mins ${role} ${shellQuote(
                updated.certExpiryMins || '0'
            )}`
        );
    }

    if (parts.length === 0) {
        return `${b} show-role ${role}`;
    }
    return parts.join(' && \\\n');
}
