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

import {
    isRoleResourceMembersManaged,
    isRoleResourceMetaManaged,
} from './resourceOwnership';
import { getResourceOwnershipUiDefaults } from '../constants/constants';

/**
 * Default UI branding for externally managed resources (e.g. Terraform, OpenTofu).
 * Sourced from merged deployment config via client-config (NEXT_PUBLIC_* from next.config.js).
 */
export const DEFAULT_RESOURCE_OWNERSHIP_UI = {
    ...getResourceOwnershipUiDefaults(),
};

/**
 * Replace {{label}} in config strings with the configured owner tool name.
 */
export function formatResourceOwnershipUiString(template, label) {
    if (template === undefined || template === null) {
        return '';
    }
    const name =
        label !== undefined && label !== null && String(label).trim() !== ''
            ? String(label)
            : DEFAULT_RESOURCE_OWNERSHIP_UI.label;
    return String(template).replace(/\{\{label\}\}/g, name);
}

/** Merge deployment config with defaults. */
export function resolveResourceOwnershipUi(fromConfig) {
    if (!fromConfig || typeof fromConfig !== 'object') {
        return { ...DEFAULT_RESOURCE_OWNERSHIP_UI };
    }
    return {
        ...DEFAULT_RESOURCE_OWNERSHIP_UI,
        ...fromConfig,
    };
}

export function getManagedIconTooltip(uiConfig) {
    const ui = resolveResourceOwnershipUi(uiConfig);
    return formatResourceOwnershipUiString(ui.managedIconTooltip, ui.label);
}

export function getMembersManagedIconTooltip(uiConfig) {
    const ui = resolveResourceOwnershipUi(uiConfig);
    return formatResourceOwnershipUiString(
        ui.membersManagedIconTooltip,
        ui.label
    );
}

/** Tooltip for role list rows: meta/object vs members-only ownership. */
export function getRoleListManagedIconTooltip(resourceOwnership, uiConfig) {
    if (isRoleResourceMetaManaged(resourceOwnership)) {
        return getManagedIconTooltip(uiConfig);
    }
    if (isRoleResourceMembersManaged(resourceOwnership)) {
        return getMembersManagedIconTooltip(uiConfig);
    }
    return getManagedIconTooltip(uiConfig);
}

export function getCliSuggestionBody(uiConfig) {
    const ui = resolveResourceOwnershipUi(uiConfig);
    return formatResourceOwnershipUiString(ui.cliSuggestionBody, ui.label);
}

export function getCliSuggestionEmergencyHeading(uiConfig) {
    const ui = resolveResourceOwnershipUi(uiConfig);
    return formatResourceOwnershipUiString(
        ui.cliSuggestionEmergencyHeading,
        ui.label
    );
}

export function getCliSuggestionGuideFooter(uiConfig) {
    const ui = resolveResourceOwnershipUi(uiConfig);
    return formatResourceOwnershipUiString(
        ui.cliSuggestionGuideFooter,
        ui.label
    );
}

/** First sentence of CLI suggestion body — used by functional tests. */
export function getCliSuggestionWarningLead(uiConfig) {
    const body = getCliSuggestionBody(uiConfig);
    const idx = body.indexOf('. ');
    return idx >= 0 ? body.slice(0, idx) : body;
}
