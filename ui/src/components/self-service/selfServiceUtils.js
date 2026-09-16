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
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { SELF_SERVICE_MEMBER_STATUS } from '../constants/constants';

export const EXPIRING_SOON_DAYS = 14;

export const resourceKey = (item) =>
    `${item.domainName}:${item.type}.${item.name}`;

export const encodePathSegment = (value) => encodeURIComponent(value ?? '');

export const splitByType = (list = []) => ({
    roles: list.filter((item) => item.type === 'role'),
    groups: list.filter((item) => item.type === 'group'),
});

export const countLabel = (roles, groups) => {
    const parts = [];
    if (roles) {
        parts.push(`${roles} ${roles === 1 ? 'role' : 'roles'}`);
    }
    if (groups) {
        parts.push(`${groups} ${groups === 1 ? 'group' : 'groups'}`);
    }
    return parts.join(', ');
};

export const matchSummary = (list, query) => {
    const { roles, groups } = splitByType(list);
    const parts = [];
    if (roles.length) {
        parts.push(`${roles.length} ${roles.length === 1 ? 'role' : 'roles'}`);
    }
    if (groups.length) {
        parts.push(
            `${groups.length} ${groups.length === 1 ? 'group' : 'groups'}`
        );
    }
    const match = parts.length ? parts.join(' and ') : '0 results';
    const verb = list.length === 1 ? 'matches' : 'match';
    return `${match} ${verb} '${query}' · every request needs approval`;
};

export const isRequestable = (item) =>
    item.memberStatus === SELF_SERVICE_MEMBER_STATUS.NONE;

export const isLeavable = (item) =>
    item.memberStatus === SELF_SERVICE_MEMBER_STATUS.MEMBER &&
    !item.inheritedFrom;

export const inheritedSource = (inheritedFrom) => {
    if (!inheritedFrom) {
        return { domain: '', name: '' };
    }
    const [domain, collection] = inheritedFrom.split(':');
    if (!collection) {
        return { domain: '', name: inheritedFrom };
    }
    const dot = collection.indexOf('.');
    const name = dot === -1 ? collection : collection.slice(dot + 1);
    return { domain: domain || '', name };
};

export const parseDate = (value) => {
    if (!value) {
        return null;
    }
    const date = /^\d{4}-\d{2}-\d{2}$/.test(value)
        ? new Date(`${value}T00:00:00`)
        : new Date(value);
    if (Number.isNaN(date.getTime())) {
        return null;
    }
    return date;
};

export const daysUntil = (value) => {
    const date = parseDate(value);
    if (!date) {
        return null;
    }
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    date.setHours(0, 0, 0, 0);
    return Math.round((date.getTime() - today.getTime()) / 86400000);
};
