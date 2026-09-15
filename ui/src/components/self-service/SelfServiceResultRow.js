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
import React from 'react';
import styled from '@emotion/styled';
import Tag from '../denali/Tag';
import Button from '../denali/Button';
import Checkbox from '../denali/CheckBox';
import Menu from '../denali/Menu/Menu';
import { colors } from '../denali/styles';
import { SELF_SERVICE_MEMBER_STATUS } from '../constants/constants';
import { inheritedSource, resourceKey } from './selfServiceUtils';

const Row = styled.div`
    align-items: center;
    background: ${colors.white};
    box-shadow: 0 1px 4px rgba(0, 0, 0, 0.14);
    display: flex;
    gap: 12px;
    margin-bottom: 10px;
    padding: 12px 15px;
`;

const Info = styled.div`
    flex: 1 1 auto;
    min-width: 0;
`;

const TitleRow = styled.div`
    align-items: center;
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
`;

const NameLink = styled.a`
    color: ${colors.grey800};
    font: 600 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    text-decoration: none;
    &:hover {
        color: ${colors.brand700};
        text-decoration: underline;
    }
`;

const DomainName = styled.div`
    color: ${colors.grey600};
    font: 300 12px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    margin-top: 2px;
`;

const Description = styled.div`
    color: ${colors.grey700};
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    line-height: 1.45;
    margin-top: 6px;
`;

const Actions = styled.div`
    align-items: center;
    display: flex;
    flex: 0 0 auto;
    gap: 8px;
`;

const ActionLink = styled.button`
    background: none;
    border: none;
    color: ${colors.brand700};
    cursor: pointer;
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    padding: 0;
    &:hover {
        text-decoration: underline;
    }
    &:disabled {
        color: ${colors.grey500};
        cursor: not-allowed;
        pointer-events: none;
        text-decoration: none;
    }
`;

const Expiry = styled.div`
    color: ${(props) => (props.urgent ? colors.red600 : colors.grey600)};
    font: 300 12px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    margin-right: 12px;
    text-align: right;
    white-space: nowrap;
`;

const TooltipContent = styled.div`
    color: ${colors.grey700};
    font: 300 13px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    line-height: 1.5;
    max-width: 260px;
    padding: 10px 16px;
`;

const TooltipLink = styled.a`
    color: ${colors.brand700};
    text-decoration: none;
    &:hover {
        text-decoration: underline;
    }
`;

const parseDate = (value) => {
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

const formatDate = (value) => {
    const date = parseDate(value);
    if (!date) {
        return value || '';
    }
    return date.toLocaleDateString('en-GB', {
        day: 'numeric',
        month: 'short',
        year: 'numeric',
    });
};

const daysUntil = (value) => {
    const date = parseDate(value);
    if (!date) {
        return null;
    }
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    date.setHours(0, 0, 0, 0);
    return Math.round((date.getTime() - today.getTime()) / 86400000);
};

const membersHref = (item) => {
    const kind = item.type === 'group' ? 'group' : 'role';
    return `/domain/${item.domainName}/${kind}/${item.name}/members`;
};

// extending only makes sense when the membership can actually expire: either
// the role/domain sets a member_expiry_days cap (surfaced as maxExpiryDays,
// the effective minimum, 0 = unlimited) or the object self-renews within a
// selfRenewMins window. With neither, the membership is permanent and Extend
// is hidden.
const hasExpiryPolicy = (item) =>
    Number(item.maxExpiryDays) > 0 ||
    (item.selfRenew && Number(item.selfRenewMins) > 0);

export default class SelfServiceResultRow extends React.Component {
    renderPills(item) {
        const pills = [];
        if (this.props.variant === 'membership') {
            if (item.selfRenew) {
                pills.push(
                    <Tag key='renew' small>
                        Self renewable
                    </Tag>
                );
            }
            if (item.deleteProtection || item.reviewEnabled) {
                pills.push(
                    <Tag key='removal' small>
                        Removal needs approval
                    </Tag>
                );
            }
        } else if (item.memberStatus === SELF_SERVICE_MEMBER_STATUS.PENDING) {
            pills.push(
                <Tag key='pending' small>
                    Pending approval
                </Tag>
            );
        }
        if (item.inheritedFrom) {
            pills.push(
                <Tag key='inherited' small>
                    Inherited
                </Tag>
            );
        }
        if (item.auditEnabled) {
            pills.push(
                <Tag key='audit' small>
                    Audit enabled
                </Tag>
            );
        }
        return pills;
    }

    renderLeaveAction(item) {
        const key = resourceKey(item);
        const inherited = Boolean(item.inheritedFrom);
        const leave = (
            <ActionLink
                onClick={() => this.props.onLeave(item)}
                disabled={inherited}
                data-testid={`leave-${key}`}
            >
                Leave
            </ActionLink>
        );
        if (!inherited) {
            return leave;
        }
        const source = inheritedSource(item.inheritedFrom);
        const sourceDomain = source.domain || item.domainName;
        const groupName = source.name || item.inheritedFrom;
        const groupHref = `/domain/${sourceDomain}/group/${groupName}/members`;
        return (
            <Menu
                placement='top'
                interactive
                trigger={
                    <span data-testid={`leave-tooltip-${key}`}>{leave}</span>
                }
            >
                <TooltipContent>
                    You have this role through the {groupName} group in{' '}
                    <TooltipLink
                        href={groupHref}
                        data-testid={`leave-tooltip-link-${key}`}
                    >
                        {sourceDomain}
                    </TooltipLink>
                    . Leave that group to drop this role.
                </TooltipContent>
            </Menu>
        );
    }

    renderActions(item) {
        const key = resourceKey(item);
        if (this.props.variant === 'membership') {
            const days = daysUntil(item.expiration);
            // red only signals an imminent expiry (<= 14 days); otherwise grey
            const urgent = days !== null && days <= 14;
            return (
                <Actions>
                    {item.expiration && (
                        <Expiry urgent={urgent} data-testid='expiry-text'>
                            {urgent
                                ? `Expires ${formatDate(
                                      item.expiration
                                  )} · ${days} days left`
                                : `Expires ${formatDate(item.expiration)}`}
                        </Expiry>
                    )}
                    {item.memberStatus === SELF_SERVICE_MEMBER_STATUS.MEMBER &&
                        !item.inheritedFrom &&
                        hasExpiryPolicy(item) && (
                            <Button
                                secondary
                                size='small'
                                onClick={() => this.props.onExtend(item)}
                                data-testid={`extend-${key}`}
                            >
                                Extend
                            </Button>
                        )}
                    {item.memberStatus ===
                    SELF_SERVICE_MEMBER_STATUS.PENDING ? (
                        <ActionLink
                            onClick={() => this.props.onCancel(item)}
                            data-testid={`cancel-${key}`}
                        >
                            Cancel request
                        </ActionLink>
                    ) : (
                        this.renderLeaveAction(item)
                    )}
                </Actions>
            );
        }

        if (item.memberStatus === SELF_SERVICE_MEMBER_STATUS.PENDING) {
            return (
                <Actions>
                    <ActionLink
                        onClick={() => this.props.onCancel(item)}
                        data-testid={`cancel-${key}`}
                    >
                        Cancel request
                    </ActionLink>
                </Actions>
            );
        }
        if (item.memberStatus === SELF_SERVICE_MEMBER_STATUS.MEMBER) {
            return <Actions>{this.renderLeaveAction(item)}</Actions>;
        }
        return <Actions />;
    }

    render() {
        const { item, selected, selectable, onToggle } = this.props;
        const key = resourceKey(item);
        return (
            <Row data-testid='self-service-result-row'>
                <Checkbox
                    name={key}
                    checked={Boolean(selected)}
                    disabled={!selectable}
                    onChange={() => onToggle?.(item)}
                    data-testid={`select-${key}`}
                />
                <Info>
                    <TitleRow>
                        <NameLink
                            href={membersHref(item)}
                            target='_blank'
                            rel='noopener noreferrer'
                            data-testid={`self-service-row-link-${key}`}
                        >
                            {item.name}
                        </NameLink>
                        {this.renderPills(item)}
                    </TitleRow>
                    <DomainName data-testid='self-service-row-domain'>
                        {item.domainName}
                    </DomainName>
                    {item.description ? (
                        <Description>{item.description}</Description>
                    ) : null}
                </Info>
                {this.renderActions(item)}
            </Row>
        );
    }
}
