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
import Header from '../header/Header';
import Head from 'next/head';
import TabGroup from '../denali/TabGroup';
import Alert from '../denali/Alert';
import { colors } from '../denali/styles';
import RequestUtils from '../utils/RequestUtils';
import API from '../../api';
import {
    MODAL_TIME_OUT,
    SELF_SERVICE_MEMBER_STATUS,
    SELF_SERVICE_TABS,
    USER_DOMAIN,
} from '../constants/constants';
import SelfServiceSearchBar from './SelfServiceSearchBar';
import SelfServiceResultRow from './SelfServiceResultRow';
import SelfServiceSelectionBar from './SelfServiceSelectionBar';
import RequestAccessModal from './RequestAccessModal';
import LeaveResourceModal from './LeaveResourceModal';
import ExtendMembershipModal from './ExtendMembershipModal';
import {
    daysUntil,
    EXPIRING_SOON_DAYS,
    isLeavable,
    isRequestable,
    matchSummary,
    partitionRequestable,
    resourceKey,
    splitByType,
} from './selfServiceUtils';

const WRITE_CONCURRENCY = 5;

const runWithLimit = async (items, handler) => {
    const results = [];
    for (let index = 0; index < items.length; index += WRITE_CONCURRENCY) {
        const batch = items.slice(index, index + WRITE_CONCURRENCY);
        results.push(...(await Promise.all(batch.map(handler))));
    }
    return results;
};

const failedMessage = (failed, fallback) =>
    failed
        .map(
            (result) =>
                `${resourceKey(result.item)}: ${result.error || fallback}`
        )
        .join('\n');

const MainContentDiv = styled.div`
    flex: 1 1 calc(100vh - 60px);
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    overflow: hidden;
`;

const PageScrollDiv = styled.div`
    height: calc(100vh - 60px);
    overflow: auto;
`;

const PageHeaderDiv = styled.div`
    background: linear-gradient(to top, #f2f2f2, #fff);
    padding: 20px 30px 0;
`;

const TitleDiv = styled.div`
    font: 600 20px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

const SubtitleDiv = styled.div`
    color: ${colors.grey600};
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    margin: 8px 0 16px;
`;

const ContentDiv = styled.div`
    padding: 24px 30px 48px;
`;

const SummaryDiv = styled.div`
    color: ${colors.grey600};
    font: 300 13px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    margin: 16px 0 8px;
`;

const SectionLabel = styled.div`
    color: ${colors.grey600};
    font: 600 12px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    letter-spacing: 0.4px;
    margin-top: 24px;
    padding-bottom: 8px;
    text-transform: uppercase;
`;

const EmptyDiv = styled.div`
    color: ${colors.grey600};
    padding: 32px 0;
`;

const PendingHeader = styled.div`
    font: 600 16px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    margin-top: 32px;
    padding-bottom: 8px;
`;

export default class SelfServiceView extends React.Component {
    constructor(props) {
        super(props);
        this.api = API();
        this.searchRequestId = 0;
        this.onTabClick = this.onTabClick.bind(this);
        this.onQueryChange = this.onQueryChange.bind(this);
        this.onDomainChange = this.onDomainChange.bind(this);
        this.onSearch = this.onSearch.bind(this);
        this.closeAlert = this.closeAlert.bind(this);
        this.toggleSelect = this.toggleSelect.bind(this);
        this.clearSelection = this.clearSelection.bind(this);
        this.state = {
            selectedTab: SELF_SERVICE_TABS.FIND,
            query: '',
            submittedQuery: '',
            domain: '',
            domains: [],
            results: [],
            memberships: [],
            membershipCount: 0,
            searching: false,
            selected: {},
            requestItems: [],
            leaveItems: [],
            extendItem: null,
            leaveMode: 'leave',
            errorMessage: null,
            showSuccess: false,
            successTitle: '',
            successMessage: '',
            actionInFlight: false,
        };
    }

    componentDidMount() {
        // The domain filter is populated from actual search results, so the
        // dropdown starts with just "All domains" until the user searches.
        this.loadMemberships();
    }

    loadMemberships() {
        return this.api
            .searchSelfServe('', '', true)
            .then((data) => {
                this.setState({
                    memberships: data?.list ?? [],
                    membershipCount: data?.membershipCount ?? 0,
                    errorMessage: null,
                });
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.fetcherErrorCheckHelper(err),
                });
            });
    }

    onTabClick(tab) {
        this.setState({
            selectedTab: tab.name,
            selected: {},
            errorMessage: null,
        });
        if (tab.name === SELF_SERVICE_TABS.MINE) {
            this.loadMemberships();
        }
    }

    onQueryChange(evt) {
        this.setState({ query: evt.target.value });
    }

    onDomainChange(chosen) {
        const domain = chosen?.value ?? '';
        this.setState({ domain }, () => {
            if (
                this.state.selectedTab === SELF_SERVICE_TABS.FIND &&
                this.state.submittedQuery
            ) {
                this.onSearch(this.state.submittedQuery);
            }
        });
    }

    pruneSelected(list) {
        const keys = new Set(list.map(resourceKey));
        const selected = {};
        Object.entries(this.state.selected).forEach(([key, item]) => {
            if (keys.has(key)) {
                selected[key] = item;
            }
        });
        return selected;
    }

    onSearch(searchTerm) {
        const query =
            typeof searchTerm === 'string'
                ? searchTerm.trim()
                : this.state.query.trim();
        if (!query) {
            this.searchRequestId += 1;
            this.setState({
                submittedQuery: '',
                results: [],
                domains: [],
                domain: '',
                selected: {},
                errorMessage: null,
            });
            return;
        }
        const requestId = (this.searchRequestId += 1);
        this.setState({ searching: true, submittedQuery: query });
        return this.api
            .searchSelfServe(query, this.state.domain, false)
            .then((data) => {
                if (requestId !== this.searchRequestId) {
                    return;
                }
                const results = data?.list ?? [];
                this.setState({
                    results,
                    domains: data?.domains ?? this.state.domains,
                    membershipCount:
                        data?.membershipCount ?? this.state.membershipCount,
                    searching: false,
                    selected: this.pruneSelected(results),
                    errorMessage: null,
                });
            })
            .catch((err) => {
                if (requestId !== this.searchRequestId) {
                    return;
                }
                this.setState({
                    searching: false,
                    errorMessage: RequestUtils.fetcherErrorCheckHelper(err),
                });
            });
    }

    toggleSelect(item) {
        const key = resourceKey(item);
        const selected = { ...this.state.selected };
        if (selected[key]) {
            delete selected[key];
        } else {
            selected[key] = item;
        }
        this.setState({ selected });
    }

    clearSelection() {
        this.setState({ selected: {} });
    }

    selectedItems() {
        return Object.values(this.state.selected);
    }

    runAction(item, action, extra = {}) {
        return this.api
            .updateSelfServe(
                {
                    domainName: item.domainName,
                    name: item.name,
                    type: item.type,
                    action,
                    auditRef: extra.justification ?? extra.auditRef ?? '',
                    justification: extra.justification ?? extra.auditRef ?? '',
                    expiration: extra.expiration ?? '',
                    reviewReminder: extra.reviewReminder ?? '',
                },
                this.props._csrf
            )
            .then((result) => ({ item, ok: true, result }))
            .catch((err) => ({
                item,
                ok: false,
                error: RequestUtils.fetcherErrorCheckHelper(err),
            }));
    }

    refreshAfterAction() {
        const tasks = [];
        if (this.state.submittedQuery) {
            tasks.push(this.onSearch(this.state.submittedQuery));
        }
        tasks.push(this.loadMemberships());
        return Promise.all(tasks);
    }

    showSuccess(title, description) {
        this.setState({
            showSuccess: true,
            successTitle: title,
            successMessage: description,
            requestItems: [],
            leaveItems: [],
            selected: {},
            errorMessage: null,
            actionInFlight: false,
        });
        setTimeout(() => this.closeAlert(), MODAL_TIME_OUT);
    }

    closeAlert() {
        this.setState({ showSuccess: false });
    }

    async handleRequestSubmit(payload) {
        if (this.state.actionInFlight) {
            return;
        }
        const items = this.state.requestItems;
        this.setState({ actionInFlight: true, errorMessage: null });
        const results = await runWithLimit(items, (item) =>
            this.runAction(item, 'request', payload)
        );
        const failed = results.filter((result) => !result.ok);
        if (failed.length === items.length) {
            this.setState({
                errorMessage: failedMessage(
                    failed,
                    'Unable to submit request.'
                ),
                actionInFlight: false,
            });
            return;
        }
        if (failed.length) {
            await this.refreshAfterAction();
            this.setState({
                requestItems: failed.map((result) => result.item),
                selected: Object.fromEntries(
                    failed.map((result) => [
                        resourceKey(result.item),
                        result.item,
                    ])
                ),
                errorMessage: failedMessage(
                    failed,
                    'Unable to submit request.'
                ),
                actionInFlight: false,
            });
            return;
        }
        await this.refreshAfterAction();
        const okCount = items.length;
        this.showSuccess(
            okCount === 1
                ? 'Request submitted'
                : `${okCount} requests submitted`,
            'A reviewer will decide. You can track requests under My Roles & Groups.'
        );
    }

    async handleLeaveSubmit(justification) {
        if (this.state.actionInFlight) {
            return;
        }
        const items = this.state.leaveItems;
        const action = this.state.leaveMode === 'cancel' ? 'cancel' : 'leave';
        this.setState({ actionInFlight: true, errorMessage: null });
        const results = await runWithLimit(items, (item) =>
            this.runAction(item, action, { justification })
        );
        const failed = results.filter((result) => !result.ok);
        if (failed.length === items.length) {
            this.setState({
                errorMessage: failedMessage(
                    failed,
                    'Unable to complete this action.'
                ),
                actionInFlight: false,
            });
            return;
        }
        if (failed.length) {
            await this.refreshAfterAction();
            this.setState({
                leaveItems: failed.map((result) => result.item),
                selected: Object.fromEntries(
                    failed.map((result) => [
                        resourceKey(result.item),
                        result.item,
                    ])
                ),
                errorMessage: failedMessage(
                    failed,
                    'Unable to complete this action.'
                ),
                actionInFlight: false,
            });
            return;
        }
        await this.refreshAfterAction();
        const okCount = items.length;
        if (action === 'cancel') {
            this.showSuccess(
                'Request withdrawn',
                okCount === 1
                    ? `Your request for ${items[0].name} was cancelled.`
                    : `${okCount} requests were cancelled.`
            );
            return;
        }
        this.showSuccess(
            okCount === 1
                ? 'Membership removed'
                : `${okCount} memberships removed`,
            okCount === 1
                ? `You left ${resourceKey(items[0])}.`
                : 'You can request them again from Find Roles & Groups.'
        );
    }

    openExtend(item) {
        this.setState({ extendItem: item, errorMessage: null });
    }

    handleExtendSubmit(expiration) {
        if (this.state.actionInFlight) {
            return;
        }
        const item = this.state.extendItem;
        if (!item) {
            return;
        }
        this.setState({ actionInFlight: true, errorMessage: null });
        this.runAction(item, 'extend', { expiration }).then(async (outcome) => {
            if (!outcome.ok) {
                this.setState({
                    errorMessage: outcome.error,
                    actionInFlight: false,
                });
                return;
            }
            this.setState({ extendItem: null });
            await this.refreshAfterAction();
            const approved = outcome.result?.approved;
            if (approved === false) {
                this.showSuccess(
                    'Request submitted',
                    `Your extension request for ${item.name} will be reviewed.`
                );
            } else if (approved === true) {
                this.showSuccess(
                    'Membership extended',
                    `${item.name} was renewed.`
                );
            } else {
                this.showSuccess(
                    'Extension submitted',
                    `Your extension for ${item.name} has been submitted.`
                );
            }
        });
    }

    renderSection(label, list, selectableFn, variant) {
        if (!list.length) {
            return null;
        }
        return (
            <>
                <SectionLabel>
                    {label} ({list.length})
                </SectionLabel>
                {list.map((item) =>
                    this.renderRow(item, selectableFn, variant)
                )}
            </>
        );
    }

    renderRow(item, selectableFn, variant) {
        const key = resourceKey(item);
        const selectable = selectableFn(item);
        return (
            <SelfServiceResultRow
                key={key}
                item={item}
                variant={variant}
                selected={Boolean(this.state.selected[key])}
                selectable={selectable}
                onToggle={selectable ? this.toggleSelect : undefined}
                onLeave={(row) =>
                    this.setState({
                        leaveItems: [row],
                        leaveMode: 'leave',
                        errorMessage: null,
                    })
                }
                onCancel={(row) =>
                    this.setState({
                        leaveItems: [row],
                        leaveMode: 'cancel',
                        errorMessage: null,
                    })
                }
                onExtend={(row) => this.openExtend(row)}
            />
        );
    }

    renderFindResults() {
        const { submittedQuery, results, searching } = this.state;
        if (!submittedQuery) {
            return (
                <EmptyDiv>
                    Search by name or description to find self-service roles and
                    groups.
                </EmptyDiv>
            );
        }
        if (searching) {
            return <EmptyDiv>Searching…</EmptyDiv>;
        }
        if (!results.length) {
            return (
                <EmptyDiv>
                    No self-service roles or groups match '{submittedQuery}'.
                </EmptyDiv>
            );
        }

        const { available, hidden } = partitionRequestable(
            results,
            this.state.memberships
        );
        if (!available.length) {
            return (
                <EmptyDiv>
                    You already hold or have requested everything matching '
                    {submittedQuery}'. Manage these under My Roles & Groups.
                </EmptyDiv>
            );
        }
        const { roles, groups } = splitByType(available);
        return (
            <>
                <SummaryDiv>
                    {matchSummary(available, submittedQuery)}
                    {hidden > 0 &&
                        ` · ${hidden} already held or requested hidden`}
                </SummaryDiv>
                {this.renderSection('Roles', roles, isRequestable)}
                {this.renderSection('Groups', groups, isRequestable)}
            </>
        );
    }

    renderMyRoles() {
        const memberships = this.state.memberships;
        const members = memberships.filter(
            (item) => item.memberStatus === SELF_SERVICE_MEMBER_STATUS.MEMBER
        );
        const pending = memberships.filter(
            (item) => item.memberStatus === SELF_SERVICE_MEMBER_STATUS.PENDING
        );
        const { roles, groups } = splitByType(members);
        const { roles: pendingRoles, groups: pendingGroups } =
            splitByType(pending);
        const expiringSoon = members.filter((item) => {
            const days = daysUntil(item.expiration);
            return days !== null && days >= 0 && days <= EXPIRING_SOON_DAYS;
        }).length;
        return (
            <>
                <SummaryDiv>
                    {members.length} memberships · {expiringSoon} expiring
                    within {EXPIRING_SOON_DAYS} days · {pending.length}{' '}
                    {pending.length === 1
                        ? 'request awaiting approval'
                        : 'requests awaiting approval'}
                </SummaryDiv>
                {members.length === 0 && (
                    <EmptyDiv>
                        You do not currently hold any self-service roles or
                        groups.
                    </EmptyDiv>
                )}
                {this.renderSection('Roles', roles, isLeavable, 'membership')}
                {this.renderSection('Groups', groups, isLeavable, 'membership')}
                {pending.length > 0 && (
                    <>
                        <PendingHeader>Pending requests</PendingHeader>
                        {this.renderSection(
                            'Roles',
                            pendingRoles,
                            () => false,
                            'pending'
                        )}
                        {this.renderSection(
                            'Groups',
                            pendingGroups,
                            () => false,
                            'pending'
                        )}
                    </>
                )}
            </>
        );
    }

    render() {
        const memberName = `${USER_DOMAIN}.${this.props.userName}`;
        const selectedItems = this.selectedItems();
        const findTab = this.state.selectedTab === SELF_SERVICE_TABS.FIND;
        const modalOpen =
            this.state.requestItems.length > 0 ||
            this.state.leaveItems.length > 0 ||
            Boolean(this.state.extendItem);
        const tabs = [
            {
                label: 'Find Roles & Groups',
                name: SELF_SERVICE_TABS.FIND,
            },
            {
                label: () => (
                    <span>
                        My Roles & Groups ({this.state.membershipCount})
                    </span>
                ),
                name: SELF_SERVICE_TABS.MINE,
            },
        ];
        return (
            <div data-testid='self-service'>
                <Head>
                    <title>Self Service - Athenz</title>
                </Head>
                <Header showSearch={true} />
                <MainContentDiv>
                    <PageScrollDiv>
                        <PageHeaderDiv>
                            <TitleDiv>Self Service</TitleDiv>
                            <SubtitleDiv>
                                Find roles and groups you can request without a
                                ticket, and manage the ones you already hold.
                            </SubtitleDiv>
                            <TabGroup
                                tabs={tabs}
                                selectedName={this.state.selectedTab}
                                onClick={this.onTabClick}
                                equalWidth={false}
                            />
                        </PageHeaderDiv>
                        <ContentDiv>
                            {findTab && (
                                <>
                                    <SelfServiceSearchBar
                                        query={this.state.query}
                                        domain={this.state.domain}
                                        domains={this.state.domains}
                                        onQueryChange={this.onQueryChange}
                                        onDomainChange={this.onDomainChange}
                                        onSearch={this.onSearch}
                                    />
                                    {this.renderFindResults()}
                                </>
                            )}
                            {!findTab && this.renderMyRoles()}
                        </ContentDiv>
                        <SelfServiceSelectionBar
                            items={selectedItems}
                            mode={findTab ? 'request' : 'leave'}
                            onClear={this.clearSelection}
                            onPrimary={() =>
                                findTab
                                    ? this.setState({
                                          requestItems: selectedItems,
                                          errorMessage: null,
                                      })
                                    : this.setState({
                                          leaveItems: selectedItems,
                                          leaveMode: 'leave',
                                          errorMessage: null,
                                      })
                            }
                        />
                    </PageScrollDiv>
                </MainContentDiv>
                {this.state.requestItems.length > 0 && (
                    <RequestAccessModal
                        isOpen={true}
                        items={this.state.requestItems}
                        memberName={memberName}
                        errorMessage={this.state.errorMessage}
                        saving={this.state.actionInFlight ? 'saving' : ''}
                        onCancel={() =>
                            this.setState({
                                requestItems: [],
                                errorMessage: null,
                            })
                        }
                        onSubmit={(payload) =>
                            this.handleRequestSubmit(payload)
                        }
                    />
                )}
                {this.state.leaveItems.length > 0 && (
                    <LeaveResourceModal
                        isOpen={true}
                        items={this.state.leaveItems}
                        mode={this.state.leaveMode}
                        errorMessage={this.state.errorMessage}
                        saving={this.state.actionInFlight ? 'saving' : ''}
                        onCancel={() =>
                            this.setState({
                                leaveItems: [],
                                errorMessage: null,
                            })
                        }
                        onSubmit={(justification) =>
                            this.handleLeaveSubmit(justification)
                        }
                    />
                )}
                {this.state.extendItem && (
                    <ExtendMembershipModal
                        isOpen={true}
                        item={this.state.extendItem}
                        errorMessage={this.state.errorMessage}
                        saving={this.state.actionInFlight ? 'saving' : ''}
                        onCancel={() =>
                            this.setState({
                                extendItem: null,
                                errorMessage: null,
                            })
                        }
                        onSubmit={(expiration) =>
                            this.handleExtendSubmit(expiration)
                        }
                    />
                )}
                <Alert
                    isOpen={Boolean(this.state.errorMessage) && !modalOpen}
                    title='Self-service error'
                    description={this.state.errorMessage}
                    type='danger'
                    onClose={() => this.setState({ errorMessage: null })}
                />
                <Alert
                    isOpen={this.state.showSuccess}
                    title={this.state.successTitle}
                    description={this.state.successMessage}
                    type='success'
                    onClose={this.closeAlert}
                />
            </div>
        );
    }
}
