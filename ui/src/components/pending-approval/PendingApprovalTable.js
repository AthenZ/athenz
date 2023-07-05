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
import React, { Fragment } from 'react';
import styled from '@emotion/styled';
import { colors } from '../denali/styles';
import PendingApprovalTableRow from './PendingApprovalTableRow';
import PendingApprovalTableHeader from './PendingApprovalTableHeader';
import Color from '../../components/denali/Color';
import DateUtils from '../utils/DateUtils';
import RequestUtils from '../utils/RequestUtils';
import {
    DATE_BEFORE_CURRENT_TIME_ERROR_MESSAGE,
    PENDING_APPROVAL_KEY_ENUM,
    PENDING_APPROVAL_TYPE_ENUM,
} from '../constants/constants';
import produce from 'immer';
import { processPendingMembers } from '../../redux/thunks/domains';
import { connect } from 'react-redux';
import {
    selectPendingMembersList,
    selectTimeZone,
} from '../../redux/selectors/domains';
import NameUtils from '../utils/NameUtils';

const TableHeader = styled.th`
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    font-size: 1.1rem;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 15px;
    text-align: left;
    white-space: nowrap;
`;

const TableHeaderDomain = styled.th`
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    font-size: 1.1rem;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 0px;
    text-align: left;
`;

const ApproveTableHeader = styled.th`
    border-top: 1px solid ${colors.grey500};
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    background: ${colors.white};
    font-weight: 600;
    font-size: 1.1rem;
    vertical-align: top;
    text-transform: uppercase;
    text-align: center;
    position: absolute;
    width: 7.6em;
    right: 7.6em;
    z-index: 1;
    height: 12.9px;
    padding-bottom: 5px;
    padding: 5px 0 5px 15px;
    white-space: nowrap;
`;

const RejectTableHeader = styled.th`
    border-top: 1px solid ${colors.grey500};
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    background: ${colors.white};
    font-weight: 600;
    font-size: 1.1rem;
    vertical-align: top;
    text-transform: uppercase;
    text-align: center;
    border-right: none;
    position: absolute;
    width: 7.6em;
    right: 0em;
    z-index: 1;
    height: 12.9px;
    padding-bottom: 5px;
    padding: 5px 0 5px 15px;
    white-space: nowrap;
`;

const DomainListTable = styled.table`
    margin-top: 20px;
    width: 100%;
    border-spacing: 0;
`;

class PendingApprovalTable extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            checkedAll: false,
            pendingMap: props.pendingData,
            checkedList: [],
            selectAllAudit: '',
            selectAllDateExpiry: '',
            selectAllDateReviewReminder: '',
        };
        this.checkAllBoxOnchange = this.checkAllBoxOnchange.bind(this);
        this.dateUtils = new DateUtils();
    }

    auditRefChange(key, event) {
        if (key === PENDING_APPROVAL_KEY_ENUM.SELECTALL) {
            this.setState({
                selectAllAudit: event.target.value,
            });
        } else {
            let pendingMap = produce(this.state.pendingMap, (draft) => {
                draft[key].auditRef = event.target.value;
            });
            this.setState({
                pendingMap: pendingMap,
            });
        }
    }

    dateChange(key, date, type) {
        if (date && date.length > 0) {
            date = this.dateUtils.uxDatetimeToRDLTimestamp(date);
        } else {
            date = null;
        }

        if (key === PENDING_APPROVAL_KEY_ENUM.SELECTALL) {
            if (type === PENDING_APPROVAL_TYPE_ENUM.EXPIRY) {
                this.setState({
                    selectAllDateExpiry: date,
                });
            } else {
                this.setState({
                    selectAllDateReviewReminder: date,
                });
            }
        } else {
            let pendingMap = produce(this.state.pendingMap, (draft) => {
                if (type === PENDING_APPROVAL_TYPE_ENUM.EXPIRY) {
                    draft[key].expiryDate = date;
                } else {
                    draft[key].reviewReminder = date;
                }
            });
            this.setState({
                pendingMap: pendingMap,
            });
        }
    }

    checkedChange(key) {
        const pos = this.state.checkedList.indexOf(key);
        let newList = this.state.checkedList;
        if (pos === -1) {
            newList.push(key);
            let newPendingMap = produce(this.state.pendingMap, (draft) => {
                draft[key].auditRefMissing = false;
            });
            if (newList.length === Object.keys(newPendingMap).length) {
                this.setState({
                    checkedList: newList,
                    checkedAll: true,
                    pendingMap: newPendingMap,
                });
            } else {
                this.setState({
                    checkedList: newList,
                    checkedAll: 2,
                    pendingMap: newPendingMap,
                });
            }
        } else {
            newList.splice(pos, 1);
            if (newList.length === 0) {
                this.setState({
                    checkedList: newList,
                    checkedAll: false,
                    selectAllAuditMissing: false,
                });
            } else {
                this.setState({
                    checkedList: newList,
                    checkedAll: 2,
                });
            }
        }
    }

    initialLoad() {
        this.setState({
            checkedList: [],
            selectAllAuditMissing: false,
            selectAllDateExpiry: '',
            selectAllReviewReminder: '',
            error: '',
        });
    }

    checkAllBoxOnchange() {
        let newList = [];
        if (this.state.checkedAll) {
            this.setState({
                checkedAll: false,
                checkedList: newList,
                selectAllAuditMissing: false,
            });
        } else {
            newList = Object.keys(this.state.pendingMap);
            this.setState({
                checkedList: newList,
                checkedAll: true,
            });
        }
    }

    pendingDecision(key, approved) {
        if (key === PENDING_APPROVAL_KEY_ENUM.SELECTALL) {
            if (this.state.selectAllAudit === '') {
                this.setState({
                    selectAllAuditMissing: true,
                });
            } else {
                // if reject action, no need to validate date
                if (
                    approved &&
                    (this.dateUtils.validateDate(
                        this.state.selectAllDateExpiry
                    ) ||
                        this.dateUtils.validateDate(
                            this.state.selectAllDateReviewReminder
                        ))
                ) {
                    this.setState({
                        errorMessage: DATE_BEFORE_CURRENT_TIME_ERROR_MESSAGE,
                    });
                    return;
                }
                this.state.checkedList.forEach((key) => {
                    let membership = {
                        memberName: this.state.pendingMap[key].memberName,
                        approved,
                        expiration: this.state.selectAllDateExpiry,
                        reviewReminder: this.state.selectAllDateReviewReminder,
                        pendingState: this.state.pendingMap[key].pendingState,
                    };
                    this.props
                        .processPending(
                            this.state.pendingMap[key].domainName,
                            this.state.pendingMap[key].roleName,
                            this.state.pendingMap[key].memberName,
                            this.state.selectAllAudit,
                            this.state.pendingMap[key].category,
                            membership,
                            this.props._csrf
                        )
                        .catch((err) => {
                            this.setState({
                                errorMessage:
                                    RequestUtils.xhrErrorCheckHelper(err),
                            });
                        });
                });
                this.initialLoad();
                this.checkAllBoxOnchange();
                this.setState({
                    selectAllAudit: '',
                });
            }
        } else {
            let auditRef = this.state.pendingMap[key].auditRef;
            if (auditRef === '') {
                let pendingMap = produce(this.state.pendingMap, (draft) => {
                    draft[key].auditRefMissing = true;
                });
                this.setState({
                    pendingMap: pendingMap,
                });
            } else {
                // if reject action, no need to validate date
                if (
                    approved &&
                    (this.dateUtils.validateDate(
                        this.state.pendingMap[key].expiryDate
                    ) ||
                        this.dateUtils.validateDate(
                            this.state.pendingMap[key].reviewReminder
                        ))
                ) {
                    this.setState({
                        errorMessage: DATE_BEFORE_CURRENT_TIME_ERROR_MESSAGE,
                    });
                    return;
                }

                let membership = {
                    memberName: this.state.pendingMap[key].memberName,
                    approved,
                    expiration: this.state.pendingMap[key].expiryDate,
                    reviewReminder: this.state.pendingMap[key].reviewReminder,
                    pendingState: this.state.pendingMap[key].pendingState,
                };
                this.props
                    .processPending(
                        this.state.pendingMap[key].domainName,
                        this.state.pendingMap[key].roleName,
                        this.state.pendingMap[key].memberName,
                        this.state.pendingMap[key].auditRef,
                        this.state.pendingMap[key].category,
                        membership,
                        this.props._csrf
                    )
                    .then(() => {
                        this.initialLoad();
                    })
                    .catch((err) => {
                        this.setState({
                            errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                        });
                    });
            }
        }
    }

    componentDidUpdate(prevProps, prevState, snapshot) {
        if (prevProps.pendingData !== this.props.pendingData) {
            this.setState({
                pendingMap: this.props.pendingData,
            });
        }
    }

    render() {
        const { view } = this.props;
        let contents = [];
        let pendingDecision = this.pendingDecision.bind(this);
        let auditRefChange = this.auditRefChange.bind(this);
        let dateChange = this.dateChange.bind(this);
        let checkedClick = this.checkedChange.bind(this);
        if (this.state.pendingMap) {
            let i = 0;
            Object.keys(this.state.pendingMap).forEach((keyInMap) => {
                let pending = this.state.pendingMap[keyInMap];
                const category = pending.category;
                const domainName = pending.domainName;
                const memberName = pending.memberName;
                const defaultExpiration = pending.expiryDate;
                const defaultReviewReminder = pending.reviewReminder;
                let color = '';
                if (i % 2 === 0) {
                    color = colors.row;
                }
                i += 1;
                const roleName = pending.roleName;
                const key = domainName + memberName + roleName;
                let checked;
                checked = this.state.checkedList.indexOf(key) !== -1;
                const userComment = pending.userComment;
                contents.push(
                    <PendingApprovalTableRow
                        category={category}
                        domainName={domainName}
                        memberName={memberName}
                        roleName={roleName}
                        userComment={userComment}
                        color={color}
                        checked={checked}
                        auditRefChange={auditRefChange}
                        dateChange={dateChange}
                        checkedClick={checkedClick}
                        pendingDecision={pendingDecision}
                        auditRefMissing={
                            this.state.pendingMap[key].auditRefMissing
                        }
                        key={domainName + roleName + memberName}
                        defaultExpiration={defaultExpiration}
                        defaultReviewReminder={defaultReviewReminder}
                        clearExpiry={this.state.pendingMap[key].expiryDate}
                        clearReviewReminder={
                            this.state.pendingMap[key].reviewReminder
                        }
                        requestPrincipal={
                            this.state.pendingMap[key].requestPrincipal
                        }
                        requestTime={this.state.pendingMap[key].requestTime}
                        requestPrincipalFull={
                            this.state.pendingMap[key].requestPrincipalFull
                        }
                        memberNameFull={
                            this.state.pendingMap[key].memberNameFull
                        }
                        requestedExpiry={this.state.pendingMap[key].expiryDate}
                        requestedReviewReminder={
                            this.state.pendingMap[key].reviewReminder
                        }
                        pendingState={this.state.pendingMap[key].pendingState}
                        view={view}
                        timeZone={this.props.timeZone}
                    />
                );
            });
        }

        let newErrorMessage = '';
        if (this.state.errorMessage) {
            newErrorMessage = this.state.errorMessage
                .split('\n')
                .map((str) => <p>{str}</p>);
        }

        return (
            <Fragment>
                {this.state.errorMessage && (
                    <Color name={'red600'}>{newErrorMessage}</Color>
                )}
                <DomainListTable data-testid='pending-approval-table'>
                    <thead>
                        <PendingApprovalTableHeader
                            checked={this.state.checkedAll}
                            onChange={this.checkAllBoxOnchange}
                            checkedList={this.state.checkedList}
                            pendingDecision={pendingDecision}
                            auditRefChange={auditRefChange}
                            dateChange={dateChange}
                            auditRefMissing={this.state.selectAllAuditMissing}
                            clearExpiry={this.state.selectAllDateExpiry}
                            clearReviewReminder={
                                this.state.selectAllDateReviewReminder
                            }
                            view={view}
                        />
                        <tr>
                            <TableHeader />
                            {view === 'admin' && (
                                <TableHeaderDomain>Domain</TableHeaderDomain>
                            )}
                            <TableHeader>Type</TableHeader>
                            <TableHeader>Pending State</TableHeader>
                            <TableHeader>Name</TableHeader>
                            <TableHeader>Member</TableHeader>
                            <TableHeader colSpan={2}>User Comment</TableHeader>
                            <TableHeader>Requester</TableHeader>
                            <TableHeader>Request Time</TableHeader>
                            <TableHeader>Audit Reference</TableHeader>
                            <TableHeader>Expiration Date</TableHeader>
                            <TableHeader>Reminder Date</TableHeader>
                            <ApproveTableHeader>Approve</ApproveTableHeader>
                            <RejectTableHeader>Reject</RejectTableHeader>
                        </tr>
                    </thead>
                    <tbody>{contents}</tbody>
                </DomainListTable>
            </Fragment>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        pendingData: selectPendingMembersList(
            state,
            props.domainName,
            props.view
        ),
        timeZone: selectTimeZone(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    processPending: (
        domainName,
        roleName,
        memberName,
        auditRef,
        category,
        membership,
        _csrf
    ) =>
        dispatch(
            processPendingMembers(
                domainName,
                roleName,
                memberName,
                auditRef,
                category,
                membership,
                _csrf
            )
        ),
});

export default connect(
    mapStateToProps,
    mapDispatchToProps
)(PendingApprovalTable);
