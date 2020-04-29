/*
 * Copyright 2020 Verizon Media
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
const TableHeader = styled.th`
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    font-size: 0.7rem;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 15px;
    text-align: left;
`;

const TableHeaderDomain = styled.th`
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    font-size: 0.7rem;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 0px;
    text-align: left;
`;

const ApproveTableHeader = styled.th`
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    font-size: 0.7rem;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    text-align: center;
    padding: 5px 0 5px 15px;
`;

const RejectTableHeader = styled.th`
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    font-size: 0.7rem;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    text-align: center;
    border-right: none;
    padding: 5px 0 5px 15px;
`;

const DomainListTable = styled.table`
    margin-top: 20px;
    width: 100%;
    border-spacing: 0;
`;

export default class PendingApprovalTable extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.state = {
            checkedAll: false,
            pendingMap: this.props.pendingData,
            checkedList: [],
            selectAllAudit: '',
            selectAllDate: '',
        };
        this.checkAllBoxOnchange = this.checkAllBoxOnchange.bind(this);
        this.dateUtils = new DateUtils();
    }

    auditRefChange(key, event) {
        if (key === 'SelectAll') {
            this.setState({
                selectAllAudit: event.target.value,
            });
        } else {
            const pendingMap = this.state.pendingMap;
            pendingMap[key].auditRef = event.target.value;
            this.setState({
                pendingMap: pendingMap,
            });
        }
    }

    dateChange(key, date) {
        if (date && date.length > 0) {
            date = this.dateUtils.uxDatetimeToRDLTimestamp(date);
            if (key === 'SelectAll') {
                this.setState({
                    selectAllDate: date,
                });
            } else {
                const pendingMap = this.state.pendingMap;
                pendingMap[key].expiryDate = date;
                this.setState({
                    pendingMap: pendingMap,
                });
            }
        }
    }

    checkedChange(key) {
        const pos = this.state.checkedList.indexOf(key);
        let newList = this.state.checkedList;
        let pendingMap = this.state.pendingMap;
        if (pos === -1) {
            newList.push(key);
            pendingMap[key].auditRefMissing = false;
            if (newList.length === Object.keys(this.state.pendingMap).length) {
                this.setState({
                    checkedList: newList,
                    checkedAll: true,
                    pendingMap: pendingMap,
                });
            } else {
                this.setState({
                    checkedList: newList,
                    checkedAll: 2,
                    pendingMap: pendingMap,
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
        this.api
            .getPendingDomainRoleMembersList()
            .then((data) => {
                this.setState({
                    pendingMap: data,
                    checkedList: [],
                    selectAllAuditMissing: false,
                    selectAllDate: '',
                });
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
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
        if (key === 'SelectAll') {
            if (this.state.selectAllAudit === '') {
                this.setState({
                    selectAllAuditMissing: true,
                });
            } else {
                let promises = [];
                this.state.checkedList.forEach((key) => {
                    let membership = {
                        memberName: this.state.pendingMap[key].memberName,
                        approved,
                        expiration: this.state.selectAllDate,
                    };
                    promises.push(
                        this.api.processPending(
                            this.state.pendingMap[key].domainName,
                            this.state.pendingMap[key].roleName,
                            this.state.pendingMap[key].memberName,
                            this.state.selectAllAudit,
                            membership,
                            this.props._csrf
                        )
                    );
                });
                Promise.all(promises)
                    .then(() => {
                        this.initialLoad();
                    })
                    .catch((err) => {
                        this.setState({
                            errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                        });
                    });
            }
        } else {
            let auditRef = this.state.pendingMap[key].auditRef;
            if (auditRef === '') {
                let pendingMap = this.state.pendingMap;
                pendingMap[key].auditRefMissing = true;
                this.setState({
                    pendingMap: pendingMap,
                });
            } else {
                let membership = {
                    memberName: this.state.pendingMap[key].memberName,
                    approved,
                    expiration: this.state.pendingMap[key].expiryDate,
                };
                this.api
                    .processPending(
                        this.state.pendingMap[key].domainName,
                        this.state.pendingMap[key].roleName,
                        this.state.pendingMap[key].memberName,
                        this.state.pendingMap[key].auditRef,
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

    render() {
        let contents = [];
        let pendingDecision = this.pendingDecision.bind(this);
        let auditRefChange = this.auditRefChange.bind(this);
        let dateChange = this.dateChange.bind(this);
        let checkedClick = this.checkedChange.bind(this);
        if (this.state.pendingMap) {
            let i = 0;
            Object.keys(this.state.pendingMap).forEach((keyInMap) => {
                let pending = this.state.pendingMap[keyInMap];
                const domainName = pending.domainName;
                const memberName = pending.memberName;
                const defaultExpiration = pending.expiryDate;
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
                        clear={this.state.pendingMap[key].expiryDate}
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
                    />
                );
            });
        }
        return (
            <Fragment>
                {this.state.errorMessage && (
                    <Color name={'red600'}>{this.state.errorMessage}</Color>
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
                            api={this.api}
                            clear={this.state.selectAllDate}
                        />
                        <tr>
                            <TableHeader />
                            <TableHeaderDomain>Domain</TableHeaderDomain>
                            <TableHeader>Role</TableHeader>
                            <TableHeader>User</TableHeader>
                            <TableHeader colSpan={2}>User Comment</TableHeader>
                            <TableHeader>Requester</TableHeader>
                            <TableHeader>Request Time</TableHeader>
                            <TableHeader>Audit Reference</TableHeader>
                            <TableHeader>Expiration Date</TableHeader>
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
