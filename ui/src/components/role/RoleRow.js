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
import React from 'react';
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import NameUtils from '../utils/NameUtils';
import styled from '@emotion/styled';
import Switch from '../denali/Switch';
import DeleteModal from '../modal/DeleteModal';
import RoleMemberDetails from './RoleMemberDetails';
import RoleMemberReviewDetails from './RoleMemberReviewDetails';
import Menu from '../denali/Menu/Menu';
import DateUtils from '../utils/DateUtils';
import RequestUtils from '../utils/RequestUtils';

const TDStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
`;

const TrStyled = styled.tr`
    background-color: ${(props) => props.color};
`;

const MenuDiv = styled.div`
    padding: 5px 10px;
    background-color: black;
    color: white;
    font-size: 12px;
`;

const LeftSpan = styled.span`
    padding-left: 20px;
`;

export default class RoleRow extends React.Component {
    constructor(props) {
        super(props);
        this.api = this.props.api;
        this.onSubmitDelete = this.onSubmitDelete.bind(this);
        this.onClickDeleteCancel = this.onClickDeleteCancel.bind(this);
        this.updateRoleMeta = this.updateRoleMeta.bind(this);
        this.saveJustification = this.saveJustification.bind(this);
        this.onReviewSubmit = this.onReviewSubmit.bind(this);
        this.state = {
            name: NameUtils.getShortName(':role.', this.props.details.name),
            showDelete: false,
            reviewMembers: false,
            showMembers: false,
        };
        this.localDate = new DateUtils();
    }

    onReviewSubmit(message) {
        this.setState({ reviewMembers: false });
        if (message) {
            this.props.onUpdateSuccess(message);
        }
    }

    saveJustification(val) {
        this.setState({ deleteJustification: val });
    }

    onClickDelete(name) {
        this.setState({
            showDelete: true,
            deleteName: name,
        });
    }

    onSubmitDelete(domain) {
        let roleName = this.state.deleteName;
        if (
            this.props.justificationRequired &&
            (this.state.deleteJustification === undefined ||
                this.state.deleteJustification.trim() === '')
        ) {
            this.setState({
                errorMessage: 'Justification is required to delete a role',
            });
            return;
        }

        this.api
            .deleteRole(
                domain,
                roleName,
                this.state.deleteJustification
                    ? this.state.deleteJustification
                    : 'deleted using Athenz UI',
                this.props._csrf
            )
            .then(() => {
                this.setState({
                    showDelete: false,
                    deleteName: null,
                    deleteJustification: null,
                    errorMessage: null,
                });
                this.props.onUpdateSuccess(
                    `Successfully deleted role ${roleName}`
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    onClickDeleteCancel() {
        this.setState({
            showDelete: false,
            deleteName: '',
        });
    }

    updateRoleMeta(key, value) {
        let roleMeta = {};

        switch (key) {
            case 'selfServe':
                roleMeta.selfServe = value;
                roleMeta.reviewEnabled = this.props.details.reviewEnabled;
                break;
            case 'reviewEnabled':
                roleMeta.reviewEnabled = value;
                roleMeta.selfServe = this.props.details.selfServe;
                break;
        }

        this.api
            .putRoleMeta(
                this.props.domain,
                this.state.name,
                roleMeta,
                'Added using Athenz UI',
                this.props._csrf
            )
            .then(() =>
                this.props.onUpdateSuccess(
                    `Successfully updated metadata for role ${this.state.name}`
                )
            )
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    toggleSelfServe(selfServe) {
        this.updateRoleMeta('selfServe', !selfServe);
    }
    toggleReviewEnabled(reviewEnabled) {
        this.updateRoleMeta('reviewEnabled', !reviewEnabled);
    }
    expandRole() {
        if (this.state.reviewMembers) {
            this.setState({
                showMembers: !this.state.showMembers,
                reviewMembers: false,
            });
        } else {
            this.setState({ showMembers: !this.state.showMembers });
        }
    }
    expandReview() {
        if (this.state.showMembers) {
            this.setState({
                reviewMembers: !this.state.reviewMembers,
                showMembers: false,
            });
        } else {
            this.setState({ reviewMembers: !this.state.reviewMembers });
        }
    }

    render() {
        let rows = [];
        let left = 'left';
        let center = 'center';
        let role = this.props.details;
        let color = this.props.color;
        let idx = this.props.idx;

        let clickDeleteCancel = this.onClickDeleteCancel.bind(this);
        let submitDelete = this.onSubmitDelete.bind(this, this.props.domain);
        let clickDelete = this.onClickDelete.bind(this, this.state.name);
        let expandRole = this.expandRole.bind(
            this,
            this.props.domain,
            this.state.name
        );
        let expandReview = this.expandReview.bind(
            this,
            this.props.domain,
            this.state.name
        );

        let selfServe = !!role.selfServe;
        let toggleSelfServe = this.toggleSelfServe.bind(this, selfServe);
        let reviewEnabled = !!role.reviewEnabled;
        let toggleReviewEnabled = this.toggleReviewEnabled.bind(
            this,
            reviewEnabled
        );
        let iconDelegated = (
            <Menu
                placement='bottom-start'
                trigger={
                    <span>
                        <Icon
                            icon={'network'}
                            color={colors.icons}
                            isLink
                            size={'1.25em'}
                            verticalAlign={'text-bottom'}
                        />
                    </span>
                }
            >
                <MenuDiv>Delegated Role</MenuDiv>
            </Menu>
        );

        let auditEnabled = !!role.auditEnabled;
        let iconAudit = (
            <Menu
                placement='bottom-start'
                trigger={
                    <span>
                        <Icon
                            icon={'file-search'}
                            color={colors.icons}
                            isLink
                            size={'1.25em'}
                            verticalAlign={'text-bottom'}
                            onHover={'audit enabled role'}
                        />
                    </span>
                }
            >
                <MenuDiv>Audit Enabled Role</MenuDiv>
            </Menu>
        );

        let roleTypeIcon = role.trust ? iconDelegated : '';
        let roleAuditIcon = auditEnabled ? iconAudit : '';

        let roleNameSpan =
            roleTypeIcon === '' && roleAuditIcon === '' ? (
                <LeftSpan>{' ' + this.state.name}</LeftSpan>
            ) : (
                <span>{' ' + this.state.name}</span>
            );

        rows.push(
            <tr key={this.state.name} data-testid='role-row'>
                <TDStyled color={color} align={left}>
                    {roleTypeIcon}
                    {roleAuditIcon}
                    {roleNameSpan}
                </TDStyled>
                <TDStyled color={color} align={left}>
                    {this.localDate.getLocalDate(role.modified, 'UTC', 'UTC')}
                </TDStyled>
                <TDStyled color={color} align={left}>
                    {role.lastReviewedDate
                        ? this.localDate.getLocalDate(
                              role.lastReviewedDate,
                              'UTC',
                              'UTC'
                          )
                        : 'N/A'}
                </TDStyled>
                <TDStyled color={color} align={center}>
                    <Switch
                        name={'reviewEnabled-' + idx}
                        value={reviewEnabled}
                        checked={reviewEnabled}
                        onChange={toggleReviewEnabled}
                    />
                </TDStyled>
                <TDStyled color={color} align={center}>
                    <Switch
                        name={'selfServe-' + idx}
                        value={selfServe}
                        checked={selfServe}
                        onChange={toggleSelfServe}
                    />
                </TDStyled>
                <TDStyled color={color} align={center}>
                    <Menu
                        placement='bottom-start'
                        trigger={
                            <span>
                                <Icon
                                    icon={'user-group'}
                                    onClick={expandRole}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </span>
                        }
                    >
                        <MenuDiv>Show Members</MenuDiv>
                    </Menu>
                </TDStyled>
                <TDStyled color={color} align={center}>
                    <Menu
                        placement='bottom-start'
                        trigger={
                            <span>
                                <Icon
                                    icon={'assignment-priority'}
                                    onClick={expandReview}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </span>
                        }
                    >
                        <MenuDiv>Review Members</MenuDiv>
                    </Menu>
                </TDStyled>
                <TDStyled color={color} align={center}>
                    <Menu
                        placement='bottom-start'
                        trigger={
                            <span>
                                <Icon
                                    icon={'trash'}
                                    onClick={clickDelete}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </span>
                        }
                    >
                        <MenuDiv>Delete Role</MenuDiv>
                    </Menu>
                </TDStyled>
            </tr>
        );

        if (this.state.showMembers) {
            rows.push(
                <TrStyled
                    color={this.props.color}
                    key={this.state.name + '-members'}
                >
                    <RoleMemberDetails
                        color={this.props.color}
                        domain={this.props.domain}
                        role={this.state.name}
                        members={this.props.details.roleMembers}
                        api={this.api}
                        trust={this.props.details.trust}
                        _csrf={this.props._csrf}
                        justificationRequired={this.props.justificationRequired}
                        userProfileLink={this.props.userProfileLink}
                    />
                </TrStyled>
            );
        }
        if (this.state.reviewMembers) {
            rows.push(
                <TrStyled
                    color={this.props.color}
                    key={this.state.name + '-reviewMembers'}
                >
                    <RoleMemberReviewDetails
                        color={this.props.color}
                        domain={this.props.domain}
                        role={this.state.name}
                        members={this.props.details.roleMembers}
                        api={this.api}
                        _csrf={this.props._csrf}
                        justificationRequired={this.props.justificationRequired}
                        onUpdateSuccess={this.onReviewSubmit}
                    />
                </TrStyled>
            );
        }

        if (this.state.showDelete) {
            rows.push(
                <DeleteModal
                    name={this.state.deleteName}
                    isOpen={this.state.showDelete}
                    cancel={clickDeleteCancel}
                    submit={submitDelete}
                    key={this.state.deleteName + '-delete'}
                    showJustification={this.props.justificationRequired}
                    message={
                        'Are you sure you want to permanently delete the Role '
                    }
                    onJustification={this.saveJustification}
                    errorMessage={this.state.errorMessage}
                />
            );
        }
        return rows;
    }
}
