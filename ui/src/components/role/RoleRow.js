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
import { Router } from '../../routes.js';
import DeleteModal from '../modal/DeleteModal';
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
    box-sizing: border-box;
    margin-top: 10px;
    box-shadow: 0 1px 4px #d9d9d9;
    border: 1px solid #fff;
    -webkit-border-image: none;
    border-image: none;
    -webkit-border-image: initial;
    border-image: initial;
    height: 50px;
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
        this.saveJustification = this.saveJustification.bind(this);
        this.state = {
            name: NameUtils.getShortName(':role.', this.props.details.name),
            showDelete: false,
        };
        this.localDate = new DateUtils();
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

    onClickFunction(route, domain, role) {
        Router.pushRoute(route, { domain: domain, role: role });
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
            errorMessage: null,
        });
    }

    render() {
        let rows = [];
        let left = 'left';
        let center = 'center';
        let role = this.props.details;
        let color = this.props.color;
        let idx = this.props.idx;

        let clickMembers = this.onClickFunction.bind(
            this,
            'members',
            this.props.domain,
            this.state.name
        );
        let clickReview = this.onClickFunction.bind(
            this,
            'review',
            this.props.domain,
            this.state.name
        );
        let clickSettings = this.onClickFunction.bind(
            this,
            'settings',
            this.props.domain,
            this.state.name
        );
        let clickPolicy = this.onClickFunction.bind(
            this,
            'role-policy',
            this.props.domain,
            this.state.name
        );

        let clickDelete = this.onClickDelete.bind(this, this.state.name);
        let submitDelete = this.onSubmitDelete.bind(this, this.props.domain);
        let clickDeleteCancel = this.onClickDeleteCancel.bind(this);

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
            <TrStyled key={this.state.name} data-testid='role-row'>
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
                    <Menu
                        placement='bottom-start'
                        trigger={
                            <span>
                                <Icon
                                    icon={'user-group'}
                                    onClick={clickMembers}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </span>
                        }
                    >
                        <MenuDiv>Members</MenuDiv>
                    </Menu>
                </TDStyled>
                <TDStyled color={color} align={center}>
                    <Menu
                        placement='bottom-start'
                        trigger={
                            <span>
                                <Icon
                                    icon={'assignment-priority'}
                                    onClick={clickReview}
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
                                    icon={'list-check'}
                                    onClick={clickPolicy}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </span>
                        }
                    >
                        <MenuDiv>Rule Policy</MenuDiv>
                    </Menu>
                </TDStyled>
                <TDStyled color={color} align={center}>
                    <Menu
                        placement='bottom-start'
                        trigger={
                            <span>
                                <Icon
                                    icon={'setting'}
                                    onClick={clickSettings}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </span>
                        }
                    >
                        <MenuDiv>Settings</MenuDiv>
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
            </TrStyled>
        );

        if (this.state.showDelete) {
            rows.push(
                <DeleteModal
                    name={this.state.deleteName}
                    isOpen={this.state.showDelete}
                    cancel={clickDeleteCancel}
                    submit={submitDelete}
                    key={this.state.deleteName + '-delete' + idx}
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
