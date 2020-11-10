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

const TDName = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 0;
    vertical-align: middle;
    word-break: break-all;
    width: 29%;
`;

const TDModified = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 0;
    vertical-align: middle;
    word-break: break-all;
    width: 17%;
`;

const TDReview = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 0;
    vertical-align: middle;
    word-break: break-all;
    width: 12%;
`;

const TDIcon = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 0;
    vertical-align: middle;
    word-break: break-all;
    width: 9%;
`;

const TDDelete = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 0;
    vertical-align: middle;
    word-break: break-all;
    width: 6%;
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

export default class RoleSectionRow extends React.Component {
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
                <TDName color={color} align={left}>
                    {roleTypeIcon}
                    {roleAuditIcon}
                    {roleNameSpan}
                </TDName>
                <TDModified color={color} align={left}>
                    {this.localDate.getLocalDate(role.modified, 'UTC', 'UTC')}
                </TDModified>
                <TDReview color={color} align={left}>
                    {role.lastReviewedDate
                        ? this.localDate.getLocalDate(
                              role.lastReviewedDate,
                              'UTC',
                              'UTC'
                          )
                        : 'N/A'}
                </TDReview>
                <TDIcon color={color} align={center}>
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
                </TDIcon>
                <TDIcon color={color} align={center}>
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
                </TDIcon>
                <TDIcon color={color} align={center}>
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
                </TDIcon>
                <TDIcon color={color} align={center}>
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
                </TDIcon>
                <TDDelete color={color} align={center}>
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
                </TDDelete>
            </TrStyled>
        );

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
