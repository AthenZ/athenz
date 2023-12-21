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
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import NameUtils from '../utils/NameUtils';
import styled from '@emotion/styled';
import DeleteModal from '../modal/DeleteModal';
import Menu from '../denali/Menu/Menu';
import DateUtils from '../utils/DateUtils';
import RequestUtils from '../utils/RequestUtils';
import { withRouter } from 'next/router';
import { css, keyframes } from '@emotion/react';
import { deleteGroup } from '../../redux/thunks/groups';
import { connect } from 'react-redux';

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
    padding: 5px 0 5px 15px;
    ${(props) =>
        props.isSuccess &&
        css`
            animation: ${colorTransition} 3s ease;
        `}
`;

const colorTransition = keyframes`
    0% {
        background-color: rgba(21, 192, 70, 0.20);
    }
    100% {
        background-color: transparent;
    }
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

class GroupRow extends React.Component {
    constructor(props) {
        super(props);
        this.onSubmitDelete = this.onSubmitDelete.bind(this);
        this.onClickDeleteCancel = this.onClickDeleteCancel.bind(this);
        this.saveJustification = this.saveJustification.bind(this);
        this.state = {
            name: NameUtils.getShortName(':group.', this.props.details.name),
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

    onClickFunction(route) {
        this.props.router.push(route, route);
    }

    onSubmitDelete() {
        let groupName = this.state.deleteName;
        if (
            this.props.justificationRequired &&
            (this.state.deleteJustification === undefined ||
                this.state.deleteJustification.trim() === '')
        ) {
            this.setState({
                errorMessage: 'Justification is required to delete a group',
            });
            return;
        }

        let auditRef = this.state.deleteJustification
            ? this.state.deleteJustification
            : 'deleted using Athenz UI';
        this.props
            .deleteGroup(groupName, auditRef, this.props._csrf)
            .then(() => {
                this.setState({
                    showDelete: false,
                    deleteName: null,
                    deleteJustification: null,
                    errorMessage: null,
                });
                this.props.onUpdateSuccess(
                    `Successfully deleted group ${groupName}`,
                    groupName
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
        let group = this.props.details;
        let color = this.props.color;
        let idx = this.props.idx;

        let clickMembers = this.onClickFunction.bind(
            this,
            `/domain/${this.props.domain}/group/${this.state.name}/members`
        );
        let clickSettings = this.onClickFunction.bind(
            this,
            `/domain/${this.props.domain}/group/${this.state.name}/settings`
        );
        let clickHistory = this.onClickFunction.bind(
            this,
            `/domain/${this.props.domain}/group/${this.state.name}/history`
        );
        let clickRoles = this.onClickFunction.bind(
            this,
            `/domain/${this.props.domain}/group/${this.state.name}/roles`
        );
        let clickTag = this.onClickFunction.bind(
            this,
            `/domain/${this.props.domain}/group/${this.state.name}/tags`
        );

        let clickDelete = this.onClickDelete.bind(this, this.state.name);
        let submitDelete = this.onSubmitDelete.bind(this, this.props.domain);
        let clickDeleteCancel = this.onClickDeleteCancel.bind(this);

        let auditEnabled = !!group.auditEnabled;
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
                        />
                    </span>
                }
            >
                <MenuDiv>Audit Enabled Group</MenuDiv>
            </Menu>
        );

        let AuditIcon = auditEnabled ? iconAudit : '';

        let NameSpan =
            AuditIcon === '' ? (
                <LeftSpan>{' ' + this.state.name}</LeftSpan>
            ) : (
                <span>{' ' + this.state.name}</span>
            );
        let newGroupAnimation =
            this.props.domain + '-' + this.state.name === this.props.newGroup;

        rows.push(
            <TrStyled
                key={this.state.name}
                data-testid='group-row'
                isSuccess={newGroupAnimation}
            >
                <TDStyled color={color} align={left}>
                    {AuditIcon}
                    {NameSpan}
                </TDStyled>
                <TDStyled color={color} align={center}>
                    {this.localDate.getLocalDate(
                        group.modified,
                        this.props.timeZone,
                        this.props.timeZone
                    )}
                </TDStyled>
                <TDStyled color={color} align={center}>
                    {group.lastReviewedDate
                        ? this.localDate.getLocalDate(
                              group.lastReviewedDate,
                              this.props.timeZone,
                              this.props.timeZone
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
                                    icon={'network'}
                                    onClick={clickRoles}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </span>
                        }
                    >
                        <MenuDiv>Roles</MenuDiv>
                    </Menu>
                </TDStyled>
                <TDStyled color={color} align={center}>
                    <Menu
                        placement='bottom-start'
                        trigger={
                            <span>
                                <Icon
                                    icon={'tag'}
                                    onClick={clickTag}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </span>
                        }
                    >
                        <MenuDiv>Tags</MenuDiv>
                    </Menu>
                </TDStyled>
                <TDStyled color={color} align={center}>
                    <Menu
                        placement='bottom-start'
                        trigger={
                            <span>
                                <Icon
                                    id={`group-settings-icon-${this.state.name}`}
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
                                    icon={'time-history'}
                                    onClick={clickHistory}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </span>
                        }
                    >
                        <MenuDiv>History</MenuDiv>
                    </Menu>
                </TDStyled>
                <TDStyled color={color} align={center}>
                    <Menu
                        placement='bottom-start'
                        trigger={
                            <span>
                                <Icon
                                    id={`delete-group-icon-${this.state.name}`}
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
                        <MenuDiv>Delete Group</MenuDiv>
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
                        'Are you sure you want to permanently delete the Group '
                    }
                    onJustification={this.saveJustification}
                    errorMessage={this.state.errorMessage}
                />
            );
        }
        return rows;
    }
}

const mapDispatchToProps = (dispatch) => ({
    deleteGroup: (groupName, auditRef, _csrf) =>
        dispatch(deleteGroup(groupName, auditRef, _csrf)),
});

export default connect(null, mapDispatchToProps)(withRouter(GroupRow));
