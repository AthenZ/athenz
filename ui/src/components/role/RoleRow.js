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
import { deleteRole } from '../../redux/thunks/roles';
import { connect } from 'react-redux';
import { selectDomainAuditEnabled } from '../../redux/selectors/domainData';

const TDStyledName = styled.div`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
    width: 28%;
`;

const TDStyledTime = styled.div`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
    width: 16%;
`;

const TDStyledIcon = styled.div`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
    width: 7%;
`;

const TrStyled = styled.div`
    box-sizing: border-box;
    margin-top: 10px;
    box-shadow: 0 1px 4px #d9d9d9;
    border: 1px solid #fff;
    -webkit-border-image: none;
    border-image: none;
    -webkit-border-image: initial;
    border-image: initial;
    display: flex;
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

class RoleRow extends React.Component {
    constructor(props) {
        super(props);
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

    onClickFunction(route) {
        this.props.router.push(route, route);
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
        let auditRef = this.state.deleteJustification
            ? this.state.deleteJustification
            : 'deleted using Athenz UI';
        this.props
            .deleteRole(roleName, auditRef, this.props._csrf)
            .then((thenRoleName) => {
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
            `/domain/${this.props.domain}/role/${this.state.name}/members`
        );
        let clickReview = this.onClickFunction.bind(
            this,
            `/domain/${this.props.domain}/role/${this.state.name}/review`
        );
        let clickSettings = this.onClickFunction.bind(
            this,
            `/domain/${this.props.domain}/role/${this.state.name}/settings`
        );
        let clickPolicy = this.onClickFunction.bind(
            this,
            `/domain/${this.props.domain}/role/${this.state.name}/policy`
        );
        let clickHistory = this.onClickFunction.bind(
            this,
            `/domain/${this.props.domain}/role/${this.state.name}/history`
        );
        let clickTag = this.onClickFunction.bind(
            this,
            `/domain/${this.props.domain}/role/${this.state.name}/tags`
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

        let iconDescription = (
            <Menu
                placement='bottom-start'
                trigger={
                    <span data-testid='description-icon'>
                        <Icon
                            icon={'information-circle'}
                            color={colors.icons}
                            size={'1.15em'}
                            verticalAlign={'text-bottom'}
                            enableTitle={false}
                            onClick={() => {
                                this.setState({
                                    recentlyCopiedToClipboard: true,
                                });
                                setTimeout(
                                    () =>
                                        this.setState({
                                            recentlyCopiedToClipboard: false,
                                        }),
                                    1000
                                );
                                navigator.clipboard.writeText(role.description);
                            }}
                        />
                    </span>
                }
            >
                <MenuDiv>
                    {this.state.recentlyCopiedToClipboard
                        ? 'Copied to clipboard'
                        : role.description}
                </MenuDiv>
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

        let reviewRequired =
            role.reviewEnabled && (role.memberExpiryDays || role.serviceExpiry);

        let roleTypeIcon = role.trust ? iconDelegated : '';
        let roleDescriptionIcon = role.description ? iconDescription : '';
        let roleAuditIcon = auditEnabled ? iconAudit : '';

        let roleNameSpan =
            roleTypeIcon === '' && roleAuditIcon === '' ? (
                <LeftSpan>{' ' + this.state.name}</LeftSpan>
            ) : (
                <span>{' ' + this.state.name}</span>
            );
        let newRole =
            this.props.newRole === this.props.domain + '-' + this.state.name;
        rows.push(
            <TrStyled
                key={this.state.name}
                data-testid='role-row'
                isSuccess={newRole}
            >
                <TDStyledName color={color} align={left}>
                    {roleTypeIcon}
                    {roleAuditIcon}
                    {roleNameSpan} {roleDescriptionIcon}
                </TDStyledName>
                <TDStyledTime color={color} align={left}>
                    {this.localDate.getLocalDate(
                        role.modified,
                        this.props.timeZone,
                        this.props.timeZone
                    )}
                </TDStyledTime>
                <TDStyledTime color={color} align={left}>
                    {role.lastReviewedDate
                        ? this.localDate.getLocalDate(
                              role.lastReviewedDate,
                              this.props.timeZone,
                              this.props.timeZone
                          )
                        : 'N/A'}
                </TDStyledTime>
                <TDStyledIcon color={color} align={center}>
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
                </TDStyledIcon>
                <TDStyledIcon color={color} align={center}>
                    <Menu
                        placement='bottom-start'
                        trigger={
                            <span>
                                <Icon
                                    icon={'assignment-priority'}
                                    onClick={clickReview}
                                    color={
                                        reviewRequired
                                            ? colors.red200
                                            : colors.icons
                                    }
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </span>
                        }
                    >
                        <MenuDiv>Review Members</MenuDiv>
                    </Menu>
                </TDStyledIcon>
                <TDStyledIcon color={color} align={center}>
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
                </TDStyledIcon>
                <TDStyledIcon color={color} align={center}>
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
                </TDStyledIcon>
                <TDStyledIcon color={color} align={center}>
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
                </TDStyledIcon>
                <TDStyledIcon color={color} align={center}>
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
                </TDStyledIcon>
                <TDStyledIcon color={color} align={center}>
                    <Menu
                        placement='bottom-start'
                        trigger={
                            <span>
                                <Icon
                                    id={`${this.state.name}-delete-role-button`}
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
                </TDStyledIcon>
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

const mapStateToProps = (state, props) => {
    return {
        ...props,
        justificationRequired: selectDomainAuditEnabled(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    deleteRole: (roleName, auditRef, _csrf) =>
        dispatch(deleteRole(roleName, auditRef, _csrf)),
});

export default connect(
    mapStateToProps,
    mapDispatchToProps
)(withRouter(RoleRow));
