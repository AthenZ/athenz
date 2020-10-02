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
import styled from '@emotion/styled';
import AddMemberForm from './AddMemberForm';
import Loader from '../denali/Loader';
import RoleMember from './RoleMember';
import RoleAuditLog from './RoleAuditLog';
import Color from '../denali/Color';
import DeleteModal from '../modal/DeleteModal';
import Alert from '../denali/Alert';
import { MODAL_TIME_OUT } from '../constants/constants';
import RequestUtils from '../utils/RequestUtils';

const TDStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 30px 20px;
    vertical-align: middle;
    word-break: break-all;
`;
const TitleDiv = styled.div`
    font-size: 16px;
    font-weight: 600;
`;
const AddMemberDiv = styled.div`
    margin: 15px 0;
`;
const AllMembersDiv = styled.div`
    margin: 15px 0;
    display: flex;
`;
const ApprovedMembersDiv = styled.div`
    width: 57%;
`;
const PendingMembersDiv = styled.div`
    width: 43%;
`;
const RoleMembersDiv = styled.div`
    flex-flow: row wrap;
    align-items: center;
    justify-content: flex-start;
`;

const AuditLogContainerDiv = styled.div`
    margin: 0;
`;

const StyledColor = styled(Color)`
    margin-bottom: 10px;
`;

export default class RoleMemberDetails extends React.Component {
    constructor(props) {
        super(props);
        this.onChange = this.onChange.bind(this);
        this.onError = this.onError.bind(this);
        this.onSubmitDelete = this.onSubmitDelete.bind(this);
        this.onClickDeleteCancel = this.onClickDeleteCancel.bind(this);
        this.onClickDelete = this.onClickDelete.bind(this);
        this.onClickPendingDelete = this.onClickPendingDelete.bind(this);
        this.saveJustification = this.saveJustification.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.state = {
            members: this.props.members || [],
            trust: this.props.trust || '',
            auditLog: [],
            showDelete: false,
            deleteJustification: undefined,
            deletePending: false,
        };
        this.loadRole();
    }
    onChange(successMessage) {
        this.setState({
            showSuccess: true,
            successMessage,
        });
        this.loadRole();
        // this is to close the success alert
        setTimeout(
            () =>
                this.setState({
                    showSuccess: false,
                }),
            MODAL_TIME_OUT
        );
    }

    saveJustification(val) {
        this.setState({ deleteJustification: val });
    }

    onClickDelete(name) {
        this.setState({
            showDelete: true,
            deleteName: name,
            deletePending: false,
        });
    }

    onClickPendingDelete(name) {
        this.setState({
            showDelete: true,
            deleteName: name,
            deletePending: true,
        });
    }

    closeModal() {
        this.setState({
            showSuccess: null,
        });
    }

    onSubmitDelete() {
        if (
            this.state.justificationRequired &&
            (this.state.deleteJustification === undefined ||
                this.state.deleteJustification.trim() === '')
        ) {
            this.setState({
                errorMessage: 'Justification is required to delete a member',
            });
            return;
        }
        if (this.state.deletePending) {
            this.props.api
                .deletePendingMember(
                    this.props.domain,
                    this.props.role,
                    this.state.deleteName,
                    this.state.deleteJustification
                        ? this.state.deleteJustification
                        : 'deleted using Athenz UI',
                    this.props._csrf
                )
                .then(() => {
                    this.setState({
                        showDelete: false,
                        errorMessage: null,
                        deleteJustification: undefined,
                        deletePending: false,
                    });
                    this.onChange(
                        `Successfully deleted ${this.state.deleteName} from role ${this.props.role}.`
                    );
                })
                .catch((err) => {
                    this.setState({
                        errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                    });
                });
        } else {
            this.props.api
                .deleteMember(
                    this.props.domain,
                    this.props.role,
                    this.state.deleteName,
                    this.state.deleteJustification
                        ? this.state.deleteJustification
                        : 'deleted using Athenz UI',
                    this.props._csrf
                )
                .then(() => {
                    this.setState({
                        showDelete: false,
                        errorMessage: null,
                        deleteJustification: undefined,
                        deletePending: false,
                    });
                    this.onChange(
                        `Successfully deleted ${this.state.deleteName} from role ${this.props.role}.`
                    );
                })
                .catch((err) => {
                    this.setState({
                        errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                    });
                });
        }
    }

    onClickDeleteCancel() {
        this.setState({
            showDelete: false,
            deleteName: '',
            errorMessage: null,
            deletePending: false,
        });
    }

    loadRole() {
        this.props.api
            .getRole(this.props.domain, this.props.role, true, true, true)
            .then((role) => {
                let justificationRequired =
                    this.props.justificationRequired ||
                    role.auditEnabled ||
                    role.reviewEnabled ||
                    role.selfServe;
                this.setState({
                    members: role.roleMembers || [],
                    trust: role.trust || '',
                    auditLog: role.auditLog || [],
                    roleObj: role,
                    justificationRequired,
                    showDelete: false,
                });
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    getTrustContent() {
        if (this.state.trust) {
            return <h5>Delegated to: {this.state.trust}</h5>;
        } else {
            return (
                <AddMemberDiv>
                    <AddMemberForm
                        api={this.props.api}
                        domain={this.props.domain}
                        role={this.props.role}
                        _csrf={this.props._csrf}
                        onChange={this.onChange}
                        roleObj={this.state.roleObj}
                        justificationRequired={this.state.justificationRequired}
                    />
                </AddMemberDiv>
            );
        }
    }

    onError(message) {
        this.setState({
            errorMessage: message,
        });
    }

    renderRoleMembers(memberStatus) {
        if (this.state.members) {
            let items = this.state.members
                .filter((item) =>
                    this.state.trust
                        ? memberStatus
                        : item.approved === memberStatus
                )
                .map((item, idx) => {
                    return (
                        <RoleMember
                            key={idx}
                            item={item}
                            domain={this.props.domain}
                            role={this.props.role}
                            api={this.props.api}
                            noanim
                            _csrf={this.props._csrf}
                            onClickRemove={this.onClickDelete}
                            onClickPendingRemove={this.onClickPendingDelete}
                            onError={this.onError}
                            userProfileLink={this.props.userProfileLink}
                        />
                    );
                });
            return <RoleMembersDiv>{items}</RoleMembersDiv>;
        } else {
            return (
                <RoleMembersDiv>
                    <Loader />
                </RoleMembersDiv>
            );
        }
    }

    render() {
        let { color } = this.props;
        return (
            <TDStyled
                color={color}
                colSpan={8}
                data-testid='role-member-details'
            >
                <TitleDiv>
                    Members (
                    {this.state.members ? this.state.members.length : 0})
                </TitleDiv>
                {this.getTrustContent()}
                <AllMembersDiv>
                    <ApprovedMembersDiv>
                        <TitleDiv>Approved</TitleDiv>
                        <RoleMembersDiv>
                            {this.renderRoleMembers(true)}
                        </RoleMembersDiv>
                    </ApprovedMembersDiv>
                    <PendingMembersDiv>
                        <TitleDiv>Pending Approval</TitleDiv>
                        <RoleMembersDiv>
                            {this.renderRoleMembers(false)}
                        </RoleMembersDiv>
                    </PendingMembersDiv>
                </AllMembersDiv>
                {this.state.errorMessage && (
                    <StyledColor name={'red600'}>
                        {this.state.errorMessage}
                    </StyledColor>
                )}
                {this.getRoleAuditLog()}
                {this.state.showDelete && (
                    <DeleteModal
                        name={this.state.deleteName}
                        isOpen={this.state.showDelete}
                        cancel={this.onClickDeleteCancel}
                        submit={this.onSubmitDelete}
                        key={this.state.deleteName + '-delete'}
                        message={
                            'Are you sure you want to permanently delete the member '
                        }
                        showJustification={this.state.justificationRequired}
                        onJustification={this.saveJustification}
                        errorMessage={this.state.errorMessage}
                    />
                )}
                {this.state.showSuccess ? (
                    <Alert
                        isOpen={this.state.showSuccess}
                        title={this.state.successMessage}
                        onClose={this.closeModal}
                        type='success'
                    />
                ) : null}
            </TDStyled>
        );
    }

    getRoleAuditLog() {
        let auditLogCount = this.state.auditLog.length || 0;
        if (auditLogCount > 0) {
            return (
                <AuditLogContainerDiv>
                    <TitleDiv>Member History ({auditLogCount})</TitleDiv>
                    <RoleAuditLog
                        auditLogRows={this.state.auditLog}
                        color={'white'}
                    />
                </AuditLogContainerDiv>
            );
        } else {
            return (
                <AuditLogContainerDiv>
                    <TitleDiv>Member History ({auditLogCount})</TitleDiv>
                </AuditLogContainerDiv>
            );
        }
    }
}
