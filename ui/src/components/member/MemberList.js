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
import Button from '../denali/Button';
import MemberTable from './MemberTable';
import Alert from '../denali/Alert';
import AddMember from './AddMember';
import { MODAL_TIME_OUT } from '../constants/constants';
import RequestUtils from '../utils/RequestUtils';

const MembersSectionDiv = styled.div`
    margin: 20px;
`;

const AddContainerDiv = styled.div`
    padding-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-flow: row nowrap;
    float: right;
`;

export default class MemberList extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.state = {
            showuser: false,
            showAddMember: false,
            members: props.members || [],
            errorMessage: null,
        };
        this.toggleAddMember = this.toggleAddMember.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.reloadMembers = this.reloadMembers.bind(this);
    }

    toggleAddMember() {
        this.setState({
            showAddMember: !this.state.showAddMember,
        });
    }

    componentDidUpdate = (prevProps) => {
        if (
            prevProps.role !== this.props.role ||
            prevProps.domain !== this.props.domain
        ) {
            this.setState({
                members: this.props.members,
                showuser: false,
            });
        }
    };

    reloadMembers(successMessage) {
        this.api
            .getRole(this.props.domain, this.props.role, true, true, true)
            .then((role) => {
                this.setState({
                    members: role.roleMembers,
                    showAddMember: false,
                    showSuccess: true,
                    successMessage,
                    errorMessage: null,
                });
                // this is to close the success alert
                setTimeout(
                    () =>
                        this.setState({
                            showSuccess: false,
                        }),
                    MODAL_TIME_OUT
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    closeModal() {
        this.setState({ showSuccess: null });
    }

    render() {
        const { domain, role } = this.props;
        const right = 'right';

        let approvedMembers = this.state.members.filter(
            (item) => item.approved
        );
        let pendingMembers = this.state.members.filter(
            (item) => !item.approved
        );
        let showPending = pendingMembers.length > 0;

        let addMember = this.state.showAddMember ? (
            <AddMember
                api={this.api}
                domain={this.props.domain}
                role={this.props.role}
                onSubmit={this.reloadMembers}
                onCancel={this.toggleAddMember}
                _csrf={this.props._csrf}
                showAddMember={this.state.showAddMember}
                justificationRequired={this.props.isDomainAuditEnabled}
            />
        ) : (
            ''
        );
        return (
            <MembersSectionDiv data-testid='member-list'>
                <AddContainerDiv>
                    <div>
                        <Button secondary onClick={this.toggleAddMember}>
                            Add Member
                        </Button>
                        {addMember}
                    </div>
                </AddContainerDiv>
                <MemberTable
                    domain={domain}
                    role={role}
                    members={approvedMembers}
                    caption='Approved'
                    api={this.api}
                    _csrf={this.props._csrf}
                    onSubmit={this.reloadMembers}
                    justificationRequired={this.props.isDomainAuditEnabled}
                    userProfileLink={this.props.userProfileLink}
                />
                <br />
                {showPending ? (
                    <MemberTable
                        domain={domain}
                        role={role}
                        members={pendingMembers}
                        caption='Pending'
                        api={this.api}
                        _csrf={this.props._csrf}
                        onSubmit={this.reloadMembers}
                        justificationRequired={this.props.isDomainAuditEnabled}
                        userProfileLink={this.props.userProfileLink}
                    />
                ) : null}
                {this.state.showSuccess ? (
                    <Alert
                        isOpen={this.state.showSuccess}
                        title={this.state.successMessage}
                        onClose={this.closeModal}
                        type='success'
                    />
                ) : null}
            </MembersSectionDiv>
        );
    }
}
