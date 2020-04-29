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
import Switch from '../denali/Switch';
import { colors } from '../denali/styles';
import Button from '../denali/Button';
import RoleTable from './RoleTable';
import UserRoleTable from './UserRoleTable';
import AddRole from './AddRole';
import Alert from '../denali/Alert';
import AddMemberToRoles from './AddMemberToRoles';
import { MODAL_TIME_OUT } from '../constants/constants';
import RequestUtils from '../utils/RequestUtils';

const RolesSectionDiv = styled.div`
    margin: 20px;
`;

const RoleLabel = styled.label`
    color: ${colors.grey800};
    margin-left: 5px;
    white-space: nowrap;
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

const SliderDiv = styled.div`
    vertical-align: middle;
`;

const AddContainerDiv = styled.div`
    padding-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-flow: row nowrap;
`;

export default class RoleList extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.state = {
            showuser: false,
            showAddRole: false,
            roles: props.roles || [],
            errorMessage: null,
        };
        this.viewRoleByUser = this.viewRoleByUser.bind(this);
        this.toggleAddRole = this.toggleAddRole.bind(this);
        this.toggleAddMemberToRoles = this.toggleAddMemberToRoles.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.reloadRoles = this.reloadRoles.bind(this);
    }

    viewRoleByUser() {
        this.setState({ showuser: !this.state.showuser });
    }

    toggleAddRole() {
        this.setState({
            showAddRole: !this.state.showAddRole,
        });
    }

    toggleAddMemberToRoles() {
        this.setState({
            showAddMemberToRoles: !this.state.showAddMemberToRoles,
        });
    }

    componentDidUpdate = (prevProps) => {
        if (prevProps.domain !== this.props.domain) {
            this.setState({
                roles: this.props.roles,
                showuser: false,
            });
        }
    };

    reloadRoles(successMessage) {
        this.api
            .getRoles(this.props.domain)
            .then((roles) => {
                this.setState({
                    roles,
                    showAddRole: false,
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
        let addRole = this.state.showAddRole ? (
            <AddRole
                api={this.api}
                domain={this.props.domain}
                onSubmit={this.reloadRoles}
                onCancel={this.toggleAddRole}
                _csrf={this.props._csrf}
                showAddRole={this.state.showAddRole}
                justificationRequired={this.props.isDomainAuditEnabled}
            />
        ) : (
            ''
        );
        let addMemberToRoles = this.state.showAddMemberToRoles ? (
            <AddMemberToRoles
                api={this.api}
                domain={this.props.domain}
                onSubmit={this.reloadRoles}
                onCancel={this.toggleAddMemberToRoles}
                _csrf={this.props._csrf}
                showAddMemberToRoles={this.state.showAddMemberToRoles}
                roles={this.state.roles}
                justificationRequired={this.props.isDomainAuditEnabled}
            />
        ) : (
            ''
        );
        return (
            <RolesSectionDiv data-testid='rolelist'>
                <AddContainerDiv>
                    <SliderDiv>
                        <Switch
                            name={'viewRoleByUser'}
                            checked={!!this.state.showuser}
                            onChange={this.viewRoleByUser}
                        />
                        <RoleLabel>View Roles By Users</RoleLabel>
                    </SliderDiv>
                    <div>
                        <Button secondary onClick={this.toggleAddRole}>
                            Add Role
                        </Button>
                        {addRole}
                        <Button secondary onClick={this.toggleAddMemberToRoles}>
                            Add Member
                        </Button>
                        {addMemberToRoles}
                    </div>
                </AddContainerDiv>
                {this.state.showuser ? (
                    <UserRoleTable
                        users={this.props.users}
                        roles={this.state.roles}
                        api={this.api}
                        domain={this.props.domain}
                        _csrf={this.props._csrf}
                        justificationRequired={this.props.isDomainAuditEnabled}
                    />
                ) : (
                    <RoleTable
                        roles={this.state.roles}
                        api={this.api}
                        domain={this.props.domain}
                        _csrf={this.props._csrf}
                        onSubmit={this.reloadRoles}
                        justificationRequired={this.props.isDomainAuditEnabled}
                        userProfileLink={this.props.userProfileLink}
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
            </RolesSectionDiv>
        );
    }
}
