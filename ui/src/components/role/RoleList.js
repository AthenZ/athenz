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
import styled from '@emotion/styled';
import { colors } from '../denali/styles';
import Button from '../denali/Button';
import SearchInput from '../denali/SearchInput';
import Alert from '../denali/Alert';
import { MODAL_TIME_OUT } from '../constants/constants';
import ButtonGroup from '../denali/ButtonGroup';
import NameUtils from '../utils/NameUtils';
import { connect } from 'react-redux';
import AddRole from './AddRole';
import RoleTable from './RoleTable';
import UserRoleTable from './UserRoleTable';
import { selectRoles } from '../../redux/selectors/roles';
import { selectDomainAuditEnabled } from '../../redux/selectors/domainData';
import AddMemberToRoles from './AddMemberToRoles';
import { selectIsLoading } from '../../redux/selectors/loading';
import {
    selectHeaderDetails,
    selectTimeZone,
} from '../../redux/selectors/domains';
import { ReduxPageLoader } from '../denali/ReduxPageLoader';

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

const StyledSearchInputDiv = styled.div`
    width: 50%;
`;

const AddContainerDiv = styled.div`
    padding-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-flow: row nowrap;
`;

class RoleList extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.state = {
            showAddRole: false,
            roles: props.roles || [],
            errorMessage: null,
            searchText: '',
        };
        this.toggleAddRole = this.toggleAddRole.bind(this);
        this.toggleAddMemberToRoles = this.toggleAddMemberToRoles.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.reloadRoles = this.reloadRoles.bind(this);
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

    componentDidUpdate = (prevProps, prevState) => {
        if (prevProps.domainName !== this.props.domainName) {
            this.setState({
                roles: this.props.roles,
                showAddRole: false,
                errorMessage: null,
                searchText: '',
            });
        }
        if (prevProps.roles !== this.props.roles) {
            this.setState({
                roles: this.props.roles,
            });
        }
        if (prevState.searchText !== this.state.searchText) {
            let roles = this.props.roles;
            if (this.state.searchText.trim() !== '') {
                roles = this.props.roles.filter((role) => {
                    return NameUtils.getShortName(':role.', role.name).includes(
                        this.state.searchText.trim()
                    );
                });
            }
            this.setState({ roles });
        }
    };

    reloadRoles(successMessage, showSuccess = true) {
        this.setState({
            showAddRole: false,
            showSuccess,
            successMessage,
            errorMessage: null,
        });
        // this is to close the success alert
        setTimeout(
            () =>
                this.setState({
                    showSuccess: false,
                    successMessage: '',
                }),
            MODAL_TIME_OUT
        );
    }

    closeModal() {
        this.setState({ showSuccess: null });
    }

    render() {
        let addRole = this.state.showAddRole ? (
            <AddRole
                domain={this.props.domainName}
                onSubmit={this.reloadRoles}
                onCancel={this.toggleAddRole}
                _csrf={this.props._csrf}
                showAddRole={this.state.showAddRole}
            />
        ) : (
            ''
        );
        let addMemberToRoles = this.state.showAddMemberToRoles ? (
            <AddMemberToRoles
                domain={this.props.domainName}
                onSubmit={this.reloadRoles}
                onCancel={this.toggleAddMemberToRoles}
                _csrf={this.props._csrf}
                showAddMemberToRoles={this.state.showAddMemberToRoles}
            />
        ) : (
            ''
        );
        const viewButtons = [
            { id: 'roles', name: 'roles', label: 'Roles' },
            { id: 'users', name: 'users', label: 'Users' },
        ];
        return this.props.isLoading.length !== 0 ? (
            <ReduxPageLoader message={'Loading roles'} />
        ) : (
            <RolesSectionDiv data-testid='rolelist'>
                <AddContainerDiv>
                    <SliderDiv>
                        <ButtonGroup
                            buttons={viewButtons}
                            selectedName={
                                this.props.showUser ? 'users' : 'roles'
                            }
                            onClick={this.props.showUserToggle}
                        />
                    </SliderDiv>
                    <StyledSearchInputDiv>
                        <SearchInput
                            dark={false}
                            name='search'
                            fluid={true}
                            value={this.state.searchText}
                            placeholder={
                                this.props.showUser
                                    ? 'Enter user name'
                                    : 'Enter role name'
                            }
                            error={this.state.error}
                            onChange={(event) =>
                                this.setState({
                                    searchText: event.target.value,
                                    error: false,
                                })
                            }
                        />
                    </StyledSearchInputDiv>
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
                {this.props.showUser ? (
                    <UserRoleTable
                        searchText={this.state.searchText}
                        domain={this.props.domainName}
                        timeZone={this.props.timeZone}
                        _csrf={this.props._csrf}
                        newMember={this.state.successMessage}
                    />
                ) : (
                    <RoleTable
                        domain={this.props.domainName}
                        prefixes={this.props.prefixes}
                        timeZone={this.props.timeZone}
                        _csrf={this.props._csrf}
                        onSubmit={this.reloadRoles}
                        newRole={this.state.successMessage}
                        roles={this.state.roles}
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

const mapStateToProps = (state, props) => {
    return {
        ...props,
        isLoading: selectIsLoading(state),
        roles: selectRoles(state),
        users: selectHeaderDetails(state),
        isDomainAuditEnabled: selectDomainAuditEnabled(state),
        timeZone: selectTimeZone(state),
    };
};

export default connect(mapStateToProps)(RoleList);
