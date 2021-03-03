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
import SearchInput from '../denali/SearchInput';
import Alert from '../denali/Alert';
import { MODAL_TIME_OUT } from '../constants/constants';
import RequestUtils from '../utils/RequestUtils';
import NameUtils from '../utils/NameUtils';
import GroupTable from './GroupTable';
import AddGroup from './AddGroup';

const GroupsSectionDiv = styled.div`
    margin: 20px;
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

export default class GroupList extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.state = {
            showAddGroup: false,
            groups: props.groups || [],
            errorMessage: null,
            searchText: '',
            error: false,
        };
        this.toggleAddGroup = this.toggleAddGroup.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.reloadGroups = this.reloadGroups.bind(this);
    }

    toggleAddGroup() {
        this.setState({
            showAddGroup: !this.state.showAddGroup,
        });
    }

    componentDidUpdate = (prevProps) => {
        if (prevProps.domain !== this.props.domain) {
            this.setState({
                groups: this.props.groups,
                showAddGroup: false,
                errorMessage: null,
                searchText: '',
            });
        }
    };

    reloadGroups(successMessage, groupName, showSuccess = true) {
        this.api
            .reloadGroups(this.props.domain, groupName)
            .then((groups) => {
                this.setState({
                    groups,
                    showAddGroup: false,
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
        let groups = this.state.groups;
        if (this.state.searchText.trim() !== '') {
            groups = this.state.groups.filter((group) => {
                return NameUtils.getShortName(':group.', group.name).includes(
                    this.state.searchText.trim()
                );
            });
        }
        let addGroup = this.state.showAddGroup ? (
            <AddGroup
                api={this.api}
                domain={this.props.domain}
                onSubmit={this.reloadGroups}
                onCancel={this.toggleAddGroup}
                _csrf={this.props._csrf}
                showAddGroup={this.state.showAddGroup}
                justificationRequired={this.props.isDomainAuditEnabled}
            />
        ) : (
            ''
        );

        let searchInput =
            this.state.groups.length > 0 ? (
                <SearchInput
                    dark={false}
                    name='search'
                    fluid={true}
                    value={this.state.searchText}
                    placeholder={'Enter group name'}
                    error={this.state.error}
                    onChange={(event) =>
                        this.setState({
                            searchText: event.target.value,
                            error: false,
                        })
                    }
                />
            ) : (
                'Click on Add Group button to create a new group.'
            );
        return (
            <GroupsSectionDiv data-testid='grouplist'>
                <AddContainerDiv>
                    <StyledSearchInputDiv>{searchInput}</StyledSearchInputDiv>
                    <div>
                        <Button secondary onClick={this.toggleAddGroup}>
                            Add Group
                        </Button>
                        {addGroup}
                    </div>
                </AddContainerDiv>
                {this.state.groups.length > 0 && (
                    <GroupTable
                        groups={groups}
                        api={this.api}
                        domain={this.props.domain}
                        _csrf={this.props._csrf}
                        onSubmit={this.reloadGroups}
                        justificationRequired={this.props.isDomainAuditEnabled}
                        userProfileLink={this.props.userProfileLink}
                        newGroup={this.state.successMessage}
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
            </GroupsSectionDiv>
        );
    }
}
