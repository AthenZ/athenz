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
import Button from '../denali/Button';
import SearchInput from '../denali/SearchInput';
import Alert from '../denali/Alert';
import { MODAL_TIME_OUT } from '../constants/constants';
import NameUtils from '../utils/NameUtils';
import AddGroup from './AddGroup';
import GroupTable from './GroupTable';
import { connect } from 'react-redux';
import { selectGroups } from '../../redux/selectors/groups';
import { selectDomainAuditEnabled } from '../../redux/selectors/domainData';
import { selectIsLoading } from '../../redux/selectors/loading';
import { selectTimeZone } from '../../redux/selectors/domains';
import { ReduxPageLoader } from '../denali/ReduxPageLoader';

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

class GroupList extends React.Component {
    constructor(props) {
        super(props);
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

    componentDidUpdate = (prevProps, prevState) => {
        if (prevProps.domain !== this.props.domain) {
            this.setState({
                groups: this.props.groups,
                showAddGroup: false,
                errorMessage: null,
                searchText: '',
            });
        }
        if (prevProps.groups !== this.props.groups) {
            this.setState({
                groups: this.props.groups,
            });
        }
        if (prevState.searchText !== this.state.searchText) {
            let groups = this.props.groups;
            if (this.state.searchText.trim() !== '') {
                groups = this.props.groups.filter((group) => {
                    return NameUtils.getShortName(
                        ':group.',
                        group.name
                    ).includes(this.state.searchText.trim());
                });
            }
            this.setState({
                groups,
            });
        }
    };

    reloadGroups(successMessage, groupName, showSuccess = true) {
        this.setState({
            showAddGroup: false,
            showSuccess,
            successMessage,
            errorMessage: null,
        });

        setTimeout(
            () =>
                this.setState({
                    showSuccess: false,
                    successMessage: '',
                }),
            MODAL_TIME_OUT
        );
        // this is to close the success alert
    }

    closeModal() {
        this.setState({ showSuccess: null });
    }

    render() {
        const { groups } = this.state;
        let addGroup = this.state.showAddGroup ? (
            <AddGroup
                domain={this.props.domain}
                onSubmit={this.reloadGroups}
                onCancel={this.toggleAddGroup}
                _csrf={this.props._csrf}
                showAddGroup={this.state.showAddGroup}
            />
        ) : (
            ''
        );

        let searchInput =
            this.props.groups.length > 0 ? (
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
        return this.props.isLoading.length !== 0 ? (
            <ReduxPageLoader message={'Loading groups'} />
        ) : (
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
                {groups.length > 0 && (
                    <GroupTable
                        groups={groups}
                        domain={this.props.domain}
                        timeZone={this.props.timeZone}
                        _csrf={this.props._csrf}
                        onSubmit={this.reloadGroups}
                        justificationRequired={this.props.isDomainAuditEnabled}
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
const mapStateToProps = (state, props) => {
    return {
        ...props,
        isLoading: selectIsLoading(state),
        groups: selectGroups(state),
        isDomainAuditEnabled: selectDomainAuditEnabled(state),
        timeZone: selectTimeZone(state),
    };
};

export default connect(mapStateToProps)(GroupList);
