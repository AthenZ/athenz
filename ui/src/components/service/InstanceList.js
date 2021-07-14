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
import RequestUtils from '../utils/RequestUtils';
import InstanceTable from './InstanceTable';
import AddStaticInstances from '../microsegmentation/AddStaticInstances';
import InputDropdown from '../denali/InputDropdown';

const InstanceSectionDiv = styled.div`
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

const SearchDiv = styled.div`
    display: flex;
    width: 100%;
`;

const DropDownDiv = styled.div`
    background: #ffffff;
    width: 35%;
`;

const SearchTextDiv = styled.div`
    background: #ffffff;
    width: 65%;
    margin-left: 5px;
`;

export default class InstanceList extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.state = {
            showAddInstance: false,
            instances: props.instances || [],
            errorMessage: null,
            error: false,
            placeholder: 'Search',
            options: [
                { value: 'Instance', name: 'Instance' },
                { value: 'Hostname', name: 'Hostname' },
                { value: 'Provider', name: 'Provider' },
            ],
            selected: this.props.option || 'Instance',
            searchText: this.props.searchText || '',
        };
        this.toggleAddInstance = this.toggleAddInstance.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.reloadInstances = this.reloadInstances.bind(this);
        this.optionChanged = this.optionChanged.bind(this);
    }

    toggleAddInstance() {
        this.setState({
            showAddInstance: !this.state.showAddInstance,
        });
    }

    componentDidUpdate = (prevProps) => {
        if (
            prevProps.domain !== this.props.domain ||
            prevProps.domain !== this.props.domain
        ) {
            this.setState({
                instances: this.props.instances || [],
                showAddInstance: false,
                errorMessage: null,
                searchText: '',
            });
        }
    };

    reloadInstances() {
        this.api
            .getInstances(
                this.props.domain,
                this.props.service,
                this.props.category
            )
            .then((instances) => {
                this.setState({
                    instances: instances.workLoadData,
                    showAddInstance: false,
                    errorMessage: null,
                });
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

    optionChanged(chosen) {
        if (chosen && chosen.value != null) {
            this.setState({
                selected: chosen.value,
            });
        }
    }

    render() {
        let instances = this.state.instances;
        if (this.state.searchText.trim() !== '') {
            switch (this.state.selected) {
                case 'Instance':
                    instances = this.state.instances.filter((instance) => {
                        let temp = instance.ipAddresses.filter((ipAddress) => {
                            return ipAddress.includes(
                                this.state.searchText.trim()
                            );
                        });
                        return temp.length > 0;
                    });
                    break;
                case 'Hostname':
                    instances = this.state.instances.filter((instance) => {
                        return instance.hostname
                            .toLowerCase()
                            .includes(
                                this.state.searchText.toLowerCase().trim()
                            );
                    });
                    break;
                case 'Provider':
                    instances = this.state.instances.filter((instance) => {
                        return instance.provider
                            .toLowerCase()
                            .includes(
                                this.state.searchText.toLowerCase().trim()
                            );
                    });
                    break;
            }
        }

        let addStaticInstance = this.state.showAddInstance ? (
            <AddStaticInstances
                api={this.api}
                domain={this.props.domain}
                onSubmit={this.reloadInstances}
                onCancel={this.toggleAddInstance}
                _csrf={this.props._csrf}
                showAddInstance={this.state.showAddInstance}
                service={this.props.service}
            />
        ) : (
            ''
        );

        let searchInput;
        if (this.state.instances.length > 0) {
            if (this.props.category != 'static') {
                searchInput = (
                    <SearchDiv>
                        <DropDownDiv>
                            <InputDropdown
                                name='search-type'
                                defaultSelectedValue={this.state.selected}
                                placeholder='Select an option'
                                onChange={this.optionChanged}
                                options={this.state.options}
                                noclear
                                fluid
                            />
                        </DropDownDiv>
                        <SearchTextDiv>
                            <SearchInput
                                dark={false}
                                name='search'
                                fluid={true}
                                value={this.state.searchText}
                                placeholder={'Search'}
                                error={this.state.error}
                                onChange={(event) =>
                                    this.setState({
                                        searchText: event.target.value,
                                        error: false,
                                    })
                                }
                            />
                        </SearchTextDiv>
                    </SearchDiv>
                );
            } else {
                searchInput = (
                    <SearchDiv>
                        <SearchTextDiv>
                            <SearchInput
                                dark={false}
                                name='search'
                                fluid={true}
                                value={this.state.searchText}
                                placeholder={'Search'}
                                error={this.state.error}
                                onChange={(event) =>
                                    this.setState({
                                        searchText: event.target.value,
                                        error: false,
                                    })
                                }
                            />
                        </SearchTextDiv>
                    </SearchDiv>
                );
            }
        } else {
            searchInput = 'No instances found';
        }

        return (
            <InstanceSectionDiv data-testid='instancelist'>
                <AddContainerDiv>
                    <StyledSearchInputDiv>{searchInput}</StyledSearchInputDiv>
                    {this.props.category == 'static' && (
                        <div>
                            <Button secondary onClick={this.toggleAddInstance}>
                                Add Static Instance
                            </Button>
                            {addStaticInstance}
                        </div>
                    )}
                </AddContainerDiv>
                {this.state.instances.length > 0 && (
                    <InstanceTable
                        instances={instances}
                        api={this.api}
                        domain={this.props.domain}
                        _csrf={this.props._csrf}
                        onSubmit={this.reloadInstances}
                        category={this.props.category}
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
            </InstanceSectionDiv>
        );
    }
}
