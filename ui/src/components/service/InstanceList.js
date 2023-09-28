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
import InstanceTable from './InstanceTable';
import AddStaticInstances from '../microsegmentation/AddStaticInstances';
import InputDropdown from '../denali/InputDropdown';
import { selectTimeZone } from '../../redux/selectors/domains';
import { selectInstancesWorkLoadData } from '../../redux/selectors/services';
import { connect } from 'react-redux';

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

class InstanceList extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            showAddInstance: false,
            instances: [],
            errorMessage: null,
            error: false,
            placeholder: 'Search',
            options: [
                { value: 'Instance', name: 'Instance' },
                { value: 'Hostname', name: 'Hostname' },
                { value: 'Provider', name: 'Provider' },
            ],
            selected: 'Instance',
            searchText: '',
        };
        this.toggleAddInstance = this.toggleAddInstance.bind(this);
        this.optionChanged = this.optionChanged.bind(this);
    }

    toggleAddInstance() {
        this.setState({
            showAddInstance: !this.state.showAddInstance,
        });
    }

    componentDidMount() {
        this.setState({
            instances: this.props.instances || [],
            showAddInstance: false,
            errorMessage: null,
            searchText: '',
        });
    }

    componentDidUpdate = (prevProps, prevState) => {
        if (prevProps.instances !== this.props.instances) {
            this.setState({
                instances: this.props.instances || [],
                showAddInstance: false,
                errorMessage: null,
                searchText: '',
            });
        }
        if (prevState.searchText !== this.state.searchText) {
            let instances = [];
            switch (this.state.selected) {
                case 'Instance':
                    instances = this.props.instances.filter((instance) => {
                        if (!instance.ipAddresses) {
                            return instance.name.includes(
                                this.state.searchText.trim()
                            );
                        }
                        let temp = instance.ipAddresses.filter((ipAddress) => {
                            return ipAddress.includes(
                                this.state.searchText.trim()
                            );
                        });
                        return temp.length > 0;
                    });
                    break;
                case 'Hostname':
                    instances = this.props.instances.filter((instance) => {
                        return instance.hostname
                            .toLowerCase()
                            .includes(
                                this.state.searchText.toLowerCase().trim()
                            );
                    });
                    break;
                case 'Provider':
                    instances = this.props.instances.filter((instance) => {
                        return instance.provider
                            .toLowerCase()
                            .includes(
                                this.state.searchText.toLowerCase().trim()
                            );
                    });
                    break;
            }
            this.setState({ instances });
        }
    };

    optionChanged(chosen) {
        if (chosen && chosen.value != null) {
            this.setState({
                selected: chosen.value,
            });
        }
    }

    render() {
        let addStaticInstance = this.state.showAddInstance ? (
            <AddStaticInstances
                domain={this.props.domain}
                onCancel={this.toggleAddInstance}
                _csrf={this.props._csrf}
                showAddInstance={this.state.showAddInstance}
                service={this.props.service}
            />
        ) : (
            ''
        );

        let searchInput;
        if (this.props.instances.length > 0) {
            searchInput = (
                <SearchDiv>
                    {this.props.category !== 'static' ? (
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
                    ) : null}
                    <SearchTextDiv>
                        <SearchInput
                            dark={false}
                            name='search'
                            fluid={true}
                            value={this.state.searchText}
                            placeholder={'Search'}
                            error={this.state.error}
                            onChange={(event) => {
                                this.setState({
                                    searchText: event.target.value,
                                    error: false,
                                });
                            }}
                        />
                    </SearchTextDiv>
                </SearchDiv>
            );
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
                        instances={this.state.instances}
                        domain={this.props.domain}
                        service={this.props.service}
                        timeZone={this.props.timeZone}
                        _csrf={this.props._csrf}
                        onSubmit={this.props.onInstancesUpdated}
                        category={this.props.category}
                    />
                )}
            </InstanceSectionDiv>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        instances: selectInstancesWorkLoadData(
            state,
            props.domain,
            props.service,
            props.category
        ),
        timeZone: selectTimeZone(state),
    };
};

export default connect(mapStateToProps, null)(InstanceList);
