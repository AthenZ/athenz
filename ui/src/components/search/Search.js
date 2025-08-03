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
import SearchInput from '../denali/SearchInput';
import { withRouter } from 'next/router';
import InputDropdown from '../denali/InputDropdown';
import styled from '@emotion/styled';

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

class Search extends React.Component {
    constructor(props) {
        super(props);
        this.optionChanged = this.optionChanged.bind(this);
        this.searchTextChanged = this.searchTextChanged.bind(this);
        this.handleKeyPress = this.handleKeyPress.bind(this);
        this.handleSearch = this.handleSearch.bind(this);
        this.state = {
            placeholder: 'Search',
            options: [
                { value: 'domain', name: 'Domain' },
                { value: 'service', name: 'Service' },
            ],
            selected: this.props.router.query?.type || 'domain',
            searchText: this.props.searchData || '',
        };
    }

    optionChanged(chosen) {
        let placeholder = 'Search';
        this.setState({
            selected: chosen.value,
            placeholder: placeholder,
        });
    }

    searchTextChanged(evt) {
        evt.preventDefault();
        this.setState({ searchText: evt.target.value });
    }

    handleKeyPress(evt) {
        // on Enter - go to search page passing domain/service and search term
        if (evt.key === 'Enter') {
            this.performSearch();
        }
    }

    handleSearch() {
        this.performSearch();
    }

    performSearch() {
        if (this.state.searchText.length === 0) {
            this.setState({ error: true });
        } else {
            this.props.router.push(
                `/search/${
                    this.state.selected
                }/${this.state.searchText.trim()}`,
                `/search/${this.state.selected}/${this.state.searchText.trim()}`
            );
        }
    }

    render() {
        return (
            <SearchDiv>
                <DropDownDiv>
                    <InputDropdown
                        name='search-type'
                        defaultSelectedValue={this.state.selected}
                        onChange={this.optionChanged}
                        options={this.state.options}
                        noclear
                        fluid
                    />
                </DropDownDiv>
                <SearchTextDiv>
                    <SearchInput
                        name='search-text'
                        value={this.state.searchText}
                        onChange={(event) =>
                            this.setState({
                                searchText: event.target.value,
                                error: false,
                            })
                        }
                        onKeyPress={this.handleKeyPress}
                        onSearch={this.handleSearch}
                        fluid
                        error={this.state.error}
                        placeholder={this.state.placeholder}
                    />
                </SearchTextDiv>
            </SearchDiv>
        );
    }
}
export default withRouter(Search);
