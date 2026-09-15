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
import Input from '../denali/Input';
import InputDropdown from '../denali/InputDropdown';
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';

const SearchRow = styled.div`
    align-items: stretch;
    display: flex;
    gap: 8px;
    width: 100%;
`;

const SearchFieldWrap = styled.div`
    flex: 1 1 auto;
    min-width: 0;
`;

const SearchButton = styled.button`
    align-items: center;
    background: linear-gradient(
        to right,
        ${colors.brand600},
        ${colors.brand700}
    );
    border: none;
    border-radius: 2px;
    cursor: pointer;
    display: flex;
    flex: 0 0 42px;
    height: 36px;
    justify-content: center;
    margin: 0;
    padding: 0;
    width: 42px;
    &:hover {
        background: linear-gradient(
            to right,
            ${colors.brand700},
            ${colors.brand800}
        );
    }
`;

const DomainFilterWrap = styled.div`
    flex: 0 0 180px;
`;

export default class SelfServiceSearchBar extends React.Component {
    constructor(props) {
        super(props);
        this.onKeyPress = this.onKeyPress.bind(this);
    }

    onKeyPress(evt) {
        if (evt.key === 'Enter') {
            this.props.onSearch();
        }
    }

    render() {
        const domainOptions = [
            { name: 'All domains', value: '' },
            ...(this.props.domains || []).map((domain) => ({
                name: domain,
                value: domain,
            })),
        ];
        const selectedDomain =
            domainOptions.find(
                (option) => option.value === (this.props.domain || '')
            ) || domainOptions[0];
        return (
            <SearchRow data-testid='self-service-search-bar'>
                <SearchFieldWrap>
                    <Input
                        fluid
                        id='self-service-search'
                        name='self-service-search'
                        placeholder='Search by name or description'
                        value={this.props.query}
                        onChange={this.props.onQueryChange}
                        onKeyPress={this.onKeyPress}
                        autoComplete='off'
                    />
                </SearchFieldWrap>
                <SearchButton
                    type='button'
                    onClick={this.props.onSearch}
                    data-testid='self-service-search-button'
                    aria-label='Search'
                >
                    <Icon icon={'search'} color={colors.white} size={'18px'} />
                </SearchButton>
                <DomainFilterWrap>
                    <InputDropdown
                        key={domainOptions
                            .map((option) => option.value)
                            .join('|')}
                        name='self-service-domain'
                        fluid
                        noclear
                        noanim
                        defaultSelectedItem={selectedDomain}
                        options={domainOptions}
                        onChange={this.props.onDomainChange}
                    />
                </DomainFilterWrap>
            </SearchRow>
        );
    }
}
