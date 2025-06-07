/*
 * Copyright The Athenz Authors
 * Licensed under the Apache License, Version 2.0
 */

import React from 'react';
import PropTypes from 'prop-types';
import styled from '@emotion/styled';
import SearchInput from '../denali/SearchInput';
import { colors } from '../denali/styles';

const FilterContainer = styled.div`
    display: flex;
    align-items: center;
    gap: 15px;
    margin-bottom: 15px;
    padding: 15px 0;
    border-bottom: 1px solid ${colors.grey300};
`;

const FilterGroup = styled.div`
    display: flex;
    align-items: center;
    gap: 8px;
`;

const FilterLabel = styled.label`
    font-size: 14px;
    font-weight: 500;
    color: ${colors.grey800};
    white-space: nowrap;
`;

const ItemCount = styled.span`
    color: ${colors.grey600};
    font-size: 14px;
    margin-left: auto;
`;

const PageSizeSelect = styled.select`
    padding: 8px 12px;
    border: 1px solid ${colors.grey300};
    border-radius: 4px;
    background-color: white;
    font-size: 14px;
    color: ${colors.grey800};
    cursor: pointer;
    min-width: 120px;
    
    &:focus {
        outline: none;
        border-color: ${colors.brand500};
        box-shadow: 0 0 0 2px ${colors.brand100};
    }
`;

const NoResultsMessage = styled.div`
    text-align: center;
    padding: 40px 20px;
    color: ${colors.grey600};
    font-style: italic;
    font-size: 16px;
    background-color: ${colors.grey100};
    border-radius: 4px;
    margin: 20px 0;
`;

export default class MemberFilter extends React.Component {
    handleSearchChange = (event) => {
        this.props.onSearchChange(event.target.value);
    };

    handlePageSizeChange = (event) => {
        this.props.onPageSizeChange(parseInt(event.target.value, 10));
    };

    render() {
        const { 
            searchText, 
            pageSize, 
            hasResults,
            isFiltered,
            totalItems,
            filteredCount
        } = this.props;
        
        const pageSizeOptions = [
            { value: 30, text: '30 items' },
            { value: 50, text: '50 items' },
            { value: 100, text: '100 items' }
        ];
        
        return (
            <>
                <FilterContainer data-testid="member-filter">
                    <FilterGroup>
                        <FilterLabel htmlFor="member-search">Search:</FilterLabel>
                        <SearchInput
                            id="member-search"
                            placeholder="Search by account name"
                            value={searchText}
                            onChange={this.handleSearchChange}
                            fluid={false}
                            width="300px"
                        />
                    </FilterGroup>
                    
                    <FilterGroup>
                        <FilterLabel htmlFor="page-size">Items per page:</FilterLabel>
                        <PageSizeSelect
                            id="page-size"
                            name="pageSize"
                            value={pageSize}
                            onChange={this.handlePageSizeChange}
                        >
                            {pageSizeOptions.map(option => (
                                <option key={option.value} value={option.value}>
                                    {option.text}
                                </option>
                            ))}
                        </PageSizeSelect>
                    </FilterGroup>
                    
                    {totalItems > 0 && (
                        <ItemCount>
                            {isFiltered 
                                ? `${hasResults ? filteredCount || 0 : 0} of ${totalItems} members`
                                : `${totalItems} members`
                            }
                        </ItemCount>
                    )}
                </FilterContainer>
                
                {isFiltered && !hasResults && (
                    <NoResultsMessage data-testid="no-results">
                        No matching members found for "{searchText}"
                    </NoResultsMessage>
                )}
            </>
        );
    }
}

MemberFilter.propTypes = {
    /** Search text value */
    searchText: PropTypes.string.isRequired,
    /** Search change handler */
    onSearchChange: PropTypes.func.isRequired,
    /** Current page size */
    pageSize: PropTypes.number.isRequired,
    /** Page size change handler */
    onPageSizeChange: PropTypes.func.isRequired,
    /** Whether results exist for current filter */
    hasResults: PropTypes.bool.isRequired,
    /** Whether filtering is active */
    isFiltered: PropTypes.bool.isRequired,
    /** Total number of items */
    totalItems: PropTypes.number.isRequired,
    /** Number of filtered items (when filtered) */
    filteredCount: PropTypes.number,
};

MemberFilter.defaultProps = {
    filteredCount: 0,
};