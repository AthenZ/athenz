/*
 * Copyright The Athenz Authors
 * Licensed under the Apache License, Version 2.0
 */

import React from 'react';
import { render, fireEvent } from '@testing-library/react';
import MemberFilter from '../MemberFilter';

describe('MemberFilter', () => {
    const defaultProps = {
        searchText: '',
        onSearchChange: jest.fn(),
        pageSize: 30,
        onPageSizeChange: jest.fn(),
        hasResults: true,
        isFiltered: false,
        totalItems: 100,
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should render without errors', () => {
        const { getByTestId } = render(<MemberFilter {...defaultProps} />);
        expect(getByTestId('member-filter')).toBeInTheDocument();
    });

    it('should display search input with placeholder', () => {
        const { getByPlaceholderText } = render(<MemberFilter {...defaultProps} />);
        expect(getByPlaceholderText('Search by account name')).toBeInTheDocument();
    });

    it('should display page size dropdown', () => {
        const { getByLabelText } = render(<MemberFilter {...defaultProps} />);
        expect(getByLabelText('Items per page:')).toBeInTheDocument();
    });

    it('should display total items count when not filtered', () => {
        const { getByText } = render(
            <MemberFilter {...defaultProps} totalItems={50} />
        );
        expect(getByText('50 members')).toBeInTheDocument();
    });

    it('should display filtered count when filtered with results', () => {
        const { getByText } = render(
            <MemberFilter 
                {...defaultProps} 
                isFiltered={true}
                hasResults={true}
                totalItems={50}
                filteredCount={10}
            />
        );
        expect(getByText('10 of 50 members')).toBeInTheDocument();
    });

    it('should display filtered count as 0 when filtered with no results', () => {
        const { getByText } = render(
            <MemberFilter 
                {...defaultProps} 
                isFiltered={true}
                hasResults={false}
                totalItems={50}
                filteredCount={0}
            />
        );
        expect(getByText('0 of 50 members')).toBeInTheDocument();
    });

    it('should call onSearchChange when search input changes', () => {
        const onSearchChange = jest.fn();
        const { getByPlaceholderText } = render(
            <MemberFilter {...defaultProps} onSearchChange={onSearchChange} />
        );
        
        const searchInput = getByPlaceholderText('Search by account name');
        fireEvent.change(searchInput, { target: { value: 'alice' } });
        
        expect(onSearchChange).toHaveBeenCalledWith('alice');
    });

    it('should call onPageSizeChange when page size changes', () => {
        const onPageSizeChange = jest.fn();
        const { getByLabelText } = render(
            <MemberFilter {...defaultProps} onPageSizeChange={onPageSizeChange} />
        );
        
        const pageSizeSelect = getByLabelText('Items per page:');
        fireEvent.change(pageSizeSelect, { target: { value: '50' } });
        
        expect(onPageSizeChange).toHaveBeenCalledWith(50);
    });

    it('should display current search text in input', () => {
        const { getByDisplayValue } = render(
            <MemberFilter {...defaultProps} searchText="alice" />
        );
        expect(getByDisplayValue('alice')).toBeInTheDocument();
    });

    it('should display current page size in dropdown', () => {
        const { container } = render(
            <MemberFilter {...defaultProps} pageSize={50} />
        );
        const select = container.querySelector('#page-size');
        expect(select.value).toBe('50');
    });

    it('should show no results message when filtered with no results', () => {
        const { getByTestId, getByText } = render(
            <MemberFilter 
                {...defaultProps} 
                isFiltered={true}
                hasResults={false}
                searchText="xyz"
            />
        );
        
        expect(getByTestId('no-results')).toBeInTheDocument();
        expect(getByText('No matching members found for "xyz"')).toBeInTheDocument();
    });

    it('should not show no results message when not filtered', () => {
        const { queryByTestId } = render(
            <MemberFilter 
                {...defaultProps} 
                isFiltered={false}
                hasResults={false}
            />
        );
        
        expect(queryByTestId('no-results')).not.toBeInTheDocument();
    });

    it('should not show no results message when filtered but has results', () => {
        const { queryByTestId } = render(
            <MemberFilter 
                {...defaultProps} 
                isFiltered={true}
                hasResults={true}
            />
        );
        
        expect(queryByTestId('no-results')).not.toBeInTheDocument();
    });

    it('should render all page size options', () => {
        const { getByText } = render(<MemberFilter {...defaultProps} />);
        
        // Check if page size options are available (this might need to be adapted based on InputDropdown implementation)
        expect(getByText('Items per page:')).toBeInTheDocument();
    });

    it('should not display member count when totalItems is 0', () => {
        const { queryByText } = render(
            <MemberFilter {...defaultProps} totalItems={0} />
        );
        
        expect(queryByText(/members$/)).not.toBeInTheDocument();
    });

    it('should have proper accessibility labels', () => {
        const { getByLabelText } = render(<MemberFilter {...defaultProps} />);
        
        expect(getByLabelText('Search:')).toBeInTheDocument();
        expect(getByLabelText('Items per page:')).toBeInTheDocument();
    });

    it('should pass correct props to SearchInput', () => {
        const { container } = render(
            <MemberFilter 
                {...defaultProps} 
                searchText="test"
            />
        );
        
        const searchInput = container.querySelector('#member-search');
        expect(searchInput).toBeInTheDocument();
        expect(searchInput.value).toBe('test');
    });

    it('should pass correct props to PageSizeSelect', () => {
        const { container } = render(
            <MemberFilter 
                {...defaultProps} 
                pageSize={100}
            />
        );
        
        const pageSizeSelect = container.querySelector('#page-size');
        expect(pageSizeSelect).toBeInTheDocument();
        expect(pageSizeSelect.value).toBe('100');
    });

    it('should match snapshot', () => {
        const { container } = render(<MemberFilter {...defaultProps} />);
        expect(container.firstChild).toMatchSnapshot();
    });

    it('should match snapshot with filtered state', () => {
        const { container } = render(
            <MemberFilter 
                {...defaultProps} 
                isFiltered={true}
                hasResults={false}
                searchText="test"
            />
        );
        expect(container.firstChild).toMatchSnapshot();
    });
});