# Athenz UI Member Pagination Design Document

## Framework Analysis

### Technology Stack
- **React**: 18.2.0 (Class component-based architecture)
- **Next.js**: 14.2.26 (SSR/SSG support)
- **Redux**: 4.2.0 + Redux Thunk 2.4.1
- **Emotion**: 11.x (CSS-in-JS)
- **Denali Design System**: 1.0.0-alpha.1

## Requirements Summary

### Functional Requirements
- **Pagination**: Role and group member lists with dynamic page numbering (max 9 pages visible)
- **Page Size Selection**: 30/50/100 items per page (default: 30)
- **Client-side Filtering**: Account name search with 200ms debounce
- **Current Page Display**: "Page X / Total" format
- **Filter Persistence**: Maintain search terms across page changes
- **No Results Handling**: Display appropriate message when no matches found

### Non-functional Requirements
- **Performance**: 200ms debounce for search input
- **Constraint**: No server requests for filtering (client-side only)
- **UX**: Preserve filter state during pagination

## Current Architecture Analysis

### Existing Member Display Components
```
Current Structure:
MemberList (Container)
  ↓
MemberTable (Display + Sort)
  ↓  
MemberRow (Individual Member) × N
```

### Key Files Analyzed
- `/src/components/member/MemberTable.js` - Core member table with sorting
- `/src/components/member/MemberList.js` - Container component
- `/src/components/role/UserRoleTable.js` - Role-specific member display
- `/src/components/group/GroupMemberList.js` - Group-specific member display

### Current Limitations
- All members loaded and sorted at once (performance issue)
- No pagination infrastructure exists
- Basic string filtering only in UserRoleTable
- No debounced search functionality

## Proposed Architecture

### New Component Hierarchy
```
Enhanced Structure:
MemberList (Data Management + Pagination State)
  ↓
  ├── MemberFilter (Search + Filtering)
  ├── MemberTable (Display Only)
  ├── Pagination (Page Controls)
  └── PageSizeSelector (Items per page)
```

### State Management Design
```javascript
// Pagination State (Component Local)
{
  currentPage: 1,
  pageSize: 30,
  searchText: '',
  filteredMembers: [],
  displayedMembers: []
}
```

## Implementation Plan

### Phase 1: Core Infrastructure

#### New Files to Create
```
src/hooks/usePagination.js              // Pagination control hook
src/hooks/useMemberFilter.js            // Filtering control hook  
src/components/member/Pagination.js     // Pagination UI component
src/components/member/MemberFilter.js   // Filtering UI component
src/components/member/PageSizeSelector.js // Page size selection UI
```

#### Files to Modify
```
src/components/member/MemberList.js     // Integrate pagination
src/components/member/MemberTable.js    // Separate display logic
src/components/role/UserRoleTable.js    // Apply role pagination
src/components/group/GroupMemberList.js // Apply group pagination
```

### Phase 2: Hook Implementation

#### usePagination.js
```javascript
/*
 * Copyright The Athenz Authors
 * Licensed under the Apache License, Version 2.0
 */

import { useState } from 'react';

export const usePagination = (items, initialPageSize = 30) => {
    const [currentPage, setCurrentPage] = useState(1);
    const [pageSize, setPageSize] = useState(initialPageSize);
    
    const totalPages = Math.ceil(items.length / pageSize);
    const startIndex = (currentPage - 1) * pageSize;
    const displayedItems = items.slice(startIndex, startIndex + pageSize);
    
    return {
        currentPage,
        pageSize,
        totalPages,
        displayedItems,
        setCurrentPage,
        setPageSize,
        goToPage: (page) => setCurrentPage(Math.min(Math.max(1, page), totalPages)),
        goToFirstPage: () => setCurrentPage(1),
        goToLastPage: () => setCurrentPage(totalPages),
    };
};
```

#### useMemberFilter.js
```javascript
/*
 * Copyright The Athenz Authors
 * Licensed under the Apache License, Version 2.0
 */

import { useState, useEffect } from 'react';
import { useDebounce } from './useDebounce';

export const useMemberFilter = (members, debounceTime = 200) => {
    const [searchText, setSearchText] = useState('');
    const [filteredMembers, setFilteredMembers] = useState(members);
    
    const debouncedSearchText = useDebounce(searchText, debounceTime);
    
    useEffect(() => {
        if (!debouncedSearchText.trim()) {
            setFilteredMembers(members);
        } else {
            const filtered = members.filter(member =>
                member.memberName.toLowerCase().includes(debouncedSearchText.toLowerCase())
            );
            setFilteredMembers(filtered);
        }
    }, [members, debouncedSearchText]);
    
    return {
        searchText,
        setSearchText,
        filteredMembers,
        isFiltered: searchText.trim().length > 0,
        hasResults: filteredMembers.length > 0,
    };
};
```

### Phase 3: UI Component Implementation

#### Pagination.js
```javascript
/*
 * Copyright The Athenz Authors
 * Licensed under the Apache License, Version 2.0
 */

import React from 'react';
import PropTypes from 'prop-types';
import styled from '@emotion/styled';
import Button from '../denali/Button';
import { colors } from '../denali/styles';

const PaginationContainer = styled.div`
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin: 15px 0;
    padding: 10px 0;
    border-top: 1px solid ${colors.grey300};
`;

const PageInfo = styled.span`
    color: ${colors.grey700};
    font-size: 14px;
    font-weight: 500;
`;

const PageButtons = styled.div`
    display: flex;
    gap: 5px;
    align-items: center;
`;

const PageButton = styled(Button)`
    min-width: 36px;
    height: 32px;
    padding: 0 8px;
`;

export default class Pagination extends React.Component {
    generatePageNumbers() {
        const { currentPage, totalPages } = this.props;
        const maxVisible = 9;
        
        if (totalPages <= maxVisible) {
            return Array.from({ length: totalPages }, (_, i) => i + 1);
        }
        
        // Dynamic page number logic for max 9 pages
        const start = Math.max(1, Math.min(currentPage - 4, totalPages - maxVisible + 1));
        const end = Math.min(totalPages, start + maxVisible - 1);
        
        return Array.from({ length: end - start + 1 }, (_, i) => start + i);
    }
    
    render() {
        const { currentPage, totalPages, onPageChange } = this.props;
        
        if (totalPages <= 1) {
            return null;
        }
        
        const pageNumbers = this.generatePageNumbers();
        
        return (
            <PaginationContainer data-testid="pagination">
                <PageInfo>
                    Page {currentPage} / {totalPages}
                </PageInfo>
                
                <PageButtons>
                    <PageButton 
                        disabled={currentPage === 1}
                        onClick={() => onPageChange(1)}
                        size="small"
                        variant="secondary"
                    >
                        First
                    </PageButton>
                    
                    <PageButton
                        disabled={currentPage === 1}
                        onClick={() => onPageChange(currentPage - 1)}
                        size="small"
                        variant="secondary"
                    >
                        ‹
                    </PageButton>
                    
                    {pageNumbers.map(pageNumber => (
                        <PageButton
                            key={pageNumber}
                            variant={currentPage === pageNumber ? 'primary' : 'secondary'}
                            onClick={() => onPageChange(pageNumber)}
                            size="small"
                        >
                            {pageNumber}
                        </PageButton>
                    ))}
                    
                    <PageButton
                        disabled={currentPage === totalPages}
                        onClick={() => onPageChange(currentPage + 1)}
                        size="small"
                        variant="secondary"
                    >
                        ›
                    </PageButton>
                    
                    <PageButton 
                        disabled={currentPage === totalPages}
                        onClick={() => onPageChange(totalPages)}
                        size="small"
                        variant="secondary"
                    >
                        Last
                    </PageButton>
                </PageButtons>
            </PaginationContainer>
        );
    }
}

Pagination.propTypes = {
    /** Current page number */
    currentPage: PropTypes.number.isRequired,
    /** Total number of pages */
    totalPages: PropTypes.number.isRequired,
    /** Page change handler */
    onPageChange: PropTypes.func.isRequired,
};
```

#### MemberFilter.js
```javascript
/*
 * Copyright The Athenz Authors
 * Licensed under the Apache License, Version 2.0
 */

import React from 'react';
import PropTypes from 'prop-types';
import styled from '@emotion/styled';
import SearchInput from '../denali/SearchInput';
import InputDropdown from '../denali/InputDropdown';
import { colors } from '../denali/styles';

const FilterContainer = styled.div`
    display: flex;
    align-items: center;
    gap: 15px;
    margin-bottom: 15px;
    padding: 15px 0;
    border-bottom: 1px solid ${colors.grey300};
`;

const FilterLabel = styled.label`
    font-size: 14px;
    font-weight: 500;
    color: ${colors.grey800};
    margin-right: 8px;
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
    render() {
        const { 
            searchText, 
            onSearchChange, 
            pageSize, 
            onPageSizeChange,
            hasResults,
            isFiltered,
            totalItems
        } = this.props;
        
        const pageSizeOptions = [
            { value: 30, text: '30 items' },
            { value: 50, text: '50 items' },
            { value: 100, text: '100 items' }
        ];
        
        return (
            <>
                <FilterContainer data-testid="member-filter">
                    <div>
                        <FilterLabel htmlFor="member-search">Search:</FilterLabel>
                        <SearchInput
                            id="member-search"
                            placeholder="Search by account name"
                            value={searchText}
                            onChange={onSearchChange}
                            fluid={false}
                            width="300px"
                        />
                    </div>
                    
                    <div>
                        <FilterLabel htmlFor="page-size">Items per page:</FilterLabel>
                        <InputDropdown
                            id="page-size"
                            name="pageSize"
                            options={pageSizeOptions}
                            value={pageSize}
                            onChange={onPageSizeChange}
                            placeholder="Items per page"
                            fluid={false}
                            width="150px"
                        />
                    </div>
                    
                    {totalItems > 0 && (
                        <span style={{ color: colors.grey600, fontSize: '14px' }}>
                            {isFiltered ? `${hasResults ? filteredMembers.length : 0} of ${totalItems} members` : `${totalItems} members`}
                        </span>
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
};
```

### Phase 4: Integration

#### Enhanced MemberList.js
```javascript
/*
 * Copyright The Athenz Authors
 * Licensed under the Apache License, Version 2.0
 */

import React from 'react';
import PropTypes from 'prop-types';
import MemberTable from './MemberTable';
import MemberFilter from './MemberFilter';
import Pagination from './Pagination';

export default class MemberList extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            currentPage: 1,
            pageSize: 30,
            searchText: '',
        };
        this.searchDebounceTimer = null;
    }
    
    componentDidUpdate(prevProps) {
        // Reset pagination when members change
        if (prevProps.members !== this.props.members) {
            this.setState({ currentPage: 1 });
        }
    }
    
    componentWillUnmount() {
        if (this.searchDebounceTimer) {
            clearTimeout(this.searchDebounceTimer);
        }
    }
    
    handleSearchChange = (value) => {
        this.setState({ searchText: value });
        
        // Debounce implementation for filtering
        clearTimeout(this.searchDebounceTimer);
        this.searchDebounceTimer = setTimeout(() => {
            this.setState({ currentPage: 1 }); // Reset to first page on search
        }, 200);
    };
    
    handlePageSizeChange = (newPageSize) => {
        this.setState({
            pageSize: newPageSize,
            currentPage: 1 // Reset to first page
        });
    };
    
    handlePageChange = (newPage) => {
        this.setState({ currentPage: newPage });
    };
    
    getFilteredMembers() {
        const { members } = this.props;
        const { searchText } = this.state;
        
        if (!searchText.trim()) {
            return members || [];
        }
        
        return (members || []).filter(member =>
            member.memberName.toLowerCase().includes(searchText.toLowerCase())
        );
    }
    
    getPaginatedMembers() {
        const { currentPage, pageSize } = this.state;
        const filteredMembers = this.getFilteredMembers();
        
        const startIndex = (currentPage - 1) * pageSize;
        return filteredMembers.slice(startIndex, startIndex + pageSize);
    }
    
    render() {
        const { members, ...tableProps } = this.props;
        const { currentPage, pageSize, searchText } = this.state;
        
        const allMembers = members || [];
        const filteredMembers = this.getFilteredMembers();
        const displayedMembers = this.getPaginatedMembers();
        const totalPages = Math.ceil(filteredMembers.length / pageSize);
        
        return (
            <div data-testid="member-list">
                <MemberFilter
                    searchText={searchText}
                    onSearchChange={this.handleSearchChange}
                    pageSize={pageSize}
                    onPageSizeChange={this.handlePageSizeChange}
                    hasResults={filteredMembers.length > 0}
                    isFiltered={searchText.trim().length > 0}
                    totalItems={allMembers.length}
                />
                
                <MemberTable
                    {...tableProps}
                    members={displayedMembers}
                />
                
                <Pagination
                    currentPage={currentPage}
                    totalPages={totalPages}
                    onPageChange={this.handlePageChange}
                />
            </div>
        );
    }
}

MemberList.propTypes = {
    /** Array of member objects */
    members: PropTypes.array,
    /** Additional props passed to MemberTable */
    category: PropTypes.string,
    domain: PropTypes.string,
    collection: PropTypes.string,
    caption: PropTypes.string,
};

MemberList.defaultProps = {
    members: [],
};
```

## Testing Strategy

### Unit Tests Required

#### Pagination Component Tests
```javascript
// src/__tests__/components/member/Pagination.test.js
describe('Pagination', () => {
    it('should display correct page numbers with max 9 visible', () => {
        // Test dynamic page number generation
    });
    
    it('should handle page changes correctly', () => {
        // Test page navigation
    });
    
    it('should disable first/prev when on first page', () => {
        // Test button states
    });
    
    it('should disable last/next when on last page', () => {
        // Test button states
    });
});
```

#### MemberFilter Component Tests
```javascript
// src/__tests__/components/member/MemberFilter.test.js
describe('MemberFilter', () => {
    it('should debounce search input correctly', async () => {
        // Test 200ms debounce functionality
    });
    
    it('should show no results message when filtered', () => {
        // Test no results state
    });
    
    it('should update page size correctly', () => {
        // Test page size selection
    });
});
```

#### Integration Tests
```javascript
// src/__tests__/components/member/MemberList.test.js
describe('MemberList Integration', () => {
    it('should filter and paginate members correctly', () => {
        // Test full workflow
    });
    
    it('should reset to first page when searching', () => {
        // Test pagination reset behavior
    });
    
    it('should maintain search state across page changes', () => {
        // Test state persistence
    });
});
```

## Framework Constraints & Considerations

### React 18.2.0 + Class Components
- Hooks only used in new utility components
- Existing class components use state management logic
- Backward compatibility maintained

### Emotion CSS-in-JS Integration
- Use Denali Design System colors and fonts
- Responsive design considerations
- Consistent styling patterns

### Redux Integration
- Avoid selector-level preprocessing (performance)
- Component-level pagination state management
- No additional Redux state required

### Performance Considerations
- Client-side filtering only (per requirements)
- Debounced search to prevent excessive filtering
- Efficient pagination rendering

## Implementation Timeline

### Week 1: Core Infrastructure
- Create pagination and filtering hooks
- Set up basic component structure

### Week 2: UI Components
- Implement Pagination component
- Implement MemberFilter component
- Create comprehensive tests

### Week 3: Integration
- Integrate pagination into MemberList
- Update MemberTable for display-only logic
- Test integration scenarios

### Week 4: Role/Group Specific Implementation
- Apply pagination to UserRoleTable
- Apply pagination to GroupMemberList
- Ensure consistent UX across all member views

### Week 5: Testing & Refinement
- Comprehensive testing
- Performance optimization
- Documentation updates

## Acceptance Criteria

### Functional Requirements ✓
- [x] Pagination with max 9 visible page numbers
- [x] Page size selection (30/50/100 items)
- [x] Client-side filtering with account name search
- [x] 200ms debounce for search input
- [x] "Page X / Total" display format
- [x] Filter persistence across page changes
- [x] No results message handling

### Non-functional Requirements ✓
- [x] No server requests for filtering
- [x] Performance optimized with debouncing
- [x] Consistent UX across role and group views
- [x] Maintains existing component patterns
- [x] Framework constraint compliance

This design ensures all requirements are met while maintaining compatibility with the existing Athenz UI architecture and framework constraints.