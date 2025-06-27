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
import { useState, useMemo, useEffect } from 'react';
import {
    PAGINATION_DEFAULT_ITEMS_PER_PAGE,
    PAGINATION_ITEMS_PER_PAGE_OPTIONS,
} from '../components/constants/constants';

/**
 * Unified hook for member filtering, sorting, and pagination
 * Handles both approved and pending members with shared logic
 *
 * @param {Array} members - Array of member objects
 * @param {Object} collectionDetails - Collection details with trust property
 * @param {boolean} paginationEnabled - Whether pagination is enabled
 * @param {string} initialFilter - Initial filter text
 * @returns {Object} Complete pagination state and controls for both member types
 */
export const useMemberPagination = (
    members = [],
    collectionDetails = {},
    paginationEnabled = true,
    initialFilter = ''
) => {
    const [filterText, setFilterText] = useState(initialFilter);
    const [approvedPage, setApprovedPage] = useState(1);
    const [pendingPage, setPendingPage] = useState(1);
    const [itemsPerPage, setItemsPerPage] = useState(
        PAGINATION_DEFAULT_ITEMS_PER_PAGE
    );

    // Memoized filtering - only recalculate when members or filter changes
    const filteredMembers = useMemo(() => {
        if (!filterText.trim()) {
            return members;
        }

        const lowerCaseFilter = filterText.toLowerCase();
        return members.filter((member) => {
            return (
                member.memberName?.toLowerCase().includes(lowerCaseFilter) ||
                member.memberFullName?.toLowerCase().includes(lowerCaseFilter)
            );
        });
    }, [members, filterText]);

    // Split members into approved and pending with memoization
    const { approvedMembers, pendingMembers } = useMemo(() => {
        if (collectionDetails.trust) {
            // Trust collections don't have pending members
            return {
                approvedMembers: filteredMembers,
                pendingMembers: [],
            };
        } else {
            return {
                approvedMembers: filteredMembers.filter(
                    (member) => member.approved
                ),
                pendingMembers: filteredMembers.filter(
                    (member) => !member.approved
                ),
            };
        }
    }, [filteredMembers, collectionDetails.trust]);

    // Sorted members with memoization to prevent unnecessary re-sorts
    const sortedApprovedMembers = useMemo(
        () =>
            [...approvedMembers].sort((a, b) =>
                a.memberName.localeCompare(b.memberName)
            ),
        [approvedMembers]
    );

    const sortedPendingMembers = useMemo(
        () =>
            [...pendingMembers].sort((a, b) =>
                a.memberName.localeCompare(b.memberName)
            ),
        [pendingMembers]
    );

    // Pagination calculations
    const approvedTotalPages =
        paginationEnabled && itemsPerPage > 0
            ? Math.ceil(sortedApprovedMembers.length / itemsPerPage)
            : 1;

    const pendingTotalPages =
        paginationEnabled && itemsPerPage > 0
            ? Math.ceil(sortedPendingMembers.length / itemsPerPage)
            : 1;

    // Paginated data
    const paginatedApprovedMembers = useMemo(() => {
        if (!paginationEnabled) return sortedApprovedMembers;

        const startIndex = (approvedPage - 1) * itemsPerPage;
        const endIndex = startIndex + itemsPerPage;
        return sortedApprovedMembers.slice(startIndex, endIndex);
    }, [sortedApprovedMembers, approvedPage, itemsPerPage, paginationEnabled]);

    const paginatedPendingMembers = useMemo(() => {
        if (!paginationEnabled) return sortedPendingMembers;

        const startIndex = (pendingPage - 1) * itemsPerPage;
        const endIndex = startIndex + itemsPerPage;
        return sortedPendingMembers.slice(startIndex, endIndex);
    }, [sortedPendingMembers, pendingPage, itemsPerPage, paginationEnabled]);

    // Navigation functions
    const approvedNavigation = {
        hasNext: paginationEnabled && approvedPage < approvedTotalPages,
        hasPrevious: paginationEnabled && approvedPage > 1,
        goToPage: (page) => {
            if (paginationEnabled && page >= 1 && page <= approvedTotalPages) {
                setApprovedPage(page);
            }
        },
        goToNextPage: () => {
            if (paginationEnabled && approvedPage < approvedTotalPages) {
                setApprovedPage(approvedPage + 1);
            }
        },
        goToPreviousPage: () => {
            if (paginationEnabled && approvedPage > 1) {
                setApprovedPage(approvedPage - 1);
            }
        },
    };

    const pendingNavigation = {
        hasNext: paginationEnabled && pendingPage < pendingTotalPages,
        hasPrevious: paginationEnabled && pendingPage > 1,
        goToPage: (page) => {
            if (paginationEnabled && page >= 1 && page <= pendingTotalPages) {
                setPendingPage(page);
            }
        },
        goToNextPage: () => {
            if (paginationEnabled && pendingPage < pendingTotalPages) {
                setPendingPage(pendingPage + 1);
            }
        },
        goToPreviousPage: () => {
            if (paginationEnabled && pendingPage > 1) {
                setPendingPage(pendingPage - 1);
            }
        },
    };

    // Reset pages when members or filter changes
    useEffect(() => {
        if (paginationEnabled) {
            setApprovedPage(1);
            setPendingPage(1);
        }
    }, [filteredMembers.length, paginationEnabled]);

    // Page size change handler
    const handlePageSizeChange = (newSize) => {
        if (paginationEnabled) {
            setItemsPerPage(newSize);
            setApprovedPage(1);
            setPendingPage(1);
        }
    };

    // Filter controls
    const clearFilter = () => setFilterText('');

    return {
        // Filter state
        filterText,
        setFilterText,
        clearFilter,
        hasFilter: filterText.trim().length > 0,

        // Approved members pagination
        approvedMembers: {
            data: paginatedApprovedMembers,
            allData: sortedApprovedMembers,
            totalItems: sortedApprovedMembers.length,
            currentPage: paginationEnabled ? approvedPage : 1,
            totalPages: approvedTotalPages,
            itemsPerPage: paginationEnabled
                ? itemsPerPage
                : sortedApprovedMembers.length,
            showPagination:
                paginationEnabled &&
                sortedApprovedMembers.length >
                    PAGINATION_ITEMS_PER_PAGE_OPTIONS[0],
            ...approvedNavigation,
        },

        // Pending members pagination
        pendingMembers: {
            data: paginatedPendingMembers,
            allData: sortedPendingMembers,
            totalItems: sortedPendingMembers.length,
            currentPage: paginationEnabled ? pendingPage : 1,
            totalPages: pendingTotalPages,
            itemsPerPage: paginationEnabled
                ? itemsPerPage
                : sortedPendingMembers.length,
            showPagination:
                paginationEnabled &&
                sortedPendingMembers.length >
                    PAGINATION_ITEMS_PER_PAGE_OPTIONS[0],
            ...pendingNavigation,
        },

        // Page size controls
        pageSizeOptions: PAGINATION_ITEMS_PER_PAGE_OPTIONS,
        currentPageSize: itemsPerPage,
        onPageSizeChange: handlePageSizeChange,

        // Global state
        paginationEnabled,
        totalMembersCount: members.length,
        filteredMembersCount: filteredMembers.length,
    };
};
