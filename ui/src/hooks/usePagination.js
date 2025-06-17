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
import { PAGINATION_ITEMS_PER_PAGE_OPTIONS } from '../components/constants/constants';

/**
 * Simplified pagination hook for general use cases
 * For complex member pagination with filtering, use useMemberPagination instead
 *
 * @param {Array} data - Array of items to paginate
 * @param {number} initialItemsPerPage - Initial items per page
 * @returns {Object} Pagination state and controls
 */
export const usePagination = (data = [], initialItemsPerPage = 10) => {
    const [currentPage, setCurrentPage] = useState(1);
    const [itemsPerPage, setItemsPerPage] = useState(initialItemsPerPage);

    const totalItems = data.length;
    const totalPages =
        itemsPerPage > 0 ? Math.ceil(totalItems / itemsPerPage) : 1;

    // Paginated data with memoization
    const paginatedData = useMemo(() => {
        if (itemsPerPage <= 0) return [];

        const startIndex = (currentPage - 1) * itemsPerPage;
        const endIndex = startIndex + itemsPerPage;
        return data.slice(startIndex, endIndex);
    }, [data, currentPage, itemsPerPage]);

    // Navigation state
    const hasNextPage = currentPage < totalPages;
    const hasPreviousPage = currentPage > 1;

    // Navigation functions
    const goToPage = (page) => {
        if (page >= 1 && page <= totalPages) {
            setCurrentPage(page);
        }
    };

    const goToNextPage = () => {
        if (hasNextPage) {
            setCurrentPage(currentPage + 1);
        }
    };

    const goToPreviousPage = () => {
        if (hasPreviousPage) {
            setCurrentPage(currentPage - 1);
        }
    };

    const setPageSize = (newItemsPerPage) => {
        setItemsPerPage(newItemsPerPage);
        setCurrentPage(1); // Reset to first page when page size changes
    };

    // Reset to first page when data length changes
    useEffect(() => {
        setCurrentPage(1);
    }, [data.length]);

    return {
        currentPage,
        totalPages,
        totalItems,
        itemsPerPage,
        paginatedData,
        hasNextPage,
        hasPreviousPage,
        showPagination: totalItems > PAGINATION_ITEMS_PER_PAGE_OPTIONS[0],
        goToPage,
        goToNextPage,
        goToPreviousPage,
        setPageSize,
    };
};
