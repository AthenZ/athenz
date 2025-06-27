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
import { useState, useMemo } from 'react';

/**
 * Custom hook for filtering member lists with performance optimization
 * @param {Array} members - Array of member objects to filter
 * @param {string} initialFilter - Initial filter text
 * @returns {Object} Filter state and methods
 */
export const useMemberFilter = (members, initialFilter = '') => {
    const [filterText, setFilterText] = useState(initialFilter);

    // Memoized filtering to prevent unnecessary re-computations
    const filteredMembers = useMemo(() => {
        if (!filterText.trim()) {
            return members;
        }

        const lowerCaseFilter = filterText.toLowerCase();

        return members.filter((member) => {
            // Filter by member name (primary field)
            if (member.memberName?.toLowerCase().includes(lowerCaseFilter)) {
                return true;
            }

            // Filter by member full name (if available)
            if (
                member.memberFullName?.toLowerCase().includes(lowerCaseFilter)
            ) {
                return true;
            }

            return false;
        });
    }, [members, filterText]);

    const clearFilter = () => {
        setFilterText('');
    };

    return {
        filterText,
        setFilterText,
        filteredMembers,
        clearFilter,
        filteredCount: filteredMembers.length,
        totalCount: members.length,
        hasFilter: filterText.trim().length > 0,
    };
};
