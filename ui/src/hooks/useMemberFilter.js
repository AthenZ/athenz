/*
 * Copyright The Athenz Authors
 * Licensed under the Apache License, Version 2.0
 */

import { useState, useEffect } from 'react';
import { useDebounce } from './useDebounce';

/**
 * Custom hook for filtering members with debounced search
 * @param {Array} members - Array of member objects
 * @param {number} debounceTime - Debounce delay in milliseconds (default: 200)
 * @returns {Object} - Filter state and controls
 */
export const useMemberFilter = (members, debounceTime = 200) => {
    const [searchText, setSearchText] = useState('');
    const [filteredMembers, setFilteredMembers] = useState(members || []);
    
    const debouncedSearchText = useDebounce(searchText, debounceTime);
    
    useEffect(() => {
        const memberList = members || [];
        
        if (!debouncedSearchText.trim()) {
            setFilteredMembers(memberList);
        } else {
            const filtered = memberList.filter(member =>
                member.memberName.toLowerCase().includes(debouncedSearchText.toLowerCase())
            );
            setFilteredMembers(filtered);
        }
    }, [members, debouncedSearchText]);
    
    return {
        searchText,
        setSearchText,
        filteredMembers,
        isFiltered: searchText.length > 0,
        hasResults: filteredMembers.length > 0,
    };
};