/*
 * Copyright The Athenz Authors
 * Licensed under the Apache License, Version 2.0
 */

import { useState, useEffect } from 'react';

/**
 * Custom hook that debounces a value
 * @param {any} value - The value to debounce
 * @param {number} delay - The delay in milliseconds
 * @returns {any} - The debounced value
 */
export const useDebounce = (value, delay) => {
    const [debouncedValue, setDebouncedValue] = useState(value);

    useEffect(() => {
        // Set up a timeout to update the debounced value after the delay
        const timeoutId = setTimeout(() => {
            setDebouncedValue(value);
        }, delay);

        // Cleanup function to clear the timeout if value or delay changes
        return () => {
            clearTimeout(timeoutId);
        };
    }, [value, delay]);

    return debouncedValue;
};