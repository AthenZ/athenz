/*
 * Copyright The Athenz Authors
 * Licensed under the Apache License, Version 2.0
 */

import { renderHook, act } from '@testing-library/react';
import { useDebounce } from '../useDebounce';

describe('useDebounce', () => {
    beforeEach(() => {
        jest.useFakeTimers();
    });

    afterEach(() => {
        jest.runOnlyPendingTimers();
        jest.useRealTimers();
    });

    it('should return initial value immediately', () => {
        const { result } = renderHook(() => useDebounce('initial', 500));
        
        expect(result.current).toBe('initial');
    });

    it('should debounce value changes', () => {
        const { result, rerender } = renderHook(
            ({ value, delay }) => useDebounce(value, delay),
            {
                initialProps: { value: 'initial', delay: 500 }
            }
        );

        expect(result.current).toBe('initial');

        // Change the value
        act(() => {
            rerender({ value: 'updated', delay: 500 });
        });
        
        // Value should not update immediately
        expect(result.current).toBe('initial');

        // Fast-forward time by 300ms (less than delay)
        act(() => {
            jest.advanceTimersByTime(300);
        });
        
        // Value should still be initial
        expect(result.current).toBe('initial');

        // Fast-forward time by remaining 200ms
        act(() => {
            jest.advanceTimersByTime(200);
        });
        
        // Value should now be updated
        expect(result.current).toBe('updated');
    });

    it('should reset debounce timer on rapid changes', () => {
        const { result, rerender } = renderHook(
            ({ value, delay }) => useDebounce(value, delay),
            {
                initialProps: { value: 'initial', delay: 500 }
            }
        );

        // First change
        act(() => {
            rerender({ value: 'change1', delay: 500 });
        });
        
        // Advance time partially
        act(() => {
            jest.advanceTimersByTime(300);
        });
        
        // Second change before first debounce completes
        act(() => {
            rerender({ value: 'change2', delay: 500 });
        });
        
        // Advance time by the original remaining time
        act(() => {
            jest.advanceTimersByTime(200);
        });
        
        // Should still be initial because timer was reset
        expect(result.current).toBe('initial');
        
        // Advance time by full delay
        act(() => {
            jest.advanceTimersByTime(300);
        });
        
        // Should now be the latest change
        expect(result.current).toBe('change2');
    });

    it('should handle different delay values', () => {
        const { result, rerender } = renderHook(
            ({ value, delay }) => useDebounce(value, delay),
            {
                initialProps: { value: 'initial', delay: 200 }
            }
        );

        act(() => {
            rerender({ value: 'updated', delay: 200 });
        });
        
        act(() => {
            jest.advanceTimersByTime(200);
        });
        
        expect(result.current).toBe('updated');
    });

    it('should handle zero delay', () => {
        const { result, rerender } = renderHook(
            ({ value, delay }) => useDebounce(value, delay),
            {
                initialProps: { value: 'initial', delay: 0 }
            }
        );

        act(() => {
            rerender({ value: 'updated', delay: 0 });
        });
        
        act(() => {
            jest.advanceTimersByTime(0);
        });
        
        expect(result.current).toBe('updated');
    });

    it('should cleanup timeout on unmount', () => {
        const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');
        
        const { unmount, rerender } = renderHook(
            ({ value, delay }) => useDebounce(value, delay),
            {
                initialProps: { value: 'initial', delay: 500 }
            }
        );

        act(() => {
            rerender({ value: 'updated', delay: 500 });
        });
        
        unmount();
        
        expect(clearTimeoutSpy).toHaveBeenCalled();
        
        clearTimeoutSpy.mockRestore();
    });
});