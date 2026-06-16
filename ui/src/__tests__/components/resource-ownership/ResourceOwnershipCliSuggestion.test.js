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
import { render, fireEvent, act } from '@testing-library/react';
import { ResourceOwnershipCliSuggestion } from '../../../components/resource-ownership/ResourceOwnershipCliSuggestion';

describe('ResourceOwnershipCliSuggestion', () => {
    const writeText = jest.fn();

    beforeEach(() => {
        jest.useFakeTimers();
        writeText.mockResolvedValue(undefined);
        Object.assign(navigator, { clipboard: { writeText } });
    });

    afterEach(() => {
        jest.useRealTimers();
        jest.restoreAllMocks();
    });

    it('copies command and resets copied state after delay', async () => {
        const { getByTestId } = render(
            <ResourceOwnershipCliSuggestion command='zms-cli -d my.domain' />
        );
        await act(async () => {
            fireEvent.click(getByTestId('resource-ownership-cli-copy'));
        });
        expect(writeText).toHaveBeenCalledWith('zms-cli -d my.domain');
        expect(getByTestId('resource-ownership-cli-copy').title).toBe('Copied');
        await act(async () => {
            jest.advanceTimersByTime(2000);
        });
        expect(getByTestId('resource-ownership-cli-copy').title).toBe(
            'Copy command'
        );
    });

    it('clears copied timer on unmount', async () => {
        const setState = jest.spyOn(
            ResourceOwnershipCliSuggestion.prototype,
            'setState'
        );
        const { getByTestId, unmount } = render(
            <ResourceOwnershipCliSuggestion command='zms-cli -d my.domain' />
        );
        await act(async () => {
            fireEvent.click(getByTestId('resource-ownership-cli-copy'));
        });
        unmount();
        setState.mockClear();
        jest.advanceTimersByTime(2000);
        expect(setState).not.toHaveBeenCalled();
        setState.mockRestore();
    });

    it('renders configurable owner label in warning copy', () => {
        const { getByTestId } = render(
            <ResourceOwnershipCliSuggestion
                command='zms-cli -d my.domain'
                resourceOwnershipUi={{
                    label: 'OpenTofu',
                    icon: 'terraform',
                    cliSuggestionBody:
                        'This resource is {{label}}-managed and cannot be edited via the Athenz UI.',
                    cliSuggestionEmergencyHeading: 'Emergency only:',
                    cliSuggestionGuideFooter: 'See',
                }}
            />
        );
        expect(
            getByTestId('resource-ownership-cli-suggestion').textContent
        ).toContain('OpenTofu-managed');
    });

    it('does not show copied state when clipboard write fails', async () => {
        writeText.mockRejectedValue(new Error('denied'));
        const { getByTestId } = render(
            <ResourceOwnershipCliSuggestion command='zms-cli -d my.domain' />
        );
        await act(async () => {
            fireEvent.click(getByTestId('resource-ownership-cli-copy'));
        });
        expect(getByTestId('resource-ownership-cli-copy').title).toBe(
            'Copy command'
        );
    });
});
