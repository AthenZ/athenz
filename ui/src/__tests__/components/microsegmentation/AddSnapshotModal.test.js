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
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import AddSnapshotModal from '../../../components/microsegmentation/AddSnapshotModal';

const domain = 'dom';
const service = 'svc';

const guideLink = 'https://example.com/guide';

const renderModal = (api, onSubmit = jest.fn(), onCancel = jest.fn()) =>
    render(
        <AddSnapshotModal
            api={api}
            domain={domain}
            service={service}
            _csrf={'csrf'}
            guideLink={guideLink}
            isOpen={true}
            onSubmit={onSubmit}
            onCancel={onCancel}
        />
    );

describe('AddSnapshotModal', () => {
    it('renders', () => {
        const { getByTestId } = renderModal({ createSnapshot: jest.fn() });
        expect(getByTestId('add-snapshot-modal')).toMatchSnapshot();
    });

    it('requires a snapshot name', () => {
        const api = { createSnapshot: jest.fn() };
        renderModal(api);

        fireEvent.click(screen.getByText('Submit'));

        expect(
            screen.getByText('Snapshot name is required.')
        ).toBeInTheDocument();
        expect(api.createSnapshot).not.toHaveBeenCalled();
    });

    it('rejects an invalid snapshot name', () => {
        const api = { createSnapshot: jest.fn() };
        renderModal(api);

        fireEvent.change(screen.getByPlaceholderText('Enter snapshot name'), {
            target: { value: 'bad name!' },
        });
        fireEvent.click(screen.getByText('Submit'));

        expect(
            screen.getByText(
                'Snapshot name may contain letters, digits, "_" and "-", with "." as a separator.'
            )
        ).toBeInTheDocument();
        expect(api.createSnapshot).not.toHaveBeenCalled();
    });

    it('creates a snapshot with the given name and active flag', async () => {
        const created = { name: 'release.v1', active: true };
        const api = { createSnapshot: jest.fn().mockResolvedValue(created) };
        const onSubmit = jest.fn();
        renderModal(api, onSubmit);

        fireEvent.change(screen.getByPlaceholderText('Enter snapshot name'), {
            target: { value: ' release.v1 ' },
        });
        fireEvent.click(screen.getByTestId('snapshot-active-switch-input'));
        fireEvent.click(screen.getByText('Submit'));

        await waitFor(() => expect(onSubmit).toHaveBeenCalledWith(created));
        expect(api.createSnapshot).toHaveBeenCalledWith(
            domain,
            service,
            'release.v1',
            true,
            'csrf'
        );
    });

    it('shows the MSD error when the create fails', async () => {
        const err = new Error('bad');
        err.statusCode = 400;
        err.body = { message: 'MSD: snapshot limit of 20 reached' };
        const api = { createSnapshot: jest.fn().mockRejectedValue(err) };
        const onSubmit = jest.fn();
        renderModal(api, onSubmit);

        fireEvent.change(screen.getByPlaceholderText('Enter snapshot name'), {
            target: { value: 'v21' },
        });
        fireEvent.click(screen.getByText('Submit'));

        await waitFor(() =>
            expect(
                screen.getByText(
                    'Status: 400. Message: MSD: snapshot limit of 20 reached'
                )
            ).toBeInTheDocument()
        );
        expect(onSubmit).not.toHaveBeenCalled();
    });

    it('explains a 403 on create and links the guide', async () => {
        const err = new Error('forbidden');
        err.statusCode = 403;
        err.body = { message: 'MSD: Forbidden' };
        const api = { createSnapshot: jest.fn().mockRejectedValue(err) };
        const onSubmit = jest.fn();
        renderModal(api, onSubmit);

        fireEvent.change(screen.getByPlaceholderText('Enter snapshot name'), {
            target: { value: 'v3' },
        });
        fireEvent.click(screen.getByText('Submit'));

        await waitFor(() =>
            expect(screen.getByTestId('snapshot-forbidden')).toHaveTextContent(
                'You are not authorized to create policy snapshots for this service. See the guide for more details.'
            )
        );
        expect(screen.getByText('guide')).toHaveAttribute('href', guideLink);
        expect(onSubmit).not.toHaveBeenCalled();
    });
});
