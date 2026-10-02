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
import SnapshotList from '../../../components/microsegmentation/SnapshotList';

const domain = 'dom';
const service = 'svc';

const snapshots = [
    {
        domainName: domain,
        serviceName: service,
        name: 'v1',
        createdTime: '2026-09-16T10:00:00.000Z',
        modified: '2026-09-20T12:30:00.000Z',
        active: true,
    },
    {
        domainName: domain,
        serviceName: service,
        name: 'v2',
        createdTime: '2026-09-25T08:15:00.000Z',
        active: false,
    },
];

const snapshotDetails = {
    ...snapshots[0],
    transportPolicyRules: { ingress: [], egress: [] },
};

const usage = { principals: [], partial: false };

const buildApi = (overrides = {}) => ({
    getSnapshots: jest.fn().mockResolvedValue({ snapshots }),
    getSnapshot: jest.fn().mockResolvedValue(snapshotDetails),
    getSnapshotUsage: jest.fn().mockResolvedValue(usage),
    createSnapshot: jest.fn().mockResolvedValue({ name: 'v3', active: false }),
    updateSnapshot: jest.fn().mockResolvedValue({ name: 'v1', active: false }),
    deleteSnapshot: jest.fn().mockResolvedValue({}),
    ...overrides,
});

const guideLink = 'https://example.com/guide';

const forbiddenError = () => {
    const err = new Error('forbidden');
    err.statusCode = 403;
    err.body = { message: 'MSD: Forbidden' };
    return err;
};

const renderList = (
    api,
    pageFeatureFlag = { snapshots: true, snapshotsGuideLink: guideLink }
) =>
    render(
        <SnapshotList
            api={api}
            domain={domain}
            service={service}
            _csrf={'csrf'}
            pageFeatureFlag={pageFeatureFlag}
        />
    );

describe('SnapshotList', () => {
    it('renders snapshots sorted by creation time, newest first', async () => {
        const api = buildApi();
        const { getByTestId } = renderList(api);

        await waitFor(() =>
            expect(getByTestId('snapshot-table')).toBeInTheDocument()
        );
        expect(api.getSnapshots).toHaveBeenCalledWith(domain, service);
        expect(screen.getByText('Snapshots (2)')).toBeInTheDocument();

        const rows = screen.getAllByTestId(/^snapshot-row-/);
        expect(rows[0]).toHaveAttribute('data-testid', 'snapshot-row-v2');
        expect(rows[1]).toHaveAttribute('data-testid', 'snapshot-row-v1');
        expect(screen.getByText('Active')).toBeInTheDocument();
        expect(screen.getByText('Inactive')).toBeInTheDocument();
        expect(screen.getByText('Guide')).toHaveAttribute(
            'href',
            'https://example.com/guide'
        );
        expect(getByTestId('snapshot-list')).toMatchSnapshot();
    });

    it('shows the empty state only for a successful empty list', async () => {
        const api = buildApi({
            getSnapshots: jest.fn().mockResolvedValue({ snapshots: [] }),
        });
        const { getByTestId, queryByTestId } = renderList(api);

        await waitFor(() =>
            expect(getByTestId('snapshot-list-empty')).toBeInTheDocument()
        );
        expect(queryByTestId('snapshot-table')).toBeNull();
        expect(screen.getByText('Snapshots (0)')).toBeInTheDocument();
    });

    it('shows an error and not the empty state when the list call fails', async () => {
        const err = new Error('failed');
        err.statusCode = 404;
        err.body = { message: 'MSD: unable to read snapshots' };
        const api = buildApi({
            getSnapshots: jest.fn().mockRejectedValue(err),
        });
        const { getByTestId, queryByTestId } = renderList(api);

        await waitFor(() =>
            expect(getByTestId('snapshot-list-error')).toBeInTheDocument()
        );
        expect(getByTestId('snapshot-list-error')).toHaveTextContent(
            'Status: 404. Message: MSD: unable to read snapshots'
        );
        expect(queryByTestId('snapshot-list-empty')).toBeNull();
        expect(queryByTestId('snapshot-table')).toBeNull();
    });

    it('explains a 403 on the list, links the guide and hides the count', async () => {
        const api = buildApi({
            getSnapshots: jest.fn().mockRejectedValue(forbiddenError()),
        });
        const { getByTestId, queryByTestId, getByText } = renderList(api);

        await waitFor(() =>
            expect(getByTestId('snapshot-forbidden')).toBeInTheDocument()
        );
        expect(getByTestId('snapshot-list-error')).toHaveTextContent(
            'You are not authorized to view the policy snapshots of this service. See the guide for more details.'
        );
        expect(getByText('guide')).toHaveAttribute('href', guideLink);
        expect(getByText('Snapshots')).toBeInTheDocument();
        expect(getByText('Add Snapshot')).toBeInTheDocument();
        expect(queryByTestId('snapshot-list-empty')).toBeNull();
        expect(queryByTestId('snapshot-table')).toBeNull();
    });

    it('omits the guide sentence on a 403 when no guide link is configured', async () => {
        const api = buildApi({
            getSnapshots: jest.fn().mockRejectedValue(forbiddenError()),
        });
        const { getByTestId, queryByText } = renderList(api, {
            snapshots: true,
            snapshotsGuideLink: '',
        });

        await waitFor(() =>
            expect(getByTestId('snapshot-forbidden')).toBeInTheDocument()
        );
        expect(getByTestId('snapshot-list-error')).toHaveTextContent(
            'You are not authorized to view the policy snapshots of this service.'
        );
        expect(queryByText('guide')).toBeNull();
        expect(getByTestId('snapshot-list-error')).not.toHaveTextContent(
            'See the'
        );
    });

    it('loads snapshot details and usage when a row is expanded', async () => {
        const api = buildApi();
        const { getByTestId, queryByTestId } = renderList(api);

        await waitFor(() =>
            expect(getByTestId('snapshot-view-v1')).toBeInTheDocument()
        );
        expect(api.getSnapshot).not.toHaveBeenCalled();

        fireEvent.click(getByTestId('snapshot-view-v1'));

        await waitFor(() =>
            expect(getByTestId('snapshot-ingress-table')).toBeInTheDocument()
        );
        expect(api.getSnapshot).toHaveBeenCalledWith(domain, service, 'v1');
        expect(api.getSnapshotUsage).toHaveBeenCalledWith(
            domain,
            service,
            'v1'
        );

        fireEvent.click(getByTestId('snapshot-view-v1'));
        expect(queryByTestId('snapshot-details')).toBeNull();
    });

    it('toggles the active flag and reloads the list', async () => {
        const api = buildApi();
        const { getByTestId } = renderList(api);

        await waitFor(() =>
            expect(
                getByTestId('snapshot-active-v1-switch-input')
            ).toBeInTheDocument()
        );
        expect(getByTestId('snapshot-active-v1-switch-input')).toBeChecked();
        expect(
            getByTestId('snapshot-active-v2-switch-input')
        ).not.toBeChecked();

        fireEvent.click(getByTestId('snapshot-active-v1-switch-input'));

        await waitFor(() =>
            expect(api.updateSnapshot).toHaveBeenCalledWith(
                domain,
                service,
                'v1',
                false,
                'csrf'
            )
        );
        await waitFor(() => expect(api.getSnapshots).toHaveBeenCalledTimes(2));
    });

    it('shows an inline error and keeps the table when the toggle fails', async () => {
        const forbidden = new Error('forbidden');
        forbidden.statusCode = 403;
        forbidden.body = { message: 'MSD: Forbidden' };
        const api = buildApi({
            updateSnapshot: jest.fn().mockRejectedValue(forbidden),
        });
        const { getByTestId } = renderList(api);

        await waitFor(() =>
            expect(
                getByTestId('snapshot-active-v2-switch-input')
            ).toBeInTheDocument()
        );
        fireEvent.click(getByTestId('snapshot-active-v2-switch-input'));

        await waitFor(() =>
            expect(getByTestId('snapshot-update-error')).toHaveTextContent(
                'You are not authorized to change the policy snapshots of this service. See the guide for more details.'
            )
        );
        expect(getByTestId('snapshot-table')).toBeInTheDocument();
        expect(api.updateSnapshot).toHaveBeenCalledWith(
            domain,
            service,
            'v2',
            true,
            'csrf'
        );
        expect(api.getSnapshots).toHaveBeenCalledTimes(1);
    });

    it('opens the add snapshot modal', async () => {
        const api = buildApi();
        const { getByTestId, getByText } = renderList(api);

        await waitFor(() =>
            expect(getByTestId('snapshot-table')).toBeInTheDocument()
        );
        fireEvent.click(getByText('Add Snapshot'));
        expect(getByTestId('add-snapshot-modal')).toBeInTheDocument();
    });

    it('deletes a snapshot and reloads the list', async () => {
        const api = buildApi();
        const { getByTestId } = renderList(api);

        await waitFor(() =>
            expect(getByTestId('snapshot-delete-v2')).toBeInTheDocument()
        );
        fireEvent.click(getByTestId('snapshot-delete-v2'));
        expect(getByTestId('delete-modal-message')).toHaveTextContent('v2');

        fireEvent.click(getByTestId('delete-modal-delete'));

        await waitFor(() =>
            expect(api.deleteSnapshot).toHaveBeenCalledWith(
                domain,
                service,
                'v2',
                false,
                'csrf'
            )
        );
        await waitFor(() => expect(api.getSnapshots).toHaveBeenCalledTimes(2));
    });

    it('asks for force delete on a 409 and resends with force', async () => {
        const conflict = new Error('conflict');
        conflict.statusCode = 409;
        conflict.body = {
            message:
                'MSD: snapshot v1 is active and cannot be deleted; mark it inactive first, or retry with force=true',
        };
        const deleteSnapshot = jest
            .fn()
            .mockRejectedValueOnce(conflict)
            .mockResolvedValueOnce({});
        const api = buildApi({ deleteSnapshot });
        const { getByTestId, getByText } = renderList(api);

        await waitFor(() =>
            expect(getByTestId('snapshot-delete-v1')).toBeInTheDocument()
        );
        fireEvent.click(getByTestId('snapshot-delete-v1'));
        fireEvent.click(getByTestId('delete-modal-delete'));

        await waitFor(() =>
            expect(getByText('Force delete')).toBeInTheDocument()
        );
        expect(deleteSnapshot).toHaveBeenLastCalledWith(
            domain,
            service,
            'v1',
            false,
            'csrf'
        );
        expect(getByTestId('delete-modal-message')).toHaveTextContent(
            'snapshot v1 is active and cannot be deleted'
        );

        fireEvent.click(getByTestId('delete-modal-delete'));

        await waitFor(() =>
            expect(deleteSnapshot).toHaveBeenLastCalledWith(
                domain,
                service,
                'v1',
                true,
                'csrf'
            )
        );
        await waitFor(() => expect(api.getSnapshots).toHaveBeenCalledTimes(2));
    });

    it('shows the delete error for other failures and keeps the modal open', async () => {
        const forbidden = new Error('forbidden');
        forbidden.statusCode = 403;
        forbidden.body = { message: 'MSD: Forbidden' };
        const api = buildApi({
            deleteSnapshot: jest.fn().mockRejectedValue(forbidden),
        });
        const { getByTestId } = renderList(api);

        await waitFor(() =>
            expect(getByTestId('snapshot-delete-v1')).toBeInTheDocument()
        );
        fireEvent.click(getByTestId('snapshot-delete-v1'));
        fireEvent.click(getByTestId('delete-modal-delete'));

        await waitFor(() =>
            expect(screen.getByTestId('snapshot-forbidden')).toHaveTextContent(
                'You are not authorized to delete the policy snapshots of this service. See the guide for more details.'
            )
        );
        expect(getByTestId('delete-modal-delete')).toBeInTheDocument();
        expect(api.getSnapshots).toHaveBeenCalledTimes(1);
    });
});
