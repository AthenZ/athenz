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
import { render, screen } from '@testing-library/react';
import SnapshotErrorMessage from '../../../components/microsegmentation/SnapshotErrorMessage';

const error = (statusCode, message) => {
    const err = new Error('failed');
    err.statusCode = statusCode;
    err.body = { message };
    return err;
};

describe('SnapshotErrorMessage', () => {
    it('renders nothing without an error', () => {
        const { container } = render(<SnapshotErrorMessage err={null} />);
        expect(container).toBeEmptyDOMElement();
    });

    it('keeps the MSD status and message for non-403 errors', () => {
        render(
            <SnapshotErrorMessage
                err={error(500, 'MSD: store unavailable')}
                action='view'
                guideLink='https://example.com/guide'
            />
        );
        expect(
            screen.getByText('Status: 500. Message: MSD: store unavailable')
        ).toBeInTheDocument();
        expect(screen.queryByTestId('snapshot-forbidden')).toBeNull();
    });

    it('explains a 403 per action and links the guide when configured', () => {
        render(
            <SnapshotErrorMessage
                err={error(403, 'MSD: Forbidden')}
                action='delete'
                guideLink='https://example.com/guide'
            />
        );
        expect(screen.getByTestId('snapshot-forbidden')).toHaveTextContent(
            'You are not authorized to delete the policy snapshots of this service. See the guide for more details.'
        );
        expect(screen.getByText('guide')).toHaveAttribute(
            'href',
            'https://example.com/guide'
        );
        expect(screen.queryByText('MSD: Forbidden')).toBeNull();
    });

    it('falls back to the view wording and drops the guide sentence', () => {
        render(<SnapshotErrorMessage err={error(403, 'MSD: Forbidden')} />);
        expect(screen.getByTestId('snapshot-forbidden')).toHaveTextContent(
            'You are not authorized to view the policy snapshots of this service.'
        );
        expect(screen.getByTestId('snapshot-forbidden')).not.toHaveTextContent(
            'See the'
        );
    });
});
