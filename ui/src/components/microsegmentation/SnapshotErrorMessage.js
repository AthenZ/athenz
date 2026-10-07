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
import RequestUtils from '../utils/RequestUtils';

const FORBIDDEN_TEXT = {
    view: 'You are not authorized to view the policy snapshots of this service.',
    create: 'You are not authorized to create policy snapshots for this service.',
    update: 'You are not authorized to change the policy snapshots of this service.',
    delete: 'You are not authorized to delete the policy snapshots of this service.',
};

/**
 * Renders an error from a snapshot API call. A 403 is turned into a short
 * "not authorized" sentence for the given action (view, create, update,
 * delete), with a link to the guide when one is configured, because the
 * authorization is granted per service and users routinely hit it. Every
 * other error keeps MSD's own status and message.
 */
export default function SnapshotErrorMessage({ err, action, guideLink }) {
    if (!err) {
        return null;
    }
    if (err.statusCode === 403) {
        return (
            <span data-testid='snapshot-forbidden'>
                {FORBIDDEN_TEXT[action] || FORBIDDEN_TEXT.view}
                {guideLink ? (
                    <>
                        {' See the '}
                        <a
                            href={guideLink}
                            target='_blank'
                            rel='noopener noreferrer'
                        >
                            guide
                        </a>
                        {' for more details.'}
                    </>
                ) : null}
            </span>
        );
    }
    return <span>{RequestUtils.xhrErrorCheckHelper(err)}</span>;
}
