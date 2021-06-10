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
import {fireEvent, render} from '@testing-library/react';
import AddSegmentation from "../../../components/microsegmentation/AddSegmentation";
import API from "../../../api";

describe('AddSegmentation', () => {
    it('should render', () => {
        let domain = 'domain';
        const showAddSegmentation = true;
        const cancel = function() {};
        const submit = function() {};
        let _csrf = 'csrf';

        const { getByTestId } = render(
            <AddSegmentation
                api={API()}
                domain={domain}
                onSubmit={submit}
                onCancel={cancel}
                _csrf={_csrf}
                showAddSegment={showAddSegmentation}
                justificationRequired={false}
            />
        );
        const addsegment = getByTestId('add-segment');
        expect(addsegment).toMatchSnapshot();
    });

    it('should render fail to submit add-segmentation: destinationService is required', () => {
        const showAddSegmentation = true;
        const cancel = function() {};
        const domain = 'domain';
        let role ='roleName';
        const submit = function() {};
        let _csrf = 'csrf';
        const api = {
            getServices(domain) {
                return new Promise((resolve, reject) => {
                    resolve(['a, b']);
                });
            },
        };
        const { getByTestId, getByText } =  render(
            <AddSegmentation
                api={api}
                domain={domain}
                onSubmit={submit}
                onCancel={cancel}
                _csrf={_csrf}
                showAddSegment={showAddSegmentation}
                justificationRequired={false}
            />
        );
        const addSegmentation = getByTestId('add-modal-message');
        expect(addSegmentation).toMatchSnapshot();
    });

});
