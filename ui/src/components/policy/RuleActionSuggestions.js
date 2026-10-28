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
import { WELL_KNOWN_POLICY_ACTIONS } from '../constants/constants';

// Suggestion list for the rule action input. Linked to the input through
// its list attribute so the browser offers the well known actions while
// still accepting any custom action typed by the user.
const RuleActionSuggestions = (props) => {
    return (
        <datalist id={props.id} data-testid='rule-action-suggestions'>
            {WELL_KNOWN_POLICY_ACTIONS.map((action) => (
                <option key={action} value={action} />
            ))}
        </datalist>
    );
};

export default RuleActionSuggestions;
