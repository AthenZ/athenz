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
import PropTypes from 'prop-types';
import styled from '@emotion/styled';
import SearchInput from '../denali/SearchInput';
import { MEMBER_FILTER_PLACEHOLDER } from '../constants/constants';

const FilterContainer = styled.div`
    margin-bottom: 16px;
    max-width: 400px;
`;

const MemberFilter = ({ value, onChange, testId, disabled }) => {
    const handleInputChange = (event) => {
        if (onChange) {
            onChange(event.target.value);
        }
    };

    const handleKeyDown = (event) => {
        if (event.key === 'Escape' && value && onChange) {
            onChange('');
            event.preventDefault();
        }
    };

    return (
        <FilterContainer data-testid={testId}>
            <SearchInput
                value={value}
                onChange={handleInputChange}
                onKeyDown={handleKeyDown}
                placeholder={MEMBER_FILTER_PLACEHOLDER}
                aria-label={`Filter members by name${
                    value ? ' (filtered)' : ''
                }`}
                data-testid={testId ? `${testId}-input` : undefined}
                disabled={disabled}
                fluid
            />
        </FilterContainer>
    );
};

MemberFilter.propTypes = {
    /** Current filter text value */
    value: PropTypes.string.isRequired,
    /** Callback when filter text changes */
    onChange: PropTypes.func.isRequired,
    /** Test ID for automated testing */
    testId: PropTypes.string,
    /** Disable the filter input */
    disabled: PropTypes.bool,
};

MemberFilter.defaultProps = {
    testId: undefined,
    disabled: false,
};

export default MemberFilter;
