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
import styled from '@emotion/styled';
import { colors } from '../denali/styles';
import {
    PAGINATION_ITEMS_PER_PAGE_LABEL,
    PAGINATION_ARIA_SELECT_PAGE_SIZE_LABEL,
} from '../constants/constants';

const SelectorContainer = styled.div`
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 14px;
    color: ${(props) => (props.compact ? colors.grey600 : colors.grey800)};
`;

const Label = styled.span`
    color: ${colors.grey600};
    font-weight: 500;
    font-size: 14px;
`;

const PageSizeSelector = ({
    value,
    options = [30, 50, 100],
    onChange,
    label = PAGINATION_ITEMS_PER_PAGE_LABEL,
    disabled = false,
    compact = false,
    className,
    testId,
}) => {
    const selectId =
        testId ||
        `page-size-selector-${Math.random().toString(36).substr(2, 9)}`;

    const handleChange = (event) => {
        const newValue = parseInt(event.target.value, 10);
        if (onChange) {
            onChange(newValue);
        }
    };

    return (
        <SelectorContainer className={className} compact={compact}>
            {label && <Label>{label}</Label>}
            <div
                className={`input has-arrow w-auto ${
                    compact ? 'is-small' : ''
                }`}
            >
                <select
                    id={selectId}
                    value={value}
                    onChange={handleChange}
                    disabled={disabled}
                    aria-label={PAGINATION_ARIA_SELECT_PAGE_SIZE_LABEL}
                    style={{ minWidth: compact ? '50px' : '60px' }}
                >
                    {options.map((option) => (
                        <option key={option} value={option}>
                            {option}
                        </option>
                    ))}
                    {!options.includes(value) && (
                        <option key={value} value={value}>
                            {value}
                        </option>
                    )}
                </select>
            </div>
        </SelectorContainer>
    );
};

export default PageSizeSelector;
