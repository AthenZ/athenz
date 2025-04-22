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
import Select from 'react-select';
import PropTypes from 'prop-types';
import { css, cx } from '@emotion/css';

const makeCssMultiSelect = () => css`
    .denali-multiselect__control {
        min-height: 36px !important;
        width: auto;
        padding: 0px 10px !important;
    }

    & > .denali-multiselect__control {
        align-items: center;
        background: rgba(1, 110, 255, 0.08) !important;
        border: none !important;
        border-radius: 4px;
        color: #303030;
        display: flex;
        outline: none;
        position: relative;
    }

    .denali-multiselect__control--menu-is-open {
        box-shadow: 0px 2px 0px #016EFF !important;
    }

    & > .denali-multiselect__control--is-focused {
        align-items: center;
        background: #016eff14 !important;
        border: none !important;
        border-radius: 4px;
        color: #303030;
        display: flex;
        min-height: 36px;
        outline: none;
        padding: 2px 25px 2px 10px;
        position: relative;
    }

    .denali-multiselect__value-container {
        padding: 0% !important;
    }

    & > .denali-multiselect__control--menu-is-open {
        align-items: center;
        background: rgba(1, 110, 255, 0.08) !important;
        border: none !important;
        border-radius: 4px;
        color: #303030;
        display: flex;
        min-height: 36px;
        outline: none;
        padding: 2px 25px 2px 10px;
        position: relative;
    }

    .denali-multiselect__multi-value__label {
        font-size: 1.4rem !important;
        padding: 0 !important;
        padding-left: 7px !important;
        margin: 0;
    }

    /* tag remove icon */
    .denali-multiselect__multi-value__remove {
        content: "";
        height: 20px;
        width: 20px;
        background-image: url("/static/close.svg");
        background-repeat: no-repeat;
        background-size: 14px;
        margin-top: 6px;
        margin-left: 5px;
    }

    .denali-multiselect__multi-value__remove > svg {
        display: none;
    }

    .denali-multiselect__multi-value__remove:hover {
        background-color: transparent !important;
        cursor: pointer;
    }

    /* drop down arrowhead */
    .denali-multiselect__dropdown-indicator {
        content: "";
        right: 10px;
    }
    
    /* clear all indicator try after or before and try hiding svg*/
    .denali-multiselect__clear-indicator > svg {
        display: none;
    }

    .denali-multiselect__clear-indicator:before {
        content: "Clear all";
    }

    .denali-multiselect__clear-indicator {
        display: block;
        color: #016eff !important;
        text-decoration: none;
        font-size: inherit;
        cursor: pointer;
    }

    .denali-multiselect__clear-indicator:hover {
        color: #004cb3 !important;
    }

    .denali-multiselect__menu-list {
        padding: 0 !important;
        font-size: 1.4rem;
        font-family: Helvetica, "Arial", sans-serif;
    }

    .denali-multiselect__control {
        align-items: center;
        background: rgba(1, 110, 255, 0.08) !important;
        border: none !important;
        border-radius: 4px;
        box-shadow: none;
        color: #303030;
        display: flex;
        min-height: 36px;
        outline: none;
        padding: 2px 25px 2px 10px;
        position: relative;
    }

    .denali-multiselect__indicator-separator {
        display: none !important;
    }

    .denali-multiselect__multi-value {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        padding: 0px 10px;
        height: 28px;
        margin: 3px;
        background-color: #CCE2FF !important;
        color: #303030;
        border-radius: 9999px !important;
        white-space: nowrap;
        transition: 300ms;
        font-size: 1.2rem;
        font-family: Helvetica, "Arial", sans-serif;
        height: 22px;
        padding: 0px 8px;
    }

    .denali-multiselect__multi-value__remove {
        padding: 0 !important;
    }

    .denali-multiselect__multi-value__remove :hover {
        background-color: #cce2ff !important;
        color: #3d4042 !important;
        cursor: pointer;
    }
`;

class MultiSelect extends React.PureComponent {
    render() {
        const {
            name,
            closeMenuOnSelect,
            isClearable,
            isSearchable,
            options,
            selectedValues,
            onChange,
            disabled,
            placeholder
        } = this.props;

        let cssMultiSelect = makeCssMultiSelect();
        const classes = cx(cssMultiSelect, 'denali-multiselect');

        const authorityFilters = selectedValues.split(',').map(filter => {
            return {
                label: filter,
                value: filter,
            }
        });

        return (
            <div data-testid="denali-multiselect">
                <Select
                    defaultValue={selectedValues && authorityFilters}
                    className={classes}
                    isMulti
                    name={name}
                    options={options.map(option => {
                        return {
                            label: option.value,
                            value: option.name
                        }
                    })}
                    classNamePrefix="denali-multiselect"
                    closeMenuOnSelect={closeMenuOnSelect}
                    isClearable={isClearable}
                    isSearchable={isSearchable}
                    onChange={onChange}
                    isDisabled={disabled}
                    placeholder={placeholder}
                />
            </div>
        );
    }
}

MultiSelect.propTypes = {
    name: PropTypes.string,
    options: PropTypes.arrayOf(
        PropTypes.shape({
            label: PropTypes.string,
            value: PropTypes.string,
        })
    ).isRequired,
    closeMenuOnSelect: PropTypes.bool,
    isClearable: PropTypes.bool,
    isSearchable: PropTypes.bool,
};

export default MultiSelect;
