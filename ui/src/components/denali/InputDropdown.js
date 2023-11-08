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
import ReactDOM from 'react-dom';
import PropTypes from 'prop-types';
import Downshift from 'downshift';
import { Manager, Popper, Reference } from 'react-popper';
import _ from 'lodash';
import Input from './Input';
import Icon from './icons/Icon';
import { cssDropShadow } from './styles/drop-shadow';
import { colors } from './styles/colors';
import { cssFontStyles, cssFontWeights } from './styles/fonts';
import { cssLink } from './styles/link';
import { css, cx, keyframes } from '@emotion/css';
import { rgba } from 'polished';

const DEBOUNCE_MS = 300;
const MIN_SEARCH_LENGTH = 2;

const makeCssInputDropdown = (props) => css`
    position: relative;
    width: ${props.fluid ? '100%' : undefined};
    label: input-dropdown;
    & input {
        cursor: ${props.filterable || props.asyncSearchFunc
            ? 'inherit'
            : 'pointer'};
    }
`;

const fadeIn = keyframes`
    from { opacity: 0 }
    to { opacity: 1 }
`;

const cssMenuDropdown = (props) => css`
    ${cssDropShadow};
    ${cssFontStyles.default};
    background-color: ${colors.white};
    border: 2px solid ${colors.grey400};
    border-radius: 4px;
    box-sizing: border-box;
    color: ${colors.black};
    line-height: 1.2;
    margin: 2px 0;
    opacity: 1;
    overflow: auto;
    width: ${props.valuesWidth ? props.valuesWidth : undefined};
    overscroll-behavior: contain; /* Not supported on Safari :( */
    z-index: 100000; /* Make sure this is higher than <Modal> */
    label: input-dropdown-options;
    &.animated {
        animation: ${fadeIn} 0.2s ease-in forwards;
        opacity: 0;
    }
    & > .dropdown-item {
        ${cssLink};
        cursor: pointer;
        padding: 10px;
        & svg {
            margin-bottom: -1px;
        }
    }
    & > .selected,
    & > .selected.highlighted {
        color: ${colors.black};
        ${cssFontWeights.bold};
    }
    & > .highlighted {
        background-color: ${rgba(colors.brand700, 0.05)};
    }
    & > .no-items {
        font-style: italic;
        padding: 5px 10px;
    }
    & > .error {
        color: ${colors.statusDanger};
    }
`;

/**
 * Escape for regular expression
 * Taken from: https://stackoverflow.com/a/2593661
 */
const regExpEscape = (s) => (s + '').replace(/[.?*+^$[\]\\(){}|-]/g, '\\$&');

/** Popper modifier to make sure dropdown is at least as wide as trigger */
const widthMod = {
    enabled: true,
    fn: (data) => {
        data.styles.minWidth = data.offsets.reference.width;
        return data;
    },
};

/**
 * This dropdown component has three distinct usage modes:
 *
 * 1. Basic dropdown - User clicks the input field and selects one of the
 *    pre-populated options.
 * 2. Filterable dropdown - Similar to 1., but with the added functionality of
 *    being able to type in the input field to filter the options.
 * 3. Search - An asynchronous function can be passed in which will serve as
 *    the search function based on the current input. The function returns an
 *    array of results to be populated in the dropdown.
 */
class InputDropdown extends React.Component {
    state = {
        isLoading: false,
        error: null,
        results: null,
    };

    getDefaultSelectedItem = () => {
        if (this.props.defaultSelectedItem) {
            return this.props.defaultSelectedItem;
        }
        if (this.props.defaultSelectedValue) {
            return this.props.options.find(
                (o) => o.value === this.props.defaultSelectedValue
            );
        }
        if (this.props.defaultSelectedName) {
            return this.props.options.find(
                (o) => o.name === this.props.defaultSelectedName
            );
        }
    };

    getOptions = (inputValue) => {
        if (this.props.asyncSearchFunc) {
            return this.state.results;
        }
        if (!this.props.filterable || !inputValue) {
            return this.props.options;
        }
        const sanitized = regExpEscape(inputValue);
        const regexp = new RegExp(sanitized, 'i');

        return this.props.options.filter((o) => o.name.search(regexp) > -1);
    };

    /**
     * If `asyncSearchFunc` is defined, then this function is called upon
     * input onChange. See the `asyncSearchFunc` prop description below for
     * expected output.
     */
    loadSearchResults = _.debounce(
        async (searchTerm) => {
            try {
                this.setState({ isLoading: true, error: null });
                const results = await this.props.asyncSearchFunc(searchTerm);
                if (!results) {
                    // Assume async function was cancelled, so don't set results
                    this.setState({ isLoading: false });
                } else {
                    this.setState({ isLoading: false, results });
                }
            } catch (error) {
                this.setState({ isLoading: false, error });
            }
        },
        DEBOUNCE_MS,
        { leading: true }
    );

    onInputChange = (e) => {
        if (
            this.props.asyncSearchFunc &&
            e.target.value.length >= MIN_SEARCH_LENGTH
        ) {
            this.loadSearchResults(e.target.value);
        } else {
            this.setState({ results: null });
        }
    };

    /**
     * Add icons within the <Input> field
     */
    renderIcons =
        ({
            clearSelection,
            isOpen,
            showArrow,
            showClose,
            toggleMenu,
            disabled,
        }) =>
        ({ sizePx }) => {
            return (
                <React.Fragment>
                    {showClose && (
                        <Icon
                            icon={'close-circle'}
                            className='clear-selection'
                            color={colors.grey500}
                            colorHover={
                                !disabled ? colors.grey600 : colors.grey500
                            }
                            isLink={!disabled}
                            size='16px'
                            onClick={() => {
                                if (!disabled) {
                                    this.setState({ results: null });
                                    clearSelection();
                                }
                            }}
                        />
                    )}
                    {showArrow &&
                        (isOpen ? (
                            <Icon
                                icon='arrowhead-up'
                                color={colors.grey500}
                                colorHover={
                                    !disabled ? colors.grey600 : colors.grey500
                                }
                                isLink={!disabled}
                                size={sizePx}
                                onClick={!disabled ? toggleMenu : undefined}
                            />
                        ) : (
                            <Icon
                                icon='arrowhead-down'
                                color={colors.grey500}
                                colorHover={
                                    !disabled ? colors.grey600 : colors.grey500
                                }
                                isLink={!disabled}
                                size={sizePx}
                                onClick={!disabled ? toggleMenu : undefined}
                            />
                        ))}
                </React.Fragment>
            );
        };

    /**
     * Render the dropdown menu with options
     */
    renderMenu = (options) => {
        const classes = cx(
            cssMenuDropdown(this.props),
            { animated: !options.noanim },
            'denali-input-dropdown-options'
        );
        const menuOptions = this.getOptions(options.inputValue);
        let markup;

        if (this.state.error) {
            // API error
            markup = (
                <div className='no-items error'>
                    Error loading results. Please try again later.
                </div>
            );
        } else if (menuOptions === null || this.state.isLoading) {
            // Loading state - Unless React Suspense is in place, show loading if
            // there is no data already loaded or loading is in progress. (NOTE: due
            // to cancellation, there can be a render cycle where isLoading is false
            // and there is no data loaded yet)
            markup = <div className='no-items loading'>Loading...</div>;
        } else if (!menuOptions || !menuOptions.length) {
            // TODO: Validate we need to check for both
            markup = (
                <div className='no-items empty'>
                    {this.props.noOptionsMessage}
                </div>
            );
        } else {
            markup = (
                <React.Fragment>
                    {menuOptions.map((item, index) => (
                        <div
                            key={item.value}
                            {...options.getItemProps({
                                className: cx('dropdown-item', {
                                    highlighted:
                                        options.highlightedIndex === index,
                                    selected:
                                        options.selectedItem &&
                                        options.selectedItem.value ===
                                            item.value,
                                }),
                                index,
                                item,
                            })}
                        >
                            {item.name}
                        </div>
                    ))}
                </React.Fragment>
            );
        }

        return (
            <div
                {...options.getMenuProps({
                    className: classes,
                    'data-placement': options.placement,
                    ref: options.ref,
                    style: {
                        ...options.style,
                        maxHeight: `${options.maxHeight}px`,
                    },
                    onScroll: (e) => e.stopPropagation(),
                })}
            >
                {markup}
            </div>
        );
    };

    render() {
        const classes = cx(
            makeCssInputDropdown(this.props),
            'denali-input-dropdown',
            this.props.className
        );

        const defaultSelectedItem = this.getDefaultSelectedItem();

        return (
            <Manager>
                <Downshift
                    initialSelectedItem={defaultSelectedItem}
                    inputValue={this.props.value}
                    itemToString={this.props.itemToString}
                    onChange={(selected) => this.props.onChange(selected)}
                >
                    {({
                        clearSelection,
                        getInputProps,
                        getItemProps,
                        getMenuProps,
                        highlightedIndex,
                        inputValue,
                        isOpen,
                        selectedItem,
                        toggleMenu,
                    }) => (
                        <div className={classes} data-testid='input-dropdown'>
                            <Reference>
                                {({ ref }) => (
                                    <Input
                                        {...getInputProps({
                                            autoComplete: 'off',
                                            autoCorrect: 'off',
                                            disabled: this.props.disabled,
                                            error: this.props.error,
                                            fluid: this.props.fluid,
                                            focused: isOpen,
                                            innerRef: ref,
                                            message: this.props.message,
                                            name: this.props.name,
                                            noanim: this.props.noanim,
                                            placeholder: this.props.placeholder,
                                            readOnly: Boolean(
                                                !this.props.asyncSearchFunc &&
                                                    !this.props.filterable
                                            ),
                                            renderIcon: this.renderIcons({
                                                showClose:
                                                    inputValue &&
                                                    !this.props.noclear,
                                                showArrow: Boolean(
                                                    !this.props.asyncSearchFunc
                                                ),
                                                isOpen,
                                                toggleMenu,
                                                clearSelection,
                                                disabled: this.props.disabled,
                                            }),
                                            spellCheck: false,
                                            onBlur: this.props.onBlur,
                                            onChange: this.onInputChange,
                                            onClick: toggleMenu,
                                            onFocus: this.props.onFocus,
                                        })}
                                    />
                                )}
                            </Reference>
                            {isOpen &&
                                (!this.props.asyncSearchFunc ||
                                    inputValue.length >= MIN_SEARCH_LENGTH) &&
                                ReactDOM.createPortal(
                                    <Popper
                                        placement='bottom-start'
                                        modifiers={{
                                            arrow: { enabled: false },
                                            flip: { enabled: false },
                                            hide: { enabled: false },
                                            preventOverflow: { enabled: false },
                                            widthMod,
                                        }}
                                    >
                                        {({ ref, style, placement }) =>
                                            this.renderMenu({
                                                getItemProps,
                                                getMenuProps,
                                                highlightedIndex,
                                                inputValue,
                                                maxHeight: this.props.maxHeight,
                                                noanim: this.props.noanim,
                                                placement,
                                                ref,
                                                selectedItem,
                                                style,
                                            })
                                        }
                                    </Popper>,
                                    document.body
                                )}
                        </div>
                    )}
                </Downshift>
            </Manager>
        );
    }
}

InputDropdown.propTypes = {
    /**
     * Instead of passing in an `options` array, an async function or Promise
     * can be used to retrieve the list of options asynchronously. This function
     * is expected to return a data structure similar to `options`, or an error
     * object if the operation fails. If no results are found, an empty array
     * should be returned. If the asynchronous operation was cancelled, the
     * function should return null or undefined.
     *
     * NOTE: If `asyncSearchFunc` is used, then `options` will be ignored.
     */
    asyncSearchFunc: PropTypes.func,
    /** Additonal class to apply to the outer div of the input dropdown */
    className: PropTypes.string,
    /**
     * Default selected item. This has higher priority over both
     * defaultSelectedName & defaultSelectedValue.
     *
     * NOTE: This prop is ignored if `asyncSearchFunc` is used.
     */
    defaultSelectedItem: PropTypes.shape({
        name: PropTypes.string.isRequired,
        value: PropTypes.any.isRequired,
    }),
    /**
     * Default selected item by name. This has lower priority than both
     * defaultSelectedItem & defaultSelectedValue.
     *
     * NOTE: This prop is ignored if `asyncSearchFunc` is used.
     */
    defaultSelectedName: PropTypes.string,
    /**
     * Default selected item by value. This has higher priority over
     * defaultSelectedName but lower priority than getDefaultSelectedItem.
     *
     * NOTE: This prop is ignored if `asyncSearchFunc` is used.
     */
    defaultSelectedValue: PropTypes.any,
    /** Dropdown disabled (one use case: while form is submitting) */
    disabled: PropTypes.bool,
    /** Toggle error state */
    error: PropTypes.bool,
    /**
     * Flag to allow typing in the input box to narrow down menu options.
     *
     * NOTE: This prop is ignored if `asyncSearchFunc` is used.
     */
    filterable: PropTypes.bool,
    /** Dropdown takes full width of parent element */
    fluid: PropTypes.bool,
    /** Max height of dropdown */
    maxHeight: PropTypes.number,
    /** Disable a message under the text field */
    message: PropTypes.string,
    /** Name for `<input>` */
    name: PropTypes.string.isRequired,
    /** Disable animations / transitions */
    noanim: PropTypes.bool,
    /** Disable option to clear selection */
    noclear: PropTypes.bool,
    /** Message to display when there are no options */
    noOptionsMessage: PropTypes.string,
    /**
     * Array of options
     */
    options: PropTypes.arrayOf(
        PropTypes.shape({
            name: PropTypes.string.isRequired,
            value: PropTypes.any.isRequired,
        })
    ),
    /** Input placeholder */
    placeholder: PropTypes.string,
    /** BETA: (Control Prop) value */
    value: PropTypes.string,
    /** Handler for `<input>` onBlur event */
    onBlur: PropTypes.func,
    /** Function called when user selects an option */
    onChange: PropTypes.func.isRequired,
    /** Handler for `<input>` onFocus event */
    onFocus: PropTypes.func,
    /** The itemToString function for getting the string value from one of the options */
    itemToString: PropTypes.func,
};

InputDropdown.defaultProps = {
    disabled: false,
    error: false,
    filterable: false,
    fluid: false,
    maxHeight: 400,
    noanim: false,
    noclear: false,
    noOptionsMessage: 'No items found',
    /**
     * Used by Downshift to determine string value of an item
     */
    itemToString: (i) => (i === null ? '' : i.name),
};

export default InputDropdown;
