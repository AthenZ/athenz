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
import ReactModal from 'react-modal';
import Icon from '../denali/icons/Icon';
import {
    colors,
    cssDropShadow,
    cssFontStyles,
    cssFontWeights,
} from '../denali/styles';
import { css, cx } from '@emotion/css';
import { rgba } from 'polished';

const TYPE_COLOR_MAP = {
    danger: 'statusDanger',
    info: 'statusInfo',
    success: 'statusSuccess',
    warning: 'statusWarning',
};

const TYPE_ICON_MAP = {
    danger: 'stop-warning',
    info: 'information-circle',
    success: 'check-circle',
    warning: 'warning',
};

// http://reactcommunity.org/react-modal/examples/set_app_element.html
ReactModal.setAppElement('body');

const modalOverlayClass = css`
    background-color: transparent;
    bottom: 0;
    left: 0;
    position: fixed;
    right: 0;
    top: 0;
    z-index: 5;
    label: modal-overlay;
`;

const makeAlertClass = (props) => css`
    ${cssDropShadow};
    align-items: flex-start;
    background: ${colors.white};
    border-radius: 4px;
    border-top: 4px solid ${colors[TYPE_COLOR_MAP[props.type]]};
    box-sizing: border-box;
    color: ${colors.black};
    display: flex;
    flex-flow: row nowrap;
    ${cssFontStyles.default};
    left: 50%;
    max-height: calc(100vh - 160px);
    min-width: 400px;
    outline: none;
    position: fixed;
    transform: translate(-50%, 0);
    width: 400px;
    label: alert;
    &.ReactModal__Content {
        opacity: 0;
        top: 0;
    }
    &.animated {
        transition: opacity 0.2s ease-out,
            top 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    }
    &.ReactModal__Content--after-open {
        top: 80px;
        opacity: 1;
    }
    /* Animate fade out on close. This is currently not used as tests fail */
    &.ReactModal__Content--before-close {
        opacity: 0;
    }
    & .left-section {
        flex: 0 0 28px;
        padding: 14px;
        & .alert-icon {
            align-items: flex-start;
            display: flex;
            justify-content: center;
        }
    }
    & .right-section {
        display: flex;
        flex: 1 1 auto;
        flex-flow: column nowrap;
        & .title-row {
            align-items: center;
            display: flex;
            flex-flow: row nowrap;
            height: initial;
            justify-content: space-between;
            padding: 14px 14px 14px 0;
            & .title {
                ${cssFontWeights.bold};
            }
        }
        & .description {
            font-size: 14px;
            font-weight: 300;
            padding: 0 14px 14px 0;
        }
    }
`;

/**
 * Alert displays a dismissable modal near the top of the screen. It is meant to
 * show a short blurb of information. There are four
 * alert types:
 *
 * 1. Info
 * 2. Success
 * 3. Warning
 * 4. Danger
 *
 * Under the hood, Alert uses [`react-modal`](http://reactcommunity.org/react-modal/).
 * To prevent the page from scrolling when the modal is showing, add the
 * following to the app's global CSS:
 *
 * ```css
 * .ReactModal__Body--open {
 *   overflow: hidden;
 * }
 */
class Alert extends React.Component {
    // Taken from:
    // https://stackoverflow.com/questions/45678517/better-way-to-cleartimeout-in-componentwillunmount
    setTimer = (ms) => {
        // Remember the timer handle
        this.timerHandle = setTimeout(() => {
            this.timerHandle = null;
            this.props.onClose();
        }, ms);
    };

    clearTimer = () => {
        // Is our timer running?
        if (this.timerHandle) {
            clearTimeout(this.timerHandle);
            this.timerHandle = null;
        }
    };

    componentDidMount() {
        if (this.props.isOpen && this.props.duration) {
            this.setTimer(this.props.duration);
        }
    }

    componentDidUpdate(prevProps) {
        if (!prevProps.isOpen && this.props.isOpen && this.props.duration) {
            this.setTimer(this.props.duration);
        } else if (prevProps.isOpen && !this.props.isOpen) {
            this.clearTimer();
        }
    }

    componentWillUnmount() {
        this.clearTimer();
    }

    render() {
        const StatusIcon = TYPE_ICON_MAP[this.props.type];
        const alertClass = makeAlertClass(this.props);

        return (
            <ReactModal
                aria={{
                    labelledby: 'alert-title',
                    describedby: 'alert-description',
                }}
                className={cx(
                    alertClass,
                    'denali-alert',
                    `denali-alert-${this.props.type}`,
                    {
                        animated: !this.props.noanim,
                    },
                    this.props.className
                )}
                closeTimeoutMS={200}
                descriptionLabel={`${this.props.type} alert`}
                isOpen={this.props.isOpen}
                overlayClassName={modalOverlayClass}
                shouldCloseOnOverlayClick={false}
                onRequestClose={this.props.onClose}
            >
                <div className='left-section'>
                    <div className='alert-icon' data-testid='alert-icon'>
                        <Icon
                            icon={'check-circle'}
                            color={colors[TYPE_COLOR_MAP[this.props.type]]}
                            decorative={true}
                            size='28px'
                            verticalAlign='middle'
                        />
                    </div>
                </div>
                <div className='right-section'>
                    <div className='title-row'>
                        <div
                            className='title'
                            id='alert-title'
                            data-testid='alert-title'
                        >
                            {this.props.title}
                        </div>
                        <div
                            className='close-button'
                            onClick={this.props.onClose}
                        >
                            <Icon
                                color={rgba(colors.grey800, 0.4)}
                                colorHover={rgba(colors.grey800, 0.6)}
                                isLink
                                size='28px'
                                icon={'close'}
                            />
                        </div>
                    </div>
                    {this.props.description && (
                        <div
                            className='description'
                            id='alert-description'
                            data-testid='alert-description'
                        >
                            {this.props.description}
                        </div>
                    )}
                </div>
            </ReactModal>
        );
    }
}

Alert.propTypes = {
    /** Additonal class to apply to the outer div of the modal content */
    className: PropTypes.string,
    /** Optional description. Can be a string or JSX / component */
    description: PropTypes.any,
    /** Once open, call `onClose()` after N milliseconds */
    duration: PropTypes.number,
    /** Disable animations / transitions */
    noanim: PropTypes.bool,
    /** Toggle the alert on or off */
    isOpen: PropTypes.bool,
    /** Title of the alert */
    title: PropTypes.string.isRequired,
    /** Alert supports four status types */
    type: PropTypes.oneOf(['danger', 'info', 'success', 'warning']),
    /** Handler for closing the alert */
    onClose: PropTypes.func.isRequired,
};

Alert.defaultProps = {
    duration: 0,
    isOpen: false,
    noanim: false,
    type: 'info',
};

export default Alert;
