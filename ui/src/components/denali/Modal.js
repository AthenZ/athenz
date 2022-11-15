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
import ScrollWatch from '../denali/ScrollWatch';
import Icon from '../denali/icons/Icon';
import { css, cx } from '@emotion/css';
import { rgba } from 'polished';
import {
    colors,
    cssDropShadow,
    cssFontStyles,
    cssScrollDropShadowTop,
} from '../denali/styles';

// http://reactcommunity.org/react-modal/examples/set_app_element.html
ReactModal.setAppElement('body');

const modalOverlayClass = css`
    background-color: rgba(0, 0, 0, 0.6);
    bottom: 0;
    left: 0;
    opacity: 0;
    position: fixed;
    right: 0;
    top: 0;
    z-index: 5;
    &.animated {
        transition: all 0.2s ease-out;
    }

    &.ReactModal__Overlay--after-open {
        opacity: 1;
    }

    /* Animate fade out on close. This is currently not used as tests fail */
    &.ReactModal__Overlay--before-close {
        opacity: 0;
    }
`;

const modalContentClass = css`
    ${cssDropShadow};
    background: ${colors.white};
    border: 1px solid ${colors.border};
    border-radius: 4px;
    box-sizing: border-box;
    display: flex;
    flex-flow: column nowrap;
    justify-content: stretch;
    max-height: calc(100vh - 120px);
    max-width: calc(100vw - 120px);
    min-width: 150px;
    left: 50%;
    margin: 0 auto;
    outline: none;
    position: absolute;
    top: 70px;
    transform: translate(-50%, 0);
    label: modal;

    & > .header {
        align-items: center;
        border-bottom: 1px solid ${colors.border};
        box-shadow: none;
        display: flex;
        flex: 0 0 50px;
        flex-flow: row nowrap;
        justify-content: space-between;
        padding: 0 20px;
        position: relative;

        & > .title {
            ${cssFontStyles.title};
        }

        & > .close-button {
            margin-left: 15px;
            margin-right: -5px;
        }

        ::after {
            ${cssScrollDropShadowTop};
            background: transparent;
            bottom: -20px;
            content: '';
            height: 20px;
            left: 0;
            opacity: 0;
            position: absolute;
            right: 0;
            transition: opacity 0.2s ease;
        }

        &.scrolled::after {
            opacity: 1;
        }
    }

    & > .content {
        flex: 1 1 auto;
        //font-size: 0.8571rem;
        overflow: auto;
        padding: 20px;
    }
`;

/**
 * Modal uses [`react-modal`](http://reactcommunity.org/react-modal/) under the
 * hood. To prevent the page from scrolling when the modal is showing, add the
 * following to the app's global CSS:
 *
 * ```css
 * .ReactModal__Body--open {
 *   overflow: hidden;
 * }
 */
export const Modal = (props) => (
    <ReactModal
        aria={{
            labelledby: 'modal-title',
            describedby: 'modal-content',
        }}
        className={cx(modalContentClass, 'denali-modal', props.className)}
        closeTimeoutMS={200}
        contentLabel='Modal'
        contentRef={props.contentRef}
        isOpen={props.isOpen}
        overlayClassName={cx(
            modalOverlayClass,
            {
                animated: !props.noanim,
            },
            'react-modal-overlay'
        )}
        overlayRef={props.overlayRef}
        onRequestClose={props.onClose}
        shouldCloseOnOverlayClick={props.shouldCloseOnOverlayClick}
    >
        <ScrollWatch>
            {({ scrollRef, scrolled, handleScroll }) => {
                const headerClass = `header${scrolled ? ' scrolled' : ''}`;
                return (
                    <React.Fragment>
                        <header
                            className={headerClass}
                            data-testid='modal-header'
                        >
                            <div
                                className={
                                    typeof props.title === 'string'
                                        ? 'title'
                                        : undefined
                                }
                                id='modal-title'
                                data-testid='modal-title'
                            >
                                {props.title}
                            </div>
                            <div
                                className='close-button'
                                onClick={props.onClose}
                            >
                                <Icon
                                    color={colors.grey800}
                                    isLink
                                    size='28px'
                                />
                            </div>
                        </header>
                        <div
                            className='content'
                            id='modal-content'
                            ref={scrollRef}
                            onScroll={handleScroll}
                            data-testid='modal-content'
                        >
                            {props.children}
                        </div>
                    </React.Fragment>
                );
            }}
        </ScrollWatch>
    </ReactModal>
);

Modal.propTypes = {
    /**
     * Content to render inside modal
     * @ignore
     */
    children: PropTypes.any,
    /** Additonal class to apply to the outer div of the modal content */
    className: PropTypes.string,
    /** Content ref callback */
    contentRef: PropTypes.func,
    /** Modal open/closed state */
    isOpen: PropTypes.bool.isRequired,
    /** Disable animations / transitions */
    noanim: PropTypes.bool,
    /** Overlay ref callback */
    overlayRef: PropTypes.func,
    /** Close modal when clicking outside of it */
    shouldCloseOnOverlayClick: PropTypes.bool,
    /** Modal title */
    title: PropTypes.oneOfType([PropTypes.string, PropTypes.element]),
    /**
     * Handler for closing the modal. Usually, the parent component will set
     * `isOpen` to false
     */
    onClose: PropTypes.func.isRequired,
};

Modal.defaultProps = {
    noanim: false,
    shouldCloseOnOverlayClick: false,
    title: '',
};

export default Modal;
