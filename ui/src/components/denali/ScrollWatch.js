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
import _throttle from 'lodash/throttle';

// Amount of scroll (pixels) from top before triggering state change
const SCROLL_THRESHOLD = 5;
// Throttle in milliseconds
const SCROLL_THROTTLE_MS = 200;

/**
 * A [render prop](https://reactjs.org/docs/render-props.html#use-render-props-for-cross-cutting-concerns)
 * component to provide handlers & trackers for scrolling within a child
 * element. ScrollWatch exposes four props to the render function (from here,
 * the element that you want to track scrolling will be called "`scroller`"):
 *
 * - `handleScroll`: attach this the scroller's `onScroll` event handler
 * - `scrolled`: Boolean value on whether scroller is scrolled.
 * - `scrolledToBottom`: Boolean if scroller's scroll position is at the bottom.
 * - `scrollRef`: Optionally attach this to the scroller's `ref` prop. This will
 *   allow ScrollWatch to detect whether the entire contents of scroller fits
 *   within the div (ie, no scrolling necessary).
 */
class ScrollWatch extends React.Component {
    state = {
        scrolled: false,
        scrolledToBottom: this.props.watchScrolledToBottom ? false : null,
    };

    // Optionally attach ref to scrolling element. This will allow this component
    // to check whether there is no scroll necessary (ie, the scrollable element
    // fits entirely on-screen), thus scrolledToBottom = true
    // TODO: See if there's a way to attach a handler directly to this ref so we
    // can combine scrollRef and handleScroll into one (ie, only one render prop
    // to handle both)
    scrollRef = React.createRef();

    // How to throttle/debounce in React:
    // https://stackoverflow.com/questions/23123138/perform-debounce-in-react-js/24679479#24679479
    throttledScroll = _throttle(({ scrollTop, clientHeight, scrollHeight }) => {
        if (this.props.watchScrolledToBottom) {
            // Detect if we've scrolled to bottom of container. Modified from:
            // https://stackoverflow.com/questions/9439725/javascript-how-to-detect-if-browser-window-is-scrolled-to-bottom
            const scrolledToBottom =
                Math.ceil(scrollTop + clientHeight) >= scrollHeight;

            // It's okay to setState multiple times
            if (this.state.scrolledToBottom !== scrolledToBottom) {
                this.setState({ scrolledToBottom });
            }
        }

        // Instead of updating the state everytime, which can get expensive for
        // onScroll, update only when the state actually flips.
        if (scrollTop > SCROLL_THRESHOLD && !this.state.scrolled) {
            this.setState({ scrolled: true });
        } else if (scrollTop < SCROLL_THRESHOLD && this.state.scrolled) {
            this.setState({ scrolled: false });
        }
    }, SCROLL_THROTTLE_MS);

    // React uses synthetic events. To access it asynchronously, as in the case
    // of throttling, normally, event.persist() needs to be used. However,
    // instead of sending the event itself into the throttled function, send
    // only the values we need.
    handleScroll = (event) =>
        this.throttledScroll({
            clientHeight: event.target.clientHeight,
            scrollHeight: event.target.scrollHeight,
            scrollTop: event.target.scrollTop,
        });

    initialSizeCheck = (ele) => {
        if (ele.scrollHeight === ele.clientHeight) {
            this.setState({ scrolledToBottom: true });
        }
    };

    componentDidMount() {
        if (this.scrollRef.current && this.props.watchScrolledToBottom) {
            this.initialSizeCheck(this.scrollRef.current);
        }
    }

    render() {
        const childProps = {
            handleScroll: this.handleScroll,
            scrolled: this.state.scrolled,
            scrolledToBottom: this.state.scrolledToBottom,
            scrollRef: this.scrollRef,
        };
        const renderedChildren = this.props.children(childProps);

        return renderedChildren && React.Children.only(renderedChildren);
    }
}

ScrollWatch.propTypes = {
    /** Since ScrollWatch uses render props, children must be a function */
    children: PropTypes.func.isRequired,
    /** By default, ScrollWatch does not listen for scrolling to the bottom */
    watchScrolledToBottom: PropTypes.bool,
};

ScrollWatch.defaultProps = {
    watchScrolledToBottom: false,
};

export default ScrollWatch;
