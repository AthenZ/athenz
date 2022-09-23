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
import { css, cx } from '@emotion/css';
import PropTypes from 'prop-types';
const { v4: uuid } = require('uuid');

const makeCssLoader = (props) => css`
    display: inline-block;
    height: ${props.size};
    vertical-align: ${props.verticalAlign};
    width: ${props.size};
    label: loader;
`;

/**
 * Loading animation SVG component
 */
class Loader extends React.PureComponent {
    render() {
        const { className, color, size, verticalAlign } = this.props;

        const cssProps = { color, size, verticalAlign };
        const cssLoader = makeCssLoader(cssProps);

        // This SVG relies on IDs to animate. However, IDs must be globally unique
        // within the document, so if there are multiple loaders on the page, things
        // may go awry. Use uuid() to generate a random ID.
        // NOTE: SVG IDs cannot have dashes.
        const idBase = uuid().replace(/-/g, '_');

        return (
            <svg
                viewBox='-4 -4 58 58'
                className={cx(cssLoader, 'denali-loader', className)}
            >
                <g>
                    <path
                        d='M25 0a25 25 0 0 0 0 50'
                        fill='none'
                        stroke={color}
                        strokeDasharray={79}
                        strokeLinecap='round'
                        strokeWidth={4}
                    >
                        <animate
                            id={`${idBase}_b`}
                            attributeType='XML'
                            attributeName='stroke-dashoffset'
                            from={9}
                            to={76}
                            dur='750ms'
                            begin={`0s; ${idBase}_a.end`}
                            fill='freeze'
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                        <animate
                            id={`${idBase}_a`}
                            attributeType='XML'
                            attributeName='stroke-dashoffset'
                            from={76}
                            to={9}
                            dur='750ms'
                            begin={`${idBase}_b.end`}
                            fill='freeze'
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                        <animate
                            id={`${idBase}_d`}
                            attributeType='XML'
                            attributeName='stroke-width'
                            from={4}
                            to={8}
                            dur='750ms'
                            begin={`0s; ${idBase}_c.end`}
                            fill='freeze'
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                        <animate
                            id={`${idBase}_c`}
                            attributeType='XML'
                            attributeName='stroke-width'
                            from={8}
                            to={4}
                            dur='750ms'
                            begin={`${idBase}_d.end`}
                            fill='freeze'
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                        <animateTransform
                            id={`${idBase}_f`}
                            attributeType='XML'
                            attributeName='transform'
                            type='rotate'
                            from='0 25 25'
                            to='0 25 25'
                            dur='750ms'
                            begin={`0s; ${idBase}_e.end`}
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                        <animateTransform
                            id={`${idBase}_g`}
                            attributeType='XML'
                            attributeName='transform'
                            type='rotate'
                            from='0 25 25'
                            to='180 25 25'
                            dur='750ms'
                            begin={`${idBase}_f.end`}
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                        <animateTransform
                            id={`${idBase}_h`}
                            attributeType='XML'
                            attributeName='transform'
                            type='rotate'
                            from='180 25 25'
                            to='180 25 25'
                            dur='750ms'
                            begin={`${idBase}_g.end`}
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                        <animateTransform
                            id={`${idBase}_e`}
                            attributeType='XML'
                            attributeName='transform'
                            type='rotate'
                            from='180 25 25'
                            to='360 25 25'
                            dur='750ms'
                            begin={`${idBase}_h.end`}
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                        <animate
                            id={`${idBase}_j`}
                            attributeType='XML'
                            attributeName='opacity'
                            from={0.7}
                            to={1}
                            dur='750ms'
                            begin={`0s; ${idBase}_i.end`}
                            fill='freeze'
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                        <animate
                            id={`${idBase}_i`}
                            attributeType='XML'
                            attributeName='opacity'
                            from={1}
                            to={0.7}
                            dur='750ms'
                            begin={`${idBase}_j.end`}
                            fill='freeze'
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                    </path>
                    <path
                        d='M25 50a25 25 0 1 0 0-50'
                        fill='none'
                        stroke={color}
                        strokeLinecap='round'
                        strokeDasharray={79}
                        strokeWidth={4}
                    >
                        <animate
                            attributeType='XML'
                            attributeName='stroke-dashoffset'
                            from={9}
                            to={76}
                            dur='750ms'
                            begin={`0s; ${idBase}_a.end`}
                            fill='freeze'
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                        <animate
                            attributeType='XML'
                            attributeName='stroke-dashoffset'
                            from={76}
                            to={9}
                            dur='750ms'
                            begin={`${idBase}_b.end`}
                            fill='freeze'
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                        <animate
                            attributeType='XML'
                            attributeName='stroke-width'
                            from={4}
                            to={8}
                            dur='750ms'
                            begin={`0s; ${idBase}_c.end`}
                            fill='freeze'
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                        <animate
                            attributeType='XML'
                            attributeName='stroke-width'
                            from={8}
                            to={4}
                            dur='750ms'
                            begin={`${idBase}_d.end`}
                            fill='freeze'
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                        <animateTransform
                            attributeType='XML'
                            attributeName='transform'
                            type='rotate'
                            from='0 25 25'
                            to='0 25 25'
                            dur='750ms'
                            begin={`0s; ${idBase}_e.end`}
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                        <animateTransform
                            attributeType='XML'
                            attributeName='transform'
                            type='rotate'
                            from='0 25 25'
                            to='180 25 25'
                            dur='750ms'
                            begin={`${idBase}_f.end`}
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                        <animateTransform
                            attributeType='XML'
                            attributeName='transform'
                            type='rotate'
                            from='180 25 25'
                            to='180 25 25'
                            dur='750ms'
                            begin={`${idBase}_g.end`}
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                        <animateTransform
                            attributeType='XML'
                            attributeName='transform'
                            type='rotate'
                            from='180 25 25'
                            to='360 25 25'
                            dur='750ms'
                            begin={`${idBase}_h.end`}
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                        <animate
                            attributeType='XML'
                            attributeName='opacity'
                            from={0.7}
                            to={1}
                            dur='750ms'
                            begin={`0s; ${idBase}_i.end`}
                            fill='freeze'
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                        <animate
                            attributeType='XML'
                            attributeName='opacity'
                            from={1}
                            to={0.7}
                            dur='750ms'
                            begin={`${idBase}_j.end`}
                            fill='freeze'
                            calcMode='spline'
                            keyTimes='0;1'
                            keySplines='0.215, 0.61, 0.355, 1'
                        />
                    </path>
                    {/* Rotate the entire circle */}
                    <animateTransform
                        attributeType='XML'
                        attributeName='transform'
                        type='rotate'
                        from='0 25 25'
                        to='360 25 25'
                        dur='6750ms'
                        repeatCount='indefinite'
                    />
                </g>
            </svg>
        );
    }
}

Loader.propTypes = {
    /** Additonal class to apply to the svg */
    className: PropTypes.string,
    /** Any valid CSS width/height value */
    size: PropTypes.string,
    /** Any valid CSS color value */
    color: PropTypes.string,
    /** Set `vertical-align` CSS property */
    verticalAlign: PropTypes.string,
};

Loader.defaultProps = {
    size: '24px',
    color: '#3570f4',
    verticalAlign: 'text-bottom',
};

export default Loader;
