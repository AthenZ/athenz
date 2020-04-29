/*
 * Copyright 2020 Verizon Media
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
// Add some helpful assertions for `react-testing-library`
import '@testing-library/jest-dom/extend-expect';
import * as emotion from 'emotion';
import { createSerializer } from 'jest-emotion';
import jsdom from 'jsdom';

const dom = new jsdom.JSDOM('<!doctype html><html><body></body></html>');

// Need to manually polyfill MutationObserver for 'react-popper-library':
// https://github.com/kentcdodds/react-testing-library/issues/141#issuecomment-406317195
global.window = dom.window;
global.document = dom.window.document;
global.navigator = dom.window.navigator;

// new lines
global.Node = dom.window.Node;
require('mutationobserver-shim');
global.MutationObserver = global.window.MutationObserver;

// Add emotion support
// https://github.com/emotion-js/emotion/blob/master/docs/testing.md
// NOTE: To extend 'expect', this must be used under jest's
// 'setupTestFrameworkScriptFile', as explained here:
// https://github.com/FormidableLabs/enzyme-matchers/issues/96
expect.addSnapshotSerializer(createSerializer(emotion));

process.env.APP_ENV = 'unittest';
