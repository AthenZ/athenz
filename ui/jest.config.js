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
module.exports = {
    collectCoverage: true,
    collectCoverageFrom: ['./src/**/*{js,jsx}'],
    // Different location when using SDv4
    coverageDirectory: 'artifacts/coverage',
    coveragePathIgnorePatterns: [
        '.next',
        'node_modules',
        '_document.js',
        '__tests__',
    ],
    coverageReporters: ['text', 'text-summary', 'lcov'],
    globalSetup: './src/global-jest-setup.js',
    moduleDirectories: ['node_modules'],
    reporters: ['default', 'jest-junit'],
    setupFilesAfterEnv: [
        '@testing-library/jest-dom',
        '<rootDir>/src/setup-jest-test-framework.js',
    ],
    testEnvironmentOptions: {
        url: 'http://localhost/',
    },
    testPathIgnorePatterns: [
        './.next/',
        './node_modules/',
        './src/__tests__/spec/',
    ],
    transform: {
        '^.+\\.js$': ['babel-jest', { presets: ['next/babel'] }],
    },
    moduleNameMapper: {
        '\\.(css|less)$': 'identity-obj-proxy',
    },
    testEnvironment: 'jsdom',
    snapshotSerializers: ['@emotion/jest/serializer'],
};
