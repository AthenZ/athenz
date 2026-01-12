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

/**
 * Wait for page to be fully loaded
 * @param {String} url - URL to navigate to (optional, if already on page)
 * @param {Number} timeout - Timeout in ms (default: 30000)
 */
module.exports.waitForPageLoad = async (url = null, timeout = 30000) => {
    if (url) {
        await browser.url(url);
    }

    // Wait for document ready state
    await browser.waitUntil(
        async () => {
            return await browser.execute(() => {
                return document.readyState === 'complete';
            });
        },
        {
            timeout,
            timeoutMsg: `Page did not load within ${timeout}ms`,
        }
    );

    // Wait for React/Next.js to be ready (if applicable)
    await browser.waitUntil(
        async () => {
            return await browser.execute(() => {
                // Check if Next.js or React app is loaded
                return (
                    (window.next && window.next.router) ||
                    (window.React &&
                        document.querySelector('[data-reactroot]')) ||
                    document.querySelector('[data-testid]') ||
                    true // Fallback if no framework detected
                );
            });
        },
        {
            timeout: timeout,
            timeoutMsg: 'Application did not initialize within timeout',
        }
    );

    // Small delay to ensure all scripts have executed
    await browser.pause(500);
};

/**
 * Wait for element to be clickable and then click it
 * @param {String|Object} selector - Element selector or WebdriverIO element
 * @param {Object} options - Options object
 * @param {Number} options.timeout - Timeout in ms (default: 30000)
 * @param {String} options.errorMsg - Custom error message
 */
module.exports.waitAndClick = async (selector, options = {}) => {
    const timeout = options.timeout || 30000;
    const errorMsg =
        options.errorMsg ||
        `Element ${selector} not clickable within ${timeout}ms`;

    const element = typeof selector === 'string' ? await $(selector) : selector;

    await element.waitForClickable({ timeout, errorMsg: errorMsg });
    await element.click();

    return element;
};

/**
 * Wait for element to be displayed and then set value
 * @param {String|Object} selector - Element selector or WebdriverIO element
 * @param {String} value - Value to set
 * @param {Object} options - Options object
 * @param {Number} options.timeout - Timeout in ms (default: 30000)
 * @param {Boolean} options.clearFirst - Clear value first (default: true)
 */
module.exports.waitAndSetValue = async (selector, value, options = {}) => {
    const timeout = options.timeout || 30000;
    const clearFirst = options.clearFirst !== false;

    const element = typeof selector === 'string' ? await $(selector) : selector;
    const errorMsg =
        options.errorMsg ||
        `Element ${selector} not displayed within ${timeout}ms`;

    await element.waitForDisplayed({ timeout, errorMsg: errorMsg });

    if (clearFirst) {
        await element.clearValue();
    }

    await element.setValue(value);

    return element;
};

/**
 * Wait for element to be displayed
 * @param {String|Object} selector - Element selector or WebdriverIO element
 * @param {Object} options - Options object
 * @param {Number} options.timeout - Timeout in ms (default: 30000)
 * @param {Boolean} options.reverse - Wait for element to not exist (default: false)
 */
module.exports.waitForElement = async (selector, options = {}) => {
    const timeout = options.timeout || 30000;
    const reverse = options.reverse || false;

    const element = typeof selector === 'string' ? await $(selector) : selector;
    const displayed = reverse ? 'not displayed' : 'still displayed';
    const errorMsg =
        options.errorMsg ||
        `Element ${selector} ${displayed} within ${timeout}ms`;

    await element.waitForDisplayed({
        timeout: timeout,
        reverse: reverse,
        errorMsg: errorMsg,
    });

    return element;
};

/**
 * Wait for element to exist in DOM
 * @param {String|Object} selector - Element selector or WebdriverIO element
 * @param {Object} options - Options object
 * @param {Number} options.timeout - Timeout in ms (default: 30000)
 * @param {Boolean} options.reverse - Wait for element to not exist (default: false)
 */
module.exports.waitForElementExist = async (selector, options = {}) => {
    const timeout = options.timeout || 30000;
    const reverse = options.reverse || false;
    const exist = reverse ? 'not exist' : 'still exist';
    const errorMsg =
        options.errorMsg || `Element ${selector} ${exist} within ${timeout}ms`;

    const element = typeof selector === 'string' ? await $(selector) : selector;

    await element.waitForExist({ timeout, reverse, errorMsg: errorMsg });

    return element;
};

/**
 * Wait for URL to match pattern
 * @param {String|RegExp} pattern - URL pattern to match
 * @param {Number} timeout - Timeout in ms (default: 30000)
 */
module.exports.waitForUrl = async (pattern, timeout = 30000) => {
    await browser.waitUntil(
        async () => {
            const currentUrl = await browser.getUrl();
            if (typeof pattern === 'string') {
                return currentUrl.includes(pattern);
            } else {
                return pattern.test(currentUrl);
            }
        },
        {
            timeout,
            timeoutMsg: `URL did not match pattern ${pattern} within ${timeout}ms`,
        }
    );
};

/**
 * Wait for network requests to complete
 * @param {Number} timeout - Timeout in ms (default: 10000)
 * @param {Number} idleTime - Time to wait with no requests in ms (default: 1000)
 */
module.exports.waitForNetworkIdle = async (
    timeout = 10000,
    idleTime = 1000
) => {
    const startTime = Date.now();
    let lastRequestTime = Date.now();

    await browser.waitUntil(
        async () => {
            const now = Date.now();

            // Check if there are pending requests
            const hasPendingRequests = await browser.execute(() => {
                if (
                    typeof performance === 'undefined' ||
                    !performance.getEntriesByType
                ) {
                    return false;
                }

                const resources = performance.getEntriesByType('resource');
                const origin = window.location.origin;

                // Check if any resource from our origin is still loading
                return resources
                    .filter((r) => r.name.startsWith(origin))
                    .some((r) => {
                        // Resource is pending if it doesn't have a responseEnd time
                        // or if responseEnd is very recent (within last 100ms)
                        return (
                            !r.responseEnd || Date.now() - r.responseEnd < 100
                        );
                    });
            });

            if (hasPendingRequests) {
                lastRequestTime = now;
            }

            // Consider idle if no requests for idleTime
            const isIdle = now - lastRequestTime >= idleTime;

            if (isIdle) {
                return true;
            }

            // Timeout check
            if (now - startTime > timeout) {
                console.warn('Network idle timeout reached, continuing anyway');
                return true;
            }

            return false;
        },
        {
            timeout: timeout + 2000, // Add buffer
            timeoutMsg: `Network did not become idle within ${timeout}ms`,
        }
    );

    // Small delay after network is idle
    await browser.pause(200);
};

/**
 * Safe navigation with page load wait
 * @param {String} url - URL to navigate to
 * @param {Number} timeout - Timeout in ms (default: 30000)
 */
module.exports.navigateAndWait = async (url, timeout = 30000) => {
    await browser.url(url);
    await module.exports.waitForPageLoad(null, timeout);
};

/**
 * Safe authentication with wait
 * @param {Number} timeout - Timeout in ms (default: 30000)
 */
module.exports.authenticateAndWait = async (timeout = 30000) => {
    await browser.newUser();
    // Wait for authentication to complete
    await browser.pause(1000);
    // Verify we're authenticated by checking for redirect away from okta
    await browser.waitUntil(
        async () => {
            const url = await browser.getUrl();
            return !url.includes('okta');
        },
        {
            timeout,
            timeoutMsg: 'Authentication did not complete within timeout',
        }
    );
};

/**
 * Retry a function with exponential backoff
 * @param {Function} fn - Function to retry (should return a Promise)
 * @param {Object} options - Options object
 * @param {Number} options.retries - Number of retries (default: 3)
 * @param {Number} options.delay - Initial delay in ms (default: 1000)
 * @param {Number} options.factor - Backoff factor (default: 2)
 * @param {Function} options.shouldRetry - Function to determine if error should be retried
 */
module.exports.retry = async (fn, options = {}) => {
    const retries = options.retries || 3;
    const delay = options.delay || 1000;
    const factor = options.factor || 2;
    const shouldRetry = options.shouldRetry || (() => true);

    let lastError;

    for (let attempt = 0; attempt <= retries; attempt++) {
        try {
            return await fn();
        } catch (error) {
            lastError = error;

            if (attempt === retries || !shouldRetry(error)) {
                throw error;
            }

            const waitTime = delay * Math.pow(factor, attempt);
            console.log(
                `Retry attempt ${
                    attempt + 1
                }/${retries} after ${waitTime}ms. Error: ${error.message}`
            );
            await browser.pause(waitTime);
        }
    }

    throw lastError;
};

module.exports.waitForTabToOpenAndSwitch = async (timeout = 30000) => {
    // Wait until a new tab opens (max 5 seconds)
    const pollInterval = 100;
    const start = Date.now();
    let windowHandles = await browser.getWindowHandles();

    while (windowHandles.length <= 1 && Date.now() - start < timeout) {
        await browser.pause(pollInterval);
        windowHandles = await browser.getWindowHandles();
    }

    expect(windowHandles.length).toBeGreaterThan(1);
    const tab = windowHandles.length - 1;
    await browser.switchToWindow(windowHandles[tab]);
};

/**
 * Close alert
 * @returns {Promise<void>}
 */
module.exports.closeAlert = async () => {
    await module.exports.waitAndClick('div[data-wdio="alert-close"]');
};

/**
 * Before each test setup
 */
module.exports.beforeEachTest = async () => {
    // Clear cookies and storage between tests
    try {
        await browser.deleteCookies();
        await browser.execute(() => {
            localStorage.clear();
            sessionStorage.clear();
        });
    } catch (e) {
        // Ignore errors if browser is not initialized
        console.warn('Could not clear browser state:', e.message);
    }
};
