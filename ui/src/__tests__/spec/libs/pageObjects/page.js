const expect = require('expect');
const {
    elementExists,
    screenshot,
    scrollBottom,
    scrollToEl,
    scrollTop,
    textPresence,
} = require('../actions');
const debug = require('debug')('AthenzUI:functional:page');
/**
 * Base Page class that all page objects subclass
 * @see https://webdriver.io/docs/pageobjects.html
 */
module.exports = class Page {
    // define elements
    get header() {
        return $('header');
    }
    /**
     * Check if element exists
     * {Object} elementFn Element getter function
     * {Boolean} reverse When true, will test that element does not exist
     * {Number} [timeout=500] Timeout in ms
     * @param args ...args spread object for args
     * @async
     */
    async elementExists(...args) {
        return elementExists(...args);
    }
    /**
     * Check that element has given text
     * @param {Object} el Element to check
     * @param {String} text Text to assert
     * @param {Number} [timeout=1500] Timeout in ms
     * @param {Boolean} reverse When true, will test that text does not exist
     * @async
     */
    async hasElementText(...args) {
        return textPresence(...args);
    }

    /**
     * Check if given text is in the page source
     * @param {String} text Text to find in the source
     * @async
     */
    async hasSource(text) {
        const source = await browser.getPageSource();
        expect(source).toContain(text);
    }

    /**
     * Check that the current page has the given title
     * @param {String} text Title text
     * @async
     */
    async hasTitle(text) {
        const title = await browser.getTitle();
        expect(title).toEqual(text);
    }

    /**
     * Open status.html page
     * @async
     */
    async openStatus({
        baseUrl = browser.config.baseUrl,
        pathname = '/status.html',
        query = {},
    } = {}) {
        const url = new URL(pathname, baseUrl);
        const urlString = url.toString();
        return browser.url(urlString);
    }

    async setLoginCookies({
        okta_at = '',
        okta_it = '',
        domain = '.dev-ui.zms.athens.yahoo.com',
    }) {
        browser.setCookies({
            name: 'okta_it',
            value: okta_it,
            domain: domain,
            isSecure: true,
            isHttpOnly: true,
        });

        browser.setCookies({
            name: 'okta_at',
            value: okta_at,
            domain: domain,
            isSecure: true,
            isHttpOnly: true,
        });
        return browser;
    }

    /**
     * Open a web page
     * @param {URL} obj URL class properties
     * @async
     */
    async open({
        baseUrl = browser.config.baseUrl,
        pathname = '/',
        query = {},
    } = {}) {
        const url = new URL(pathname, baseUrl);
        // url.search = new URLSearchParams({
        //     ...query
        // });
        const urlString = url.toString();
        debug('url: %s', urlString);
        browser.url(urlString);
    }

    /**
     * Create a screenshot of the current page
     * @param {String} name Unique name of the screenshot
     * @param {Object} [target] Element to screenshot, current page by default
     * @async
     */
    async screenshot(name, target) {
        await screenshot(name, target);
    }

    /**
     * Scroll to the viewport bottom
     * @async
     */
    async scrollBottom() {
        await scrollBottom();
    }

    /**
     * Scroll to the top of the page
     * @async
     */
    async scrollTop() {
        await scrollTop();
    }

    /**
     * 1) Check if defer module exists
     * 2) Scroll to defer module on page
     * 3) Check if post defer module fetches
     * @async
     */
    async verifyDeferModuleExistsAndTriggersOnViewport(
        deferModule,
        postDeferModule
    ) {
        await elementExists(deferModule);
        await scrollToEl(deferModule);
        await elementExists(postDeferModule);
    }

    /**
     * Verifies client network request. This requires `perfLoggingPrefs` and
     * `goog:loggingPrefs` to be enabled in the browser capability
     * @param {String} text String of text to validate in the request
     * @async
     */
    async verifyNetworkRequest(text) {
        // gather performance logs from browser
        // only works in chrome
        if (typeof browser.getLogs === 'function') {
            const browserLogs = await browser.getLogs('performance');
            if (browserLogs.length) {
                // ensure request was fired based on text
                const request = browserLogs.filter((log) => {
                    const m = JSON.parse(log.message).message;
                    return (
                        m.method === 'Network.requestWillBeSent' &&
                        m.params.documentURL.includes(text)
                    );
                });

                expect(request.length).toEqual(1);
            }
        }
    }
};
