const { screenshot } = require('../libs/actions');
const HomePage = require('../libs/pageObjects/homepage.page');
const debug = require('debug')('AthenzUI:functional:dummyspec');

describe('homepage', () => {
    before(async () => {
        // debug('browser config: %o', browser.config);
        await HomePage.openStatus();
        debug('opened status, setting cookies now..');
        await HomePage.setLoginCookies({
            okta_it: browser.config.OKTA_IT,
            okta_at: browser.config.OKTA_AT,
            domain: browser.config.COOKIE_DOMAIN
        });
        debug('cookies are set. lets run some tests.');
    });
    after(() => {
        screenshot('homepage');
    });

    it('should display home page', async () => {
        await HomePage.open();
        await HomePage.elementExists(HomePage.body);
    });
});
