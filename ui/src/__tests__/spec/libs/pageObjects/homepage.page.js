const Page = require('./page');

/**
 * Subclass for homepage page functionality
 * @extends Page
 */
class HomePage extends Page {
    constructor() {
        super();
    }

    get wrapperDiv() {
        return $('#__next');
    }

    get body() {
        return $('body');
    }
}

module.exports = new HomePage();
