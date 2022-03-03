const fs = require('fs');
const path = require('path');

const artifactsDir =
    process.env.TEST_DIR || path.resolve(process.cwd(), 'artifacts');
const screenshotsDir = path.resolve(artifactsDir, 'screenshots');

/**
 * Check if element exists
 * @param {Object} elementFn Element getter function
 * @param {Boolean} reverse When true, will test that element does not exist
 * @param {Number} [timeout=500] Timeout in ms
 */
module.exports.elementExists = async (
    elementFn,
    reverse = false,
    timeout = 500
) => {
    let el = await elementFn;
    await el.waitForExist(timeout, reverse);
};

/**
 * Scroll to bottom of the current viewport location
 * @async
 */
module.exports.scrollBottom = async () => {
    await browser.execute('window.scrollTo(0, document.body.scrollHeight);');
};

/**
 * Scroll to the element on page
 * @param {Object} elementFn Element getter function
 * @async
 */
module.exports.scrollToEl = async (elementFn) => {
    const el = await elementFn;

    await el.scrollIntoView();
};

/**
 * Scroll to the top of the page
 * @async
 */
module.exports.scrollTop = async () => {
    await browser.execute('window.scrollTo(0, 0)');
};

/**
 * Take a screenshot of an element or the current page
 * @param {String} name Name of the image
 * @param {Object} [target=browser] Target element or page by default
 */
module.exports.screenshot = async (name, target = browser) => {
    if (!fs.existsSync(screenshotsDir)) {
        fs.mkdirSync(screenshotsDir, { recursive: true });
    }

    const screenshotPath = path.resolve(screenshotsDir, `${name}.png`);
    let image;
    try {
        image = await target.takeScreenshot();
    } catch (e) {
        console.error(e);
    }

    const stream = fs.createWriteStream(screenshotPath);
    stream.write(new Buffer(image, 'base64'));
    stream.end();

    if (fs.existsSync(screenshotPath)) {
        console.log(`${screenshotPath} successfully created!`);
    } else {
        console.error(`${screenshotPath} was not created!`);
    }
};

/**
 * Check if element contains certain text
 * @param {Object} el Element to check
 * @param {String} text Text to assert
 * @param {Number} [timeout=1500] Timeout in ms
 * @param {Boolean} reverse When true, will test that text does not exist
 */
module.exports.textPresence = async (
    el,
    text,
    timeout = 15000,
    reverse = false
) => {
    browser.waitUntil(
        async () => {
            const t = el.getText();
            return reverse ? !t.includes(text) : t.includes(text);
        },
        timeout,
        `"${el}" should have contained text "${text}"`
    );
};
