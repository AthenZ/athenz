const path = require('path');
const BROWSERS = require('./libs/browsers');
const browsers = (process.env.BROWSERS || 'chrome').split(',');

const debug = require('debug')('AthenzUI:functional:wdioconf');
const {
    BUILD_NUMBER,
    MAX_INSTANCES: maxInstances = 20,
    PARENT_TUNNEL = 'yahoo_general',
    RETRIES,
    SAUCE_ACCESS_KEY,
    SAUCE_USERNAME,
    SCREWDRIVER,
    TEST_DIR = path.resolve(process.cwd(), 'artifacts'),
    TUNNEL_IDENTIFIER = 'tunnel-yahoo-corp',
    OKTA_IT,
    OKTA_AT,
    COOKIE_DOMAIN,
    INSTANCE,
} = process.env;

const capabilities = !SCREWDRIVER
    ? [
          {
              browserName: 'chrome',
              'goog:chromeOptions': {
                  perfLoggingPrefs: {
                      enableNetwork: true,
                      enablePage: false,
                  },
              },
              'goog:loggingPrefs': {
                  performance: 'ALL',
                  browser: 'ALL',
              },
          },
      ]
    : browsers.map(function(name) {
          const tunnelIdentifier = TUNNEL_IDENTIFIER
              ? `${TUNNEL_IDENTIFIER}-${(Math.random() * 9 + 21) | 0}`
              : undefined;
          return Object.assign(
              {
                  maxInstances,
                  'parent-tunnel': PARENT_TUNNEL,
                  tunnelIdentifier,
                  build: BUILD_NUMBER,
                  screenResolution: '1280x1024',
              },
              BROWSERS[name]
          );
      });

const config = {
    // ==================
    // Specify Test Files
    // ==================
    // Define which test specs should run. The pattern is relative to the directory
    // from which `wdio` was called. Notice that, if you are calling `wdio` from an
    // NPM script (see https://docs.npmjs.com/cli/run-script) then the current working
    // directory is where your package.json resides, so `wdio` will be called from there.
    //
    specs: ['./src/__tests__/spec/tests/**/*.spec.js'],
    // Patterns to exclude.
    exclude: [
        // 'path/to/excluded/files'
    ],
    suites: {
        all: ['./src/__tests__/spec/tests/all/**/*.spec.js'],
    },
    //
    // ============
    // Capabilities
    // ============
    // Define your capabilities here. WebdriverIO can run multiple capabilities at the same
    // time. Depending on the number of capabilities, WebdriverIO launches several test
    // sessions. Within your capabilities you can overwrite the spec and exclude options in
    // order to group specific specs to a specific capability.
    //
    // First, you can define how many instances should be started at the same time. Let's
    // say you have 3 different capabilities (Chrome, Firefox, and Safari) and you have
    // set maxInstances to 1; wdio will spawn 3 processes. Therefore, if you have 10 spec
    // files and you set maxInstances to 10, all spec files will get tested at the same time
    // and 30 processes will get spawned. The property handles how many capabilities
    // from the same test should run tests.
    //
    // maxInstances: browsers.includes('chrome') ? 1 : 20,
    //
    // If you have trouble getting all important capabilities together, check out the
    // Sauce Labs platform configurator - a great tool to configure your capabilities:
    // https://docs.saucelabs.com/reference/platforms-configurator
    //
    // capabilities: [{
    // maxInstances can get overwritten per capability. So if you have an in-house Selenium
    // grid with only 5 firefox instances available you can make sure that not more than
    // 5 instances get started at a time.
    // maxInstances: 5,
    //
    //     browserName: 'firefox'
    // }],
    capabilities,
    //
    // Add files to watch (e.g. application code or page objects) when running `wdio` command
    // with `--watch` flag. Globbing is supported.
    filesToWatch: ['./src/**/*.js'],
    //
    // ===================
    // Test Configurations
    // ===================
    // Define all options that are relevant for the WebdriverIO instance here
    //
    // Level of logging verbosity: trace | debug | info | warn | error | silent
    logLevel: 'error',
    //
    // If you only want to run your tests until a specific amount of tests have failed use
    // bail (default is 0 - don't bail, run all tests).
    bail: 1,
    //
    // Set a base URL in order to shorten url command calls. If your url parameter starts
    // with "/", then the base url gets prepended.
    baseUrl: INSTANCE,
    //
    // Default timeout for all waitFor* commands.
    waitforTimeout: 5000,
    //
    // Framework you want to run your specs with.
    // The following are supported: Mocha, Jasmine, and Cucumber
    // see also: http://webdriver.io/guide/testrunner/frameworks.html
    //
    // Make sure you have the wdio adapter package for the specific framework installed
    // before running any tests.
    framework: 'mocha',
    //
    // The number of times to retry the entire specfile when it fails as a whole
    specFileRetries: 1,
    //
    // Test reporter for stdout.
    // The only one supported by default is 'dot'
    // see also: http://webdriver.io/guide/testrunner/reporters.html
    reporters: ['spec', ['junit', { outputDir: TEST_DIR }]],
    //
    // Options to be passed to Mocha.
    // See the full list at http://mochajs.org/
    mochaOpts: {
        // require: ['ts-node/register'],
        ui: 'bdd',
        timeout: 30000,
        retries: !isNaN(+RETRIES) ? +RETRIES : 2,
    },
    //
    // =====
    // Hooks
    // =====
    // WebdriverIO provides a several hooks you can use to interfere the test process in order to enhance
    // it and build services around it. You can either apply a single function to it or an array of
    // methods. If one of them returns with a promise, WebdriverIO will wait until that promise is
    // resolved to continue.
    //
    /**
     * Gets executed once before all workers get launched.
     * @param {Object} config wdio configuration object
     * @param {Array.<Object>} capabilities list of capabilities details
     */
    // onPrepare: function (config, capabilities) {
    //     // process.env.BROWSER_NAME = capabilities.browserName;
    // },
    /**
     * Gets executed just before initialising the webdriver session and test framework. It allows you
     * to manipulate configurations depending on the capability or spec.
     * @param {Object} config wdio configuration object
     * @param {Array.<Object>} capabilities list of capabilities details
     * @param {Array.<String>} specs List of spec file paths that are to be run
     */
    // beforeSession: function (config, capabilities, specs) {
    // },
    /**
     * Gets executed before test execution begins. At this point you can access to all global
     * variables like `browser`. It is the perfect place to define custom commands.
     * @param {Array.<Object>} capabilities list of capabilities details
     * @param {Array.<String>} specs List of spec file paths that are to be run
     */
    // before: function(capabilities, specs) {
    // },
    /**
     * Gets executed before the suite starts.
     * @param {Object} suite suite details
     */
    // beforeSuite: function (suite) {
    // },
    /**
     * This hook gets executed _before_ a hook within the suite starts.
     * (For example, this runs before calling `beforeEach` in Mocha.)
     *
     * (`stepData` and `world` are Cucumber-specific.)
     *
     */
    // beforeHook: function (test, context/*, stepData, world*/) {
    // },
    /**
     * Hook that gets executed _after_ a hook within the suite ends.
     * (For example, this runs after calling `afterEach` in Mocha.)
     *
     * (`stepData` and `world` are Cucumber-specific.)
     */
    // afterHook: function (test, context, { error, result, duration, passed, retries }/*, stepData, world*/) {
    // },
    /**
     * Function to be executed before a test (in Mocha/Jasmine) starts.
     */
    // beforeTest: function (test, context) {
    // },
    /**
     * Runs before a WebdriverIO command is executed.
     * @param {String} commandName hook command name
     * @param {Array} args arguments that the command would receive
     */
    // beforeCommand: function (commandName, args) {
    // },
    /**
     * Runs after a WebdriverIO command gets executed
     * @param {String} commandName hook command name
     * @param {Array} args arguments that command would receive
     * @param {Number} result 0 - command success, 1 - command error
     * @param {Object} error error object, if any
     */
    // afterCommand: function (commandName, args, result, error) {
    // },
    /**
     * Function to be executed after a test (in Mocha/Jasmine)
     */
    // afterTest: function (test, context, { error, result, duration, passed, retries }) {
    // },
    /**
     * Hook that gets executed after the suite has ended.
     * @param {Object} suite suite details
     */
    // afterSuite: function (suite) {
    // },
    /**
     * Gets executed after all tests are done. You still have access to all global variables from
     * the test.
     * @param {Number} result 0 - test pass, 1 - test fail
     * @param {Array.<Object>} capabilities list of capabilities details
     * @param {Array.<String>} specs List of spec file paths that ran
     */
    // after: function (result, capabilities, specs) {
    // },
    /**
     * Gets executed right after terminating the webdriver session.
     * @param {Object} config wdio configuration object
     * @param {Array.<Object>} capabilities list of capabilities details
     * @param {Array.<String>} specs List of spec file paths that ran
     */
    // afterSession: function (config, capabilities, specs) {
    // },
    /**
     * Gets executed after all workers have shut down and the process is about to exit.
     * An error thrown in the `onComplete` hook will result in the test run failing.
     * @param {Object} exitCode 0 - success, 1 - fail
     * @param {Object} config wdio configuration object
     * @param {Array.<Object>} capabilities list of capabilities details
     * @param {<Object>} results object containing test results
     */
    // onComplete: function (exitCode, config, capabilities, results) {
    // },
    /**
     * Gets executed when a refresh happens.
     * @param {String} oldSessionId session ID of the old session
     * @param {String} newSessionId session ID of the new session
     */
    // onReload: function(oldSessionId, newSessionId) {
    // },
};

// Configure SauceLabs if run on Screwdriver
if (SCREWDRIVER) {
    //
    // =================
    // Service Providers
    // =================
    // WebdriverIO supports Sauce Labs, Browserstack, and Testing Bot (other cloud providers
    // should work too though). These services define specific user and key (or access key)
    // values you need to put in here in order to connect to these services.
    //
    config.user = SAUCE_USERNAME || 'sso-yahoo-pgote';
    config.key = SAUCE_ACCESS_KEY;
    config.sauceConnect = true;
    config.services = ['sauce'];
    config.maxInstances = maxInstances;
} else if (process.env.PLATFORM === 'Darwin') {
    config.runner = 'local';
    config.port = 4445;
    config.path = '/wd/hub';
    config.services = ['selenium-standalone'];
    config.maxInstances = 1;
} else {
    config.runner = 'local';
    //
    // =====================
    // Server Configurations
    // =====================
    // Host address of the running Selenium server. This information is usually obsolete, as
    // WebdriverIO automatically connects to localhost. Also if you are using one of the
    // supported cloud services like Sauce Labs, Browserstack, or Testing Bot, you also don't
    // need to define host and port information (because WebdriverIO can figure that out
    // from your user and key information). However, if you are using a private Selenium
    // backend, you should define the `hostname`, `port`, and `path` here.
    //
    // e.g. http://selenium:4444/wd/hub for local docker setup
    config.hostname = 'selenium';
    config.port = 4444;
    config.path = '/wd/hub';
    config.maxInstances = 1;
}

config.OKTA_AT = OKTA_AT;
config.OKTA_IT = OKTA_IT;
config.COOKIE_DOMAIN = COOKIE_DOMAIN;

debug('final config object: %O', config);

exports.config = config;
