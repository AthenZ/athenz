'use strict';
const fs = require('fs');
const path = require('path');
const mkdirp = require('mkdirp');
const exec = require('child_process').exec;
const {
  BUILD_NUMBER,
  SD_JOB_NAME,
  WORK_DIR,
  TUNNEL_IDENTIFIER = 'tunnel-yahoo-corp',
  PARENT_TUNNEL = 'yahoo_general'
} = process.env;
let sdv4Job = SD_JOB_NAME === 'master';
let athenzDomain;
let athenzService;

if (process.env.INSTANCE) { // executing functional test pointing at dev environment
  athenzDomain = 'athenz.k8s';
  athenzService = 'athenz-ui-development';
} else { // executing functional test pointing at local environment
  athenzDomain = 'athenz.dev';
  athenzService = 'devui';
}

let sdAthenzKeyFilePath = WORK_DIR + '/func.key.pem';
let sdAthenzCertFiledPath = WORK_DIR + '/func.cert.pem';
let localAthenzKeyFilePath = '~/.athenz/keys/' + athenzDomain + '.' + athenzService + '.key.pem';
let localAthenzCertFilePath = '~/.athenz/certs/' + athenzDomain + '.' + athenzService + '.cert.pem';

let functionalTestConfig = {
  'athensZtsAPI': 'https://zts.athens.yahoo.com:4443/zts/v1',
  'athenzService': athenzService,
  'athenzDomain': athenzDomain,
  'athenzKeyFile': sdv4Job ? sdAthenzKeyFilePath : localAthenzKeyFilePath,
  'athenzCertFile': sdv4Job ? sdAthenzCertFiledPath : localAthenzCertFilePath,
  'sauceUser': sdv4Job ? 'athenzui-saucelabs' : process.env.SAUCE_USERNAME,
  'sauceKey': process.env.SAUCE_KEY,
  'instance': process.env.INSTANCE || 'https://local-ui.athenz.ouryahoo.com/',
  'cookieDomain': process.env.COOKIE || '.athenz.ouryahoo.com',
  'sauceSeleniumAddress': 'ondemand.us-west-1.saucelabs.com/wd/hub',
  'screenResolution': '1600x1200'
};

const sauceLabsKey = functionalTestConfig.sauceKey || '';
const sauceLabsUser = functionalTestConfig.sauceUser || '';
const localOrRemote = { };
if (!sauceLabsUser) {
  //
  // Test runner services
  // Services take over a specific job you don't want to take care of. They enhance
  // your test setup with almost no effort. Unlike plugins, they don't add new
  // commands. Instead, they hook themselves up into the test process.
  localOrRemote.saucelabs = {
    runner: 'local',
    services: ['chromedriver']
  };
  localOrRemote.capabilities = [
    {
      browserName: 'chrome',
      browserVersion: 'latest',
      acceptInsecureCerts: true
    }
  ];
} else {
  // SauceLabs Settings
  localOrRemote.saucelabs = {
    user: sauceLabsUser,
    key: sauceLabsKey,
    services: ['sauce'],
    sauceConnect: true,
    region: 'us',
    updateJob: true,
    sauceSeleniumAddress: functionalTestConfig.sauceSeleniumAddress,
    setJobName: (config, capabilities, suiteTitle) => {
      capabilities.name = suiteTitle + ':' + 'Athenz UI Tests';
    }
  };
  // Capabilities - These are the browsers to use in SauceLabs
  localOrRemote.capabilities = [
    {
      browserName: 'chrome',
      acceptInsecureCerts: true,
      browserVersion: 'latest',
      platformName: 'OS X 12',
      maxInstances: 7,
      'sauce:options': {
        tunnelIdentifier: TUNNEL_IDENTIFIER + '-' + (Math.floor(Math.random() * 8) + 1),
        parentTunnel: process.env.SAUCE_TUNNEL || PARENT_TUNNEL,
        name: process.env.npm_package_name || 'Athenz UI Tests',
        build: BUILD_NUMBER,
        screenResolution: functionalTestConfig.screenResolution
      }
    }
  ];
}
let config = {
    ...localOrRemote.saucelabs,
    //
    // ====================
    // Runner Configuration
    // ====================
    // WebdriverIO supports running e2e tests as well as unit and component tests.
    runner: 'local',
    
    //
    // =================
    // Service Providers
    // =================
    // WebdriverIO supports Sauce Labs, Browserstack, Testing Bot and LambdaTest (other cloud providers
    // should work too though). These services define specific user and key (or access key)
    // values you need to put in here in order to connect to these services.
    //
    //
    // If you run your tests on Sauce Labs you can specify the region you want to run your tests
    // in via the `region` property. Available short handles for regions are `us` (default), `eu` and `apac`.
    // These regions are used for the Sauce Labs VM cloud and the Sauce Labs Real Device Cloud.
    // If you don't provide the region it will default for the `us`
    region: 'us',
    //
    // ==================
    // Specify Test Files
    // ==================
    // Define which test specs should run. The pattern is relative to the directory
    // from which `wdio` was called.
    //
    // The specs are defined as an array of spec files (optionally using wildcards
    // that will be expanded). The test for each spec file will be run in a separate
    // worker process. In order to have a group of spec files run in the same worker
    // process simply enclose them in an array within the specs array.
    //
    // If you are calling `wdio` from an NPM script (see https://docs.npmjs.com/cli/run-script),
    // then the current working directory is where your `package.json` resides, so `wdio`
    // will be called from there.
    //
    specs: [
        './tests/*.spec.js'
    ],
    // Patterns to exclude.
    exclude: [
        // 'path/to/excluded/files'
    ],
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
    maxInstances: 10,
    //
    // If you have trouble getting all important capabilities together, check out the
    // Sauce Labs platform configurator - a great tool to configure your capabilities:
    // https://saucelabs.com/platform/platform-configurator
    //
    capabilities: [
      ...localOrRemote.capabilities
    ],
    //
    // ===================
    // Test Configurations
    // ===================
    // Define all options that are relevant for the WebdriverIO instance here
    //
    // Level of logging verbosity: trace | debug | info | warn | error | silent
    logLevel: 'info',
    //
    // Set specific log levels per logger
    // loggers:
    // - webdriver, webdriverio
    // - @wdio/browserstack-service, @wdio/devtools-service, @wdio/sauce-service
    // - @wdio/mocha-framework, @wdio/jasmine-framework
    // - @wdio/local-runner
    // - @wdio/sumologic-reporter
    // - @wdio/cli, @wdio/config, @wdio/utils
    // Level of logging verbosity: trace | debug | info | warn | error | silent
    // logLevels: {
    //     webdriver: 'info',
    //     '@wdio/appium-service': 'info'
    // },
    //
    // If you only want to run your tests until a specific amount of tests have failed use
    // bail (default is 0 - don't bail, run all tests).
    bail: 0,
    //
    // Set a base URL in order to shorten url command calls. If your `url` parameter starts
    // with `/`, the base url gets prepended, not including the path portion of your baseUrl.
    // If your `url` parameter starts without a scheme or `/` (like `some/path`), the base url
    // gets prepended directly.
    baseUrl: functionalTestConfig.instance,
    //
    // Default timeout for all waitFor* commands.
    waitforTimeout: 10000,
    //
    // Default timeout in milliseconds for request
    // if browser driver or grid doesn't send response
    connectionRetryTimeout: 120000,
    //
    // Default request retries count
    connectionRetryCount: 3,
    //
    // Test runner services
    // Services take over a specific job you don't want to take care of. They enhance
    // your test setup with almost no effort. Unlike plugins, they don't add new
    // commands. Instead, they hook themselves up into the test process.
    
    // Framework you want to run your specs with.
    // The following are supported: Mocha, Jasmine, and Cucumber
    // see also: https://webdriver.io/docs/frameworks
    //
    // Make sure you have the wdio adapter package for the specific framework installed
    // before running any tests.
    framework: 'mocha',
    //
    // The number of times to retry the entire specfile when it fails as a whole
    specFileRetries: 1,
    //
    // Delay in seconds between the spec file retry attempts
    // specFileRetriesDelay: 0,
    //
    // Whether or not retried specfiles should be retried immediately or deferred to the end of the queue
    // specFileRetriesDeferred: false,
    //
    // Test reporter for stdout.
    // The only one supported by default is 'dot'
    // see also: https://webdriver.io/docs/dot-reporter
    reporters: ['spec'],


    
    //
    // Options to be passed to Mocha.
    // See the full list at http://mochajs.org/
    mochaOpts: {
        ui: 'bdd',
        timeout: 60000,
        retries: 2,
    },
    //
    // =====
    // Hooks
    // =====
    // WebdriverIO provides several hooks you can use to interfere with the test process in order to enhance
    // it and to build services around it. You can either apply a single function or an array of
    // methods to it. If one of them returns with a promise, WebdriverIO will wait until that promise got
    // resolved to continue.
    /**
     * Gets executed once before all workers get launched.
     * @param {Object} config wdio configuration object
     * @param {Array.<Object>} capabilities list of capabilities details
     */
    // onPrepare: function (config, capabilities) {
    // },
    /**
     * Gets executed before a worker process is spawned and can be used to initialise specific service
     * for that worker as well as modify runtime environments in an async fashion.
     * @param  {String} cid      capability id (e.g 0-0)
     * @param  {[type]} caps     object containing capabilities for session that will be spawn in the worker
     * @param  {[type]} specs    specs to be run in the worker process
     * @param  {[type]} args     object that will be merged with the main configuration once worker is initialized
     * @param  {[type]} execArgv list of string arguments passed to the worker process
     */
    // onWorkerStart: function (cid, caps, specs, args, execArgv) {
    // },
    /**
     * Gets executed just after a worker process has exited.
     * @param  {String} cid      capability id (e.g 0-0)
     * @param  {Number} exitCode 0 - success, 1 - fail
     * @param  {[type]} specs    specs to be run in the worker process
     * @param  {Number} retries  number of retries used
     */
    // onWorkerEnd: function (cid, exitCode, specs, retries) {
    // },
    /**
     * Gets executed just before initialising the webdriver session and test framework. It allows you
     * to manipulate configurations depending on the capability or spec.
     * @param {Object} config wdio configuration object
     * @param {Array.<Object>} capabilities list of capabilities details
     * @param {Array.<String>} specs List of spec file paths that are to be run
     * @param {String} cid worker id (e.g. 0-0)
     */
    // beforeSession: function (config, capabilities, specs, cid) {
    // },
    /**
     * Gets executed before test execution begins. At this point you can access to all global
     * variables like `browser`. It is the perfect place to define custom commands.
     * @param {Array.<Object>} capabilities list of capabilities details
     * @param {Array.<String>} specs        List of spec file paths that are to be run
     * @param {Object}         browser      instance of created browser/device session
     */
     before: function(capabilities, specs, browser) {
        browser.addCommand('screenshot', function(filename) {
          return browser.takeScreenshot().then(function(png) {
            return browser.driver.controlFlow().execute(function() {
              return new Promise(function(fulfill) {
                mkdirp(path.dirname(filename), function() {
                  let stream = fs.createWriteStream(filename);
                  stream.write(new Buffer(png, 'base64'));
                  stream.end(function() {
                    fulfill();
                  });
                });
              });
            });
          });
        });
        let count = 0;
        let Mocha = require('mocha');
        if (!Mocha._pesExt) {
          Mocha._pesExt = true;
          let run = Mocha.prototype.run;
          Mocha.prototype.run = function() {
            this.suite.on('pre-require', function() {
              // Anything that is shared across all tests should be put here.
              function screenshot(test) {
                if (test.state === 'failed') {
                  let shotsDir = path.join(process.cwd(), 'artifacts/shots'),
                    filename = encodeURIComponent(test.title.replace(/\s+/g, '-'));
                  if (process.env.ARTIFACTS_DIR) {
                    shotsDir = path.join(process.env.ARTIFACTS_DIR, 'shots');
                  }
      
                  filename = path.join(shotsDir, count + '-' + filename + '.png');
                  count += 1;
                  console.log('\n=====================Test case failed!=======================');
                  console.log('Test file: ' + test.file);
                  console.log('Test name: ' + test.title);
                  console.log('Screen shot location: ' + filename);
                  console.log('===============================================================\n');
                  return browser.screenshot(filename);
                }
              }
      
              afterEach(function(){
                screenshot(this.currentTest);
              });
            });
            return run.apply(this, arguments);
          };
        }
    
        let getAccessToken = function(callback) {
          let command = 'zts-accesstoken' +
                                ' -domain ' + functionalTestConfig.athenzDomain +
                                ' -service ' + functionalTestConfig.athenzService +
                                ' -svc-key-file ' + functionalTestConfig.athenzKeyFile +
                                ' -svc-cert-file ' + functionalTestConfig.athenzCertFile +
                                ' -zts ' + functionalTestConfig.athensZtsAPI;
          console.log('Fetching access token using command: ', command);
          exec(command, (err, stdout, stderr) => {
            let value = {};
            if (err) {
              console.log('Fetching tokens failed: ', err, stderr);
            }
            if (stdout) {
              try {
                value = JSON.parse(stdout);
              } catch(e) {
                console.log('Parsing JSON failed: ', e);
                callback(e, value);
              }
            }
            callback(err, value);
          });
        };
    
        browser.addCommand('newUser', function() {
          return new Promise(function(fulfill, reject) {
            getAccessToken(async function(err, tokens) {
              if (err) {
                reject(err);
                return;
              } else {
                await browser.url('/akamai');
                await browser.setCookies({
                  name: 'okta_at',
                  value: tokens.access_token,
                  path: '/',
                  domain: functionalTestConfig.cookieDomain,
                  secure: true,
                  httpOnly: true
                });
        
                await browser.setCookies({
                  name: 'okta_it',
                  value: tokens.id_token,
                  path: '/',
                  domain: functionalTestConfig.cookieDomain,
                  secure: true,
                  httpOnly: true
                });
        
                await browser.setCookies({
                  name: 'okta_rt',
                  value: '',
                  path: '/',
                  domain: functionalTestConfig.cookieDomain,
                  secure: true,
                  httpOnly: true
                });
                fulfill();
              }
            });
          });
        });
      }
    /**
     * Runs before a WebdriverIO command gets executed.
     * @param {String} commandName hook command name
     * @param {Array} args arguments that command would receive
     */
    // beforeCommand: function (commandName, args) {
    // },
    /**
     * Hook that gets executed before the suite starts
     * @param {Object} suite suite details
     */
    // beforeSuite: function (suite) {
    // },
    /**
     * Function to be executed before a test (in Mocha/Jasmine) starts.
     */
    // beforeTest: function (test, context) {
    // },
    /**
     * Hook that gets executed _before_ a hook within the suite starts (e.g. runs before calling
     * beforeEach in Mocha)
     */
    // beforeHook: function (test, context) {
    // },
    /**
     * Hook that gets executed _after_ a hook within the suite starts (e.g. runs after calling
     * afterEach in Mocha)
     */
    // afterHook: function (test, context, { error, result, duration, passed, retries }) {
    // },
    /**
     * Function to be executed after a test (in Mocha/Jasmine only)
     * @param {Object}  test             test object
     * @param {Object}  context          scope object the test was executed with
     * @param {Error}   result.error     error object in case the test fails, otherwise `undefined`
     * @param {Any}     result.result    return object of test function
     * @param {Number}  result.duration  duration of test
     * @param {Boolean} result.passed    true if test has passed, otherwise false
     * @param {Object}  result.retries   informations to spec related retries, e.g. `{ attempts: 0, limit: 0 }`
     */
    // afterTest: function(test, context, { error, result, duration, passed, retries }) {
    // },


    /**
     * Hook that gets executed after the suite has ended
     * @param {Object} suite suite details
     */
    // afterSuite: function (suite) {
    // },
    /**
     * Runs after a WebdriverIO command gets executed
     * @param {String} commandName hook command name
     * @param {Array} args arguments that command would receive
     * @param {Number} result 0 - command success, 1 - command error
     * @param {Object} error error object if any
     */
    // afterCommand: function (commandName, args, result, error) {
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
     * Gets executed after all workers got shut down and the process is about to exit. An error
     * thrown in the onComplete hook will result in the test run failing.
     * @param {Object} exitCode 0 - success, 1 - fail
     * @param {Object} config wdio configuration object
     * @param {Array.<Object>} capabilities list of capabilities details
     * @param {<Object>} results object containing test results
     */
    // onComplete: function(exitCode, config, capabilities, results) {
    // },
    /**
    * Gets executed when a refresh happens.
    * @param {String} oldSessionId session ID of the old session
    * @param {String} newSessionId session ID of the new session
    */
    // onReload: function(oldSessionId, newSessionId) {
    // }
}

console.log('final config object: %O', config);

exports.config = config;
