/**
 * Copyright 2016 Yahoo Inc.
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
/*jshint camelcase: false */
'use strict';
var path = require('path');
var SSO = require('sso');
var sso = new SSO({
  useCache: true
});
var exec = require('child_process').spawn;
var PromiseLib = require('promise');

var fs = require('fs');
var mkdirp = require('mkdirp');

var build = '';
if (process.env.CI) {
  build += process.env.JOB;

  if (process.env.PULL_REQUEST) {
    build += ' #' + process.env.PULL_REQUEST;
  } else {
    build += ' ' + process.env.npm_package_version;
  }
} else {
  build += process.env.LOGNAME;
}

var url = '';
if(process.env.INSTANCE) {
  url = process.env.INSTANCE + '/athenz';
} else {
  url = 'http://localhost:4080/athenz';
}

var users = {};
var configUser = process.env.USER || 'zms_ci_admin';

// If a developer is using this, use his user credential from $HOME/.credential
if (configUser !== 'zms_ci_admin') {
  var user = fs.readFileSync(process.env.HOME + '/.credential', 'utf8');
  users[configUser] = users[configUser] || {};
  users[configUser].cookies = {
    USER: {
      name: 'USER',
      value: user,
      path: '/',
      domain: '.localhost'
    }
  };
}

var config = {
  specs: [
    path.join(__dirname, '../functional/' + 'index.js')
  ],
  capabilities: {
    browserName: 'phantomjs',
    build: build,
    name: process.env.npm_package_name || 'Athenz UI Tests',
    screenResolution: '1600x1200',
    customData: {
      name: process.env.npm_package_name,
      version: process.env.npm_package_version,
      commit: process.env.npm_package_gitHead,
      instance: process.env.INSTANCE,
      buildUrl: process.env.BUILD_URL,
      hostname: process.env.HOSTNAME
    }
  },
  baseUrl: url,
  allScriptsTimeout: 20000,
  framework: 'mocha',
  mochaOpts: {
    timeout: (15 * 60 * 1000), // default timeout
    slow: 6000,
    ui: 'bdd',
    reporter: process.env.CI ? 'xunit-file' : 'spec'
  },
  onPrepare: function() {
    browser.screenshot =  function(filename) {
      return browser.takeScreenshot().then(function(png) {
        return browser.driver.controlFlow().execute(function() {
          return new PromiseLib(function(fulfill) {
            mkdirp(path.dirname(filename), function() {
              var stream = fs.createWriteStream(filename);
              stream.write(Buffer.from(png, 'base64'));
              stream.end(function() {
                fulfill();
              });
            });
          });
        });
      });
    };
    var count = 0;
    var Mocha = require('mocha');
    if (!Mocha._athenzExt) {
      Mocha._athenzExt = true;
      var run = Mocha.prototype.run;
      Mocha.prototype.run = function() {
        this.suite.on('pre-require', function() {
          // Anything that is shared across all tests should be put here.
          function screenshot(test) {
            if (test.state === 'failed') {
              var shotsDir = path.join(process.cwd(), 'artifacts/shots'),
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
    browser.ignoreSynchronization = true;
    var chai = require('chai');
    var chaiAsPromised = require('chai-as-promised');
    chai.use(chaiAsPromised);
    global.assert = chai.assert;
    global.expect = chai.expect;

    var getPassword = function(user, callback) {
      if (users[user] && users[user].password) {
        return callback(null, users[user].password);
      }
      /*
      var child = exec('docker', [
        '--tlsverify=0',
        'exec',
        '-t',
        'policy-ui',
        'getykey',
        user
      ]);
      */
      var child = exec('vagrant', [
        'ssh',
        '-c',
        'zms_ci_admin_password'
      ]);

      child.stderr.on('data', function(err) {
        callback(err.toString());
      });
      child.stdout.on('data', function(pass) {
        callback(null, pass.toString());
      });
    };

    if (!browser.newUser) {
      browser.newUser = function(user) {
        user = user || configUser;
        console.log('Browser User: ', user);
        return browser.driver.controlFlow().execute(function() {
          return new PromiseLib(function(fulfill, reject) {
            var c;
            if (users[user] && users[user].cookies) {
              c = users[user].cookies.USER;
              browser.driver.get(url);
              return browser.driver.manage().addCookie(c.name, c.value, c.path, c.domain, c.secure).then(function() {
                fulfill(users[user].cookies);
              });
            }
            getPassword(user, function(err, pass) {
              if (err) {
                return reject(err);
              }
              users[user] = users[user] || {};
              users[user].password = pass;
              sso.login(user, pass, function(serr, cookies) {
                if (serr) {
                  return reject(serr);
                }
                users[user].cookies = cookies;
                c = cookies.USER;
                browser.driver.get(url);
                browser.driver.manage().addCookie(c.name, c.value, c.path, c.domain, c.secure).then(function() {
                  fulfill(cookies);
                });
              });
            });
          });
        }, 'creating user');
      };
    }
  }
};

exports.config = config;
