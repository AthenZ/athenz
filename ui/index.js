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
'use strict';

process.chdir(__dirname);

var path = require('path');
var version = require('./package.json').version;
var express = require('express');
var favicon = require('serve-favicon');
var app = express();
var hbs = require('express-handlebars');

var pageUtils = require('./src/utils/page');
var hbsHelpers = require('./src/utils/handlebarHelpers');
var routeHandlers = require('./src/routeHandlers/main');
var searchRoutes = require('./src/routeHandlers/search');
var domainRoutes = require('./src/routeHandlers/domain');
var serviceRoutes = require('./src/routeHandlers/service');
var roleRoutes = require('./src/routeHandlers/role');
var policyRoutes = require('./src/routeHandlers/policy');
var userRoutes = require('./src/routeHandlers/user');
var config = require('./config/config.js')();

module.exports = app;

var busboy = require('express-busboy');
busboy.extend(app);

var exphbs = require('express-handlebars');
app.engine('handlebars', exphbs({ defaultLayout: 'main' }));
app.set('view engine', 'handlebars');
app.engine('handlebars', hbs.create({
  defaultLayout: 'main',
  helpers: hbsHelpers
}).engine);

// normalize request params
var normalized = require('express-normalized');
app.use(normalized());

var fs = require('fs');
var crypto = require('crypto');

var http = require('http');
var https = require('https');
var cookieParser = require('cookie-parser');
app.use(cookieParser());

app.use('/assets', express.static(path.join(__dirname, 'build', version)));
app.use('/imgs', express.static(path.join(__dirname, 'public', 'imgs')));
app.use('/fonts', express.static(path.join(__dirname, 'public', 'fonts')));

app.use(function(req, res, next) {
  req.config = config;
  next();
});

//Setup the REST Client factory after the config
var client = require('./src/rdl-rest.js')({
  apiHost: config.zms,
  rdl: require('./config/zms.json'),
  requestOpts: {
    strictSSL: config.strictSSL
  }
});

// middle-ware to redirect when there is trailing slash so that urls are
// guaranteed not to contain trailing slash
app.use(function(req, res, next) {
  if (req.url.substr(-1) === '/' && req.url.length > 1) {
    res.redirect(301, req.url.slice(0, -1));
  } else {
    next();
  }
});

// Verify user token
app.use(function(req, res, next) {
  if (req.cookies.cred && req.cookies.cred.body && req.cookies.cred.signature) {
    var pubkey = './keys/' + req.config.serviceFQN + '_pub.pem';
    fs.readFile(pubkey, 'utf8', function (err, publicKey) {
      if (err) {
        console.error('Failed load publicKey');
        next();
        return;
      }
      var verify = crypto.createVerify('sha256');
      verify.update(req.cookies.cred.body);
      verify.end();
      if (verify.verify(publicKey, req.cookies.cred.signature, 'base64')) {
        var cred = req.cookies.cred.body;
        req.cred = {};
        req.cred.body = JSON.parse(Buffer.from(cred, 'base64').toString());
        req.cred.encoded = cred;
        req.cred.signature = req.cookies.cred.signature;
      }
      next();
    });
  } else {
    next();
  }
});

// Authenticate user and receive user token
app.use(function(req, res, next) {
    var username;
  if (req.cred) {
    username = req.cred.body.username;
    next();
  } else if (req.body.username && req.body.password) {
    username = req.body.username;
    var password = req.body.password;
    var cred = Buffer.from(username + ':' + password).toString('base64');
    var options = {
      ca: fs.readFileSync('keys/zms_cert.pem'),
      host: process.env.ZMS_SERVER,
      port: 4443,
      path: '/zms/v1/user/_self_/token?services=' + req.config.serviceFQN,
      headers: {'Authorization': 'Basic '+cred}
    };
    var result = {};
    https.get(options, function(response) {
      response.setEncoding('utf8');
      var json = "";
      response.on('data',function(d) {
        json += d;
      }).on('end',function() {
        req.cred = {};
        req.cred.body = {
          username: username,
          'Athenz-Principal-Auth': JSON.parse(json).token
        };
        req.cred.encoded = Buffer.from(JSON.stringify(req.cred.body)).toString('base64');
        next();
      });
    }).on('error',function(err) {
      console.log(err);
      routeHandlers.notLogged(req, res);
    });
  } else {
    routeHandlers.notLogged(req, res);
  }
});

// Sign user token with service key
app.use(function(req, res, next){
  if (req.cred && req.cred.body && req.cred.body['Athenz-Principal-Auth']) {
    var token = req.cred.body['Athenz-Principal-Auth'];
    var key = './keys/' + req.config.serviceFQN + '.pem';
    var keyVersion = req.config.authKeyVersion;
    req.authSvcToken = userRoutes.signToken(token, key, keyVersion);
  }
  next();
});

// Sign user token
app.use(function(req, res, next){
  var key = './keys/' + req.config.serviceFQN + '.pem';
  fs.readFile(key, 'utf8', function (err, privateKey) {
    if (err) {
      console.error('Failed load privateKey');
      next();
      return;
    }
    var sign = crypto.createSign('sha256');
    sign.update(req.cred.encoded);
    var signature = sign.sign(privateKey, 'base64');
    var cred = {
      body: req.cred.encoded,
      signature: signature
    };
    res.cookie('cred', cred, {
      maxAge : 60000,
      httpOnly : false
    });
    next();
  });
});

app.use(function(req, res, next) {
  req.userCred = req.cred ? req.cred.body.username : req.config.user;
  req.user = {
    userDomain: 'user.' + req.userCred,
    login: req.userCred
  };

  req.cookiesForwardCheck = {};
  req.restClient = client(req, {
    'Athenz-Principal-Auth': function(currentReq) {
      if (currentReq.authSvcToken) {
        return currentReq.authSvcToken;
      }
      return null;
    }
  });

  res.locals.user = {
    name: req.userCred,
    icon: '/imgs/welcome_to_athenz.gif'
  };
  res.locals.originalUrl = pageUtils.cleanupOriginalUrl(req.originalUrl || '');
  res.locals.msg = [];
  res.locals.zms = req.config.zms;
  res.locals.serviceFQN = req.config.serviceFQN;

  next();
});

app.all('/', routeHandlers.redirect);
app.get('/athenz', routeHandlers.init, routeHandlers.home);
app.post('/athenz', routeHandlers.init, routeHandlers.home);

// Domain Routes
app.get('/athenz/domain/create/:domainType', routeHandlers.init, domainRoutes.addDomainsPage);
app.get('/athenz/domain/manage', routeHandlers.init, routeHandlers.manageDomains);
app.post('/athenz/domain/create/:domainType', domainRoutes.addDomain);
app.post('/athenz/domain/:domainId/delete', domainRoutes.deleteDomain);
app.post('/athenz/domain/:domainId/edit', domainRoutes.editDomain);

app.get('/athenz/domain/:domainId/:section', routeHandlers.init, routeHandlers.domainRoutes);

app.post('/athenz/domain/:domainId/role/add', roleRoutes.addRole);
app.post('/athenz/domain/:domainId/role/:role/delete', roleRoutes.deleteRole);

app.post('/athenz/domain/:domainId/service/add', serviceRoutes.addService);
app.post('/athenz/domain/:domainId/service/:service/delete', serviceRoutes.deleteService);
app.post('/athenz/domain/:domainId/service/:service/key/add', serviceRoutes.addKey);
app.post('/athenz/domain/:domainId/service/:service/key/:id/delete', serviceRoutes.deleteKey);

app.post('/athenz/domain/:domainId/policy/add', policyRoutes.addPolicy);
app.post('/athenz/domain/:domainId/policy/:policy/delete', policyRoutes.deletePolicy);
app.post('/athenz/domain/:domainId/policy/:policy/assertion/add', policyRoutes.addAssertion);
app.post('/athenz/domain/:domainId/policy/:policy/assertion/:id/delete', policyRoutes.deleteAssertion);

app.post('/athenz/domain/:domainId/member/add', domainRoutes.postMember);
app.post('/athenz/domain/:domainId/member/delete', domainRoutes.deleteMember);
app.post('/athenz/domain/:domainId/member/:member/delete', domainRoutes.deleteMember);

// Search Route
app.get('/athenz/search', routeHandlers.init, searchRoutes.searchResultsPage);

// AJAX Get routes
app.get('/athenz/ajax/domain/:domainId/role/:role/info', roleRoutes.getRoleRow);
app.get('/athenz/ajax/domain/:domainId/service/:service/info', serviceRoutes.getServiceRow);
app.get('/athenz/ajax/domain/:domainId/policy/:policy/info', policyRoutes.getPolicyRow);
app.get('/athenz/ajax/domain', domainRoutes.allDomains);

app.all('*', routeHandlers.notFound);
