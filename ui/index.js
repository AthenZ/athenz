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
var middleware = require('./src/utils/middleware.js');
var routeHandlers = require('./src/routeHandlers/main');
var searchRoutes = require('./src/routeHandlers/search');
var domainRoutes = require('./src/routeHandlers/domain');
var serviceRoutes = require('./src/routeHandlers/service');
var roleRoutes = require('./src/routeHandlers/role');
var policyRoutes = require('./src/routeHandlers/policy');
var userRoutes = require('./src/routeHandlers/user');
var config = require('./config/config.js')();

var loginUtils = require(config.loginUtils);
var routesUtils = require(config.routesUtils);

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
app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));

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
app.use(middleware.redirectOnTrailingSlash);

loginUtils.signUserToken(app);
loginUtils.authenticateUser(app);
loginUtils.saveCookie(app);

app.use(function(req, res, next) {
  req.cookiesForwardCheck = {};
  req.restClient = client(req, {
    cookie: function(currentReq) {
      if (currentReq.cookiesForwardCheck[currentReq.currentMethod]) {
        return currentReq.headers.cookie;
      }
      return null;
    },
    [req.config.authHeader]: function(currentReq) {
      if (currentReq.authSvcToken) {
        return currentReq.authSvcToken;
      }
      return null;
    }
  });

  res.locals.user = {
    name: req.username,
    icon: req.config.userIcon(req.username),
    link: req.config.userLink(req.username)
  };
  res.locals.originalUrl = pageUtils.cleanupOriginalUrl(req.originalUrl || '');
  res.locals.msg = [];
  res.locals.zms = req.config.zms_ajax || req.config.zms;
  res.locals.serviceFQN = req.config.serviceFQN;
  res.locals.athenzScript = req.config.athenzScript;
  res.locals.headerLinks = req.config.headerLinks;
  res.locals.userDomain = req.config.userDomain;

  next();
});

app.use(function(req, res, next) {
  //Check for CSRF, if bad origin, force re-auth
  if (req.get("origin") && req.get("host") !== req.get("origin").split("/")[2]) {
    res.redirect(302, "/athenz/login?error=1");
  }else{
    next();
  }
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

// Additional routes
routesUtils.add(app);

app.all('*', routeHandlers.notFound);
