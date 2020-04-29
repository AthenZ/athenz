/**
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

function notLogged(req, res) {
  var viewData = {
    pageTitle: 'Athenz UI login page',
    url: req.originalUrl,
    target: req.config.loginPath,
    redirect: req.query.redirect || '/athenz'
  };
  if (req.query && req.query.error) {
    res.locals.appContextMessage = '401 Unauthorized';
    res.locals.appContextMessageType = 'error';
  }
  if (req.method === 'GET' && req.originalUrl.indexOf('ajax') === -1) {
    return res.render('login', viewData);
  } else if(req.method === 'POST' && req.originalUrl.indexOf('ajax') === -1) {
    return res.redirect(req.body.redirect || '/athenz');
  }
  res.status(401).send('');
}

module.exports = {
  notLogged: notLogged
};

