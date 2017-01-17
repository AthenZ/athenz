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

function isUserAllowed(userId, featureValue) {
  var valueArr = featureValue.split(',');
  return valueArr.indexOf(userId) !== -1;
}

var features = {};

/**
 * A feature value can have one of the following 3 values
 * 1. false 2. true 3. A CSV of by ids
 */
module.exports = {
  isEnabled: function(feature, user) {
    var featureValue = features[feature];
    if (!featureValue) {
      return false;
    }

    if (true === featureValue || isUserAllowed(user, featureValue)) {
      return true;
    }

    return false;
  },
  setFeatures: function(config) {
    features = config;
  }
};
