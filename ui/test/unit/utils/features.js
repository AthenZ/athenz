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

var featureUtils = require('../../../src/utils/features.js');
var expect = require('chai').expect;


describe('pagination', function() {
  beforeEach(function() {
    featureUtils.setFeatures({features: false});
  });

  it('should show feature disabled for false values', function() {
    expect(featureUtils.isEnabled('feature')).to.be.false;
    expect(featureUtils.isEnabled('newfeature')).to.be.false;
  });

  it('should show feature enabled for true value', function() {
    featureUtils.setFeatures({feature: true});
    expect(featureUtils.isEnabled('feature')).to.be.true;
  });

  it('should show feature enabled for whitelisted by user id', function() {
    featureUtils.setFeatures({feature: 'jim,karen,indy'});
    expect(featureUtils.isEnabled('feature', 'karen')).to.be.true;

    expect(featureUtils.isEnabled('feature', 'boo')).to.be.false;
  });
});
