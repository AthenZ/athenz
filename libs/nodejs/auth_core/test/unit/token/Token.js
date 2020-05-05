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

var Token = require('../../../src/token/Token');

var fs = require('fs');
var sinon = require('sinon');
var expect = require('chai').expect;
var sandbox;

var privateKey = Buffer.from(fs.readFileSync(process.cwd() + '/test/resources/unit_test_private_k0.pem', 'utf8'));
var publicKey = Buffer.from(fs.readFileSync(process.cwd() + '/test/resources/public_k0.pem', 'utf8'));
var publicKey01 = Buffer.from(fs.readFileSync(process.cwd() + '/test/resources/public_k1.pem', 'utf8'));

var unsignedToken = 'testUnsignedToken';
var signature = 'FKO8UyQ4zWolsfAGrD5oFj46kcC8c9Vv24F4K8Lt8XFrh_DBZw7QcBn8ctK8y3twVX10OgTKgLN4IsHlcp6GIHiBZPS0QEKPnXAWfUfJnzwt_bvbDMwSG4xQeyNQnuQZmwKvB.NOL7VF7xJd3BuffN66nzFIepysqzd0.4HuTfi8a4jim6xxYeU3npW1_8c5HUMr72MDb5.JEoAJ1nuq.LlCWIxmH0gdgXeJ9BjxwNfj4FKCvsfltG2x6Gpizp0xRJjyZl72yhI6zVR87_9vRyJvj05jUeJXtZSVLl3mxVoRHef4PVGIftDVmE1eaUi_4RgAifN25ch4EDr18VrXvQ--';

describe('Token impl', function() {
  beforeEach(function() {
    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('should test sign', function() {
    var token = new Token();
    try {
      token._unsignedToken = unsignedToken;
      token.sign(privateKey);
    } catch (e) {
      expect(1).to.be.false;
      return;
    }
    expect(token.getSignature()).to.equal(signature);
  });

  it('should test sign: invalid argument: result error', function() {
    var token = new Token();
    var signature = null;
    try {
      token._unsignedToken = unsignedToken;
      signature = token.sign('dummyPriKey');
    } catch (e) {
      expect(e.message).to.contain('Crypto:sign:');
      return;
    }
    expect(1).to.be.false;
  });

  it('should test setTimeStamp', function() {
    var token = new Token();
    token.setTimeStamp(1000, 30);

    expect(token.getTimestamp()).to.equal(1000);
    expect(token.getExpiryTime()).to.equal(1030);
  });

  it('should test setTimeStamp: issueTime < 0', function() {
    var token = new Token();
    token.setTimeStamp(-100, 30);

    expect(token.getTimestamp()).to.be.a('number');
    expect(token.getExpiryTime()).to.be.a('number');
  });

  it('should test setTimeStamp', function() {
    var token = new Token();
    token.setTimeStamp(1000, 30);

    expect(token.getTimestamp()).to.equal(1000);
    expect(token.getExpiryTime()).to.equal(1030);
  });

  it('should test validate', function() {
    var token = new Token();
    token.setTimeStamp(0, 500);
    token._unsignedToken = unsignedToken;
    token._signature = signature;

    expect(token.validate(publicKey, 1000, true)).to.true;
  });

  it('should test validate: null unsignedToken or null signature: result false', function() {
    var token = new Token();
    token.setTimeStamp(0, 500);
    token._unsignedToken = unsignedToken;
    token._signature = null;

    expect(token.validate(publicKey, 1000, true)).to.false;

    token._unsignedToken = null;
    token._signature = signature;

    expect(token.validate(publicKey, 1000, true)).to.false;
  });

  it('should test validate: null publicKey: result false', function() {
    var token = new Token();
    token.setTimeStamp(0, 500);
    token._unsignedToken = unsignedToken;
    token._signature = signature;

    expect(token.validate(null, 1000, true)).to.false;
  });

  it('should test validate: timeStamp over now: result false', function() {
    var token = new Token();
    token.setTimeStamp(Math.floor(Date.now() / 1000) + 2000, 500);
    token._unsignedToken = unsignedToken;
    token._signature = signature;

    expect(token.validate(publicKey, 100, true)).to.false;
  });

  it('should test validate: now over expiryTime: result false', function() {
    var token = new Token();
    token.setTimeStamp(10, 10);
    token._unsignedToken = unsignedToken;
    token._signature = signature;

    expect(token.validate(publicKey, 100, true)).to.false;
  });

  it('should test validate: expiryTime over now + allowedOffset: result false', function() {
    var token = new Token();
    token.setTimeStamp(0, 40 * 24 * 60 * 60);
    token._unsignedToken = unsignedToken;
    token._signature = signature;

    expect(token.validate(publicKey, 30, true)).to.false;
  });

  it('should test validate: other publicKey: result false', function() {
    var token = new Token();
    token.setTimeStamp(0, 500);
    token._unsignedToken = unsignedToken;
    token._signature = signature;

    expect(token.validate(publicKey01, 1000, true)).to.false;
  });

  it('should test validate: invalid publicKey: result false', function() {
    var token = new Token();
    token.setTimeStamp(0, 500);
    token._unsignedToken = unsignedToken;
    token._signature = signature;

    expect(token.validate('testPublicKey', 1000, true)).to.false;
  });
});


