'use strict';

var ybase64 = require('../../../src/util/YBase64');

var sinon = require('sinon');
var expect = require('chai').expect;
var sandbox;

var testMessage = 'testMessageToEncodeWithYBase64\n';

describe('YBase64 util', function() {
  beforeEach(function() {
    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('should ybase64 string eqals test data', function() {
    expect(ybase64.ybase64Encode(testMessage)).to.equal('dGVzdE1lc3NhZ2VUb0VuY29kZVdpdGhZQmFzZTY0Cg--');
    expect(new Buffer(testMessage).toString('base64').replace(/\+/g, '.').replace(/\//g, '_').replace(/=/g, '-')).to
      .equal('dGVzdE1lc3NhZ2VUb0VuY29kZVdpdGhZQmFzZTY0Cg--');
  });

  it('should string eqals ybase64 decoded test data', function() {
    expect(ybase64.ybase64Decode('dGVzdE1lc3NhZ2VUb0VuY29kZVdpdGhZQmFzZTY0Cg--').toString('UTF-8')).to.equal(testMessage);
    expect(ybase64.ybase64Decode('dGVzdE1lc3NhZ2VUb0VuY29kZVdpdGhZQmFzZTY0Cg--').toString('UTF-8')).to
      .equal(new Buffer(ybase64.ybase64Encode(testMessage).replace(/\./g, '+').replace(/_/g, '/').replace(/-/g, '='), 'base64').toString());
  });

  it('should test ybase64Decode: invalid input: result error', function() {
    try {
      ybase64.ybase64Decode(123456789);
    } catch (e) {
      expect(e.message).to.be.contain('is not string');
      return;
    }
    expect(1).to.be.false;
  });

});
