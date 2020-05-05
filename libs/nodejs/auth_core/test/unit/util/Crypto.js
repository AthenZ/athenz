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

var fs = require('fs');

var ybase64 = require('../../../src/util/YBase64');
var crypto = require('../../../src/util/Crypto');
var helpers = require('../../config/helpers');

var sinon = require('sinon');
var expect = require('chai').expect;
var sandbox;

var privateKey = Buffer.from(fs.readFileSync(process.cwd() + '/test/resources/unit_test_private_k0.pem', 'utf8'));
var publicKey = Buffer.from(fs.readFileSync(process.cwd() + '/test/resources/public_k0.pem', 'utf8'));

var testSharedSecret = 'testSharedSecretString';
var testMessage = 'testMessageString\n';
var digestAlgorithm = 'RSA-SHA256';

describe('Crypto util', function() {
  beforeEach(function() {
    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('should hmac digest eqals test data', function() {
    expect(crypto.hmac(testMessage, testSharedSecret)).to.equal('mmReH0yvVj.2Dq0l6MWD5bQys4ucYNevmWDv_x.2fcM-');
  });

  it('should signeture eqals test data with ybase64 key', function() {
    expect(crypto.sign(testMessage, privateKey, digestAlgorithm)).to
      .equal('WKXwUwB9wsAKFOURhE914X9GMlBogFITqvmNmr08b0OZoPt.ot_wFfRI6faiEzV_g4vwV9nU4FNBJ1TS.afoQmxsaA38ERnjadYMPOgb2EOJyDid57qCQ7.BJomyNar0hXpNZHDT1pOYrnVle0B49ov5EVqEGk9njFQ3wsJBBY5KiP4u0QK9sX8r5XL0_gij4zsNiIIokm6Isda_IXTd3Jh2Zf99fn9Tev8ZED.iFmpqfK55xG2_k7jKN9g9TP3ouJHSIKsguzQHWWZjGZiqhvDqlS5vdeKoNYTRElDbkNy3or6JG9NUdc7LgYKozG5WFxvFEScBWDOzT.tJEmT7TQ--');
    expect(crypto.sign(testMessage, ybase64.ybase64Decode(helpers.privateKey), digestAlgorithm)).to
      .equal('WKXwUwB9wsAKFOURhE914X9GMlBogFITqvmNmr08b0OZoPt.ot_wFfRI6faiEzV_g4vwV9nU4FNBJ1TS.afoQmxsaA38ERnjadYMPOgb2EOJyDid57qCQ7.BJomyNar0hXpNZHDT1pOYrnVle0B49ov5EVqEGk9njFQ3wsJBBY5KiP4u0QK9sX8r5XL0_gij4zsNiIIokm6Isda_IXTd3Jh2Zf99fn9Tev8ZED.iFmpqfK55xG2_k7jKN9g9TP3ouJHSIKsguzQHWWZjGZiqhvDqlS5vdeKoNYTRElDbkNy3or6JG9NUdc7LgYKozG5WFxvFEScBWDOzT.tJEmT7TQ--');
  });

  it('should result be true with ybase64 key and ybase64 signeture', function() {
    expect(crypto.verify(testMessage, publicKey, 'WKXwUwB9wsAKFOURhE914X9GMlBogFITqvmNmr08b0OZoPt.ot_wFfRI6faiEzV_g4vwV9nU4FNBJ1TS.afoQmxsaA38ERnjadYMPOgb2EOJyDid57qCQ7.BJomyNar0hXpNZHDT1pOYrnVle0B49ov5EVqEGk9njFQ3wsJBBY5KiP4u0QK9sX8r5XL0_gij4zsNiIIokm6Isda_IXTd3Jh2Zf99fn9Tev8ZED.iFmpqfK55xG2_k7jKN9g9TP3ouJHSIKsguzQHWWZjGZiqhvDqlS5vdeKoNYTRElDbkNy3or6JG9NUdc7LgYKozG5WFxvFEScBWDOzT.tJEmT7TQ--', digestAlgorithm)).to.equal(true);
    expect(crypto.verify(testMessage, ybase64.ybase64Decode(helpers.publicKey), 'WKXwUwB9wsAKFOURhE914X9GMlBogFITqvmNmr08b0OZoPt.ot_wFfRI6faiEzV_g4vwV9nU4FNBJ1TS.afoQmxsaA38ERnjadYMPOgb2EOJyDid57qCQ7.BJomyNar0hXpNZHDT1pOYrnVle0B49ov5EVqEGk9njFQ3wsJBBY5KiP4u0QK9sX8r5XL0_gij4zsNiIIokm6Isda_IXTd3Jh2Zf99fn9Tev8ZED.iFmpqfK55xG2_k7jKN9g9TP3ouJHSIKsguzQHWWZjGZiqhvDqlS5vdeKoNYTRElDbkNy3or6JG9NUdc7LgYKozG5WFxvFEScBWDOzT.tJEmT7TQ--', digestAlgorithm)).to.equal(true);
  });

  it('should result be true with ybase64 key and base64 signeture', function() {
    expect(crypto.verify(testMessage, publicKey, 'WKXwUwB9wsAKFOURhE914X9GMlBogFITqvmNmr08b0OZoPt+ot/wFfRI6faiEzV/g4vwV9nU4FNBJ1TS+afoQmxsaA38ERnjadYMPOgb2EOJyDid57qCQ7+BJomyNar0hXpNZHDT1pOYrnVle0B49ov5EVqEGk9njFQ3wsJBBY5KiP4u0QK9sX8r5XL0/gij4zsNiIIokm6Isda/IXTd3Jh2Zf99fn9Tev8ZED+iFmpqfK55xG2/k7jKN9g9TP3ouJHSIKsguzQHWWZjGZiqhvDqlS5vdeKoNYTRElDbkNy3or6JG9NUdc7LgYKozG5WFxvFEScBWDOzT+tJEmT7TQ==', digestAlgorithm)).to.equal(true);
    expect(crypto.verify(testMessage, ybase64.ybase64Decode(helpers.publicKey), 'WKXwUwB9wsAKFOURhE914X9GMlBogFITqvmNmr08b0OZoPt+ot/wFfRI6faiEzV/g4vwV9nU4FNBJ1TS+afoQmxsaA38ERnjadYMPOgb2EOJyDid57qCQ7+BJomyNar0hXpNZHDT1pOYrnVle0B49ov5EVqEGk9njFQ3wsJBBY5KiP4u0QK9sX8r5XL0/gij4zsNiIIokm6Isda/IXTd3Jh2Zf99fn9Tev8ZED+iFmpqfK55xG2/k7jKN9g9TP3ouJHSIKsguzQHWWZjGZiqhvDqlS5vdeKoNYTRElDbkNy3or6JG9NUdc7LgYKozG5WFxvFEScBWDOzT+tJEmT7TQ==', digestAlgorithm)).to.equal(true);
  });

  it('should result be false with wrong ybase64 key and ybase64 signeture', function() {
    expect(crypto.verify(testMessage, ybase64.ybase64Decode('LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF4OHErZWJ5MkM1RjZBU0cvQ2NTdgpJZk1nbFFKOUFHSXJJUldncGxKRGhPY2tBUnpDMWZyZjNrbkM5UHlOV25tcHhkai9hYkZXczE5RDhmYVRLK2lsCjNUMkpnTHAzcHN6c1N4QUZjS3VFZjVwU0tybk4xYWpGSitIYUU4cmkrQ1V5T3F1azN4dEkrS0ZZakFVQ2t3RXMKQTVMZDJGZStneU5xOWh0KzRsZjhrZ1lZVnArd3Zpai9pZTdST2Jia3ZsVkh2UjFaOUJJY2F1Sytyb1g5cjVhVwptVEVsRHRidTcyN3pNZWRqM1dPTTJhTHJiQmgvbm1rV28yQ0xIc0gydUhhVGtvbkxjQ0ZLL1BlK2cyclhHZVVaCnQzMm14UmErNzlqNmhHVDdKYUllU2dEcnVMMXMyWDFyd0UvUGlCS00zM1JxeUFQalB1eFRsODNKclpmZmIza1MKdlFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg--'), 'gMxEtUsPcsfPizj9Q6yh_Gx2lnbCv9.zTg96L82Fwh6TJ8KdX2qHx0GbX4598dtczgkKL3fpfE_ojyjuLsVUIjD9TnDm0CJOb2RTwOzN3jPQLW0ge0nfC2IlWfJSC_M9uo3orRVEgJrZ9amISfA1GcqT4Fxge64rLXp87cguRtofx3M5dBdfOKCcHEhvd9iCrZoqFLoXCa24MD6ZoE71pXS2u6b47xmLCf6UqQ9r9bEmRVWfqTXYp_GAv_Yz73bz0FmIk_VwaZm541J_bkD8RrYYwovZ9O2aUAIWcceSblNZVPz98ijpsGDSPDh_CXNbRL6XRktKo8dRh8x9nfUy4Q--', digestAlgorithm)).to.equal(false);
  });

  it('should test randaomSalt', function() {
    var salt = crypto.randomSalt();

    expect(salt).to.be.a('string');
    expect(salt.length).to.equal(8);
  });
});
