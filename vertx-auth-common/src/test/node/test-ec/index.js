var assert = require('assert');
var fs = require('fs');
var jwt = require('jsonwebtoken');

describe('JWT', function () {
  describe('interop', function () {
    it('should verify a token generated from Vert.x', function () {

      // One way to create a key pair is:
      // openssl ecparam -name secp256r1 -genkey -param_enc explicit -out ecdsa-private.pem
      // openssl ec -in ecdsa-private.pem -pubout -out ecdsa-public.pem

      // but we just reuse the keytool one (we need to mark the begin/end so the node api can process it)
      var PUBKEY = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwq481nd4jdkvwYCck6CaC+obxrrLOdArA28iPxkKyRw687M7WJZI4OGnIMx97uSuANNCb7SllqoKvYJix+0OMg==\n-----END PUBLIC KEY-----';

      var token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoidGVzdCIsImlhdCI6MTQ5OTA3Mzg5Nn0.TVZyzs1KNXywNi3MEv5UuoHl9lq9kBvIBRk1C5Qj8SdMhmlqHmFh1OtAJDmeyiDOxEbg-nfiVLrQAL9HpkNcDA';
      // the token was created from the private key above in vert.x using:
      // String signed = sk.sign(new JsonObject().put("test", "test"), new JsonObject().put("algorithm", "ES256"));

      var decoded = jwt.verify(token, PUBKEY);
      assert.equal('test', decoded.test);
    });
  });
});

