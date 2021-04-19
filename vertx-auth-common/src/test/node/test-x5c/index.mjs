import fs from 'fs'
import jose from 'node-jose'
import pem from 'pem'

async function run () {
  try {
    // keystore to stick our node-jose keys before we do signing
    let keystore = jose.JWK.createKeyStore()

    // load in the private key
    let privatepem = fs.readFileSync('./private2048b.key', 'utf8')
    let privatekey = await keystore.add(privatepem, 'pem')

    // and the public key
    let publicpem = fs.readFileSync('./public2048b.crt', 'utf8')

    // we need the public key chain in x5c header. x5c header chain will be used during
    // decode, a full cert can be provided to ensure validation all the way to root
    // https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#page-9
    // unfortunately we can't just use plain jwk, since jwk is only the *key* and not the
    // full *certificate*, so ... x5c it is
    let x5cChain = cert_to_x5c(publicpem)

    // the message body
    let message = JSON.stringify({
      iss: 'vertx-auth-unit-tests',
      sub: '1234',
      bundle: '...'
    })

    // and signing options
    let signoptions = { fields: { x5c: x5cChain } }

    // sign 'message' with the 'privatekey', include the 'x5c' chain in the headers
    let signed = await jose.JWS.createSign(signoptions, privatekey).update(message, 'utf8').final()

    // bet you didn't think it would be that big
    console.log(signed.signatures[0].protected + '.' + signed.payload + '.' + signed.signatures[0].signature)
  } catch (err) {
    console.log(err)
  }
}

run()

// taken from (MIT licensed):
// https://github.com/hildjj/node-posh/blob/master/lib/index.js
function cert_to_x5c (cert, maxdepth) {
  if (maxdepth == null) {
    maxdepth = 0;
  }
  /*
   * Convert a PEM-encoded certificate to the version used in the x5c element
   * of a [JSON Web Key](http://tools.ietf.org/html/draft-ietf-jose-json-web-key).
   *
   * `cert` PEM-encoded certificate chain
   * `maxdepth` The maximum number of certificates to use from the chain.
   */

  cert = cert.replace(/-----[^\n]+\n?/gm, ',').replace(/\n/g, '');
  cert = cert.split(',').filter(function(c) {
    return c.length > 0;
  });
  if (maxdepth > 0) {
    cert = cert.splice(0, maxdepth);
  }
  return cert;
}
