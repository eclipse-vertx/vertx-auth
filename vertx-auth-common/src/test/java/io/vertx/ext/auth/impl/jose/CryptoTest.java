package io.vertx.ext.auth.impl.jose;

import io.vertx.ext.auth.PubSecKeyOptions;
import org.junit.Test;

import static junit.framework.TestCase.assertFalse;
import static org.junit.Assert.assertNotNull;

/**
 * @author <a href="mailto:david@davidafsilva.pt">david</a>
 */
public class CryptoTest {

  @Test
  public void ecdsaSignatureComplianceTest() throws Exception {

    JWT jwt = new JWT()
      .addJWK(new JWK(
        new PubSecKeyOptions()
          .setAlgorithm("ES512")
          .setBuffer("-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQASisgweVL1tAtIvfmpoqvdXF8sPKTV9YTKNxBwkdkm+/auh4pR8TbaIfsEzcsGUVv61DFNFXb0ozJfurQ59G2XcgAn3vROlSSnpbIvuhKrzL5jwWDTaYa5tVF1Zjwia/5HUhKBkcPuWGXg05nMjWhZfCuEetzMLoGcHmtvabugFrqsAg=\n-----END PUBLIC KEY-----\n")));

    assertFalse(jwt.isUnsecure());
    //Test verification for token created using https://github.com/auth0/node-jsonwebtoken/tree/v7.0.1
    assertNotNull(jwt.decode("eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCIsImlhdCI6MTQ2NzA2NTgyN30.Aab4x7HNRzetjgZ88AMGdYV2Ml7kzFbl8Ql2zXvBores7iRqm2nK6810ANpVo5okhHa82MQf2Q_Zn4tFyLDR9z4GAcKFdcAtopxq1h8X58qBWgNOc0Bn40SsgUc8wOX4rFohUCzEtnUREePsvc9EfXjjAH78WD2nq4tn-N94vf14SncQ"));
    //Test verification for token created using https://github.com/jwt/ruby-jwt/tree/v1.5.4
    assertNotNull(jwt.decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJ0ZXN0IjoidGVzdCJ9.AV26tERbSEwcoDGshneZmhokg-tAKUk0uQBoHBohveEd51D5f6EIs6cskkgwtfzs4qAGfx2rYxqQXr7LTXCNquKiAJNkTIKVddbPfped3_TQtmHZTmMNiqmWjiFj7Y9eTPMMRRu26w4gD1a8EQcBF-7UGgeH4L_1CwHJWAXGbtu7uMUn"));
  }
}
