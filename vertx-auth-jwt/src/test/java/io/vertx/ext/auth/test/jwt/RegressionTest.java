package io.vertx.ext.auth.test.jwt;

import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.jwt.JWTOptions;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(VertxUnitRunner.class)
public class RegressionTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void testKeyPairVerify(TestContext should) {

    JsonObject claims = new JsonObject()
      .put("deviceId", "123456789");
    JWTOptions jwtOptions = new JWTOptions()
      .setAlgorithm("RS256")
      .setExpiresInMinutes(10_080) // 7 days
      .setIssuer("10k-steps-api")
      .setSubject("paulo");

    JWTAuth jwtAuth = JWTAuth.create(rule.vertx(), new JWTAuthOptions()
      .addPubSecKey(new PubSecKeyOptions()
        .setAlgorithm("RS256")
        .setBuffer("-----BEGIN PUBLIC KEY-----\n" +
          "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtJ8yf+Qjg55lixUpuXqm\n" +
          "bvpSo/QazKK9xY6wjOiEUX714p7v9lc2lGqOoHGbVzRoLXW4obfLrsJSunmxLE+y\n" +
          "L+SVLNOfKRz5Rt1bcwXuFa/XqmFzrwqHDyOyR1+GsrBlAo4655XpShYIxBeR0Dlm\n" +
          "KqhOcXhUEYDelYozRiDtVCposiRjGbrQi0VxAHYkyKMqraKDyX6FN5gl6w4odPJr\n" +
          "98mEINuTsJwve+R8uYGkwhTy79nrxbH+wiFwwQu32jUeqIXFATcsONSkd0jj8d8l\n" +
          "i3QnQdB+128JKDFh33Uj0AON1BSPxLgWCEtu7ZwT2+OmWQ64uHC3jFAexfKQZ7T/\n" +
          "twIDAQAB\n" +
          "-----END PUBLIC KEY-----\n"))
      .addPubSecKey(new PubSecKeyOptions()
        .setAlgorithm("RS256")
        .setBuffer("-----BEGIN PRIVATE KEY-----\n" +
          "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0nzJ/5CODnmWL\n" +
          "FSm5eqZu+lKj9BrMor3FjrCM6IRRfvXinu/2VzaUao6gcZtXNGgtdbiht8uuwlK6\n" +
          "ebEsT7Iv5JUs058pHPlG3VtzBe4Vr9eqYXOvCocPI7JHX4aysGUCjjrnlelKFgjE\n" +
          "F5HQOWYqqE5xeFQRgN6VijNGIO1UKmiyJGMZutCLRXEAdiTIoyqtooPJfoU3mCXr\n" +
          "Dih08mv3yYQg25OwnC975Hy5gaTCFPLv2evFsf7CIXDBC7faNR6ohcUBNyw41KR3\n" +
          "SOPx3yWLdCdB0H7XbwkoMWHfdSPQA43UFI/EuBYIS27tnBPb46ZZDri4cLeMUB7F\n" +
          "8pBntP+3AgMBAAECggEATM7J7cK5K3ZHHg7g0GQMtHK0g84BO3YVFxankzQpWHKR\n" +
          "403NI0dRCWoKvsWw1jON/Y7q9bIv5l/ySCQJqJs3XdBpc0eGjjgo9O6avd4OsaA2\n" +
          "KNkKFax3ZIO8g0dnA0OpoJ2VBPgl3YBjN+gB9LcD8C3kNbKCpXLUtGixhyfnZHtw\n" +
          "5Ql0toYhdWOkZaBNG5cpydoWjWqNGyXi9Sq3nEiKHpShuQb2JuKJjjdpppY+0pbs\n" +
          "tjrs5i4kE0o8CFub1rWo+G7DrkFSMVyeMWdgtdnyZ+YHuGRRuVJoLf3RTJIMcEuD\n" +
          "rzkYfQrsPcSMeAh8uOQ2zQKmDKuiIfqlt8RBZU/qwQKBgQDn111ENH1ON3poTssd\n" +
          "1T9mdUG7SOVSFjLRM04n7DzY4T2fm5h7NepJwaAEYPfV4wl7Vsy8LbTohiIaXs4o\n" +
          "FF1/BjYIzzHqTUSqUD5/K9Zk+pBflaGX+kPQFkiu04Xqu4T2lMGr0h8jB6ODzo4n\n" +
          "/qTrt9qIffX7dYX9h0w85hFuoQKBgQDHcX7pw8lyPPcjGc+GYKvMXjAmUmIwrjus\n" +
          "FXB2yINAOLhUuC6cDKRtSQP+9tkRoqsrWEa+P6z3Nbh78G5o+mYnZllJkLCRthM1\n" +
          "xw117jwLJa2Khx41yGFN9HM1vTVryF82UiNuC9PBG6L7xRa25S6jZYwDezcEwKWX\n" +
          "ZfcfkIIHVwKBgGpYodGdejUcwauDKSzAGtr2wnYUVAy5XgoUTK+Hb8nUWB4Uk3dB\n" +
          "Hf1DMhGQIV8dS8Yl5LgVBzz5+j66ajp8TP7tbG/SCwV8+Bhfwqs3AptDTGJsErnR\n" +
          "9LVI44I+SNmJts4dIlGciufYoyrc3tx9tEzkAvxFO0ZjfFj1bQUqS6jBAoGAC5nK\n" +
          "bAZ7XS22olAKBiLxWz3PRytbksFPrz6//+jB2aZy8lqUO3dwyPqKRPZOwfvYQPkt\n" +
          "hDtn8CkrxenCQlDuSDRn1SOZYaBZlbMyUT2+OFfEtF4Pn8k7/7DMUr/ir5ZEE4DL\n" +
          "lscRVhYpcMOSAqlqAQ8TCdDM7nXWK+w+Z5OcPJkCgYEAnXWyc5cqEQxOxXr3f1x7\n" +
          "OhHOpThn4Tydz9bKOYIQhtNVdOA4ncUfcdLTKx0iJx/nvtysRUEzKpyxfkbGK75N\n" +
          "a6kamaIjOMtahgZJ/NiOiE5PF19UZyY/E5vXZTBAUsOI3r+mLhuDxYC67PfVSt3D\n" +
          "Mnj3LzastNMlixPEqjmWXUM=\n" +
          "-----END PRIVATE KEY-----\n")));

    String token = jwtAuth.generateToken(claims, jwtOptions);
    System.out.println(token);
    String token2 = jwtAuth.generateToken(claims, jwtOptions);
    System.out.println(token2);
  }
}
