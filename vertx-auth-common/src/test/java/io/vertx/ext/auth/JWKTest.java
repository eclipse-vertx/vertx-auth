package io.vertx.ext.auth;

import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.jose.JWK;
import io.vertx.ext.auth.impl.jose.JWT;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

public class JWKTest {

  @Test
  public void publicRSA() {
    JsonObject jwk = new JsonObject()
      .put("kty", "RSA")
      .put("n", "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
      .put("e", "AQAB")
      .put("alg", "RS256")
      .put("kid", "2011-04-29");

    new JWK(jwk);
  }

  @Test
  public void publicEC() {
    JsonObject jwk = new JsonObject()
      .put("kty", "EC")
      .put("crv", "P-256")
      .put("x", "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")
      .put("y", "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")
//      .put("use", "enc")
      .put("kid", "1");

    new JWK(jwk);
  }

  @Test
  public void privateEC() {
    JsonObject jwk = new JsonObject()
      .put("kty", "EC")
      .put("crv", "P-256")
      .put("x", "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")
      .put("y", "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")
      .put("d", "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE")
//      .put("use", "enc")
      .put("kid", "1");

    new JWK(jwk);
  }

  @Test
  public void privateRSA() {
    JsonObject jwk = new JsonObject()
      .put("kty", "RSA")
      .put("n", "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
      .put("e", "AQAB")
      .put("d", "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q")
      .put("p", "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs")
      .put("q", "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk")
      .put("dp", "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0")
      .put("dq", "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk")
      .put("qi", "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU")
      .put("alg", "RS256")
      .put("kid", "2011-04-29");

    new JWK(jwk);
  }

  @Test
  public void keycloakRSA() {
    JsonObject jwk = new JsonObject()
      .put("kty", "RSA")
      .put("n", "m8fbXeoEBu1eRE1Tsgq_L414mbiNPOhFNT20jKM-rd6nspp-7xoCsuYfuqUwEgAYAB_kRnTwcZj_SZXiQvauvM4-Howa6VpwPriZc3BRpzT4LBiskYBqoXslmRq7KMrNi0X-NKw4U1GIVfbYSSeoODpVj2IvC8hYUvzRF8w989DNHlduFyHweXcsOmGlHb9KZNyYy5N2zGNy5WHdtRuwGie7J5yKsJ4y0-YsJQG2GrkgDCa1ulS961KIrqLCEdLkoTsvJvnGPEXbajOQ2tIuh3iiIXY3QfMF05908Mhr0vzdApeHSdYrvv6WTyu66xj6prm_TaWcyfCqubYb53MIqQ")
      .put("alg", "RS256")
      .put("e", "AQAB")
      .put("use", "sig")
      .put("kid", "-s66_hGKPJ6ISSKeQyxslRl-cjQaqvcxoUlqIWj4CxM");

    JWK key = new JWK(jwk);
  }

  @Test
  public void x509CertChain() {

    JWT jwt = new JWT();

    try {
      // this certificate is expired
      // it should be ignored from the final list
      jwt.addJWK(new JWK(new JsonObject()
        .put("kty", "RSA")
        .put("alg", "RS256")
        .put("x5c", new JsonArray().add(
          "MIIDJjCCAg6gAwIBAgIIZtJv8PyRUgowDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UEAxMrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAeFw0xNzEwMDgxMTQzMzRaFw0xNzEwMTExMjEzMzRaMDYxNDAyBgNVBAMTK2ZlZGVyYXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6fNn5kfLZQ43Z+ZTqFMUF+dN2L2BphQKzgaWCsyzyJYwEySgMxbO8cQgTlgZzcC1Rt6phWHMBkFQQNykSk/K0A8xaaNqFNNVzeszR+XJ3IvCQGo8rS2K/LrNofGZrph00k6DZ7XJsWav0GotAwDd0H6IsNbFHCyRJ75ASzZr8fT8RJ9bQeTLoCsmwPXYBPeSvoWgZzOypbmLhohw0J7fBUbgVZ8fR3crhv6RDOp4/fDALWxCVPptFn0hMPeT2Dla9kbnPfVSWtciyvty5JJXnpuoqA6rLfEpMGYnMSk+SbD2R0W9O2LMRfoJ52qml+2s/aLpNKGJc2vLzDyH7CiavAgMBAAGjODA2MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQAlDoCH/E43ruorgPIATCO++dOfOIb/n+NgE727UeK1acELi+dUjSdYEe+WXdY2sichgE1JqPrsMWFHCwHTUfVubmku5BTklj9k6F9jKc+XDMra1w0KGSGrxwSqwYhkhSdMOGGa9C3td+s7M/E4JV+XoQXAY3uEaB0lO4c+pckDwU/LAGrMldogT3+zE+4NRS7p8dstnww3OIHUCFfytbhcY8sH4VjqdMWGrv8R/1L0jXok8vFPEAwvXzVc3NeUClio0hOEmhTjbLgebsgToB1aNC1pnzmHTclVndTwDcnDkhImpvuWE1lX+KPkFJ54ixS4Bi2cqWud1aQ2Mqi7KHfK"
        ))));

      fail("Should fail to load this certificate because it expired in 2017");
    } catch (RuntimeException e) {
      // OK
    }

    try {
      // this certificate is expired
      // it should be ignored from the final list
      jwt.addJWK(new JWK(new JsonObject()
        .put("kty", "RSA")
        .put("alg", "RS256")
        .put("x5c", new JsonArray().add(
          "MIIDJjCCAg6gAwIBAgIIeABc0/4wb7AwDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UEAxMrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAeFw0xNzEwMDkxMTQzMzRaFw0xNzEwMTIxMjEzMzRaMDYxNDAyBgNVBAMTK2ZlZGVyYXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3ICz+C7FKE4jbsRh/cZK1I9M5lXGlyvk8c72BuK3/uLwnRH5eSrooA1LEqwVdKV5MOTuHHnxWFb57yyBl8Ld3CGK/aeZYIGd6iV8ym/jw6rCdJhkL6yCZ3/Xj3+Un+5Vf+ObjHd04X/GbwleFRcldJilpgwtt0PKT/JBl/lKqTzzH/HWzdp3tj5gfVJzj1NxfN4K0GSFDy/5pRYsT9NebFC/JoBgSXrEEZXaigqQsYiI+lTDL59TLq8XaaT0V1sfoHnspu3DikgO51eJBP3c0wB2CvXxk+vMlSQMsnDcsztiijGPwrpxrLwDyzsm3Rs7WI9kDHPeUeKhGX0/s9AnBAgMBAAGjODA2MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQAiZt536sXwNXqUs92edWsQ+uiraJblATuMSslrQhGJjUebmlpIUMe8Dv2dj+/bYK7gZyjUQKwjmtCJ+U8Z2Ec/v9yEqKpyzfYIOTF/17d31OvisnccIbjBL2X+b/OHsFDjaY5hZrs0mczr1ePaYlE/EsyIFEZCwGbgarp7FxlRrdJEBN8jnjUgK6Kig2GLtcQcHfkIjxmVDzgS47TAtxPNTBGQypWubALTWt+WTAFpQGcW6pj9nOxuV2XB4RkFg7XrHtnBvad4/KAD/kp2if6BFyvwWcyQzKqqKcjJHinaGWf7qlBLBJTQcZcWPJEzFdwBsHHejgU8vy9hR97rvU8s"
        ))));

      fail("Should fail to load this certificate because it expired in 2017");
    } catch (RuntimeException e) {
      // OK
    }

    try {
      // this certificate is expired
      // it should be ignored from the final list
      jwt.addJWK(new JWK(new JsonObject()
        .put("kty", "RSA")
        .put("alg", "RS256")
        .put("x5c", new JsonArray().add(
          "MIIDJjCCAg6gAwIBAgIIcz32mW0b5V8wDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UEAxMrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAeFw0xNzEwMDcxMTQzMzRaFw0xNzEwMTAxMjEzMzRaMDYxNDAyBgNVBAMTK2ZlZGVyYXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDDmL6MaLATK497Ce9H6UVx4FFiHiDH3X44UtonDCvzIKtJVzMCDJzXDLAUEKxQEMGEekpJWKWogYbZ8iqF1fb8gUn47Fi9cOYm1gXr2RZNp9mMW2cCXwR0iqPVf7LfU+b2BgP+th4sbcJmE0uMgT/L1+Tn8xs45zRn5uvj/DOKeDod8REhNsA4B8J3xGLT+1cOpiCL4LUL+CzYeF5gQhaqlnax7xSwa8iDa5484JXwbdrR+6+HqGCO62yl8n9Ufd54fBjDJjOJ6r6wNZzJXmoaWcmn1NmVn3PbjZZ1gePcLaS501NSDvqnqy9uzpy7VmJkD1ZmRov13yFZ4ni0tCDdAgMBAAGjODA2MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQAfVSQFYR21K1IynPE/g0aYueSQHvbo7SaT/iCmLS4g4EXqpGFGSMgQZWe9FckFYqAkJZ8AS2BtlzflfNYBH9K6V++sm5xxhsH+DmS/dXUQrSWuwKc5sS385D5kg2vJlqO1snCYOg1iEMkvU36mEO3o0kAi+2g1NWOWiCFLLqoC4onmwDKv/K5qpwb2n3+IUbaS8R/cgGsq6B7ohCSrdHfErOOitNsynLO733lcFJKYxrYu4/OpvGkKBaxGf8h1BsDmNfenfYq4ak0N+8nTxPfc0fARyCkHSJPQ5WWMfi14d7J6hjc8qZHIDsAiJ50LB36Nk9p+KEQT5yh3UFbPXJO6"
        ))));

      fail("Should fail to load this certificate because it expired in 2017");
    } catch (RuntimeException e) {
      // OK
    }

    try {
      jwt.decode("eyJhbGciOiJSUzI1NiIsImtpZCI6Ijc0MjQzMGI2ZDRkZjQxMzVlM2JkOTgyYWM2YmVjNDNhMTE4ODhkMWIifQ.eyJhenAiOiI1ODUyMDUyMjk1NzctZGlxZ2l1NWkwbjNoN2hzZmF0cG91MzY0OXVvaGduOWkuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI1ODUyMDUyMjk1NzctZGlxZ2l1NWkwbjNoN2hzZmF0cG91MzY0OXVvaGduOWkuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDI1ODI3NDEyNjA5NDc1ODQxNDQiLCJhdF9oYXNoIjoicGJWZE1Nb3l6UDl5UU9sMk54bkJDUSIsImlzcyI6ImFjY291bnRzLmdvb2dsZS5jb20iLCJpYXQiOjE1MDc1NzgyMDMsImV4cCI6MTUwNzU4MTgwM30.cU21Gu1jEcAONlQ0vf0ju8W7gsdyzPo-U3U6JCFaVqYqF5J2JmhCSk_-kJcY19WKyg8iwibOSNuuQE8PP0eCiIWDY-fq_3wOoO4IBUa5zlmTMNdz9Af4vH2h-optaG89tXE89J_-D2TjkKDdu1nPVLefX6E95vjb3P9LP5LfFJV53zT_deacFn4XiyCVMBl7sfNE0A6YG3PmZkVNgyIYJCv21bB5N_YtWTSEV_8YSFaJwDcEihqBGiFe3fO3k9-A237HuKevBRfo_xAyIQXnCHiLg8eETGTK3sfRh_ugxMI0jvgt4hBZQTioGjnaMRmQxaiJ_3IOrpSJeMu_JIg8-g");
      fail("Should not decode because the certificates are expired");
    } catch (RuntimeException e) {
      // OK
    }
  }

  @Test
  public void symmetricHMAC() {
    JsonObject jwk = new JsonObject()
      .put("kty", "oct")
      .put("k", "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

    new JWK(jwk);
  }


  @Test
  public void publicECK() {
    JsonObject jwk = new JsonObject()
      .put("kty", "EC")
      .put("crv", "secp256k1")
      .put("x", "ELZhvOXbbuPdoPq0H1dTq1rvR4v6ddu00sewn6fw-ow")
      .put("y", "nY56UtXSG-G2wbCzByDlVezHiPj_D8j-7xq1qFhZ_Bs")
//      .put("use", "enc")
      .put("kid", "1");

    new JWK(jwk);
  }

  @Test
  public void loadAzure() {
    Vertx vertx = Vertx.vertx();
    JsonObject azure = new JsonObject(vertx.fileSystem()
      .readFileBlocking("azure.json"));

    JWK key = new JWK(azure.getJsonArray("keys").getJsonObject(1));

    JWT jwt = new JWT()
      .addJWK(key)
      .nonceAlgorithm("SHA-256");


    System.out.println(
      jwt.decode("eyJ0eXAiOiJKV1QiLCJub25jZSI6InM5TzdaZ2F6WVJEd2VCZzZhbDNWVkhuZFFOQ0JHSVZZaDMxTDZRVFljTDAiLCJhbGciOiJSUzI1NiIsIng1dCI6Im5PbzNaRHJPRFhFSzFqS1doWHNsSFJfS1hFZyIsImtpZCI6Im5PbzNaRHJPRFhFSzFqS1doWHNsSFJfS1hFZyJ9.eyJhdWQiOiIwMDAwMDAwMy0wMDAwLTAwMDAtYzAwMC0wMDAwMDAwMDAwMDAiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9mY2FhZjcxMC03YzllLTRjYTAtOWNkYS02OTczOWZhZmJhNGIvIiwiaWF0IjoxNjExNjg3NDE1LCJuYmYiOjE2MTE2ODc0MTUsImV4cCI6MTYxMTY5MTMxNSwiYWNjdCI6MCwiYWNyIjoiMSIsImFjcnMiOlsidXJuOnVzZXI6cmVnaXN0ZXJzZWN1cml0eWluZm8iLCJ1cm46bWljcm9zb2Z0OnJlcTEiLCJ1cm46bWljcm9zb2Z0OnJlcTIiLCJ1cm46bWljcm9zb2Z0OnJlcTMiLCJjMSIsImMyIiwiYzMiLCJjNCIsImM1IiwiYzYiLCJjNyIsImM4IiwiYzkiLCJjMTAiLCJjMTEiLCJjMTIiLCJjMTMiLCJjMTQiLCJjMTUiLCJjMTYiLCJjMTciLCJjMTgiLCJjMTkiLCJjMjAiLCJjMjEiLCJjMjIiLCJjMjMiLCJjMjQiLCJjMjUiXSwiYWlvIjoiQVVRQXUvOFNBQUFBMFYwa0M4S25EM01RbUJ0WGk4OG9lT3NzT2xzU0JLZ1Rld1diQ1RnV2x0MEZ4dG9POVZtVjVjOGRLTStNckE1MXJoZW1Ebm9HMGJGUkRJWkpnM3Izb0E9PSIsImFtciI6WyJwd2QiLCJtZmEiXSwiYXBwX2Rpc3BsYXluYW1lIjoicG9iLXNlcnZlciIsImFwcGlkIjoiMTNjOWUxMTItYjE1OC00YjE5LThkNTctZTFmMzg4MWM0MzgzIiwiYXBwaWRhY3IiOiIxIiwiZmFtaWx5X25hbWUiOiJMb3BlcyIsImdpdmVuX25hbWUiOiJQYXVsbyIsImlkdHlwIjoidXNlciIsImlwYWRkciI6IjIxNy4xMDIuMTY1LjQ2IiwibmFtZSI6IkxhYiBQYXVsbyBMb3BlcyIsIm9pZCI6IjUyYmY4YWMyLTNlODMtNGNmNC04MTYxLTBiMTM1YWUwNjk4YiIsInBsYXRmIjoiMTQiLCJwdWlkIjoiMTAwMzIwMDEwRjQzQjcyRSIsInJoIjoiMC5BQUFBRVBlcV9KNThvRXljMm1sem42LTZTeExoeVJOWXNSbExqVmZoODRnY1E0TjVBRHMuIiwic2NwIjoiZW1haWwgb3BlbmlkIHByb2ZpbGUgVXNlci5SZWFkIiwic2lnbmluX3N0YXRlIjpbImttc2kiXSwic3ViIjoiWXltcTZLUmlLMHVUX1NVZ0JzYWUtaElIRE5VX0FLQVpvRG5TTWwxR3VpZyIsInRlbmFudF9yZWdpb25fc2NvcGUiOiJFVSIsInRpZCI6ImZjYWFmNzEwLTdjOWUtNGNhMC05Y2RhLTY5NzM5ZmFmYmE0YiIsInVuaXF1ZV9uYW1lIjoicGF1bG9AbGFiLnRlbnRpeG8uY29tIiwidXBuIjoicGF1bG9AbGFiLnRlbnRpeG8uY29tIiwidXRpIjoiZGNzM1ZzMXk5VW1SOXBzV05JaUxBQSIsInZlciI6IjEuMCIsIndpZHMiOlsiNjJlOTAzOTQtNjlmNS00MjM3LTkxOTAtMDEyMTc3MTQ1ZTEwIiwiYjc5ZmJmNGQtM2VmOS00Njg5LTgxNDMtNzZiMTk0ZTg1NTA5Il0sInhtc19zdCI6eyJzdWIiOiJiNGRXNmVuWk9fRGhFLUMyZE1Qdks5Y1JXcW8zXy1FQVc5MVJ4WmRKNnNVIn0sInhtc190Y2R0IjoxNjEwOTEyOTM2fQ.M4dXPZszAsL_rnceagjZnmd8yzbbB3hou4L6vVLGzqAt4wVg8KwQKxcxIGqBqgDWRlBvLYqWs61dvt8vSa-9GaMJifHwmfWoXPvyVzdxhx3qrqgHdsz1HWX5WzcDlEbHrPXZGE8KM-0czE67rePMxEHK7vLf5TbmERLGJt4QDOGZxVHYvnplIrIM1eGjANIeWYTyW5g-YDx3VX6yVl5QHvP4CFdINhDV7i-L3bjmV4M8F6wYs7Xs7nIrKYEiyjTrpXGUL7u29eHXgzeGlSxfXeqTdYmgEt6lFOxx-fZzO0m92AhPGGAe6IB85FtqSi5T95Nif3pHPsouryhDco8y3g")
    );
  }

  private static int getVersion() {
    String version = System.getProperty("java.version");

    if (version.startsWith("1.")) {
      version = version.substring(2, 3);
    } else {
      int dot = version.indexOf(".");
      if (dot != -1) {
        version = version.substring(0, dot);
      }
    }

    int dash = version.indexOf('-');
    if (dash != -1) {
      version = version.substring(0, dash);
    }

    return Integer.parseInt(version);
  }

  @Test
  public void testOKP() {
    assumeTrue("JVM doesn't support EdDSA", getVersion() >= 15);
    JsonObject jwk = new JsonObject()
      .put("kty", "OKP")
      .put("alg", "EdDSA")
      .put("crv", "Ed25519")
      .put("x", "UUFFMkomijuOugmzEIiRfEpV-iV78ELK9XNGorZMIl0")
      .put("d", "Qmdi9hWKKno_Ml4pfvSzyEUYrRwvGom-J0EwKcACWPU")
      .put("use", "sig")
      .put("kid", "1");

    JWT jwt = new JWT().addJWK(new JWK(jwk));

    String token = jwt.sign(new JsonObject().put("hello", "world"), new JWTOptions().setAlgorithm("EdDSA"));
    JsonObject decoded = jwt.decode(token);
    assertEquals("world", decoded.getString("hello"));
  }

  @Test
  public void testOKPInterop() {
    assumeTrue("JVM doesn't support EdDSA", getVersion() >= 15);

    // this key and token were generated from
    // com.nimbusds.jose.*
    JsonObject jwk = new JsonObject()
      .put("kty", "OKP")
      .put("alg", "EdDSA")
      .put("crv", "Ed25519")
      .put("x", "CIvYtKVA8ul314zLdxRJwwmWEyAj1j0rm6-7Ii6a74E")
      .put("use", "sig")
      .put("kid", "123");

    JWT jwt = new JWT().addJWK(new JWK(jwk));

    String token = "eyJraWQiOiIxMjMiLCJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJhdWQiOiJ5b3UiLCJzdWIiOiJib2IiLCJpc3MiOiJtZSIsImV4cCI6MTYxNzk3Mjk1M30.diKQd6G1dA72XxHNqN9UaYWTgqcZxRaZh9sxN3eFfc7Tlkqk1APU9Qkj8X96gABZxnYx0Djf7nK6YJf6VpcBBA";
    JsonObject decoded = jwt.decode(token);
    assertEquals("you", decoded.getString("aud"));
    assertEquals("bob", decoded.getString("sub"));
    assertEquals("me", decoded.getString("iss"));
    assertNotNull(decoded.getInteger("exp"));
  }

  @Test
  public void testOID() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
    // this keystore holds algorithms in OID format, not human readable strings
    try (InputStream in = JWKTest.class.getResourceAsStream("/keystore.p12")) {
      KeyStore ks = KeyStore.getInstance("PKCS12");
      ks.load(in, "secret".toCharArray());

      JWT jwt = new JWT();

      for (JWK key : JWK.load(ks, "secret", null)) {
        jwt.addJWK(key);
      }

      assertFalse(jwt.isUnsecure());
    }
  }

  @Test(expected = RuntimeException.class)
  public void publicECKSignZero() {
    JsonObject jwk = new JsonObject()
      .put("kty", "EC")
      .put("crv", "P-256")
      .put("x", "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")
      .put("y", "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")
      .put("d", "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE")
//      .put("use", "enc")
      .put("kid", "1");

    JWT jwt = new JWT().addJWK(new JWK(jwk));

    String token = jwt.sign(new JsonObject().put("user", "Paulo"), new JWTOptions().setAlgorithm("ES256"));
    String zeros = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[64]);
    token = token.substring(0, token.lastIndexOf('.') + 1) + zeros;
    jwt.decode(token);
  }
}
