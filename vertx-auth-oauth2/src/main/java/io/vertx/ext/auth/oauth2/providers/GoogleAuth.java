package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.jwt.JWTOptions;

/**
 * Simplified factory to create an {@link io.vertx.ext.auth.oauth2.OAuth2Auth} for Google.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface GoogleAuth {

  /**
   * Create a OAuth2Auth provider for Google
   *
   * @param clientId     the client id given to you by Google
   * @param clientSecret the client secret given to you by Google
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret) {
    return create(vertx, clientId, clientSecret, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Google
   *
   * @param clientId          the client id given to you by Google
   * @param clientSecret      the client secret given to you by Google
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, OAuth2FlowType.AUTH_CODE, new OAuth2ClientOptions(httpClientOptions)
        .setSite("https://accounts.google.com")
        .setTokenPath("https://www.googleapis.com/oauth2/v3/token")
        .setAuthorizationPath("/o/oauth2/auth")
        .setIntrospectionPath("https://www.googleapis.com/oauth2/v3/tokeninfo")
        .setUserInfoPath("https://www.googleapis.com/oauth2/v3/userinfo")
        // https://www.googleapis.com/oauth2/v1/certs
        .setPubSecKeyOptions(new PubSecKeyOptions()
          .setType("RS256")
          .addX509Certificate(
              "-----BEGIN CERTIFICATE-----\n" +
              "MIIDJjCCAg6gAwIBAgIIZtJv8PyRUgowDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE\n" +
              "AxMrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe\n" +
              "Fw0xNzEwMDgxMTQzMzRaFw0xNzEwMTExMjEzMzRaMDYxNDAyBgNVBAMTK2ZlZGVy\n" +
              "YXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqG\n" +
              "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6fNn5kfLZQ43Z+ZTqFMUF+dN2L2BphQKz\n" +
              "gaWCsyzyJYwEySgMxbO8cQgTlgZzcC1Rt6phWHMBkFQQNykSk/K0A8xaaNqFNNVz\n" +
              "eszR+XJ3IvCQGo8rS2K/LrNofGZrph00k6DZ7XJsWav0GotAwDd0H6IsNbFHCyRJ\n" +
              "75ASzZr8fT8RJ9bQeTLoCsmwPXYBPeSvoWgZzOypbmLhohw0J7fBUbgVZ8fR3crh\n" +
              "v6RDOp4/fDALWxCVPptFn0hMPeT2Dla9kbnPfVSWtciyvty5JJXnpuoqA6rLfEpM\n" +
              "GYnMSk+SbD2R0W9O2LMRfoJ52qml+2s/aLpNKGJc2vLzDyH7CiavAgMBAAGjODA2\n" +
              "MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsG\n" +
              "AQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQAlDoCH/E43ruorgPIATCO++dOfOIb/\n" +
              "n+NgE727UeK1acELi+dUjSdYEe+WXdY2sichgE1JqPrsMWFHCwHTUfVubmku5BTk\n" +
              "lj9k6F9jKc+XDMra1w0KGSGrxwSqwYhkhSdMOGGa9C3td+s7M/E4JV+XoQXAY3uE\n" +
              "aB0lO4c+pckDwU/LAGrMldogT3+zE+4NRS7p8dstnww3OIHUCFfytbhcY8sH4Vjq\n" +
              "dMWGrv8R/1L0jXok8vFPEAwvXzVc3NeUClio0hOEmhTjbLgebsgToB1aNC1pnzmH\n" +
              "TclVndTwDcnDkhImpvuWE1lX+KPkFJ54ixS4Bi2cqWud1aQ2Mqi7KHfK\n" +
              "-----END CERTIFICATE-----\n"
          )
          .addX509Certificate(
            "-----BEGIN CERTIFICATE-----\n" +
              "MIIDJjCCAg6gAwIBAgIIeABc0/4wb7AwDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE\n" +
              "AxMrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe\n" +
              "Fw0xNzEwMDkxMTQzMzRaFw0xNzEwMTIxMjEzMzRaMDYxNDAyBgNVBAMTK2ZlZGVy\n" +
              "YXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqG\n" +
              "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3ICz+C7FKE4jbsRh/cZK1I9M5lXGlyvk8\n" +
              "c72BuK3/uLwnRH5eSrooA1LEqwVdKV5MOTuHHnxWFb57yyBl8Ld3CGK/aeZYIGd6\n" +
              "iV8ym/jw6rCdJhkL6yCZ3/Xj3+Un+5Vf+ObjHd04X/GbwleFRcldJilpgwtt0PKT\n" +
              "/JBl/lKqTzzH/HWzdp3tj5gfVJzj1NxfN4K0GSFDy/5pRYsT9NebFC/JoBgSXrEE\n" +
              "ZXaigqQsYiI+lTDL59TLq8XaaT0V1sfoHnspu3DikgO51eJBP3c0wB2CvXxk+vMl\n" +
              "SQMsnDcsztiijGPwrpxrLwDyzsm3Rs7WI9kDHPeUeKhGX0/s9AnBAgMBAAGjODA2\n" +
              "MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsG\n" +
              "AQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQAiZt536sXwNXqUs92edWsQ+uiraJbl\n" +
              "ATuMSslrQhGJjUebmlpIUMe8Dv2dj+/bYK7gZyjUQKwjmtCJ+U8Z2Ec/v9yEqKpy\n" +
              "zfYIOTF/17d31OvisnccIbjBL2X+b/OHsFDjaY5hZrs0mczr1ePaYlE/EsyIFEZC\n" +
              "wGbgarp7FxlRrdJEBN8jnjUgK6Kig2GLtcQcHfkIjxmVDzgS47TAtxPNTBGQypWu\n" +
              "bALTWt+WTAFpQGcW6pj9nOxuV2XB4RkFg7XrHtnBvad4/KAD/kp2if6BFyvwWcyQ\n" +
              "zKqqKcjJHinaGWf7qlBLBJTQcZcWPJEzFdwBsHHejgU8vy9hR97rvU8s\n" +
              "-----END CERTIFICATE-----\n"
          )
          .addX509Certificate(
            "-----BEGIN CERTIFICATE-----\n" +
              "MIIDJjCCAg6gAwIBAgIIcz32mW0b5V8wDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE\n" +
              "AxMrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe\n" +
              "Fw0xNzEwMDcxMTQzMzRaFw0xNzEwMTAxMjEzMzRaMDYxNDAyBgNVBAMTK2ZlZGVy\n" +
              "YXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqG\n" +
              "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDDmL6MaLATK497Ce9H6UVx4FFiHiDH3X44\n" +
              "UtonDCvzIKtJVzMCDJzXDLAUEKxQEMGEekpJWKWogYbZ8iqF1fb8gUn47Fi9cOYm\n" +
              "1gXr2RZNp9mMW2cCXwR0iqPVf7LfU+b2BgP+th4sbcJmE0uMgT/L1+Tn8xs45zRn\n" +
              "5uvj/DOKeDod8REhNsA4B8J3xGLT+1cOpiCL4LUL+CzYeF5gQhaqlnax7xSwa8iD\n" +
              "a5484JXwbdrR+6+HqGCO62yl8n9Ufd54fBjDJjOJ6r6wNZzJXmoaWcmn1NmVn3Pb\n" +
              "jZZ1gePcLaS501NSDvqnqy9uzpy7VmJkD1ZmRov13yFZ4ni0tCDdAgMBAAGjODA2\n" +
              "MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsG\n" +
              "AQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQAfVSQFYR21K1IynPE/g0aYueSQHvbo\n" +
              "7SaT/iCmLS4g4EXqpGFGSMgQZWe9FckFYqAkJZ8AS2BtlzflfNYBH9K6V++sm5xx\n" +
              "hsH+DmS/dXUQrSWuwKc5sS385D5kg2vJlqO1snCYOg1iEMkvU36mEO3o0kAi+2g1\n" +
              "NWOWiCFLLqoC4onmwDKv/K5qpwb2n3+IUbaS8R/cgGsq6B7ohCSrdHfErOOitNsy\n" +
              "nLO733lcFJKYxrYu4/OpvGkKBaxGf8h1BsDmNfenfYq4ak0N+8nTxPfc0fARyCkH\n" +
              "SJPQ5WWMfi14d7J6hjc8qZHIDsAiJ50LB36Nk9p+KEQT5yh3UFbPXJO6\n" +
              "-----END CERTIFICATE-----\n"
          ))
        .setUserInfoParameters(new JsonObject()
          .put("alt", "json"))
        .setScopeSeparator(" ")
        .setClientID(clientId)
        .setClientSecret(clientSecret));
  }

  /**
   * Create a OAuth2Auth provider for Google Service Account (Server to Server)
   *
   * @param serviceAccountJson the configuration json file from your Google API page
   */
  static OAuth2Auth create(Vertx vertx, JsonObject serviceAccountJson) {
    return create(vertx, serviceAccountJson, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Google Service Account (Server to Server)
   *
   * @param serviceAccountJson the configuration json file from your Google API page
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, JsonObject serviceAccountJson, HttpClientOptions httpClientOptions) {
    final StringBuilder privateKey = new StringBuilder();
    for (String s : serviceAccountJson.getString("private_key").split("\n")) {
      if ("-----BEGIN PRIVATE KEY-----".equals(s) || "-----END PRIVATE KEY-----".equals(s)) {
        continue;
      }
      privateKey.append(s);
    }

    return
      OAuth2Auth.create(vertx, OAuth2FlowType.AUTH_JWT, new OAuth2ClientOptions(httpClientOptions)
        .setSite("https://accounts.google.com")
        .setTokenPath(serviceAccountJson.getString("token_uri"))
        .setPubSecKeyOptions(new PubSecKeyOptions()
          .setType("RS256")
          .setSecretKey(privateKey.toString()))
        .setJWTOptions(new JWTOptions()
          .setAlgorithm("RS256")
          .setExpiresInMinutes(60)
          .addAudience("https://www.googleapis.com/oauth2/v4/token")
          .setIssuer(serviceAccountJson.getString("client_email"))));
  }
}
