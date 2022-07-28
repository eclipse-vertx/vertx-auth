package io.vertx.ext.auth.webauthn;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.impl.Codec;
import io.vertx.ext.auth.impl.cose.CWK;
import io.vertx.ext.auth.impl.jose.JWK;
import io.vertx.ext.auth.impl.jose.JWS;
import io.vertx.ext.auth.webauthn.impl.CBOR;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@RunWith(VertxUnitRunner.class)
public class WebAuthNTest {

  private final DummyStore database = new DummyStore();

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Before
  public void resetDatabase() {
    database.clear();
  }

  @Test(timeout = 1000)
  public void testFIDORegister(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    final JsonObject webauthn = new JsonObject("{\"getClientExtensionResults\":{},\"rawId\":\"vp6cvoSgvTWSyFpnmdpm1dwiuREvsm-Kqw0Jt0Y0PQfjHsEhKE82KompUXqEt5yQIQl9ZKj6L1-700LGaVUMoQ\",\"response\":{\"attestationObject\":\"o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhAOOPecQ34VN0QW-cmj-Sft9aCahqgTlFQzbQH1LpEgrTAiBWW6KoqlKbLMtGd1Y_VcQML8eugYZcrmSSCS0of2T-M2N4NWOBWQIyMIICLjCCARigAwIBAgIECmML_zALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCkxJzAlBgNVBAMMHll1YmljbyBVMkYgRUUgU2VyaWFsIDE3NDI2MzI5NTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKQjZF26iyPtbNnl5IuTKs_fRWTHVzHxz1IHRRBrSbqWD60PCqUJPe4zkIRFqBa4NnzdhVcS80nlZuY3ANQm0J-jJjAkMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4yMAsGCSqGSIb3DQEBCwOCAQEAZTmwMqHPxEjSB64Umwq2tGDKplAcEzrwmg6kgS8KPkJKXKSu9T1H6XBM9-LAE9cN48oUirFFmDIlTbZRXU2Vm2qO9OdrSVFY-qdbF9oti8CKAmPHuJZSW6ii7qNE59dHKUaP4lDYpnhRDqttWSUalh2LPDJQUpO9bsJPkgNZAhBUQMYZXL_MQZLRYkX-ld7llTNOX5u7n_4Y5EMr-lqOyVVC9lQ6JP6xoa9q6Zp9-Y9ZmLCecrrcuH6-pLDgAzPcc8qxhC2OR1B0ZSpI9RBgcT0KqnVE0tq1KEDeokPqF3MgmDRkJ--_a2pV0wAYfPC3tC57BtBdH_UXEB8xZVFhtGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQL6enL6EoL01kshaZ5naZtXcIrkRL7JviqsNCbdGND0H4x7BIShPNiqJqVF6hLeckCEJfWSo-i9fu9NCxmlVDKGlAQIDJiABIVgg0TT3Vc7gnmO4ptAzJ671fahlgW8CrqgiCn_fPWFeEbciWCD9wLIGCTxTxmbe6ahfYQuboizWT7Y8u3BaYKSa6XTtxA\",\"clientDataJSON\":\"eyJjaGFsbGVuZ2UiOiJQZXlodVVYaVQzeG55V1pqZWNaU1NxaFVTdUttYmZPV0dGREN0OGZDUXYwIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9\"},\"id\":\"vp6cvoSgvTWSyFpnmdpm1dwiuREvsm-Kqw0Jt0Y0PQfjHsEhKE82KompUXqEt5yQIQl9ZKj6L1-700LGaVUMoQ\",\"type\":\"public-unwrap\"}");

    final String userId = Codec.base64UrlEncode(UUID.randomUUID().toString().getBytes());
    final String username = "paulo";
    final String credID = "vp6cvoSgvTWSyFpnmdpm1dwiuREvsm-Kqw0Jt0Y0PQfjHsEhKE82KompUXqEt5yQIQl9ZKj6L1-700LGaVUMoQ";
    final String publicKey = "pQECAyYgASFYINE091XO4J5juKbQMyeu9X2oZYFvAq6oIgp_3z1hXhG3Ilgg_cCyBgk8U8Zm3umoX2ELm6Is1k-2PLtwWmCkmul07cQ";

    webAuthN.authenticate(
      new JsonObject()
        .put("webauthn", webauthn)
        .put("challenge", "PeyhuUXiT3xnyWZjecZSSqhUSuKmbfOWGFDCt8fCQv0")
        .put("username", username)
        .put("userId", userId)
        .put("origin", "http://localhost:3000")
      , fn -> {
        should.assertTrue(fn.succeeded());

        final User user = fn.result();
        should.assertEquals(userId, user.principal().getString("userId"));

        final Authenticator expectedAuthenticator = new Authenticator()
          .setUserId(userId)
          .setUserName(username)
          .setCredID(credID)
          .setPublicKey(publicKey);

        testAuthenticatorStored(
          should,
          new Authenticator().setCredID(credID),
          expectedAuthenticator
        );

        test.complete();
      });
  }

  private void testAuthenticatorStored(final TestContext should, final Authenticator query, final Authenticator expected) {
    final List<Authenticator> results = database.fetch(query).result();
    should.assertEquals(1, results.size());

    final Authenticator result = results.get(0);
    if (expected.getUserId() != null) {
      should.assertEquals(expected.getUserId(), result.getUserId());
    }
    if (expected.getUserId() != null) {
      should.assertEquals(expected.getUserName(), result.getUserName());
    }
    if (expected.getCredID() != null) {
      should.assertEquals(expected.getCredID(), result.getCredID());
    }
    if (expected.getPublicKey() != null) {
      should.assertEquals(expected.getPublicKey(), result.getPublicKey());
    }
  }

  @Test(timeout = 1000)
  public void testFIDOLogin(TestContext should) {
    final Async test = should.async();
    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")).setRequireResidentKey(true))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    final String userId = Codec.base64UrlEncode(UUID.randomUUID().toString().getBytes());

    database.add(
      new Authenticator()
        .setCredID("-r1iW_eHUyIpU93f77odIrdUlNVfYzN-JPCTWGtdn-1wxdLxhlS9NmzLNbYsQ7XVZlGSWbh_63E5oFHcNh4JNw")
        .setPublicKey("pQECAyYgASFYIB4QBsdBFyVm79aQFrgdhAFsV0bD0-UfzsRRihvSU8bnIlggdBaaNC3nGWGcZd1msfoD0vMt0Ydg9InOFKkz6PKUEf8")
        .setCounter(0)
        .setUserId(userId)
    );

    final JsonObject webauthn = new JsonObject("{\"getClientExtensionResults\":{},\"rawId\":\"-r1iW_eHUyIpU93f77odIrdUlNVfYzN-JPCTWGtdn-1wxdLxhlS9NmzLNbYsQ7XVZlGSWbh_63E5oFHcNh4JNw\",\"response\":{\"authenticatorData\":\"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAFA\",\"signature\":\"MEUCIA3bv92hSE3wNz1CNGIinx27YLJgucNnBwqjV7qWqHqiAiEAjBsxBaK2nEfCilGSZ3yzoHVJilwkhOOkwZAJ52xp-h8\",\"userHandle\":\"null\",\"clientDataJSON\":\"eyJjaGFsbGVuZ2UiOiI2b2pkb19LS0c0a1hvWjVKRF9BbHY2Q2hyVXRPT3o3dXFlaWlvRmxCc3pvIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9\"},\"id\":\"-r1iW_eHUyIpU93f77odIrdUlNVfYzN-JPCTWGtdn-1wxdLxhlS9NmzLNbYsQ7XVZlGSWbh_63E5oFHcNh4JNw\",\"type\":\"public-unwrap\"}");

    webAuthN.authenticate(
      new JsonObject()
        .put("webauthn", webauthn)
        .put("origin", "http://localhost:3000")
        .put("challenge", "6ojdo_KKG4kXoZ5JD_Alv6ChrUtOOz7uqeiioFlBszo")
      , fn -> {
        should.assertTrue(fn.succeeded());

        final User user = fn.result();
        should.assertEquals(userId, user.principal().getString("userId"));

        test.complete();
      });
  }

  @Test(timeout = 1000)
  public void testFIDOLoginWhenNoAuthenticatorsFoundByCredID(TestContext should) {
    final Async test = should.async();
    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")).setRequireResidentKey(true))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    final JsonObject webauthn = new JsonObject("{\"getClientExtensionResults\":{},\"rawId\":\"-r1iW_eHUyIpU93f77odIrdUlNVfYzN-JPCTWGtdn-1wxdLxhlS9NmzLNbYsQ7XVZlGSWbh_63E5oFHcNh4JNw\",\"response\":{\"authenticatorData\":\"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAFA\",\"signature\":\"MEUCIA3bv92hSE3wNz1CNGIinx27YLJgucNnBwqjV7qWqHqiAiEAjBsxBaK2nEfCilGSZ3yzoHVJilwkhOOkwZAJ52xp-h8\",\"userHandle\":\"null\",\"clientDataJSON\":\"eyJjaGFsbGVuZ2UiOiI2b2pkb19LS0c0a1hvWjVKRF9BbHY2Q2hyVXRPT3o3dXFlaWlvRmxCc3pvIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9\"},\"id\":\"-r1iW_eHUyIpU93f77odIrdUlNVfYzN-JPCTWGtdn-1wxdLxhlS9NmzLNbYsQ7XVZlGSWbh_63E5oFHcNh4JNw\",\"type\":\"public-unwrap\"}");

    webAuthN.authenticate(
      new JsonObject()
        .put("webauthn", webauthn)
        .put("origin", "http://localhost:3000")
        .put("challenge", "6ojdo_KKG4kXoZ5JD_Alv6ChrUtOOz7uqeiioFlBszo")
      , fn -> {
        should.assertFalse(fn.succeeded());
        test.complete();
      });
  }

  @Test(timeout = 1000)
  @Ignore("test data contains an expired certificate")
  public void testPAckedFull(TestContext should) {
    final Async test = should.async();
    WebAuthn webAuthN = WebAuthn.create(rule.vertx(), new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    final JsonObject webauthn = new JsonObject("{\n" +
      "    \"rawId\": \"wsLryOAxXMU54s2fCSWPzWjXHOBKPploN-UHftj4_rpIu6BZxNXppm82f7Y6iX9FEOKKeS5-N2TALeyzLnJfAA\",\n" +
      "    \"id\": \"wsLryOAxXMU54s2fCSWPzWjXHOBKPploN-UHftj4_rpIu6BZxNXppm82f7Y6iX9FEOKKeS5-N2TALeyzLnJfAA\",\n" +
      "    \"response\": {\n" +
      "        \"clientDataJSON\": \"eyJjaGFsbGVuZ2UiOiJZTVdFVGYtUDc5aU1iLUJxZFRreVNOUmVPdmE3bksyaVZDOWZpQzhpR3ZZeXB1bkVPQ1pHWjYtWTVPVjFydk1pRGdBaldmRmk2VUMwV3lLR3NqQS1nQSIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4ub3JnIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9\",\n" +
      "        \"attestationObject\": \"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAIzOihC6Ba80o5JnoYOJJ_EtEVmWQcAvxVCnsCFnVRQZAiAfeIddLPsPl1FeSX8B5xZANcQKGNoO7pb0TZPnuJdebGN4NWOBWQKzMIICrzCCAZegAwIBAgIESFs9tjANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDDBZZdWJpY28gRklETyBQcmV2aWV3IENBMB4XDTE4MDQxMjEwNTcxMFoXDTE4MTIzMTEwNTcxMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTIxMzkzOTEyNjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPss3TBDKMVySlDM5vYLrX0nqRtZ4eZvKXuJydQ9wrLHeIm08P-dAijLlG384BsZWJtngEqsl38oGJzNsyV0yiijbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS42MBMGCysGAQQBguUcAgEBBAQDAgQwMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER-e3H0wDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMvPkvVjXQiuvSZmGCB8NqTvGqhxyEfkoU-vz63PaaTsG3jEzjl0C7PZ26VxCvqWPJdM3P3e7Kp18sj4RjEHUmkya2PPipOwBd3p0qMQSQ8MeziCPLQ9uvGGb4YShcvaprMv4c21b4piza-znHneNCmmq-ZS4Y23o-vYv085_BEwyLPcmPjSZ5qWysCq7rVvZ7OWwcU1zu5RhSZyUKl8dzK9lAzs5OdRH2fzEewsW2OkB_Ow_jBvAxqwLXXTHuwMFaRfpmBoZuQlcofSrnwJ8KA-K-e0dKTz2zC8EbZrWYrSpbrHKyqxeBT6DkUd8H4tgAd5lOr_yqrtVmIaRfq07NmhhdXRoRGF0YVjElWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4_Xy7IpvdRBAAAAAPigEfOMCk0VgAYXER-e3H0AQMLC68jgMVzFOeLNnwklj81o1xzgSj6ZaDflB37Y-P66SLugWcTV6aZvNn-2Ool_RRDiinkufjdkwC3ssy5yXwClAQIDJiABIVggAYD1TSpf120DSVxen8ki56kF1bmT4EXO-P0JnSk5mMwiWCB3TlMZBRqPY6llzDcfHd-oW0EHdaFNgBdlGGFobpHKlw\"\n" +
      "    }\n" +
      "}");

    webAuthN.authenticate(
      new JsonObject()
        .put("webauthn", webauthn)
        .put("origin", "https://webauthn.org")
        .put("challenge", "YMWETf-P79iMb-BqdTkySNReOva7nK2iVC9fiC8iGvYypunEOCZGZ6-Y5OV1rvMiDgAjWfFi6UC0WyKGsjA-gA")
        .put("username", "paulo")
      , fn -> {
        should.assertTrue(fn.succeeded());
        test.complete();
      });
  }

  @Test(timeout = 1000)
  public void testPAckedSurrogate(TestContext should) {
    final Async test = should.async();
    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    database.add(
      new Authenticator()
        .setCredID("H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14")
        .setPublicKey("pAEDAzn__iBZAQDAIqzybPPmgeL5OR6JKq9bWDiENJlN_LePQEnf1_sgOm4FJ9kBTbOTtWplfoMXg40A7meMppiRqP72A3tmILwZ5xKIyY7V8Y2t8X1ilYJol2nCKOpAEqGLTRJjF64GQxen0uFpi1tA6l6N-ZboPxjky4aidBdUP22YZuEPCO8-9ZTha8qwvTgZwMHhZ40TUPEJGGWOnHNlYmqnfFfk0P-UOZokI0rqtqqQGMwzV2RrH2kjKTZGfyskAQnrqf9PoJkye4KUjWkWnZzhkZbrDoLyTEX2oWvTTflnR5tAVMQch4UGgEHSZ00G5SFoc19nGx_UJcqezx5cLZsny-qQYDRjIUMBAAE")
        .setCounter(0)
    );

    final JsonObject webauthn = new JsonObject("{\n" +
      "    \"id\": \"H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14\",\n" +
      "    \"rawId\": \"H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14\",\n" +
      "    \"response\": {\n" +
      "        \"attestationObject\": \"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzn__mNzaWdZAQCPypMLXWqtCZ1sc5QdjhH-pAzm8-adpfbemd5zsym2krscwV0EeOdTrdUOdy3hWj5HuK9dIX_OpNro2jKrHfUj_0Kp-u87iqJ3MPzs-D9zXOqkbWqcY94Zh52wrPwhGfJ8BiQp5T4Q97E042hYQRDKmtv7N-BT6dywiuFHxfm1sDbUZ_yyEIN3jgttJzjp_wvk_RJmb78bLPTlym83Y0Ws73K6FFeiqFNqLA_8a4V0I088hs_IEPlj8PWxW0wnIUhI9IcRf0GEmUwTBpbNDGpIFGOudnl_C3YuXuzK3R6pv2r7m9-9cIIeeYXD9BhSMBQ0A8oxBbVF7j-0xXDNrXHZaGF1dGhEYXRhWQFnSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAOKjVmSRjt0nqud40p1PeHgEAIB-l9gZ544Ds7vzo_O76UZ8DCXiWFc8DN8LWNZYQH0NepAEDAzn__iBZAQDAIqzybPPmgeL5OR6JKq9bWDiENJlN_LePQEnf1_sgOm4FJ9kBTbOTtWplfoMXg40A7meMppiRqP72A3tmILwZ5xKIyY7V8Y2t8X1ilYJol2nCKOpAEqGLTRJjF64GQxen0uFpi1tA6l6N-ZboPxjky4aidBdUP22YZuEPCO8-9ZTha8qwvTgZwMHhZ40TUPEJGGWOnHNlYmqnfFfk0P-UOZokI0rqtqqQGMwzV2RrH2kjKTZGfyskAQnrqf9PoJkye4KUjWkWnZzhkZbrDoLyTEX2oWvTTflnR5tAVMQch4UGgEHSZ00G5SFoc19nGx_UJcqezx5cLZsny-qQYDRjIUMBAAE\",\n" +
      "        \"clientDataJSON\": \"eyJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjaGFsbGVuZ2UiOiJBWGtYV1hQUDNnTHg4T0xscGtKM2FSUmhGV250blNFTmdnbmpEcEJxbDFuZ0tvbDd4V3dldlVZdnJwQkRQM0xFdmRyMkVPU3RPRnBHR3huTXZYay1WdyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ\"\n" +
      "    },\n" +
      "    \"type\": \"public-unwrap\"\n" +
      "}");

    webAuthN.authenticate(
      new JsonObject()
        .put("webauthn", webauthn)
        .put("origin", "http://localhost:3000")
        .put("challenge", "AXkXWXPP3gLx8OLlpkJ3aRRhFWntnSENggnjDpBql1ngKol7xWwevUYvrpBDP3LEvdr2EOStOFpGGxnMvXk-Vw")
        .put("username", "paulo")
      , fn -> {
        should.assertTrue(fn.succeeded());
        test.complete();
      });
  }

  @Test
  public void testVerify() throws IOException {
    try (CBOR decoder = new CBOR(Base64.getDecoder().decode("pQECAyYgASFYIB4QBsdBFyVm79aQFrgdhAFsV0bD0+UfzsRRihvSU8bnIlggdBaaNC3nGWGcZd1msfoD0vMt0Ydg9InOFKkz6PKUEf8="))) {
      JWK key = CWK.toJWK(decoder.read());
      JWS jws = new JWS(key);
      System.out.println(jws.verify(
        Base64.getUrlDecoder().decode("MEUCIA3bv92hSE3wNz1CNGIinx27YLJgucNnBwqjV7qWqHqiAiEAjBsxBaK2nEfCilGSZ3yzoHVJilwkhOOkwZAJ52xp-h8"),
        Base64.getDecoder().decode("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MBAAAAFF/+s2iT3LHeLABfvFkPvdiAp+mysYMYk94fUEZu//oj")
      ));
    }
  }

  @Test(timeout = 1000)
  public void testAndroidKey(TestContext should) {
    final Async test = should.async();
    WebAuthn webAuthN = WebAuthn.create(
      rule.vertx(),
      new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    database.add(
      new Authenticator()
        .setCredID("AVUvAmX241vMKYd7ZBdmkNWaYcNYhoSZCJjFRGmROb6I4ygQUVmH6k9IMwcbZGeAQ4v4WMNphORudwje5h7ty9A")
        .setPublicKey("pQECAyYgASFYIDhJog_eJsNLAIg5GlgneD3_k4gLFlQIiq369XollUmhIlggdDxLUkXPJoXPkQVDZ81Pr7lITnBZNlEBH8DcznYhxo8")
        .setCounter(0)
    );

    final JsonObject webauthn = new JsonObject("{\n" +
      "    \"rawId\": \"AZD7huwZVx7aW1efRa6Uq3JTQNorj3qA9yrLINXEcgvCQYtWiSQa1eOIVrXfCmip6MzP8KaITOvRLjy3TUHO7_c\",\n" +
      "    \"id\": \"AZD7huwZVx7aW1efRa6Uq3JTQNorj3qA9yrLINXEcgvCQYtWiSQa1eOIVrXfCmip6MzP8KaITOvRLjy3TUHO7_c\",\n" +
      "    \"response\": {\n" +
      "        \"clientDataJSON\": \"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVGY2NWJTNkQ1dGVtaDJCd3ZwdHFnQlBiMjVpWkRSeGp3QzVhbnM5MUlJSkRyY3JPcG5XVEs0TFZnRmplVVY0R0RNZTQ0dzhTSTVOc1pzc0lYVFV2RGciLCJvcmlnaW4iOiJodHRwczpcL1wvd2ViYXV0aG4ub3JnIiwiYW5kcm9pZFBhY2thZ2VOYW1lIjoiY29tLmFuZHJvaWQuY2hyb21lIn0\",\n" +
      "        \"attestationObject\": \"o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmNzaWdYRjBEAiAsp6jPtimcSgc-fgIsVwgqRsZX6eU7KKbkVGWa0CRJlgIgH5yuf_laPyNy4PlS6e8ZHjs57iztxGiTqO7G91sdlWBjeDVjg1kCzjCCAsowggJwoAMCAQICAQEwCgYIKoZIzj0EAwIwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxOzA5BgNVBAMMMkFuZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gSW50ZXJtZWRpYXRlMB4XDTE4MTIwMjA5MTAyNVoXDTI4MTIwMjA5MTAyNVowHzEdMBsGA1UEAwwUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ4SaIP3ibDSwCIORpYJ3g9_5OICxZUCIqt-vV6JZVJoXQ8S1JFzyaFz5EFQ2fNT6-5SE5wWTZRAR_A3M52IcaPo4IBMTCCAS0wCwYDVR0PBAQDAgeAMIH8BgorBgEEAdZ5AgERBIHtMIHqAgECCgEAAgEBCgEBBCAqQ4LXu9idi1vfF3LP7MoUOSSHuf1XHy63K9-X3gbUtgQAMIGCv4MQCAIGAWduLuFwv4MRCAIGAbDqja1wv4MSCAIGAbDqja1wv4U9CAIGAWduLt_ov4VFTgRMMEoxJDAiBB1jb20uZ29vZ2xlLmF0dGVzdGF0aW9uZXhhbXBsZQIBATEiBCBa0F7CIcj4OiJhJ97FV1AMPldLxgElqdwhywvkoAZglTAzoQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N4AwIBF7-DeQMCAR6_hT4DAgEAMB8GA1UdIwQYMBaAFD_8rNYasTqegSC41SUcxWW7HpGpMAoGCCqGSM49BAMCA0gAMEUCIGd3OQiTgFX9Y07kE-qvwh2Kx6lEG9-Xr2ORT5s7AK_-AiEAucDIlFjCUo4rJfqIxNY93HXhvID7lNzGIolS0E-BJBhZAnwwggJ4MIICHqADAgECAgIQATAKBggqhkjOPQQDAjCBmDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwqQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MB4XDTE2MDExMTAwNDYwOVoXDTI2MDEwODAwNDYwOVowgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxOzA5BgNVBAMMMkFuZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gSW50ZXJtZWRpYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6555-EJjWazLKpFMiYbMcK2QZpOCqXMmE_6sy_ghJ0whdJdKKv6luU1_ZtTgZRBmNbxTt6CjpnFYPts-Ea4QFKNmMGQwHQYDVR0OBBYEFD_8rNYasTqegSC41SUcxWW7HpGpMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0WEOR5QzohWjDPMBIGA1UdEwEB_wQIMAYBAf8CAQAwDgYDVR0PAQH_BAQDAgKEMAoGCCqGSM49BAMCA0gAMEUCIEuKm3vugrzAM4euL8CJmLTdw42rJypFn2kMx8OS1A-OAiEA7toBXbb0MunUhDtiTJQE7zp8zL1e-yK75_65dz9ZP_tZAo8wggKLMIICMqADAgECAgkAogWe0Q5DW1cwCgYIKoZIzj0EAwIwgZgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxMzAxBgNVBAMMKkFuZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gUm9vdDAeFw0xNjAxMTEwMDQzNTBaFw0zNjAxMDYwMDQzNTBaMIGYMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYDVQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATuXV7H4cDbbQOmfua2G-xNal1qaC4P_39JDn13H0Qibb2xr_oWy8etxXfSVpyqt7AtVAFdPkMrKo7XTuxIdUGko2MwYTAdBgNVHQ4EFgQUyK3pd0xFw6PPDRYQ5HlDOiFaMM8wHwYDVR0jBBgwFoAUyK3pd0xFw6PPDRYQ5HlDOiFaMM8wDwYDVR0TAQH_BAUwAwEB_zAOBgNVHQ8BAf8EBAMCAoQwCgYIKoZIzj0EAwIDRwAwRAIgNSGj74s0Rh6c1WDzHViJIGrco2VB9g2ezooZjGZIYHsCIE0L81HZMHx9W9o1NB2oRxtjpYVlPK1PJKfnTa9BffG_aGF1dGhEYXRhWMWVaQiPHs7jIylUA129ENfK45EwWidRtVm7j9fLsim91EUAAAAAKPN9K5K4QcSwKoYM73zANABBAVUvAmX241vMKYd7ZBdmkNWaYcNYhoSZCJjFRGmROb6I4ygQUVmH6k9IMwcbZGeAQ4v4WMNphORudwje5h7ty9ClAQIDJiABIVggOEmiD94mw0sAiDkaWCd4Pf-TiAsWVAiKrfr1eiWVSaEiWCB0PEtSRc8mhc-RBUNnzU-vuUhOcFk2UQEfwNzOdiHGjw\"\n" +
      "    },\n" +
      "    \"type\": \"public-unwrap\"\n" +
      "}");

    webAuthN.authenticate(
      new JsonObject()
        .put("webauthn", webauthn)
        .put("origin", "https://webauthn.org")
        .put("challenge", "Tf65bS6D5temh2BwvptqgBPb25iZDRxjwC5ans91IIJDrcrOpnWTK4LVgFjeUV4GDMe44w8SI5NsZssIXTUvDg")
        .put("username", "paulo")
      , fn -> {
        should.assertTrue(fn.succeeded());
        test.complete();
      });
  }

  @Test(timeout = 1000)
  @Ignore("test data contains an expired certificate")
  public void testAndroidSafetyNet(TestContext should) {
    final Async test = should.async();
    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    database.add(
      new Authenticator()
        .setCredID("AVUvAmX241vMKYd7ZBdmkNWaYcNYhoSZCJjFRGmROb6I4ygQUVmH6k9IMwcbZGeAQ4v4WMNphORudwje5h7ty9A")
        .setPublicKey("pQECAyYgASFYIDhJog_eJsNLAIg5GlgneD3_k4gLFlQIiq369XollUmhIlggdDxLUkXPJoXPkQVDZ81Pr7lITnBZNlEBH8DcznYhxo8")
        .setCounter(0)
    );

    final JsonObject webauthn = new JsonObject("{\n" +
      "    \"rawId\": \"AZD7huwZVx7aW1efRa6Uq3JTQNorj3qA9yrLINXEcgvCQYtWiSQa1eOIVrXfCmip6MzP8KaITOvRLjy3TUHO7_c\",\n" +
      "    \"id\": \"AZD7huwZVx7aW1efRa6Uq3JTQNorj3qA9yrLINXEcgvCQYtWiSQa1eOIVrXfCmip6MzP8KaITOvRLjy3TUHO7_c\",\n" +
      "    \"response\": {\n" +
      "        \"clientDataJSON\": \"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVGY2NWJTNkQ1dGVtaDJCd3ZwdHFnQlBiMjVpWkRSeGp3QzVhbnM5MUlJSkRyY3JPcG5XVEs0TFZnRmplVVY0R0RNZTQ0dzhTSTVOc1pzc0lYVFV2RGciLCJvcmlnaW4iOiJodHRwczpcL1wvd2ViYXV0aG4ub3JnIiwiYW5kcm9pZFBhY2thZ2VOYW1lIjoiY29tLmFuZHJvaWQuY2hyb21lIn0\",\n" +
      "        \"attestationObject\": \"o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaDE0MzY2MDE5aHJlc3BvbnNlWRS9ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxHYTJwRFEwSkljV2RCZDBsQ1FXZEpVVkpZY205T01GcFBaRkpyUWtGQlFVRkJRVkIxYm5wQlRrSm5hM0ZvYTJsSE9YY3dRa0ZSYzBaQlJFSkRUVkZ6ZDBOUldVUldVVkZIUlhkS1ZsVjZSV1ZOUW5kSFFURlZSVU5vVFZaU01qbDJXako0YkVsR1VubGtXRTR3U1VaT2JHTnVXbkJaTWxaNlRWSk5kMFZSV1VSV1VWRkVSWGR3U0ZaR1RXZFJNRVZuVFZVNGVFMUNORmhFVkVVMFRWUkJlRTFFUVROTlZHc3dUbFp2V0VSVVJUVk5WRUYzVDFSQk0wMVVhekJPVm05M1lrUkZURTFCYTBkQk1WVkZRbWhOUTFaV1RYaEZla0ZTUW1kT1ZrSkJaMVJEYTA1b1lrZHNiV0l6U25WaFYwVjRSbXBCVlVKblRsWkNRV05VUkZVeGRtUlhOVEJaVjJ4MVNVWmFjRnBZWTNoRmVrRlNRbWRPVmtKQmIxUkRhMlIyWWpKa2MxcFRRazFVUlUxNFIzcEJXa0puVGxaQ1FVMVVSVzFHTUdSSFZucGtRelZvWW0xU2VXSXliR3RNYlU1MllsUkRRMEZUU1hkRVVWbEtTMjlhU1doMlkwNUJVVVZDUWxGQlJHZG5SVkJCUkVORFFWRnZRMmRuUlVKQlRtcFlhM293WlVzeFUwVTBiU3N2UnpWM1QyOHJXRWRUUlVOeWNXUnVPRGh6UTNCU04yWnpNVFJtU3pCU2FETmFRMWxhVEVaSWNVSnJOa0Z0V2xaM01rczVSa2N3VHpseVVsQmxVVVJKVmxKNVJUTXdVWFZ1VXpsMVowaEROR1ZuT1c5MmRrOXRLMUZrV2pKd09UTllhSHAxYmxGRmFGVlhXRU40UVVSSlJVZEtTek5UTW1GQlpucGxPVGxRVEZNeU9XaE1ZMUYxV1ZoSVJHRkROMDlhY1U1dWIzTnBUMGRwWm5NNGRqRnFhVFpJTDNob2JIUkRXbVV5YkVvck4wZDFkSHBsZUV0d2VIWndSUzkwV2xObVlsazVNRFZ4VTJ4Q2FEbG1jR293TVRWamFtNVJSbXRWYzBGVmQyMUxWa0ZWZFdWVmVqUjBTMk5HU3pSd1pYWk9UR0Y0UlVGc0swOXJhV3hOZEVsWlJHRmpSRFZ1Wld3MGVFcHBlWE0wTVROb1lXZHhWekJYYUdnMVJsQXpPV2hIYXpsRkwwSjNVVlJxWVhwVGVFZGtkbGd3YlRaNFJsbG9hQzh5VmsxNVdtcFVORXQ2VUVwRlEwRjNSVUZCWVU5RFFXeG5kMmRuU2xWTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkSlJtOUVRVlJDWjA1V1NGTlZSVVJFUVV0Q1oyZHlRbWRGUmtKUlkwUkJWRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRVTFDTUVkQk1WVmtSR2RSVjBKQ1VYRkNVWGRIVjI5S1FtRXhiMVJMY1hWd2J6UlhObmhVTm1veVJFRm1RbWRPVmtoVFRVVkhSRUZYWjBKVFdUQm1hSFZGVDNaUWJTdDRaMjU0YVZGSE5rUnlabEZ1T1V0NlFtdENaMmR5UW1kRlJrSlJZMEpCVVZKWlRVWlpkMHAzV1VsTGQxbENRbEZWU0UxQlIwZEhNbWd3WkVoQk5reDVPWFpaTTA1M1RHNUNjbUZUTlc1aU1qbHVUREprTUdONlJuWk5WRUZ5UW1kbmNrSm5SVVpDVVdOM1FXOVpabUZJVWpCalJHOTJURE5DY21GVE5XNWlNamx1VERKa2VtTnFTWFpTTVZKVVRWVTRlRXh0VG5sa1JFRmtRbWRPVmtoU1JVVkdha0ZWWjJoS2FHUklVbXhqTTFGMVdWYzFhMk50T1hCYVF6VnFZakl3ZDBsUldVUldVakJuUWtKdmQwZEVRVWxDWjFwdVoxRjNRa0ZuU1hkRVFWbExTM2RaUWtKQlNGZGxVVWxHUVhwQmRrSm5UbFpJVWpoRlMwUkJiVTFEVTJkSmNVRm5hR2cxYjJSSVVuZFBhVGgyV1ROS2MweHVRbkpoVXpWdVlqSTVia3d3WkZWVmVrWlFUVk0xYW1OdGQzZG5aMFZGUW1kdmNrSm5SVVZCWkZvMVFXZFJRMEpKU0RGQ1NVaDVRVkJCUVdSM1EydDFVVzFSZEVKb1dVWkpaVGRGTmt4TldqTkJTMUJFVjFsQ1VHdGlNemRxYW1RNE1FOTVRVE5qUlVGQlFVRlhXbVJFTTFCTVFVRkJSVUYzUWtsTlJWbERTVkZEVTFwRFYyVk1Tblp6YVZaWE5rTm5LMmRxTHpsM1dWUktVbnAxTkVocGNXVTBaVmswWXk5dGVYcHFaMGxvUVV4VFlta3ZWR2g2WTNweGRHbHFNMlJyTTNaaVRHTkpWek5NYkRKQ01HODNOVWRSWkdoTmFXZGlRbWRCU0ZWQlZtaFJSMjFwTDFoM2RYcFVPV1ZIT1ZKTVNTdDRNRm95ZFdKNVdrVldla0UzTlZOWlZtUmhTakJPTUVGQlFVWnRXRkU1ZWpWQlFVRkNRVTFCVW1wQ1JVRnBRbU5EZDBFNWFqZE9WRWRZVURJM09IbzBhSEl2ZFVOSWFVRkdUSGx2UTNFeVN6QXJlVXhTZDBwVlltZEpaMlk0WjBocWRuQjNNbTFDTVVWVGFuRXlUMll6UVRCQlJVRjNRMnR1UTJGRlMwWlZlVm8zWmk5UmRFbDNSRkZaU2t0dldrbG9kbU5PUVZGRlRFSlJRVVJuWjBWQ1FVazVibFJtVWt0SlYyZDBiRmRzTTNkQ1REVTFSVlJXTm10aGVuTndhRmN4ZVVGak5VUjFiVFpZVHpReGExcDZkMG8yTVhkS2JXUlNVbFF2VlhORFNYa3hTMFYwTW1Nd1JXcG5iRzVLUTBZeVpXRjNZMFZYYkV4UldUSllVRXg1Um1wclYxRk9ZbE5vUWpGcE5GY3lUbEpIZWxCb2RETnRNV0kwT1doaWMzUjFXRTAyZEZnMVEzbEZTRzVVYURoQ2IyMDBMMWRzUm1sb2VtaG5iamd4Ukd4a2IyZDZMMHN5VlhkTk5sTTJRMEl2VTBWNGEybFdabllyZW1KS01ISnFkbWM1TkVGc1pHcFZabFYzYTBrNVZrNU5ha1ZRTldVNGVXUkNNMjlNYkRabmJIQkRaVVkxWkdkbVUxZzBWVGw0TXpWdmFpOUpTV1F6VlVVdlpGQndZaTl4WjBkMmMydG1aR1Y2ZEcxVmRHVXZTMU50Y21sM1kyZFZWMWRsV0daVVlra3plbk5wYTNkYVltdHdiVkpaUzIxcVVHMW9kalJ5YkdsNlIwTkhkRGhRYmpod2NUaE5Na3RFWmk5UU0ydFdiM1F6WlRFNFVUMGlMQ0pOU1VsRlUycERRMEY2UzJkQmQwbENRV2RKVGtGbFR6QnRjVWRPYVhGdFFrcFhiRkYxUkVGT1FtZHJjV2hyYVVjNWR6QkNRVkZ6UmtGRVFrMU5VMEYzU0dkWlJGWlJVVXhGZUdSSVlrYzVhVmxYZUZSaFYyUjFTVVpLZG1JelVXZFJNRVZuVEZOQ1UwMXFSVlJOUWtWSFFURlZSVU5vVFV0U01uaDJXVzFHYzFVeWJHNWlha1ZVVFVKRlIwRXhWVVZCZUUxTFVqSjRkbGx0Um5OVk1teHVZbXBCWlVaM01IaE9la0V5VFZSVmQwMUVRWGRPUkVwaFJuY3dlVTFVUlhsTlZGVjNUVVJCZDA1RVNtRk5SVWw0UTNwQlNrSm5UbFpDUVZsVVFXeFdWRTFTTkhkSVFWbEVWbEZSUzBWNFZraGlNamx1WWtkVloxWklTakZqTTFGblZUSldlV1J0YkdwYVdFMTRSWHBCVWtKblRsWkNRVTFVUTJ0a1ZWVjVRa1JSVTBGNFZIcEZkMmRuUldsTlFUQkhRMU54UjFOSllqTkVVVVZDUVZGVlFVRTBTVUpFZDBGM1oyZEZTMEZ2U1VKQlVVUlJSMDA1UmpGSmRrNHdOWHByVVU4NUszUk9NWEJKVW5aS2VucDVUMVJJVnpWRWVrVmFhRVF5WlZCRGJuWlZRVEJSYXpJNFJtZEpRMlpMY1VNNVJXdHpRelJVTW1aWFFsbHJMMnBEWmtNelVqTldXazFrVXk5a1RqUmFTME5GVUZwU2NrRjZSSE5wUzFWRWVsSnliVUpDU2pWM2RXUm5lbTVrU1UxWlkweGxMMUpIUjBac05YbFBSRWxMWjJwRmRpOVRTa2d2VlV3clpFVmhiSFJPTVRGQ2JYTkxLMlZSYlUxR0t5dEJZM2hIVG1oeU5UbHhUUzg1YVd3M01Va3laRTQ0UmtkbVkyUmtkM1ZoWldvMFlsaG9jREJNWTFGQ1ltcDRUV05KTjBwUU1HRk5NMVEwU1N0RWMyRjRiVXRHYzJKcWVtRlVUa001ZFhwd1JteG5UMGxuTjNKU01qVjRiM2x1VlhoMk9IWk9iV3R4TjNwa1VFZElXR3Q0VjFrM2IwYzVhaXRLYTFKNVFrRkNhemRZY2twbWIzVmpRbHBGY1VaS1NsTlFhemRZUVRCTVMxY3dXVE42Tlc5Nk1rUXdZekYwU2t0M1NFRm5UVUpCUVVkcVoyZEZlazFKU1VKTWVrRlBRbWRPVmtoUk9FSkJaamhGUWtGTlEwRlpXWGRJVVZsRVZsSXdiRUpDV1hkR1FWbEpTM2RaUWtKUlZVaEJkMFZIUTBOelIwRlJWVVpDZDAxRFRVSkpSMEV4VldSRmQwVkNMM2RSU1UxQldVSkJaamhEUVZGQmQwaFJXVVJXVWpCUFFrSlpSVVpLYWxJclJ6UlJOamdyWWpkSFEyWkhTa0ZpYjA5ME9VTm1NSEpOUWpoSFFURlZaRWwzVVZsTlFtRkJSa3AyYVVJeFpHNUlRamRCWVdkaVpWZGlVMkZNWkM5alIxbFpkVTFFVlVkRFEzTkhRVkZWUmtKM1JVSkNRMnQzU25wQmJFSm5aM0pDWjBWR1FsRmpkMEZaV1ZwaFNGSXdZMFJ2ZGt3eU9XcGpNMEYxWTBkMGNFeHRaSFppTW1OMldqTk9lVTFxUVhsQ1owNVdTRkk0UlV0NlFYQk5RMlZuU21GQmFtaHBSbTlrU0ZKM1QyazRkbGt6U25OTWJrSnlZVk0xYm1JeU9XNU1NbVI2WTJwSmRsb3pUbmxOYVRWcVkyMTNkMUIzV1VSV1VqQm5Ra1JuZDA1cVFUQkNaMXB1WjFGM1FrRm5TWGRMYWtGdlFtZG5ja0puUlVaQ1VXTkRRVkpaWTJGSVVqQmpTRTAyVEhrNWQyRXlhM1ZhTWpsMlduazVlVnBZUW5aak1td3dZak5LTlV4NlFVNUNaMnR4YUd0cFJ6bDNNRUpCVVhOR1FVRlBRMEZSUlVGSGIwRXJUbTV1TnpoNU5uQlNhbVE1V0d4UlYwNWhOMGhVWjJsYUwzSXpVazVIYTIxVmJWbElVRkZ4TmxOamRHazVVRVZoYW5aM1VsUXlhVmRVU0ZGeU1ESm1aWE54VDNGQ1dUSkZWRlYzWjFwUksyeHNkRzlPUm5ab2MwODVkSFpDUTA5SllYcHdjM2RYUXpsaFNqbDRhblUwZEZkRVVVZzRUbFpWTmxsYVdpOVlkR1ZFVTBkVk9WbDZTbkZRYWxrNGNUTk5SSGh5ZW0xeFpYQkNRMlkxYnpodGR5OTNTalJoTWtjMmVIcFZjalpHWWpaVU9FMWpSRTh5TWxCTVVrdzJkVE5OTkZSNmN6TkJNazB4YWpaaWVXdEtXV2s0ZDFkSlVtUkJka3RNVjFwMUwyRjRRbFppZWxsdGNXMTNhMjAxZWt4VFJGYzFia2xCU21KRlRFTlJRMXAzVFVnMU5uUXlSSFp4YjJaNGN6WkNRbU5EUmtsYVZWTndlSFUyZURaMFpEQldOMU4yU2tORGIzTnBjbE50U1dGMGFpODVaRk5UVmtSUmFXSmxkRGh4THpkVlN6UjJORnBWVGpnd1lYUnVXbm94ZVdjOVBTSmRmUS5leUp1YjI1alpTSTZJa2tyVW5GVE1IVnZlSEpKYld0MkwxTXJOa3hZVlhwMlNrVTJRVkZ5UkRGNGJEQjVTM2Q0TW0xS1NUUTlJaXdpZEdsdFpYTjBZVzF3VFhNaU9qRTFOREV6TXpZM01qazVNekFzSW1Gd2ExQmhZMnRoWjJWT1lXMWxJam9pWTI5dExtZHZiMmRzWlM1aGJtUnliMmxrTG1kdGN5SXNJbUZ3YTBScFoyVnpkRk5vWVRJMU5pSTZJbVZSWXl0MmVsVmpaSGd3UmxaT1RIWllTSFZIY0VRd0sxSTRNRGR6VlVWMmNDdEtaV3hsV1ZwemFVRTlJaXdpWTNSelVISnZabWxzWlUxaGRHTm9JanAwY25WbExDSmhjR3REWlhKMGFXWnBZMkYwWlVScFoyVnpkRk5vWVRJMU5pSTZXeUk0VURGelZ6QkZVRXBqYzJ4M04xVjZVbk5wV0V3Mk5IY3JUelV3UldRclVrSkpRM1JoZVRGbk1qUk5QU0pkTENKaVlYTnBZMGx1ZEdWbmNtbDBlU0k2ZEhKMVpYMC5XTGV3N1FqemM2QTZHeVZfck1VRlhSZzEyVEtSb0ROLXJhSG9NSzY3SGdCbk5Yc0QtOUtjaG1TVFpBWWZfLXFKZE1wN1BhYml4VnF4ZDdDQzFxTFBPaUZYLVd5RGJzZlltNmRabFFiODhSd2R6LVEyUVJfTDFCN3NTaURlV1lTeDZmMm10MlQ0WXQ4MjNGNHNGYk8zVlpXM1RacmRRLXBlMVFWMEZYTTRUQ1dXbWVVRUUyWEJmaFVYbHJ5MEFicWhnQUNsWWFGcG8xdUhXUjhEOFkweDhtUDFocmVTMUtNN2NfT01lc1E5dl9mdlBETUE0SEUtYlpZbHZrRVV2VmFCeFpWVzB2SXN4eWxiWllSNVMxSjIwSXRPLV9kSDFERWRkY1kzcmc3bzd6RlJGSGFnd0QyN3dCMzlCTmk4cVNVcG1heEk1VWhrNE04X3BDSWtmLXBwaUFoYXV0aERhdGFYxZVpCI8ezuMjKVQDXb0Q18rjkTBaJ1G1WbuP18uyKb3URQAAAAAAAAAAAAAAAAAAAAAAAAAAAEEBkPuG7BlXHtpbV59FrpSrclNA2iuPeoD3Kssg1cRyC8JBi1aJJBrV44hWtd8KaKnozM_wpohM69EuPLdNQc7v96UBAgMmIAEhWCBVEWSlJerLbRupcvBaXA5Cqpp1Ba46HZTH-dqgmeMCYSJYIIlzYLPXaVavxbpZ4G6ZJWJ6hwW_NgiKAHpSNL8Bwf_d\"\n" +
      "    }\n" +
      "}");

    webAuthN.authenticate(
      new JsonObject()
        .put("webauthn", webauthn)
        .put("origin", "https://webauthn.org")
        .put("challenge", "Tf65bS6D5temh2BwvptqgBPb25iZDRxjwC5ans91IIJDrcrOpnWTK4LVgFjeUV4GDMe44w8SI5NsZssIXTUvDg")
        .put("username", "paulo")
      , fn -> {
        should.assertTrue(fn.succeeded());
        test.complete();
      });
  }

  @Test
  public void testAndroidCertificate() throws CertificateException {
    String cert = "MIIDFDCCArqgAwIBAgIBAjAKBggqhkjOPQQDAjCB3DE9MDsGA1UEAww0RkFLRSBBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3QgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTkwNDI1MDU0OTMyWhcNNDYwOTEwMDU0OTMyWjCB5DFFMEMGA1UEAww8RkFLRSBBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZSBGQUtFMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKtQYStiTRe7w7UbBEk7BUkLjB-LnbzzebLe3KB8UqHXtg3TIXXcK37dvCbbCNVfhvZxtpTcME2kooqMTgOm9cejYzBhMA8GA1UdEwEB_wQFMAMBAf8wDgYDVR0PAQH_BAQDAgKEMB0GA1UdDgQWBBSj0qos7w2M8iQC1Ry0YLy_alskFDAfBgNVHSMEGDAWgBRSmhsy4FaqzVEP71-ANwaL8pEjHTAKBggqhkjOPQQDAgNIADBFAiEAsW8uQC-0es5tOY3w_T7IshPj3o__B5IQRsHq8IlZKH0CIG75Q6isJ4twXhaLE4b0TkuLadd7i4zarqZsoaSWXy75";
    JWS.parseX5c(Base64.getUrlDecoder().decode(cert));
  }
}
