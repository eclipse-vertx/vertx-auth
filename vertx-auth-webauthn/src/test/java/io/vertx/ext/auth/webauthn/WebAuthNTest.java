package io.vertx.ext.auth.webauthn;

import com.fasterxml.jackson.core.JsonParser;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn.impl.CBOR;
import io.vertx.ext.auth.webauthn.impl.COSE;
import io.vertx.ext.jwt.JWK;
import io.vertx.ext.jwt.JWT;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.util.Base64;

@RunWith(VertxUnitRunner.class)
public class WebAuthNTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Test(timeout = 1000)
  public void testFIDORegister(TestContext should) {
    final Async test = should.async();

    WebAuthN webAuthN = WebAuthN.create(rule.vertx(), new WebAuthNOptions().setRealm("FIDO Examples Corporation").setOrigin("http://localhost:3000"), new DummyStore());

    final JsonObject webauthn = new JsonObject("{\"getClientExtensionResults\":{},\"rawId\":\"vp6cvoSgvTWSyFpnmdpm1dwiuREvsm-Kqw0Jt0Y0PQfjHsEhKE82KompUXqEt5yQIQl9ZKj6L1-700LGaVUMoQ\",\"response\":{\"attestationObject\":\"o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhAOOPecQ34VN0QW-cmj-Sft9aCahqgTlFQzbQH1LpEgrTAiBWW6KoqlKbLMtGd1Y_VcQML8eugYZcrmSSCS0of2T-M2N4NWOBWQIyMIICLjCCARigAwIBAgIECmML_zALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCkxJzAlBgNVBAMMHll1YmljbyBVMkYgRUUgU2VyaWFsIDE3NDI2MzI5NTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKQjZF26iyPtbNnl5IuTKs_fRWTHVzHxz1IHRRBrSbqWD60PCqUJPe4zkIRFqBa4NnzdhVcS80nlZuY3ANQm0J-jJjAkMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4yMAsGCSqGSIb3DQEBCwOCAQEAZTmwMqHPxEjSB64Umwq2tGDKplAcEzrwmg6kgS8KPkJKXKSu9T1H6XBM9-LAE9cN48oUirFFmDIlTbZRXU2Vm2qO9OdrSVFY-qdbF9oti8CKAmPHuJZSW6ii7qNE59dHKUaP4lDYpnhRDqttWSUalh2LPDJQUpO9bsJPkgNZAhBUQMYZXL_MQZLRYkX-ld7llTNOX5u7n_4Y5EMr-lqOyVVC9lQ6JP6xoa9q6Zp9-Y9ZmLCecrrcuH6-pLDgAzPcc8qxhC2OR1B0ZSpI9RBgcT0KqnVE0tq1KEDeokPqF3MgmDRkJ--_a2pV0wAYfPC3tC57BtBdH_UXEB8xZVFhtGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQL6enL6EoL01kshaZ5naZtXcIrkRL7JviqsNCbdGND0H4x7BIShPNiqJqVF6hLeckCEJfWSo-i9fu9NCxmlVDKGlAQIDJiABIVgg0TT3Vc7gnmO4ptAzJ671fahlgW8CrqgiCn_fPWFeEbciWCD9wLIGCTxTxmbe6ahfYQuboizWT7Y8u3BaYKSa6XTtxA\",\"clientDataJSON\":\"eyJjaGFsbGVuZ2UiOiJQZXlodVVYaVQzeG55V1pqZWNaU1NxaFVTdUttYmZPV0dGREN0OGZDUXYwIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9\"},\"id\":\"vp6cvoSgvTWSyFpnmdpm1dwiuREvsm-Kqw0Jt0Y0PQfjHsEhKE82KompUXqEt5yQIQl9ZKj6L1-700LGaVUMoQ\",\"type\":\"public-key\"}");

    webAuthN.authenticate(
      new JsonObject()
        .put("webauthn", webauthn)
        .put("challenge", "PeyhuUXiT3xnyWZjecZSSqhUSuKmbfOWGFDCt8fCQv0")
        .put("username", "paulo")
      , fn -> {
        should.assertTrue(fn.succeeded());
        test.complete();
      });
  }

  @Test(timeout = 1000)
  public void testFIDOLogin(TestContext should) {
    final Async test = should.async();
    WebAuthN webAuthN = WebAuthN.create(
      rule.vertx(),
      new WebAuthNOptions().setRealm("FIDO Examples Corporation").setOrigin("http://localhost:3000"),
      new DummyStore(
        new JsonObject()
          .put("paulo",
            new JsonArray()
              .add(
                new JsonObject()
                  .put("credID", "-r1iW_eHUyIpU93f77odIrdUlNVfYzN-JPCTWGtdn-1wxdLxhlS9NmzLNbYsQ7XVZlGSWbh_63E5oFHcNh4JNw")
                  .put("publicKey", "pQECAyYgASFYIB4QBsdBFyVm79aQFrgdhAFsV0bD0-UfzsRRihvSU8bnIlggdBaaNC3nGWGcZd1msfoD0vMt0Ydg9InOFKkz6PKUEf8")
                  .put("counter", 0)
          ))));

    final JsonObject webauthn = new JsonObject("{\"getClientExtensionResults\":{},\"rawId\":\"-r1iW_eHUyIpU93f77odIrdUlNVfYzN-JPCTWGtdn-1wxdLxhlS9NmzLNbYsQ7XVZlGSWbh_63E5oFHcNh4JNw\",\"response\":{\"authenticatorData\":\"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAFA\",\"signature\":\"MEUCIA3bv92hSE3wNz1CNGIinx27YLJgucNnBwqjV7qWqHqiAiEAjBsxBaK2nEfCilGSZ3yzoHVJilwkhOOkwZAJ52xp-h8\",\"userHandle\":null,\"clientDataJSON\":\"eyJjaGFsbGVuZ2UiOiI2b2pkb19LS0c0a1hvWjVKRF9BbHY2Q2hyVXRPT3o3dXFlaWlvRmxCc3pvIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9\"},\"id\":\"-r1iW_eHUyIpU93f77odIrdUlNVfYzN-JPCTWGtdn-1wxdLxhlS9NmzLNbYsQ7XVZlGSWbh_63E5oFHcNh4JNw\",\"type\":\"public-key\"}");

    webAuthN.authenticate(
      new JsonObject()
        .put("webauthn", webauthn)
        .put("challenge", "6ojdo_KKG4kXoZ5JD_Alv6ChrUtOOz7uqeiioFlBszo")
        .put("username", "paulo")
      , fn -> {
        should.assertTrue(fn.succeeded());
        test.complete();
      });
  }

  @Test(timeout = 1000)
  @Ignore
  public void testPAckedFull(TestContext should) {
    final Async test = should.async();
    WebAuthN webAuthN = WebAuthN.create(rule.vertx(), new WebAuthNOptions().setRealm("FIDO Examples Corporation").setOrigin("http://localhost:3000"), new DummyStore());

    final JsonObject webauthn = new JsonObject("{\n" +
      "    \"rawId\": \"wsLryOAxXMU54s2fCSWPzWjXHOBKPploN-UHftj4_rpIu6BZxNXppm82f7Y6iX9FEOKKeS5-N2TALeyzLnJfAA\",\n" +
      "    \"id\": \"wsLryOAxXMU54s2fCSWPzWjXHOBKPploN-UHftj4_rpIu6BZxNXppm82f7Y6iX9FEOKKeS5-N2TALeyzLnJfAA\",\n" +
      "    \"response\": {\n" +
      "        \"clientDataJSON\": \"eyJjaGFsbGVuZ2UiOiJZTVdFVGYtUDc5aU1iLUJxZFRreVNOUmVPdmE3bksyaVZDOWZpQzhpR3ZZeXB1bkVPQ1pHWjYtWTVPVjFydk1pRGdBaldmRmk2VUMwV3lLR3NqQS1nQSIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4ub3JnIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9\",\n" +
      "        \"attestationObject\": \"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAIzOihC6Ba80o5JnoYOJJ_EtEVmWQcAvxVCnsCFnVRQZAiAfeIddLPsPl1FeSX8B5xZANcQKGNoO7pb0TZPnuJdebGN4NWOBWQKzMIICrzCCAZegAwIBAgIESFs9tjANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDDBZZdWJpY28gRklETyBQcmV2aWV3IENBMB4XDTE4MDQxMjEwNTcxMFoXDTE4MTIzMTEwNTcxMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTIxMzkzOTEyNjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPss3TBDKMVySlDM5vYLrX0nqRtZ4eZvKXuJydQ9wrLHeIm08P-dAijLlG384BsZWJtngEqsl38oGJzNsyV0yiijbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS42MBMGCysGAQQBguUcAgEBBAQDAgQwMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER-e3H0wDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMvPkvVjXQiuvSZmGCB8NqTvGqhxyEfkoU-vz63PaaTsG3jEzjl0C7PZ26VxCvqWPJdM3P3e7Kp18sj4RjEHUmkya2PPipOwBd3p0qMQSQ8MeziCPLQ9uvGGb4YShcvaprMv4c21b4piza-znHneNCmmq-ZS4Y23o-vYv085_BEwyLPcmPjSZ5qWysCq7rVvZ7OWwcU1zu5RhSZyUKl8dzK9lAzs5OdRH2fzEewsW2OkB_Ow_jBvAxqwLXXTHuwMFaRfpmBoZuQlcofSrnwJ8KA-K-e0dKTz2zC8EbZrWYrSpbrHKyqxeBT6DkUd8H4tgAd5lOr_yqrtVmIaRfq07NmhhdXRoRGF0YVjElWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4_Xy7IpvdRBAAAAAPigEfOMCk0VgAYXER-e3H0AQMLC68jgMVzFOeLNnwklj81o1xzgSj6ZaDflB37Y-P66SLugWcTV6aZvNn-2Ool_RRDiinkufjdkwC3ssy5yXwClAQIDJiABIVggAYD1TSpf120DSVxen8ki56kF1bmT4EXO-P0JnSk5mMwiWCB3TlMZBRqPY6llzDcfHd-oW0EHdaFNgBdlGGFobpHKlw\"\n" +
      "    }");

    webAuthN.authenticate(
      new JsonObject()
        .put("webauthn", webauthn)
        .put("challenge", "qK8_4Z1aHwKAcSe-8A0m0yDflEfSi0jD-MUo9efupcs")
        .put("username", "paulo")
      , fn -> {
        should.assertTrue(fn.succeeded());
        test.complete();
      });
  }

  @Test(timeout = 1000)
  @Ignore
  public void testPAckedSurrogate(TestContext should) {
    final Async test = should.async();
    WebAuthN webAuthN = WebAuthN.create(rule.vertx(), new WebAuthNOptions().setRealm("FIDO Examples Corporation").setOrigin("http://localhost:3000"), new DummyStore());

    final JsonObject webauthn = new JsonObject("{\n" +
      "    \"id\": \"H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14\",\n" +
      "    \"rawId\": \"H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14\",\n" +
      "    \"response\": {\n" +
      "        \"attestationObject\": \"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzn__mNzaWdZAQCPypMLXWqtCZ1sc5QdjhH-pAzm8-adpfbemd5zsym2krscwV0EeOdTrdUOdy3hWj5HuK9dIX_OpNro2jKrHfUj_0Kp-u87iqJ3MPzs-D9zXOqkbWqcY94Zh52wrPwhGfJ8BiQp5T4Q97E042hYQRDKmtv7N-BT6dywiuFHxfm1sDbUZ_yyEIN3jgttJzjp_wvk_RJmb78bLPTlym83Y0Ws73K6FFeiqFNqLA_8a4V0I088hs_IEPlj8PWxW0wnIUhI9IcRf0GEmUwTBpbNDGpIFGOudnl_C3YuXuzK3R6pv2r7m9-9cIIeeYXD9BhSMBQ0A8oxBbVF7j-0xXDNrXHZaGF1dGhEYXRhWQFnSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAOKjVmSRjt0nqud40p1PeHgEAIB-l9gZ544Ds7vzo_O76UZ8DCXiWFc8DN8LWNZYQH0NepAEDAzn__iBZAQDAIqzybPPmgeL5OR6JKq9bWDiENJlN_LePQEnf1_sgOm4FJ9kBTbOTtWplfoMXg40A7meMppiRqP72A3tmILwZ5xKIyY7V8Y2t8X1ilYJol2nCKOpAEqGLTRJjF64GQxen0uFpi1tA6l6N-ZboPxjky4aidBdUP22YZuEPCO8-9ZTha8qwvTgZwMHhZ40TUPEJGGWOnHNlYmqnfFfk0P-UOZokI0rqtqqQGMwzV2RrH2kjKTZGfyskAQnrqf9PoJkye4KUjWkWnZzhkZbrDoLyTEX2oWvTTflnR5tAVMQch4UGgEHSZ00G5SFoc19nGx_UJcqezx5cLZsny-qQYDRjIUMBAAE\",\n" +
      "        \"clientDataJSON\": \"eyJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjaGFsbGVuZ2UiOiJBWGtYV1hQUDNnTHg4T0xscGtKM2FSUmhGV250blNFTmdnbmpEcEJxbDFuZ0tvbDd4V3dldlVZdnJwQkRQM0xFdmRyMkVPU3RPRnBHR3huTXZYay1WdyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ\"\n" +
      "    },\n" +
      "    \"type\": \"public-key\"\n" +
      "}");

    webAuthN.authenticate(
      new JsonObject()
        .put("webauthn", webauthn)
        .put("challenge", "AXkXWXPP3gLx8OLlpkJ3aRRhFWntnSENggnjDpBql1ngKol7xWwevUYvrpBDP3LEvdr2EOStOFpGGxnMvXk-Vw")
        .put("username", "paulo")
      , fn -> {
        should.assertTrue(fn.succeeded());
        test.complete();
      });
  }

  @Test
  public void testVerify() throws IOException {
      try (JsonParser parser = CBOR.cborParser(Base64.getDecoder().decode("pQECAyYgASFYIB4QBsdBFyVm79aQFrgdhAFsV0bD0+UfzsRRihvSU8bnIlggdBaaNC3nGWGcZd1msfoD0vMt0Ydg9InOFKkz6PKUEf8="))) {
        JWK key = COSE.toJWK(CBOR.parse(parser));
        System.out.println(key.verify(
          Base64.getUrlDecoder().decode("MEUCIA3bv92hSE3wNz1CNGIinx27YLJgucNnBwqjV7qWqHqiAiEAjBsxBaK2nEfCilGSZ3yzoHVJilwkhOOkwZAJ52xp-h8"),
          Base64.getDecoder().decode("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MBAAAAFF/+s2iT3LHeLABfvFkPvdiAp+mysYMYk94fUEZu//oj")
        ));
      }
  }
}
