package io.vertx.ext.auth.webauthn.impl.attestation;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn.*;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(VertxUnitRunner.class)
public class AttestationTest {

  private final DummyStore database = new DummyStore();

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Before
  public void resetDatabase() {
    database.clear();
  }

  @Test
  public void testPackedFullAttestation(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    JsonObject packedFullAttestationWebAuthnSample = new JsonObject()
      .put("rawId", "wsLryOAxXMU54s2fCSWPzWjXHOBKPploN-UHftj4_rpIu6BZxNXppm82f7Y6iX9FEOKKeS5-N2TALeyzLnJfAA")
      .put("id", "wsLryOAxXMU54s2fCSWPzWjXHOBKPploN-UHftj4_rpIu6BZxNXppm82f7Y6iX9FEOKKeS5-N2TALeyzLnJfAA")
      .put("response", new JsonObject()
        .put("clientDataJSON", "eyJjaGFsbGVuZ2UiOiJZTVdFVGYtUDc5aU1iLUJxZFRreVNOUmVPdmE3bksyaVZDOWZpQzhpR3ZZeXB1bkVPQ1pHWjYtWTVPVjFydk1pRGdBaldmRmk2VUMwV3lLR3NqQS1nQSIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4ub3JnIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9")
        .put("attestationObject", "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAIzOihC6Ba80o5JnoYOJJ_EtEVmWQcAvxVCnsCFnVRQZAiAfeIddLPsPl1FeSX8B5xZANcQKGNoO7pb0TZPnuJdebGN4NWOBWQKzMIICrzCCAZegAwIBAgIESFs9tjANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDDBZZdWJpY28gRklETyBQcmV2aWV3IENBMB4XDTE4MDQxMjEwNTcxMFoXDTE4MTIzMTEwNTcxMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTIxMzkzOTEyNjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPss3TBDKMVySlDM5vYLrX0nqRtZ4eZvKXuJydQ9wrLHeIm08P-dAijLlG384BsZWJtngEqsl38oGJzNsyV0yiijbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS42MBMGCysGAQQBguUcAgEBBAQDAgQwMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER-e3H0wDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMvPkvVjXQiuvSZmGCB8NqTvGqhxyEfkoU-vz63PaaTsG3jEzjl0C7PZ26VxCvqWPJdM3P3e7Kp18sj4RjEHUmkya2PPipOwBd3p0qMQSQ8MeziCPLQ9uvGGb4YShcvaprMv4c21b4piza-znHneNCmmq-ZS4Y23o-vYv085_BEwyLPcmPjSZ5qWysCq7rVvZ7OWwcU1zu5RhSZyUKl8dzK9lAzs5OdRH2fzEewsW2OkB_Ow_jBvAxqwLXXTHuwMFaRfpmBoZuQlcofSrnwJ8KA-K-e0dKTz2zC8EbZrWYrSpbrHKyqxeBT6DkUd8H4tgAd5lOr_yqrtVmIaRfq07NmhhdXRoRGF0YVjElWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4_Xy7IpvdRBAAAAAPigEfOMCk0VgAYXER-e3H0AQMLC68jgMVzFOeLNnwklj81o1xzgSj6ZaDflB37Y-P66SLugWcTV6aZvNn-2Ool_RRDiinkufjdkwC3ssy5yXwClAQIDJiABIVggAYD1TSpf120DSVxen8ki56kF1bmT4EXO-P0JnSk5mMwiWCB3TlMZBRqPY6llzDcfHd-oW0EHdaFNgBdlGGFobpHKlw"));

    webAuthN.authenticate(
        new JsonObject()
          .put("username", "paulo")
          .put("origin", "https://webauthn.org")
          .put("webauthn", packedFullAttestationWebAuthnSample)
          .put("challenge", "YMWETf-P79iMb-BqdTkySNReOva7nK2iVC9fiC8iGvYypunEOCZGZ6-Y5OV1rvMiDgAjWfFi6UC0WyKGsjA-gA"))
      .onFailure(err -> test.complete())
      .onSuccess(user -> should.fail("certificate is expired in 2018"));
  }

  @Test
  public void testNoneAttestation(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    JsonObject packedFullAttestationWebAuthnSample = new JsonObject()
      .put("rawId", "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc")
      .put("id", "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc")
      .put("type", "public-key")
      .put("response", new JsonObject()
        .put("clientDataJSON", "eyJjaGFsbGVuZ2UiOiIzM0VIYXYtaloxdjlxd0g3ODNhVS1qMEFSeDZyNW8tWUhoLXdkN0M2alBiZDdXaDZ5dGJJWm9zSUlBQ2Vod2Y5LXM2aFhoeVNITy1ISFVqRXdaUzI5dyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=")
        .put("attestationObject", "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonluvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGMpVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww=="));

    webAuthN.authenticate(
        new JsonObject()
          .put("username", "paulo")
          .put("origin", "https://localhost:8443")
          .put("webauthn", packedFullAttestationWebAuthnSample)
          .put("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w"))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  public void testNoneAttestationWithNonZeroAAGUID(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    JsonObject packedFullAttestationWebAuthnSample = new JsonObject()
      .put("rawId", "NXuPCPFpc9r3QrCL3dEQqg")
      .put("id", "NXuPCPFpc9r3QrCL3dEQqg")
      .put("type", "public-key")
      .put("response", new JsonObject()
        .put("clientDataJSON", "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoieW5CaVctWlhSdHVSTmF1OFgwRURMUSIsIm9yaWdpbiI6Imh0dHBzOlwvXC81NTlhLTEwNi0xMzktMTM4LTI0My5uZ3Jvay1mcmVlLmFwcCIsImFuZHJvaWRQYWNrYWdlTmFtZSI6ImNvbS5hbmRyb2lkLmNocm9tZSJ9")
        .put("attestationObject", "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUHT97vfV9fOzGz3r17kQoRd6881wS7VK-SXENe6WwxcddAAAAAOqbjWZNAR0hPOS2tIy1ddQAEDV7jwjxaXPa90Kwi93REKqlAQIDJiABIVggRjiIjY-sUTXhqNi5z2Pm9irTUvJnYC865BJytjXBDdsiWCD2BScW511sKkQ28ztKs_DKTVRMcYINMRMR8lwT958G8g"));

    webAuthN.authenticate(
        new WebAuthnCredentials()
          .setUsername("paulo")
          .setOrigin("https://559a-106-139-138-243.ngrok-free.app")
          .setWebauthn(packedFullAttestationWebAuthnSample)
          .setChallenge("ynBiW-ZXRtuRNau8X0EDLQ"))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  public void testU2FAttestation(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    JsonObject packedFullAttestationWebAuthnSample = new JsonObject()
      .put("rawId", "Bo-VjHOkJZy8DjnCJnIc0Oxt9QAz5upMdSJxNbd-GyAo6MNIvPBb9YsUlE0ZJaaWXtWH5FQyPS6bT_e698IirQ==")
      .put("id", "Bo-VjHOkJZy8DjnCJnIc0Oxt9QAz5upMdSJxNbd-GyAo6MNIvPBb9YsUlE0ZJaaWXtWH5FQyPS6bT_e698IirQ==")
      .put("type", "public-key")
      .put("response", new JsonObject()
        .put("clientDataJSON", "eyJjaGFsbGVuZ2UiOiJWdTh1RHFua3dPamQ4M0tMajZTY24yQmdGTkxGYkdSN0txX1hKSndRbm5hdHp0VVI3WElCTDdLOHVNUENJYVFtS3cxTUNWUTVhYXpOSkZrN05ha2dxQSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=")
        .put("attestationObject", "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEgwRgIhAO-683ISJhKdmUPmVbQuYZsp8lkD7YJcInHS3QOfbrioAiEAzgMJ499cBczBw826r1m55Jmd9mT4d1iEXYS8FbIn8MpjeDVjgVkCSDCCAkQwggEuoAMCAQICBFVivqAwCwYJKoZIhvcNAQELMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjAqMSgwJgYDVQQDDB9ZdWJpY28gVTJGIEVFIFNlcmlhbCAxNDMyNTM0Njg4MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESzMfdz2BRLmZXL5FhVF-F1g6pHYjaVy-haxILIAZ8sm5RnrgRbDmbxMbLqMkPJH9pgLjGPP8XY0qerrnK9FDCaM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwCwYJKoZIhvcNAQELA4IBAQCsFtmzbrazqbdtdZSzT1n09z7byf3rKTXra0Ucq_QdJdPnFhTXRyYEynKleOMj7bdgBGhfBefRub4F226UQPrFz8kypsr66FKZdy7bAnggIDzUFB0-629qLOmeOVeAMmOrq41uxICn3whK0sunt9bXfJTD68CxZvlgV8r1_jpjHqJqQzdio2--z0z0RQliX9WvEEmqfIvHaJpmWemvXejw1ywoglF0xQ4Gq39qB5CDe22zKr_cvKg1y7sJDvHw2Z4Iab_p5WdkxCMObAV3KbAQ3g7F-czkyRwoJiGOqAgau5aRUewWclryqNled5W8qiJ6m5RDIMQnYZyq-FTZgpjXaGF1dGhEYXRhWMRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0EAAAAAAAAAAAAAAAAAAAAAAAAAAABABo-VjHOkJZy8DjnCJnIc0Oxt9QAz5upMdSJxNbd-GyAo6MNIvPBb9YsUlE0ZJaaWXtWH5FQyPS6bT_e698IiraUBAgMmIAEhWCA1c9AIeH5sN6x1Q-2qR7v255tkeGbWs0ECCDw35kJGBCJYIBjTUxruadjFFMnWlR5rPJr23sBJT9qexY9PCc9o8hmT"));

    webAuthN.authenticate(
        new JsonObject()
          .put("username", "adam")
          .put("origin", "https://localhost:8443")
          .put("webauthn", packedFullAttestationWebAuthnSample)
          .put("challenge", "Vu8uDqnkwOjd83KLj6Scn2BgFNLFbGR7Kq_XJJwQnnatztUR7XIBL7K8uMPCIaQmKw1MCVQ5aazNJFk7NakgqA"))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Ignore()
  @Test
  public void testU2FHypersecuAttestation(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    JsonObject packedFullAttestationWebAuthnSample = new JsonObject()
      .put("rawId", "HRiuOZKJ6yNnBrSnocnFuGgsjcAZICl4-0uEDAQHCIXncWQCkYUBvvUzZQovrxmeB9Qm23hmj6PnzWyoiWtt8w")
      .put("id", "HRiuOZKJ6yNnBrSnocnFuGgsjcAZICl4-0uEDAQHCIXncWQCkYUBvvUzZQovrxmeB9Qm23hmj6PnzWyoiWtt8w")
      .put("type", "public-key")
      .put("response", new JsonObject()
        .put("clientDataJSON", "eyJjaGFsbGVuZ2UiOiJwU0c5ejZHZDVtNDhXV3c5ZTAzQUppeGJLaWEweW5FcW03b185S0VrUFkwemNhWGhqbXhvQ2hDNVFSbks0RTZYSVQyUUZjX3VHeWNPNWxVTXlnZVpndyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4ub3JnIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9")
        .put("attestationObject", "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEgwRgIhANsxYs-ntdvXjEaGTl-T91fmoSQCCzLEmXpzwuIqSrzUAiEA2vnx_cP4Ck9ASruZ7NdCtHKleCfd0NwCHcv2cMj175JjeDVjgVkBQDCCATwwgeSgAwIBAgIKOVGHiTh4UmRUCTAKBggqhkjOPQQDAjAXMRUwEwYDVQQDEwxGVCBGSURPIDAxMDAwHhcNMTQwODE0MTgyOTMyWhcNMjQwODE0MTgyOTMyWjAxMS8wLQYDVQQDEyZQaWxvdEdudWJieS0wLjQuMS0zOTUxODc4OTM4Nzg1MjY0NTQwOTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIeOKoi1TAiEYdCsb8XIAncH9Ko9EuGkXEugACIy1mV0fefgs7ZA4hnz5X3CS67eUWgMASZzpwKHVybohhppKGAwCgYIKoZIzj0EAwIDRwAwRAIg6BuIpLPxP_wPNiOJZJiqKKKlBUB2CgCwMYibSjki5S8CIOPFCx-Y1JKxbJ7nDs96PsvjDcRfpynzvswDG_V6VuK0aGF1dGhEYXRhWMSVaQiPHs7jIylUA129ENfK45EwWidRtVm7j9fLsim91EEAAAAAAAAAAAAAAAAAAAAAAAAAAABAHRiuOZKJ6yNnBrSnocnFuGgsjcAZICl4-0uEDAQHCIXncWQCkYUBvvUzZQovrxmeB9Qm23hmj6PnzWyoiWtt86UBAgMmIAEhWCCHjiqItUwIhGHQrG_FyAJ3B_SqPRLhpFxLoAAiMtZldCJYIH3n4LO2QOIZ8-V9wkuu3lFoDAEmc6cCh1cm6IYaaShg"));

    webAuthN.authenticate(
        new JsonObject()
          .put("username", "adam")
          .put("origin", "https://webauthn.org")
          .put("webauthn", packedFullAttestationWebAuthnSample)
          .put("challenge", "pSG9z6Gd5m48WWw9e03AJixbKia0ynEqm7o_9KEkPY0zcaXhjmxoChC5QRnK4E6XIT2QFc_uGycO5lUMygeZgw"))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  public void testPackedAttestation(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    JsonObject packedFullAttestationWebAuthnSample = new JsonObject()
      .put("rawId", "sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r")
      .put("id", "sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r")
      .put("type", "public-key")
      .put("response", new JsonObject()
        .put("clientDataJSON", "eyJjaGFsbGVuZ2UiOiJ1Vlg4OElnUmEwU1NyTUlSVF9xN2NSY2RmZ2ZSQnhDZ25fcGtwVUFuWEpLMnpPYjMwN3dkMU9MWFEwQXVOYU10QlIzYW1rNkhZenAtX1Z4SlRQcHdHdyIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4ub3JnIiwidG9rZW5CaW5kaW5nIjp7InN0YXR1cyI6Im5vdC1zdXBwb3J0ZWQifSwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9")
        .put("attestationObject", "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAIsK0Wr9tmud-waIYoQw20UWi7DL_gDx_PNG3PB57eHLAiEAtRyd-4JI2pCVX-dDz4mbHc_AkvC3d_4qnBBa3n2I_hVjeDVjg1kCRTCCAkEwggHooAMCAQICEBWfe8LNiRjxKGuTSPqfM-IwCgYIKoZIzj0EAwIwSTELMAkGA1UEBhMCQ04xHTAbBgNVBAoMFEZlaXRpYW4gVGVjaG5vbG9naWVzMRswGQYDVQQDDBJGZWl0aWFuIEZJRE8yIENBLTEwIBcNMTgwNDExMDAwMDAwWhgPMjAzMzA0MTAyMzU5NTlaMG8xCzAJBgNVBAYTAkNOMR0wGwYDVQQKDBRGZWl0aWFuIFRlY2hub2xvZ2llczEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEdMBsGA1UEAwwURlQgQmlvUGFzcyBGSURPMiBVU0IwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASABnVcWfvJSbAVqNIKkliXvoMKsu_oLPiP7aCQlmPlSMcfEScFM7QkRnidTP7hAUOKlOmDPeIALC8qHddvTdtdo4GJMIGGMB0GA1UdDgQWBBR6VIJCgGLYiuevhJglxK-RqTSY8jAfBgNVHSMEGDAWgBRNO9jEZxUbuxPo84TYME-daRXAgzAMBgNVHRMBAf8EAjAAMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEEI4MkVENzNDOEZCNEU1QTIwCgYIKoZIzj0EAwIDRwAwRAIgJEtFo76I3LfgJaLGoxLP-4btvCdKIsEFLjFIUfDosIcCIDQav04cJPILGnPVPazCqfkVtBuyOmsBbx_v-ODn-JDAWQH_MIIB-zCCAaCgAwIBAgIQFZ97ws2JGPEoa5NI-p8z4TAKBggqhkjOPQQDAjBLMQswCQYDVQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxHTAbBgNVBAMMFEZlaXRpYW4gRklETyBSb290IENBMCAXDTE4MDQxMDAwMDAwMFoYDzIwMzgwNDA5MjM1OTU5WjBJMQswCQYDVQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxGzAZBgNVBAMMEkZlaXRpYW4gRklETzIgQ0EtMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI5-YAnswRZlzKD6w-lv5Qg7lW1XJRHrWzL01mc5V91n2LYXNR3_S7mA5gupuTO5mjQw8xfqIRMHVr1qB3TedY-jZjBkMB0GA1UdDgQWBBRNO9jEZxUbuxPo84TYME-daRXAgzAfBgNVHSMEGDAWgBTRoZhNgX_DuWv2B2e9UBL-kEXxVDASBgNVHRMBAf8ECDAGAQH_AgEAMA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAgNJADBGAiEA-3-j0kBHoRFQwnhWbSHMkBaY7KF_TztINFN5ymDkwmUCIQDrCkPBiMHXvYg-kSRgVsKwuVtYonRvC588qRwpLStZ7FkB3DCCAdgwggF-oAMCAQICEBWfe8LNiRjxKGuTSPqfM9YwCgYIKoZIzj0EAwIwSzELMAkGA1UEBhMCQ04xHTAbBgNVBAoMFEZlaXRpYW4gVGVjaG5vbG9naWVzMR0wGwYDVQQDDBRGZWl0aWFuIEZJRE8gUm9vdCBDQTAgFw0xODA0MDEwMDAwMDBaGA8yMDQ4MDMzMTIzNTk1OVowSzELMAkGA1UEBhMCQ04xHTAbBgNVBAoMFEZlaXRpYW4gVGVjaG5vbG9naWVzMR0wGwYDVQQDDBRGZWl0aWFuIEZJRE8gUm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJ3wCm47zF9RMtW-pPlkEHTVTLfSYBlsidz7zOAUiuV6k36PvtKAI_-LZ8MiC9BxQUfUrfpLY6klw344lwLq7POjQjBAMB0GA1UdDgQWBBTRoZhNgX_DuWv2B2e9UBL-kEXxVDAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAgNIADBFAiEAt7E9ZQYxnhfsSk6c1dSmFNnJGoU3eJiycs2DoWh7-IoCIA9iWJH8h-UOAaaPK66DtCLe6GIxdpIMv3kmd1PRpWqsaGF1dGhEYXRhWOSVaQiPHs7jIylUA129ENfK45EwWidRtVm7j9fLsim91EEAAAABQjgyRUQ3M0M4RkI0RTVBMgBgsL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401rpQECAyYgASFYIFkdweEE6mWiIAYPDoKz3881Aoa4sn8zkTm0aPKKYBvdIlggtlG32lxrang8M0tojYJ36CL1VMv2pZSzqR_NfvG88bA"));

    webAuthN.authenticate(
        new JsonObject()
          .put("username", "adam")
          .put("origin", "https://webauthn.org")
          .put("webauthn", packedFullAttestationWebAuthnSample)
          .put("challenge", "uVX88IgRa0SSrMIRT_q7cRcdfgfRBxCgn_pkpUAnXJK2zOb307wd1OLXQ0AuNaMtBR3amk6HYzp-_VxJTPpwGw"))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  public void testTPMAttestation(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    JsonObject packedFullAttestationWebAuthnSample = new JsonObject()
      .put("rawId", "hWzdFiPbOMQ5KNBsMhs-Zeh8F0iTHrH63YKkrxJFgjQ")
      .put("id", "hWzdFiPbOMQ5KNBsMhs-Zeh8F0iTHrH63YKkrxJFgjQ")
      .put("response", new JsonObject()
        .put("clientDataJSON", "ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLA0KCSJjaGFsbGVuZ2UiIDogIndrNkxxRVhBTUFacHFjVFlsWTJ5b3I1RGppeUlfYjFneTluRE90Q0IxeUdZbm1fNFdHNFVrMjRGQXI3QXhUT0ZmUU1laWdrUnhPVExaTnJMeEN2Vl9RIiwNCgkib3JpZ2luIiA6ICJodHRwczovL3dlYmF1dGhuLm9yZyIsDQoJInRva2VuQmluZGluZyIgOiANCgl7DQoJCSJzdGF0dXMiIDogInN1cHBvcnRlZCINCgl9DQp9")
        .put("attestationObject", "o2NmbXRjdHBtaGF1dGhEYXRhWQFnlWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4_Xy7IpvdRFAAAAAAiYcFjK3EuBtuEw3lDcvpYAIIVs3RYj2zjEOSjQbDIbPmXofBdIkx6x-t2CpK8SRYI0pAEDAzkBACBZAQDF2m9Nk1e94gL1xVjNCjFW0lTy4K2atXkx-YJrdH3hrE8p1gcIdNzleRDhmERJnY5CRwM5sXDQIrUBq4jpwvTtMC5HGccN6-iEJAPtm9_CJzCmGhtw9hbF8bcAys94RhN9xLLUaajhWqtPrYZXCEAi0o9E2QdTIxJrcAfJgZOf33JMr0--R1BAQxpOoGRDC8ss-tfQW9ufZLWw4JUuz4Z5Jz1sbfqBYB8UUDMWoT0HgsMaPmvd7T17xGvB-pvvDf-Dt96vFGtYLEZEgho8Yu26pr5CK_BOQ-2vX9N4MIYVPXNhogMGGmKYqybhM3yhye0GdBpZBUd5iOcgME6uGJ1_IUMBAAFnYXR0U3RtdKZjdmVyYzIuMGNhbGc5__5jc2lnWQEAcV1izWGUWIs0DEOZNQGdriNNXo6nbrGDLzEAeswCK9njYGCLmOkHVgSyafhsjCEMZkQmuPUmEOMDKosqxup_tiXQwG4yCW9TyWoINWGayQ4vcr6Ys-l6KMPkg__d2VywhfonnTJDBfE_4BIRD60GR0qBzTarthDHQFMqRtoUtuOsTF5jedU3EQPojRA5iCNC2naCCZuMSURdlPmhlW5rAaRZVF41ZZECi5iFOM2rO0UpGuQSLUvr1MqQOsDytMf7qWZMvwT_5_8BF6GNdB2l2VzmIJBbV6g8z7dj0fRkjlCXBp8UG2LvTq5SsfugrRWXOJ8BkdMplPfl0mz6ssU_n2N4NWOCWQS2MIIEsjCCA5qgAwIBAgIQEyidpWZzRxOSMNfrAvV1fzANBgkqhkiG9w0BAQsFADBBMT8wPQYDVQQDEzZOQ1UtTlRDLUtFWUlELTE1OTFENEI2RUFGOThEMDEwNDg2NEI2OTAzQTQ4REQwMDI2MDc3RDMwHhcNMTgwNTIwMTYyMDQ0WhcNMjgwNTIwMTYyMDQ0WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvQ6XK2ujM11E7x4SL34p252ncyQTd3-4r5ALQhBbFKS95gUsuENTG-48GBQwu48i06cckm3eH20TUeJvn4-pj6i8LFOrIK14T3P3GFzbxgQLq1KVm63JWDdEXk789JgzQjHNO7DZFKWTEiktwmBUPUA88TjQcXOtrR5EXTrt1FzGzabOepFann3Ny_XtxI8lDZ3QLwPLJfmk7puGtkGNaXOsRC7GLAnoEB7UWvjiyKG6HAtvVTgxcW5OQnHFb9AHycU5QdukXrP0njdCpLCRR0Nq6VMKmVU3MaGh-DCwYEB32sPNPdDkPDWyk16ItwcmXqfSBV5ZOr8ifvcXbCWUWwIDAQABo4IB5TCCAeEwDgYDVR0PAQH_BAQDAgeAMAwGA1UdEwEB_wQCMAAwbQYDVR0gAQH_BGMwYTBfBgkrBgEEAYI3FR8wUjBQBggrBgEFBQcCAjBEHkIAVABDAFAAQQAgACAAVAByAHUAcwB0AGUAZAAgACAAUABsAGEAdABmAG8AcgBtACAAIABJAGQAZQBuAHQAaQB0AHkwEAYDVR0lBAkwBwYFZ4EFCAMwSgYDVR0RAQH_BEAwPqQ8MDoxODAOBgVngQUCAwwFaWQ6MTMwEAYFZ4EFAgIMB05QQ1Q2eHgwFAYFZ4EFAgEMC2lkOjRFNTQ0MzAwMB8GA1UdIwQYMBaAFMISqVvO-lb4wMFvsVvdAzRHs3qjMB0GA1UdDgQWBBSv4kXTSA8i3NUM0q57lrWpM8p_4TCBswYIKwYBBQUHAQEEgaYwgaMwgaAGCCsGAQUFBzAChoGTaHR0cHM6Ly9hemNzcHJvZG5jdWFpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L25jdS1udGMta2V5aWQtMTU5MWQ0YjZlYWY5OGQwMTA0ODY0YjY5MDNhNDhkZDAwMjYwNzdkMy8zYjkxOGFlNC0wN2UxLTQwNTktOTQ5MS0wYWQyNDgxOTA4MTguY2VyMA0GCSqGSIb3DQEBCwUAA4IBAQAs-vqdkDX09fNNYqzbv3Lh0vl6RgGpPGl-MYgO8Lg1I9UKvEUaaUHm845ABS8m7r9p22RCWO6TSEPS0YUYzAsNuiKiGVna4nB9JWZaV9GDS6aMD0nJ8kNciorDsV60j0Yb592kv1VkOKlbTF7-Z10jaapx0CqhxEIUzEBb8y9Pa8oOaQf8ORhDHZp-mbn_W8rUzXSDS0rFbWKaW4tGpVoKGRH-f9vIeXxGlxVS0wqqRm_r-h1aZInta0OOiL_S4367gZyeLL3eUnzdd-eYySYn2XINPbVacK8ZifdsLMwiNtz5uM1jbqpEn2UoB3Hcdn0hc12jTLPWFfg7GiKQ0hk9WQXsMIIF6DCCA9CgAwIBAgITMwAAAQDiBsSROVGXhwAAAAABADANBgkqhkiG9w0BAQsFADCBjDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE2MDQGA1UEAxMtTWljcm9zb2Z0IFRQTSBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDE0MB4XDTE3MDIwMTE3NDAyNFoXDTI5MTIzMTE3NDAyNFowQTE_MD0GA1UEAxM2TkNVLU5UQy1LRVlJRC0xNTkxRDRCNkVBRjk4RDAxMDQ4NjRCNjkwM0E0OEREMDAyNjA3N0QzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9IwUMSiQUbrQR0NLkKR-9RB8zfHYdlmDB0XN_m8qrNHKRJ__lBOR-mwU_h3MFRZF6X3ZZwka1DtwBdzLFV8lVu33bc15stjSd6B22HRRKQ3sIns5AYQxg0eX2PtWCJuIhxdM_jDjP2hq9Yvx-ibt1IO9UZwj83NGxXc7Gk2UvCs9lcFSp6U8zzl5fGFCKYcxIKH0qbPrzjlyVyZTKwGGSTeoMMEdsZiq-m_xIcrehYuHg-FAVaPLLTblS1h5cu80-ruFUm5Xzl61YjVU9tAV_Y4joAsJ5QP3VPocFhr5YVsBVYBiBcQtr5JFdJXZWWEgYcFLdAFUk8nJERS7-5xLuQIDAQABo4IBizCCAYcwCwYDVR0PBAQDAgGGMBsGA1UdJQQUMBIGCSsGAQQBgjcVJAYFZ4EFCAMwFgYDVR0gBA8wDTALBgkrBgEEAYI3FR8wEgYDVR0TAQH_BAgwBgEB_wIBADAdBgNVHQ4EFgQUwhKpW876VvjAwW-xW90DNEezeqMwHwYDVR0jBBgwFoAUeowKzi9IYhfilNGuVcFS7HF0pFYwcAYDVR0fBGkwZzBloGOgYYZfaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcmwwfQYIKwYBBQUHAQEEcTBvMG0GCCsGAQUFBzAChmFodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRQTSUyMFJvb3QlMjBDZXJ0aWZpY2F0ZSUyMEF1dGhvcml0eSUyMDIwMTQuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQAKc9z1UUBAaybIVnK8yL1N1iGJFFFFw_PpkxW76hgQhUcCxNFQskfahfFzkBD05odVC1DKyk2PyOle0G86FCmZiJa14MtKNsiu66nVqk2hr8iIcu-cYEsgb446yIGd1NblQKA1C_28F2KHm8YRgcFtRSkWEMuDiVMa0HDU8aI6ZHO04Naj86nXeULJSZsA0pQwNJ04-QJP3MFQzxQ7md6D-pCx-LVA-WUdGxT1ofaO5NFxq0XjubnZwRjQazy_m93dKWp19tbBzTUKImgUKLYGcdmVWXAxUrkxHN2FbZGOYWfmE2TGQXS2Z-g4YAQo1PleyOav3HNB8ti7u5HpI3t9a73xuECy2gFcZQ24DJuBaQe4mU5I_hPiAa-822nPPL6w8m1eegxhHf7ziRW_hW8s1cvAZZ5Jpev96zL_zRv34MsRWhKwLbu2oOCSEYYh8D8DbQZjmsxlUYR_q1cP8JKiIo6NNJ85g7sjTZgXxeanA9wZwqwJB-P98VdVslC17PmVu0RHOqRtxrht7OFT7Z10ecz0tj9ODXrv5nmBktmbgHRirRMl84wp7-PJhTXdHbxZv-OoL4HP6FxyDbHxLB7QmR4-VoEZN0vsybb1A8KEj2pkNY_tmxHH6k87euM99bB8FHrW9FNrXCGL1p6-PYtiky52a5YQZGT8Hz-ZnxobTmhjZXJ0SW5mb1ih_1RDR4AXACIAC7xZ9N_ZpqQtw7hmr_LfDRmCa78BS2erCtbrsXYwa4AHABSsnz8FacZi-wkUkfHu4xjG8MPfmwAAAAGxWkjHaED549jznwUBqeDEpT-7xBMAIgALcSGuv6a5r9BwMvQvCSXg7GdAjdWZpXv6D4DH8VYBCE8AIgALAVI0eQ_AAZjNvrhUEMK2q4wxuwIFOnHIDF0Qljhf47RncHViQXJlYVkBNgABAAsABgRyACCd_8vzbDg65pn7mGjcbcuJ1xU4hL4oA5IsEkFYv60irgAQABAIAAAAAAABAMXab02TV73iAvXFWM0KMVbSVPLgrZq1eTH5gmt0feGsTynWBwh03OV5EOGYREmdjkJHAzmxcNAitQGriOnC9O0wLkcZxw3r6IQkA-2b38InMKYaG3D2FsXxtwDKz3hGE33EstRpqOFaq0-thlcIQCLSj0TZB1MjEmtwB8mBk5_fckyvT75HUEBDGk6gZEMLyyz619Bb259ktbDglS7PhnknPWxt-oFgHxRQMxahPQeCwxo-a93tPXvEa8H6m-8N_4O33q8Ua1gsRkSCGjxi7bqmvkIr8E5D7a9f03gwhhU9c2GiAwYaYpirJuEzfKHJ7QZ0GlkFR3mI5yAwTq4YnX8"));

    webAuthN.authenticate(
        new JsonObject()
          .put("username", "paulo")
          .put("origin", "https://webauthn.org")
          .put("webauthn", packedFullAttestationWebAuthnSample)
          .put("challenge", "wk6LqEXAMAZpqcTYlY2yor5DjiyI_b1gy9nDOtCB1yGYnm_4WG4Uk24FAr7AxTOFfQMeigkRxOTLZNrLxCvV_Q"))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  public void testTPM2Attestation(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    JsonObject packedFullAttestationWebAuthnSample = new JsonObject()
      .put("rawId", "SErwRhxIzjPowcnM3e-D-u89EQXLUe1NYewpshd7Mc0")
      .put("id", "SErwRhxIzjPowcnM3e-D-u89EQXLUe1NYewpshd7Mc0")
      .put("type", "public-key")
      .put("response", new JsonObject()
        .put("clientDataJSON", "eyJvcmlnaW4iOiJodHRwczovL2Rldi5kb250bmVlZGEucHciLCJjaGFsbGVuZ2UiOiJhNGRlMGQzNi0wNTdkLTRlOWQtODMxYS0yYzU3OGZhODkxNzAiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0")
        .put("attestationObject", "o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzkBAGNzaWdZAQBQOHlE5VBKg1MLNOxzRaWeOjV3Yq3BdrsAH_AczyCt_-ViFhu3pHPAz96LOJSdPbx1hBXXV8luSYtoadCiu145LQ-sD_3-Cv_lnOSiVnUC1tjUx2gdAWYWbWIexQ1jQpEc0OHi7J50zrggPM8-CCknw1t2suCU5MCD-u5rG9FA8COwDDqzthYxxFHjW6FLaC_bmEKMdFWFasVP3HaS0Zm7FOXni7eVAhpAHCbF5O9-gTBS6rkKkdU9WStjU73MjbGYXQkfH0oIIbef9lk3gcoeiOCtxjbzuoJxRz88fohLRJqhMc3_bc0S8UlV2elDGCT1o53KhmM6jEpXtS5emxH_Y3ZlcmMyLjBjeDVjglkEhzCCBIMwggNroAMCAQICDwStgIiExXme4brfBK3tSDANBgkqhkiG9w0BAQsFADBBMT8wPQYDVQQDEzZOQ1UtTlRDLUtFWUlELUZGOTkwMzM4RTE4NzA3OUE2Q0Q2QTAzQURDNTcyMzc0NDVGNkE0OUEwHhcNMTgwMjAxMDAwMDAwWhcNMjUwMTMxMjM1OTU5WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwOoUlH3ttEQJ3vc3eLuB3q9pJWyFjYDPIkltrrvCCtrxkqGBUGN5NWbUxPmOlD6FN-yrZn72qvr3SAaYYmpr3zwTc8IQLk_gr5mGjSjx-tPLBvzG2ugtfo-MAtQos4-igb9YhPLEVnjNkXORdk2rKmzNkuIsHt0d13ErUjMbd0P-TSXyrK2Mqh83n0GO1JSSwYd_7Kv1UAKTc8hDHiF6G2NWv6j3dv3y81RTzMblZof_3cDS_ckM4XMhnVbtr1ZijQfFCE7MkC7Iaox2HlnR4EuPFZtmkDVA3BZBV4jJQkw3V2qWAiy8n5Gakfqu1nJ9ASdY-QjtcdxAxS5HD9YlCQIDAQABo4IBtzCCAbMwDgYDVR0PAQH_BAQDAgeAMAwGA1UdEwEB_wQCMAAwewYDVR0gAQH_BHEwbzBtBgkrBgEEAYI3FR8wYDBeBggrBgEFBQcCAjBSHlAARgBBAEsARQAgAEYASQBEAE8AIABUAEMAUABBACAAVAByAHUAcwB0AGUAZAAgAFAAbABhAHQAZgBvAHIAbQAgAEkAZABlAG4AdABpAHQAeTAQBgNVHSUECTAHBgVngQUIAzBKBgNVHREBAf8EQDA-pDwwOjE4MA4GBWeBBQIDDAVpZDoxMzAQBgVngQUCAgwHTlBDVDZ4eDAUBgVngQUCAQwLaWQ6RkZGRkYxRDAwHwYDVR0jBBgwFoAUdOhwbuNi8U8_KoCvb3uGHTvHco0wHQYDVR0OBBYEFM8mwuxelMX4CRoIgZUqNrfpeywzMHgGCCsGAQUFBwEBBGwwajBoBggrBgEFBQcwAoZcaHR0cHM6Ly9maWRvYWxsaWFuY2UuY28ubnovdHBtcGtpL05DVS1OVEMtS0VZSUQtRkY5OTAzMzhFMTg3MDc5QTZDRDZBMDNBREM1NzIzNzQ0NUY2QTQ5QS5jcnQwDQYJKoZIhvcNAQELBQADggEBAAu0b-1iYy5HRou5bvrLdAHw0T9zu_E1KLlK9p6Y0UJdkeN_ogpk4xxW_6P_-zTkr-HV7NItUg2un6sHREwSbSsZkrCL-29EU_ttKExQgEUVdMtlfmUY04fY9_yoEd22i3JBfcSfzKIIWo-ktoJa1Cdd8fLINilufLOKiAI7Rq1tAhiXAa2LDXOQhJ4pTStxoq_cVojDCXRs_ydBhsIUVk20m0WAZExpwrNnsBSsK2XgxBo-sFsCYtHMbuL4FyUujGqt5K3ARL_eCFfkqeD-6z5YteOF0kRVj5ICzZzhmv75UZCdpgAhsjzoIvIX6LM4gP9dPnuhgQbGc_e33MU97w1ZBgUwggYBMIID6aADAgECAg8EV2dM14jMuwRaKXATKH8wDQYJKoZIhvcNAQELBQAwgb8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxNjA0BgNVBAMMLUZJRE8gRmFrZSBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxODExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzAeFw0xNzAyMDEwMDAwMDBaFw0zNTAxMzEyMzU5NTlaMEExPzA9BgNVBAMTNk5DVS1OVEMtS0VZSUQtRkY5OTAzMzhFMTg3MDc5QTZDRDZBMDNBREM1NzIzNzQ0NUY2QTQ5QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANc-c30RpQd-_LCoiLJbXz3t_vqciOIovwjez79_DtVgi8G9Ph-tPL-lC0ueFGBMSPcKd_RDdSFe2QCYQd9e0DtiFxra-uWGa0olI1hHI7bK2GzNAZSTKEbwgqpf8vXMQ-7SPajg6PfxSOLH_Nj2yd6tkNkUSdlGtWfY8XGB3n-q--nt3UHdUQWEtgUoTe5abBXsG7MQSuTNoad3v6vk-tLd0W44ivM6pbFqFUHchx8mGLApCpjlVXrfROaCoc9E91hG9B-WNvekJ0dM6kJ658Hy7yscQ6JdqIEolYojCtWaWNmwcfv--OE1Ax_4Ub24gl3hpB9EOcBCzpb4UFmLYUECAwEAAaOCAXUwggFxMAsGA1UdDwQEAwIBhjAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzAbBgNVHSUEFDASBgkrBgEEAYI3FSQGBWeBBQgDMBIGA1UdEwEB_wQIMAYBAf8CAQAwHQYDVR0OBBYEFHTocG7jYvFPPyqAr297hh07x3KNMB8GA1UdIwQYMBaAFEMRFpma7p1QN8JP_uJbFckJMz8yMGgGA1UdHwRhMF8wXaBboFmGV2h0dHBzOi8vZmlkb2FsbGlhbmNlLmNvLm56L3RwbXBraS9jcmwvRklETyBGYWtlIFRQTSBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDE4LmNybDBvBggrBgEFBQcBAQRjMGEwXwYIKwYBBQUHMAKGU2h0dHBzOi8vZmlkb2FsbGlhbmNlLmNvLm56L3RwbXBraS9GSURPIEZha2UgVFBNIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTguY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQBI6GeuxIkeKcmRmFQnkPnkvSybRIJEkzWKa2f00vdBygxtzpkXF2WMHbvuMU3_K3WMFzg2xkSPjM3x_-UxOWGYgVIq8fXUdy2NhmLz4tPI65_nQXpS22rzmXFzsj4x9yS0JF2NnW5xm-O8UdckFdwIZx4Ew_zA-rIF3hqbY4Ejz2AdsbvHJo-WTpu-wWDbBQyR19eqNyYZ6vf9K8DB2JZviIDXdOpkuOJLA40MKMlnhv5K4BZs7mDZIaPzNA_MrcH3_dYXq4tIoGu5Pr1ZNCQ--93XYG1eRbvCgSDYUCRza5AgBGCIhmx2-tqLYeCd9qdy4O9R9c9qRjEThbjnGStYZ0DuB6VCaH1WjiRqyq4VNi9cv15-RoC4zswWwuHee97AAJ_Tx29w6S4Kw9DQR6A0vtw_OHLuOkGH63ns0DACf_h1MvsAMnXXX0Q0P8IpNdBQGvLvrRtRdBNx06NHY1HGZOZ9PdJ6J4mnroB2ln3cMGZG9kyRv2vbwq6sCrYZVYjo3tf4MUtkEY4FijoYbMEDK7VlbTiDPnobhkxI1-bz5DTFnR3IfVybYAeGrBCKSg2UUTPvVgM3WZ-oGlP8W9dg1347hqgxP0vLgDM6cV7rhaFC_ZAf2Et9KLRZSj7lNpJWxHxPyz9mM4w3qFwdgWKwlXl3OQtJRT4Kbs6r3gzB5WdwdWJBcmVhWQE2AAEACwAGBHIAIJ3_y_NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi_rSKuABAAEAgAAAAAAAEAyrTnIMhu5L9IekvzVTVNQC_B6KLF5RjxsGSG77uhDTH1xvx5NrWRAuPxEk72qfIIhYtjaGV7W5AE1_ukFQ5kJI6GRbWqGjXFVrr2sKdwhEt-OEYNED98w-onDJrEQzavArkvUnvrCW9DWKEXAYJTDfO5EjkOPrBdrolsn9KrLLxAwQNimvADs0DbNh_nQBouzOrLo1cqotumrB8GBgMoo1TNPNydbj6XMWBPkLr80x0l17-wZ5GoVAOkS0US0j2gSPLYKFuvbqI2uEPFFP5gXxUjHcvL8C-Jtm1RqRlwcVe7yCAEKGeAYtO_4zg57RJ9-SS5f0Ju5Ybk88GghAsVZWhjZXJ0SW5mb1it_1RDR4AXACIACxHmjtRNtTcuFCluL4Ssx4OYdRiBkh4w_CKgb4tzx5RTACDQqzIhd64iLKVs_ajjQ6oOneGWAulD1ZvjSNcImb3hEwAAAAFHcBdIVWl7S8aFYKUBc375jTRWVfsAIgALtHtW7TTkHy4bqr58TXW5fVNgPv3f6eBaub4mUtjUSbYAIgALn_Mwnd0pw9xWhM1D9xO61kUmXwLkDF8pMZ7jiRjzSqZoYXV0aERhdGFZAWc93EcQ6cCIsinbqJ1WMiC7Ofcimv9GWwplaxr7mor4oEEAAABKp9bZOooNEeialKbPcQcvcwAgSErwRhxIzjPowcnM3e-D-u89EQXLUe1NYewpshd7Mc2kAQMDOQEAIFkBAMq05yDIbuS_SHpL81U1TUAvweiixeUY8bBkhu-7oQ0x9cb8eTa1kQLj8RJO9qnyCIWLY2hle1uQBNf7pBUOZCSOhkW1qho1xVa69rCncIRLfjhGDRA_fMPqJwyaxEM2rwK5L1J76wlvQ1ihFwGCUw3zuRI5Dj6wXa6JbJ_Sqyy8QMEDYprwA7NA2zYf50AaLszqy6NXKqLbpqwfBgYDKKNUzTzcnW4-lzFgT5C6_NMdJde_sGeRqFQDpEtFEtI9oEjy2Chbr26iNrhDxRT-YF8VIx3Ly_AvibZtUakZcHFXu8ggBChngGLTv-M4Oe0SffkkuX9CbuWG5PPBoIQLFWUhQwEAAQ"));

    webAuthN.authenticate(
        new JsonObject()
          .put("username", "paulo")
          .put("origin", "https://dev.dontneeda.pw")
          .put("domain", "dev.dontneeda.pw")
          .put("webauthn", packedFullAttestationWebAuthnSample)
          .put("challenge", "a4de0d36-057d-4e9d-831a-2c578fa89170"))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  public void testBrokenSafetyNetAttestation(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    JsonObject packedFullAttestationWebAuthnSample = new JsonObject()
      .put("rawId", "qCXEfJ-dEoBlWqIl0iq2p_gj13HSg7r_MA7xOcOiO8RkCrYNmQHIjV9yhZVASr87cUsflo7DNuuvGsnrlTl1ig")
      .put("id", "qCXEfJ-dEoBlWqIl0iq2p_gj13HSg7r_MA7xOcOiO8RkCrYNmQHIjV9yhZVASr87cUsflo7DNuuvGsnrlTl1ig")
      .put("response", new JsonObject()
        .put("clientDataJSON", "eyJjaGFsbGVuZ2UiOiJEa1hCdWRCa2wzTzBlTUV5SGZBTVgxT2tRbHV4c2hjaW9WU3dITVJMUlhtd044SXJldHg3cWJ0MWx3Y0p4d0FxWUU0SUxTZjVwd3lHMEhXSWtEekVMUT09Iiwib3JpZ2luIjoid2ViYXV0aG4ub3JnIiwiaGFzaEFsZyI6IlNIQS0yNTYifQ")
        .put("attestationObject", "o2hhdXRoRGF0YVjElWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4_Xy7IpvdRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQKglxHyfnRKAZVqiJdIqtqf4I9dx0oO6_zAO8TnDojvEZAq2DZkByI1fcoWVQEq_O3FLH5aOwzbrrxrJ65U5dYqlAQIDJiABIVggh5OJfYRDzVGIowKqU57AnoVjjdmmjGi9zlMkjAVV9DAiWCDr0iSi0viIKNPMTIdN28gWNmkcwOr6DQx66MPff3Odm2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaDEyNjg1MDIzaHJlc3BvbnNlWRSnZXlKaGJHY2lPaUpTVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxGYVdwRFEwRXpTMmRCZDBsQ1FXZEpTVmxyV1c4MVJqQm5PRFpyZDBSUldVcExiMXBKYUhaalRrRlJSVXhDVVVGM1ZrUkZURTFCYTBkQk1WVkZRbWhOUTFaV1RYaElha0ZqUW1kT1ZrSkJiMVJHVldSMllqSmtjMXBUUWxWamJsWjZaRU5DVkZwWVNqSmhWMDVzWTNwRmJFMURUVWRCTVZWRlFYaE5ZMUl5T1haYU1uaHNTVVZzZFdSSFZubGliVll3U1VWR01XUkhhSFpqYld3d1pWTkNTRTE2UVdWR2R6QjRUbnBGZVUxRVVYaE5la1UwVGtST1lVWjNNSGhQUkVWNVRVUk5kMDFFUVhkTlJFSmhUVWQzZUVONlFVcENaMDVXUWtGWlZFRnNWbFJOVWsxM1JWRlpSRlpSVVVsRVFYQkVXVmQ0Y0ZwdE9YbGliV3hvVFZKWmQwWkJXVVJXVVZGSVJFRXhUbUl6Vm5Wa1IwWndZbWxDVjJGWFZqTk5VazEzUlZGWlJGWlJVVXRFUVhCSVlqSTVibUpIVldkVFZ6VnFUVkp6ZDBkUldVUldVVkZFUkVKS2FHUklVbXhqTTFGMVdWYzFhMk50T1hCYVF6VnFZakl3ZDJkblJXbE5RVEJIUTFOeFIxTkpZak5FVVVWQ1FWRlZRVUUwU1VKRWQwRjNaMmRGUzBGdlNVSkJVVU5WYWpoM1dXOVFhWGhMWW1KV09ITm5XV2QyVFZSbVdDdGtTWE5HVkU5clowdFBiR2hVTUdrd1ltTkVSbHBMTW5KUGVFcGFNblZUVEZOV2FGbDJhWEJhVGtVelNFcFJXWFYxV1hkR2FtbDVLM2xyWm1GMFFVZFRhbEo2UmpGaU16RjFORE12TjI5SE5XcE5hRE5UTXpkaGJIZHFWV0k0UTFkcFZIaHZhWEJXVDFsM1MwdDZkVlY1YTNGRlEzUnFiR2hLTkVGclYyRkVVeXRhZUV0RmNVOWhaVGwwYmtOblpVaHNiRnBGTDA5U1oyVk5ZWGd5V0U1RGIwZzJjM0pVUlZKamEzTnFlbHBhY2tGWGVFdHpaR1oyVm5KWVRucERVamxFZUZaQlUzVkpOa3g2ZDJnNFJGTnNNa1ZQYjJ0aWMyRnVXaXNyTDBweFRXVkJRa1ptVUhkcWVYZHlZakJ3Y2tWVmVUQndZV1ZXYzNWa0t6QndaV1Y0U3k4MUswVTJhM0JaUjBzMFdrc3libXR2Vmt4MVowVTFkR0ZJY2tGcU9ETlJLMUJQWW1KMlQzcFhZMFpyY0c1V1MzbHFielpMVVVGdFdEWlhTa0ZuVFVKQlFVZHFaMmRHUjAxSlNVSlJha0ZVUW1kT1ZraFRWVVZFUkVGTFFtZG5ja0puUlVaQ1VXTkVRVlJCWkVKblRsWklVa1ZGUm1wQlZXZG9TbWhrU0ZKc1l6TlJkVmxYTld0amJUbHdXa00xYW1JeU1IZGhRVmxKUzNkWlFrSlJWVWhCVVVWRldFUkNZVTFETUVkRFEzTkhRVkZWUmtKNlFVTm9hVVp2WkVoU2QwOXBPSFpqUjNSd1RHMWtkbUl5WTNaYU0wNTVUV2s1U0ZaR1RraFRWVVpJVFhrMWFtTnVVWGRMVVZsSlMzZFpRa0pSVlVoTlFVZEhTRmRvTUdSSVFUWk1lVGwyV1ROT2QweHVRbkpoVXpWdVlqSTVia3d3WkZWVk1HUktVVlZqZWsxQ01FZEJNVlZrUkdkUlYwSkNVVWM0U1hKUmRFWlNOa05WVTJ0cGEySXpZV2x0YzIweU5tTkNWRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRVTFDT0VkQk1WVmtTWGRSV1UxQ1lVRkdTR1pEZFVaRFlWb3pXakp6VXpORGFIUkRSRzlJTm0xbWNuQk1UVU5GUjBFeFZXUkpRVkZoVFVKbmQwUkJXVXRMZDFsQ1FrRklWMlZSU1VaQmVrRkpRbWRhYm1kUmQwSkJaMGwzVFZGWlJGWlNNR1pDUTI5M1MwUkJiVzlEVTJkSmIxbG5ZVWhTTUdORWIzWk1NazU1WWtNMWQyRXlhM1ZhTWpsMlduazVTRlpHVGtoVFZVWklUWGsxYW1OdGQzZEVVVmxLUzI5YVNXaDJZMDVCVVVWTVFsRkJSR2RuUlVKQlJpOVNlazV1UXpWRWVrSlZRblJ1YURKdWRFcE1WMFZSYURsNlJXVkdXbVpRVERsUmIydHliRUZ2V0dkcVYyZE9PSEJUVWxVeGJGWkhTWEIwZWsxNFIyaDVNeTlQVWxKYVZHRTJSREpFZVRob2RrTkVja1pKTXl0c1Exa3dNVTFNTlZFMldFNUZOVkp6TW1ReFVtbGFjRTF6ZWtRMFMxRmFUa2N6YUZvd1FrWk9VUzlqYW5KRGJVeENUMGRMYTBWVk1XUnRRVmh6UmtwWVNtbFBjakpEVGxSQ1QxUjFPVVZpVEZkb1VXWmtRMFl4WW5kNmVYVXJWelppVVZOMk9GRkVialZQWkUxVEwxQnhSVEZrUldkbGRDODJSVWxTUWpjMk1VdG1XbEVyTDBSRk5reHdNMVJ5V2xSd1QwWkVSR2RZYUN0TVowZFBjM2RvUld4cU9XTXpkbHBJUjBwdWFHcHdkRGh5YTJKcGNpOHlkVXhIWm5oc1ZsbzBTekY0TlVSU1RqQlFWVXhrT1hsUVUyMXFaeXRoYWpFcmRFaDNTVEZ0VVcxYVZsazNjWFpQTlVSbmFFOTRhRXBOUjJ4Nk5teE1hVnB0ZW05blBTSXNJazFKU1VWWVJFTkRRVEJUWjBGM1NVSkJaMGxPUVdWUGNFMUNlamhqWjFrMFVEVndWRWhVUVU1Q1oydHhhR3RwUnpsM01FSkJVWE5HUVVSQ1RVMVRRWGRJWjFsRVZsRlJURVY0WkVoaVJ6bHBXVmQ0VkdGWFpIVkpSa3AyWWpOUloxRXdSV2RNVTBKVFRXcEZWRTFDUlVkQk1WVkZRMmhOUzFJeWVIWlpiVVp6VlRKc2JtSnFSVlJOUWtWSFFURlZSVUY0VFV0U01uaDJXVzFHYzFVeWJHNWlha0ZsUm5jd2VFNTZRVEpOVkZWM1RVUkJkMDVFU21GR2R6QjVUVlJGZVUxVVZYZE5SRUYzVGtSS1lVMUdVWGhEZWtGS1FtZE9Wa0pCV1ZSQmJGWlVUVkkwZDBoQldVUldVVkZMUlhoV1NHSXlPVzVpUjFWblZraEtNV016VVdkVk1sWjVaRzFzYWxwWVRYaEtWRUZxUW1kT1ZrSkJUVlJJUldSMllqSmtjMXBUUWtwaWJsSnNZMjAxYkdSRFFrSmtXRkp2WWpOS2NHUklhMmRTZWsxM1oyZEZhVTFCTUVkRFUzRkhVMGxpTTBSUlJVSkJVVlZCUVRSSlFrUjNRWGRuWjBWTFFXOUpRa0ZSUkV0VmEzWnhTSFl2VDBwSGRXOHlia2xaWVU1V1YxaFJOVWxYYVRBeFExaGFZWG8yVkVsSVRFZHdMMnhQU2lzMk1EQXZOR2hpYmpkMmJqWkJRVUl6UkZaNlpGRlBkSE0zUnpWd1NEQnlTbTV1VDBaVlFVczNNVWMwYm5wTFRXWklRMGRWYTNOWEwyMXZibUVyV1RKbGJVcFJNazRyWVdsamQwcExaWFJRUzFKVFNXZEJkVkJQUWpaQllXaG9PRWhpTWxoUE0yZzVVbFZyTWxRd1NFNXZkVUl5Vm5wNGIwMVliR3Q1VnpkWVZWSTFiWGMyU210TVNHNUJOVEpZUkZadlVsUlhhMDUwZVRWdlEwbE9USFpIYlc1U2Mwb3hlbTkxUVhGWlIxWlJUV012TjNONUt5OUZXV2hCVEhKV1NrVkJPRXRpZEhsWUszSTRjMjUzVlRWRE1XaFZjbmRoVnpaTlYwOUJVbUU0Y1VKd1RsRmpWMVJyWVVsbGIxbDJlUzl6UjBsS1JXMXFVakIyUmtWM1NHUndNV05UWVZkSmNqWXZOR2MzTW00M1QzRllkMlpwYm5VM1dsbFhPVGRGWm05UFUxRktaVUY2UVdkTlFrRkJSMnBuWjBWNlRVbEpRa3g2UVU5Q1owNVdTRkU0UWtGbU9FVkNRVTFEUVZsWmQwaFJXVVJXVWpCc1FrSlpkMFpCV1VsTGQxbENRbEZWU0VGM1JVZERRM05IUVZGVlJrSjNUVU5OUWtsSFFURlZaRVYzUlVJdmQxRkpUVUZaUWtGbU9FTkJVVUYzU0ZGWlJGWlNNRTlDUWxsRlJraG1RM1ZHUTJGYU0xb3ljMU16UTJoMFEwUnZTRFp0Wm5Kd1RFMUNPRWRCTVZWa1NYZFJXVTFDWVVGR1NuWnBRakZrYmtoQ04wRmhaMkpsVjJKVFlVeGtMMk5IV1ZsMVRVUlZSME5EYzBkQlVWVkdRbmRGUWtKRGEzZEtla0ZzUW1kbmNrSm5SVVpDVVdOM1FWbFpXbUZJVWpCalJHOTJUREk1YW1NelFYVmpSM1J3VEcxa2RtSXlZM1phTTA1NVRXcEJlVUpuVGxaSVVqaEZTM3BCY0UxRFpXZEtZVUZxYUdsR2IyUklVbmRQYVRoMldUTktjMHh1UW5KaFV6VnVZakk1Ymt3eVpIcGpha2wyV2pOT2VVMXBOV3BqYlhkM1VIZFpSRlpTTUdkQ1JHZDNUbXBCTUVKbldtNW5VWGRDUVdkSmQwdHFRVzlDWjJkeVFtZEZSa0pSWTBOQlVsbGpZVWhTTUdOSVRUWk1lVGwzWVRKcmRWb3lPWFphZVRsNVdsaENkbU15YkRCaU0wbzFUSHBCVGtKbmEzRm9hMmxIT1hjd1FrRlJjMFpCUVU5RFFWRkZRVWhNWlVwc2RWSlVOMkoyY3pJMlozbEJXamh6YnpneGRISlZTVk5rTjA4ME5YTnJSRlZ0UVdkbE1XTnVlR2hITVZBeVkwNXRVM2hpVjNOdmFVTjBNbVYxZURsTVUwUXJVRUZxTWt4SldWSkdTRmN6TVM4MmVHOXBZekZyTkhSaVYxaHJSRU5xYVhJek4zaFVWRTV4VWtGTlVGVjVSbEpYVTJSMmRDdHViRkJ4ZDI1aU9FOWhNa2t2YldGVFNuVnJZM2hFYWs1VFpuQkVhQzlDWkRGc1drNW5aR1F2T0dOTVpITkZNeXQzZVhCMVprbzVkVmhQTVdsUmNHNW9PWHBpZFVaSmQzTkpUMDVIYkRGd00wRTRRMmQ0YTNGSkwxVkJhV2d6U21GSFQzRmpjR05rWVVOSmVtdENZVkk1ZFZsUk1WZzBhekpXWnpWQlVGSk1iM1Y2Vm5rM1lUaEpWbXMyZDNWNU5uQnRLMVEzU0ZRMFRGazRhV0pUTlVaRldteG1RVVpNVTFjNFRuZHpWbm81VTBKTE1sWnhiakZPTUZCSlRXNDFlRUUyVGxwV1l6ZHZPRE0xUkV4QlJuTm9SVmRtUXpkVVNXVXpaejA5SWwxOS5leUp1YjI1alpTSTZJbXhYYTBscWVEZFBOSGxOY0ZaQlRtUjJVa1JZZVhWUFVrMUdiMjVWWWxaYWRUUXZXSGszU1hCMlpGSkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVkZMWjJ4NFNIbG1ibEpMUVZwV2NXbEtaRWx4ZEhGbU5FazVaSGd3YjA4MkwzcEJUemhVYmtSdmFuWkZXa0Z4TWtSYWEwSjVTVEZtWTI5WFZsRkZjUzlQTTBaTVNEVmhUM2Q2WW5KeWVISktOalZWTldSWmNXeEJVVWxFU21sQlFrbFdaMmRvTlU5S1psbFNSSHBXUjBsdmQwdHhWVFUzUVc1dlZtcHFaRzF0YWtkcE9YcHNUV3RxUVZaV09VUkJhVmREUkhJd2FWTnBNSFpwU1V0T1VFMVVTV1JPTWpoblYwNXRhMk4zVDNJMlJGRjROalpOVUdabU0wOWtiU3QxTm1WS2NVeENiREZJTWxNeWRISkJRa2hNYVc1cmJuTjVWazFRYlM5Q1RsVldXakpLUm14eU9EQWlMQ0owYVcxbGMzUmhiWEJOY3lJNk1UVXlPRGt4TVRZek5ETTROU3dpWVhCclVHRmphMkZuWlU1aGJXVWlPaUpqYjIwdVoyOXZaMnhsTG1GdVpISnZhV1F1WjIxeklpd2lZWEJyUkdsblpYTjBVMmhoTWpVMklqb2lTazlETTFWcmMyeHpkVlo2TVRObFQzQnVSa2s1UW5CTWIzRkNaemxyTVVZMlQyWmhVSFJDTDBkcVRUMGlMQ0pqZEhOUWNtOW1hV3hsVFdGMFkyZ2lPbVpoYkhObExDSmhjR3REWlhKMGFXWnBZMkYwWlVScFoyVnpkRk5vWVRJMU5pSTZXeUpIV0ZkNU9GaEdNM1pKYld3ekwwMW1ibTFUYlhsMVMwSndWRE5DTUdSWFlraFNVaTgwWTJkeEsyZEJQU0pkTENKaVlYTnBZMGx1ZEdWbmNtbDBlU0k2Wm1Gc2MyVXNJbUZrZG1salpTSTZJbEpGVTFSUFVrVmZWRTlmUmtGRFZFOVNXVjlTVDAwc1RFOURTMTlDVDA5VVRFOUJSRVZTSW4wLmlDRjZEMm9zOERZdURWT250M3pESkIybVNYblpqdFdKdGxfanpTRHg1TXJSQzlBMmZtRkJaNno1a3BRWjJNaVE3b290ajlXa0hNZ3hxSWhyWDNkbGgyUE9IQXdrSVMzNHlTakxWTnNTUHByRTg0ZVpncVNGTE1FWVQwR1IyZVZMSEFNUE44bjVSOEs2YnVET0dGM25TaTZHS3pHNTdabGw4Q1NvYjJ5aUFTOXI3c3BkQTZIMFRESC1OR3pTZGJNSUlkOGZaRDFkekZLTlFyNzdiNmxiSUFGZ1FiUlpCcm5wLWUtSDRpSDZkMjFvTjJOQVlSblI1WVVSYWNQNmtHR2oyY0Z4c3dFMjkwOHd4djloaVlOS05vamVldThYYzRJdDdQYmhsQXVPN3l3aFFGQTgxaVBDQ0ZtMTFCOGNmVVhiV0E4bF8ydHROUEJFTUdNNi1aNlZ5UQ"));

    webAuthN.authenticate(
        new JsonObject()
          .put("username", "adam")
          .put("origin", "webauthn.org")
          .put("webauthn", packedFullAttestationWebAuthnSample)
          .put("challenge", "DkXBudBkl3O0eMEyHfAMX1OkQluxshcioVSwHMRLRXmwN8Iretx7qbt1lwcJxwAqYE4ILSf5pwyG0HWIkDzELQ=="))
      .onFailure(err -> test.complete())
      .onSuccess(user -> {
        should.fail("This attestation is missing a type");
      });
  }

  @Test
  @Ignore("Attestation Certificate is expired")
  public void testSafetyNetAttestation(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation"))
          .setTimeoutInMilliseconds(System.currentTimeMillis()))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    JsonObject packedFullAttestationWebAuthnSample = new JsonObject()
      .put("rawId", "AQsMmnEQ8OxpZxijXBMT4tyamgkqC_3hr18_e8KeK8nG69ijcTaXNKX_CRmYiW0fegPE0N_3NVHEaj_kit7LPNM")
      .put("id", "AQsMmnEQ8OxpZxijXBMT4tyamgkqC_3hr18_e8KeK8nG69ijcTaXNKX_CRmYiW0fegPE0N_3NVHEaj_kit7LPNM")
      .put("response", new JsonObject()
        .put("clientDataJSON", "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQUhOWlE1WWFoZVpZOF9lYXdvM0VITHlXdjhCemlqaXFzQlVlNDZ2LVFTZyIsIm9yaWdpbiI6Imh0dHA6XC9cL2xvY2FsaG9zdDo0MjAwIiwiYW5kcm9pZFBhY2thZ2VOYW1lIjoiY29tLmFuZHJvaWQuY2hyb21lIn0")
        .put("attestationObject",
          "o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaTIxMjQxODA0NmhyZXNwb25zZVkgcmV5SmhiR2Np" +
            "T2lKU1V6STFOaUlzSW5nMVl5STZXeUpOU1VsR1dIcERRMEpGWldkQmQwbENRV2RKVVdadE9HbFpXbnAxY1RCRlNr" +
            "RkJRVUZCU0RkMVVsUkJUa0puYTNGb2EybEhPWGN3UWtGUmMwWkJSRUpIVFZGemQwTlJXVVJXVVZGSFJYZEtWbFY2" +
            "UldsTlEwRkhRVEZWUlVOb1RWcFNNamwyV2pKNGJFbEdVbmxrV0U0d1NVWk9iR051V25CWk1sWjZTVVY0VFZGNlJW" +
            "Uk5Ra1ZIUVRGVlJVRjRUVXRTTVZKVVNVVk9Ra2xFUmtWT1JFRmxSbmN3ZVUxVVFUTk5WR3Q0VFhwRmVrNUVTbUZH" +
            "ZHpCNVRWUkZkMDFVWTNoTmVrVjZUa1JHWVUxQ01IaEhla0ZhUW1kT1ZrSkJUVlJGYlVZd1pFZFdlbVJETldoaWJW" +
            "SjVZakpzYTB4dFRuWmlWRU5EUVZOSmQwUlJXVXBMYjFwSmFIWmpUa0ZSUlVKQ1VVRkVaMmRGVUVGRVEwTkJVVzlE" +
            "WjJkRlFrRkxaazVUUWxsNE0wMDJTbkpKYVRCTVVVUkdORlZhYUhSemVUZ3lRMjgwVG5aM2NpOUdTVzQzTHpsbksz" +
            "aHpWM3BEV1dkU04xRnpSMjF5ZVVjNWRsQkdja2Q1VVhKRlpHcERVWFZDVTFGVGQyOXZOR2R3YVVocGR6RllibkZH" +
            "Wm5KT1l6SjNURkpQTDFCVWRTdGhhMFpFU1UwMlozVXpaR1JuZDFGWFIwZGFjbFpRZWt0RmFrOTVUbE5HVFVKTU1G" +
            "ZEJTMmwxZFZsQ2RqRTBVWFp1YmxjeFJXdFpZbkZLWkZSb05reFhabVYyWTFkU1N5dFVkRlpoT1hwelIyNUZibWMz" +
            "YTAxUVYxQkNTekJPTUdKUVozaGlOR3B1ZUdGSWNXeE1lSEV2UTJwRWJreHJSRVZrZFdabFZEVlZaM0pzVkc1M09W" +
            "VnRXbTFOZUdGUWRHRXZkbm93WTJnMlpteERkM2xwZG1wSGFqSjRWRWhMVmxsMmJWbHdORlJtVEdjd1kxVk9VRVV4" +
            "WkV0cVRrbGlTMWxEZUZGSlZucHVlSFY0WlhCVVUxWnBXWFZqVUVZMFZuZHVLelpFT1ZwNFVVcEtLeTlsTmt0TVNX" +
            "dERRWGRGUVVGaFQwTkJia0YzWjJkS2MwMUJORWRCTVZWa1JIZEZRaTkzVVVWQmQwbEdiMFJCVkVKblRsWklVMVZG" +
            "UkVSQlMwSm5aM0pDWjBWR1FsRmpSRUZVUVUxQ1owNVdTRkpOUWtGbU9FVkJha0ZCVFVJd1IwRXhWV1JFWjFGWFFr" +
            "SlVUWE5VU1RWeFowRlBVbXRCWkROTlVFd3dOV2cwTm1KdlZsaEVRV1pDWjA1V1NGTk5SVWRFUVZkblFsRnNOR2hu" +
            "VDNOc1pWSnNRM0pzTVVZeVIydEpVR1ZWTjA4MGEycENkRUpuWjNKQ1owVkdRbEZqUWtGUlVtaE5SamgzUzJkWlNV" +
            "dDNXVUpDVVZWSVRVRkhSMGh0YURCa1NFRTJUSGs1ZGxrelRuZE1ia0p5WVZNMWJtSXlPVzVNTW1Rd1kzcEdhMDVI" +
            "YkhWa1JFRjRRbWRuY2tKblJVWkNVV04zUVc5WmJHRklVakJqUkc5MlRETkNjbUZUTlc1aU1qbHVURE5LYkdOSE9I" +
            "WlpNbFo1WkVoTmRsb3pVbnBOVjFFd1RHMVNiR05xUVdSQ1owNVdTRkpGUlVacVFWVm5hRXBvWkVoU2JHTXpVWFZa" +
            "VnpWclkyMDVjRnBETldwaU1qQjNTVkZaUkZaU01HZENRbTkzUjBSQlNVSm5XbTVuVVhkQ1FXZEZkMFJCV1V0TGQx" +
            "bENRa0ZJVjJWUlNVWkJla0V2UW1kT1ZraFNPRVZQUkVFeVRVUlRaMDF4UVhkb2FUVnZaRWhTZDA5cE9IWlpNMHB6" +
            "WTNrMWQyRXlhM1ZhTWpsMlduazVibVJJVFhoYVJGSndZbTVSZGxnd1dsRmpXRVpLVTBka1dVNXFaM1ZaTTBwelRV" +
            "bEpRa0YzV1V0TGQxbENRa0ZJVjJWUlNVVkJaMU5DT1VGVFFqaFJSSFpCU0ZWQldFNTRSR3QyTjIxeE1GWkZjMVky" +
            "WVRGR1ltMUZSR1kzTVdad1NETkxSbnBzVEVwbE5YWmlTRVJ6YjBGQlFVWTJkbmd5VHpGblFVRkNRVTFCVW1wQ1JV" +
            "RnBRa3AxVjFCU2JWSk5kbXBqVkZWd1NXSnlUa3RvT0hONFlrZDRUbEJOWm14aWNuWXhaSGhVYWtwM1EyZEpaMU01" +
            "ZDJkTVZVcGxVWEZNVFZJNFdHVnVSMDVtZVZsb1lYRnNjbEo0ZUUwNGMxQTRWa2x3VVVkVFV6QkJaR2RDT1ZCMlRE" +
            "UnFMeXRKVmxkbmEzZHpSRXR1YkV0S1pWTjJSa1J1WjBwbWVUVnhiREpwV21acFRIY3hkMEZCUVZoeEwwaFpLMHRC" +
            "UVVGRlFYZENTRTFGVlVOSlJESk1NbkpJUW14S2FUbFNSbTlQWmtWQ00yUjRTR1ZJVjFSS2QzTndORFpKWmtscU5t" +
            "OUxTM0JZWWtGcFJVRXlOVk5aUmswNFp6RlVLMGRKVlhKVlRUQjRZMDVVZDJrdmJISnhhRmxyVVUxSEswWnpNbVp0" +
            "Um1SSmQwUlJXVXBMYjFwSmFIWmpUa0ZSUlV4Q1VVRkVaMmRGUWtGRU5qaG1lRWhNZUU5REsxWnNUakZTVGtONVMy" +
            "UlVjV1pJWWxKQlFXUk9XVmczTjBoWEwyMVFRbTVWUXpGb2NtVlVSM2hIZUZOT01VUm9hazF4Tkhwb09GQkRiVEI2" +
            "TDNKQ00zQkVkMmxuYldsTmRtRllVRVZFYXpaRWJHbE5VMFY1WkRCak5ua3dPV2cxVjA1WFRpOWplR3BITDNWUk1E" +
            "SjZSRU12UldrdlptUkZaM1V5TVVobmVITTNRMFZVZFROMFpUWkNiekZTZUM5NFIxRnRLMnRvTlhZd2NIWXJhVmw2" +
            "Y25oVmJFOHZUV1J2YjJsa2VqbENRMWhYT0haeVRVbzJVbk5SVmxKUWVUUjVSbGN2TXpjeU4yeDFSRnBaTUVoME5X" +
            "MUZSa2xLUTNCV1EybENUSE5wZURCd2JWUnNhMXBhZFhSRWFDOHZUV1JOTlVFME56RldRVU14VTBsNGVrTXpUMkYw" +
            "ZEZoV1RGTnRTWFpuZDFoWFlsbzVhekpzZWtwcGVrRnNiRkpMVld0TlRGUmtjMDlFY0RVek0yNVBhMlJXVTFvMlpp" +
            "dEljbkZKYzFSTVRuTTFVVk5MWWtVMGNuaHlkbFpPS3pROUlpd2lUVWxKUm1wRVEwTkJNMU5uUVhkSlFrRm5TVTVC" +
            "WjBOUGMyZEplazV0VjB4YVRUTmliWHBCVGtKbmEzRm9hMmxIT1hjd1FrRlJjMFpCUkVKSVRWRnpkME5SV1VSV1VW" +
            "RkhSWGRLVmxWNlJXbE5RMEZIUVRGVlJVTm9UVnBTTWpsMldqSjRiRWxHVW5sa1dFNHdTVVpPYkdOdVduQlpNbFo2" +
            "U1VWNFRWRjZSVlZOUWtsSFFURlZSVUY0VFV4U01WSlVTVVpLZG1JelVXZFZha1YzU0doalRrMXFRWGRQUkVWNlRV" +
            "UkJkMDFFVVhsWGFHTk9UV3BqZDA5VVRYZE5SRUYzVFVSUmVWZHFRa2ROVVhOM1ExRlpSRlpSVVVkRmQwcFdWWHBG" +
            "YVUxRFFVZEJNVlZGUTJoTldsSXlPWFphTW5oc1NVWlNlV1JZVGpCSlJrNXNZMjVhY0ZreVZucEpSWGhOVVhwRlZF" +
            "MUNSVWRCTVZWRlFYaE5TMUl4VWxSSlJVNUNTVVJHUlU1RVEwTkJVMGwzUkZGWlNrdHZXa2xvZG1OT1FWRkZRa0pS" +
            "UVVSblowVlFRVVJEUTBGUmIwTm5aMFZDUVV0MlFYRnhVRU5GTWpkc01IYzVla000WkZSUVNVVTRPV0pCSzNoVWJV" +
            "UmhSemQ1TjFabVVUUmpLMjFQVjJoc1ZXVmlWVkZ3U3pCNWRqSnlOamM0VWtwRmVFc3dTRmRFYW1WeEsyNU1TVWhP" +
            "TVVWdE5XbzJja0ZTV21sNGJYbFNVMnBvU1ZJd1MwOVJVRWRDVFZWc1pITmhlblJKU1VvM1R6Qm5Memd5Y1dvdmRr" +
            "ZEViQzh2TTNRMGRGUnhlR2xTYUV4UmJsUk1XRXBrWlVJck1rUm9hMlJWTmtsSlozZzJkMDQzUlRWT1kxVklNMUpq" +
            "YzJWcVkzRnFPSEExVTJveE9YWkNiVFpwTVVab2NVeEhlVzFvVFVaeWIxZFdWVWRQTTNoMFNVZzVNV1J6WjNrMFpV" +
            "WkxZMlpMVmt4WFN6TnZNakU1TUZFd1RHMHZVMmxMYlV4aVVrbzFRWFUwZVRGbGRVWktiVEpLVFRsbFFqZzBSbXR4" +
            "WVROcGRuSllWMVZsVm5SNVpUQkRVV1JMZG5OWk1rWnJZWHAyZUhSNGRuVnpURXA2VEZkWlNHczFOWHBqVWtGaFkw" +
            "UkJNbE5sUlhSQ1lsRm1SREZ4YzBOQmQwVkJRV0ZQUTBGWVdYZG5aMFo1VFVFMFIwRXhWV1JFZDBWQ0wzZFJSVUYz" +
            "U1VKb2FrRmtRbWRPVmtoVFZVVkdha0ZWUW1kbmNrSm5SVVpDVVdORVFWRlpTVXQzV1VKQ1VWVklRWGRKZDBWbldV" +
            "UldVakJVUVZGSUwwSkJaM2RDWjBWQ0wzZEpRa0ZFUVdSQ1owNVdTRkUwUlVablVWVktaVWxaUkhKS1dHdGFVWEUx" +
            "WkZKa2FIQkRSRE5zVDNwMVNrbDNTSGRaUkZaU01HcENRbWQzUm05QlZUVkxPSEpLYmtWaFN6Qm5ibWhUT1ZOYWFY" +
            "cDJPRWxyVkdOVU5IZGhRVmxKUzNkWlFrSlJWVWhCVVVWRldFUkNZVTFEV1VkRFEzTkhRVkZWUmtKNlFVSm9hSEJ2" +
            "WkVoU2QwOXBPSFppTWs1NlkwTTFkMkV5YTNWYU1qbDJXbms1Ym1SSVRubE5WRUYzUW1kbmNrSm5SVVpDVVdOM1FX" +
            "OVphMkZJVWpCalJHOTJURE5DY21GVE5XNWlNamx1VEROS2JHTkhPSFpaTWxaNVpFaE5kbG96VW5wamFrVjFXa2RX" +
            "ZVUxRVVVZEJNVlZrU0hkUmRFMURjM2RMWVVGdWIwTlhSMGt5YURCa1NFRTJUSGs1YW1OdGQzVmpSM1J3VEcxa2Rt" +
            "SXlZM1phTTFKNlkycEZkbG96VW5wamFrVjFXVE5LYzAxRk1FZEJNVlZrU1VGU1IwMUZVWGREUVZsSFdqUkZUVUZS" +
            "U1VKTlJHZEhRMmx6UjBGUlVVSXhibXREUWxGTmQwdHFRVzlDWjJkeVFtZEZSa0pSWTBOQlVsbGpZVWhTTUdOSVRU" +
            "Wk1lVGwzWVRKcmRWb3lPWFphZVRsNVdsaENkbU15YkRCaU0wbzFUSHBCVGtKbmEzRm9hMmxIT1hjd1FrRlJjMFpC" +
            "UVU5RFFXZEZRVWxXVkc5NU1qUnFkMWhWY2pCeVFWQmpPVEkwZG5WVFZtSkxVWFZaZHpOdVRHWnNUR1pNYURWQldW" +
            "ZEZaVlpzTDBSMU1UaFJRVmRWVFdSalNqWnZMM0ZHV21Kb1dHdENTREJRVG1OM09UZDBhR0ZtTWtKbGIwUlpXVGxE" +
            "YXk5aUsxVkhiSFZvZURBMmVtUTBSVUptTjBnNVVEZzBibTV5ZDNCU0t6UkhRa1JhU3l0WWFETkpNSFJ4U25reWNt" +
            "ZFBjVTVFWm14eU5VbE5VVGhhVkZkQk0zbHNkR0ZyZWxOQ1MxbzJXSEJHTUZCd2NYbERVblp3TDA1RFIzWXlTMWd5" +
            "VkhWUVEwcDJjMk53TVM5dE1uQldWSFI1UW1wWlVGSlJLMUYxUTFGSFFVcExhblJPTjFJMVJFWnlabFJ4VFZkMldX" +
            "ZFdiSEJEU2tKcmQyeDFOeXMzUzFrelkxUkpabnBGTjJOdFFVeHphMDFMVGt4MVJIb3JVbnBEWTNOWlZITldZVlUz" +
            "Vm5BemVFdzJNRTlaYUhGR2EzVkJUMDk0UkZvMmNFaFBhamtyVDBwdFdXZFFiVTlVTkZnekt6ZE1OVEZtV0VwNVVr" +
            "ZzVTMlpNVWxBMmJsUXpNVVExYm0xelIwRlBaMW95Tmk4NFZEbG9jMEpYTVhWdk9XcDFOV1phVEZwWVZsWlROVWd3" +
            "U0hsSlFrMUZTM2xIVFVsUWFFWlhjbXgwTDJoR1V6STRUakY2WVV0Sk1GcENSMFF6WjFsblJFeGlhVVJVT1daSFdI" +
            "TjBjR3NyUm0xak5HOXNWbXhYVUhwWVpUZ3hkbVJ2Ulc1R1luSTFUVEkzTWtoa1owcFhieXRYYUZRNVFsbE5NRXBw" +
            "SzNka1ZtMXVVbVptV0dkc2IwVnZiSFZVVG1OWGVtTTBNV1JHY0dkS2RUaG1Sak5NUnpCbmJESnBZbE5aYVVOcE9X" +
            "RTJhSFpWTUZSd2NHcEtlVWxYV0doclNsUmpUVXBzVUhKWGVERldlWFJGVlVkeVdESnNNRXBFZDFKcVZ5ODJOVFp5" +
            "TUV0V1FqQXllRWhTUzNadE1scExTVEF6Vkdkc1RFbHdiVlpEU3pOclFrdHJTMDV3UWs1clJuUTRjbWhoWm1ORFMw" +
            "OWlPVXA0THpsMGNFNUdiRkZVYkRkQ016bHlTbXhLVjJ0U01UZFJibHB4Vm5CMFJtVlFSazlTYjFwdFJucE5QU0lz" +
            "SWsxSlNVWlpha05EUWtWeFowRjNTVUpCWjBsUlpEY3dUbUpPY3pJclVuSnhTVkV2UlRoR2FsUkVWRUZPUW1kcmNX" +
            "aHJhVWM1ZHpCQ1FWRnpSa0ZFUWxoTlVYTjNRMUZaUkZaUlVVZEZkMHBEVWxSRldrMUNZMGRCTVZWRlEyaE5VVkl5" +
            "ZUhaWmJVWnpWVEpzYm1KcFFuVmthVEY2V1ZSRlVVMUJORWRCTVZWRlEzaE5TRlZ0T1haa1EwSkVVVlJGWWsxQ2Ew" +
            "ZEJNVlZGUVhoTlUxSXllSFpaYlVaelZUSnNibUpwUWxOaU1qa3dTVVZPUWsxQ05GaEVWRWwzVFVSWmVFOVVRWGRO" +
            "UkVFd1RXeHZXRVJVU1RSTlJFVjVUMFJCZDAxRVFUQk5iRzkzVW5wRlRFMUJhMGRCTVZWRlFtaE5RMVpXVFhoSmFr" +
            "Rm5RbWRPVmtKQmIxUkhWV1IyWWpKa2MxcFRRbFZqYmxaNlpFTkNWRnBZU2pKaFYwNXNZM2xDVFZSRlRYaEdSRUZU" +
            "UW1kT1ZrSkJUVlJETUdSVlZYbENVMkl5T1RCSlJrbDRUVWxKUTBscVFVNUNaMnR4YUd0cFJ6bDNNRUpCVVVWR1FV" +
            "RlBRMEZuT0VGTlNVbERRMmRMUTBGblJVRjBhRVZEYVhnM2FtOVlaV0pQT1hrdmJFUTJNMnhoWkVGUVMwZzVaM1pz" +
            "T1UxbllVTmpabUl5YWtndk56Wk9kVGhoYVRaWWJEWlBUVk12YTNJNWNrZzFlbTlSWkhObWJrWnNPVGQyZFdaTGFq" +
            "WmlkMU5wVmpadWNXeExjaXREVFc1NU5sTjRia2RRWWpFMWJDczRRWEJsTmpKcGJUbE5XbUZTZHpGT1JVUlFhbFJ5" +
            "UlZSdk9HZFpZa1YyY3k5QmJWRXpOVEZyUzFOVmFrSTJSekF3YWpCMVdVOUVVREJuYlVoMU9ERkpPRVV6UTNkdWNV" +
            "bHBjblUyZWpGcldqRnhLMUJ6UVdWM2JtcEllR2R6U0VFemVUWnRZbGQzV2tSeVdGbG1hVmxoVWxGTk9YTkliV3Rz" +
            "UTJsMFJETTRiVFZoWjBrdmNHSnZVRWRwVlZVck5rUlBiMmR5UmxwWlNuTjFRalpxUXpVeE1YQjZjbkF4V210cU5W" +
            "cFFZVXMwT1d3NFMwVnFPRU00VVUxQlRGaE1NekpvTjAweFlrdDNXVlZJSzBVMFJYcE9hM1JOWnpaVVR6aFZjRzEy" +
            "VFhKVmNITjVWWEYwUldvMVkzVklTMXBRWm0xbmFFTk9Oa296UTJsdmFqWlBSMkZMTDBkUU5VRm1iRFF2V0hSalpD" +
            "OXdNbWd2Y25Nek4wVlBaVnBXV0hSTU1HMDNPVmxDTUdWelYwTnlkVTlETjFoR2VGbHdWbkU1VDNNMmNFWk1TMk4z" +
            "V25CRVNXeFVhWEo0V2xWVVVVRnpObkY2YTIwd05uQTVPR2MzUWtGbEsyUkVjVFprYzI4ME9UbHBXVWcyVkV0WUx6" +
            "RlpOMFI2YTNabmRHUnBlbXByV0ZCa2MwUjBVVU4yT1ZWM0szZHdPVlUzUkdKSFMyOW5VR1ZOWVROTlpDdHdkbVY2" +
            "TjFjek5VVnBSWFZoS3l0MFoza3ZRa0pxUmtaR2VUTnNNMWRHY0U4NVMxZG5lamQ2Y0cwM1FXVkxTblE0VkRFeFpH" +
            "eGxRMlpsV0d0clZVRkxTVUZtTlhGdlNXSmhjSE5hVjNkd1ltdE9SbWhJWVhneWVFbFFSVVJuWm1jeFlYcFdXVGd3" +
            "V21OR2RXTjBURGRVYkV4dVRWRXZNR3hWVkdKcFUzY3hia2cyT1UxSE5ucFBNR0k1WmpaQ1VXUm5RVzFFTURaNVN6" +
            "VTJiVVJqV1VKYVZVTkJkMFZCUVdGUFEwRlVaM2RuWjBVd1RVRTBSMEV4VldSRWQwVkNMM2RSUlVGM1NVSm9ha0ZR" +
            "UW1kT1ZraFNUVUpCWmpoRlFsUkJSRUZSU0M5TlFqQkhRVEZWWkVSblVWZENRbFJyY25semJXTlNiM0pUUTJWR1RE" +
            "RktiVXhQTDNkcFVrNTRVR3BCWmtKblRsWklVMDFGUjBSQlYyZENVbWRsTWxsaFVsRXlXSGx2YkZGTU16QkZlbFJU" +
            "Ynk4dmVqbFRla0puUW1kbmNrSm5SVVpDVVdOQ1FWRlNWVTFHU1hkS1VWbEpTM2RaUWtKUlZVaE5RVWRIUjFkb01H" +
            "UklRVFpNZVRsMldUTk9kMHh1UW5KaFV6VnVZakk1Ymt3eVpIcGpha1YzUzFGWlNVdDNXVUpDVVZWSVRVRkxSMGhY" +
            "YURCa1NFRTJUSGs1ZDJFeWEzVmFNamwyV25rNWJtTXpTWGhNTW1SNlkycEZkVmt6U2pCTlJFbEhRVEZWWkVoM1VY" +
            "Sk5RMnQzU2paQmJHOURUMGRKVjJnd1pFaEJOa3g1T1dwamJYZDFZMGQwY0V4dFpIWmlNbU4yV2pOT2VVMVRPVzVq" +
            "TTBsNFRHMU9lV0pFUVRkQ1owNVdTRk5CUlU1RVFYbE5RV2RIUW0xbFFrUkJSVU5CVkVGSlFtZGFibWRSZDBKQlow" +
            "bDNSRkZaVEV0M1dVSkNRVWhYWlZGSlJrRjNTWGRFVVZsTVMzZFpRa0pCU0ZkbFVVbEdRWGROZDBSUldVcExiMXBK" +
            "YUhaalRrRlJSVXhDVVVGRVoyZEZRa0ZFVTJ0SWNrVnZiemxETUdSb1pXMU5XRzlvTm1SR1UxQnphbUprUWxwQ2FV" +
            "eG5PVTVTTTNRMVVDdFVORlo0Wm5FM2RuRm1UUzlpTlVFelVta3habmxLYlRsaWRtaGtSMkZLVVROaU1uUTJlVTFC" +
            "V1U0dmIyeFZZWHB6WVV3cmVYbEZiamxYY0hKTFFWTlBjMmhKUVhKQmIzbGFiQ3QwU21GdmVERXhPR1psYzNOdFdH" +
            "NHhhRWxXZHpReGIyVlJZVEYyTVhabk5FWjJOelI2VUd3MkwwRm9VM0ozT1ZVMWNFTmFSWFEwVjJrMGQxTjBlalpr" +
            "VkZvdlEweEJUbmc0VEZwb01VbzNVVXBXYWpKbWFFMTBabFJLY2psM05Ib3pNRm95TURsbVQxVXdhVTlOZVN0eFpI" +
            "VkNiWEIyZGxsMVVqZG9Xa3cyUkhWd2MzcG1ibmN3VTJ0bWRHaHpNVGhrUnpsYVMySTFPVlZvZG0xaFUwZGFVbFpp" +
            "VGxGd2MyY3pRbHBzZG1sa01HeEpTMDh5WkRGNGIzcGpiRTk2WjJwWVVGbHZka3BLU1hWc2RIcHJUWFV6TkhGUllq" +
            "bFRlaTk1YVd4eVlrTm5hamc5SWwxOS5leUp1YjI1alpTSTZJbTlWY0RrMlRUbE1ialpEWVN0alRGZzRaa3hqYTI1" +
            "bGFHMTVNMW8xTkZNNFEwOVVkbGc1Vm1zeEswazlJaXdpZEdsdFpYTjBZVzF3VFhNaU9qRTJNamMyTkRnNE1UUTFO" +
            "amdzSW1Gd2ExQmhZMnRoWjJWT1lXMWxJam9pWTI5dExtZHZiMmRzWlM1aGJtUnliMmxrTG1kdGN5SXNJbUZ3YTBS" +
            "cFoyVnpkRk5vWVRJMU5pSTZJbFY0ZFRWcFVYa3lObEZoY1ZoU2IwcG1NMHcwY0ZSQksyNU1jbGxTWmxkMFlYSjRh" +
            "WEJSYzA1Q1pXczlJaXdpWTNSelVISnZabWxzWlUxaGRHTm9JanAwY25WbExDSmhjR3REWlhKMGFXWnBZMkYwWlVS" +
            "cFoyVnpkRk5vWVRJMU5pSTZXeUk0VURGelZ6QkZVRXBqYzJ4M04xVjZVbk5wV0V3Mk5IY3JUelV3UldRclVrSkpR" +
            "M1JoZVRGbk1qUk5QU0pkTENKaVlYTnBZMGx1ZEdWbmNtbDBlU0k2ZEhKMVpTd2laWFpoYkhWaGRHbHZibFI1Y0dV" +
            "aU9pSkNRVk5KUXl4SVFWSkVWMEZTUlY5Q1FVTkxSVVFpZlEuT0ZIY2NSTGlXOFB5VGhxeXJ5X0J4SzlBeDNqODNn" +
            "OVdFT2ZKdU5SeUctWnFfRVdtdkU2RS1sYWNFQWJlRzFNZV9Ib1JkS2tkMktYbWpkMU5lOWx4ampuRUZWZFJwaUt5" +
            "T1F0bFMyR2RnQnZRWEVoWEM1WDlBdDA0WGFyQkctVHlpOUNhX2lTLXRiNV9rcXNqYmFjVWRqSTN4RUI5YVdQTHF5" +
            "M3lPX3JFM1JFTDZIVlU5bE9XQWtfbE5qdkozU3dXQkthNVZwVDZOclZuMEp1UkFuZ2tYVmRjS1JlaVpKbFdaNW9j" +
            "V1l4ajgxY2ZYX2xPR29FM3ozZEtheG44U0ZNNTlVLTVUQm5Gdl9NTzBFRVUwVXJpSDhmQlp6UmdGSHFoUlNvRGs2" +
            "UmF1aUh0a0JjZjhRVkJ4TURwVXdFd25qOWc0OUVLSkFwVWtqcjZxcFpxdXRfcFBBaGF1dGhEYXRhWMVJlg3liA6M" +
            "aHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0UAAAAAuT_ZYfLmRi-xIoIAIkfeeABBAQsMmnEQ8OxpZxijXBMT4tya" +
            "mgkqC_3hr18_e8KeK8nG69ijcTaXNKX_CRmYiW0fegPE0N_3NVHEaj_kit7LPNOlAQIDJiABIVggxf5sshpkLLen" +
            "92NUd9sRVM1fVR6FRFZY_P7fnCq3crgiWCALN83GhRoAD4faTpk1bp7bGclHRleO922RvPUpSnBb-w"));

    webAuthN.authenticate(
        new JsonObject()
          .put("username", "adam")
          .put("origin", "http://localhost:4200")
          .put("webauthn", packedFullAttestationWebAuthnSample)
          .put("challenge", "AHNZQ5YaheZY8_eawo3EHLyWv8BzijiqsBUe46v-QSg"))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  @Ignore("Missing authenticator keys")
  public void testUnknownChallenge(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    JsonObject packedFullAttestationWebAuthnSample = new JsonObject()
      .put("rawId", "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb")
      .put("id", "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb")
      .put("response", new JsonObject()
        .put("clientDataJSON", "eyJjaGFsbGVuZ2UiOiJlYVR5VU5ueVBERGRLOFNORWdURVV2ejFROGR5bGtqalRpbVlkNVg3UUFvLUY4X1oxbHNKaTNCaWxVcEZaSGtJQ05EV1k4cjlpdm5UZ1c3LVhaQzNxUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0=")
        .put("authenticatorData", "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaw==")
        .put("signature", "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7")
        .put("userHandle", ""));

    webAuthN.authenticate(
        new JsonObject()
          .put("username", "adam")
          .put("origin", "https://localhost:8443")
          .put("webauthn", packedFullAttestationWebAuthnSample)
          .put("challenge", "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ"))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  @Ignore("Missing authenticator keys")
  public void testWindowsHelloAttestation(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    JsonObject packedFullAttestationWebAuthnSample = new JsonObject()
      .put("rawId", "AwVUFfSwuMV1DRHfYmNry1IUGW03wEw9aTAR7kJM1nw")
      .put("id", "AwVUFfSwuMV1DRHfYmNry1IUGW03wEw9aTAR7kJM1nw")
      .put("response", new JsonObject()
        .put("clientDataJSON", "ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5nZXQiLA0KCSJjaGFsbGVuZ2UiIDogIm03WlUwWi1fSWl3dmlGbkYxSlhlSmpGaFZCaW5jVzY5RTFDdGo4QVEtWWJiMXVjNDFiTUh0SXRnNkpBQ2gxc09qX1pYam9udzJhY2pfSkQyaS1heEVRIiwNCgkib3JpZ2luIiA6ICJodHRwczovL3dlYmF1dGhuLm9yZyIsDQoJInRva2VuQmluZGluZyIgOiANCgl7DQoJCSJzdGF0dXMiIDogInN1cHBvcnRlZCINCgl9DQp9")
        .put("authenticatorData", "lWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4_Xy7IpvdQFAAAAAQ")
        .put("signature", "ElyXBPkS6ps0aod8pSEwdbaeG04SUSoucEHaulPrK3eBk3R4aePjTB-SjiPbya5rxzbuUIYO0UnqkpZrb19ZywWqwQ7qVxZzxSq7BCZmJhcML7j54eK_2nszVwXXVgO7WxpBcy_JQMxjwjXw6wNAxmnJ-H3TJJO82x4-9pDkno-GjUH2ObYk9NtkgylyMcENUaPYqajSLX-q5k14T2g839UC3xzsg71xHXQSeHgzPt6f3TXpNxNNcBYJAMm8-exKsoMkxHPDLkzK1wd5giietdoT25XQ72i8fjSSL8eiS1gllEjwbqLJn5zMQbWlgpSzJy3lK634sdeZtmMpXbRtMA")
        .put("userHandle", "YWs"));

    webAuthN.authenticate(
        new JsonObject()
          .put("username", "adam")
          .put("origin", "https://webauthn.org")
          .put("webauthn", packedFullAttestationWebAuthnSample)
          .put("challenge", "m7ZU0Z-_IiwviFnF1JXeJjFhVBincW69E1Ctj8AQ-Ybb1uc41bMHtItg6JACh1sOj_ZXjonw2acj_JD2i-axEQ"))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  @Ignore("Expired certificate")
  public void testPackedFullAttestationSample(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    JsonObject packedFullAttestationWebAuthnSample = new JsonObject()
      .put("rawId", "wsLryOAxXMU54s2fCSWPzWjXHOBKPploN-UHftj4_rpIu6BZxNXppm82f7Y6iX9FEOKKeS5-N2TALeyzLnJfAA")
      .put("id", "wsLryOAxXMU54s2fCSWPzWjXHOBKPploN-UHftj4_rpIu6BZxNXppm82f7Y6iX9FEOKKeS5-N2TALeyzLnJfAA")
      .put("response", new JsonObject()
        .put("clientDataJSON", "eyJjaGFsbGVuZ2UiOiJZTVdFVGYtUDc5aU1iLUJxZFRreVNOUmVPdmE3bksyaVZDOWZpQzhpR3ZZeXB1bkVPQ1pHWjYtWTVPVjFydk1pRGdBaldmRmk2VUMwV3lLR3NqQS1nQSIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4ub3JnIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9")
        .put("attestationObject", "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAIzOihC6Ba80o5JnoYOJJ_EtEVmWQcAvxVCnsCFnVRQZAiAfeIddLPsPl1FeSX8B5xZANcQKGNoO7pb0TZPnuJdebGN4NWOBWQKzMIICrzCCAZegAwIBAgIESFs9tjANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDDBZZdWJpY28gRklETyBQcmV2aWV3IENBMB4XDTE4MDQxMjEwNTcxMFoXDTE4MTIzMTEwNTcxMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTIxMzkzOTEyNjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPss3TBDKMVySlDM5vYLrX0nqRtZ4eZvKXuJydQ9wrLHeIm08P-dAijLlG384BsZWJtngEqsl38oGJzNsyV0yiijbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS42MBMGCysGAQQBguUcAgEBBAQDAgQwMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER-e3H0wDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMvPkvVjXQiuvSZmGCB8NqTvGqhxyEfkoU-vz63PaaTsG3jEzjl0C7PZ26VxCvqWPJdM3P3e7Kp18sj4RjEHUmkya2PPipOwBd3p0qMQSQ8MeziCPLQ9uvGGb4YShcvaprMv4c21b4piza-znHneNCmmq-ZS4Y23o-vYv085_BEwyLPcmPjSZ5qWysCq7rVvZ7OWwcU1zu5RhSZyUKl8dzK9lAzs5OdRH2fzEewsW2OkB_Ow_jBvAxqwLXXTHuwMFaRfpmBoZuQlcofSrnwJ8KA-K-e0dKTz2zC8EbZrWYrSpbrHKyqxeBT6DkUd8H4tgAd5lOr_yqrtVmIaRfq07NmhhdXRoRGF0YVjElWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4_Xy7IpvdRBAAAAAPigEfOMCk0VgAYXER-e3H0AQMLC68jgMVzFOeLNnwklj81o1xzgSj6ZaDflB37Y-P66SLugWcTV6aZvNn-2Ool_RRDiinkufjdkwC3ssy5yXwClAQIDJiABIVggAYD1TSpf120DSVxen8ki56kF1bmT4EXO-P0JnSk5mMwiWCB3TlMZBRqPY6llzDcfHd-oW0EHdaFNgBdlGGFobpHKlw"));

    webAuthN.authenticate(
        new JsonObject()
          .put("username", "paulo")
          .put("origin", "https://webauthn.org")
          .put("webauthn", packedFullAttestationWebAuthnSample)
          .put("challenge", "YMWETf-P79iMb-BqdTkySNReOva7nK2iVC9fiC8iGvYypunEOCZGZ6-Y5OV1rvMiDgAjWfFi6UC0WyKGsjA-gA"))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  public void testPackedSurrogateAttestationSample(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    JsonObject packedFullAttestationWebAuthnSample = new JsonObject()
      .put("rawId", "H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14")
      .put("id", "H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14")
      .put("response", new JsonObject()
        .put("clientDataJSON", "eyJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjaGFsbGVuZ2UiOiJBWGtYV1hQUDNnTHg4T0xscGtKM2FSUmhGV250blNFTmdnbmpEcEJxbDFuZ0tvbDd4V3dldlVZdnJwQkRQM0xFdmRyMkVPU3RPRnBHR3huTXZYay1WdyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ")
        .put("attestationObject", "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzn__mNzaWdZAQCPypMLXWqtCZ1sc5QdjhH-pAzm8-adpfbemd5zsym2krscwV0EeOdTrdUOdy3hWj5HuK9dIX_OpNro2jKrHfUj_0Kp-u87iqJ3MPzs-D9zXOqkbWqcY94Zh52wrPwhGfJ8BiQp5T4Q97E042hYQRDKmtv7N-BT6dywiuFHxfm1sDbUZ_yyEIN3jgttJzjp_wvk_RJmb78bLPTlym83Y0Ws73K6FFeiqFNqLA_8a4V0I088hs_IEPlj8PWxW0wnIUhI9IcRf0GEmUwTBpbNDGpIFGOudnl_C3YuXuzK3R6pv2r7m9-9cIIeeYXD9BhSMBQ0A8oxBbVF7j-0xXDNrXHZaGF1dGhEYXRhWQFnSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAOKjVmSRjt0nqud40p1PeHgEAIB-l9gZ544Ds7vzo_O76UZ8DCXiWFc8DN8LWNZYQH0NepAEDAzn__iBZAQDAIqzybPPmgeL5OR6JKq9bWDiENJlN_LePQEnf1_sgOm4FJ9kBTbOTtWplfoMXg40A7meMppiRqP72A3tmILwZ5xKIyY7V8Y2t8X1ilYJol2nCKOpAEqGLTRJjF64GQxen0uFpi1tA6l6N-ZboPxjky4aidBdUP22YZuEPCO8-9ZTha8qwvTgZwMHhZ40TUPEJGGWOnHNlYmqnfFfk0P-UOZokI0rqtqqQGMwzV2RrH2kjKTZGfyskAQnrqf9PoJkye4KUjWkWnZzhkZbrDoLyTEX2oWvTTflnR5tAVMQch4UGgEHSZ00G5SFoc19nGx_UJcqezx5cLZsny-qQYDRjIUMBAAE"));

    webAuthN.authenticate(
        new JsonObject()
          .put("username", "paulo")
          .put("origin", "http://localhost:3000")
          .put("webauthn", packedFullAttestationWebAuthnSample)
          .put("challenge", "AXkXWXPP3gLx8OLlpkJ3aRRhFWntnSENggnjDpBql1ngKol7xWwevUYvrpBDP3LEvdr2EOStOFpGGxnMvXk-Vw"))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  @Ignore("Certificate expired")
  public void testAndroidSafetyNet(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    JsonObject packedFullAttestationWebAuthnSample = new JsonObject()
      .put("rawId", "AZD7huwZVx7aW1efRa6Uq3JTQNorj3qA9yrLINXEcgvCQYtWiSQa1eOIVrXfCmip6MzP8KaITOvRLjy3TUHO7_c")
      .put("id", "AZD7huwZVx7aW1efRa6Uq3JTQNorj3qA9yrLINXEcgvCQYtWiSQa1eOIVrXfCmip6MzP8KaITOvRLjy3TUHO7_c")
      .put("response", new JsonObject()
        .put("clientDataJSON", "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVGY2NWJTNkQ1dGVtaDJCd3ZwdHFnQlBiMjVpWkRSeGp3QzVhbnM5MUlJSkRyY3JPcG5XVEs0TFZnRmplVVY0R0RNZTQ0dzhTSTVOc1pzc0lYVFV2RGciLCJvcmlnaW4iOiJodHRwczpcL1wvd2ViYXV0aG4ub3JnIiwiYW5kcm9pZFBhY2thZ2VOYW1lIjoiY29tLmFuZHJvaWQuY2hyb21lIn0")
        .put("attestationObject", "o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaDE0MzY2MDE5aHJlc3BvbnNlWRS9ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxHYTJwRFEwSkljV2RCZDBsQ1FXZEpVVkpZY205T01GcFBaRkpyUWtGQlFVRkJRVkIxYm5wQlRrSm5hM0ZvYTJsSE9YY3dRa0ZSYzBaQlJFSkRUVkZ6ZDBOUldVUldVVkZIUlhkS1ZsVjZSV1ZOUW5kSFFURlZSVU5vVFZaU01qbDJXako0YkVsR1VubGtXRTR3U1VaT2JHTnVXbkJaTWxaNlRWSk5kMFZSV1VSV1VWRkVSWGR3U0ZaR1RXZFJNRVZuVFZVNGVFMUNORmhFVkVVMFRWUkJlRTFFUVROTlZHc3dUbFp2V0VSVVJUVk5WRUYzVDFSQk0wMVVhekJPVm05M1lrUkZURTFCYTBkQk1WVkZRbWhOUTFaV1RYaEZla0ZTUW1kT1ZrSkJaMVJEYTA1b1lrZHNiV0l6U25WaFYwVjRSbXBCVlVKblRsWkNRV05VUkZVeGRtUlhOVEJaVjJ4MVNVWmFjRnBZWTNoRmVrRlNRbWRPVmtKQmIxUkRhMlIyWWpKa2MxcFRRazFVUlUxNFIzcEJXa0puVGxaQ1FVMVVSVzFHTUdSSFZucGtRelZvWW0xU2VXSXliR3RNYlU1MllsUkRRMEZUU1hkRVVWbEtTMjlhU1doMlkwNUJVVVZDUWxGQlJHZG5SVkJCUkVORFFWRnZRMmRuUlVKQlRtcFlhM293WlVzeFUwVTBiU3N2UnpWM1QyOHJXRWRUUlVOeWNXUnVPRGh6UTNCU04yWnpNVFJtU3pCU2FETmFRMWxhVEVaSWNVSnJOa0Z0V2xaM01rczVSa2N3VHpseVVsQmxVVVJKVmxKNVJUTXdVWFZ1VXpsMVowaEROR1ZuT1c5MmRrOXRLMUZrV2pKd09UTllhSHAxYmxGRmFGVlhXRU40UVVSSlJVZEtTek5UTW1GQlpucGxPVGxRVEZNeU9XaE1ZMUYxV1ZoSVJHRkROMDlhY1U1dWIzTnBUMGRwWm5NNGRqRnFhVFpJTDNob2JIUkRXbVV5YkVvck4wZDFkSHBsZUV0d2VIWndSUzkwV2xObVlsazVNRFZ4VTJ4Q2FEbG1jR293TVRWamFtNVJSbXRWYzBGVmQyMUxWa0ZWZFdWVmVqUjBTMk5HU3pSd1pYWk9UR0Y0UlVGc0swOXJhV3hOZEVsWlJHRmpSRFZ1Wld3MGVFcHBlWE0wTVROb1lXZHhWekJYYUdnMVJsQXpPV2hIYXpsRkwwSjNVVlJxWVhwVGVFZGtkbGd3YlRaNFJsbG9hQzh5VmsxNVdtcFVORXQ2VUVwRlEwRjNSVUZCWVU5RFFXeG5kMmRuU2xWTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkSlJtOUVRVlJDWjA1V1NGTlZSVVJFUVV0Q1oyZHlRbWRGUmtKUlkwUkJWRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRVTFDTUVkQk1WVmtSR2RSVjBKQ1VYRkNVWGRIVjI5S1FtRXhiMVJMY1hWd2J6UlhObmhVTm1veVJFRm1RbWRPVmtoVFRVVkhSRUZYWjBKVFdUQm1hSFZGVDNaUWJTdDRaMjU0YVZGSE5rUnlabEZ1T1V0NlFtdENaMmR5UW1kRlJrSlJZMEpCVVZKWlRVWlpkMHAzV1VsTGQxbENRbEZWU0UxQlIwZEhNbWd3WkVoQk5reDVPWFpaTTA1M1RHNUNjbUZUTlc1aU1qbHVUREprTUdONlJuWk5WRUZ5UW1kbmNrSm5SVVpDVVdOM1FXOVpabUZJVWpCalJHOTJURE5DY21GVE5XNWlNamx1VERKa2VtTnFTWFpTTVZKVVRWVTRlRXh0VG5sa1JFRmtRbWRPVmtoU1JVVkdha0ZWWjJoS2FHUklVbXhqTTFGMVdWYzFhMk50T1hCYVF6VnFZakl3ZDBsUldVUldVakJuUWtKdmQwZEVRVWxDWjFwdVoxRjNRa0ZuU1hkRVFWbExTM2RaUWtKQlNGZGxVVWxHUVhwQmRrSm5UbFpJVWpoRlMwUkJiVTFEVTJkSmNVRm5hR2cxYjJSSVVuZFBhVGgyV1ROS2MweHVRbkpoVXpWdVlqSTVia3d3WkZWVmVrWlFUVk0xYW1OdGQzZG5aMFZGUW1kdmNrSm5SVVZCWkZvMVFXZFJRMEpKU0RGQ1NVaDVRVkJCUVdSM1EydDFVVzFSZEVKb1dVWkpaVGRGTmt4TldqTkJTMUJFVjFsQ1VHdGlNemRxYW1RNE1FOTVRVE5qUlVGQlFVRlhXbVJFTTFCTVFVRkJSVUYzUWtsTlJWbERTVkZEVTFwRFYyVk1Tblp6YVZaWE5rTm5LMmRxTHpsM1dWUktVbnAxTkVocGNXVTBaVmswWXk5dGVYcHFaMGxvUVV4VFlta3ZWR2g2WTNweGRHbHFNMlJyTTNaaVRHTkpWek5NYkRKQ01HODNOVWRSWkdoTmFXZGlRbWRCU0ZWQlZtaFJSMjFwTDFoM2RYcFVPV1ZIT1ZKTVNTdDRNRm95ZFdKNVdrVldla0UzTlZOWlZtUmhTakJPTUVGQlFVWnRXRkU1ZWpWQlFVRkNRVTFCVW1wQ1JVRnBRbU5EZDBFNWFqZE9WRWRZVURJM09IbzBhSEl2ZFVOSWFVRkdUSGx2UTNFeVN6QXJlVXhTZDBwVlltZEpaMlk0WjBocWRuQjNNbTFDTVVWVGFuRXlUMll6UVRCQlJVRjNRMnR1UTJGRlMwWlZlVm8zWmk5UmRFbDNSRkZaU2t0dldrbG9kbU5PUVZGRlRFSlJRVVJuWjBWQ1FVazVibFJtVWt0SlYyZDBiRmRzTTNkQ1REVTFSVlJXTm10aGVuTndhRmN4ZVVGak5VUjFiVFpZVHpReGExcDZkMG8yTVhkS2JXUlNVbFF2VlhORFNYa3hTMFYwTW1Nd1JXcG5iRzVLUTBZeVpXRjNZMFZYYkV4UldUSllVRXg1Um1wclYxRk9ZbE5vUWpGcE5GY3lUbEpIZWxCb2RETnRNV0kwT1doaWMzUjFXRTAyZEZnMVEzbEZTRzVVYURoQ2IyMDBMMWRzUm1sb2VtaG5iamd4Ukd4a2IyZDZMMHN5VlhkTk5sTTJRMEl2VTBWNGEybFdabllyZW1KS01ISnFkbWM1TkVGc1pHcFZabFYzYTBrNVZrNU5ha1ZRTldVNGVXUkNNMjlNYkRabmJIQkRaVVkxWkdkbVUxZzBWVGw0TXpWdmFpOUpTV1F6VlVVdlpGQndZaTl4WjBkMmMydG1aR1Y2ZEcxVmRHVXZTMU50Y21sM1kyZFZWMWRsV0daVVlra3plbk5wYTNkYVltdHdiVkpaUzIxcVVHMW9kalJ5YkdsNlIwTkhkRGhRYmpod2NUaE5Na3RFWmk5UU0ydFdiM1F6WlRFNFVUMGlMQ0pOU1VsRlUycERRMEY2UzJkQmQwbENRV2RKVGtGbFR6QnRjVWRPYVhGdFFrcFhiRkYxUkVGT1FtZHJjV2hyYVVjNWR6QkNRVkZ6UmtGRVFrMU5VMEYzU0dkWlJGWlJVVXhGZUdSSVlrYzVhVmxYZUZSaFYyUjFTVVpLZG1JelVXZFJNRVZuVEZOQ1UwMXFSVlJOUWtWSFFURlZSVU5vVFV0U01uaDJXVzFHYzFVeWJHNWlha1ZVVFVKRlIwRXhWVVZCZUUxTFVqSjRkbGx0Um5OVk1teHVZbXBCWlVaM01IaE9la0V5VFZSVmQwMUVRWGRPUkVwaFJuY3dlVTFVUlhsTlZGVjNUVVJCZDA1RVNtRk5SVWw0UTNwQlNrSm5UbFpDUVZsVVFXeFdWRTFTTkhkSVFWbEVWbEZSUzBWNFZraGlNamx1WWtkVloxWklTakZqTTFGblZUSldlV1J0YkdwYVdFMTRSWHBCVWtKblRsWkNRVTFVUTJ0a1ZWVjVRa1JSVTBGNFZIcEZkMmRuUldsTlFUQkhRMU54UjFOSllqTkVVVVZDUVZGVlFVRTBTVUpFZDBGM1oyZEZTMEZ2U1VKQlVVUlJSMDA1UmpGSmRrNHdOWHByVVU4NUszUk9NWEJKVW5aS2VucDVUMVJJVnpWRWVrVmFhRVF5WlZCRGJuWlZRVEJSYXpJNFJtZEpRMlpMY1VNNVJXdHpRelJVTW1aWFFsbHJMMnBEWmtNelVqTldXazFrVXk5a1RqUmFTME5GVUZwU2NrRjZSSE5wUzFWRWVsSnliVUpDU2pWM2RXUm5lbTVrU1UxWlkweGxMMUpIUjBac05YbFBSRWxMWjJwRmRpOVRTa2d2VlV3clpFVmhiSFJPTVRGQ2JYTkxLMlZSYlUxR0t5dEJZM2hIVG1oeU5UbHhUUzg1YVd3M01Va3laRTQ0UmtkbVkyUmtkM1ZoWldvMFlsaG9jREJNWTFGQ1ltcDRUV05KTjBwUU1HRk5NMVEwU1N0RWMyRjRiVXRHYzJKcWVtRlVUa001ZFhwd1JteG5UMGxuTjNKU01qVjRiM2x1VlhoMk9IWk9iV3R4TjNwa1VFZElXR3Q0VjFrM2IwYzVhaXRLYTFKNVFrRkNhemRZY2twbWIzVmpRbHBGY1VaS1NsTlFhemRZUVRCTVMxY3dXVE42Tlc5Nk1rUXdZekYwU2t0M1NFRm5UVUpCUVVkcVoyZEZlazFKU1VKTWVrRlBRbWRPVmtoUk9FSkJaamhGUWtGTlEwRlpXWGRJVVZsRVZsSXdiRUpDV1hkR1FWbEpTM2RaUWtKUlZVaEJkMFZIUTBOelIwRlJWVVpDZDAxRFRVSkpSMEV4VldSRmQwVkNMM2RSU1UxQldVSkJaamhEUVZGQmQwaFJXVVJXVWpCUFFrSlpSVVpLYWxJclJ6UlJOamdyWWpkSFEyWkhTa0ZpYjA5ME9VTm1NSEpOUWpoSFFURlZaRWwzVVZsTlFtRkJSa3AyYVVJeFpHNUlRamRCWVdkaVpWZGlVMkZNWkM5alIxbFpkVTFFVlVkRFEzTkhRVkZWUmtKM1JVSkNRMnQzU25wQmJFSm5aM0pDWjBWR1FsRmpkMEZaV1ZwaFNGSXdZMFJ2ZGt3eU9XcGpNMEYxWTBkMGNFeHRaSFppTW1OMldqTk9lVTFxUVhsQ1owNVdTRkk0UlV0NlFYQk5RMlZuU21GQmFtaHBSbTlrU0ZKM1QyazRkbGt6U25OTWJrSnlZVk0xYm1JeU9XNU1NbVI2WTJwSmRsb3pUbmxOYVRWcVkyMTNkMUIzV1VSV1VqQm5Ra1JuZDA1cVFUQkNaMXB1WjFGM1FrRm5TWGRMYWtGdlFtZG5ja0puUlVaQ1VXTkRRVkpaWTJGSVVqQmpTRTAyVEhrNWQyRXlhM1ZhTWpsMlduazVlVnBZUW5aak1td3dZak5LTlV4NlFVNUNaMnR4YUd0cFJ6bDNNRUpCVVhOR1FVRlBRMEZSUlVGSGIwRXJUbTV1TnpoNU5uQlNhbVE1V0d4UlYwNWhOMGhVWjJsYUwzSXpVazVIYTIxVmJWbElVRkZ4TmxOamRHazVVRVZoYW5aM1VsUXlhVmRVU0ZGeU1ESm1aWE54VDNGQ1dUSkZWRlYzWjFwUksyeHNkRzlPUm5ab2MwODVkSFpDUTA5SllYcHdjM2RYUXpsaFNqbDRhblUwZEZkRVVVZzRUbFpWTmxsYVdpOVlkR1ZFVTBkVk9WbDZTbkZRYWxrNGNUTk5SSGh5ZW0xeFpYQkNRMlkxYnpodGR5OTNTalJoTWtjMmVIcFZjalpHWWpaVU9FMWpSRTh5TWxCTVVrdzJkVE5OTkZSNmN6TkJNazB4YWpaaWVXdEtXV2s0ZDFkSlVtUkJka3RNVjFwMUwyRjRRbFppZWxsdGNXMTNhMjAxZWt4VFJGYzFia2xCU21KRlRFTlJRMXAzVFVnMU5uUXlSSFp4YjJaNGN6WkNRbU5EUmtsYVZWTndlSFUyZURaMFpEQldOMU4yU2tORGIzTnBjbE50U1dGMGFpODVaRk5UVmtSUmFXSmxkRGh4THpkVlN6UjJORnBWVGpnd1lYUnVXbm94ZVdjOVBTSmRmUS5leUp1YjI1alpTSTZJa2tyVW5GVE1IVnZlSEpKYld0MkwxTXJOa3hZVlhwMlNrVTJRVkZ5UkRGNGJEQjVTM2Q0TW0xS1NUUTlJaXdpZEdsdFpYTjBZVzF3VFhNaU9qRTFOREV6TXpZM01qazVNekFzSW1Gd2ExQmhZMnRoWjJWT1lXMWxJam9pWTI5dExtZHZiMmRzWlM1aGJtUnliMmxrTG1kdGN5SXNJbUZ3YTBScFoyVnpkRk5vWVRJMU5pSTZJbVZSWXl0MmVsVmpaSGd3UmxaT1RIWllTSFZIY0VRd0sxSTRNRGR6VlVWMmNDdEtaV3hsV1ZwemFVRTlJaXdpWTNSelVISnZabWxzWlUxaGRHTm9JanAwY25WbExDSmhjR3REWlhKMGFXWnBZMkYwWlVScFoyVnpkRk5vWVRJMU5pSTZXeUk0VURGelZ6QkZVRXBqYzJ4M04xVjZVbk5wV0V3Mk5IY3JUelV3UldRclVrSkpRM1JoZVRGbk1qUk5QU0pkTENKaVlYTnBZMGx1ZEdWbmNtbDBlU0k2ZEhKMVpYMC5XTGV3N1FqemM2QTZHeVZfck1VRlhSZzEyVEtSb0ROLXJhSG9NSzY3SGdCbk5Yc0QtOUtjaG1TVFpBWWZfLXFKZE1wN1BhYml4VnF4ZDdDQzFxTFBPaUZYLVd5RGJzZlltNmRabFFiODhSd2R6LVEyUVJfTDFCN3NTaURlV1lTeDZmMm10MlQ0WXQ4MjNGNHNGYk8zVlpXM1RacmRRLXBlMVFWMEZYTTRUQ1dXbWVVRUUyWEJmaFVYbHJ5MEFicWhnQUNsWWFGcG8xdUhXUjhEOFkweDhtUDFocmVTMUtNN2NfT01lc1E5dl9mdlBETUE0SEUtYlpZbHZrRVV2VmFCeFpWVzB2SXN4eWxiWllSNVMxSjIwSXRPLV9kSDFERWRkY1kzcmc3bzd6RlJGSGFnd0QyN3dCMzlCTmk4cVNVcG1heEk1VWhrNE04X3BDSWtmLXBwaUFoYXV0aERhdGFYxZVpCI8ezuMjKVQDXb0Q18rjkTBaJ1G1WbuP18uyKb3URQAAAAAAAAAAAAAAAAAAAAAAAAAAAEEBkPuG7BlXHtpbV59FrpSrclNA2iuPeoD3Kssg1cRyC8JBi1aJJBrV44hWtd8KaKnozM_wpohM69EuPLdNQc7v96UBAgMmIAEhWCBVEWSlJerLbRupcvBaXA5Cqpp1Ba46HZTH-dqgmeMCYSJYIIlzYLPXaVavxbpZ4G6ZJWJ6hwW_NgiKAHpSNL8Bwf_d"));

    webAuthN.authenticate(
        new JsonObject()
          .put("username", "paulo")
          .put("webauthn", packedFullAttestationWebAuthnSample)
          .put("challenge", "Tf65bS6D5temh2BwvptqgBPb25iZDRxjwC5ans91IIJDrcrOpnWTK4LVgFjeUV4GDMe44w8SI5NsZssIXTUvDg"))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  @Ignore("Certificate is expired")
  public void testAppleAttestation(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    JsonObject packedFullAttestationWebAuthnSample = new JsonObject()
      .put("rawId", "J4lAqPXhefDrUD7oh5LQMbBH5TE")
      .put("id", "J4lAqPXhefDrUD7oh5LQMbBH5TE")
      .put("type", "public-key")
      .put("response", new JsonObject()
        .put("clientDataJSON", "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiaDV4U3lJUk14MklRUHIxbVFrNkdEOThYU1FPQkhnTUhWcEpJa01WOU5rYyIsIm9yaWdpbiI6Imh0dHBzOi8vZGV2LmRvbnRuZWVkYS5wdyJ9")
        .put("attestationObject", "o2NmbXRlYXBwbGVnYXR0U3RtdKJjYWxnJmN4NWOCWQJHMIICQzCCAcmgAwIBAgIGAXSFZw11MAoGCCqGSM49BAMCMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwOTEzMDI0OTE3WhcNMjAwOTE0MDI1OTE3WjCBkTFJMEcGA1UEAwxAMzI3ZWI1ODhmMTU3ZDZiYjY0NTRmOTdmNWU1NmM4NmY0NGI1MDdjODgxOGZmMjMwYmQwZjYyNWJkYjY1YmNiNjEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARiAlQ11YPbcpjmwM93iOefyu00h8-4BALNKnBDB5I9n17wD5wNqP0hYua340eB75Z1L_V6I7R4qraq7763zj9mo1UwUzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB_wQEAwIE8DAzBgkqhkiG92NkCAIEJjAkoSIEIPuwR1EQvcCtYCRahnJWisqz6YYLEAXH16p0WXbLfY6tMAoGCCqGSM49BAMCA2gAMGUCMDpEvt_ifVr8uu1rnLykezfrHBXwLL-D6DO73l_sX_DLRwXDmqTiPSx0WHiB554m5AIxAIAXIId3WdSC2B2zYFm4ZsJP_jAgjTL1GguZ-Ae78AN2AcjKblEabOdkbKr0aL_M9FkCODCCAjQwggG6oAMCAQICEFYlU5XHp_tA6-Io2CYIU7YwCgYIKoZIzj0EAwMwSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODM4MDFaFw0zMDAzMTMwMDAwMDBaMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASDLocvJhSRgQIlufX81rtjeLX1Xz_LBFvHNZk0df1UkETfm_4ZIRdlxpod2gULONRQg0AaQ0-yTREtVsPhz7_LmJH-wGlggb75bLx3yI3dr0alruHdUVta-quTvpwLJpGjZjBkMBIGA1UdEwEB_wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUJtdk2cV4wlpn0afeaxLQG2PxxtcwHQYDVR0OBBYEFOuugsT_oaxbUdTPJGEFAL5jvXeIMA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEA3YsaNIGl-tnbtOdle4QeFEwnt1uHakGGwrFHV1Azcifv5VRFfvZIlQxjLlxIPnDBAjAsimBE3CAfz-Wbw00pMMFIeFHZYO1qdfHrSsq-OM0luJfQyAW-8Mf3iwelccboDgdoYXV0aERhdGFYmD3cRxDpwIiyKduonVYyILs59yKa_0ZbCmVrGvuaivigRQAAAAAAAAAAAAAAAAAAAAAAAAAAABQniUCo9eF58OtQPuiHktAxsEflMaUBAgMmIAEhWCBiAlQ11YPbcpjmwM93iOefyu00h8-4BALNKnBDB5I9nyJYIF7wD5wNqP0hYua340eB75Z1L_V6I7R4qraq7763zj9m"));

    webAuthN.authenticate(
        new JsonObject()
          .put("username", "adam")
          .put("origin", "https://dev.dontneeda.pw")
          .put("webauthn", packedFullAttestationWebAuthnSample)
          .put("challenge", "h5xSyIRMx2IQPr1mQk6GD98XSQOBHgMHVpJIkMV9Nkc"))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  @Ignore("Certificate expired")
  public void testAppleAttestation2(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("FIDO Examples Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    JsonObject packedFullAttestationWebAuthnSample = new JsonObject()
      .put("rawId", "J4lAqPXhefDrUD7oh5LQMbBH5TE")
      .put("id", "J4lAqPXhefDrUD7oh5LQMbBH5TE")
      .put("type", "public-key")
      .put("response", new JsonObject()
        .put("clientDataJSON", "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoia093TXZFMm1RTzZvdTBCMGpqRDBWQSIsIm9yaWdpbiI6Imh0dHBzOi8vNmNjM2M5ZTc5NjdhLm5ncm9rLmlvIn0")
        .put("attestationObject", "o2NmbXRlYXBwbGVnYXR0U3RtdKJjYWxnJmN4NWOCWQJIMIICRDCCAcmgAwIBAgIGAXUCfWGDMAoGCCqGSM49BAMCMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAxMDA3MDk0NjEyWhcNMjAxMDA4MDk1NjEyWjCBkTFJMEcGA1UEAwxANjEyNzZmYzAyZDNmZThkMTZiMzNiNTU0OWQ4MTkyMzZjODE3NDZhODNmMmU5NGE2ZTRiZWUxYzcwZjgxYjViYzEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR5_lkIu1EpyAk4t1TATSs0DvpmFbmHaYv1naTlPqPm_vsD2qEnDVgE6KthwVqsokNcfb82nXHKFcUjsABKG3W3o1UwUzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB_wQEAwIE8DAzBgkqhkiG92NkCAIEJjAkoSIEIJxgAhVAs-GYNN_jfsYkRcieGylPeSzka5QTwyMO84aBMAoGCCqGSM49BAMCA2kAMGYCMQDaHBjrI75xAF7SXzyF5zSQB_Lg9PjTdyye-w7stiqy84K6lmo8d3fIptYjLQx81bsCMQCvC8MSN-aewiaU0bMsdxRbdDerCJJj3xJb3KZwloevJ3daCmCcrZrAPYfLp2kDOshZAjgwggI0MIIBuqADAgECAhBWJVOVx6f7QOviKNgmCFO2MAoGCCqGSM49BAMDMEsxHzAdBgNVBAMMFkFwcGxlIFdlYkF1dGhuIFJvb3QgQ0ExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwMzE4MTgzODAxWhcNMzAwMzEzMDAwMDAwWjBIMRwwGgYDVQQDDBNBcHBsZSBXZWJBdXRobiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgy6HLyYUkYECJbn1_Na7Y3i19V8_ywRbxzWZNHX9VJBE35v-GSEXZcaaHdoFCzjUUINAGkNPsk0RLVbD4c-_y5iR_sBpYIG--Wy8d8iN3a9Gpa7h3VFbWvqrk76cCyaRo2YwZDASBgNVHRMBAf8ECDAGAQH_AgEAMB8GA1UdIwQYMBaAFCbXZNnFeMJaZ9Gn3msS0Btj8cbXMB0GA1UdDgQWBBTrroLE_6GsW1HUzyRhBQC-Y713iDAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIxAN2LGjSBpfrZ27TnZXuEHhRMJ7dbh2pBhsKxR1dQM3In7-VURX72SJUMYy5cSD5wwQIwLIpgRNwgH8_lm8NNKTDBSHhR2WDtanXx60rKvjjNJbiX0MgFvvDH94sHpXHG6A4HaGF1dGhEYXRhWJhWHo8_bWPQzAMKYRIrGXu__PkMUfuqHM4RH7Jea4WDgkUAAAAAAAAAAAAAAAAAAAAAAAAAAAAUomGfdaNI-cYgWrq2klNk97zkcg-lAQIDJiABIVggef5ZCLtRKcgJOLdUwE0rNA76ZhW5h2mL9Z2k5T6j5v4iWCD7A9qhJw1YBOirYcFarKJDXH2_Np1xyhXFI7AASht1tw"));

    webAuthN.authenticate(
        new JsonObject()
          .put("username", "paulo")
          .put("origin", "https://6cc3c9e7967a.ngrok.io")
          .put("webauthn", packedFullAttestationWebAuthnSample)
          .put("challenge", "kOwMvE2mQO6ou0B0jjD0VA"))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }
}
