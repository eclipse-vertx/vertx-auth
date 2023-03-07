package io.vertx.ext.auth.webauthn.impl.attestation;

import io.vertx.ext.auth.webauthn.WebAuthnOptions;
import io.vertx.ext.auth.webauthn.impl.metadata.MetaDataServiceImpl;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.atomic.AtomicInteger;

@RunWith(VertxUnitRunner.class)
public class MetaDataServiceIT {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  @Test
  @Ignore("The URLs have expired")
  public void loadStatements(TestContext should) {
    final Async test = should.async();

    MetaDataServiceImpl mds = new MetaDataServiceImpl(
      rule.vertx(),
      new WebAuthnOptions()
        .putRootCertificate(
          "mds",
          "MIICZzCCAe6gAwIBAgIPBF0rd3WL/GExWV/szYNVMAoGCCqGSM49BAMDMGcxCzAJ" +
            "BgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMScwJQYDVQQLDB5GQUtF" +
            "IE1ldGFkYXRhIFRPQyBTaWduaW5nIEZBS0UxFzAVBgNVBAMMDkZBS0UgUm9vdCBG" +
            "QUtFMB4XDTE3MDIwMTAwMDAwMFoXDTQ1MDEzMTIzNTk1OVowZzELMAkGA1UEBhMC" +
            "VVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxJzAlBgNVBAsMHkZBS0UgTWV0YWRh" +
            "dGEgVE9DIFNpZ25pbmcgRkFLRTEXMBUGA1UEAwwORkFLRSBSb290IEZBS0UwdjAQ" +
            "BgcqhkjOPQIBBgUrgQQAIgNiAARcVLd6r4fnNHzs5K2zfbg//4X9/oBqmsdRVtZ9" +
            "iXhlgM9vFYaKviYtqmwkq0D3Lihg3qefeZgXXYi4dFgvzU7ZLBapSNM3CT8RDBe/" +
            "MBJqsPwaRQbIsGmmItmt/ESNQD6jYDBeMAsGA1UdDwQEAwIBBjAPBgNVHRMBAf8E" +
            "BTADAQH/MB0GA1UdDgQWBBTd95rIHO/hX9Oh69szXzD0ahmZWTAfBgNVHSMEGDAW" +
            "gBTd95rIHO/hX9Oh69szXzD0ahmZWTAKBggqhkjOPQQDAwNnADBkAjBkP3L99KEX" +
            "QzviJVGytDMWBmITMBYv1LgNXXiSilWixTyQqHrYrFpLvNFyPZQvS6sCMFMAOUCw" +
            "Ach/515XH0XlDbMgdIe2N4zzdY77TVwiHmsxTFWRT0FtS7fUk85c/LzSPQ==")
        .addRootCrl(
          "MIIB1jCCAV0CAQEwCgYIKoZIzj0EAwMwZzELMAkGA1UEBhMCVVMxFjAUBgNVBAoM" +
            "DUZJRE8gQWxsaWFuY2UxJzAlBgNVBAsMHkZBS0UgTWV0YWRhdGEgVE9DIFNpZ25p" +
            "bmcgRkFLRTEXMBUGA1UEAwwORkFLRSBSb290IEZBS0UXDTIwMDIwMTAwMDAwMFoX" +
            "DTIyMDIwMTAwMDAwMFowgZMwLwIQBCZYfWbvAtCiCiDkzlVBNhcNMTQwMzAxMDAw" +
            "MDAwWjAMMAoGA1UdFQQDCgEAMC8CEHAc4zP0TEonwYAmqsFKK0oXDTE0MDQxMzAw" +
            "MDAwMFowDDAKBgNVHRUEAwoBADAvAhD7GIBl71xpqmIqTSJH2pXBFw0xNTAzMjUw" +
            "MDAwMDBaMAwwCgYDVR0VBAMKAQCgLzAtMAoGA1UdFAQDAgEBMB8GA1UdIwQYMBaA" +
            "FN33msgc7+Ff06Hr2zNfMPRqGZlZMAoGCCqGSM49BAMDA2cAMGQCMBYPltbCN54u" +
            "A5eG2BqhHXfIrp7DLgxJYWaXF7lIk/e5yFpYqJDksq0ZGIyK+CGS8QIwXIbqlrb0" +
            "8lFFz+Onh5B1JminysL+Yjfg8ogovLJg+ANU0aRPtqh5iOzV7FB0tU+Z"));

    // add MDS servers
    String[] servers = new String[]{
      "https://mds.certinfra.fidoalliance.org/execute/0be34f782929722bffbc482c2e6dcae32d6335645352785a2387371b9b2d9fe9",
      "https://mds.certinfra.fidoalliance.org/execute/354f1d9ba876185d5f5553e3f19fece08afd6e5740355b359bec1d2457ab8c89",
      "https://mds.certinfra.fidoalliance.org/execute/3823c29331b4173d256d38e4a0506a9cf90fc338e2b06d2b2f3ab0653c78b39f",
      "https://mds.certinfra.fidoalliance.org/execute/631f627b4784b6736839db842184e4619257d78d754fa785187ce545b2e61c73",
      "https://mds.certinfra.fidoalliance.org/execute/db68c9e3a05afbab92826ec72c3e01a70bd9c03b7199697e8e28bcca8d56b505"
    };

    final AtomicInteger cnt = new AtomicInteger(servers.length);

    for (String url : servers) {
      mds
        .fetchTOC(url)
        .onFailure(should::fail)
        .onSuccess(allOk -> {
          if (cnt.decrementAndGet() == 0) {
            should.assertEquals(500, mds.metadata().size());
            test.complete();
          }
        });
    }
  }
}
