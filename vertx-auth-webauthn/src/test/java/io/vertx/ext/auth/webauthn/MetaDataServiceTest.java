package io.vertx.ext.auth.webauthn;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn.impl.metadata.MetaDataServiceImpl;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(VertxUnitRunner.class)
public class MetaDataServiceTest {

  final String data = "{\"aaguid\":\"a7d6d93a-8a0d-11e8-9a94-a6cf71072f73\",\"attestationCertificates\":{\"alg\":\"RS256\",\"includesRoot\":false,\"x5c\":[\"MIIEgzCCA2ugAwIBAgIPBK2AiITFeZ7hut8Ere1IMA0GCSqGSIb3DQEBCwUAMEExPzA9BgNVBAMTNk5DVS1OVEMtS0VZSUQtRkY5OTAzMzhFMTg3MDc5QTZDRDZBMDNBREM1NzIzNzQ0NUY2QTQ5QTAeFw0xODAyMDEwMDAwMDBaFw0yNTAxMzEyMzU5NTlaMAAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDA6hSUfe20RAne9zd4u4Her2klbIWNgM8iSW2uu8IK2vGSoYFQY3k1ZtTE-Y6UPoU37Ktmfvaq-vdIBphiamvfPBNzwhAuT-CvmYaNKPH608sG_Mba6C1-j4wC1Cizj6KBv1iE8sRWeM2Rc5F2TasqbM2S4iwe3R3XcStSMxt3Q_5NJfKsrYyqHzefQY7UlJLBh3_sq_VQApNzyEMeIXobY1a_qPd2_fLzVFPMxuVmh__dwNL9yQzhcyGdVu2vVmKNB8UITsyQLshqjHYeWdHgS48Vm2aQNUDcFkFXiMlCTDdXapYCLLyfkZqR-q7Wcn0BJ1j5CO1x3EDFLkcP1iUJAgMBAAGjggG3MIIBszAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH_BAIwADB7BgNVHSABAf8EcTBvMG0GCSsGAQQBgjcVHzBgMF4GCCsGAQUFBwICMFIeUABGAEEASwBFACAARgBJAEQATwAgAFQAQwBQAEEAIABUAHIAdQBzAHQAZQBkACAAUABsAGEAdABmAG8AcgBtACAASQBkAGUAbgB0AGkAdAB5MBAGA1UdJQQJMAcGBWeBBQgDMEoGA1UdEQEB_wRAMD6kPDA6MTgwDgYFZ4EFAgMMBWlkOjEzMBAGBWeBBQICDAdOUENUNnh4MBQGBWeBBQIBDAtpZDpGRkZGRjFEMDAfBgNVHSMEGDAWgBR06HBu42LxTz8qgK9ve4YdO8dyjTAdBgNVHQ4EFgQUzybC7F6UxfgJGgiBlSo2t-l7LDMweAYIKwYBBQUHAQEEbDBqMGgGCCsGAQUFBzAChlxodHRwczovL2ZpZG9hbGxpYW5jZS5jby5uei90cG1wa2kvTkNVLU5UQy1LRVlJRC1GRjk5MDMzOEUxODcwNzlBNkNENkEwM0FEQzU3MjM3NDQ1RjZBNDlBLmNydDANBgkqhkiG9w0BAQsFAAOCAQEAC7Rv7WJjLkdGi7lu-st0AfDRP3O78TUouUr2npjRQl2R43-iCmTjHFb_o__7NOSv4dXs0i1SDa6fqwdETBJtKxmSsIv7b0RT-20oTFCARRV0y2V-ZRjTh9j3_KgR3baLckF9xJ_Moghaj6S2glrUJ13x8sg2KW58s4qIAjtGrW0CGJcBrYsNc5CEnilNK3Gir9xWiMMJdGz_J0GGwhRWTbSbRYBkTGnCs2ewFKwrZeDEGj6wWwJi0cxu4vgXJS6Maq3krcBEv94IV-Sp4P7rPli144XSRFWPkgLNnOGa_vlRkJ2mACGyPOgi8hfosziA_10-e6GBBsZz97fcxT3vDQ\",\"MIIGATCCA-mgAwIBAgIPBFdnTNeIzLsEWilwEyh_MA0GCSqGSIb3DQEBCwUAMIG_MQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMTYwNAYDVQQDDC1GSURPIEZha2UgVFBNIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTgxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcwHhcNMTcwMjAxMDAwMDAwWhcNMzUwMTMxMjM1OTU5WjBBMT8wPQYDVQQDEzZOQ1UtTlRDLUtFWUlELUZGOTkwMzM4RTE4NzA3OUE2Q0Q2QTAzQURDNTcyMzc0NDVGNkE0OUEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDXPnN9EaUHfvywqIiyW1897f76nIjiKL8I3s-_fw7VYIvBvT4frTy_pQtLnhRgTEj3Cnf0Q3UhXtkAmEHfXtA7Yhca2vrlhmtKJSNYRyO2ythszQGUkyhG8IKqX_L1zEPu0j2o4Oj38Ujix_zY9snerZDZFEnZRrVn2PFxgd5_qvvp7d1B3VEFhLYFKE3uWmwV7BuzEErkzaGnd7-r5PrS3dFuOIrzOqWxahVB3IcfJhiwKQqY5VV630TmgqHPRPdYRvQfljb3pCdHTOpCeufB8u8rHEOiXaiBKJWKIwrVmljZsHH7_vjhNQMf-FG9uIJd4aQfRDnAQs6W-FBZi2FBAgMBAAGjggF1MIIBcTALBgNVHQ8EBAMCAYYwFgYDVR0gBA8wDTALBgkrBgEEAYI3FR8wGwYDVR0lBBQwEgYJKwYBBAGCNxUkBgVngQUIAzASBgNVHRMBAf8ECDAGAQH_AgEAMB0GA1UdDgQWBBR06HBu42LxTz8qgK9ve4YdO8dyjTAfBgNVHSMEGDAWgBRDERaZmu6dUDfCT_7iWxXJCTM_MjBoBgNVHR8EYTBfMF2gW6BZhldodHRwczovL2ZpZG9hbGxpYW5jZS5jby5uei90cG1wa2kvY3JsL0ZJRE8gRmFrZSBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxOC5jcmwwbwYIKwYBBQUHAQEEYzBhMF8GCCsGAQUFBzAChlNodHRwczovL2ZpZG9hbGxpYW5jZS5jby5uei90cG1wa2kvRklETyBGYWtlIFRQTSBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDE4LmNydDANBgkqhkiG9w0BAQsFAAOCAgEASOhnrsSJHinJkZhUJ5D55L0sm0SCRJM1imtn9NL3QcoMbc6ZFxdljB277jFN_yt1jBc4NsZEj4zN8f_lMTlhmIFSKvH11HctjYZi8-LTyOuf50F6Uttq85lxc7I-MfcktCRdjZ1ucZvjvFHXJBXcCGceBMP8wPqyBd4am2OBI89gHbG7xyaPlk6bvsFg2wUMkdfXqjcmGer3_SvAwdiWb4iA13TqZLjiSwONDCjJZ4b-SuAWbO5g2SGj8zQPzK3B9_3WF6uLSKBruT69WTQkPvvd12BtXkW7woEg2FAkc2uQIARgiIZsdvrai2HgnfancuDvUfXPakYxE4W45xkrWGdA7gelQmh9Vo4kasquFTYvXL9efkaAuM7MFsLh3nvewACf08dvcOkuCsPQ0EegNL7cPzhy7jpBh-t57NAwAn_4dTL7ADJ1119END_CKTXQUBry760bUXQTcdOjR2NRxmTmfT3SeieJp66AdpZ93DBmRvZMkb9r28KurAq2GVWI6N7X-DFLZBGOBYo6GGzBAyu1ZW04gz56G4ZMSNfm8-Q0xZ0dyH1cm2AHhqwQikoNlFEz71YDN1mfqBpT_FvXYNd-O4aoMT9Ly4AzOnFe64WhQv2QH9hLfSi0WUo-5TaSVsR8T8s_ZjOMN6hcHYFisJV5dzkLSUU-Cm7Oq94MweU\"]},\"counter\":74,\"credID\":\"SErwRhxIzjPowcnM3e-D-u89EQXLUe1NYewpshd7Mc0\",\"fmt\":\"tpm\",\"publicKey\":\"pAEDAzkBACBZAQDKtOcgyG7kv0h6S_NVNU1AL8HoosXlGPGwZIbvu6ENMfXG_Hk2tZEC4_ESTvap8giFi2NoZXtbkATX-6QVDmQkjoZFtaoaNcVWuvawp3CES344Rg0QP3zD6icMmsRDNq8CuS9Se-sJb0NYoRcBglMN87kSOQ4-sF2uiWyf0qssvEDBA2Ka8AOzQNs2H-dAGi7M6sujVyqi26asHwYGAyijVM083J1uPpcxYE-QuvzTHSXXv7BnkahUA6RLRRLSPaBI8tgoW69uoja4Q8UU_mBfFSMdy8vwL4m2bVGpGXBxV7vIIAQoZ4Bi07_jODntEn35JLl_Qm7lhuTzwaCECxVlIUMBAAE\",\"type\":\"public-key\",\"userName\":\"paulo\"}";

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void testVerify() {

    // defaults
    MetaDataService mds = new MetaDataServiceImpl(rule.vertx(), new WebAuthnOptions());

    Authenticator authenticator = new Authenticator(new JsonObject(data));
    // doesn't throw
    mds.verify(authenticator);
  }

  @Test
  public void testMDS3(TestContext should) {
    final Async test = should.async();
    // defaults
    MetaDataService mds = new MetaDataServiceImpl(rule.vertx(), new WebAuthnOptions());

    mds.fetchTOC()
      .onFailure(should::fail)
      .onSuccess(res -> {
        Authenticator authenticator = new Authenticator(new JsonObject(data));
        // doesn't throw
        try {
          mds.verify(authenticator);
          test.complete();
        } catch (RuntimeException e) {
          should.fail(e);
        }
      });
  }

}
