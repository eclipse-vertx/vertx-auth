package io.vertx.ext.auth.test.jwt;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RunWith(VertxUnitRunner.class)
public class JWKTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void testJWK(TestContext should) {

    JsonObject response = new JsonObject("{\"keys\":[{\"kty\":\"EC\",\"kid\":\"3pZFiNEiyZmOkGH9YQzNP3AOt7I\",\"use\":\"sig\",\"x\":\"r8TDXsFBN_vwcb0p_1RudIM_qPwBDh1Apms4xKUbzEI\",\"y\":\"5fSOPY1uf3oFIQVhm9tt1Vm05BLwK4fbL4H8sppzLPw\",\"crv\":\"P-256\"},{\"kty\":\"EC\",\"kid\":\"DoEtKNSwDMF2qL79mUUm1a9qCW8\",\"use\":\"sig\",\"x\":\"AWEaX4183mTqnLpURnDNAodhOGu57niqdZZLUCMyl-Ug09qGmR_eFs_RMM-BcNbOTGFCxKX0nfIg3VLLx-akuCbr\",\"y\":\"AUa4vw0MVGadM3pMtRLSQ92CALm7YuzXhD8PGhd5p47SeB5_FbFcukbbdCJ5qc4v4IRrsUgVdb3o7cPg-gPVsL7N\",\"crv\":\"P-521\"},{\"kty\":\"EC\",\"kid\":\"IfHxNcQlszN8c4FbBsbsmdMZMIg\",\"use\":\"sig\",\"x\":\"53dWNCloaV3DN686a8he6A8XaZkh1UtQfWy0LMzno6sDjzC1lObu_PtzZh_Kfn4n\",\"y\":\"CBnvr7rDND1Llnz5ZCG1lCid2kmEr2z5ZHnUU6b2r9mBk0qXIrptpcXnZRGs8FDD\",\"crv\":\"P-384\"},{\"kty\":\"RSA\",\"kid\":\"saIIAZ4HZjT6-UJDHEnqGK8xZL8\",\"use\":\"sig\",\"n\":\"mWJsMDRxIFxjzbdYoGjGf9fs5hoy88SOX9im1ytaANsL7P9IW-81YZf2K3W2Hs0ushpy0QjAUfKBxgFXtPJESGlX44R23oR9c0x5V5ipq-nW0Jhwj1y314JR4HWm_Nj0pmk5YBXZ7m8y3BzAyVaImmbEkXvYpltuTRAc5nlUomRWqDy8alwIW5tmTMKh1RX5DJshJcCknud2CzuTPnWYxebEUBPT7COpxN1cy4F174I7l0QCDpB1h08o_g3fgqZh3VI3_y6zoUc6tNLod2U0i59vLNuqFKhMU7JLMYfzmVuEsRHsP5GUJ_jlfGeVJD0JqPZ7oBJdMmZpQ18zKNur_Q\",\"e\":\"AQAB\"},{\"kty\":\"EC\",\"kid\":\"4c3wOhcuhKPz_rr7K52gcDyhCkg\",\"use\":\"sig\",\"x\":\"gI53wWLB0sNNgbnp8jeGVP4HG9-7pQsAovDTo1o1cxY\",\"y\":\"vQnXvlSEdJAFn3bOJFr4BFQrkZZYiW-3z6fSAX2f3GU\",\"crv\":\"P-256\"},{\"kty\":\"RSA\",\"kid\":\"J3tj3uarnYTMow2vYNfv21bPV3c\",\"use\":\"sig\",\"n\":\"uV2t0fWDV9SQAwa-X5Frc7TlV5rAsYxSj_5DstOYQc4EQ5ZNlZYb5U7Myrt61YB5DlohcWZDklGNKhX9vI4K-ONm5AJwWfpCka9xQM_cUf4RPh2P-dPWPTdNiFQPDKCZ3a_MzHLQXRvhm6xsPWbHx9-mmghSESFAB7EZtboUx_tAjO8VnoYdL-4yzegADOmwF48-q6RM1L4VEo__ZCXbKqN0hKu2qS5ZmI54ZXmNz6RYoZEgQtxZbpEDkUuaONjlM1i-VOhP-43_70FqvPA08O3QLAJXFotdnY_epBzKFdVmWMCYTaZjFLbYiWIWNGK2QEvjopkpAq3UG21ea7yE0Q\",\"e\":\"AQAB\"},{\"kty\":\"EC\",\"kid\":\"KIJyNyl41ElVTo05G56exRR8XMw\",\"use\":\"sig\",\"x\":\"Aebigt8TQX8q6b6FYYgQ6_bU2lWYw3i4pQYkQg9xwbiFbxty0TMcGgX_kCjNsUpJnVXHGDUUPsj0wti3YT_dR8QG\",\"y\":\"AF8nk9I_FlZW1bKOA2S8c-uuUs1Wou133GrZGuNPO2ZCM1h13L6ZMp8h2AUTnjDWViCy2-LSksvIvf12xjVzE_S7\",\"crv\":\"P-521\"},{\"kty\":\"EC\",\"kid\":\"Xcn9I0CxfK9UVOxR-teHT0xkuMU\",\"use\":\"sig\",\"x\":\"COtg2PaCmNGGGFbd9wbC4fIXHq1FHQjBo9kiwyxhzF2TtCy-7rePV85HboKmaFhi\",\"y\":\"FEM8YaIaLRJ-vWi2T21pq0p7ZNNjmJLuF56DX8VdKqeMukmTk5odtx4UiRyfXtgR\",\"crv\":\"P-384\"},{\"kty\":\"EC\",\"kid\":\"OCEXyzl4ptsV8KPIGjyNnXeykjU\",\"use\":\"sig\",\"x\":\"voelTvgz2r1jd-PSRlfnF9AMqx-aGbpKfTCAh4bXFB0\",\"y\":\"DiMPqkmlkfHl7C-3d_0CNbjQeobPTlMUkTC90JeEyOo\",\"crv\":\"P-256\"},{\"kty\":\"EC\",\"kid\":\"TtRDj0Lg-lNtyjJfC0CLxWDtRFc\",\"use\":\"sig\",\"x\":\"o5hK3lNAWVND66lruO7f44wGTHn6WX6JoRN8DifFkXEdHQwhpU4Fw0t4auFtfuLB\",\"y\":\"52LQCOfYB65F2PE4gF7uARr1Dpnqr8XxlIj-jftapV0oUHaSIVc3z_RVb9QjARaD\",\"crv\":\"P-384\"},{\"kty\":\"RSA\",\"kid\":\"_IfAuPopMSUDaM3A1TTd9U1P8Z0\",\"use\":\"sig\",\"n\":\"ppCBlc9Pf5CfAT9IYIfspWEHcgAxggabzx3RtgpbL_FA6PAs7cRp8sl-Vmfe4FetVbRq9g1kxneRZa_f2cIHljG4K0p6qFu8Yk_A74Cu27LoesQb4ORPMGVjaUu8x8ZXecVdX9Ck99hyejOCWK_6Wr8TpwngexIcWMuSDxcwd47L92LBsa-ZXqGaekmYX4NE8M27x07BQTx5PUF_DYKqOSFS9V_XinkmX4Zg65NUlpdfkpVDp5ENBeAUEFSDD_2vLxDsxQSgx6tFe-xXO9oGcLLsY5S5O9OvvGZqeVE3DRW8AgNjrn5rWtvmTDrgOMWwUGNXB2O9BXhg1ilFLz5lRQ\",\"e\":\"AQAB\"},{\"kty\":\"EC\",\"kid\":\"kxjrffhSuYuEGxQKyOErhaeM5MY\",\"use\":\"sig\",\"x\":\"ADre2ClDCPNO7GntHVf22db_VQVMZ-Cnn9JNXORlV4xlfbt1NwbXNg5i6smnVQ18ihwRhJAXe3QXrCz7mINM_9NN\",\"y\":\"AHlb0KSK7RbMABbgoEtq6qepNxoSs9QHc_WYFom146930DEDCI-HXglymdeyfYp5e7yFIfiMxLImt9cJzCo0LLKC\",\"crv\":\"P-521\"},{\"kty\":\"EC\",\"kid\":\"Dk4RD6AgiCES5YVhGu50QugL5yU\",\"use\":\"enc\",\"x\":\"XPWIR8GBmfzV6vN1ygGCfqGM8ONWs8DMK8ovmEWQldX0G1oVoOJEC5YYy-oD3R4t\",\"y\":\"ANfnz4lBuZ31LC8PHpQlrdmQJKQsYlwwFu_posnsR1juZrX_rYxlcbGY1pJk7HRI\",\"crv\":\"P-384\"},{\"kty\":\"RSA\",\"kid\":\"MeCINpY4hXxV_CUS2MN3NfLVlyU\",\"use\":\"enc\",\"n\":\"oqONs61aFVgMgLp0HK6zGatDH78zMSqYcqIEMkR--W3iKfFgd9aw2GPRMCJulIfZhrAC8COPRK1EQrkdgIWPTdDdnjBG50BzbnZ8CeA29gJ97Vor69JfCZ590ipL-9jecTFWVevJ3qrrv49dPA1UXajgXmw0BuAQJMyzGhTaC2uIAHTIjsv3AxpXCpKP5V72FsKja7xin69vANkMJwjAL3G0S3G8sUU0Y08S5caDL1jG7COoek57-LRUOsgTuffkCzukRFGM6JoRUT3-hLTGmL4rT-GMmGypyhEj4GAWnif6qHeKybLhlPQ8j147R93a_uob7jc18dUB9a-i_euXYw\",\"e\":\"AQAB\"},{\"kty\":\"EC\",\"kid\":\"hj027j-wX3xJfC2GzwH2F9lYWs0\",\"use\":\"enc\",\"x\":\"ARbGJkX3jY-ajCk711ilpzfAJiGU18guc5xVlHiQm0j1YfcF1XlZrQIq14MWd3tDB7oYZoqmx6WGKbYyg93XG-Ht\",\"y\":\"AAjGPHt5Aio6-k2HPCynM33HhIIOgML58vpndCwsXZmKJ78M22sJFXbnr-i5VZIix5kljy9VG2vYAeHOpMtJI7Oj\",\"crv\":\"P-521\"},{\"kty\":\"EC\",\"kid\":\"imBX-vtXiWUtvk9np1GD5M_CIKQ\",\"use\":\"enc\",\"x\":\"Ogv5wZ36hGt_ysmLlnIxFo8zlCwP4vwtLD9DaqeHaWo\",\"y\":\"16KQxCw4zgFSZj3LNpvVBqdkRrKbf4uuwSXB3xg1k_U\",\"crv\":\"P-256\"}]}");

    String responseString = new String(
      Base64
        .getDecoder()
        .decode(
          Base64
            .getEncoder()
            .encode(
              response
                .encode()
                .getBytes())));

    JsonObject jwksResponse = new JsonObject(responseString);
    JsonArray keys = jwksResponse.getJsonArray("keys");

    // extract JWKS from keys array
    List jwks = ((List<Object>) keys.getList()).stream()
      .map(o -> new JsonObject((Map<String, Object>) o))
      .collect(Collectors.toList());


    // configure JWTAuth
    JWTAuthOptions jwtAuthOptions = new JWTAuthOptions();
    jwtAuthOptions.setJwks(jwks);
    // Configure JWT validation options
    JWTOptions jwtOptions = new JWTOptions();
    jwtOptions.setIssuer("https://dummyserver.com");
    jwtAuthOptions.setJWTOptions(jwtOptions);

    JWTAuth.create(rule.vertx(), jwtAuthOptions);
  }
}
