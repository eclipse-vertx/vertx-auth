package io.vertx.ext.jwt;

import io.vertx.core.json.JsonObject;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
public class JWTTest {

  @Test
  public void createPublicKey() {
    JWT jwt = new JWT().addPublicKey("RS256", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqGQkaBkiZWpUjFOuaabgfXgjzZzfJd0wozrS1czX5qHNKG3P79P/UtZeR3wGN8r15jVYiH42GMINMs7R7iP5Mbm1iImge5p/7/dPmXirKOKOBhjA3hNTiV5BlPDTQyiuuTAUEms5dY4+moswXo5zM4q9DFu6B7979o+v3kX6ZB+k3kNhP08wH82I4eJKoenN/0iCT7ALoG3ysEJf18+HEysSnniLMJr8R1pYF2QRFlqaDv3Mqyp7ipxYkt4ebMCgE7aDzT6OrfpyPowObpdjSMTUXpcwIcH8mIZCWFmyfF675zEeE0e+dHKkL1rPeCI7rr7Bqc5+1DS5YM54fk8xQwIDAQAB");
    assertFalse(jwt.isUnsecure());
    assertTrue(jwt.availableAlgorithms().containsAll(Arrays.asList("RS256", "none")));
  }

  @Test
  public void createKeystore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
    KeyStore ks = KeyStore.getInstance("jceks");

    try (InputStream in = JWTTest.class.getResourceAsStream("/keystore.jceks")) {
      ks.load(in, "secret".toCharArray());
    }

    JWT jwt = new JWT(ks, "secret".toCharArray());
    assertFalse(jwt.isUnsecure());
    // assert algorithms are available
    assertTrue(jwt.availableAlgorithms().containsAll(Arrays.asList("HS256", "HS512", "RS256", "HS384", "none")));
  }

  @Test
  public void createPrivateKey() {
    JWT jwt = new JWT().addPrivateKey("RS256", "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+LyhQqgy0hkUtdJfcBs/dleD+486n8xQkzNl0doRQZ2mEA72uU4HE6q9cDXDJJFMOJsYuwmyj2Zk590e+iWvWuV2DlXXH0mbCKlDajk4Kux6Z8XB8kVXGi3SjbiQ2CcoMe674ki2Yz0I78VZy9vZ1rz3f2z8eFsUnL+ywF6TCvptYeLqCJJSEJhTOFrGHowHYagUucEhVIodyrwWdHNyo4IguzgKJ/Ke1Aq5hZYRhJYiETD15TcbvT0yUTY96bIRSQzk5Z66S3AyCuai/UtKaJy5v8FcjpJuYutoy+zSgUj14Bhp/cvL8xgbypPwi3a9TAuFTzXBsORstUzvNh1IfAgMBAAECggEAXHSocK56hrhPoQ1xVfGp09stCjzNFjDBtjIv9MI5CK19SkRXTgwipgxBO8r87YvPJK4M4mZ6Uh1StC9WnXZJCpYKtBFQtNfARNw1ekp7/hOBiO0q9iPhQyhAh8Lfr7WKmA74vLazm/oGBQYKNNGCdyu+NLltMb94ENjng6O64UDZXJa5m1k0TqjBveu0B3ti8xYOKuO2expZieflWuW6g/9sPa1gqKauciVGkshleSpPKxV9fjlauQ2yUwI/4naPfOovCc8F0A+A6sDTCq66E2jZCwxr7xEahzU1fYPPnMZNXf8VaJxeDWsiUoJxSabmerH/icm6mubdiHUw07R04QKBgQDrnM4ECMB5zfeFtYZkcrVIMt1wpQJ/40Hn6bIntg7CancjqxYo4eOVVHVNy18ciiSB2ih7LdrmwjjzUsDbT0+NIM5kCOwlJPA7qzLY/G0p9iZfZlU0437OckXUHbnnyEyzygmU/AIQ7Mq2vM6Bjt+B0nDczRrRqD8Phf9rmq09nQKBgQDOpAr0z3DmKa/LDH/UVgSfNQyFnbHIEZPVh39tjHVDNY60uol8FDlpmaLfoy3GnCgCihcXRtykkW1LROt2lM3R2ZpG5yc8K7Nu7GdtiyasUdQIgXqNJ4UFbQo/PUJ69f5SM9k0KwICOIibBTwsYRSkmj80nDjFnlQJJu+WqOTf6wKBgQDoWSEc/1h4hfJDzIh0xF4bjfWsIT2+ymjzABYtbS9O8Fj/NrfKp0CcwcZQam8oIN7xoybqmoTVrdElu4TugV8M6L5ADkB6PNwfq6ugKgapK9IZoDwExRgHFM/h51KuzWs+nc4nOwH6mNkrrjPjtfaZ+uJMDIQXH1jYwSbqgYW4TQKBgHdcinee27gXnFPNhIlCpqjQG8uSq37FqH9PJWxCFfoclbIPjhr+E6vL8yj7ORXgXbwZx/zKEel9l4RC60Az9C+jYlpSa3d2Rs9r/tJn7o7bNX80S3X9vfjEY4bj++LK9XzGNlDMBv0BaucgvwFjkmkCMEBTfPep3SDsPLjqFkrBAoGBALaaBgulePsvrdNHDyt1S2VL/InoGGPHN/6NLYW/Nv8NYA+mhizyrFKwMYJIgrm09Z9Je7UQkYImrozfE7j3LaSWeXHy5kUjdJc458ile+Lzb4MyJ/ytu+BeGSdCvBZc/jZf8LpiLrGoIz+oDMWD0cC+r1OmFtjn4uy3S7MCmuKO");
    assertFalse(jwt.isUnsecure());
    System.out.println(jwt.availableAlgorithms());
    assertTrue(jwt.availableAlgorithms().containsAll(Arrays.asList("RS256", "none")));
  }

  @Test
  public void createPublicKey2() throws Exception {
    JWT jwt = new JWT().addPublicKey("RS256",
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuGbXWiK3dQTyCbX5xdE4\n" +
      "yCuYp0AF2d15Qq1JSXT/lx8CEcXb9RbDddl8jGDv+spi5qPa8qEHiK7FwV2KpRE9\n" +
      "83wGPnYsAm9BxLFb4YrLYcDFOIGULuk2FtrPS512Qea1bXASuvYXEpQNpGbnTGVs\n" +
      "WXI9C+yjHztqyL2h8P6mlThPY9E9ue2fCqdgixfTFIF9Dm4SLHbphUS2iw7w1JgT\n" +
      "69s7of9+I9l5lsJ9cozf1rxrXX4V1u/SotUuNB3Fp8oB4C1fLBEhSlMcUJirz1E8\n" +
      "AziMCxS+VrRPDM+zfvpIJg3JljAh3PJHDiLu902v9w+Iplu1WyoB2aPfitxEhRN0\n" +
      "YwIDAQAB");
    assertFalse(jwt.isUnsecure());
    assertTrue(jwt.availableAlgorithms().containsAll(Arrays.asList("RS256", "none")));
    System.out.println(
      jwt.decode("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA").encodePrettily()
    );
  }

  @Test
  public void createPublicKey3() throws Exception {
    JWT jwt = new JWT().addPublicKey("RS256",
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjoVg6150oqh7csrGMsttu7r+s4YBkYDkKrg2v6Gd5NhJw9NKnFlojPnLPoDSlxpNpN2sWegexcsFdDdmtuMzTxQ3hnkFWHDDXsyfj2fKQwDjgcxg95nRaaI+/OGhWbEsGdt/A5jxg2f4Vp4VLTwCj7Ujq4hVx67vO/zbJ2k0cD2uz5T731tvqweC7H/Os+G8B1+PpH5e1jGkDPZohe4ERCEdwNcC9IAt1tPr/LKfh+84hOkE3i9mGG/LGUiJShtw7ia2jXTMb1JErlJsLJOjh+guz6OztQOICN//+rRA4AACB//+IeJ8mr/jN/dww+RfYyeAd/SId56ae8H4SE4HQQIDAQAB");
    assertFalse(jwt.isUnsecure());
    assertTrue(jwt.availableAlgorithms().containsAll(Arrays.asList("RS256", "none")));
    System.out.println(
      jwt.decode("eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiIxOWZkMzViZi0yNzRkLTRjNDItOTNlNi02ZjI4MjA2YmNkNjAiLCJleHAiOjE0ODIyNDUzNDIsIm5iZiI6MCwiaWF0IjoxNDgyMjQ1MjgyLCJpc3MiOiJodHRwczovL3NlY3VyZS1zc28tc3NvLmU4Y2EuZW5naW50Lm9wZW5zaGlmdGFwcHMuY29tL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImRlbW9hcHAiLCJzdWIiOiJkZDZiMTZiMS1mM2RiLTQxMGEtYjBjNC1kMWIwZmMyMzAwOGMiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJkZW1vYXBwIiwic2Vzc2lvbl9zdGF0ZSI6Ijc0Nzg3NmNmLTFiN2YtNGQyZC05OTdjLTRkODhhNmNlMjU2ZSIsImNsaWVudF9zZXNzaW9uIjoiZjlkODZiNTYtZWQzNy00Mjg1LWE2MjEtNTcyOTk4M2MzNjkyIiwiYWxsb3dlZC1vcmlnaW5zIjpbXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImNyZWF0ZS1yZWFsbSIsImFkbWluIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsibWFzdGVyLXJlYWxtIjp7InJvbGVzIjpbIm1hbmFnZS1ldmVudHMiLCJ2aWV3LXJlYWxtIiwidmlldy1pZGVudGl0eS1wcm92aWRlcnMiLCJtYW5hZ2UtcmVhbG0iLCJtYW5hZ2UtaWRlbnRpdHktcHJvdmlkZXJzIiwiaW1wZXJzb25hdGlvbiIsInZpZXctZXZlbnRzIiwiY3JlYXRlLWNsaWVudCIsIm1hbmFnZS11c2VycyIsInZpZXctdXNlcnMiLCJ2aWV3LWNsaWVudHMiLCJtYW5hZ2UtY2xpZW50cyJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctcHJvZmlsZSJdfX0sIm5hbWUiOiIiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhZG1pbiJ9.UNVAIx7bA4_sxyjluz3NwdP43zE9ItxhCWW9SuMnvVn4J849Mgu7HX3pSrQcDDZyTNiHSJ6a_XoSNoUKFiG8CmiGSiQvu2v8mY3KvJDTQ7mIw9hKjLgBj7Ybm_QE55mlEf6lviohNGvt4SeOEiMNsV07NAtAUDS7qYh9IWEYFUKWBgeXlSipfHmCCmBSUwavNmJinOO2Fx27sZIjJ-icVrim0mHjGSkytzBdrb9mUOyoCkZyFzWOOhW5pZfa5JJFfLOxrJlUCglbkn-K5qneGItisRQRtCckV-fN9lL6hq8dmSB6VvDBfMRzYZ1ORQMP57ydYYJeYMDYDAF8enMNEA").encodePrettily()
    );
  }

  @Test
  public void createHMac() throws Exception {
    JWT jwt = new JWT().addPrivateKey("HS256","qnscAdgRlkIhAUPY44oiexBKtQbGY0orf7OV1I50");
    assertFalse(jwt.isUnsecure());
    assertTrue(jwt.availableAlgorithms().containsAll(Arrays.asList("HS256", "none")));

    String token = jwt.sign(new JsonObject().put("test", "test"), new JsonObject());
    assertNotNull(token);
    // verify
    assertNotNull(jwt.decode(token));
    assertTrue(jwt.decode(token).containsKey("test"));
  }
}
