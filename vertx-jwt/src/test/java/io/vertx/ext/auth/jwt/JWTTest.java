package io.vertx.ext.auth.jwt;

import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
public class JWTTest {

  @Test
  public void createPublicKey() {
    JWT jwt = new JWT("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqGQkaBkiZWpUjFOuaabgfXgjzZzfJd0wozrS1czX5qHNKG3P79P/UtZeR3wGN8r15jVYiH42GMINMs7R7iP5Mbm1iImge5p/7/dPmXirKOKOBhjA3hNTiV5BlPDTQyiuuTAUEms5dY4+moswXo5zM4q9DFu6B7979o+v3kX6ZB+k3kNhP08wH82I4eJKoenN/0iCT7ALoG3ysEJf18+HEysSnniLMJr8R1pYF2QRFlqaDv3Mqyp7ipxYkt4ebMCgE7aDzT6OrfpyPowObpdjSMTUXpcwIcH8mIZCWFmyfF675zEeE0e+dHKkL1rPeCI7rr7Bqc5+1DS5YM54fk8xQwIDAQAB", false);
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
    JWT jwt = new JWT("MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+LyhQqgy0hkUtdJfcBs/dleD+486n8xQkzNl0doRQZ2mEA72uU4HE6q9cDXDJJFMOJsYuwmyj2Zk590e+iWvWuV2DlXXH0mbCKlDajk4Kux6Z8XB8kVXGi3SjbiQ2CcoMe674ki2Yz0I78VZy9vZ1rz3f2z8eFsUnL+ywF6TCvptYeLqCJJSEJhTOFrGHowHYagUucEhVIodyrwWdHNyo4IguzgKJ/Ke1Aq5hZYRhJYiETD15TcbvT0yUTY96bIRSQzk5Z66S3AyCuai/UtKaJy5v8FcjpJuYutoy+zSgUj14Bhp/cvL8xgbypPwi3a9TAuFTzXBsORstUzvNh1IfAgMBAAECggEAXHSocK56hrhPoQ1xVfGp09stCjzNFjDBtjIv9MI5CK19SkRXTgwipgxBO8r87YvPJK4M4mZ6Uh1StC9WnXZJCpYKtBFQtNfARNw1ekp7/hOBiO0q9iPhQyhAh8Lfr7WKmA74vLazm/oGBQYKNNGCdyu+NLltMb94ENjng6O64UDZXJa5m1k0TqjBveu0B3ti8xYOKuO2expZieflWuW6g/9sPa1gqKauciVGkshleSpPKxV9fjlauQ2yUwI/4naPfOovCc8F0A+A6sDTCq66E2jZCwxr7xEahzU1fYPPnMZNXf8VaJxeDWsiUoJxSabmerH/icm6mubdiHUw07R04QKBgQDrnM4ECMB5zfeFtYZkcrVIMt1wpQJ/40Hn6bIntg7CancjqxYo4eOVVHVNy18ciiSB2ih7LdrmwjjzUsDbT0+NIM5kCOwlJPA7qzLY/G0p9iZfZlU0437OckXUHbnnyEyzygmU/AIQ7Mq2vM6Bjt+B0nDczRrRqD8Phf9rmq09nQKBgQDOpAr0z3DmKa/LDH/UVgSfNQyFnbHIEZPVh39tjHVDNY60uol8FDlpmaLfoy3GnCgCihcXRtykkW1LROt2lM3R2ZpG5yc8K7Nu7GdtiyasUdQIgXqNJ4UFbQo/PUJ69f5SM9k0KwICOIibBTwsYRSkmj80nDjFnlQJJu+WqOTf6wKBgQDoWSEc/1h4hfJDzIh0xF4bjfWsIT2+ymjzABYtbS9O8Fj/NrfKp0CcwcZQam8oIN7xoybqmoTVrdElu4TugV8M6L5ADkB6PNwfq6ugKgapK9IZoDwExRgHFM/h51KuzWs+nc4nOwH6mNkrrjPjtfaZ+uJMDIQXH1jYwSbqgYW4TQKBgHdcinee27gXnFPNhIlCpqjQG8uSq37FqH9PJWxCFfoclbIPjhr+E6vL8yj7ORXgXbwZx/zKEel9l4RC60Az9C+jYlpSa3d2Rs9r/tJn7o7bNX80S3X9vfjEY4bj++LK9XzGNlDMBv0BaucgvwFjkmkCMEBTfPep3SDsPLjqFkrBAoGBALaaBgulePsvrdNHDyt1S2VL/InoGGPHN/6NLYW/Nv8NYA+mhizyrFKwMYJIgrm09Z9Je7UQkYImrozfE7j3LaSWeXHy5kUjdJc458ile+Lzb4MyJ/ytu+BeGSdCvBZc/jZf8LpiLrGoIz+oDMWD0cC+r1OmFtjn4uy3S7MCmuKO", true);
    assertFalse(jwt.isUnsecure());
    System.out.println(jwt.availableAlgorithms());
    assertTrue(jwt.availableAlgorithms().containsAll(Arrays.asList("RS256", "none")));
  }
}
