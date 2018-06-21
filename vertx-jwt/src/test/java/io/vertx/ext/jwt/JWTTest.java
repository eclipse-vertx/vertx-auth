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
    JWT jwt = new JWT().addSecretKey("RS256", "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+LyhQqgy0hkUtdJfcBs/dleD+486n8xQkzNl0doRQZ2mEA72uU4HE6q9cDXDJJFMOJsYuwmyj2Zk590e+iWvWuV2DlXXH0mbCKlDajk4Kux6Z8XB8kVXGi3SjbiQ2CcoMe674ki2Yz0I78VZy9vZ1rz3f2z8eFsUnL+ywF6TCvptYeLqCJJSEJhTOFrGHowHYagUucEhVIodyrwWdHNyo4IguzgKJ/Ke1Aq5hZYRhJYiETD15TcbvT0yUTY96bIRSQzk5Z66S3AyCuai/UtKaJy5v8FcjpJuYutoy+zSgUj14Bhp/cvL8xgbypPwi3a9TAuFTzXBsORstUzvNh1IfAgMBAAECggEAXHSocK56hrhPoQ1xVfGp09stCjzNFjDBtjIv9MI5CK19SkRXTgwipgxBO8r87YvPJK4M4mZ6Uh1StC9WnXZJCpYKtBFQtNfARNw1ekp7/hOBiO0q9iPhQyhAh8Lfr7WKmA74vLazm/oGBQYKNNGCdyu+NLltMb94ENjng6O64UDZXJa5m1k0TqjBveu0B3ti8xYOKuO2expZieflWuW6g/9sPa1gqKauciVGkshleSpPKxV9fjlauQ2yUwI/4naPfOovCc8F0A+A6sDTCq66E2jZCwxr7xEahzU1fYPPnMZNXf8VaJxeDWsiUoJxSabmerH/icm6mubdiHUw07R04QKBgQDrnM4ECMB5zfeFtYZkcrVIMt1wpQJ/40Hn6bIntg7CancjqxYo4eOVVHVNy18ciiSB2ih7LdrmwjjzUsDbT0+NIM5kCOwlJPA7qzLY/G0p9iZfZlU0437OckXUHbnnyEyzygmU/AIQ7Mq2vM6Bjt+B0nDczRrRqD8Phf9rmq09nQKBgQDOpAr0z3DmKa/LDH/UVgSfNQyFnbHIEZPVh39tjHVDNY60uol8FDlpmaLfoy3GnCgCihcXRtykkW1LROt2lM3R2ZpG5yc8K7Nu7GdtiyasUdQIgXqNJ4UFbQo/PUJ69f5SM9k0KwICOIibBTwsYRSkmj80nDjFnlQJJu+WqOTf6wKBgQDoWSEc/1h4hfJDzIh0xF4bjfWsIT2+ymjzABYtbS9O8Fj/NrfKp0CcwcZQam8oIN7xoybqmoTVrdElu4TugV8M6L5ADkB6PNwfq6ugKgapK9IZoDwExRgHFM/h51KuzWs+nc4nOwH6mNkrrjPjtfaZ+uJMDIQXH1jYwSbqgYW4TQKBgHdcinee27gXnFPNhIlCpqjQG8uSq37FqH9PJWxCFfoclbIPjhr+E6vL8yj7ORXgXbwZx/zKEel9l4RC60Az9C+jYlpSa3d2Rs9r/tJn7o7bNX80S3X9vfjEY4bj++LK9XzGNlDMBv0BaucgvwFjkmkCMEBTfPep3SDsPLjqFkrBAoGBALaaBgulePsvrdNHDyt1S2VL/InoGGPHN/6NLYW/Nv8NYA+mhizyrFKwMYJIgrm09Z9Je7UQkYImrozfE7j3LaSWeXHy5kUjdJc458ile+Lzb4MyJ/ytu+BeGSdCvBZc/jZf8LpiLrGoIz+oDMWD0cC+r1OmFtjn4uy3S7MCmuKO");
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
    JWT jwt = new JWT().addSecret("HS256","qnscAdgRlkIhAUPY44oiexBKtQbGY0orf7OV1I50");
    assertFalse(jwt.isUnsecure());
    assertTrue(jwt.availableAlgorithms().containsAll(Arrays.asList("HS256", "none")));

    String token = jwt.sign(new JsonObject().put("test", "test"), new JWTOptions());
    assertNotNull(token);
    // verify
    assertNotNull(jwt.decode(token));
    assertTrue(jwt.decode(token).containsKey("test"));
  }

  @Test
  public void testECKeyPair() {
    JWT vk = new JWT().addPublicKey("ES256","MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwq481nd4jdkvwYCck6CaC+obxrrLOdArA28iPxkKyRw687M7WJZI4OGnIMx97uSuANNCb7SllqoKvYJix+0OMg==");
    JWT sk = new JWT().addSecretKey("ES256","MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQguQt7y3Vy2llRyEi6deLKm5ywIEnYReXYJfKXNtrvMFugCgYIKoZIzj0DAQehRANCAATCrjzWd3iN2S/BgJyToJoL6hvGuss50CsDbyI/GQrJHDrzsztYlkjg4acgzH3u5K4A00JvtKWWqgq9gmLH7Q4y");

    String signed = sk.sign(new JsonObject().put("test", "test"), new JWTOptions().setAlgorithm("ES256"));

    JsonObject decoded = vk.decode(signed);

    assertEquals("test", decoded.getString("test"));
  }

  @Test
  public void testGoogleCerts() {
    JWT jwt = new JWT();
    jwt.addCertificate("RS256",
       "-----BEGIN CERTIFICATE-----\nMIIDJjCCAg6gAwIBAgIIZtJv8PyRUgowDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE\nAxMrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe\nFw0xNzEwMDgxMTQzMzRaFw0xNzEwMTExMjEzMzRaMDYxNDAyBgNVBAMTK2ZlZGVy\nYXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6fNn5kfLZQ43Z+ZTqFMUF+dN2L2BphQKz\ngaWCsyzyJYwEySgMxbO8cQgTlgZzcC1Rt6phWHMBkFQQNykSk/K0A8xaaNqFNNVz\neszR+XJ3IvCQGo8rS2K/LrNofGZrph00k6DZ7XJsWav0GotAwDd0H6IsNbFHCyRJ\n75ASzZr8fT8RJ9bQeTLoCsmwPXYBPeSvoWgZzOypbmLhohw0J7fBUbgVZ8fR3crh\nv6RDOp4/fDALWxCVPptFn0hMPeT2Dla9kbnPfVSWtciyvty5JJXnpuoqA6rLfEpM\nGYnMSk+SbD2R0W9O2LMRfoJ52qml+2s/aLpNKGJc2vLzDyH7CiavAgMBAAGjODA2\nMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsG\nAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQAlDoCH/E43ruorgPIATCO++dOfOIb/\nn+NgE727UeK1acELi+dUjSdYEe+WXdY2sichgE1JqPrsMWFHCwHTUfVubmku5BTk\nlj9k6F9jKc+XDMra1w0KGSGrxwSqwYhkhSdMOGGa9C3td+s7M/E4JV+XoQXAY3uE\naB0lO4c+pckDwU/LAGrMldogT3+zE+4NRS7p8dstnww3OIHUCFfytbhcY8sH4Vjq\ndMWGrv8R/1L0jXok8vFPEAwvXzVc3NeUClio0hOEmhTjbLgebsgToB1aNC1pnzmH\nTclVndTwDcnDkhImpvuWE1lX+KPkFJ54ixS4Bi2cqWud1aQ2Mqi7KHfK\n-----END CERTIFICATE-----\n"
    );
    jwt.addCertificate("RS256",
       "-----BEGIN CERTIFICATE-----\nMIIDJjCCAg6gAwIBAgIIeABc0/4wb7AwDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE\nAxMrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe\nFw0xNzEwMDkxMTQzMzRaFw0xNzEwMTIxMjEzMzRaMDYxNDAyBgNVBAMTK2ZlZGVy\nYXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3ICz+C7FKE4jbsRh/cZK1I9M5lXGlyvk8\nc72BuK3/uLwnRH5eSrooA1LEqwVdKV5MOTuHHnxWFb57yyBl8Ld3CGK/aeZYIGd6\niV8ym/jw6rCdJhkL6yCZ3/Xj3+Un+5Vf+ObjHd04X/GbwleFRcldJilpgwtt0PKT\n/JBl/lKqTzzH/HWzdp3tj5gfVJzj1NxfN4K0GSFDy/5pRYsT9NebFC/JoBgSXrEE\nZXaigqQsYiI+lTDL59TLq8XaaT0V1sfoHnspu3DikgO51eJBP3c0wB2CvXxk+vMl\nSQMsnDcsztiijGPwrpxrLwDyzsm3Rs7WI9kDHPeUeKhGX0/s9AnBAgMBAAGjODA2\nMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsG\nAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQAiZt536sXwNXqUs92edWsQ+uiraJbl\nATuMSslrQhGJjUebmlpIUMe8Dv2dj+/bYK7gZyjUQKwjmtCJ+U8Z2Ec/v9yEqKpy\nzfYIOTF/17d31OvisnccIbjBL2X+b/OHsFDjaY5hZrs0mczr1ePaYlE/EsyIFEZC\nwGbgarp7FxlRrdJEBN8jnjUgK6Kig2GLtcQcHfkIjxmVDzgS47TAtxPNTBGQypWu\nbALTWt+WTAFpQGcW6pj9nOxuV2XB4RkFg7XrHtnBvad4/KAD/kp2if6BFyvwWcyQ\nzKqqKcjJHinaGWf7qlBLBJTQcZcWPJEzFdwBsHHejgU8vy9hR97rvU8s\n-----END CERTIFICATE-----\n"
    );
    jwt.addCertificate("RS256",
       "-----BEGIN CERTIFICATE-----\nMIIDJjCCAg6gAwIBAgIIcz32mW0b5V8wDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE\nAxMrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe\nFw0xNzEwMDcxMTQzMzRaFw0xNzEwMTAxMjEzMzRaMDYxNDAyBgNVBAMTK2ZlZGVy\nYXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDDmL6MaLATK497Ce9H6UVx4FFiHiDH3X44\nUtonDCvzIKtJVzMCDJzXDLAUEKxQEMGEekpJWKWogYbZ8iqF1fb8gUn47Fi9cOYm\n1gXr2RZNp9mMW2cCXwR0iqPVf7LfU+b2BgP+th4sbcJmE0uMgT/L1+Tn8xs45zRn\n5uvj/DOKeDod8REhNsA4B8J3xGLT+1cOpiCL4LUL+CzYeF5gQhaqlnax7xSwa8iD\na5484JXwbdrR+6+HqGCO62yl8n9Ufd54fBjDJjOJ6r6wNZzJXmoaWcmn1NmVn3Pb\njZZ1gePcLaS501NSDvqnqy9uzpy7VmJkD1ZmRov13yFZ4ni0tCDdAgMBAAGjODA2\nMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsG\nAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQAfVSQFYR21K1IynPE/g0aYueSQHvbo\n7SaT/iCmLS4g4EXqpGFGSMgQZWe9FckFYqAkJZ8AS2BtlzflfNYBH9K6V++sm5xx\nhsH+DmS/dXUQrSWuwKc5sS385D5kg2vJlqO1snCYOg1iEMkvU36mEO3o0kAi+2g1\nNWOWiCFLLqoC4onmwDKv/K5qpwb2n3+IUbaS8R/cgGsq6B7ohCSrdHfErOOitNsy\nnLO733lcFJKYxrYu4/OpvGkKBaxGf8h1BsDmNfenfYq4ak0N+8nTxPfc0fARyCkH\nSJPQ5WWMfi14d7J6hjc8qZHIDsAiJ50LB36Nk9p+KEQT5yh3UFbPXJO6\n-----END CERTIFICATE-----\n"
    );

    assertNotNull(jwt.decode("eyJhbGciOiJSUzI1NiIsImtpZCI6Ijc0MjQzMGI2ZDRkZjQxMzVlM2JkOTgyYWM2YmVjNDNhMTE4ODhkMWIifQ.eyJhenAiOiI1ODUyMDUyMjk1NzctZGlxZ2l1NWkwbjNoN2hzZmF0cG91MzY0OXVvaGduOWkuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI1ODUyMDUyMjk1NzctZGlxZ2l1NWkwbjNoN2hzZmF0cG91MzY0OXVvaGduOWkuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDI1ODI3NDEyNjA5NDc1ODQxNDQiLCJhdF9oYXNoIjoicGJWZE1Nb3l6UDl5UU9sMk54bkJDUSIsImlzcyI6ImFjY291bnRzLmdvb2dsZS5jb20iLCJpYXQiOjE1MDc1NzgyMDMsImV4cCI6MTUwNzU4MTgwM30.cU21Gu1jEcAONlQ0vf0ju8W7gsdyzPo-U3U6JCFaVqYqF5J2JmhCSk_-kJcY19WKyg8iwibOSNuuQE8PP0eCiIWDY-fq_3wOoO4IBUa5zlmTMNdz9Af4vH2h-optaG89tXE89J_-D2TjkKDdu1nPVLefX6E95vjb3P9LP5LfFJV53zT_deacFn4XiyCVMBl7sfNE0A6YG3PmZkVNgyIYJCv21bB5N_YtWTSEV_8YSFaJwDcEihqBGiFe3fO3k9-A237HuKevBRfo_xAyIQXnCHiLg8eETGTK3sfRh_ugxMI0jvgt4hBZQTioGjnaMRmQxaiJ_3IOrpSJeMu_JIg8-g"));
    assertNotNull(jwt.decode("eyJhbGciOiJSUzI1NiIsImtpZCI6ImMzODM1NWU3MjA5ZTlmOTkwOWJlODUxOTIyODhkMDg1OTY1NGEyOTUifQ.eyJhenAiOiI1ODUyMDUyMjk1NzctZGlxZ2l1NWkwbjNoN2hzZmF0cG91MzY0OXVvaGduOWkuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI1ODUyMDUyMjk1NzctZGlxZ2l1NWkwbjNoN2hzZmF0cG91MzY0OXVvaGduOWkuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDI1ODI3NDEyNjA5NDc1ODQxNDQiLCJhdF9oYXNoIjoiV1hJZlQ3WWVIaWZUaXVmRkt2NldJZyIsImlzcyI6ImFjY291bnRzLmdvb2dsZS5jb20iLCJpYXQiOjE1MDc1Nzk5MTEsImV4cCI6MTUwNzU4MzUxMX0.fZ_Z0Xz3Odef-1_iZbpn50h9vQ6mtY7Fqc69cWsfX_8f699252hNPnZWDvw_gfe0HU1b8hvGKIbR7ZTzzqqzgMBRW8Jy7FqNAj0zlKi2OIMaQlWFmQG7owMQOYXuc0FSI_EMCjBVe7jdbkFxZ6PTa6o0k-A88Aw2NEmLitTSp2WSPtcSu7o_oV3DawC0qUyMyP-xhG5rPEbhpn0WJ4f3NGV8qY1wY2nsV9PdO985IQQJNjp3DHoV1eWQDsg0v1ouTnGjNVLWRIxV2CZPW6T9PpkQO9eh5WBoqCAKfVg3mBGs0Am0xdh-GSqwejBpPWqVQyXVDfjCbHYTan8li3rPSg"));
  }
}
