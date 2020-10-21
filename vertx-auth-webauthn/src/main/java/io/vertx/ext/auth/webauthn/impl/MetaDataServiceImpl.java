package io.vertx.ext.auth.webauthn.impl;

import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.impl.VertxInternal;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.CertificateHelper;
import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import io.vertx.ext.auth.impl.jose.JWS;
import io.vertx.ext.auth.impl.jose.JWT;
import io.vertx.ext.auth.webauthn.MetaDataService;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class MetaDataServiceImpl implements MetaDataService {

  private static final Base64.Decoder BASE64DEC = Base64.getDecoder();
  private static final Logger LOG = LoggerFactory.getLogger(MetaDataServiceImpl.class);

  private final VertxInternal vertx;
  private final SimpleHttpClient httpClient;
  private final JWT jwt;

  private final Metadata metadata;

  public MetaDataServiceImpl(Vertx vertx) {
    this.vertx = (VertxInternal) vertx;
    this.httpClient = new SimpleHttpClient(vertx, "vertx-auth", new HttpClientOptions());
    this.jwt = new JWT().allowEmbeddedKey(true);
    this.metadata = new Metadata(vertx);
  }

  @Override
  public Future<Boolean> fetchTOC(String toc, String rootCertificate) {
    final Promise<Boolean> promise = vertx.promise();
    httpClient.fetch(HttpMethod.GET, toc, null, null)
      .onFailure(promise::fail)
      .onSuccess(res -> {
        try {
          // verify jwt
          JsonObject json = jwt.decode(res.body().toString(), true);
          System.out.println(json.getJsonObject("header").encodePrettily());
          // verify cert chain
          JsonArray chain = json.getJsonObject("header").getJsonArray("x5c");
          List<X509Certificate> certChain = new ArrayList<>();

          for (int i = 0; i < chain.size(); i++) {
            // "x5c" (X.509 Certificate Chain) Header Parameter
            // https://tools.ietf.org/html/rfc7515#section-4.1.6
            // states:
            // Each string in the array is a base64-encoded (Section 4 of [RFC4648] -- not base64url-encoded) DER
            // [ITU.X690.2008] PKIX certificate value.
            certChain.add(JWS.parseX5c(BASE64DEC.decode(chain.getString(i).getBytes(StandardCharsets.UTF_8))));
          }
          // add the root certificate
          certChain.add(JWS.parseX5c(rootCertificate == null ? FIDO_MDS_ROOT_CERTIFICATE : rootCertificate));
          CertificateHelper.checkValidity(certChain);

          JsonArray entries = json.getJsonObject("payload").getJsonArray("entries");

          final AtomicInteger cnt = new AtomicInteger(entries.size());
          final AtomicBoolean success = new AtomicBoolean(true);

          entries.forEach(el ->
            addEntry((JsonObject) el)
              .onFailure(err -> {
                LOG.error("Failed to add entry", err);
                success.set(false);
                if (cnt.decrementAndGet() == 0) {
                  promise.complete(success.get());
                }
              })
              .onComplete(done -> {
                if (cnt.decrementAndGet() == 0) {
                  promise.complete(success.get());
                }
              }));

        } catch (RuntimeException | CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
          promise.fail(e);
        }
      });

    return promise.future();
  }

  private Future<Void> addEntry(JsonObject entry) {
    final Promise<Void> promise = vertx.promise();
    httpClient.fetch(HttpMethod.GET, entry.getString("url"), null, null)
      .onFailure(promise::fail)
      .onSuccess(res -> {
        try {
          MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
          byte[] raw = res.body().getBytes();
          byte[] digest = sha256.digest(raw);
          if (MessageDigest.isEqual(digest, entry.getBinary("hash"))) {
            metadata.loadMetadata(new JsonObject(Buffer.buffer(BASE64DEC.decode(raw))));
            promise.complete();
          } else {
            promise.fail("MDS entry hash did not match corresponding hash in MDS TOC");
          }
        } catch (RuntimeException | NoSuchAlgorithmException e) {
          promise.fail(e);
        }
      });

    return promise.future();
  }

  @Override
  public MetaDataService addStatement(JsonObject statement) {
    metadata.loadMetadata(statement);
    return this;
  }

  @Override
  public MetaDataService flush() {
    metadata.clear();
    return this;
  }

  Metadata metadata() {
    return metadata;
  }

//  public static void main(String[] args) {
//    Vertx vertx = Vertx.vertx();
//    MetaDataServiceImpl mds = new MetaDataServiceImpl(vertx);
//    String[] servers = new String[]{
//      "https://mds.certinfra.fidoalliance.org/execute/08ad7f28023a1c67c1a7c3609a62e4e128dd75e8a2fdcc593a3b3de11dd521c2",
//      "https://mds.certinfra.fidoalliance.org/execute/5f52dab5778fb99704005d08e05490f17b2bdcb7618565b54f5433665df4c13b",
//      "https://mds.certinfra.fidoalliance.org/execute/a77e5de6d3a3dbc4bed334296e2f0d2692c209717a6582b13dde47a9905858b9",
//      "https://mds.certinfra.fidoalliance.org/execute/a8b473933dc0561707f16a924655024cb57d70a581a51f18d03ea010a24ee195",
//      "https://mds.certinfra.fidoalliance.org/execute/b7c8e450b2bf77313fa4321ce7f661cffafd4fbe385813ff1ecb8c839792cba7"
//    };
//
//    String rootCert =
//      "MIICZzCCAe6gAwIBAgIPBF0rd3WL/GExWV/szYNVMAoGCCqGSM49BAMDMGcxCzAJ" +
//        "BgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMScwJQYDVQQLDB5GQUtF" +
//        "IE1ldGFkYXRhIFRPQyBTaWduaW5nIEZBS0UxFzAVBgNVBAMMDkZBS0UgUm9vdCBG" +
//        "QUtFMB4XDTE3MDIwMTAwMDAwMFoXDTQ1MDEzMTIzNTk1OVowZzELMAkGA1UEBhMC" +
//        "VVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxJzAlBgNVBAsMHkZBS0UgTWV0YWRh" +
//        "dGEgVE9DIFNpZ25pbmcgRkFLRTEXMBUGA1UEAwwORkFLRSBSb290IEZBS0UwdjAQ" +
//        "BgcqhkjOPQIBBgUrgQQAIgNiAARcVLd6r4fnNHzs5K2zfbg//4X9/oBqmsdRVtZ9" +
//        "iXhlgM9vFYaKviYtqmwkq0D3Lihg3qefeZgXXYi4dFgvzU7ZLBapSNM3CT8RDBe/" +
//        "MBJqsPwaRQbIsGmmItmt/ESNQD6jYDBeMAsGA1UdDwQEAwIBBjAPBgNVHRMBAf8E" +
//        "BTADAQH/MB0GA1UdDgQWBBTd95rIHO/hX9Oh69szXzD0ahmZWTAfBgNVHSMEGDAW" +
//        "gBTd95rIHO/hX9Oh69szXzD0ahmZWTAKBggqhkjOPQQDAwNnADBkAjBkP3L99KEX" +
//        "QzviJVGytDMWBmITMBYv1LgNXXiSilWixTyQqHrYrFpLvNFyPZQvS6sCMFMAOUCw" +
//        "Ach/515XH0XlDbMgdIe2N4zzdY77TVwiHmsxTFWRT0FtS7fUk85c/LzSPQ==";
//
//    for (String url : servers) {
//      mds.fetchTOC(url, rootCert)
//        .onFailure(err -> System.out.println("Ignoring: " + url + " - " + err.getMessage()))
//        .onSuccess(toc -> {
//          toc.getJsonArray("entries")
//            .forEach(el -> {
//              mds.addEntry((JsonObject) el)
//                .onFailure(Throwable::printStackTrace);
//            });
//        });
//    }
//  }
}
