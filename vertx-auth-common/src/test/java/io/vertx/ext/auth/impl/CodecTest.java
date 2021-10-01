package io.vertx.ext.auth.impl;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

public class CodecTest {

  @Test
  public void testBase32() {
    String source = "The quick brown fox jumps over the lazy dog.";

    assertEquals(
      "KRUGKIDROVUWG2ZAMJZG653OEBTG66BANJ2W24DTEBXXMZLSEB2GQZJANRQXU6JAMRXWOLQ",
      Codec.base32Encode(source.getBytes(StandardCharsets.UTF_8))
    );
  }

  @Test
  public void testBase16() {
    byte[] source = "The quick brown fox jumps over the lazy dog.".getBytes(StandardCharsets.UTF_8);

    assertArrayEquals(
      source,
      Codec.base16Decode(Codec.base16Encode(source))
    );
  }
}
