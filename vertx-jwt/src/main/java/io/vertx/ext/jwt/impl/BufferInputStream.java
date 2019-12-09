package io.vertx.ext.jwt.impl;

import io.vertx.core.buffer.Buffer;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

public class BufferInputStream extends InputStream {
  private final Buffer buffer;
  private int pos = 0;

  public BufferInputStream(Buffer buffer) {
    this.buffer = buffer;
  }

  @Override
  public int read() throws IOException {
    if (pos == buffer.length()) {
      throw new EOFException();
    }
    return buffer.getByte(pos++);
  }
}
