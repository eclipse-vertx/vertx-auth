package io.vertx.ext.jwt;

public class JWTException extends IllegalStateException {
    public enum Reason {
        EXPIRED,
        JWK_HAS_NO_MATCHING_KID,
        INVALID_SIGNATURE
    }
    private Reason reason;
    public JWTException(String message) {
        this(null, message);
    }
    public JWTException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }
    public Reason getReason() {
        return reason;
    }
}
