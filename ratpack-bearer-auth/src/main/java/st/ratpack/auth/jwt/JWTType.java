package st.ratpack.auth.jwt;

public enum JWTType {
    JWE("JWE"), JWS("JWS"), PlainJWT("PlainJWT");

    private String type;

    JWTType(String type) {
        this.type = type;
    }

    String getName() {
        return this.type;
    }
}
