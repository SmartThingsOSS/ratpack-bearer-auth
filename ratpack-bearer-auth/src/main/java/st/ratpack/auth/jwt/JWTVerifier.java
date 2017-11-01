package st.ratpack.auth.jwt;

public interface JWTVerifier {
    boolean mayBeJWTToken(String token);

    boolean verify(String token);
}
