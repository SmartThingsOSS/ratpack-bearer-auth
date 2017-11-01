package st.ratpack.auth.jwt.impl;

public class JWEVerifier extends AbstractJWTVerifier {

    @Override
    public boolean mayBeJWTToken(String token) {
        return false;
    }

    @Override
    public boolean verify(String token) { return false;}
}
