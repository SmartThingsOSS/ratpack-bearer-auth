package st.ratpack.auth.jwt;

import java.util.List;


public interface JWTVerifierFactory {
    public JWTVerifier getJWTVerifier(JWTType type) throws Exception;
}
