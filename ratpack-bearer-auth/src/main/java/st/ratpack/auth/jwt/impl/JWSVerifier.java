package st.ratpack.auth.jwt.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.proc.JWSVerifierFactory;
import com.nimbusds.jwt.SignedJWT;
import st.ratpack.auth.jwt.JWKProvider;

import java.security.Key;
import java.util.Optional;
import java.util.Set;

public class JWSVerifier extends AbstractJWTVerifier {
    private final JWKProvider jwkProvider;
    private final Set<JWSAlgorithm> enforcedAlgorithms;
    private final JWSVerifierFactory jwsVerifierFactory;
    private static final String REGEX = "^[a-zA-Z0-9\\-_]+?\\.[a-zA-Z0-9\\-_]+?\\.([a-zA-Z0-9\\-_]+)?$";

    public JWSVerifier(JWKProvider jwkProvider, Set<JWSAlgorithm> enforcedAlgorithms) {
        this.jwkProvider = jwkProvider;
        this.enforcedAlgorithms = enforcedAlgorithms;
        this.jwsVerifierFactory = new DefaultJWSVerifierFactory();
    }


    @Override
    public boolean mayBeJWTToken(String token) {
        return token != null && token.matches(REGEX);
    }

    @Override
    public boolean verify(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            return verifyJwtSignature(signedJWT) && verifyJwtExp(signedJWT);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean verifyJwtSignature(SignedJWT signedJWT) throws Exception {
        String keyId = signedJWT.getHeader().getKeyID();
        if (enforcedAlgorithms != null &&
            enforcedAlgorithms.size() > 0 &&
            !enforcedAlgorithms.contains(signedJWT.getHeader().getAlgorithm())) {
            return false;
        }
        Optional<JWK> jwk = jwkProvider.getJWK(keyId);
        if (!jwk.isPresent()) {
            return false;
        }

        Key key = getJWKKey(jwk.get());
        if (key == null) {
            return false;
        }
        com.nimbusds.jose.JWSVerifier verifier = jwsVerifierFactory.createJWSVerifier(signedJWT.getHeader(), key);
        if (verifier == null) {
            return false;
        }
        return 	jwk.isPresent() && signedJWT.verify(verifier);
    }

    private Key getJWKKey(JWK jwk) {
        try {
            if (jwk instanceof AssymetricJWK) {
                return ((AssymetricJWK) jwk).toPublicKey();
            } else if (jwk instanceof SecretJWK) {
                return ((SecretJWK) jwk).toSecretKey();
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }
}
