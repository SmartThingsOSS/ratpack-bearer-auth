package st.ratpack.auth.jwt.impl;

import com.google.inject.Inject;
import com.nimbusds.jose.JWSAlgorithm;
import st.ratpack.auth.jwt.JWKProvider;
import st.ratpack.auth.jwt.JWTType;
import st.ratpack.auth.jwt.JWTVerifier;
import st.ratpack.auth.jwt.JWTVerifierFactory;
import st.ratpack.auth.jwt.impl.JWSVerifier;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class DefaultJWTVerifierFactory implements JWTVerifierFactory{
    private final JWKProvider jwkProvider;
    private final List<String> algorithms;

    public DefaultJWTVerifierFactory(JWKProvider jwkProvider, List<String> algorithms) {
        this.jwkProvider = jwkProvider;
        this.algorithms = algorithms;
    }

    public JWTVerifier getJWTVerifier(JWTType type) throws Exception {
        switch (type) {
            case JWS:
                if (jwkProvider == null) {
                    throw new Exception("JWKProvider is not provided when getting JWSVerifier");
                }
                Set<JWSAlgorithm> algos = new HashSet<>();
                if (algorithms != null) {
                    algos = algorithms.stream().map(JWSAlgorithm::parse).collect(Collectors.toSet());
                }
                return new JWSVerifier(jwkProvider, algos);
            case JWE:
                throw new Exception("not implemented");
            case PlainJWT:
                throw new Exception("not implemented");
            default:
                return null;
        }
    }
}
