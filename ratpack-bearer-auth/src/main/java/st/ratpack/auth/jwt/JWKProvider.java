package st.ratpack.auth.jwt;

import com.nimbusds.jose.jwk.JWK;
import ratpack.service.Service;

import java.util.Optional;

public interface JWKProvider extends Service {
   Optional<JWK> getJWK(String kid);
}
