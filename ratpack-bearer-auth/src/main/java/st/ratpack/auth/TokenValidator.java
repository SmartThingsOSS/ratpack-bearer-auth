package st.ratpack.auth;

import ratpack.exec.Promise;

import java.util.Optional;

public interface TokenValidator {

	Promise<ValidateTokenResult> validate(String token);

}
