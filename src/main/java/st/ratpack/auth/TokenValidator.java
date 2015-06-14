package st.ratpack.auth;

import ratpack.exec.Promise;

public interface TokenValidator {

	Promise<Boolean> validate(String token);

}
