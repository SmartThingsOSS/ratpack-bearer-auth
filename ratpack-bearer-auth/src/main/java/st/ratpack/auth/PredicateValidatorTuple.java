package st.ratpack.auth;

import ratpack.exec.Promise;

import java.util.Optional;
import java.util.function.Predicate;

public class PredicateValidatorTuple {
	private Predicate<String> predicate;
	private TokenValidator tokenValidator;

	public PredicateValidatorTuple(Predicate<String> predicate, TokenValidator tokenValidator) {
		this.predicate = predicate;
		this.tokenValidator = tokenValidator;
	}

	public Predicate<String> getPredicate() {
		return predicate;
	}

	public TokenValidator getTokenValidator() {
		return tokenValidator;
	}

	public boolean canValidate(String token) {
		return predicate.test(token);
	}

}
