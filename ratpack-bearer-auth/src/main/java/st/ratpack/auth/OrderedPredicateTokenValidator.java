package st.ratpack.auth;

import ratpack.exec.Promise;

import java.util.List;
import java.util.Optional;

public class OrderedPredicateTokenValidator implements TokenValidator {


	private List<PredicateValidatorTuple> predicateValidatorTuples;

	OrderedPredicateTokenValidator(List<PredicateValidatorTuple> predicateValidatorTuples) {
		this.predicateValidatorTuples = predicateValidatorTuples;
	}


	@Override
	public Promise<Optional<OAuthToken>> validate(String token) {
		for (PredicateValidatorTuple predicateValidator : predicateValidatorTuples) {
			if (predicateValidator.canValidate(token)) {
				return predicateValidator.getTokenValidator().validate(token);
			}
		}

		return Promise.value(Optional.empty());
	}
}
