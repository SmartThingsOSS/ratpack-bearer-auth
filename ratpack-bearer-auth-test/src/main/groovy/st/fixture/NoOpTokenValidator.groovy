package st.fixture

import ratpack.exec.Promise
import st.ratpack.auth.DefaultValidateTokenResult
import st.ratpack.auth.ValidateTokenResult
import st.ratpack.auth.internal.DefaultOAuthToken
import st.ratpack.auth.TokenValidator

/**
 * Used to circumvent token validation during testing.
 */
class NoOpTokenValidator implements TokenValidator {

	Map<String, Object> info

	/**
	 * Additional information for the validated tokens contain `user_name` and `authorities`
	 */
	NoOpTokenValidator() {
		info = ['user_name': 'fakeUser', authorities: ['ROLE_FAKE']]
	}

	/**
	 * Override the additional information placed into the validated tokens
	 *
	 * @param additionalInformation overrides the default
	 */
	NoOpTokenValidator(Map<String, Object> additionalInformation) {
		info = additionalInformation ?: [:]
	}

	@Override
	Promise<ValidateTokenResult> validate(String token) {
		if (token.contains("service")) {
			return Promise.value(ValidateTokenResult.valid(new DefaultOAuthToken('faketoken', 'fake client', ['service'] as Set<String>, [:])))
		}
		return Promise.value(ValidateTokenResult.valid(new DefaultOAuthToken('faketoken', 'fake client', ['mobile'] as Set<String>, info)))
	}
}
