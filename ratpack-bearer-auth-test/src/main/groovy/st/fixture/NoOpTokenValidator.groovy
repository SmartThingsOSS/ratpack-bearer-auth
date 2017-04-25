package st.fixture

import ratpack.exec.Promise
import st.ratpack.auth.DefaultOAuthToken
import st.ratpack.auth.OAuthToken
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
	Promise<Optional<OAuthToken>> validate(String token) {
		if (token.contains("service")) {
			return Promise.value(Optional.of(new DefaultOAuthToken('faketoken', 'fake client', ['service'] as Set<String>, [:])))
		}
		return Promise.value(Optional.of(new DefaultOAuthToken('faketoken', 'fake client', ['mobile'] as Set<String>, info)))
	}
}
