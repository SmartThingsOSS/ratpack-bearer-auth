package st.fixture

import ratpack.exec.Promise
import st.ratpack.auth.DefaultOAuthToken
import st.ratpack.auth.OAuthToken
import st.ratpack.auth.TokenValidator
import st.ratpack.auth.DefaultUser

/**
 * Used to circumvent token validation during testing.
 */
class NoOpTokenValidator implements TokenValidator {

	@Override
	Promise<Optional<OAuthToken>> validate(String token) {
		if (token.contains("service")) {
			return Promise.value(Optional.of(new DefaultOAuthToken('faketoken', 'fake client', ['service'] as Set<String>, [:])))
		}
		def info = ['user_name': 'fakeUser', authorities: ['ROLE_FAKE']]
		return Promise.value(Optional.of(new DefaultOAuthToken('faketoken', 'fake client', ['mobile'] as Set<String>, info)))

	}
}
