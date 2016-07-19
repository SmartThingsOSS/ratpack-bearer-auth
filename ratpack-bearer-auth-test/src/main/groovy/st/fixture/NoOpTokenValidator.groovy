package st.fixture

import ratpack.exec.Promise
import st.ratpack.auth.OAuthToken
import st.ratpack.auth.TokenValidator
import st.ratpack.auth.User

/**
 * Used to circumvent token validation during testing.
 */
class NoOpTokenValidator implements TokenValidator {

	@Override
	Promise<Optional<OAuthToken>> validate(String token) {
		if (token.contains("service")) {
			return Promise.value(Optional.of(new OAuthToken(Optional.<User> empty(), ['service'] as Set<String>, 'fake client', 'faketoken')))
		}
		def user = Optional.of(new User("fakeUser", ["ROLE_FAKE"] as Set<String>))
		return Promise.value(Optional.of(new OAuthToken(user, ['mobile'] as Set<String>, 'fake client', 'faketoken')))
	}
}
