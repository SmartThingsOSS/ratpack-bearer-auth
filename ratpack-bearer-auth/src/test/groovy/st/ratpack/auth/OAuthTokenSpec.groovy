package st.ratpack.auth

import spock.lang.Specification

class OAuthTokenSpec extends Specification {

	def 'OAuthToken constructor builds valid OAuthToken'() {
		given:
		Optional<User> user = Optional.of(new User())
		Set scopes = ['mobile'] as Set
		String clientId = 'clientId'
		String authToken = 'authToken'

		when:
		OAuthToken token = new OAuthToken(user, scopes, clientId, authToken)

		then:
		assert token.user == user
		assert token.scopes == scopes
		assert token.clientId == clientId
		assert token.authToken == authToken
	}
}
