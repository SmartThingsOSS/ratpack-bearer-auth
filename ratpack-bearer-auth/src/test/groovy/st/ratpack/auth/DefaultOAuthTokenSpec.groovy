package st.ratpack.auth

import spock.lang.Specification
import st.ratpack.auth.internal.DefaultOAuthToken

class DefaultOAuthTokenSpec extends Specification {

	void 'it should build a valid token from a constructor'() {
		given:
		Set scopes = ['mobile'] as Set
		String clientId = 'clientId'
		String authToken = 'authToken'
		Map<String, Object> additionalInfo = [:]

		when:
		OAuthToken token = new DefaultOAuthToken(authToken, clientId, scopes, additionalInfo)

		then:
		assert token.clientId == clientId
		assert token.value == authToken
		assert token.scope == scopes
		assert token.additionalInformation == additionalInfo
	}

	void 'it should build a valid token from a builder'() {
		given:
		Set scopes = ['mobile'] as Set
		String clientId = 'clientId'
		String authToken = 'authToken'
		Map<String, Object> additionalInfo = [:]

		when:
		OAuthToken token =
				new DefaultOAuthToken.Builder()
					.setAuthToken(authToken)
					.setClientId(clientId)
					.setScope(scopes)
					.setAdditionalInformation(additionalInfo)
					.build()

		then:
		assert token.clientId == clientId
		assert token.value == authToken
		assert token.scope == scopes
		assert token.additionalInformation == additionalInfo
		assert !token.isUserToken()
	}

	void 'it should build a valid token from another token'() {
		given:
		Set scopes = ['mobile'] as Set
		String clientId = 'clientId'
		String authToken = 'authToken'
		Map<String, Object> additionalInfo = [:]

		OAuthToken token =
				new DefaultOAuthToken.Builder()
						.setAuthToken(authToken)
						.setClientId(clientId)
						.setScope(scopes)
						.setAdditionalInformation(additionalInfo)
						.build()

		when:
		OAuthToken result = new DefaultOAuthToken.Builder(token).build()

		then:
		assert token.clientId == result.clientId
		assert token.value == result.value
		assert token.scope == result.scope
		assert token.additionalInformation == result.additionalInformation
		assert !token.isUserToken()
	}

	void 'it should build a valid user token from another token'() {
		given:
		Set scopes = ['mobile'] as Set
		String clientId = 'clientId'
		String authToken = 'authToken'
		Map<String, Object> additionalInfo = ['user_name': 'batman']

		OAuthToken token =
				new DefaultOAuthToken.Builder()
						.setAuthToken(authToken)
						.setClientId(clientId)
						.setScope(scopes)
						.setAdditionalInformation(additionalInfo)
						.build()

		when:
		OAuthToken result = new DefaultOAuthToken.Builder(token).build()

		then:
		assert token.clientId == result.clientId
		assert token.value == result.value
		assert token.scope == result.scope
		assert token.additionalInformation == result.additionalInformation
		assert token.isUserToken()
	}
}
