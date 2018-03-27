package st.ratpack.auth

import spock.lang.Specification
import st.ratpack.auth.internal.DefaultOAuthToken
import st.ratpack.auth.internal.DefaultUser

class DefaultUserSpec extends Specification {

	void 'it should build a user from a constructor'() {
		given:
		String username = 'batman'
		Set<String> authorities = ['ROLE_USER']
		Map<String, Object> additionalInfo = [:]

		when:
		User user = new DefaultUser(username, authorities, additionalInfo)

		then:
		assert user.userName == username
		assert user.authorities == authorities
		assert user.additionalInformation == additionalInfo
	}

	void 'it should build a user from a builder'() {
		given:
		String username = 'batman'
		Set<String> authorities = ['ROLE_USER']
		Map<String, Object> additionalInfo = [:]

		when:
		User user =
			new DefaultUser.Builder()
				.setUserName(username)
				.setAuthorities(authorities)
				.setAdditionalInformation(additionalInfo)
				.build()

		then:
		assert user.userName == username
		assert user.authorities == authorities
		assert user.additionalInformation == additionalInfo
	}

	void 'it should build a user from another user'() {
		given:
		String username = 'batman'
		Set<String> authorities = ['ROLE_USER']
		Map<String, Object> additionalInfo = [:]
		User user =
			new DefaultUser.Builder()
				.setUserName(username)
				.setAuthorities(authorities)
				.setAdditionalInformation(additionalInfo)
				.build()

		when:
		User result = new DefaultUser.Builder(user).build()

		then:
		assert user.userName == result.userName
		assert user.authorities == result.authorities
		assert user.additionalInformation == result.additionalInformation
	}

	void 'it should build a user from a user oauth token'() {
		given:
		String username = 'batman'
		Set<String> authorities = ['ROLE_USER']
		Set scopes = ['mobile'] as Set
		String clientId = 'clientId'
		String authToken = 'authToken'
		Map<String, Object> additionalInfo = [
			'user_name': username,
			'authorities': authorities
		]

		OAuthToken token =
				new DefaultOAuthToken.Builder()
						.setAuthToken(authToken)
						.setClientId(clientId)
						.setScope(scopes)
						.setAdditionalInformation(additionalInfo)
						.build()

		when:
		User user = new DefaultUser.Builder(token).build()

		then:
		assert user.userName == username
		assert user.authorities == authorities
		assert user.additionalInformation == additionalInfo
	}

	void 'it should build a user from a user oauth token when authorities are null'() {
		given:
		String username = 'batman'
		Set<String> authorities = null
		Set scopes = ['mobile'] as Set
		String clientId = 'clientId'
		String authToken = 'authToken'
		Map<String, Object> additionalInfo = [
			'user_name': username,
			'authorities': authorities
		]

		OAuthToken token =
				new DefaultOAuthToken.Builder()
						.setAuthToken(authToken)
						.setClientId(clientId)
						.setScope(scopes)
						.setAdditionalInformation(additionalInfo)
						.build()

		when:
		User user = new DefaultUser.Builder(token).build()

		then:
		assert user.userName == username
		assert user.authorities.size() == 0
		assert user.additionalInformation == additionalInfo
	}

}
