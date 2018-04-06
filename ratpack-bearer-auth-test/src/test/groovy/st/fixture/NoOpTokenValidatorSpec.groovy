package st.fixture

import ratpack.test.exec.ExecHarness
import spock.lang.AutoCleanup
import spock.lang.Specification
import spock.lang.Unroll
import st.ratpack.auth.OAuthToken
import st.ratpack.auth.TokenValidator
import st.ratpack.auth.ValidateTokenResult
import st.ratpack.auth.internal.DefaultOAuthToken

class NoOpTokenValidatorSpec extends Specification {

	@AutoCleanup
	ExecHarness harness = ExecHarness.harness()

	@Unroll
	def "it should provide a no-op validation test fixuture - token : #token, isUserToken: #isUserToken"() {
		given:
		TokenValidator validator = new NoOpTokenValidator()

		when:
		ValidateTokenResult result = harness.yield {
			return validator.validate(token)
		}.valueOrThrow

		then:
		result.isValid()
		with(result.getOAuthToken(), { OAuthToken token ->
			assert token.isUserToken() == isUserToken
		})

		where:
		token     | isUserToken
		'service' | false
		'blargh'  | true
	}

	@Unroll
	def "can provide custom additional info for mobile scoped tokens only - token : #token"() {
		given:
		TokenValidator validator = new NoOpTokenValidator(info)

		when:
		ValidateTokenResult result = harness.yield {
			return validator.validate(token)
		}.valueOrThrow

		then:
		result.isValid()
		with(result.getOAuthToken(), { OAuthToken token ->
			assert token.isUserToken() == isUserToken
			assert token.additionalInformation == expectedInfo
		})

		where:
		token     | isUserToken | info                                                  | expectedInfo
		'service' | false       | ['user_name': 'testUser', authorities: ['ROLE_TEST']] | [:]
		'blargh'  | true        | ['user_name': 'testUser', authorities: ['ROLE_TEST']] | ['user_name': 'testUser', authorities: ['ROLE_TEST']]
	}

	def "custom validation can be injected"() {
		given:
		TokenValidator validator = new NoOpTokenValidator({ token ->
			if (token.contains('test')) {
				OAuthToken oAuthToken = new DefaultOAuthToken.Builder()
						.setAuthToken("testtoken")
						.setClientId("test client")
						.setScope(['test'])
						.setAdditionalInformation(['user_name': 'testUser', authorities: ['ROLE_TEST']])
						.build()
				return ValidateTokenResult.valid(oAuthToken)
			}
			return ValidateTokenResult.INVALID_CASE
		})

		when:
		ValidateTokenResult result = harness.yield {
			return validator.validate(token)
		}.valueOrThrow

		then:
		assert result.status == status
		if (result.isValid()) {
			with(result.getOAuthToken(), { OAuthToken token ->
				assert token.isUserToken()
				assert token.value == "testtoken"
				assert token.clientId == "test client"
				assert token.scope.contains('test')
			})
		}

		where:
		token  | status
		'test' | ValidateTokenResult.Status.VALID
		'bad'  | ValidateTokenResult.Status.INVALID
	}
}
