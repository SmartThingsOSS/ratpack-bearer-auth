package st.ratpack.auth

import ratpack.exec.ExecResult
import ratpack.exec.Promise
import ratpack.test.exec.ExecHarness
import spock.lang.AutoCleanup
import spock.lang.Specification
import st.ratpack.auth.internal.DefaultOAuthToken

class CachingTokenValidatorSpec extends Specification {

	@AutoCleanup
	ExecHarness harness = ExecHarness.harness()

	def "Caching validator only calls upstream once for a token"() {
		given:
		String token = "fakeToken"
		OAuthToken oAuthToken =
				new DefaultOAuthToken.Builder()
					.setAuthToken(token)
					.build()

		TokenValidator tokenValidator = Mock(TokenValidator)
		CachingTokenValidator cachingTokenValidator
		harness.run {
			cachingTokenValidator = new CachingTokenValidator(tokenValidator)
		}

		when: "Validating a token"
		ExecResult<ValidateTokenResult> result = harness.yield {
			cachingTokenValidator.validate(token)
		}

		then: "Calls upstream on a cache miss"
		1 * tokenValidator.validate(token) >> Promise.<ValidateTokenResult> value(ValidateTokenResult.valid(oAuthToken))
		result.success
		result.value.isValid()

		when: "A second validation call happens"
		result = harness.yield {
			cachingTokenValidator.validate(token)
		}

		then: "No More calls to upstream"
		0 * _._
		result.success
		result.value.isValid()
	}

}
