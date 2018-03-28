package st.ratpack.auth

import ratpack.exec.ExecResult
import ratpack.exec.Promise
import ratpack.test.exec.ExecHarness
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll
import st.ratpack.auth.internal.DefaultOAuthToken

class CachingTokenValidatorSpec extends Specification {

	@AutoCleanup
	ExecHarness harness = ExecHarness.harness()
	TokenValidator tokenValidator = Mock()
	CachingTokenValidator cachingTokenValidator = new CachingTokenValidator(tokenValidator)
	@Shared
	ValidateTokenResult validTokenResult = ValidateTokenResult.valid(Mock(OAuthToken))

	def setup() {
		0 * _
	}

	def "Caching validator only calls upstream once for a token"() {
		given:
		String token = "fakeToken"
		OAuthToken oAuthToken =
				new DefaultOAuthToken.Builder()
						.setAuthToken(token)
						.build()

		when: "Validating a token"
		ExecResult<ValidateTokenResult> result = harness.yield {
			cachingTokenValidator.validate(token)
		}

		then: "Calls upstream on a cache miss"
		result.success
		result.value.isValid()

		and:
		1 * tokenValidator.validate(token) >> Promise.value(ValidateTokenResult.valid(oAuthToken))

		when: "A second validation call happens"
		result = harness.yield {
			cachingTokenValidator.validate(token)
		}

		then: "No More calls to upstream"
		result.success
		result.value.isValid()
	}


	@Unroll("error token results are not cached - #validateTokenResult.status")
	def 'error token results are not cached'() {
		given:
		String token = UUID.randomUUID().toString()

		when:
		ValidateTokenResult result = harness.yield {
			cachingTokenValidator.validate(token)
		}.valueOrThrow

		then:
		result == cachedResult

		and:
		tokenValidator.validate(token) >> Promise.value(validateTokenResult)

		where:
		validateTokenResult              | cachedResult
		ValidateTokenResult.INVALID_CASE | ValidateTokenResult.INVALID_CASE
		ValidateTokenResult.ERROR_CASE   | null
		validTokenResult                 | validTokenResult
	}
}
