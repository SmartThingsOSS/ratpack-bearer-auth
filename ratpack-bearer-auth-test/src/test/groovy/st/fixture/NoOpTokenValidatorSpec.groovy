package st.fixture

import ratpack.exec.ExecResult
import ratpack.test.exec.ExecHarness
import spock.lang.AutoCleanup
import spock.lang.Specification
import spock.lang.Unroll
import st.ratpack.auth.OAuthToken
import st.ratpack.auth.TokenValidator
import st.ratpack.auth.ValidateTokenResult

class NoOpTokenValidatorSpec extends Specification {

	@AutoCleanup
	ExecHarness harness = ExecHarness.harness()

	@Unroll
	void "it should provide a no-op validation test fixuture [ token : #token, isUserToken: #isUserToken"() {
		given:
		TokenValidator validator = new NoOpTokenValidator()

		when:
		ExecResult<ValidateTokenResult> result = harness.yield {
			return validator.validate(token)
		}

		then:
		assert result.getValueOrThrow().isValid()
		with(result.getValueOrThrow().getOAuthToken(), { OAuthToken token ->
		    assert token.isUserToken() == isUserToken
		})

		where:
		token          |  isUserToken
		'service'      |  false
		'service:gdpr' |  false
		'gdpr'         |  true
		'blargh'       |  true
	}
}
