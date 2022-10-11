package st.ratpack.auth.handler

import io.netty.handler.codec.http.HttpHeaderNames
import ratpack.exec.Promise
import ratpack.handling.UserId
import spock.lang.Specification
import spock.lang.Unroll
import st.ratpack.auth.DefaultValidateTokenResult
import st.ratpack.auth.User
import st.ratpack.auth.ValidateTokenResult
import st.ratpack.auth.internal.DefaultOAuthToken
import st.ratpack.auth.OAuthToken
import st.ratpack.auth.TokenValidator

import static ratpack.groovy.test.handling.GroovyRequestFixture.handle

class BearerTokenAuthHandlerSpec extends Specification {

	def "Should set OAuthToken on valid token"() {
		given:
		def tokenValidator = Mock(TokenValidator)
		def oAuthToken = new DefaultOAuthToken.Builder().setAdditionalInformation([
				"user_name": "kenny.powers@smartthings.com",
				"uuid"     : UUID.randomUUID().toString()
		]) build()

		when:
		def result = handle(new BearerTokenAuthHandler(tokenValidator)) {
			header(HttpHeaderNames.AUTHORIZATION.toString(), "Bearer Token")
		}

		then:
		1 * tokenValidator.validate("Token") >> Promise.value(ValidateTokenResult.valid(oAuthToken))
		result.getRegistry().maybeGet(OAuthToken).present
		result.getRegistry().maybeGet(ValidateTokenResult).present
		result.getRegistry().maybeGet(User).present
		result.getRegistry().maybeGet(UserId).present
		result.calledNext
	}

	@Unroll
	def "Should not set OAuthToken on bad header: #authHeader"() {
		when:
		def result = handle(new BearerTokenAuthHandler(Mock(TokenValidator))) {
			header(HttpHeaderNames.AUTHORIZATION.toString(), authHeader)
		}

		then:
		!result.getRegistry().maybeGet(OAuthToken).present
		!result.getRegistry().maybeGet(ValidateTokenResult).present
		result.calledNext

		where:
		authHeader << [
				"",
				"Basic BLAH",
				"Bearer Token Something"
		]
	}

	def "Should not set OAuthToken on invalid token"() {
		given:
		def tokenValidator = Mock(TokenValidator)

		when:
		def result = handle(new BearerTokenAuthHandler(tokenValidator)) {
			header(HttpHeaderNames.AUTHORIZATION.toString(), "Bearer Token")
		}

		then:
		1 * tokenValidator.validate("Token") >> Promise.value(ValidateTokenResult.INVALID_CASE)

		!result.getRegistry().maybeGet(OAuthToken).present
		result.getRegistry().maybeGet(ValidateTokenResult).present
		result.calledNext
	}
}
