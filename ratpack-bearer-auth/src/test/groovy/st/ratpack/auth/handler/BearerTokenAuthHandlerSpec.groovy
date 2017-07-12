package st.ratpack.auth.handler

import io.netty.handler.codec.http.HttpHeaderNames
import ratpack.exec.Promise
import spock.lang.Specification
import spock.lang.Unroll
import st.ratpack.auth.DefaultOAuthToken
import st.ratpack.auth.OAuthToken
import st.ratpack.auth.TokenValidator

import static ratpack.groovy.test.handling.GroovyRequestFixture.handle

class BearerTokenAuthHandlerSpec extends Specification {

	def "Should set OAuthToken on valid token"() {
		given:
		def tokenValidator = Mock(TokenValidator)
		def oAuthToken = new DefaultOAuthToken.Builder().build();

		when:
		def result = handle(new BearerTokenAuthHandler(tokenValidator)) {
			header(HttpHeaderNames.AUTHORIZATION.toString(), "Bearer Token")
		}

		then:
		1 * tokenValidator.validate("Token") >> Promise.value(Optional.of(oAuthToken))
		result.getRegistry().maybeGet(OAuthToken).present
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
		1 * tokenValidator.validate("Token") >> Promise.value(Optional.empty())

		!result.getRegistry().maybeGet(OAuthToken).present
		result.calledNext
	}
}
