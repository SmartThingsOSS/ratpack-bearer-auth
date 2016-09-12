package st.ratpack.auth

import io.netty.handler.codec.http.HttpHeaderNames
import ratpack.exec.Promise
import spock.lang.Specification
import spock.lang.Unroll
import st.ratpack.auth.handler.BearerTokenAuthHandler

import static ratpack.groovy.test.handling.GroovyRequestFixture.handle

class BearerTokenAuthHandlerSpec extends Specification {

	@Unroll
	def "401 on Bad Header #authHeader"() {
		when:
		def result = handle(new BearerTokenAuthHandler(Mock(TokenValidator))) {
			header(HttpHeaderNames.AUTHORIZATION.toString(), authHeader)
		}

		then:
		result.status.code == 401

		where:
		authHeader << [
			"",
			"Basic BLAH",
			"Bearer Token Something"
		]
	}

	def "Next handler on Valid token"() {
		given:
		def tokenValidator = Mock(TokenValidator)
		def oAuthToken = new DefaultOAuthToken.Builder().build();

		when:
		def result = handle(new BearerTokenAuthHandler(tokenValidator)) {
			header(HttpHeaderNames.AUTHORIZATION.toString(), "Bearer Token")
		}

		then:
		1 * tokenValidator.validate("Token") >> Promise.value(Optional.of(oAuthToken))
		result.calledNext
	}

	def "401 handler on invalid token"() {
		given:
		def tokenValidator = Mock(TokenValidator)

		when:
		def result = handle(new BearerTokenAuthHandler(tokenValidator)) {
			header(HttpHeaderNames.AUTHORIZATION.toString(), "Bearer Token")
		}

		then:
		1 * tokenValidator.validate("Token") >> Promise.value(Optional.empty())
		result.status.code == 401
	}
}
