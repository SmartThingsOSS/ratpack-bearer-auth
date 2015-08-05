package st.ratpack.auth

import io.netty.handler.codec.http.HttpHeaderNames
import ratpack.test.exec.ExecHarness
import spock.lang.Specification
import spock.lang.Unroll

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
			null,
			"",
			"Basic BLAH",
			"Bearer Token Something"
		]
	}

	def "Next handler on Valid token"() {
		given:
		def tokenValidator = Mock(TokenValidator)
		def harness = ExecHarness.harness()

		when:
		def result = handle(new BearerTokenAuthHandler(tokenValidator)) {
			header(HttpHeaderNames.AUTHORIZATION.toString(), "Bearer Token")
		}

		then:
		1 * tokenValidator.validate("Token") >> harness.promiseOf(Optional.of(Mock(User)))
		result.calledNext
	}

	def "401 handler on invalid token"() {
		given:
		def tokenValidator = Mock(TokenValidator)
		def harness = ExecHarness.harness()


		when:
		def result = handle(new BearerTokenAuthHandler(tokenValidator)) {
			header(HttpHeaderNames.AUTHORIZATION.toString(), "Bearer Token")
		}

		then:
		1 * tokenValidator.validate("Token") >> harness.promiseOf(Optional.empty())
		result.status.code == 401
	}
}
