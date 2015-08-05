package st.ratpack.auth

import io.netty.buffer.UnpooledByteBufAllocator
import ratpack.exec.ExecControl
import ratpack.exec.ExecResult
import ratpack.http.client.HttpClient
import ratpack.test.embed.EmbeddedApp
import ratpack.test.exec.ExecHarness
import spock.lang.Shared
import spock.lang.Specification
import st.fixture.SpringSecCheckTokenStub

class SpringSecCheckTokenValidatorSpec extends Specification {

	@Shared
	EmbeddedApp springSec = SpringSecCheckTokenStub.stub

	ExecHarness harness

	def setup() {
		harness = ExecHarness.harness()
	}

	def cleanup() {
		harness.close()
	}

	def "Check valid token"() {
		given:
		def conf = new AuthModule.Config(host: springSec.getAddress(), user: "fake", password: "pass")
		ExecControl execControl
		def httpClientToSpringSec
		TokenValidator tokenValidator
		harness.run {
			execControl = ExecHarness.execControl()
			httpClientToSpringSec = HttpClient.httpClient(execControl.getController(), new UnpooledByteBufAllocator(false), 2000)
			tokenValidator = new SpringSecCheckTokenValidator(conf, httpClientToSpringSec, execControl)
		}

		when:
		ExecResult<Optional<User>> result = harness.yield {
			return tokenValidator.validate("fakeToken")
		}

		then:
		result.getValueOrThrow().isPresent()
		result.getValueOrThrow().get().username == "beckje01"

	}

	def "Check invalid token"() {
		given:
		def conf = new AuthModule.Config(host: springSec.getAddress(), user: "fake", password: "pass")
		ExecControl execControl
		def httpClientToSpringSec
		TokenValidator tokenValidator
		harness.run {
			execControl = ExecHarness.execControl()
			httpClientToSpringSec = HttpClient.httpClient(execControl.getController(), new UnpooledByteBufAllocator(false), 2000)
			tokenValidator = new SpringSecCheckTokenValidator(conf, httpClientToSpringSec, execControl)
		}

		when:
		ExecResult<Optional<User>> result = harness.yield {
			return tokenValidator.validate("badToken")
		}

		then:
		!result.getValueOrThrow().isPresent()

	}
}
