package st.ratpack.auth

import io.netty.buffer.UnpooledByteBufAllocator
import ratpack.exec.ExecResult
import ratpack.http.client.HttpClient
import ratpack.test.embed.EmbeddedApp
import ratpack.test.exec.ExecHarness
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification
import st.fixture.SpringSecCheckTokenStub
import st.ratpack.auth.springsec.SpringSecCheckAuthModule
import st.ratpack.auth.springsec.SpringSecCheckTokenValidator

class SpringSecCheckTokenValidatorSpec extends Specification {

	@Shared
	EmbeddedApp springSec = SpringSecCheckTokenStub.stub

	@AutoCleanup
	ExecHarness harness = ExecHarness.harness()

	def "Check valid token"() {
		given:
		def conf = new SpringSecCheckAuthModule.Config(host: springSec.getAddress(), user: "fake", password: "pass")
		def httpClientToSpringSec
		TokenValidator tokenValidator
		harness.run {
			httpClientToSpringSec = HttpClient.httpClient(new UnpooledByteBufAllocator(false), 2000)
			tokenValidator = new SpringSecCheckTokenValidator(conf, httpClientToSpringSec)
		}

		when:
		ExecResult<Optional<OAuthToken>> result = harness.yield {
			return tokenValidator.validate("fakeToken")
		}

		then:
		result.getValueOrThrow().isPresent()
		with(result.getValueOrThrow().get()) { OAuthToken returnedToken ->
			returnedToken.clientId == 'clientapp'
			returnedToken.value == 'fakeToken'
			returnedToken.scope.contains("read")

			User user = new DefaultUser.Builder(returnedToken).build();
			user.userName == "beckje01"
			user.authorities.size() == 2
			user.authorities.contains('ROLE_CONSOLE')
			user.authorities.contains('ROLE_USER')
		}
	}

	def "Check invalid token"() {
		given:
		def conf = new SpringSecCheckAuthModule.Config(host: springSec.getAddress(), user: "fake", password: "pass")
		def httpClientToSpringSec
		TokenValidator tokenValidator
		harness.run {
			httpClientToSpringSec = HttpClient.httpClient(new UnpooledByteBufAllocator(false), 2000)
			tokenValidator = new SpringSecCheckTokenValidator(conf, httpClientToSpringSec)
		}

		when:
		ExecResult<Optional<OAuthToken>> result = harness.yield {
			return tokenValidator.validate("badToken")
		}

		then:
		!result.getValueOrThrow().isPresent()

	}
}
