package st.ratpack.auth

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.datatype.guava.GuavaModule
import com.fasterxml.jackson.datatype.jdk7.Jdk7Module
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module
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
			tokenValidator = new SpringSecCheckTokenValidator(conf, httpClientToSpringSec, getDefaultJackson())
		}

		when:
		ExecResult<Optional<OAuthToken>> result = harness.yield {
			return tokenValidator.validate("fakeToken")
		}

		then:
		result.getValueOrThrow().isPresent()
		with(result.getValueOrThrow().get()) { OAuthToken returnedToken ->
			returnedToken.user.get().username == "beckje01"
			returnedToken.scopes.contains("read")
			returnedToken.clientId == 'clientapp'
			returnedToken.authToken == 'fakeToken'
		}

	}

	def "Check invalid token"() {
		given:
		def conf = new SpringSecCheckAuthModule.Config(host: springSec.getAddress(), user: "fake", password: "pass")
		def httpClientToSpringSec
		TokenValidator tokenValidator
		harness.run {
			httpClientToSpringSec = HttpClient.httpClient(new UnpooledByteBufAllocator(false), 2000)
			tokenValidator = new SpringSecCheckTokenValidator(conf, httpClientToSpringSec, getDefaultJackson())
		}

		when:
		ExecResult<Optional<User>> result = harness.yield {
			return tokenValidator.validate("badToken")
		}

		then:
		!result.getValueOrThrow().isPresent()

	}

	private static ObjectMapper getDefaultJackson() {
		ObjectMapper objectMapper = new ObjectMapper();
		objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
		objectMapper.registerModule(new Jdk7Module());
		objectMapper.registerModule(new Jdk8Module());
		objectMapper.registerModule(new GuavaModule());
		JsonFactory factory = objectMapper.getFactory();
		factory.enable(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES);
		factory.enable(JsonParser.Feature.ALLOW_SINGLE_QUOTES);

		return objectMapper;
	}
}
