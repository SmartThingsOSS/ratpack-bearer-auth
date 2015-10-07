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
		def httpClientToSpringSec
		SpringSecCheckTokenValidator tokenValidator
		harness.run {
			httpClientToSpringSec = HttpClient.httpClient(new UnpooledByteBufAllocator(false), 2000)
			tokenValidator = new SpringSecCheckTokenValidator(conf, httpClientToSpringSec, getDefaultJackson())
		}

		when:
		ExecResult<Optional<OAuthToken>> result = harness.yield {
			return tokenValidator.validate("fakeToken")
		}

		then:
		def optional = result.getValueOrThrow()
		optional.isPresent()
		with(optional.get()) { OAuthToken returnedToken ->
			returnedToken.user.get().username == "beckje01"
			returnedToken.scopes.contains("read")
			returnedToken.clientId == 'clientapp'
			tokenValidator.cache.asMap() == [fakeToken: returnedToken]
		}

		when: 'a second request is made'
		ExecResult<Optional<OAuthToken>> result2 = harness.yield {
			return tokenValidator.validate("fakeToken")
		}

		then: 'the cached result is returned'
		result2.getValueOrThrow().get().is(optional.get())

		when: 'the ttl expires'
		sleep(SpringSecCheckTokenValidator.DEFAULT_TTL)
		tokenValidator.cache.cleanUp() //make sure to evict expired values

		then: 'the cache is empty'
		tokenValidator.cache.size() == 0

	}

	def "Check invalid token"() {
		given:
		def conf = new AuthModule.Config(host: springSec.getAddress(), user: "fake", password: "pass")
		def httpClientToSpringSec
		SpringSecCheckTokenValidator tokenValidator
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
		tokenValidator.cache.size() == 0 //nothing cached

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
