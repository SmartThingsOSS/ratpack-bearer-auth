package st.ratpack.auth.springsec

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder
import com.github.tomakehurst.wiremock.http.Fault
import io.netty.channel.ConnectTimeoutException
import io.netty.handler.codec.PrematureChannelClosureException
import ratpack.exec.Promise
import ratpack.http.client.HttpClient
import ratpack.http.client.HttpClientReadTimeoutException
import ratpack.http.client.internal.DefaultHttpClient
import ratpack.test.exec.ExecHarness
import spock.lang.Shared
import spock.lang.Specification

import javax.net.ssl.SSLException
import java.time.Duration
import java.time.Instant

import static com.github.tomakehurst.wiremock.client.WireMock.*

class SpringSecCheckTokenProviderSpec extends Specification {

	@Shared
	int authServicePort = 10111

	@Shared
	WireMockServer authService

	@Shared
	String authHost = "http://localhost:" + authServicePort

	@Shared
	HttpClient httpClient = DefaultHttpClient.of({
		it.readTimeout(Duration.ofMillis(1000))
	})

	@Shared
	def conf = new SpringSecCheckAuthModule.Config(host: new URI(authHost), user: "fake", password: "pass")

	@Shared
	ExecHarness harness = ExecHarness.harness()

	def setup() {
		authService.resetAll()
	}

	def setupSpec() {
		authService = new WireMockServer(authServicePort)
		authService.start()
	}

	def 'test socket issue retries'() {
		given:
		SpringSecCheckTokenProvider provider = new SpringSecCheckTokenProvider(httpClient, conf)
		addCheckTokenMapping(aResponse()
			.withFault(Fault.RANDOM_DATA_THEN_CLOSE)
			.withStatus(500))

		when: 'we attempt a check token call which results in a premature socket closure'
		Instant beforeRetries = Instant.now()
		harness.yield {
			provider.checkToken("blahblah")
		}.getValueOrThrow()


		then: 'we attempt 2 retries'
		Instant postRetries = Instant.now()
		Duration.between(beforeRetries, postRetries) > Duration.ofMillis(600)
		//the calling code of this provider expects the error to be thrown
		thrown PrematureChannelClosureException
		verifyNoMissingStubs()
		verifyCount(3)

		cleanup:
		authService.resetAll()
	}

	def 'successful check token request'() {

		given:
		HttpClient shortTimeoutClient = DefaultHttpClient.of({spec -> spec.readTimeout(Duration.ofMillis(500))})
		SpringSecCheckTokenProvider provider = new SpringSecCheckTokenProvider(shortTimeoutClient, conf)

		addCheckTokenMapping(aResponse()
			.withFixedDelay(100)
			.withStatus(200))

		when: 'we attempt a check token call which results in a premature socket closure'
		harness.yield {
			provider.checkToken("blahblah")
		}.getValueOrThrow()

		then: 'single attempt to check token'
		verifyCount(1)
		verifyNoMissingStubs()

		cleanup:
		authService.resetAll()
	}

	def 'read timeout check'() {

		given:
		HttpClient shortTimeoutClient = DefaultHttpClient.of({spec -> spec.readTimeout(Duration.ofMillis(500))})
		SpringSecCheckTokenProvider provider = new SpringSecCheckTokenProvider(shortTimeoutClient, conf)

		addCheckTokenMapping(aResponse()
			.withFixedDelay(2000)
			.withStatus(200))

		when: 'we attempt a check token call which results in a premature socket closure'
		harness.yield {
			provider.checkToken("blahblah")
		}.getValueOrThrow()

		then: 'single attempt to check token on read timeout'
		verifyCount(1)
		verifyNoMissingStubs()
		thrown HttpClientReadTimeoutException

		cleanup:
		authService.resetAll()

	}

	//interaction tests
	def 'exercise additional retried error types'() {

		setup:
		Promise errorp = Promise.error(error)
		Promise errorPromise = Spy(errorp)
		HttpClient spyClient = Spy(httpClient)
		SpringSecCheckTokenProvider provider = new SpringSecCheckTokenProvider(spyClient, conf)

		when:
		harness.yield {
			provider.checkToken("blahblah")
		}.getValueOrThrow()

		then:
		0 * _
		thrown errorClass
		1 * spyClient.post(*_) >> { return errorPromise }
		1 * errorPromise.retry(*_) >> errorp

		where:
		error                                                     		 | errorClass
		new SSLException("SSL Engine is already closed")          		 | SSLException
		new SocketException("bad socket")                         		 | SocketException
		new PrematureChannelClosureException("premature closure") 		 | PrematureChannelClosureException
		new ConnectTimeoutException("premature closure")          		 | ConnectTimeoutException

	}

	//utility methods

	void verifyNoMissingStubs() {
		assert !authService.findUnmatchedRequests().requests
	}

	void addCheckTokenMapping(ResponseDefinitionBuilder response) {
		authService.addStubMapping(
			post(urlPathEqualTo("/oauth/check_token"))
				.willReturn(response)
				.build())
	}

	void verifyCount(int count) {
		authService.verify(count, postRequestedFor(urlPathEqualTo("/oauth/check_token")))
	}


}
