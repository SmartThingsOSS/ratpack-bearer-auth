package st.ratpack.auth

import ratpack.exec.ExecResult
import ratpack.exec.Promise
import ratpack.test.exec.ExecHarness
import spock.lang.AutoCleanup
import spock.lang.Specification
import spock.util.concurrent.PollingConditions

import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class CachingTokenValidatorSpec extends Specification {

	@AutoCleanup
	ExecHarness harness = ExecHarness.harness()

	def "Caching validator only calls upstream once for a token"() {
		given:
		String token = "fakeToken"
		OAuthToken oAuthToken =
			new DefaultOAuthToken.Builder()
				.setAuthToken(token)
				.build()

		TokenValidator tokenValidator = Mock(TokenValidator)
		CachingTokenValidator cachingTokenValidator
		harness.run { exec ->
			cachingTokenValidator = new CachingTokenValidator(tokenValidator, 2, TimeUnit.SECONDS, false, exec.controller)
		}

		when: "Validating a token"
		ExecResult<Optional<OAuthToken>> result = harness.yield {
			cachingTokenValidator.validate(token)
		}

		then: "Calls upstream on a cache miss"
		1 * tokenValidator.validate(token) >> Promise.<Optional<OAuthToken>> value(Optional.<OAuthToken> of(oAuthToken))
		result.success
		result.value.isPresent()

		when: "A second validation call happens"
		result = harness.yield {
			cachingTokenValidator.validate(token)
		}

		then: "No More calls to upstream"
		0 * tokenValidator.validate(_)
		result.success
		result.value.isPresent()

		when: "validate after timeout"
		result = harness.yield {
			sleep(2000)
			cachingTokenValidator.validate(token)
		}

		then: "Call upstream again"
		1 * tokenValidator.validate(token) >> Promise.<Optional<OAuthToken>> value(Optional.<OAuthToken> of(oAuthToken))
		result.success
		result.value.isPresent()
	}

	def "Caching validator returns old value while refreshing"() {
		given:
		AtomicInteger counter = new AtomicInteger(0)
		String token = "fakeToken"

		TokenValidator tokenValidator = Mock()

		def conditions = new PollingConditions(timeout: 10)

		_ * tokenValidator.validate(token) >> { t ->
			int count = counter.incrementAndGet()
			if (count < 3) {
				Promise.value(Optional.of(
					new DefaultOAuthToken.Builder()
						.setAuthToken(token)
						.setAdditionalInformation([version: count])
						.build()))
			} else {
				Promise.value(Optional.empty())
			}
		}

		CachingTokenValidator cachingTokenValidator

		harness.run { exec ->
			cachingTokenValidator = new CachingTokenValidator(tokenValidator, 1, TimeUnit.SECONDS, true, exec.controller)
		}

		when: "Validating a token"
		ExecResult<Optional<OAuthToken>> result = harness.yield {
			cachingTokenValidator.validate(token)
		}

		then: "Calls upstream on a cache miss"
		conditions.eventually {
			counter.get() == 1
		}

		result.success
		result.value.isPresent()
		result.value.get().additionalInformation.version == 1

		when: "A second validation call happens"
		result = harness.yield {
			cachingTokenValidator.validate(token)
		}

		then: "No More calls to upstream"
		result.success
		result.value.isPresent()
		result.value.get().additionalInformation.version == 1

		sleep(1111) // wait for possible async call and timeout of cache
		counter.get() == 1 // still not called

		when: "validate after timeout"
		result = harness.yield {
			cachingTokenValidator.validate(token)
		}

		then: "Call upstream again but still present during refresh"
		result.success
		result.value.isPresent()
		result.value.get().additionalInformation.version == 1

		conditions.eventually { // the token should be fetched eventually
			counter.get() == 2
		}

		when: "the cache should now return the refreshed value"
		sleep(10) // wait just a bit after the increment for the promise to be put in the cache
		result = harness.yield {
			cachingTokenValidator.validate(token)
		}

		then:
		result.success
		result.value.isPresent()
		result.value.get().additionalInformation.version == 2
		sleep(1111) // wait for possible async call and timeout of cache
		counter.get() == 2 // still not called

		when: 'trigger another refresh'
		result = harness.yield {
			cachingTokenValidator.validate(token)
		}

		then: 'get the cached value while it is refreshed'
		result.success
		result.value.isPresent()
		result.value.get().additionalInformation.version == 2

		when: 'the cache is populated with an empty token and then is fetched'
		conditions.eventually { // the token should be fetched eventually
			counter.get() == 3
		}
		sleep(10) // wait just a bit after the increment for the promise to be put in the cache
		result = harness.yield {
			cachingTokenValidator.validate(token)
		}

		then: 'the result is now empty and an immediate call to refresh happens without waiting for the timeout'
		result.success
		!result.value.isPresent()

		conditions.eventually { // the token should be fetched eventually
			counter.get() == 4
		}
	}

}
