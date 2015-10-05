package st.ratpack.auth

import ratpack.exec.Promise
import spock.lang.Specification

class CachingTokenValidatorSpec extends Specification {

	long ttl = 500
	TokenValidator validator = Mock()

	def cachingValidator = new CachingTokenValidator(ttl, validator)

	def 'cached token validator returns same result for ttl'() {
		given:
		String token = 'token'

		when:
		def result1 = cachingValidator.validate(token)
		long expire = System.currentTimeMillis() + ttl

		then: 'the token is validated'
		1 * validator.validate(token) >> { Promise.value(Optional.of(new OAuthToken())) }

		when: 'validations happen until before the expiration'
		def results = []
		while (expire > System.currentTimeMillis() + 50) { //50ms to complete
			results << cachingValidator.validate(token)
		}

		then: 'the cached results are returned'
		results != []
		0 * validator._
		results.every { it.is result1 }

		when: 'wait until expiration time has passed since first request'
		while (expire > System.currentTimeMillis()); //busy
		def result2 = cachingValidator.validate(token)

		then: 'validation happens again'
		1 * validator.validate(token) >> { Promise.value(Optional.of(new OAuthToken())) }
		result2.is(result1) == false
	}
}
