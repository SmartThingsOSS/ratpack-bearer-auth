package st.ratpack.auth

import ratpack.exec.Promise
import ratpack.test.exec.ExecHarness
import spock.lang.AutoCleanup
import spock.lang.Specification
import st.ratpack.auth.internal.DefaultOAuthToken

class OrderedPredicateTokenValidatorSpec extends Specification {

	@AutoCleanup
	ExecHarness execHarness = ExecHarness.harness()

	def "Use first matching Predicate"() {
		given:
		TokenValidator mockValidator1 = Mock(TokenValidator)
		TokenValidator mockValidator2 = Mock(TokenValidator)
		OAuthToken token = new DefaultOAuthToken('authToken', 'clientId', [] as Set, [
				fullName   : 'Darth Vader',
				user_name  : 'darth',
				authorities: ['admin', 'test']
		]);


		and:
		TokenValidator tokenValidator = new OrderedPredicateTokenValidator([new PredicateValidatorTuple({ String x -> x.size() > 0 }, mockValidator1), new PredicateValidatorTuple({ String x -> x != "" }, mockValidator2)])

		when:
		def result = execHarness.yield({
			tokenValidator.validate("token")
		})

		then:
		result.valueOrThrow.get() == token

		and:
		1 * mockValidator1.validate("token") >> Promise.value(Optional.of(token))
		0 * _
	}

	def "Use second matching Predicate"() {
		given:
		TokenValidator mockValidator1 = Mock(TokenValidator)
		TokenValidator mockValidator2 = Mock(TokenValidator)
		OAuthToken token = new DefaultOAuthToken('authToken', 'clientId', [] as Set, [
				fullName   : 'Darth Vader',
				user_name  : 'darth',
				authorities: ['admin', 'test']
		]);


		and:
		TokenValidator tokenValidator = new OrderedPredicateTokenValidator([new PredicateValidatorTuple({ String x -> x.size() > 100 }, mockValidator1), new PredicateValidatorTuple({ String x -> x != "" }, mockValidator2)])

		when:
		def result = execHarness.yield({
			tokenValidator.validate("token")
		})

		then:
		result.valueOrThrow.get() == token

		and:
		1 * mockValidator2.validate("token") >> Promise.value(Optional.of(token))
		0 * _
	}


	def "No validation if no predicate matches"() {
		given:
		TokenValidator mockValidator1 = Mock(TokenValidator)
		TokenValidator mockValidator2 = Mock(TokenValidator)

		and:
		TokenValidator tokenValidator = new OrderedPredicateTokenValidator([new PredicateValidatorTuple({ String x -> x.size() > 100 }, mockValidator1), new PredicateValidatorTuple({ String x -> x != "" }, mockValidator2)])

		when:
		def result = execHarness.yield({
			tokenValidator.validate("")
		})

		then:
		!result.valueOrThrow.isValid()

		and:
		0 * _
	}

	def "No error if no predicates"() {
		given:
		TokenValidator tokenValidator = new OrderedPredicateTokenValidator([])

		when:
		def result = execHarness.yield({
			tokenValidator.validate("")
		})

		then:
		!result.valueOrThrow.isValid()

		and:
		0 * _
	}
}
