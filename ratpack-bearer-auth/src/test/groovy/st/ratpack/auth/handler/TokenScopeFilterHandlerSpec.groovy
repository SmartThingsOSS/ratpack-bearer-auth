package st.ratpack.auth.handler

import spock.lang.Specification
import spock.lang.Unroll
import st.ratpack.auth.OAuthToken
import st.ratpack.auth.internal.DefaultOAuthToken

import static ratpack.groovy.test.handling.GroovyRequestFixture.handle

class TokenScopeFilterHandlerSpec extends Specification {

	@Unroll
	def "For #scopes a token with #tokenScopes calledNext: #calledNext"() {
		given:
		OAuthToken oauthToken =
				new DefaultOAuthToken.Builder()
		          .setScope(tokenScopes)
		          .build()

		when:
		def result = handle(new TokenScopeFilterHandler((String[])scopes.toArray())) {
			registry.add(oauthToken)
		}


		then:
		result.calledNext == calledNext
		result.status.code == calledNext ? 200 : 403

		where:
		scopes              | tokenScopes           || calledNext
		['mobile']          | []                    || false
		['mobile', 'coool'] | ['fire']              || false
		['service']         | ['service']           || true
		['service']         | ['service', 'mobile'] || true
	}

}
