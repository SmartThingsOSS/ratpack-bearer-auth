package st.ratpack.auth.handler

import io.netty.handler.codec.http.HttpResponseStatus
import spock.lang.Specification
import st.ratpack.auth.DefaultOAuthToken
import st.ratpack.auth.OAuthToken

import static ratpack.groovy.test.handling.GroovyRequestFixture.handle

class RequireAuthHandlerSpec extends Specification {

	void 'it should call next with a valid token'() {
		given:
		OAuthToken token = new DefaultOAuthToken.Builder().build()

		when:
		def result = handle(new RequireAuthHandler(), {
			registry { spec ->
				spec.add(OAuthToken.class, token)
			}
		})

		then:
		assert result.calledNext
	}

	void 'it should raise a 401 when no token present'() {
		when:
		def result = handle(new RequireAuthHandler(), {})

		then:
		assert result.sentResponse
		assert result.status.code == HttpResponseStatus.UNAUTHORIZED.code()
	}

}
