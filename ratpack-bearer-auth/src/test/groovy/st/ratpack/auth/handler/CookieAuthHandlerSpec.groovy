package st.ratpack.auth.handler

import ratpack.exec.Promise
import ratpack.test.handling.HandlingResult
import ratpack.test.handling.RequestFixture
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Subject
import st.ratpack.auth.DefaultOAuthToken
import st.ratpack.auth.OAuthToken
import st.ratpack.auth.TokenValidator
import st.ratpack.auth.User

class CookieAuthHandlerSpec extends Specification {
	TokenValidator validator;
	RequestFixture requestFixture

	@Subject
	@Shared
	CookieAuthHandler cookieAuthHandler

	def setup() {
		validator = Mock(TokenValidator)
		cookieAuthHandler = new CookieAuthHandler("JTKN", validator)
		requestFixture = RequestFixture.requestFixture()
			.registry { reg ->
				reg.add(TokenValidator, validator)
		}
	}

	def 'Should set user when successfully finding user details from the cookie value'() {
		given:
		OAuthToken token = new DefaultOAuthToken('authToken', 'clientId', [] as Set, [
			fullName: 'Darth Vader',
			user_name: 'darth',
			authorities: ['admin', 'test']
		]);

		when:
		HandlingResult result = requestFixture
			.header('Cookie', 'JTKN=authToken')
			.handle(cookieAuthHandler)

		then:
		1 * validator.validate('authToken') >> Promise.value(Optional.of(token))
		0 * _

		User user = result.getRegistry().get(User);
		assert result.getRegistry().get(OAuthToken).getValue() == 'authToken'
		assert user.getUserName() == 'darth'
		assert user.getAuthorities().containsAll(['admin', 'test'])
		assert user.getAdditionalInformation()['fullName'] == 'Darth Vader'
		assert result.calledNext
	}

	def 'Should not set user when the cookie is not found'() {
		when:
		HandlingResult result = requestFixture
			.handle(cookieAuthHandler)

		then:
		0 * _

		assert !result.getRegistry().maybeGet(OAuthToken).present
		assert !result.getRegistry().maybeGet(User).present
		assert result.calledNext
	}

	def 'Should not set user when unsuccessful at looking up user details'() {

		when:
		HandlingResult result = requestFixture
			.header('Cookie', 'JTKN=authToken')
			.handle(cookieAuthHandler)

		then:
		1 * validator.validate('authToken') >>
			Promise.value(Optional.empty())
		0 * _

		assert !result.getRegistry().maybeGet(OAuthToken).present
		assert !result.getRegistry().maybeGet(User).present
		assert result.calledNext
	}
}
