package st.fixture

import ratpack.exec.Promise
import ratpack.func.Function
import st.ratpack.auth.OAuthToken
import st.ratpack.auth.TokenValidator
import st.ratpack.auth.ValidateTokenResult
import st.ratpack.auth.internal.DefaultOAuthToken

/**
 * Used to circumvent token validation during testing.
 */
class NoOpTokenValidator implements TokenValidator {

	Function<String, ValidateTokenResult> validator

	/**
	 * Additional information for the validated tokens contain `user_name` and `authorities`
	 */
	NoOpTokenValidator() {
		this({ token ->
			return ValidateTokenResult.valid(buildDefaultToken(token, ['user_name': 'fakeUser', authorities: ['ROLE_FAKE']]))
		})
	}

	/**
	 * Allows injecting custom validation logic into your tests.
	 *
	 * @param validator validation function
	 */
	NoOpTokenValidator(Function<String, ValidateTokenResult> validator) {
		this.validator = validator
	}

	/**
	 * Override the additional information placed into the validated tokens
	 *
	 * @param additionalInformation overrides the default
	 * @deprecated As of 5.0.2, see {@link #NoOpTokenValidator(Function)}
	 */
	@Deprecated
	NoOpTokenValidator(Map<String, Object> additionalInformation) {
		this({ token ->
			return ValidateTokenResult.valid(buildDefaultToken(token, additionalInformation))
		})
	}

	private static OAuthToken buildDefaultToken(String token, Map<String, Object> mobileTokenInfo) {
		Collection<String> scopes = token.contains("service") ? ['service'] : ['mobile']
		Map<String, Object> additionalInfo = token.contains("service") ? [:] : mobileTokenInfo
		return new DefaultOAuthToken.Builder()
				.setAuthToken('faketoken')
				.setClientId('fake client')
				.setScope(scopes)
				.setAdditionalInformation(additionalInfo)
				.build()
	}

	@Override
	Promise<ValidateTokenResult> validate(String token) {
		return Promise.value(validator.apply(token))
	}
}
