package st.ratpack.auth;

@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
public class DefaultValidateTokenResult implements ValidateTokenResult {

	private Status status;
	private OAuthToken oAuthToken;


	public DefaultValidateTokenResult(Status status, OAuthToken oAuthToken) {
		this.status = status;
		this.oAuthToken = oAuthToken;
	}


	@Override
	public Status getStatus() {
		return this.status;
	}

	@Override
	public OAuthToken getOAuthToken() {
		return oAuthToken;
	}
}
