package st.ratpack.auth.internal;

import st.ratpack.auth.OAuthToken;

import java.util.*;

public class DefaultOAuthToken implements OAuthToken {

	private static final long serialVersionUID = -1236874447952674147L;
	private final String authToken;
	private final String clientId;
	private final Set<String> scope;
	private final Map<String, Object> additionalInformation;

	public DefaultOAuthToken(
		String authToken,
		String clientId,
		Set<String> scope,
		Map<String, Object> additionalInformation
	) {
		this.scope = scope;
		this.clientId = clientId;
		this.authToken = authToken;
		this.additionalInformation = additionalInformation;
	}

	@Override
	public Set<String> getScope() {
		return new HashSet<>(scope);
	}

	@Override
	public String getClientId() {
		return clientId;
	}

	@Override
	public String getValue() { return authToken; }

	@Override
	public Map<String, Object> getAdditionalInformation() {
		return new HashMap<>(additionalInformation);
	}

	@Override
	public String toString() {
		return "DefaultOAuthToken{" +
				"clientId='" + clientId + '\'' +
				", scope=" + scope +
				'}';
	}

	public static class Builder {

		private String clientId;
		private String authToken;
		private Set<String> scope = new HashSet<>();
		private Map<String, Object> additionalInformation = new HashMap<>();

		public Builder() {
            //
		}

		public Builder(OAuthToken token) {
			this.clientId = token.getClientId();
			this.authToken = token.getValue();
			this.scope.addAll(token.getScope());
			this.additionalInformation.putAll(token.getAdditionalInformation());
		}

		public DefaultOAuthToken.Builder setClientId(String clientId) {
			this.clientId = clientId;
			return this;
		}

		public DefaultOAuthToken.Builder setAuthToken(String authToken) {
			this.authToken = authToken;
			return this;
		}

		public DefaultOAuthToken.Builder setScope(Collection<String> scope) {
			this.scope.addAll(scope);
			return this;
		}

		public DefaultOAuthToken.Builder setAdditionalInformation(Map<String, Object> additionalInformation) {
			this.additionalInformation.putAll(additionalInformation);
			return this;
		}

		public DefaultOAuthToken build() {
			return new DefaultOAuthToken(authToken, clientId, scope, additionalInformation);
		}

		@Override
		public String toString() {
			return "DefaultOAuthToken.Builder{" +
					"clientId='" + clientId + '\'' +
					", scope=" + scope +
					'}';
		}
	}
}
