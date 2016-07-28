package st.ratpack.auth;

import java.util.Optional;
import java.util.Set;

public class OAuthToken {

	private Optional<User> user = Optional.empty();
	private Set<String> scopes;
	private String clientId;
	private String authToken;

	public OAuthToken() {
	}

	public OAuthToken(Optional<User> user, Set<String> scopes, String clientId, String authToken) {
		this.user = user;
		this.scopes = scopes;
		this.clientId = clientId;
		this.authToken = authToken;
	}

	public Optional<User> getUser() {
		return user;
	}

	public void setUser(Optional<User> user) {
		this.user = user;
	}

	public Set<String> getScopes() {
		return scopes;
	}

	public void setScopes(Set<String> scopes) {
		this.scopes = scopes;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getAuthToken() { return authToken; }

	public void setAuthToken(String authToken) { this.authToken = authToken; }
}
