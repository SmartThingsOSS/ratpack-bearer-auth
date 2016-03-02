package st.ratpack.auth;

import java.util.Optional;
import java.util.Set;

public class OAuthToken {

	private Optional<User> user = Optional.empty();
	private Set<String> scopes;
	private String clientId;

	public OAuthToken() {
	}

	public OAuthToken(Optional<User> user, Set<String> scopes, String clientId) {
		this.user = user;
		this.scopes = scopes;
		this.clientId = clientId;
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
}
