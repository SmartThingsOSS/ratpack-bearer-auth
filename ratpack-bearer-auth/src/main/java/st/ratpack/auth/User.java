package st.ratpack.auth;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Set;

public class User {

	private String username;
	private Set<String> authorities;

	public User() {
	}

	public User(String username, Set<String> authorities) {
		this.username = username;
		this.authorities = authorities;
	}

	public String getUsername() {
		return username;
	}

	@JsonProperty("user_name")
	public void setUsername(String username) {
		this.username = username;
	}

	public Set<String> getAuthorities() {
		return authorities;
	}

	public void setAuthorities(Set<String> authorities) {
		this.authorities = authorities;
	}
}
