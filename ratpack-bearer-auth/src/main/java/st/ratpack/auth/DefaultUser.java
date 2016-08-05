package st.ratpack.auth;

import java.util.*;

public class DefaultUser implements User {

	private final String userName;
	private final Set<String> authorities;
	private final Map<String, Object> additionalInformation;

	public DefaultUser(String userName, Set<String> authorities, Map<String, Object> additionalInformation) {
		this.userName = userName;
		this.authorities = authorities;
		this.additionalInformation = additionalInformation;
	}

	@Override
	public String getUserName() {
		return userName;
	}

	@Override
	public Set<String> getAuthorities() {
		return new HashSet<>(authorities);
	}

	@Override
	public Map<String, Object> getAdditionalInformation() {
		return new HashMap<>(additionalInformation);
	}

	@Override
	public String toString() {
		return "DefaultUser{" +
				"userName='" + userName + '\'' +
				", authorities=" + authorities +
				'}';
	}

	public static class Builder {

		private String userName;
		private Set<String> authorities = new HashSet<>();
		private Map<String, Object> additionalInformation = new HashMap<>();

		public Builder() {

		}

		public Builder(User user) {
			this.userName = user.getUserName();
			this.authorities.addAll(user.getAuthorities());
			this.additionalInformation.putAll(user.getAdditionalInformation());
		}

		@SuppressWarnings("unchecked")
		public Builder(OAuthToken token) {
			String userName = (String) token.getAdditionalInformation().get("user_name");
			Collection<String> authorities = Collection.class.cast(token.getAdditionalInformation().get("authorities"));
			if (userName == null || userName.isEmpty()) {
				throw new IllegalArgumentException("Cannot construct a user from a client based oauth token");
			}
			this.userName = userName;
			this.authorities.addAll(authorities);
			this.additionalInformation.putAll(token.getAdditionalInformation());
		}

		public Builder setUserName(String userName) {
			this.userName = userName;
			return this;
		}

		public Builder setAuthorities(Collection<String> authorities) {
			this.authorities.addAll(authorities);
			return this;
		}

		public Builder setAdditionalInformation(Map<String, Object> additionalInformation) {
			this.additionalInformation.putAll(additionalInformation);
			return this;
		}

		public DefaultUser build() {
			return new DefaultUser(userName, authorities, additionalInformation);
		}

		@Override
		public String toString() {
			return "Builder{" +
					"userName='" + userName + '\'' +
					", authorities=" + authorities +
					'}';
		}
	}
}
