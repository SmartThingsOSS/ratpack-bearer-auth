package st.ratpack.auth;

import com.google.inject.Scopes;
import ratpack.guice.ConfigurableModule;

import java.net.URI;

public class AuthModule extends ConfigurableModule<AuthModule.Config> {

	@Override
	protected void configure() {
		bind(SpringSecCheckTokenValidator.class).in(Scopes.SINGLETON);
	}

	public static class Config {
		URI host;
		String user;
		String password;

		public URI getHost() {
			return host;
		}

		public void setHost(URI host) {
			this.host = host;
		}

		public String getUser() {
			return user;
		}

		public void setUser(String user) {
			this.user = user;
		}

		public String getPassword() {
			return password;
		}

		public void setPassword(String password) {
			this.password = password;
		}
	}

}
