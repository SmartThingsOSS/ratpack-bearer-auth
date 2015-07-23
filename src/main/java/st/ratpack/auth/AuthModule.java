package st.ratpack.auth;

import com.google.inject.Provides;
import com.google.inject.Scopes;
import com.google.inject.Singleton;
import ratpack.exec.ExecControl;
import ratpack.guice.ConfigurableModule;
import ratpack.http.client.HttpClient;

import java.net.URI;

public class AuthModule extends ConfigurableModule<AuthModule.Config> {

	@Override
	protected void configure() {
	}

	@Provides
	@Singleton
	public TokenValidator tokenValidator(AuthModule.Config config, HttpClient httpClient, ExecControl execControl) {
		return new SpringSecCheckTokenValidator(config, httpClient, execControl);
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
