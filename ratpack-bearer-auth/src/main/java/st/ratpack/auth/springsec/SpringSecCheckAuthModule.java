package st.ratpack.auth.springsec;

import com.google.inject.Provides;
import com.google.inject.Singleton;
import ratpack.guice.ConfigurableModule;
import ratpack.http.client.HttpClient;
import st.ratpack.auth.*;

import java.net.URI;

public class SpringSecCheckAuthModule extends ConfigurableModule<SpringSecCheckAuthModule.Config> {

	@Override
	protected void configure() {
	}

	@Provides
	@Singleton
	public TokenValidator tokenValidator(SpringSecCheckAuthModule.Config config, HttpClient httpClient) {
		return new CachingTokenValidator(new SpringSecCheckTokenValidator(config, httpClient));
	}

	public static class Config {
		private URI host;
		private String user;
		private String password;

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
