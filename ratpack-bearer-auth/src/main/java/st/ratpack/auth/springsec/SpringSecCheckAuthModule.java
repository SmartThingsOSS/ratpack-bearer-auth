package st.ratpack.auth.springsec;

import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Provides;
import com.google.inject.Scopes;
import com.google.inject.multibindings.OptionalBinder;
import ratpack.guice.ConfigurableModule;
import st.ratpack.auth.CachingTokenValidator;
import st.ratpack.auth.TokenProvider;
import st.ratpack.auth.TokenValidator;
import st.ratpack.auth.handler.BearerTokenAuthHandler;
import st.ratpack.auth.handler.RequireAuthHandler;

import java.net.URI;

public class SpringSecCheckAuthModule extends ConfigurableModule<SpringSecCheckAuthModule.Config> {

	@Override
	protected void configure() {
		bind(RequireAuthHandler.class).in(Scopes.SINGLETON);
		OptionalBinder.newOptionalBinder(binder(), TokenProvider.class)
				.setDefault().to(SpringSecCheckTokenProvider.class).in(Scopes.SINGLETON);

		OptionalBinder.newOptionalBinder(binder(), TokenValidator.class)
				.setDefault().toProvider(TokenValidatorProvider.class).in(Scopes.SINGLETON);
	}

	public static class Config {
		private URI host;
		private String user;
		private String password;
		private int connectRetries = 2;
		private long backoff = 200;

		public URI getHost() {
			return host;
		}

		public void setHost(URI host) {
			this.host = host;
		}

		public String getUser() {
			return user;
		}

		public int getConnectRetries() {
			return connectRetries;
		}

		public long getBackoff() {
			return backoff;
		}

		public void setBackoff(long backoff) {
			this.backoff = backoff;
		}

		public void setConnectRetries(int retries) {
			this.connectRetries = retries;
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

	public static class TokenValidatorProvider implements Provider<TokenValidator> {

		private final TokenProvider tokenProvider;

		@Inject
		TokenValidatorProvider(TokenProvider tokenProvider) {
			this.tokenProvider = tokenProvider;
		}

		@Override
		public TokenValidator get() {
			return new CachingTokenValidator(new SpringSecCheckTokenValidator(tokenProvider));
		}
	}

	@Provides
	public BearerTokenAuthHandler defaultBearerTokenAuthHandler(TokenValidator validator) {
		return new BearerTokenAuthHandler(validator);
	}
}
