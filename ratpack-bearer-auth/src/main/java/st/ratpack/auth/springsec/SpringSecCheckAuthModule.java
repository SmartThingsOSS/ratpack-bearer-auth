package st.ratpack.auth.springsec;

import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Scopes;
import com.google.inject.multibindings.OptionalBinder;
import ratpack.exec.ExecController;
import ratpack.guice.ConfigurableModule;
import st.ratpack.auth.CachingTokenValidator;
import st.ratpack.auth.TokenProvider;
import st.ratpack.auth.TokenValidator;

import java.net.URI;
import java.util.concurrent.TimeUnit;

public class SpringSecCheckAuthModule extends ConfigurableModule<SpringSecCheckAuthModule.Config> {

	@Override
	protected void configure() {
		OptionalBinder.newOptionalBinder(binder(), TokenProvider.class)
				.setDefault().to(SpringSecCheckTokenProvider.class).in(Scopes.SINGLETON);

		OptionalBinder.newOptionalBinder(binder(), TokenValidator.class)
				.setDefault().toProvider(TokenValidatorProvider.class).in(Scopes.SINGLETON);
	}

	public static class Config {
		private URI host;
		private String user;
		private String password;
		private CacheConfig cacheConfig = new CacheConfig();

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

		public CacheConfig getCacheConfig() {
			return cacheConfig;
		}

		public void setCacheConfig(CacheConfig cacheConfig) {
			this.cacheConfig = cacheConfig;
		}
	}

	public static class CacheConfig {
		private boolean enabled = true;
		private long cacheMinutes = 5L;
		private boolean refresh = false;

		public boolean isEnabled() {
			return enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public long getCacheMinutes() {
			return cacheMinutes;
		}

		public void setCacheMinutes(long cacheMinutes) {
			this.cacheMinutes = cacheMinutes;
		}

		public boolean isRefresh() {
			return refresh;
		}

		public void setRefresh(boolean refresh) {
			this.refresh = refresh;
		}
	}

	public static class TokenValidatorProvider implements Provider<TokenValidator> {

		private final TokenProvider tokenProvider;
		private final CacheConfig cacheConfig;
		private final ExecController controller;

		@Inject
		TokenValidatorProvider(TokenProvider tokenProvider, Config config, ExecController controller) {
			this.tokenProvider = tokenProvider;
			this.cacheConfig = config.getCacheConfig();
			this.controller = controller;
		}

		@Override
		public TokenValidator get() {
			TokenValidator validator = new SpringSecCheckTokenValidator(tokenProvider);
			if (cacheConfig.isEnabled()) {
				validator = new CachingTokenValidator(
						validator,
						cacheConfig.getCacheMinutes(), TimeUnit.MINUTES,
						cacheConfig.isRefresh(),
						controller);
			}
			return validator;
		}
	}

}
