package st.ratpack.auth;

import ratpack.guice.ConfigurableModule;

import java.net.URI;

public class AuthModule extends ConfigurableModule<AuthModule.Config> {

	@Override
	protected void configure() {

	}

	public static class Config {
		URI host;
		String user;
		String password;
	}
}
