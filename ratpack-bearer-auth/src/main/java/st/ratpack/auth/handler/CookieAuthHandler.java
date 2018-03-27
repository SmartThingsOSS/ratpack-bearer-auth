package st.ratpack.auth.handler;

import io.netty.handler.codec.http.cookie.Cookie;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ratpack.exec.Promise;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import ratpack.registry.Registry;
import st.ratpack.auth.ValidateTokenResult;
import st.ratpack.auth.internal.DefaultUser;
import st.ratpack.auth.OAuthToken;
import st.ratpack.auth.TokenValidator;
import st.ratpack.auth.User;

import java.util.Optional;

public class CookieAuthHandler implements Handler {
	private static final Logger LOG = LoggerFactory.getLogger(CookieAuthHandler.class);
	private final TokenValidator validator;
	private final String tokenCookieName;

	public CookieAuthHandler(
		String tokenCookieName,
		TokenValidator validator
	) {
		this.tokenCookieName = tokenCookieName;
		this.validator = validator;
	}

	@Override
	public void handle(Context ctx) throws Exception {
		Optional<Cookie> authCookie = ctx.getRequest()
			.getCookies()
			.stream()
			.filter(cookie -> cookie.name().equals(tokenCookieName))
			.findFirst();

		if (authCookie.isPresent()) {
			LOG.debug("Found " + tokenCookieName + " cookie and now attempting to validate.");
			Promise<ValidateTokenResult> optionalToken = validator.validate(authCookie.get().value());
			optionalToken
				.onError(throwable -> {
					LOG.debug("Error validating " + tokenCookieName + " cookie.", throwable);
					ctx.next();
				})
				.then((validateTokenResult) -> {
					if (validateTokenResult.isValid()) {
						LOG.debug(tokenCookieName + " cookie is valid.");
						ctx.next(Registry.of(registrySpec -> {
							OAuthToken authToken = validateTokenResult.getOAuthToken();
							// Add the oauth token object to the registry
							registrySpec.add(authToken);
							registrySpec.add(validateTokenResult);

							if (authToken.isUserToken()) {
								DefaultUser.Builder  builder = new DefaultUser.Builder(authToken);
								User user = builder.build();
								// Add the user to the registry
								registrySpec.add(user);
							}
						}));
					} else {
						ctx.next();
					}
			});
		} else {
			LOG.debug(tokenCookieName + " cookie was not found.");
			ctx.next();
		}
	}
}
