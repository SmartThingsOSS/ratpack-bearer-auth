package st.ratpack.auth.handler;

import io.netty.handler.codec.http.HttpHeaderNames;
import ratpack.exec.Promise;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import ratpack.registry.Registry;
import st.ratpack.auth.ValidateTokenResult;
import st.ratpack.auth.internal.DefaultUser;
import st.ratpack.auth.OAuthToken;
import st.ratpack.auth.TokenValidator;
import st.ratpack.auth.User;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class BearerTokenAuthHandler implements Handler {

	private TokenValidator validator;

	public BearerTokenAuthHandler(TokenValidator validator) {
		this.validator = validator;
	}

	@Override
	public void handle(Context ctx) throws Exception {
		String authHeader = ctx.getRequest().getHeaders().get(HttpHeaderNames.AUTHORIZATION);
		if (authHeader != null && authHeader.startsWith("Bearer")) {
			//Confirm token is valid
			List<String> parts = Arrays.asList(authHeader.trim().split(" "));
			if (parts.size() == 2) {
				String token = parts.get(1);
				Promise<ValidateTokenResult> optionalToken = validator.validate(token);
				optionalToken
					.onError(t -> {
						ctx.next();
					})
					.then((validateTokenResult) -> {
						if (validateTokenResult.isValid()) {
							ctx.next(Registry.of(registrySpec -> {

								OAuthToken authToken = validateTokenResult.getOAuthToken();
								// Add the oauth token object to the registry
								registrySpec.add(authToken);
								registrySpec.add(validateTokenResult);

								if (authToken.isUserToken()) {
									DefaultUser.Builder  builder = new DefaultUser.Builder(authToken);
									User user = builder.build();
									registrySpec.add(user);
								}

							}));
						} else {
							ctx.next(Registry.single(validateTokenResult));
						}
					});
			} else {
				ctx.next();
			}
		} else {
			ctx.next();
		}
	}
}
