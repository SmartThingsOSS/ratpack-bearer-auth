package st.ratpack.auth.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.netty.handler.codec.http.HttpHeaderNames;
import ratpack.exec.Promise;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import ratpack.registry.Registry;
import st.ratpack.auth.OAuthToken;
import st.ratpack.auth.TokenValidator;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class BearerTokenAuthHandler implements Handler {

	TokenValidator validator;

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

				Promise<Optional<OAuthToken>> user = validator.validate(token);

				user.onError(t -> {sendError(ctx);}).then((Optional<OAuthToken> oAuthToken) -> {
					if (oAuthToken.isPresent()) {
						ctx.next(Registry.of(registrySpec -> {
							OAuthToken authToken = oAuthToken.get();
							//Add the oauth token object to the registry
							registrySpec.add(authToken);
							if (authToken.getUser().isPresent()) {
								//If we have a user add it to the registry
								registrySpec.add(authToken.getUser().get());
							}
						}));
					} else {
						sendError(ctx);
					}
				});
			} else {
				sendError(ctx);
			}
		} else {
			sendError(ctx);
		}
	}

	private void sendError(Context ctx) {
		//Not authorized stop the chain here
		ctx.getResponse().status(401).send();
	}
}
