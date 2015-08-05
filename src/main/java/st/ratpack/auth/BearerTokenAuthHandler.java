package st.ratpack.auth;

import io.netty.handler.codec.http.HttpHeaderNames;
import ratpack.exec.Promise;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import ratpack.registry.Registry;

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

				Promise<Optional<User>> user = validator.validate(token);

				user.onError(t -> {sendError(ctx);}).then((Optional<User> u) -> {
					if (u.isPresent()) {
						ctx.next(Registry.single(u.get()));
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
