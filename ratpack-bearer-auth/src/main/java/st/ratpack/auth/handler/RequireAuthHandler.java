package st.ratpack.auth.handler;

import ratpack.handling.Context;
import ratpack.handling.Handler;
import st.ratpack.auth.OAuthToken;

import java.util.Optional;

public class RequireAuthHandler implements Handler {
	@Override
	public void handle(Context ctx) throws Exception {
		Optional<OAuthToken> token = ctx.maybeGet(OAuthToken.class);
		if (token.isPresent()) {
			ctx.next();
		} else {
			ctx.getResponse().status(401).send();
		}
	}
}
