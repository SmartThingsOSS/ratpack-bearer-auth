package st.ratpack.auth.handler;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import st.ratpack.auth.OAuthToken;

import java.util.Optional;

public class TokenScopeFilterHandler implements Handler {

	private ImmutableSet<String> allowedScopes;

	public TokenScopeFilterHandler(String... scopes) {
		allowedScopes = ImmutableSet.copyOf(scopes);
	}

	@Override
	public void handle(Context ctx) throws Exception {
		Optional<OAuthToken> oAuthTokenOptional = ctx.maybeGet(OAuthToken.class);

		if (oAuthTokenOptional.isPresent()) {
			Sets.SetView<String> sharedScopes = Sets.intersection(oAuthTokenOptional.get().getScopes(), allowedScopes);
			if (!sharedScopes.isEmpty()) {
				ctx.next();
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
