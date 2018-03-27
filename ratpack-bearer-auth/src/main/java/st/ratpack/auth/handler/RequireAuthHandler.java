package st.ratpack.auth.handler;

import ratpack.handling.Context;
import ratpack.handling.Handler;
import st.ratpack.auth.OAuthToken;
import st.ratpack.auth.ValidateTokenResult;

import java.util.Optional;

public class RequireAuthHandler implements Handler {
	@Override
	public void handle(Context ctx) throws Exception {
		Optional<OAuthToken> token = ctx.maybeGet(OAuthToken.class);
		if (token.isPresent()) {
			ctx.next();
		} else {
			Optional<ValidateTokenResult> oValidateTokenResult = ctx.maybeGet(ValidateTokenResult.class);

			if (oValidateTokenResult.isPresent()) {
				ValidateTokenResult validateTokenResult = oValidateTokenResult.get();
				if (validateTokenResult.isErrorResult()) {
					ctx.getResponse().status(520).send();
				} else {
					ctx.getResponse().status(401).send();
				}
			} else {
				ctx.getResponse().status(401).send();
			}
		}
	}
}
