package st.ratpack.auth.springsec;

import com.google.inject.Inject;
import io.netty.handler.codec.http.HttpHeaderNames;
import ratpack.exec.Promise;
import ratpack.http.HttpUrlBuilder;
import ratpack.http.client.HttpClient;
import ratpack.http.client.ReceivedResponse;
import ratpack.http.client.RequestSpec;
import st.ratpack.auth.TokenProvider;

import java.net.URI;
import java.util.Base64;

import static io.netty.handler.codec.http.HttpHeaderValues.APPLICATION_JSON;
import static io.netty.handler.codec.http.HttpHeaderValues.APPLICATION_X_WWW_FORM_URLENCODED;

public class SpringSecCheckTokenProvider implements TokenProvider {

	private final HttpClient httpClient;
	private final SpringSecCheckAuthModule.Config config;

	@Inject
	public SpringSecCheckTokenProvider(
		HttpClient httpClient,
		SpringSecCheckAuthModule.Config config
	) {
		this.httpClient = httpClient;
		this.config = config;
	}

	@Override
	public Promise<ReceivedResponse> checkToken(String token) {

		URI uri = HttpUrlBuilder.base(config.getHost())
			.path("oauth/check_token")
			.build();


		return httpClient.post(uri, rs -> rs
			.body(body -> body.type(APPLICATION_X_WWW_FORM_URLENCODED.toString()).text("token=" + token))
			.redirects(0)
			.headers(headers -> {
				headers.add(
					HttpHeaderNames.AUTHORIZATION,
					buildBasicAuthHeader(config.getUser(), config.getPassword())
				);
				headers.add(HttpHeaderNames.ACCEPT, APPLICATION_JSON);
			})
		);
	}

	private String buildBasicAuthHeader(String user, String password) {
		String encodedCreds = Base64.getEncoder().encodeToString((user + ":" + password).getBytes());
		return "Basic " + encodedCreds;
	}
}
