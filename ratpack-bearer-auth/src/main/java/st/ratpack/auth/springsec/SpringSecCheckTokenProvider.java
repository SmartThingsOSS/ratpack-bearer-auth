package st.ratpack.auth.springsec;

import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer;
import com.google.inject.Inject;
import io.netty.handler.codec.http.HttpHeaderNames;
import ratpack.exec.Promise;
import ratpack.func.Action;
import ratpack.http.HttpUrlBuilder;
import ratpack.http.client.HttpClient;
import ratpack.http.client.ReceivedResponse;
import st.ratpack.auth.TokenProvider;

import java.net.URI;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

import static io.netty.handler.codec.http.HttpHeaderValues.APPLICATION_JSON;
import static io.netty.handler.codec.http.HttpHeaderValues.APPLICATION_X_WWW_FORM_URLENCODED;

public class SpringSecCheckTokenProvider implements TokenProvider {

	private final HttpClient httpClient;
	private final SpringSecCheckAuthModule.Config config;
	private final Action<Duration> checkTokenTimer;

	@Inject
	public SpringSecCheckTokenProvider(
		HttpClient httpClient,
		SpringSecCheckAuthModule.Config config,
		MetricRegistry metricRegistry

	) {
		this.httpClient = httpClient;
		this.config = config;
		Timer timer = metricRegistry.timer("oauth.check_token");
		this.checkTokenTimer = duration -> timer.update(duration.toMillis(), TimeUnit.MILLISECONDS);
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
			})).time(checkTokenTimer);
	}

	private String buildBasicAuthHeader(String user, String password) {
		String encodedCreds = Base64.getEncoder().encodeToString((user + ":" + password).getBytes());
		return "Basic " + encodedCreds;
	}
}
