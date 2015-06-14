package st.ratpack.auth;

import com.google.inject.Inject;
import io.netty.handler.codec.http.HttpHeaderNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ratpack.exec.ExecControl;
import ratpack.exec.Promise;
import ratpack.http.client.HttpClient;
import ratpack.http.client.ReceivedResponse;

import java.util.Base64;

public class SpringSecCheckTokenValidator implements TokenValidator {

	private final HttpClient httpClient;
	private final AuthModule.Config config;
	private final ExecControl execControl;
	private static Logger logger = LoggerFactory.getLogger(SpringSecCheckTokenValidator.class);

	@Inject
	SpringSecCheckTokenValidator(AuthModule.Config config, HttpClient httpClient, ExecControl execControl) {
		this.httpClient = httpClient;
		this.config = config;
		this.execControl = execControl;
	}

	@Override
	public Promise<Boolean> validate(String token) {

		Promise<ReceivedResponse> resp = httpClient.get(config.host, rs -> {
			rs.headers(headers -> {
				headers.add(HttpHeaderNames.AUTHORIZATION, buildBasicAuthHeader(config.user, config.password));
			});
		});

		return execControl.promise(fulfiller -> {
			resp.onError(t -> {
				logger.error("Failed to check auth token.", t);
				fulfiller.success(false);
			}).then(response -> {
				if (response.getStatusCode() != 200) {

					fulfiller.success(false);
				} else {
					fulfiller.success(true);
				}
			});

		});
	}

	private String buildBasicAuthHeader(String user, String password) {
		String encodedCreds = Base64.getEncoder().encodeToString((user + ":" + password).getBytes());
		return "BASIC " + encodedCreds;
	}
}
