package st.ratpack.auth;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.guava.GuavaModule;
import com.fasterxml.jackson.datatype.jdk7.Jdk7Module;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.google.inject.Inject;
import com.google.inject.ProvidedBy;
import io.netty.handler.codec.http.HttpHeaderNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ratpack.exec.ExecControl;
import ratpack.exec.Promise;
import ratpack.http.HttpUrlBuilder;
import ratpack.http.client.HttpClient;
import ratpack.http.client.ReceivedResponse;
import ratpack.jackson.Jackson;
import ratpack.jackson.JsonParseOpts;
import ratpack.parse.Parse;
import ratpack.parse.Parser;

import java.net.URI;
import java.util.Base64;
import java.util.Optional;

public class SpringSecCheckTokenValidator implements TokenValidator {

	private final HttpClient httpClient;
	private final AuthModule.Config config;
	private final ExecControl execControl;
	private static Logger logger = LoggerFactory.getLogger(SpringSecCheckTokenValidator.class);

	SpringSecCheckTokenValidator(AuthModule.Config config, HttpClient httpClient, ExecControl execControl) {
		this.httpClient = httpClient;
		this.config = config;
		this.execControl = execControl;
	}

	@Override
	public Promise<Optional<User>> validate(String token) {

		URI uri = HttpUrlBuilder.base(config.host)
			.path("oauth/check_token")
			.params("token", token)
			.build();

		Promise<ReceivedResponse> resp = httpClient.get(uri, rs -> {
			rs.redirects(0);
			rs.headers(headers -> {
				headers.add(HttpHeaderNames.AUTHORIZATION, buildBasicAuthHeader(config.user, config.password));
			});
		});

		return execControl.promise(fulfiller -> {
			resp.onError(t -> {
				logger.error("Failed to check auth token.", t);
				fulfiller.success(Optional.<User>empty());
			}).then(response -> {
				if (response.getStatusCode() != 200) {
					logger.error("Got Status: " + response.getStatusCode());
					fulfiller.success(Optional.<User>empty());
				} else {
					User user = null;
					ObjectMapper objectMapper = getDefaultJackson();
					user = objectMapper.readValue(response.getBody().getInputStream(), User.class);
					fulfiller.success(Optional.ofNullable(user));
				}
			});

		});
	}

	private String buildBasicAuthHeader(String user, String password) {
		String encodedCreds = Base64.getEncoder().encodeToString((user + ":" + password).getBytes());
		return "Basic " + encodedCreds;
	}

	static ObjectMapper getDefaultJackson() {
		ObjectMapper objectMapper = new ObjectMapper();
		objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
		objectMapper.registerModule(new Jdk7Module());
		objectMapper.registerModule(new Jdk8Module());
		objectMapper.registerModule(new GuavaModule());
		JsonFactory factory = objectMapper.getFactory();
		factory.enable(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES);
		factory.enable(JsonParser.Feature.ALLOW_SINGLE_QUOTES);

		return objectMapper;
	}
}
