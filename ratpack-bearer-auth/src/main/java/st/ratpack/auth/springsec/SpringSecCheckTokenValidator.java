package st.ratpack.auth.springsec;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import io.netty.handler.codec.http.HttpHeaderNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ratpack.exec.Promise;
import ratpack.http.HttpUrlBuilder;
import ratpack.http.client.HttpClient;
import ratpack.http.client.ReceivedResponse;
import st.ratpack.auth.DefaultOAuthToken;
import st.ratpack.auth.OAuthToken;
import st.ratpack.auth.TokenValidator;

import java.net.URI;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class SpringSecCheckTokenValidator implements TokenValidator {

	private static final TypeReference<HashMap<String, Object>> mapTypeRef = new TypeReference<HashMap<String, Object>>() {};
	private final HttpClient httpClient;
	private final SpringSecCheckAuthModule.Config config;
	private static Logger logger = LoggerFactory.getLogger(SpringSecCheckTokenValidator.class);
	private final ObjectMapper objectMapper;

	public SpringSecCheckTokenValidator(SpringSecCheckAuthModule.Config config, HttpClient httpClient) {
		this.httpClient = httpClient;
		this.config = config;
		this.objectMapper = buildObjectMapper();
	}

	@Override
	public Promise<Optional<OAuthToken>> validate(String token) {

		URI uri = HttpUrlBuilder.base(config.getHost())
			.path("oauth/check_token")
			.params("token", token)
			.build();

		Promise<ReceivedResponse> resp = httpClient.get(uri, rs -> {
			rs.redirects(0);
			rs.headers(headers -> {
				headers.add(HttpHeaderNames.AUTHORIZATION, buildBasicAuthHeader(config.getUser(), config.getPassword()));
				headers.add(HttpHeaderNames.ACCEPT, "application/json");
			});
		});

		return Promise.of(downstream ->
			resp.onError(t -> {
				logger.error("Failed to check auth token.", t);
				downstream.success(Optional.<OAuthToken>empty());
			}).then(response -> {
				if (response.getStatusCode() != 200) {
					logger.error("Got Status: " + response.getStatusCode());
					downstream.success(Optional.<OAuthToken>empty());
				} else {
					OAuthToken oAuthToken = null;

					try {
						Map<String, Object> data = objectMapper.readValue(response.getBody().getInputStream(), mapTypeRef);
						String clientId = (String) data.get("client_id");

						if (clientId != null && !clientId.isEmpty()) {
							data.put("auth_token", token);
							DefaultOAuthToken.Builder builder = objectMapper.convertValue(data, DefaultOAuthToken.Builder.class);
							builder.setAdditionalInformation(data);
							oAuthToken = builder.build();
						}

						downstream.success(Optional.ofNullable(oAuthToken));
					} catch (JsonParseException ex) {
						logger.error("Could not parse body");
						downstream.error(ex);
					}
				}
			})
		);
	}

	private String buildBasicAuthHeader(String user, String password) {
		String encodedCreds = Base64.getEncoder().encodeToString((user + ":" + password).getBytes());
		return "Basic " + encodedCreds;
	}

	private static ObjectMapper buildObjectMapper() {
		ObjectMapper objectMapper = new ObjectMapper();
		objectMapper.setPropertyNamingStrategy(PropertyNamingStrategy.CAMEL_CASE_TO_LOWER_CASE_WITH_UNDERSCORES);
		objectMapper.getFactory().enable(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES);
		objectMapper.getFactory().enable(JsonParser.Feature.ALLOW_SINGLE_QUOTES);
		objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
		return objectMapper;
	}

}
