package st.ratpack.auth.springsec;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ratpack.exec.Promise;
import ratpack.http.client.ReceivedResponse;
import st.ratpack.auth.DefaultOAuthToken;
import st.ratpack.auth.OAuthToken;
import st.ratpack.auth.TokenProvider;
import st.ratpack.auth.TokenValidator;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class SpringSecCheckTokenValidator implements TokenValidator {
	private static Logger logger = LoggerFactory.getLogger(SpringSecCheckTokenValidator.class);
	private static final TypeReference<HashMap<String, Object>> mapTypeRef = new TypeReference<HashMap<String, Object>>() {};

	private final TokenProvider tokenProvider;
	private final ObjectMapper objectMapper;

	public SpringSecCheckTokenValidator(TokenProvider tokenProvider) {
		this.tokenProvider = tokenProvider;
		this.objectMapper = buildObjectMapper();
	}

	@Override
	public Promise<Optional<OAuthToken>> validate(String token) {

		Promise<ReceivedResponse> resp = tokenProvider.checkToken(token);

		return Promise.async(downstream ->
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

	private static ObjectMapper buildObjectMapper() {
		ObjectMapper objectMapper = new ObjectMapper();
		objectMapper.setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);
		objectMapper.getFactory().enable(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES);
		objectMapper.getFactory().enable(JsonParser.Feature.ALLOW_SINGLE_QUOTES);
		objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
		return objectMapper;
	}

}
