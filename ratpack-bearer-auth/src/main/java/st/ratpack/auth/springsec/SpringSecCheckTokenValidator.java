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
import st.ratpack.auth.*;
import st.ratpack.auth.internal.DefaultOAuthToken;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class SpringSecCheckTokenValidator implements TokenValidator {
	private static Logger logger = LoggerFactory.getLogger(SpringSecCheckTokenValidator.class);
	private static final TypeReference<HashMap<String, Object>> mapTypeRef = new TypeReference<HashMap<String, Object>>() {
	};

	private final TokenProvider tokenProvider;
	private final ObjectMapper objectMapper;

	public SpringSecCheckTokenValidator(TokenProvider tokenProvider) {
		this.tokenProvider = tokenProvider;
		this.objectMapper = buildObjectMapper();
	}

	@Override
	public Promise<ValidateTokenResult> validate(String token) {

		Promise<ReceivedResponse> resp = tokenProvider.checkToken(token);

		return Promise.async(downstream ->
				resp.onError(t -> {
					logger.error("Failed to check auth token.", t);
					downstream.success(ValidateTokenResult.ERROR_CASE);
				}).then(response -> {
					int statusCode = response.getStatusCode();
					if (statusCode == 200) {
						try {
							Map<String, Object> data = objectMapper.readValue(response.getBody().getInputStream(), mapTypeRef);
							String clientId = (String) data.get("client_id");

							if (clientId != null && !clientId.isEmpty()) {
								data.put("auth_token", token);
								DefaultOAuthToken.Builder builder = objectMapper.convertValue(data, DefaultOAuthToken.Builder.class);
								builder.setAdditionalInformation(data);
								downstream.success(ValidateTokenResult.valid(builder.build()));
							} else {
								downstream.success(ValidateTokenResult.ERROR_CASE);
							}
						} catch (JsonParseException ex) {
							downstream.error(ex);
						}
					} else if (statusCode == 400) {
						downstream.success(ValidateTokenResult.INVALID_CASE);
					} else if (statusCode >= 500) {
						downstream.success(ValidateTokenResult.ERROR_CASE);
					} else {
						logger.error("Got Status: " + response.getStatusCode());
						downstream.success(ValidateTokenResult.ERROR_CASE);
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
