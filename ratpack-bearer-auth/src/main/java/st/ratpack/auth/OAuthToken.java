package st.ratpack.auth;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

public interface OAuthToken {

	Set<String> getScope();

	String getClientId();

	String getValue();

	Map<String, Object> getAdditionalInformation();

	default boolean isUserToken() {
		Map<String, Object> info = getAdditionalInformation();
		return info != null && info.containsKey("user_name");
	}
}
