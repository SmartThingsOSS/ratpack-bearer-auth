package st.ratpack.auth;

import java.io.Serializable;
import java.util.Map;
import java.util.Set;

public interface OAuthToken extends Serializable {

	Set<String> getScope();

	String getClientId();

	String getValue();

	Map<String, Object> getAdditionalInformation();

	default boolean isUserToken() {
		Map<String, Object> info = getAdditionalInformation();
		return info != null && info.containsKey("user_name");
	}
}
