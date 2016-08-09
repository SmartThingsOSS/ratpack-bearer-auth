package st.ratpack.auth;

import java.util.Map;
import java.util.Set;

public interface User {

	String getUserName();

	Set<String> getAuthorities();

	Map<String, Object> getAdditionalInformation();
}
