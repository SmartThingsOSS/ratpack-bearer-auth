package st.ratpack.auth;

import ratpack.exec.Promise;
import ratpack.http.client.ReceivedResponse;

public interface TokenProvider {
	Promise<ReceivedResponse> checkToken(String token);
}
