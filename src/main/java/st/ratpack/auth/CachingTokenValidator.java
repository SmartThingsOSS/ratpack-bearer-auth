package st.ratpack.auth;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import ratpack.exec.Promise;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

public class CachingTokenValidator implements TokenValidator {

	public static long DEFAULT_TTL = 5000;

	private final LoadingCache<String, Promise<Optional<OAuthToken>>> cache;

	public CachingTokenValidator(Long ttl, final TokenValidator tokenValidator) {
		ttl = ttl != null ? ttl : DEFAULT_TTL;

		cache = CacheBuilder.newBuilder()
				.expireAfterWrite(ttl, TimeUnit.MILLISECONDS)
				.build(new CacheLoader<String, Promise<Optional<OAuthToken>>>() {

					@Override
					public Promise<Optional<OAuthToken>> load(String key) throws Exception {
						return tokenValidator.validate(key).cache();
					}
				});
	}

	@Override
	public Promise<Optional<OAuthToken>> validate(String token) {
		return cache.getUnchecked(token);
	}
}
