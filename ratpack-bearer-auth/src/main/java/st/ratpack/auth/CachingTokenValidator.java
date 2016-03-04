package st.ratpack.auth;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ratpack.exec.Promise;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

public class CachingTokenValidator implements TokenValidator {

	private final TokenValidator upstreamValidator;
	private final LoadingCache<String, Promise<Optional<OAuthToken>>> cache;
	private static Logger logger = LoggerFactory.getLogger(CachingTokenValidator.class);

	public CachingTokenValidator(TokenValidator upstreamValidator) {
		this.upstreamValidator = upstreamValidator;

		cache = Caffeine.<String, Promise<Optional<OAuthToken>>>newBuilder()
			.maximumSize(10000L)
			.expireAfterWrite(5L, TimeUnit.MINUTES)
			//			.executor(Execution.current().getEventLoop())  Don't do this it makes Ratpack hang.
			.build(this::loadCache);
	}

	@Override
	public Promise<Optional<OAuthToken>> validate(String token) {
		return cache.get(token);
	}

	private Promise<Optional<OAuthToken>> loadCache(String token) {
		logger.trace("Cache MISS: {}", token);
		//Make sure we only call the validate on the upstream once
		Promise<Optional<OAuthToken>>
				promiseOAuthToken = upstreamValidator.validate(token).cache();

		promiseOAuthToken
				.onError(e -> cache.invalidate(token))
				.map(o -> o.orElse(null))
				.onNull(() -> cache.invalidate(token))
				.then(o -> logger.trace("PUTTING: {}", o));

		return promiseOAuthToken;
	}
}
