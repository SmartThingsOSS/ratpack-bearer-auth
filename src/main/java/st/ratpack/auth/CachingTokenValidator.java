package st.ratpack.auth;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ratpack.exec.Promise;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

public class CachingTokenValidator implements TokenValidator {

	private final TokenValidator upstreamValidator;
	private final Cache<String, Promise<Optional<OAuthToken>>> cache;
	private static Logger logger = LoggerFactory.getLogger(CachingTokenValidator.class);

	public CachingTokenValidator(TokenValidator upstreamValidator) {
		this.upstreamValidator = upstreamValidator;

		cache = Caffeine.<String, Promise<Optional<OAuthToken>>>newBuilder()
			.maximumSize(10000L)
			.expireAfterWrite(5L, TimeUnit.MINUTES)
			.recordStats()
			//			.executor(Execution.current().getEventLoop())  Don't do this it makes Ratpack hang.
			.build();
	}

	@Override
	public Promise<Optional<OAuthToken>> validate(String token) {
		return cache.get(token, this::loadCache);
	}

	private Promise<Optional<OAuthToken>> loadCache(String token) {
		logger.trace("Cache MISS: {}", token);
		//Make sure we only call the validate on the upstream once
		Promise<Optional<OAuthToken>>
				promiseOAuthToken = upstreamValidator.validate(token).cache();

		promiseOAuthToken.then(o -> logger.trace("PUTTING: {}", o));

		return promiseOAuthToken;
	}
}
