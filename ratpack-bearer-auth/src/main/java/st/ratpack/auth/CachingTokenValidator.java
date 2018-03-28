package st.ratpack.auth;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ratpack.exec.Promise;

import java.util.concurrent.TimeUnit;

public class CachingTokenValidator implements TokenValidator {

	private final TokenValidator upstreamValidator;
	private final LoadingCache<String, Promise<ValidateTokenResult>> cache;
	private static Logger logger = LoggerFactory.getLogger(CachingTokenValidator.class);


	public CachingTokenValidator(TokenValidator upstreamValidator) {
		this(upstreamValidator, 100_000L, 5L, TimeUnit.MINUTES);
	}

	public CachingTokenValidator(TokenValidator upstreamValidator, Long maximumSize, Long expiration, TimeUnit expirationUnit) {
		this.upstreamValidator = upstreamValidator;

		cache = Caffeine.newBuilder()
				.maximumSize(maximumSize)
				.expireAfterWrite(expiration, expirationUnit)
				//			.executor(Execution.current().getEventLoop())  Don't do this it makes Ratpack hang.
				.build(this::loadCache);
	}

	@Override
	public Promise<ValidateTokenResult> validate(String token) {
		return cache.get(token);
	}

	private Promise<ValidateTokenResult> loadCache(String token) {

		//Make sure we only call the validate on the upstream once
		Promise<ValidateTokenResult> promiseOAuthToken = upstreamValidator.validate(token)
				.onError(e -> logger.error("upstream validator error", e))
				.map(validateTokenResult -> {
					//This will ignore any error cases but allow for caching of invalid tokens
					ValidateTokenResult result = validateTokenResult.isErrorResult() ?
							null : validateTokenResult;
					logger.trace("PUTTING: {}", result);
					return result;
				})
				.cache();

		return promiseOAuthToken;
	}
}
