package st.ratpack.auth;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ratpack.exec.Promise;
import com.github.benmanes.caffeine.cache.Cache;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

public class CachingTokenValidator implements TokenValidator {

	TokenValidator upstreamValidator;
	Cache<String, Promise<Optional<OAuthToken>>> cache;
	private static Logger logger = LoggerFactory.getLogger(CachingTokenValidator.class);

	public CachingTokenValidator(TokenValidator upstreamValidator) {
		this.upstreamValidator = upstreamValidator;

		cache = Caffeine.<String, Promise<Optional<OAuthToken>>>newBuilder()
			.maximumSize(10000L)
			.expireAfterWrite(5L, TimeUnit.MINUTES)
			//			.executor(Execution.current().getEventLoop())  Don't do this it makes Ratpack hang.
			.build();
	}

	@Override
	public Promise<Optional<OAuthToken>> validate(String token) {
		Promise<Optional<OAuthToken>> promiseOAuthToken = cache.getIfPresent(token);

		if (promiseOAuthToken == null) {
			//Cache miss use the upstream validator
			logger.trace("Cache MISS: " + token);
			promiseOAuthToken = upstreamValidator.validate(token);

			//Make sure we only call the validate on the upstream once
			promiseOAuthToken = promiseOAuthToken.cache();

			promiseOAuthToken.then(optionalOAuth -> {
				logger.trace("PUTTING: " + optionalOAuth);
				cache.put(token, Promise.value(optionalOAuth));
			});

			//TODO The wiretap is cleaner but doesn't currently seem to work due to upstream bug
			//Wiretap the promise so we can cache any successful results
			//			promiseOAuthToken.wiretap(optionalResult -> {
			//				logger.trace("Wiretap called");
			//				if (optionalResult.isSuccess()) {
			//					logger.trace("Caching promise value");
			//					cache.put(token, Promise.value(optionalResult.getValue()));
			//				}
			//			});
		} else {
			logger.trace("CACHE HIT: " + token);
		}

		return promiseOAuthToken;
	}
}
