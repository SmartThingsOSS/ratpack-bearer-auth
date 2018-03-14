package st.ratpack.auth;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ratpack.exec.ExecController;
import ratpack.exec.Promise;

import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public class CachingTokenValidator implements TokenValidator {

	private final TokenValidator upstreamValidator;
	private final LoadingCache<String, Promise<Optional<OAuthToken>>> cache;
	private final ExecController execController;
	private static Logger logger = LoggerFactory.getLogger(CachingTokenValidator.class);

	public CachingTokenValidator(TokenValidator upstreamValidator,
	                             long timoutMinutes, TimeUnit timeUnit,
	                             boolean refresh,
	                             ExecController execController) {
		this.upstreamValidator = upstreamValidator;
		this.execController = execController;

		if (refresh) {
			cache = Caffeine.<String, Promise<Optional<OAuthToken>>>newBuilder()
					.maximumSize(10000L)
					.refreshAfterWrite(timoutMinutes, timeUnit)
					.build(this::loadCacheAsync);
		} else {
			cache = Caffeine.<String, Promise<Optional<OAuthToken>>>newBuilder()
					.maximumSize(10000L)
					.expireAfterWrite(timoutMinutes, timeUnit)
					.build(this::loadCache);
		}
	}

	@Override
	public Promise<Optional<OAuthToken>> validate(String token) {
		return cache.get(token);
	}

	private Promise<Optional<OAuthToken>> loadCacheAsync(String token) {
		AtomicReference<Promise<Optional<OAuthToken>>> reference = new AtomicReference<>();
		CountDownLatch latch = new CountDownLatch(1);
		execController.fork()
				.start(execution -> {
					reference.set(loadCache(token));
					latch.countDown();
				});
		try {
			latch.await(1, TimeUnit.MINUTES);
		} catch (InterruptedException ex) {
			logger.error("cache load interrupt", ex);
		}

		Promise<Optional<OAuthToken>> result = reference.get();
		logger.trace("PUTTING: {} {}", token, result);
		return result;
	}

	private Promise<Optional<OAuthToken>> loadCache(String token) {
		logger.trace("Cache MISS: {}", token);
		//Make sure we only call the validate on the upstream once
		Promise<Optional<OAuthToken>>
				promiseOAuthToken = upstreamValidator.validate(token)
				.next(o -> {
					// this should just get invoked once
					if (!o.isPresent()) {
						// evict and let another request try
						logger.trace("EVICT NOT PRESENT: {}", o);
						cache.invalidate(token);
					} else {
						logger.trace("PROMISE RESOLVED: {}", token);
					}
				})
				.flatMapError(e -> {
					logger.warn("error validating token", e);
					cache.invalidate(token); // evict and let another request try
					return Promise.value(Optional.empty());
				})

				// Cache the promise execution the first time it is used so when it is read
				// the wrapped validator does not get called again
				.cache();
		return promiseOAuthToken;
	}
}
