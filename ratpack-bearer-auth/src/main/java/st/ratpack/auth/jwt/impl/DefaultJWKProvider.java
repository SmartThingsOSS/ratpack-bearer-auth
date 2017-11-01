package st.ratpack.auth.jwt.impl;

import com.google.common.collect.ImmutableMap;
import com.google.inject.Inject;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ratpack.exec.ExecController;
import ratpack.exec.Execution;
import ratpack.exec.Promise;
import ratpack.http.HttpUrlBuilder;
import ratpack.http.client.HttpClient;
import ratpack.service.StartEvent;
import ratpack.service.StopEvent;
import st.ratpack.auth.jwt.JWKProvider;

import java.net.URI;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public class DefaultJWKProvider implements JWKProvider {

	private final HttpClient httpClient;
	private final URI jwkSetUrl;
	private final long jwkSetReloadInterval;
	private final AtomicReference<Map<String, JWK>> keyMap = new AtomicReference<>(ImmutableMap.of());
	private static Logger logger = LoggerFactory.getLogger(DefaultJWKProvider.class);

	private ScheduledExecutorService executorService;
	private volatile ScheduledFuture<?> nextFuture;
	private volatile boolean stopped;

	@Inject
	public DefaultJWKProvider(
		HttpClient httpClient,
		URI jwkUrl,
		long jwkInternal
	) {
		this.httpClient = httpClient;
		this.jwkSetUrl = jwkUrl;
		this.jwkSetReloadInterval = jwkInternal;
	}

	@Override
	public Optional<JWK> getJWK(String kid) {
		Map<String, JWK> map = keyMap.get();
		if (map != null) {
			return Optional.ofNullable(map.get(kid));
		} else {
			return Optional.empty();
		}
	}

	@Override
	public void onStart(StartEvent event) throws Exception {
		ExecController controller = event.getRegistry().get(ExecController.class);
		executorService = controller.getExecutor();
		run();
	}

	@Override
	public void onStop(StopEvent event) throws Exception {
		stopped = true;
		if (nextFuture != null) {
			nextFuture.cancel(true);
		}
	}

	private Promise<Void> run() {
		if (!stopped) {
			Execution.fork()
					.onComplete(e -> {
						scheduleNext();
					})
					.onError(e -> {
						scheduleNext();
					})
					.start(e -> loadJWKSet());
		}
		return Promise.value(null);
	}

	private Promise<Void> scheduleNext() {
		nextFuture = executorService.schedule((Runnable) this::run, jwkSetReloadInterval, TimeUnit.SECONDS);
		return Promise.value(null);
	}

	private void loadJWKSet() {
		URI uri = HttpUrlBuilder.base(jwkSetUrl).build();
		httpClient
				.get(uri)
				.onError(e -> new Exception("failed to get jwk set from auth server", e))
				.then(receivedResponse -> {
					if (receivedResponse == null ||
							!receivedResponse.getStatus().is2xx()) {
						throw new Exception("failed to get jwk set from auth server");
					}
					JWKSet jwkSet = JWKSet.parse(receivedResponse.getBody().getText());
					swapNewJWTSet(jwkSet);
					logger.debug("loaded " + jwkSet.getKeys().size() + " JWKs from auth server");

				});
	}

	private void swapNewJWTSet(JWKSet jwkSet) {
		Map<String, JWK> oldMap = this.keyMap.get();
		ImmutableMap.Builder<String, JWK> builder = ImmutableMap.builder();
		jwkSet.getKeys().forEach(key ->
                builder.put(key.getKeyID(), key)
        );
		keyMap.compareAndSet(oldMap, builder.build());
	}

}
