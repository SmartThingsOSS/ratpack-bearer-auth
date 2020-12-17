package st.ratpack.auth;

import java.io.Serializable;

public interface ValidateTokenResult extends Serializable {

	Status getStatus();

	OAuthToken getOAuthToken();

	default Boolean isErrorResult() {
		return Status.UNKNOWN.equals(this.getStatus());
	}

	default Boolean isValid() {
		return this.getStatus().equals(Status.VALID);
	}

	default Boolean isCacheable() {
		return true;
	}

	static ValidateTokenResult valid(OAuthToken oAuthToken) {
		return new DefaultValidateTokenResult(Status.VALID, oAuthToken);
	}

	ValidateTokenResult ERROR_CASE = new ValidateTokenResult() {
		@Override
		public Status getStatus() {
			return Status.UNKNOWN;
		}

		@Override
		public OAuthToken getOAuthToken() {
			return null;
		}
	};

	ValidateTokenResult INVALID_CASE = new ValidateTokenResult() {
		@Override
		public Status getStatus() {
			return Status.INVALID;
		}

		@Override
		public OAuthToken getOAuthToken() {
			return null;
		}
	};

	enum Status {
		VALID, INVALID, UNKNOWN
	}
}
