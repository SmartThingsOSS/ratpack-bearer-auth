package st.ratpack.auth;

public interface ValidateTokenResult {

	Status getStatus();

	OAuthToken getOAuthToken();

	default Boolean isErrorResult() {
		return Status.UNKNOWN.equals(this.getStatus());
	}

	default Boolean isValid() {
		return this.getStatus().equals(Status.VALID);
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
