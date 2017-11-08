package st.ratpack.auth.jwt.impl;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import st.ratpack.auth.jwt.JWTVerifier;

import java.text.ParseException;
import java.util.Date;


public abstract class AbstractJWTVerifier implements JWTVerifier {
    private static final String EXPIRATION_TIME_CLAIM = "exp";

    protected boolean verifyJwtExp(JWT jwt) throws ParseException {
        Date expDate = jwt.getJWTClaimsSet().getDateClaim(EXPIRATION_TIME_CLAIM);
        if (expDate == null) {
            return false;
        }

        return new Date().before(expDate);
    }
}
