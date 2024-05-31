package com.yahoo.athenz.common.server.external;

import com.yahoo.athenz.auth.token.IdToken;

public interface IdTokenSigner {

    /**
     * Sign the given id token and return the signed token
     * @param idToken id token to be signed
     * @param keyType key type to be used for signing: rsa or ec
     * @return signed token
     */
    String sign(IdToken idToken, String keyType);

    default String sign(IdToken idToken) {
        return sign(idToken, null);
    }

}
