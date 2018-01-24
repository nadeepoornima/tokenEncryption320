package org.wso2.carbon.token.encryptor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;

import java.nio.charset.Charset;

public class TokenProcessor {
    private static final Log log = LogFactory.getLog(TokenProcessor.class);

    public static String getEncryptedToken(String token) {
        log.debug("Encoding : " + token);
        byte [] convertedByteToken = token.getBytes(Charset.defaultCharset());
        try {
            String convertedToken = CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(convertedByteToken);
            log.debug("Encoded : " + convertedToken);
            return convertedToken;
        } catch (CryptoException e) {
            log.error("Unable to perform encoding");
            e.printStackTrace();
            return null;
        }
    }
}
