/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.token.encryptor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;

import java.nio.charset.Charset;
import java.util.logging.Logger;

/**
 * Encrypt given value using Crypto Utils.
 */
public class TokenProcessor {
//    private static final Log log = LogFactory.getLog(TokenProcessor.class);
    private static final Logger LOGGER = Logger.getLogger(TokenProcessor.class.getName());

    /**
     * Encrypt and return provided string.
     * @param token
     * @return
     */
    public static String getEncryptedToken(String token) throws Exception {
        LOGGER.info("Encoding : " + token);
        // "eyJ" is common for Base64 JSON Web Tokens
        if (token.startsWith("eyJ") && token.length()>500)  {
            LOGGER.warning("Token has already encrypted. Skipping encryption.");
            LOGGER.info("====================================================");
            return token; // Return the original token without encryption
        }
        byte [] convertedByteToken = token.getBytes(Charset.defaultCharset());
        String convertedToken = CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(convertedByteToken);
        LOGGER.info("Encoded : " + convertedToken);
        return convertedToken;
    }
}
