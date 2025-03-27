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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;


/**
 * Class to manipulate db related operations.
 */
public class DbUtils {

//    private static final Log log = LogFactory.getLog(DbUtils.class);
    private static final Logger LOGGER = Logger.getLogger(DbUtils.class.getName());

    /**
     * Select data from database, Related to consumer secrete.
     */
    private final String selectQueryOauthApps = "SELECT CONSUMER_KEY, CONSUMER_SECRET FROM IDN_OAUTH_CONSUMER_APPS";

    /**
     * Update query to save encrypted consumer secrete.
     */
    private final String updateQueryOauthApps = "UPDATE IDN_OAUTH_CONSUMER_APPS SET CONSUMER_SECRET = ? WHERE CONSUMER_KEY = ?";

    /**
     * Select query for access token and refresh tokens.
     */
    private final String selectQueryAccessTokens = "SELECT TOKEN_ID, ACCESS_TOKEN, REFRESH_TOKEN FROM IDN_OAUTH2_ACCESS_TOKEN";

    /**
     * Update query to save encrypted client access and refresh token.
     */
    private final String updateQueryAccessTokens = "UPDATE IDN_OAUTH2_ACCESS_TOKEN SET ACCESS_TOKEN = ?, REFRESH_TOKEN = ? WHERE TOKEN_ID = ?";

    /**
     * Database connection.
     */
    private Connection databaseConnection;

    /**
     * Constructor.
     * @param databaseConnection
     */
    public DbUtils(Connection databaseConnection) {

        this.databaseConnection = databaseConnection;
    }

    /**
     * Get tokens from database.
     * @return
     */
    public List<IdnAccessToken> getAccessTokenList()
    {
        try {
            Statement statement = databaseConnection.createStatement();
            ResultSet resultSet = statement.executeQuery(selectQueryAccessTokens);
            List<IdnAccessToken> accessTokens = new ArrayList<>();
            while(resultSet.next())
            {
                IdnAccessToken temp = new IdnAccessToken();
                temp.setId(resultSet.getString("TOKEN_ID"));
                temp.setAccessToken(resultSet.getString("ACCESS_TOKEN"));
                temp.setRefreshToken(resultSet.getString("REFRESH_TOKEN"));
                accessTokens.add(temp);
            }
            return accessTokens;
        } catch (SQLException e) {
            LOGGER.info("Error: Unable to execute query");
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Get list of applications with client secret.
     * @return
     */
    public List<IdnOauthApplication> getOauthAppsList()
    {
        try {
            Statement statement = databaseConnection.createStatement();
            ResultSet resultSet = statement.executeQuery(selectQueryOauthApps);
            List<IdnOauthApplication> apps = new ArrayList<>();
            while(resultSet.next())
            {
                IdnOauthApplication temp = new IdnOauthApplication();
                temp.setId(resultSet.getString("CONSUMER_KEY"));
                temp.setClientSecreat(resultSet.getString("CONSUMER_SECRET"));
                apps.add(temp);
            }
            return apps;
        } catch (SQLException e) {
            LOGGER.info("Error: Unable to execute query");
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Encrypt and save client secrets.
     * @param idnOauthApplicationList
     * @throws SQLException
     */
    public void saveClientSecret(List<IdnOauthApplication> idnOauthApplicationList) throws SQLException {
        try {
            PreparedStatement statement = databaseConnection.prepareStatement(updateQueryOauthApps);
            for(IdnOauthApplication tempapp : idnOauthApplicationList) {
                String convertedToken = null;
                try {
                    convertedToken = TokenProcessor.getEncryptedToken(tempapp.getClientSecreat());
                    databaseConnection.setAutoCommit(false);
                    statement.setString(1,convertedToken);
                    statement.setString(2,tempapp.getId());
                    statement.addBatch();
                } catch (Exception e) {
                    LOGGER.info("Error: Unable to encrypt Client secrets ");
                    e.printStackTrace();
                    databaseConnection.rollback();
                }
            }
            int [] execution = statement.executeBatch();
            databaseConnection.commit();
            LOGGER.info("Client Secrets Converted :" +execution);
        } catch (SQLException e) {
            LOGGER.info("Unable to update Client secrets ");
            e.printStackTrace();
            databaseConnection.rollback();
        }
    }

    /**
     * Encrypt and save access and refresh tokens.
     * @param idnAccessTokens
     * @throws SQLException
     */
    public void saveApplicationTokens(List<IdnAccessToken> idnAccessTokens) throws SQLException {
        try {
            PreparedStatement statement = databaseConnection.prepareStatement(updateQueryAccessTokens);
            for(IdnAccessToken temptokens : idnAccessTokens) {
                try {
                    String convertedaccessToken = TokenProcessor.getEncryptedToken(temptokens.getAccessToken());
                    String convertedrefreshToken = TokenProcessor.getEncryptedToken(temptokens.getRefreshToken());
                    databaseConnection.setAutoCommit(false);
                    statement.setString(1,convertedaccessToken);
                    statement.setString(2,convertedrefreshToken);
                    statement.setString(3,temptokens.getId());
                    statement.addBatch();
                } catch (Exception e) {
                    LOGGER.info("Error: Unable to encrypt Client secrets ");
                    e.printStackTrace();
                }
            }
            int [] execution = statement.executeBatch();
            databaseConnection.commit();
            LOGGER.info("Tokens Converted :" +execution);
        } catch (SQLException e) {
            LOGGER.info("Error: Unable to update Tokens ");
            databaseConnection.rollback();
            e.printStackTrace();
        }
    }

}
