package com.workingbit.accounts.service;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClient;
import com.amazonaws.services.cognitoidp.model.*;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.workingbit.accounts.common.CommonUtils;
import com.workingbit.accounts.common.StringMap;
import com.workingbit.accounts.config.AWSProperties;
import com.workingbit.accounts.config.OAuthProperties;
import com.workingbit.accounts.exception.DataAccessException;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.*;

import static com.amazonaws.util.Base64.encodeAsString;

/**
 * Created by Aleksey Popryaduhin on 13:33 11/06/2017.
 */
@Singleton
public class AWSCognitoService {

  private final AWSProperties awsProperties;
  private final OAuthProperties oAuthProperties;
  private final com.workingbit.accounts.service.OAuthClientService oAuthClientService;
  private final com.workingbit.accounts.service.DynamoDbService dynamoDbService;

  private final AWSCognitoIdentityProvider awsCognitoIdentityProvider;

  @Inject
  public AWSCognitoService(AWSProperties awsProperties,
                           OAuthProperties oAuthProperties,
                           com.workingbit.accounts.service.OAuthClientService oAuthClientService,
                           com.workingbit.accounts.service.DynamoDbService dynamoDbService) {
    this.awsProperties = awsProperties;
    this.awsCognitoIdentityProvider = AWSCognitoIdentityProviderClient.builder()
        .withRegion(awsProperties.getRegion())
        .build();
    this.oAuthProperties = oAuthProperties;
    this.oAuthClientService = oAuthClientService;
    this.dynamoDbService = dynamoDbService;
  }

  public StringMap register(String username, String email, String password) throws Exception {
    List<AttributeType> userAttributes = new ArrayList<>();
    userAttributes.add(new AttributeType().withName(awsProperties.getAttributeEmail()).withValue(email));
    SignUpRequest signUpRequest = new SignUpRequest()
        .withClientId(awsProperties.getAppClientId())
        .withSecretHash(getSecretHash(username))
        .withUsername(username)
        .withPassword(password)
        .withUserAttributes(userAttributes);
    try {
      awsCognitoIdentityProvider.signUp(signUpRequest);
    } catch (InvalidParameterException e) {
      return createStatusFail("register.FAIL", e.getErrorMessage());
    } catch (UsernameExistsException e) {
      return createStatusFail("register.FAIL", e.getErrorMessage());
    }
    return createStatusOk("register.CONFIRM_EMAIL", "Registration succeed. Confirmation code was sent on your email.");
  }

  public StringMap registerFacebookUser(String facebookAccessToken)
      throws Exception {
    StringMap userDetailsFromFacebook = oAuthClientService.getUserDetailsFromFacebook(facebookAccessToken);
    return adminCreateUser(userDetailsFromFacebook);
  }

  public StringMap confirmRegistration(String username, String confirmationCode) throws Exception {
    ConfirmSignUpRequest confirmSignUpRequest = new ConfirmSignUpRequest()
        .withClientId(awsProperties.getAppClientId())
        .withSecretHash(getSecretHash(username))
        .withUsername(username)
        .withSecretHash(getSecretHash(username))
        .withConfirmationCode(confirmationCode);
    try {
      awsCognitoIdentityProvider.confirmSignUp(confirmSignUpRequest);
    } catch (UserNotFoundException e) {
      return createStatusFail("confirmRegistration.FAIL", e.getErrorMessage());
    } catch (ExpiredCodeException e) {
      return createStatusFail("confirmRegistration.FAIL", e.getErrorMessage());
    }
    return createStatusOk("confirmRegistration.CONFIRMED", "Registration confirmed");
  }

  public StringMap resendCode(String username) throws Exception {
    ResendConfirmationCodeRequest resendConfirmationCodeRequest = new ResendConfirmationCodeRequest()
        .withClientId(awsProperties.getAppClientId())
        .withSecretHash(getSecretHash(username))
        .withUsername(username);
    try {
      awsCognitoIdentityProvider.resendConfirmationCode(resendConfirmationCodeRequest);
    } catch (InvalidParameterException e) {
      return createStatusFail("resendCode.FAIL", e.getErrorMessage());
    }
    return createStatusOk("resendCode.SENT", "Code resent");
  }

  public StringMap authenticateUser(String username, String password) throws Exception {
    if (StringUtils.isBlank(username) || StringUtils.isBlank(password)) {
      return createStatusFail("authenticateUser.INVALID_PARAMS");
    }
    Map<String, String> authParameters = new HashMap<>();
    authParameters.put("USERNAME", username);
    authParameters.put("PASSWORD", password);
    authParameters.put("SECRET_HASH", getSecretHash(username));
    AdminInitiateAuthRequest adminInitiateAuthRequest = new AdminInitiateAuthRequest()
        .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
        .withClientId(awsProperties.getAppClientId())
        .withUserPoolId(awsProperties.getUserPoolId())
        .withAuthParameters(authParameters);

    AdminInitiateAuthResult adminInitiateAuthResult = awsCognitoIdentityProvider.adminInitiateAuth(adminInitiateAuthRequest);
    if (Objects.equals(adminInitiateAuthResult.getChallengeName(), ChallengeNameType.NEW_PASSWORD_REQUIRED.name())) {
      return createStatusFail("authenticateUser.NEW_PASSWORD_REQUIRED");
    }
    AuthenticationResultType authenticationResult = adminInitiateAuthResult.getAuthenticationResult();
    return createStatusOk("authenticate.AUTHENTICATED", saveAuthenticationTokens(username, authenticationResult));
  }

  /**
   * Set permanent password for a user and sign he up
   *
   * @param username
   * @param password
   * @param tempPassword
   * @return AccessToke, IdToken, RefreshToken
   * @throws Exception
   */
  public StringMap authenticateNewUser(String username, String password, String tempPassword) throws Exception {
    if (StringUtils.isBlank(username) || StringUtils.isBlank(tempPassword) || StringUtils.isBlank(password)) {
      return createStatusFail("authenticateNewUser.INVALID_PARAMS");
    }

    Map<String, String> authParams = new HashMap<>();
    authParams.put("USERNAME", username);
    authParams.put("PASSWORD", tempPassword);
    authParams.put("SECRET_HASH", getSecretHash(username));

    AdminInitiateAuthRequest initialRequest = new AdminInitiateAuthRequest()
        .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
        .withAuthParameters(authParams)
        .withClientId(awsProperties.getAppClientId())
        .withUserPoolId(awsProperties.getUserPoolId());

    AdminInitiateAuthResult initialResponse = awsCognitoIdentityProvider.adminInitiateAuth(initialRequest);
    if (!ChallengeNameType.NEW_PASSWORD_REQUIRED.name().equals(initialResponse.getChallengeName())) {
      return createStatusFail("authenticateNewUser.MISMATCH_CHALLENGE", initialResponse.getChallengeName());
    }

    Map<String, String> challengeResponses = new HashMap<>();
    challengeResponses.put("USERNAME", username);
    challengeResponses.put("PASSWORD", tempPassword);
    challengeResponses.put("NEW_PASSWORD", password);
    challengeResponses.put("SECRET_HASH", getSecretHash(username));

    AdminRespondToAuthChallengeRequest finalRequest = new AdminRespondToAuthChallengeRequest()
        .withChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
        .withChallengeResponses(challengeResponses)
        .withClientId(awsProperties.getAppClientId())
        .withUserPoolId(awsProperties.getUserPoolId())
        .withSession(initialResponse.getSession());

    AdminRespondToAuthChallengeResult challengeResponse = awsCognitoIdentityProvider.adminRespondToAuthChallenge(finalRequest);
    if (StringUtils.isBlank(challengeResponse.getChallengeName())) {
      return createStatusOk("authenticateNewUser.AUTHENTICATED",
          saveAuthenticationTokens(username, challengeResponse.getAuthenticationResult()));
    } else {
      throw new RuntimeException("unexpected challenge: " + challengeResponse.getChallengeName());
    }
  }

  public StringMap authenticateFacebookUser(String facebookAccessToken) throws Exception {
    // get user from Facebook by access_token
    StringMap userFromFacebook = oAuthClientService.getUserDetailsFromFacebook(facebookAccessToken);
    String username = userFromFacebook.getString(awsProperties.getAttributeEmail());
    // retrieve user from db to get his tokens
    Map<String, AttributeValue> userFromDb = dynamoDbService.retrieveByUsername(username);
    GetUserRequest getUserRequest;
    GetUserResult user;
    try {
      // get user by access token
      getUserRequest = new GetUserRequest()
          .withAccessToken(userFromDb.get(awsProperties.getUserAccessToken()).getS());
      user = awsCognitoIdentityProvider.getUser(getUserRequest);
      if (user == null) {
        throw new NotAuthorizedException("authenticateFacebookUser.FAIL");
      }
    } catch (NotAuthorizedException e) {
      // access token is expired. Refresh it using refresh token
      StringMap authTokens;
      try {
        authTokens = refreshToken(username, userFromDb.get(awsProperties.getRefreshToken()).getS());

        getUserRequest = new GetUserRequest()
            .withAccessToken(authTokens.getString(awsProperties.getUserAccessToken()));
        // update user tokens
        dynamoDbService.storeUserWithAuthTokens(username, true, authTokens);
        user = awsCognitoIdentityProvider.getUser(getUserRequest);
        if (user == null) {
          throw new NotAuthorizedException("authenticateFacebookUser.FAIL");
        }
      } catch (UserNotFoundException ex) {
        return createStatusFail("authenticateFacebookUser.FAIL", ex.getErrorMessage());
      } catch (NotAuthorizedException ex) {
        // refresh token has been revoked
        ex.printStackTrace();
      }
      // get user using new access token
    } catch (UserNotFoundException ex) {
      return createStatusFail("authenticateFacebookUser.FAIL", ex.getErrorMessage());
    }

    // authenticate with stored password
    String password = userFromDb.get(awsProperties.getAttributePassword()).getS() + oAuthProperties.getTempPasswordSecret();
    return authenticateUser(username, password);
  }

  private StringMap refreshToken(String username, String refreshToken) throws Exception {
    Map<String, String> authParameters = new HashMap<>();
    authParameters.put("REFRESH_TOKEN", refreshToken);
    authParameters.put("SECRET_HASH", getSecretHash(username));
    AdminInitiateAuthRequest adminInitiateAuthRequest = new AdminInitiateAuthRequest()
        .withAuthFlow(AuthFlowType.REFRESH_TOKEN_AUTH)
        .withClientId(awsProperties.getAppClientId())
        .withUserPoolId(awsProperties.getUserPoolId())
        .withAuthParameters(authParameters);
    AdminInitiateAuthResult adminInitiateAuthResult = awsCognitoIdentityProvider.adminInitiateAuth(adminInitiateAuthRequest);
    return saveAuthenticationTokens(username, adminInitiateAuthResult.getAuthenticationResult());
  }

  public StringMap forgotPassword(String username) throws Exception {
    ForgotPasswordRequest forgotPasswordRequest = new ForgotPasswordRequest()
        .withClientId(awsProperties.getAppClientId())
        .withUsername(username)
        .withSecretHash(getSecretHash(username));
    awsCognitoIdentityProvider.forgotPassword(forgotPasswordRequest);
    return createStatusOk("forgotPassword.SENT", "Password reminded");
  }

  public StringMap confirmForgotPassword(String username, String confirmation, String password) throws Exception {
    ConfirmForgotPasswordRequest confirmForgotPasswordRequest = new ConfirmForgotPasswordRequest()
        .withClientId(awsProperties.getAppClientId())
        .withUsername(username)
        .withConfirmationCode(confirmation)
        .withSecretHash(getSecretHash(username))
        .withPassword(password);
    awsCognitoIdentityProvider.confirmForgotPassword(confirmForgotPasswordRequest);
    return createStatusOk("confirmForgotPassword.CHANGED", "Password confirmed");
  }

  public StringMap logout(String username) {
    AdminUserGlobalSignOutRequest adminUserGlobalSignOutRequest = new AdminUserGlobalSignOutRequest()
        .withUserPoolId(awsProperties.getUserPoolId())
        .withUsername(username);
    awsCognitoIdentityProvider.adminUserGlobalSignOut(adminUserGlobalSignOutRequest);
    return createStatusOk("logout.SUCCESS", "User is logged out");
  }

  private String getSecretHash(String username) throws Exception {
    String appClientId = awsProperties.getAppClientId(),
        appSecretKey = awsProperties.getAppClientSecret();
    byte[] data = (username + appClientId).getBytes("UTF-8");
    byte[] key = appSecretKey.getBytes("UTF-8");

    return encodeAsString(hmacSHA256(data, key));
  }

  private byte[] hmacSHA256(byte[] data, byte[] key) throws Exception {
    String algorithm = "HmacSHA256";
    Mac mac = Mac.getInstance(algorithm);
    mac.init(new SecretKeySpec(key, algorithm));
    return mac.doFinal(data);
  }

  private StringMap createStatusOk(String code, String message) {
    StringMap resp = new StringMap();
    resp.put(awsProperties.getStatus(), awsProperties.getStatusOk());
    resp.put(awsProperties.getStatusCode(), code);
    resp.put(awsProperties.getStatusMessage(), message);
    return resp;
  }

  private StringMap createStatusOk(String code, StringMap data) {
    StringMap resp = new StringMap();
    resp.put(awsProperties.getStatus(), awsProperties.getStatusOk());
    resp.put(awsProperties.getStatusCode(), code);
    resp.put(awsProperties.getStatusMessage(), CommonUtils.convertMapToJSON(data));
    return resp;
  }

  private StringMap createStatusFail(String message) {
    StringMap resp = new StringMap();
    resp.put(awsProperties.getStatus(), awsProperties.getStatusFail());
    resp.put(awsProperties.getStatusMessage(), message);
    return resp;
  }

  private StringMap createStatusFail(String code, String message) {
    StringMap resp = new StringMap();
    resp.put(awsProperties.getStatus(), awsProperties.getStatusFail());
    resp.put(awsProperties.getStatusCode(), code);
    resp.put(awsProperties.getStatusMessage(), message);
    return resp;
  }

  private StringMap saveAuthenticationTokens(String username, AuthenticationResultType authenticationResult) throws DataAccessException {
    Map<String, Object> authTokens = new HashMap<>();
    authTokens.put(awsProperties.getUserAccessToken(), authenticationResult.getAccessToken());
    authTokens.put(awsProperties.getUserIdToken(), authenticationResult.getIdToken());
    authTokens.put(awsProperties.getRefreshToken(), authenticationResult.getRefreshToken());
    dynamoDbService.storeUserWithAuthTokens(username, true, CommonUtils.cleanseMap(authTokens));

    // don't reveal refresh token to out
    authTokens.remove(awsProperties.getRefreshToken());

    // return tokens and username
    StringMap resp = new StringMap();
    resp.putAll(authTokens);
    resp.put(awsProperties.getAttributeUsername(), username);
    return resp;
  }

  private StringMap adminCreateUser(StringMap userDetailsFromFacebook) throws Exception {
    List<AttributeType> userAttributes = new ArrayList<>();
    userAttributes.add(new AttributeType()
        .withName(awsProperties.getAttributeEmail())
        .withValue(userDetailsFromFacebook.getString("email")));
    userAttributes.add(new AttributeType()
        .withName("email_verified")
        .withValue("True"));
    userAttributes.add(new AttributeType()
        .withName(awsProperties.getAttributeGivenName())
        .withValue(userDetailsFromFacebook.getString("first_name")));
    userAttributes.add(new AttributeType()
        .withName(awsProperties.getAttributeFamilyName())
        .withValue(userDetailsFromFacebook.getString("last_name")));
    userAttributes.add(new AttributeType()
        .withName(awsProperties.getAttributeFamilyName())
        .withValue(userDetailsFromFacebook.getString("gender")));
    userAttributes.add(new AttributeType()
        .withName(awsProperties.getAttributeLocale())
        .withValue(userDetailsFromFacebook.getString("locale")));
    userAttributes.add(new AttributeType()
        .withName(awsProperties.getAttributePicture())
        .withValue(userDetailsFromFacebook.getString("picture")));
    userAttributes.add(new AttributeType()
        .withName(awsProperties.getAttributeBirthday())
        .withValue(userDetailsFromFacebook.getString("birthday")));
    String email = userDetailsFromFacebook.getString("email");
    String tempPassword = RandomStringUtils.random(90, oAuthProperties.getAsd());
    AdminCreateUserRequest adminCreateUserRequest = new AdminCreateUserRequest()
        .withUsername(email)
        .withTemporaryPassword(tempPassword)
        .withMessageAction(MessageActionType.SUPPRESS)
        .withUserPoolId(awsProperties.getUserPoolId())
        .withUserAttributes(userAttributes);
    try {
      awsCognitoIdentityProvider.adminCreateUser(adminCreateUserRequest);
    } catch (UsernameExistsException e) {
      return createStatusFail("adminCreateUser.FAIL", e.getErrorMessage());
    }
    dynamoDbService.storeUser(email, tempPassword);

    String permPassword = tempPassword + oAuthProperties.getTempPasswordSecret();
    return authenticateNewUser(email, permPassword, tempPassword);
  }
}
