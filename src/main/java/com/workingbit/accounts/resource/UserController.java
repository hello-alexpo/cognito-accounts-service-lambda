package com.workingbit.accounts.resource;

import com.workingbit.accounts.common.StringMap;
import com.workingbit.accounts.config.AWSProperties;
import com.workingbit.accounts.service.AWSCognitoService;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@Path("/users")
public class UserController {

  private final AWSCognitoService awsCognitoService;
  private final AWSProperties awsProperties;

  @Inject
  public UserController(AWSCognitoService awsCognitoService,
                        AWSProperties awsProperties) {
    this.awsCognitoService = awsCognitoService;
    this.awsProperties = awsProperties;
  }

  @POST
  @Path("/register")
  public StringMap register(StringMap credentials) throws Exception {
    return awsCognitoService.register(
        credentials.getString(awsProperties.getAttributeUsername()),
        credentials.getString(awsProperties.getAttributeEmail()),
        credentials.getString(awsProperties.getAttributePassword())
    );
  }

  /**
   * Register via Facebook
   * @param credentials Facebook access token
   * @return AccessToke, IdToken, RefreshToken
   * @throws Exception
   */
  @POST
  @Path("/registerFacebookUser")
  public StringMap registerFacebookUser(StringMap credentials) throws Exception {
    return awsCognitoService.registerFacebookUser(
        credentials.getString(awsProperties.getFacebookAccessTokenName())
    );
  }

  @POST
  @Path("/confirmRegistration")
  public StringMap confirmRegistration(StringMap confirmationCode) throws Exception {
    return awsCognitoService.confirmRegistration(
        confirmationCode.getString(awsProperties.getAttributeUsername()),
        confirmationCode.getString(awsProperties.getConfirmationCode())
    );
  }

  @POST
  @Path("/resendCode")
  public StringMap resendCode(StringMap credentials) throws Exception {
    return awsCognitoService.resendCode(
        credentials.getString(awsProperties.getAttributeUsername())
    );
  }

  @POST
  @Path("/forgotPassword")
  public StringMap forgotPassword(StringMap credentials) throws Exception {
    return awsCognitoService.forgotPassword(
        credentials.getString(awsProperties.getAttributeUsername())
    );
  }

  @POST
  @Path("/confirmForgotPassword")
  public StringMap confirmForgotPassword(StringMap credentials) throws Exception {
    return awsCognitoService.confirmForgotPassword(
        credentials.getString(awsProperties.getAttributeUsername()),
        credentials.getString(awsProperties.getConfirmationCode()),
        credentials.getString(awsProperties.getAttributePassword())
    );
  }

  @POST
  @Path("/authenticate")
  public StringMap authenticate(StringMap credentials) throws Exception {
    return awsCognitoService.authenticateUser(
        credentials.getString(awsProperties.getAttributeUsername()),
        credentials.getString(awsProperties.getAttributePassword()));
  }

  /**
   * Register via Facebook
   * @param credentials Facebook access token
   * @return AccessToke, IdToken, RefreshToken
   * @throws Exception
   */
  @POST
  @Path("/authenticateFacebookUser")
  public StringMap authenticateFacebookUser(StringMap credentials) throws Exception {
    return awsCognitoService.authenticateFacebookUser(
        credentials.getString(awsProperties.getFacebookAccessTokenName())
    );
  }

  @POST
  @Path("/logout")
  public StringMap logout(StringMap credentials) {
    return awsCognitoService.logout(credentials.getString(awsProperties.getAttributeUsername()));
  }
}