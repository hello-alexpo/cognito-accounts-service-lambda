//package com.workingbit.accounts.resource;
//
//import com.workingbit.accounts.common.StringMap;
//import com.workingbit.accounts.config.AWSProperties;
//import com.workingbit.accounts.service.AWSCognitoService;
//
//import javax.inject.Inject;
//import javax.ws.rs.Consumes;
//import javax.ws.rs.POST;
//import javax.ws.rs.Path;
//import javax.ws.rs.Produces;
//import javax.ws.rs.core.MediaType;
//
//@Consumes(MediaType.APPLICATION_JSON)
//@Produces(MediaType.APPLICATION_JSON)
//@Path("/users")
//public class UserController {
//
//  private final AWSCognitoService awsCognitoService;
//  private final AWSProperties awsProperties;
//
//  @Inject
//  public UserController(AWSCognitoService awsCognitoService,
//                        AWSProperties awsProperties) {
//    this.awsCognitoService = awsCognitoService;
//    this.awsProperties = awsProperties;
//  }
//
//  @POST
//  @Path("/register")
//  public StringMap register(@RequestBody StringMap credentials) throws Exception {
//    return awsCognitoService.register(
//        credentials.getString(awsProperties.getAttributeUsername()),
//        credentials.getString(awsProperties.getAttributeEmail()),
//        credentials.getString(awsProperties.getAttributePassword())
//    );
//  }
//
//  /**
//   * Register via Facebook
//   * @param credentials Facebook access token
//   * @return AccessToke, IdToken, RefreshToken
//   * @throws Exception
//   */
//  @PostMapping("/registerFacebookUser")
//  public StringMap registerFacebookUser(@RequestBody StringMap credentials) throws Exception {
//    return awsCognitoService.registerFacebookUser(
//        credentials.getString(awsProperties.getFacebookAccessTokenName())
//    );
//  }
//
//  @PostMapping("/confirmRegistration")
//  public StringMap confirmRegistration(@RequestBody StringMap confirmationCode) throws Exception {
//    return awsCognitoService.confirmRegistration(
//        confirmationCode.getString(awsProperties.getAttributeUsername()),
//        confirmationCode.getString(awsProperties.getConfirmationCode())
//    );
//  }
//
//  @PostMapping("/resendCode")
//  public StringMap resendCode(@RequestBody StringMap credentials) throws Exception {
//    return awsCognitoService.resendCode(
//        credentials.getString(awsProperties.getAttributeUsername())
//    );
//  }
//
//  @PostMapping("/forgotPassword")
//  public StringMap forgotPassword(@RequestBody StringMap credentials) throws Exception {
//    return awsCognitoService.forgotPassword(
//        credentials.getString(awsProperties.getAttributeUsername())
//    );
//  }
//
//  @PostMapping("/confirmForgotPassword")
//  public StringMap confirmForgotPassword(@RequestBody StringMap credentials) throws Exception {
//    return awsCognitoService.confirmForgotPassword(
//        credentials.getString(awsProperties.getAttributeUsername()),
//        credentials.getString(awsProperties.getConfirmationCode()),
//        credentials.getString(awsProperties.getAttributePassword())
//    );
//  }
//
//  @PostMapping("/authenticate")
//  public StringMap authenticate(@RequestBody StringMap credentials) throws Exception {
//    return awsCognitoService.authenticateUser(
//        credentials.getString(awsProperties.getAttributeUsername()),
//        credentials.getString(awsProperties.getAttributePassword()));
//  }
//
//  /**
//   * Register via Facebook
//   * @param credentials Facebook access token
//   * @return AccessToke, IdToken, RefreshToken
//   * @throws Exception
//   */
//  @PostMapping("/authenticateFacebookUser")
//  public StringMap authenticateFacebookUser(@RequestBody StringMap credentials) throws Exception {
//    return awsCognitoService.authenticateFacebookUser(
//        credentials.getString(awsProperties.getFacebookAccessTokenName())
//    );
//  }
//
//  @PostMapping("/logout")
//  public StringMap logout(@RequestBody StringMap credentials) {
//    return awsCognitoService.logout(credentials.getString(awsProperties.getAttributeUsername()));
//  }
//}