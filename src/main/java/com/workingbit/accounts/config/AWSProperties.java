package com.workingbit.accounts.config;

import lombok.Getter;
import org.apache.deltaspike.core.api.config.ConfigProperty;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 * Created by Aleksey Popryaduhin on 08:57 11/06/2017.
 */
@ApplicationScoped
public class AWSProperties {

    @Inject
    @ConfigProperty(name = "CLIENT_ID")
    private @Getter
    String clientId;

    @Inject
    @ConfigProperty(name = "REGION")
    private @Getter
    String region;

    @Inject
    @ConfigProperty(name = "USER_POOL_ID")
    private @Getter
    String userPoolId;

    @Inject
    @ConfigProperty(name = "APP_CLIENT_ID")
    private @Getter
    String appClientId;

    @Inject
    @ConfigProperty(name = "APP_CLIENT_SECRET")
    private @Getter
    String appClientSecret;

    @Inject
    @ConfigProperty(name = "IDENTITY_POOL_ID")
    private @Getter
    String identityPoolId;

    @Inject
    @ConfigProperty(name = "COGNITO_USER_POOL_NAME")
    private @Getter
    String cognitoUserPoolName;


    @Inject
    @ConfigProperty(name = "USER_TABLE")
    private @Getter
    String userTable;

    @Inject
    @ConfigProperty(name = "READ_CAPACITY_UNITS")
    private @Getter
    Long readCapacityUnits;

    @Inject
    @ConfigProperty(name = "WRITE_CAPACITY_UNITS")
    private @Getter
    Long writeCapacityUnits;


    @Inject
    @ConfigProperty(name = "ATTRIBUTE_UID")
    private @Getter
    String attributeUid;

    @Inject
    @ConfigProperty(name = "ATTRIBUTE_EMAIL")
    private @Getter
    String attributeEmail;

    @Inject
    @ConfigProperty(name = "ATTRIBUTE_USERNAME")
    private @Getter
    String attributeUsername;

    @Inject
    @ConfigProperty(name = "ATTRIBUTE_PASSWORD")
    private @Getter
    String attributePassword;

    @Inject
    @ConfigProperty(name = "ATTRIBUTE_GIVEN_NAME")
    private @Getter
    String attributeGivenName;

    @Inject
    @ConfigProperty(name = "ATTRIBUTE_FAMILY_NAME")
    private @Getter
    String attributeFamilyName;

    @Inject
    @ConfigProperty(name = "ATTRIBUTE_IDENTITY_ID")
    private @Getter
    String attributeIdentityId;

    @Inject
    @ConfigProperty(name = "ATTRIBUTE_ENABLED")
    private @Getter
    String attributeEnabled;

    @Inject
    @ConfigProperty(name = "ATTRIBUTE_GENDER")
    private @Getter
    String attributeGender;

    @Inject
    @ConfigProperty(name = "ATTRIBUTE_LOCALE")
    private @Getter
    String attributeLocale;

    @Inject
    @ConfigProperty(name = "ATTRIBUTE_PICTURE")
    private @Getter
    String attributePicture;

    @Inject
    @ConfigProperty(name = "ATTRIBUTE_BIRTHDAY")
    private @Getter
    String attributeBirthday;


    private @Getter
    String status = "ok";

    private @Getter
    Boolean statusOk = true;

    private @Getter
    Boolean statusFail = false;

    private @Getter
    String statusMessage = "message";

    private @Getter
    String statusCode = "code";

    @Inject
    @ConfigProperty(name = "CONFIRMATION_CODE")
    private @Getter
    String confirmationCode;


    @Inject
    @ConfigProperty(name = "AWS_SESSION_TOKEN")
    private @Getter
    String awsSessionToken;

    @Inject
    @ConfigProperty(name = "AWS_ACCESS_KEY_ID")
    private @Getter
    String awsAccessKeyId;

    @Inject
    @ConfigProperty(name = "AWS_SECRET_KEY")
    private @Getter
    String awsSecretKey;


    @Inject
    @ConfigProperty(name = "USER_ACCESS_TOKEN")
    private @Getter
    String userAccessToken;

    @Inject
    @ConfigProperty(name = "USER_REFRESH_TOKEN")
    private @Getter
    String refreshToken;

    @Inject
    @ConfigProperty(name = "USER_ID_TOKEN")
    private @Getter
    String userIdToken;


    @Inject
    @ConfigProperty(name = "FACEBOOK_PROVIDER_NAME")
    private @Getter
    String facebookProviderName;

    @Inject
    @ConfigProperty(name = "FACEBOOK_ACCESS_TOKEN_NAME")
    private @Getter
    String facebookAccessTokenName;
}
