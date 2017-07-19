package com.workingbit.accounts.config;

import org.apache.deltaspike.core.api.config.PropertyFileConfig;

/**
 * Created by Aleksey Popryaduhin on 17:21 17/07/2017.
 */
public class OAuthConfig implements PropertyFileConfig {

    @Override
    public String getPropertyFileName() {
        return "file:./oauth.properties";
    }

    @Override
    public boolean isOptional() {
        return false;
    }
}
