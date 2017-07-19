package com.workingbit.accounts.config;

import org.apache.deltaspike.core.api.config.PropertyFileConfig;

/**
 * Created by Aleksey Popryaduhin on 17:20 17/07/2017.
 */
public class AWSConfig implements PropertyFileConfig {
    @Override
    public String getPropertyFileName() {
        return "file:./aws.properties";
    }

    @Override
    public boolean isOptional() {
        return false;
    }
}
