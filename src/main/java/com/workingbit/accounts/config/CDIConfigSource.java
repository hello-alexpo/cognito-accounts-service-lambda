package com.workingbit.accounts.config;

import org.apache.deltaspike.core.api.config.Source;
import org.apache.deltaspike.core.api.projectstage.ProjectStage;
import org.apache.deltaspike.core.spi.config.ConfigSource;

import java.util.HashMap;
import java.util.Map;

/**
 * Implementation of Deltaspike ConfigSource to set the ProjectStage based off an "environment" variable
 */
@Source
public class CDIConfigSource implements ConfigSource {

    private final Map<String, ProjectStage> mapping;
    private final Map<String, String> properties;

    public CDIConfigSource() {
        this.mapping = new HashMap<>();
        this.mapping.put("development", ProjectStage.Development);
        this.mapping.put("test", ProjectStage.UnitTest);
        this.mapping.put("staging", ProjectStage.Staging);
        this.mapping.put("production", ProjectStage.Production);

        this.properties = new HashMap<>();
        String env = System.getenv("DELTASPIKE_PROJECT_STAGE");
        if (env == null || env.trim().length() == 0) {
            env = "development";
        }
        env = this.mapping.get(env).getClass().getSimpleName();
        properties.put("org.apache.deltaspike.ProjectStage", env);
    }

    @Override
    public int getOrdinal() {
        return 500;
    }

    @Override
    public Map<String, String> getProperties() {
        return this.properties;
    }

    @Override
    public String getPropertyValue(String string) {
        return this.properties.get(string);
    }

    @Override
    public String getConfigName() {
        return "cdiConfigSource";
    }

    @Override
    public boolean isScannable() {
        return false;
    }
}