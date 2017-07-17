package com.workingbit.accounts.config;

import lombok.Getter;
import org.apache.deltaspike.core.api.config.ConfigProperty;

import javax.inject.Inject;
import javax.inject.Singleton;

/**
 * Created by Aleksey Popryaduhin on 08:57 11/06/2017.
 */
@Singleton
public class OAuthProperties {

    @Inject
    @ConfigProperty(name = "FB_FIELDS")
    private @Getter
    String fbFields;

    @Inject
    @ConfigProperty(name = "FB_API_GRAPH")
    private @Getter
    String fbApiGraph;

    @Inject
    @ConfigProperty(name = "TEMP_PASSWORD_SECRET")
    private @Getter
    String tempPasswordSecret;

    private @Getter
    char[] asd = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'G', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '{', '}', '[', ']', ':', ':', '\\', '/', '|', '.', ',', '?', '"', '\'', '`'};//Alphabet&Digit

}
