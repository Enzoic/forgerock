package com.enzoic.auth;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.PASSWORD;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import java.io.File;


import static org.mockito.BDDMockito.given;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.node.api.ExternalRequestContext.Builder;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.enzoic.auth.nodes.EnzoicCheckPassword;

public class EnzoicCheckPasswordTest {
	
	
	@Mock
	private CheckCompromisedCredentialsUsingAPI checkCompromisedCredentialsUsingAPI;
	
	@Mock
	private EnzoicCheckPassword.Config config;
	
	@InjectMocks
	EnzoicCheckPassword node;	
	
	@BeforeMethod
    public void before() {
        initMocks(this);
        when(config.Api_Key()).thenReturn("jkffhniafshasiuh");
        when(config.Secret()).thenReturn("jkffhniafshasiuh".toCharArray());


    }
	
	@Test
	public void testTrueOutcome() throws NodeProcessException {
        given(config.CheckCompromisedPasswordOptions()).willReturn(EnzoicCheckPassword.CheckCompromisedPassword.LocalPasswordCheck);

        String inputStream = loadJsonFromResource();
        when(config.LocalPasswordFilePath()).thenReturn(inputStream);
        		
		JsonValue sharedState = json(object(field(USERNAME, "bob")));
        JsonValue transientState = json(object(field(PASSWORD, "Password")));
        
     // When
        Action result = node.process(getContext(sharedState, transientState));

     // Then
        assertThat(result.outcome).isEqualTo("true");
        assertThat(result.callbacks).isEmpty();
	}
	
	@Test
	public void testFalseOutcome() throws NodeProcessException {
        given(config.CheckCompromisedPasswordOptions()).willReturn(EnzoicCheckPassword.CheckCompromisedPassword.LocalPasswordCheck);
		
        String inputStream = loadJsonFromResource();
        
        when(config.LocalPasswordFilePath()).thenReturn(inputStream);
		
		JsonValue sharedState = json(object(field(USERNAME, "bob")));
        JsonValue transientState = json(object(field(PASSWORD, "secret")));
        
     // When
        Action result = node.process(getContext(sharedState, transientState));

     // Then
        assertThat(result.outcome).isEqualTo("false");
        assertThat(result.callbacks).isEmpty();
	}
	
	
	private TreeContext getContext(JsonValue sharedState, JsonValue transientState) {
        return new TreeContext(sharedState, transientState, new Builder().build(), emptyList());
    }
	
	private String loadJsonFromResource() {
		File resourcesDirectory = new File("src/test/resources/password.csv");
		return resourcesDirectory.getAbsolutePath();
	
	}
	
}
