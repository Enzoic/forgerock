package com.enzoic.auth;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.test.assertj.AssertJJsonValueAssert.assertThat;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.PASSWORD;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.MockitoAnnotations.initMocks;

import java.security.PrivilegedAction;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext.Builder;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.identity.idm.IdentityUtils;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.enzoic.auth.nodes.EnzoicSaveNewPassword;
import com.google.inject.Provider;
import com.iplanet.sso.SSOToken;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdType;

public class EnzoicSaveNewPasswordTest {
    @Mock
    CoreWrapper coreWrapper;

    @Mock
    AMIdentityRepository identityRepository;

    @Mock
    IdentityUtils identityUtils;

    @Mock
    Provider<PrivilegedAction<SSOToken>> adminTokenActionProvider;

    @InjectMocks
    EnzoicSaveNewPassword node;

    @Mock
    AMIdentity amIdentity;

    @Mock
    SSOToken adminToken;

    @BeforeMethod
    public void setup() throws Exception {
        node = null;
        initMocks(this);
        given(coreWrapper.convertRealmPathToRealmDn(any())).willReturn("org=name");
        given(coreWrapper.getAMIdentityRepository(any())).willReturn(identityRepository);
        given(amIdentity.isActive()).willReturn(true);
        given(identityUtils.getAmIdentity(any(SSOToken.class), any(String.class), eq(IdType.USER), any()))
                .willReturn(amIdentity);
        given(adminTokenActionProvider.get()).willReturn(() -> adminToken);
    }

    @Test
    public void testProcessPassesUsernameAndPasswordToIdentityRepository() throws Exception {
        // Given
        given(identityRepository.authenticate(any(Callback[].class))).willReturn(true);
        JsonValue sharedState = json(object(field(USERNAME, "bob")));
        JsonValue transientState = json(object(field(PASSWORD, "secret")));

        // When
        node.process(getContext(sharedState, transientState));

        // Then
        ArgumentCaptor<Callback[]> callbacksCaptor = ArgumentCaptor.forClass(Callback[].class);
        verify(identityRepository).authenticate(eq(IdType.USER), callbacksCaptor.capture());
        Callback[] callbacks = callbacksCaptor.getValue();
        assertThat(callbacks.length).isEqualTo(2);
        assertThat(callbacks[0]).isInstanceOf(NameCallback.class);
        assertThat(((NameCallback) callbacks[0]).getName()).isEqualTo("bob");
        assertThat(callbacks[1]).isInstanceOf(PasswordCallback.class);
        assertThat(((PasswordCallback) callbacks[1]).getPassword()).isEqualTo("secret".toCharArray());
    }

    @Test
    public void testProcessWithNoCallbacksReturnsTrueIfAuthenticationIsSuccessful() throws Exception {
        // Given
        given(identityRepository.authenticate(eq(IdType.USER), any(Callback[].class))).willReturn(true);
        JsonValue sharedState = json(object(field(USERNAME, "bob")));
        JsonValue transientState = json(object(field(PASSWORD, "secret")));

        // When
        Action result = node.process(getContext(sharedState, transientState));

        // Then
        assertThat(result.outcome).isEqualTo("true");
        assertThat(result.callbacks).isEmpty();
        assertThat(result.sharedState).isObject().containsExactly(entry(USERNAME, "bob"));
        assertThat(sharedState).isObject().containsExactly(entry(USERNAME, "bob"));
        assertThat(transientState).isObject().containsExactly(entry(PASSWORD, "secret"));
    }

    @Test
    public void testProcessWithNoCallbacksReturnsFalseIfAuthenticationIsNotSuccessful() throws Exception {
        // Given
        given(identityRepository.authenticate(any(Callback[].class))).willReturn(false);
        JsonValue sharedState = json(object(field(USERNAME, "bob")));
        JsonValue transientState = json(object(field(PASSWORD, "secret")));

        // When
        Action result = node.process(getContext(sharedState, transientState));

        // Then
        assertThat(result.outcome).isEqualTo("false");
        assertThat(result.callbacks).isEmpty();
        assertThat(result.sharedState).isObject().containsExactly(entry(USERNAME, "bob"));
        assertThat(sharedState).isObject().containsExactly(entry(USERNAME, "bob"));
        assertThat(transientState).isObject().containsExactly(entry(PASSWORD, "secret"));
    }

    private TreeContext getContext(JsonValue sharedState, JsonValue transientState) {
        return new TreeContext(sharedState, transientState, new Builder().build(), emptyList());
    }
}
