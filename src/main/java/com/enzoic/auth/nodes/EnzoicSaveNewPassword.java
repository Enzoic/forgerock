package com.enzoic.auth.nodes;

import static com.enzoic.auth.Constants.OLD_PASSWORD;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.PASSWORD;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.identity.idm.IdentityUtils;
import org.forgerock.openam.idrepo.ldap.IdentityNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.Inject;
import com.google.inject.Provider;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.InvalidPasswordException;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;

import java.security.AccessController;
import java.security.PrivilegedAction;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;


/**
 * @author Sacumen (www.sacumen.com)
 * Enzoic Save Password Node with true and false outcome.
 * Saves new password to Identity Repository.
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = EnzoicSaveNewPassword.Config.class)
public class EnzoicSaveNewPassword extends AbstractDecisionNode {

    private final CoreWrapper coreWrapper;
    private final IdentityUtils identityUtils;
    private final Provider<PrivilegedAction<SSOToken>> adminTokenActionProvider;

    private final Logger logger = LoggerFactory.getLogger(EnzoicSaveNewPassword.class);


    /**
     * Configuration for the data store node.
     */
    public interface Config {
    }

    /**
     * Guice constructor.
     *
     * @param coreWrapper              A core wrapper instance.
     * @param identityUtils            A {@code IdentityUtils} instance.
     * @param adminTokenActionProvider A provider for an {@code SSOToken}.
     */
    @Inject
    public EnzoicSaveNewPassword(CoreWrapper coreWrapper, IdentityUtils identityUtils,
                                 Provider<PrivilegedAction<SSOToken>> adminTokenActionProvider) {
        this.coreWrapper = coreWrapper;
        this.identityUtils = identityUtils;
        this.adminTokenActionProvider = adminTokenActionProvider;
    }

    /**
     * Execution of the node starts from here.
     */
    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        logger.info("Enzoic save password started");

        //Saving new password
        updatePassword(context);

        //Authenticating new password.
        AMIdentityRepository idrepo = coreWrapper.getAMIdentityRepository(
                coreWrapper.convertRealmPathToRealmDn(context.sharedState.get(REALM).asString()));

        logger.info("AMIdentityRepository claimed");

        NameCallback nameCallback = new NameCallback("notused");
        nameCallback.setName(context.sharedState.get(USERNAME).asString());


        PasswordCallback passwordCallback = new PasswordCallback("notused", false);
        passwordCallback.setPassword(getPassword(context));

        logger.info("NameCallback and PasswordCallback set");

        Callback[] callbacks = new Callback[]{nameCallback, passwordCallback};

        boolean success = false;

        JsonValue newState = context.sharedState.copy();
        JsonValue newTransientState = context.transientState.copy();


        try {
            logger.debug("authenticating {} " + nameCallback.getName());

            success = idrepo.authenticate(getIdentityType(), callbacks)
                    && isActive(context, nameCallback);

            logger.debug("Success is " + success);

        } catch (InvalidPasswordException e) {
            logger.error("invalid password error");
            // Ignore. Success is already false!
        } catch (IdentityNotFoundException e) {
            logger.error("invalid username error");
        } catch (IdRepoException | AuthLoginException e) {
            logger.error("Exception in data store decision node");
            throw new NodeProcessException(e);
        } catch (SSOException e) {
            logger.error("Exception checking user status");
            throw new NodeProcessException(e);
        }
        return goTo(success).replaceSharedState(newState)
                            .replaceTransientState(newTransientState).build();
    }

    /**
     * @param context      TreeContext
     * @param nameCallback NameCallback
     * @return True if user is active else false.
     * @throws IdRepoException
     * @throws SSOException
     */
    private boolean isActive(TreeContext context, NameCallback nameCallback) throws IdRepoException, SSOException {
        SSOToken token = AccessController.doPrivileged(adminTokenActionProvider.get());


        return identityUtils.getAmIdentity(token, nameCallback.getName(), getIdentityType(),
                                           context.sharedState.get(REALM).asString()).isActive();
    }

    /**
     * @return IdType
     */
    private IdType getIdentityType() {
        return IdType.USER;
    }


    /**
     * @param context TreeContext
     * @return Getting password from transient state.
     * @throws NodeProcessException
     */
    private char[] getPassword(TreeContext context) throws NodeProcessException {
        String password = context.transientState.get(PASSWORD).asString();
        if (password == null) {
            logger.error("Password is null, note this field is not stored across multiple requests");
            throw new NodeProcessException("Unable to authenticate");
        }
        return password.toCharArray();
    }

    /**
     * Change password.
     *
     * @param context TreeContext
     * @throws NodeProcessException
     */
    private void updatePassword(TreeContext context) throws NodeProcessException {
        logger.info("updating password....");

        String userName = context.sharedState.get(USERNAME).asString();
        String oldPassword = context.sharedState.get(OLD_PASSWORD).asString();
        String newPassword = context.transientState.get(PASSWORD).asString();

        logger.debug("username is " + userName);
        logger.debug("old password is " + oldPassword);
        logger.debug("new password is " + newPassword);

        SSOToken token = AccessController.doPrivileged(adminTokenActionProvider.get());

        try {
            identityUtils.getAmIdentity(token, userName, getIdentityType(),
                                        context.sharedState.get(REALM).asString()).changePassword(oldPassword,
                                                                                                  newPassword);
        } catch (SSOException | IdRepoException e) {
            throw new NodeProcessException(e.getLocalizedMessage());
        }
    }

}
