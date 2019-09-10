package com.enzoic.auth.nodes;

import static javax.security.auth.callback.TextOutputCallback.ERROR;
import static javax.security.auth.callback.TextOutputCallback.WARNING;
import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.PASSWORD;
import static org.forgerock.openam.utils.CollectionUtils.isEmpty;
import static com.enzoic.auth.Constants.*;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.utils.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.sm.RequiredValueValidator;

import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import java.util.stream.Collectors;
import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;

/**
 * 
 * @author Sacumen(www.sacumen.com)
 * 
 * A node that prompt the user to reset a password.
 * 
 * Enzoic Reset Password node with single outcome. It takes new password and confirm password from the user.
 * 
 * Outcome is connected to Enzoic Check Password node.
 *
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = EnzoicResetPassword.Config.class)
public class EnzoicResetPassword extends SingleOutcomeNode {
    private final Logger logger = LoggerFactory.getLogger(EnzoicResetPassword.class);
    
	public static final String BUNDLE = "com/enzoic/auth/nodes/EnzoicResetPassword";
    
    private final Config config;
    
    private List<Callback> passwordCallbacks;
    
    private ResourceBundle bundle;

    /**
     * Node configuration.
     */
    public interface Config {

        /**
         * The length of the password.
         *
         * @return the length
         */
        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        default int minPasswordLength() {
            return 8;
        }
    }

    /**
     * Constructor.
     *
     * @param config the config
     */
    @Inject
    public EnzoicResetPassword(@Assisted EnzoicResetPassword.Config config) {
        this.config = config;
    }

    /**
     * Execution of the node starts from here.
     */
    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        logger.info("Reset PasswordNode started");
        
        bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());
        initialiseCallbacks(context);

        List<PasswordCallback> callbacks = context.getCallbacks(PasswordCallback.class);
        
        if (isEmpty(callbacks)) {
            return send(passwordCallbacks).build();
        }

        PasswordPair passwords = getPasswords(callbacks);
        
        if (!checkPassword(passwords)) {
            return send(passwordCallbacks).build();
        }

        logger.debug("Entered new password is "+passwords.password);
        
        return goToNext()
                .replaceTransientState(context.transientState.copy().put(PASSWORD, passwords.password))
                .build();
    }

    /**
     * Initialize the password callbacks for new and confirm password.
     */
    private void initialiseCallbacks(TreeContext context) {
    	JsonValue resetPasswordMsg = context.transientState.get(RESET_PASSWORD);
        logger.info("Reset password message is "+ resetPasswordMsg);

    	
        passwordCallbacks = new ArrayList<>();
        
        if(!resetPasswordMsg.isNull()) 
        	passwordCallbacks.add(new TextOutputCallback(WARNING,resetPasswordMsg.asString()));
        
        passwordCallbacks.add(new PasswordCallback(bundle.getString("callback.password"), false));
        passwordCallbacks.add(new PasswordCallback(bundle.getString("callback.password.confirm"), false));
                
    }

    /**
     * Retrieving new password and confirm password.
     * @param callbacks Password Callbacks
     * @return Passwords
     * @throws NodeProcessException
     */
    private PasswordPair getPasswords(List<PasswordCallback> callbacks) throws NodeProcessException {
        List<String> passwords = callbacks.stream()
                .map(PasswordCallback::getPassword)
                .map(String::new)
                .collect(Collectors.toList());

        if (passwords.size() != 2) {
            throw new NodeProcessException("There should be 2 PasswordCallback and " + passwords.size()
                    + " has been found");
        }
        return new PasswordPair(passwords.get(0), passwords.get(1));
    }

    /**
     * Checks minimum length of the passwords, passwords should be equal and they should not be empty as well.
     * 
     * @param passwords New and Confirm passsword.
     * @return true if passwords are valid.
     */
    private boolean checkPassword(PasswordPair passwords) {
        if (StringUtils.isBlank(passwords.password)) {
            return false;
        } else if (passwords.password.length() < config.minPasswordLength()) {
            passwordCallbacks.add(0,getErrorCallback(String.format(bundle.getString("error.password.length"),
                    config.minPasswordLength())));
            return false;
        } else if (!passwords.password.equals(passwords.confirmPassword)) {
            passwordCallbacks.add(0,getErrorCallback(bundle.getString("error.password.mismatch")));
            return false;
        }
        return true;
    }

    /**
     * Showing error message to user.
     * @param message Message
     * @return TextOutputCallback
     */
    private TextOutputCallback getErrorCallback(String message) {
        return new TextOutputCallback(ERROR, message);
    }
    

    private static class PasswordPair {
        final String password;
        final String confirmPassword;

        PasswordPair(String password, String confirmPassword) {
            this.password = password;
            this.confirmPassword = confirmPassword;
        }
    }
}
