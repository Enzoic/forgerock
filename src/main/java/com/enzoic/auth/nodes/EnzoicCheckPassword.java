package com.enzoic.auth.nodes;

import net.bytebuddy.implementation.bytecode.Throw;
import org.apache.commons.lang.StringUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.identity.idm.IdentityUtils;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.enzoic.auth.CheckCompromisedCredentialsUsingAPI;
import com.enzoic.auth.Constants;
import com.enzoic.auth.FetchCompromisedPasswordFromLocalCSVFile;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOToken;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdType;
import static com.enzoic.auth.Constants.*;
import static com.sun.org.apache.xalan.internal.xsltc.compiler.util.Type.Node;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import org.forgerock.openam.auth.node.api.SharedStateConstants;
import sun.reflect.generics.tree.Tree;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.*;

/**
 * 
 * @author Saucmen(www.sacumen.com) Enzoic Check Compromised Password node with
 *         two outcome. If entered password or credentials is compromised then
 *         true outcome and it will go to Enzoic Reset Password node. If entered
 *         password or credentials is not compromised then false outcome and it
 *         will go to Success Page.
 *
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = EnzoicCheckPassword.Config.class)
public class EnzoicCheckPassword extends AbstractDecisionNode {

	private final Logger logger = LoggerFactory.getLogger(EnzoicCheckPassword.class);
	private CheckCompromisedCredentialsUsingAPI checkCompromisedCredentialsUsingAPI;
	private final Config config;
	private final Provider<PrivilegedAction<SSOToken>> adminTokenActionProvider;
	private final IdentityUtils identityUtils;

	/**
	 * Configuration for the data store node.
	 */
	public interface Config {

		@Attribute(order = 100, requiredValue = true)
		String Api_Key();

		@Attribute(order = 200, requiredValue = true)
		@Password
		char[] Secret();

		@Attribute(order = 300)
		default boolean CheckForSynchronousOrAsynchronousFlow() {
			return false;
		}

		@Attribute(order = 400, requiredValue = true)
		Integer CredentialCheckTimeout();

		@Attribute(order = 500, requiredValue = true)
		String UserAttribute();

		@Attribute(order = 600)
		String UniqueIdentifier();

		@Attribute(order = 700, requiredValue = true)
		String LocalPasswordFilePath();

		@Attribute(order = 800, requiredValue = true)
		default int LocalPasswordCacheExpirationTime() {
			return 3;
		}
		
		@Attribute(order = 900)
        default CheckCompromisedPassword CheckCompromisedPasswordOptions() {
            return CheckCompromisedPassword.LocalPasswordCheck;
        }


	}

	public enum CheckCompromisedPassword {
		LocalPasswordCheck,
		PasswordCheckUsingAPI,
		CredentialCheckUsingAPI

	}

	/**
	 * Inject dependency
	 * 
	 * @param config                              EnzoicCheckPassword Config
	 * @param checkCompromisedCredentialsUsingAPI CheckCompromisedCredentialsUsingAPI
	 */
	@Inject
	public EnzoicCheckPassword(@Assisted Config config,
			CheckCompromisedCredentialsUsingAPI checkCompromisedCredentialsUsingAPI, IdentityUtils identityUtils,
			Provider<PrivilegedAction<SSOToken>> adminTokenActionProvider) {
		this.config = config;
		this.checkCompromisedCredentialsUsingAPI = checkCompromisedCredentialsUsingAPI;
		this.adminTokenActionProvider = adminTokenActionProvider;
		this.identityUtils = identityUtils;
	}

	/**
	 * Execution of the node starts from here.
	 */
	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		logger.info("Check Password Node started");

		checkCompromisedCredentialsUsingAPI.initialize(config.Api_Key(), String.valueOf(config.Secret()),
				config.CredentialCheckTimeout());

		String password = context.transientState.get(SharedStateConstants.PASSWORD).asString();
		String userName = context.sharedState.get(SharedStateConstants.USERNAME).asString();

		logger.debug("Username is " + userName);
		logger.debug("Password is " + password);

		if (config.CheckForSynchronousOrAsynchronousFlow()) {

			AsyncThread thread = new AsyncThread(userName, password, context);
			thread.start();

			return goTo(true).build();
		} else {

			boolean result = processPassword(userName, password,context);
			logger.debug("Result from synchronous process is " + result);

			if (result) {
				context.transientState.put(RESET_PASSWORD, RESET_PASSWORD_MSG);
				JsonValue oldPasswordValue = context.sharedState.get(OLD_PASSWORD);
				if(oldPasswordValue.isNull()){
					context.sharedState.put(OLD_PASSWORD, password);
				}
			}

			return goTo(result).build();
		}

	}

	/**
	 * Stores result in Identity Store
	 * 
	 * @param result
	 * @param context
	 */
	private void storeAttributeInIdentityStore(Boolean result, TreeContext context) {
		logger.info("Storing result into identity store");
		SSOToken token = AccessController.doPrivileged(adminTokenActionProvider.get());

		Map<String, Set<String>> attrMap = new HashMap<>();
		Set<String> resultSet = new HashSet<>();
		resultSet.add(String.valueOf(result));
		attrMap.put(config.UserAttribute(), resultSet);

		try {
			AMIdentity identity = identityUtils.getAmIdentity(token, context.sharedState.get(USERNAME).asString(),
					IdType.USER, context.sharedState.get(REALM).asString());
			identity.setAttributes(attrMap);
			identity.store();
		} catch (Exception e) {
			logger.error("Not able to store attribute in identity store. " + e);
		}
	}

	/**
	 * Get value from Identity Store
	 *
	 * @param uniqueIdentifier
	 * @param context
	 */
	private String getAttributeFromIdentityStore(String uniqueIdentifier,TreeContext context) throws NodeProcessException {
		logger.info("Storing result into identity store");
		SSOToken token = AccessController.doPrivileged(adminTokenActionProvider.get());
		Set<String> attributes;

		try {
			AMIdentity identity = identityUtils.getAmIdentity(token, context.sharedState.get(USERNAME).asString(),
					IdType.USER, context.sharedState.get(REALM).asString());
			attributes = identity.getAttribute(uniqueIdentifier);
		} catch (Exception e) {
			logger.error("Not able to get attribute from identity store. " + e);
			throw new NodeProcessException("Not able to get attribute from identity store. " + e);
		}

		Iterator<String> iterator = attributes.iterator();

		if(iterator.hasNext()){
			return iterator.next();
		}
		else{
			return StringUtils.EMPTY;
		}

	}

	/**
	 * Processing request
	 * 
	 * @param userName UserName
	 * @param password UserPassword
	 * @return result
	 */
	private Boolean processPassword(String userName, String password, TreeContext context) throws NodeProcessException {
		try {
			return processPasswordCheck(userName, password, context);
		} catch (NodeProcessException e) {
			logger.error("Caught exception, Not able to process", e);
			throw e;
		}

	}

	/**
	 * Checking if password is compromised or not.
	 * 
	 * @param userName UserName
	 * @param password UserPassword
	 * @return result
	 * @throws NodeProcessException
	 */
	private boolean processPasswordCheck(String userName, String password, TreeContext context) throws NodeProcessException {
		String configValue = config.CheckCompromisedPasswordOptions().toString();
		if (configValue.equals(Constants.LOCAL_PASSWORD_CHECK)) {
			logger.debug("Checking compromised password using local file system");
			logger.debug("Cache expiration time is " + config.LocalPasswordCacheExpirationTime());
			logger.debug("Config file is " + config.LocalPasswordFilePath());

			FetchCompromisedPasswordFromLocalCSVFile compromisedPasswordFromLocalCsvFile = FetchCompromisedPasswordFromLocalCSVFile
					.getInstance(this.config.LocalPasswordCacheExpirationTime(), this.config.LocalPasswordFilePath());

			List<String> compromisedPasswords = compromisedPasswordFromLocalCsvFile.getEntry(userName);

			return compromisedPasswords.contains(password);
		} else if (configValue.equals(Constants.PASSWORD_CHECK_USING_API)) {
			logger.debug("Checking compromised password using API");

			return checkCompromisedCredentialsUsingAPI.passwordCheckUsingAPI(password);
		} else if (configValue.equals(Constants.CREDENTIAL_CHECK_USING_API)) {
			logger.debug("Checking compromised credentials using API");
			String uniqueIdentifier = config.UniqueIdentifier();

			if(uniqueIdentifier != null && !uniqueIdentifier.isEmpty()){
               String attributeValue = getAttributeFromIdentityStore(uniqueIdentifier,context);
               if(attributeValue.isEmpty()){
				   throw new NodeProcessException("Not able to get any value of "+uniqueIdentifier+" from identity store");
			   }else{
               	   userName = attributeValue;
			   }
			}

			return checkCompromisedCredentialsUsingAPI.credentialCheckUsingAPI(userName, password);

		} else {
			throw new NodeProcessException(NO_CONFIGURATION_ERROR_MSG);
		}
	}

	public class AsyncThread extends Thread {

		private String userName;
		private String password;
		private TreeContext context;

		AsyncThread(String userName, String password, TreeContext context) {
			this.userName = userName;
			this.password = password;
			this.context = context;
		}

		public void run() {
			logger.info(this.getName() + ": Async Thread is running...");
			Boolean result = null;
			try {
				result = processPassword(userName, password,context);
			} catch (NodeProcessException e) {
				logger.error("Caught exception while checking password", e);
			}
			logger.info("Result from Asynchronous process is " + result);
			storeAttributeInIdentityStore(result, context);

		}
	}

}
