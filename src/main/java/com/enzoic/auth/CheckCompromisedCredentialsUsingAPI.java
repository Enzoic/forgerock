package com.enzoic.auth;

import java.io.IOException;

import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.passwordping.client.PasswordPing;

public class CheckCompromisedCredentialsUsingAPI {
	
	private PasswordPing passwordping;
	private final static Logger logger = LoggerFactory.getLogger(CheckCompromisedCredentialsUsingAPI.class);

	
	public void initialize(String apiKey, String secret, Integer timeoutInMs) {
		this.passwordping = new PasswordPing(apiKey, secret);
		this.passwordping.SetRequestTimeout(timeoutInMs);
	}


	public boolean passwordCheckUsingAPI(String password) throws NodeProcessException {
		logger.info("passwordCheckUsingAPI....");

		try {

			return passwordping.CheckPassword(password);
		} 
		catch (IOException e) {
			logger.error("Caught some error while checking compromised password using API");
			throw new NodeProcessException(e.getLocalizedMessage());
		}
	}

	public boolean credentialCheckUsingAPI(String userName,String password) throws NodeProcessException {
		logger.info("credentialCheckUsingAPI....");

		try {
			return passwordping.CheckCredentials(userName,password);
			
		} catch (IOException e) {
			
			logger.error("Caught some error while checking compromised credentials using API");

			throw new NodeProcessException(e.getLocalizedMessage());
		}
	}

}