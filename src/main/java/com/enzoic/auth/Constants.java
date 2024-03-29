package com.enzoic.auth;

/**
 * @author Sacumen(www.sacumen.com)
 * Constant class
 */
public final class Constants {

    // saving old password to reset new password
    public static String OLD_PASSWORD = "old_Password";

    //reset password
    public static String RESET_PASSWORD = "reset_password_msg";

    //Messages
    public static String RESET_PASSWORD_MSG = "Entered password is compromised password, Please reset password.";
    public static String
            NO_CONFIGURATION_ERROR_MSG =
            "User has not selected any option in check compromised credential node,Please select at least one option.";

    //Stores flow behaviour
    public static String SYNCHRONOUS = "synchronous";
    public static String USER_ATTRIBUTE = "user_attribute";
    public static String MAP_ATTRIBUTE = "map_attribute";
    
    //Option to check compromised password
    public static String LOCAL_PASSWORD_CHECK="LocalPasswordCheck";
    public static String PASSWORD_CHECK_USING_API="PasswordCheckUsingAPI";
    public static String CREDENTIAL_CHECK_USING_API="CredentialCheckUsingAPI";


    

}
