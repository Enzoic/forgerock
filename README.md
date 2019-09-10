# Enzoic-Auth

A simple authentication nodes for ForgeRock's [Identity Platform][forgerock_platform] 6.5 and above.

# Enzoic Information

Enzoic specializes in cyber-security and fraud detection
Cybersecurity is a complex and ever-evolving market. Compromised credentials remain a large risk for most organizations and the attackers are getting more sophisticated each year.

Organizations need solutions that combine cloud security expertise and innovative, easy-to-deploy tools to layer-in with other security measures.

Enzoic was created as a streamlined solution to detect compromised credentials with minimal friction for end users.

# Installation

The Enzoic-Auth tree nodes will be packaged as a jar file using the maven build tool and will be deployed in to the ForgeRock Access Management (AM)6 application WEB-INF/lib folder which is running on tomcat server.

# Enzoic-Auth Tree Configuration

Following are the nodes that will be available after deploying the jar file:

* Enzoic Check Compromised Password
```js
This node will check compromised password using passwordping-java-client. 

Attributes to be configured are:
API Key : API Key to call password ping api.

Seret : Seret to call password ping api

Synchronous/Asynchronous : Flag to set flow as Synchronous or Asynchronous.

Credential Check Timeout(In MilliSeconds) : Timeout for password ping api and it should be enter in MilliSecond.

User Attribute : A string which will contain output for Asynchronous flow. User needs to add this attribute and this should be defined in identity store.

Unique Identifier : The unique user identifying attribute to check against the Enzoic API.

Local password file path : Local csv file location which contains compromised passwords

Local password Cache Expiration Time(In Seconds) : We are adding localfile in cache for Local Password Check. So user needs to configure cache expiration time and it should be given in seconds.

Check Compromised Password : User needs to select option to check compromised password against local file or API.
```

![Screenshot from 2019-08-09 13-13-06](https://user-images.githubusercontent.com/20396535/62763279-c68e5700-baa8-11e9-9535-9566255cf185.png)
![Screenshot from 2019-08-27 14-21-45](https://user-images.githubusercontent.com/20396535/63756588-40f70d80-c8d6-11e9-9b35-e3d7dafb4b2c.png)



* Enzoic Reset Password
```js
This node will collect new password to reset the password. 

Attributes to be configured are:
Minimum Password Length : User need to configure mnimum password length for new password validation.
```
![Screenshot from 2019-08-09 13-24-07](https://user-images.githubusercontent.com/20396535/62763373-01908a80-baa9-11e9-8d84-d69c76d90b36.png)



* Enzoic Save Password
```js
This node will save new password to reset password for user. There are no configurable attributes to it.
```

* Retry Limit Decesion
```js
Applies retry logic if entered password for reset password node is also a compromise password. 
Attributes to be configured are:

* Retry Limit : The number of times to allow a retry
```
![retry](https://user-images.githubusercontent.com/20396535/57918264-0849a000-78b4-11e9-905f-78ef61b88986.PNG)


* Message Node
```js
Display message to the user. Attributes to be configured are:

* Message : Localisation overrides - as key fill shortcut for language (first will be used as default if not empty or "Default message" if empty), value is message for language defined by key.

* Positve Answer : Localisation overrides - as key fill shortcut for language (first will be used as default if not empty or "Yes" if empty), value is positive answer for language defined by key.

* Negative Answer :Localisation overrides - as key fill shortcut for language (first will be used as default if not empty or "No" if empty), value is negative answer for language defined by key.
```
![message](https://user-images.githubusercontent.com/20396535/57918307-1eeff700-78b4-11e9-870b-2eaa203e40ec.PNG)



## Configure the trees as follows

 * Navigate to **Realm** > **Authentication** > **Trees** > **Create Tree**
 
 ![tree](https://user-images.githubusercontent.com/20396535/48189113-66c21e80-e365-11e8-8045-326786a41aca.PNG)
 
 
 ## Configuring Enzoic-Sync Auth Tree
```js
this section depicts configuration of Enzoic-Sync Auth Tree
```

* Configure Enzoic-Sync Auth Tree as shown below

Tree Configuration : 
![Enzoic_updatedTree](https://user-images.githubusercontent.com/20396535/57918407-5a8ac100-78b4-11e9-8e33-1f7bb0dd4e81.PNG)


 ## Configuring Enzoic-Async Auth Tree
```js
this section depicts configuration of Enzoic-Async Auth Tree
```

* Configure Enzoic-Async Auth Tree as shown below

Tree Configuration : 
![Screenshot from 2019-08-09 13-28-31](https://user-images.githubusercontent.com/20396535/62763610-9f845500-baa9-11e9-8f14-869d8b85384a.png)


