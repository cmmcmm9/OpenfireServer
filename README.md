# OpenfireServer Auth Extension
Custom Authorization Class to integrate Firebase authentication for the Openfire XMPP server. Accepts the user's username and a valid Firebase ID token (JWT).
If the token is expired, or the user did not confirm their email, it will reject the authorization attempt. 
