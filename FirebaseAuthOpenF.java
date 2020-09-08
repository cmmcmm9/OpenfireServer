/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.jivesoftware.openfire.auth;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;

import javax.security.sasl.SaslException;
import javax.xml.bind.DatatypeConverter;

import org.jivesoftware.database.DbConnectionManager;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.sasl.ScramSha1SaslServer;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.util.JiveGlobals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.auth.FirebaseAuthException;




import com.google.firebase.auth.FirebaseToken;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import org.dom4j.CharacterData;
import static org.jivesoftware.openfire.muc.MUCRole.Log;
import org.jivesoftware.openfire.user.DefaultUserProvider;
import org.jivesoftware.openfire.user.UserAlreadyExistsException;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.openfire.user.UserNotFoundException;




/**
 *
 * @author cmmcm
 */
public class FirebaseAuthOpenF implements AuthProvider {
    
    private static final String QUERY_USER = "SELECT username FROM ofUser where username=?";
    String os = System.getProperty("os.name");
    private String appName = "openfireAuth";
    
    public FirebaseAuthOpenF(){
        try {
            initFirebase();
        } catch (InternalUnauthenticatedException ex) {
            java.util.logging.Logger.getLogger(FirebaseAuthOpenF.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    //method to make sure that there is always exactly one instance of the Firebase app
    private void initFirebase() throws InternalUnauthenticatedException{
        
        InputStream path = getClass().getResourceAsStream("/tapin-c0ba6-firebase-adminsdk-wcwb2-f27fea915a.json");
        Boolean create = false;
        
        try{
            FirebaseApp.getInstance(appName);
            System.out.println("Firebase App Already Exists");
        }
        catch(Exception ex){
            System.out.println("Firebase app doesn't exist, time to create it");
            create = true;
        }
        if(FirebaseApp.getApps().isEmpty() || create){
     
            FirebaseOptions options = null;
            try {
                options = new FirebaseOptions.Builder()
                        .setCredentials(GoogleCredentials.fromStream(path))
                        .setDatabaseUrl("https://tapin-c0ba6.firebaseio.com")
                        .build();
            } catch (IOException ex) {
                java.util.logging.Logger.getLogger(FirebaseAuthOpenF.class.getName()).log(Level.SEVERE, null, ex);
                System.out.println("Failed to Init Firebase");
            }
            
            FirebaseApp.initializeApp(options, appName);
            
        }

    }
    

    //made public for test purposes
    //method to check ID token. Note Firebase tokens expire in on hour
    //will return false if firebase token is not real token
    private Boolean checkToken(String idToken) throws ConnectionException{
        
        boolean isAuthorized = false;
        FirebaseToken decodedToken = null;
        
        try {
            initFirebase();
        } catch (InternalUnauthenticatedException ex) {
            java.util.logging.Logger.getLogger(FirebaseAuthOpenF.class.getName()).log(Level.SEVERE, null, ex);
            System.out.println("Failed to Init Firebase");
        }
        
        
        try {
            decodedToken = FirebaseAuth.getInstance(FirebaseApp.getInstance(appName)).verifyIdToken(idToken);
            isAuthorized = true;
        } catch (FirebaseAuthException ex) {
            java.util.logging.Logger.getLogger(FirebaseAuthOpenF.class.getName()).log(Level.SEVERE, null, ex);
            isAuthorized = false;
            System.out.println("Failed to decode Token Firebase");
        }
        
        if(decodedToken != null){
            if(decodedToken.isEmailVerified() == false){
                isAuthorized = false;
            }
        }
        
        if(decodedToken != null){
            if(isAuthorized){
                try{
                    addFirebaseUser(decodedToken);
                }
                catch(ConnectionException ex){
                    throw new ConnectionException(ex);
                }
                
            }
        }
        
        
        return isAuthorized;
    }
    

    
    //method called to add an Authorized Firebase user that was not in the database
    //user could have not been entered due to network error on their account creation
    private void addFirebaseUser(FirebaseToken decodedToken) throws ConnectionException{
        Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
                String username = decodedToken.getUid();
                con = DbConnectionManager.getConnection();
                pstmt = con.prepareStatement(QUERY_USER);
                pstmt.setString(1, username);
                rs = pstmt.executeQuery();
                
                if (!rs.next()) {
                    DefaultUserProvider makeUser = new DefaultUserProvider();
                    String name = decodedToken.getName();
                    String email = decodedToken.getEmail();
                    String password = decodedToken.getUid();
                    makeUser.createUser(username, password, name, email);
            }
            }
        catch (SQLException sqle) {
            Log.error("User SQL failure:", sqle);
            throw new ConnectionException(sqle);
        }   catch (UserAlreadyExistsException ex) {
                java.util.logging.Logger.getLogger(FirebaseAuthOpenF.class.getName()).log(Level.SEVERE, null, ex);
            }
    }
    //sql statement to check if user exists in the database

    
    //method to verify users. If it does not throw an exception, the user is authorized
    @Override
    public void authenticate(String username , String idToken) throws UnauthorizedException, ConnectionException, InternalUnauthenticatedException {
        
         
        boolean isFirebaseUser = false;
        Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        initFirebase();
        
        if (username == null || idToken == null) {
            throw new UnauthorizedException();
        }
        if (username == "" || idToken == ""){
            throw new UnauthorizedException();
        }
        
        username = username.trim().toLowerCase();
       
        if (username.contains("@")) {
            // Check that the specified domain matches the server's domain
            int index = username.indexOf("@");
            String domain = username.substring(index + 1);
            if (domain.equals(XMPPServer.getInstance().getServerInfo().getXMPPDomain())) {
                username = username.substring(0, index);
            } else {
                // Unknown domain. Return authentication failed.
                throw new UnauthorizedException();
            }
        }
        
      
        isFirebaseUser = checkToken(idToken);
        
        if(!isFirebaseUser){
            throw new UnauthorizedException("User not authorized");
        }
        
        //check if the username is in the database, and if the user is not but they
        //are a valid Firebase user then create the user.

        //got this far without an exception, user must be valid

    }

    
    //all methods below are unused
    @Override
    public String getPassword(String username) throws UserNotFoundException, UnsupportedOperationException {
        return username;
//throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    //needed to ensure a Firebase user's password is null. 
    @Override
    public void setPassword(String username, String password) throws UserNotFoundException, UnsupportedOperationException {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean supportsPasswordRetrieval() {
        return false;
//throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean isScramSupported() {
        return false;
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String getSalt(String username) throws UnsupportedOperationException, UserNotFoundException {
        return username;
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public int getIterations(String username) throws UnsupportedOperationException, UserNotFoundException {
        int i = 0;
        return i;
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String getServerKey(String username) throws UnsupportedOperationException, UserNotFoundException {
        return username;
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String getStoredKey(String username) throws UnsupportedOperationException, UserNotFoundException {
        return username;
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
  
}
