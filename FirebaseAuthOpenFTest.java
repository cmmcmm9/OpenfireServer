/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.jivesoftware.openfire.auth;

import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author cmmcm
 */
public class FirebaseAuthOpenFTest {
    
    public FirebaseAuthOpenFTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of authenticate method, of class FirebaseAuthOpenF.
     * 
     */
    
//    @Test(expected = UnauthorizedException.class)
//public void myTest() {
//    FirebaseAuthOpenF instance = new FirebaseAuthOpenF();
//        try {
//            instance.authenticate("", "");
//        } catch (UnauthorizedException | ConnectionException | InternalUnauthenticatedException ex) {
//            Logger.getLogger(FirebaseAuthOpenFTest.class.getName()).log(Level.SEVERE, null, ex);
//        }
//}
    @Test
    public void testAuthenticate() {
        System.out.println("authenticate");
        String username = "";
        String idToken = "";
        FirebaseAuthOpenF instance = new FirebaseAuthOpenF();
        UnauthorizedException unExcp = null;

       try{
           instance.authenticate(username, idToken);
       }catch(UnauthorizedException ex){
           unExcp = ex;
       } catch (ConnectionException ex) {
            Logger.getLogger(FirebaseAuthOpenFTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InternalUnauthenticatedException ex) {
            Logger.getLogger(FirebaseAuthOpenFTest.class.getName()).log(Level.SEVERE, null, ex);
        }
       assertNotNull(unExcp);
       
       //
       username = null;
       idToken = null;
       unExcp = null;
       
       try{
           instance.authenticate(username, idToken);
       }catch(UnauthorizedException ex){
           unExcp = ex;
       } catch (ConnectionException ex) {
            Logger.getLogger(FirebaseAuthOpenFTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InternalUnauthenticatedException ex) {
            Logger.getLogger(FirebaseAuthOpenFTest.class.getName()).log(Level.SEVERE, null, ex);
        }
       assertNotNull(unExcp);
       
       //
       username = "myusername";
       idToken = "fakeToken";
       unExcp = null;
       
       try{
           instance.authenticate(username, idToken);
       }catch(UnauthorizedException ex){
           unExcp = ex;
       } catch (ConnectionException ex) {
            Logger.getLogger(FirebaseAuthOpenFTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InternalUnauthenticatedException ex) {
            Logger.getLogger(FirebaseAuthOpenFTest.class.getName()).log(Level.SEVERE, null, ex);
        }
       assertNotNull(unExcp);
       
       //realt token but unVerified, unverified@gmail.com
       unExcp = null;
       idToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjZjZmMyMzViZDYxMGZhY2FlYzVlYjBhZGU5NTg5ZGE5NTI4MmRlY2QiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoiQm9iIFNhZ2V0IiwicGljdHVyZSI6Imh0dHA6Ly93d3cuZXhhbXBsZS5jb20vMTIzNDU2NzgvcGhvdG8ucG5nIiwiaXNzIjoiaHR0cHM6Ly9zZWN1cmV0b2tlbi5nb29nbGUuY29tL3RhcGluLWMwYmE2IiwiYXVkIjoidGFwaW4tYzBiYTYiLCJhdXRoX3RpbWUiOjE1OTU3OTk5NDUsInVzZXJfaWQiOiJQMFVyTWpwdTdTUGJmQUFJNkpKSHVFVXB0Wm8yIiwic3ViIjoiUDBVck1qcHU3U1BiZkFBSTZKSkh1RVVwdFpvMiIsImlhdCI6MTU5NTc5OTk0NSwiZXhwIjoxNTk1ODAzNTQ1LCJlbWFpbCI6InVudmVyaWZpZWRAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJmaXJlYmFzZSI6eyJpZGVudGl0aWVzIjp7ImVtYWlsIjpbInVudmVyaWZpZWRAZ21haWwuY29tIl19LCJzaWduX2luX3Byb3ZpZGVyIjoicGFzc3dvcmQifX0.d-HXlxMBk-e8Fo_GLBjaciTMi6hzRJaJNFgtPoOnpJ0kJi7LqRL1hKU8Spm5f2TMZILODmOS_zQlsk0wEdrCE5HwStaskEdxPNQ-SioMSE6KqOH53AID1LMrQRbAuaNa4fvTZk25civeEMWDHZVLtqpMBmrTy8Osd0NytyujMs8zrvvKwvtEiBZZxSgfKd13miiFJLS5Nlr1G1Jg2XhGnK4vrm2euWW_GpzalaoKCn3v-AvVrU9sEz38gwGGe8OP9X6xgjuA5_2aOaDOWaNpKOLJOgvU0dtToFqqLvUbRgUsZFFuDm_DUvKY3A96DqSAVSfFRy3lnoxhPu1Nsm-4qA";
       Boolean result = instance.checkToken(idToken);
       assertEquals(false, result );
       
       //make sure authenticate() thows exception after unverififed emails
       username = "myusername";
       unExcp = null;
       
       try{
           instance.authenticate(username, idToken);
       }catch(UnauthorizedException ex){
           unExcp = ex;
       } catch (ConnectionException ex) {
            Logger.getLogger(FirebaseAuthOpenFTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InternalUnauthenticatedException ex) {
            Logger.getLogger(FirebaseAuthOpenFTest.class.getName()).log(Level.SEVERE, null, ex);
        }
       assertNotNull(unExcp);
       

       
       //real token, email is verified, dabs@gmail.com
       unExcp = null;
       idToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjZjZmMyMzViZDYxMGZhY2FlYzVlYjBhZGU5NTg5ZGE5NTI4MmRlY2QiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoiQm9iIFNhZ2V0IiwicGljdHVyZSI6Imh0dHA6Ly93d3cuZXhhbXBsZS5jb20vMTIzNDU2NzgvcGhvdG8ucG5nIiwiaXNzIjoiaHR0cHM6Ly9zZWN1cmV0b2tlbi5nb29nbGUuY29tL3RhcGluLWMwYmE2IiwiYXVkIjoidGFwaW4tYzBiYTYiLCJhdXRoX3RpbWUiOjE1OTU4MDAwNDksInVzZXJfaWQiOiJiRUpaTjBpMHR5TUhvZldMb25VazFBT2pLUUsyIiwic3ViIjoiYkVKWk4waTB0eU1Ib2ZXTG9uVWsxQU9qS1FLMiIsImlhdCI6MTU5NTgwMDA1MCwiZXhwIjoxNTk1ODAzNjUwLCJlbWFpbCI6ImRhYnNAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsInBob25lX251bWJlciI6IisxOTc4ODc5OTYyOSIsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnsicGhvbmUiOlsiKzE5Nzg4Nzk5NjI5Il0sImVtYWlsIjpbImRhYnNAZ21haWwuY29tIl19LCJzaWduX2luX3Byb3ZpZGVyIjoicGFzc3dvcmQifX0.mr3kVTZtS-hF7CbHbD6db4pWImP66UxmSQC7sUh6FFtSx5w4oVodUy8w86ao_dojK-buTT5yf_ANv-NqBcByHL4ng4wSae-A-_eAJJO2BgkOStwvLEgSA6o1nGlnPY4KAeXiYR4y42LS2ttvJ_mxpk07uwXaFBjslcmGi0dDLd-AtuS9ur8gLp5NT-4txzKN7tmAO2uOeANr7qUpi9MSUU3wE8_2udNhfSWtE5LxrYjAdWCbPumWJcwjzUCO3aT3wocu3PYA3dZvw27bmjjshIey2ZHADj7weUbK8LwMWXDUnSEGhQx7k3-YpnDLVJzxG_vrA6frEQ7AqZRMGK7kXQ";
       result = instance.checkToken(idToken);
       assertEquals(true, result );
       
       //verify authenticate calls checkToken correctly and it is authenticated
       username = "myusername";
       unExcp = null;
       try{
           instance.authenticate(username, idToken);
       }catch(UnauthorizedException ex){
           unExcp = ex;
       } catch (ConnectionException ex) {
            Logger.getLogger(FirebaseAuthOpenFTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InternalUnauthenticatedException ex) {
            Logger.getLogger(FirebaseAuthOpenFTest.class.getName()).log(Level.SEVERE, null, ex);
        }
       assertNull(unExcp);
       

       
       
       
        
        
        // TODO review the generated test code and remove the default call to fail.
        //fail("The test case is a prototype.");
    }

    /**
     * Test of getPassword method, of class FirebaseAuthOpenF.
     */
    @Test
    public void testGetPassword() throws Exception {
        System.out.println("getPassword");
        String username = "";
        FirebaseAuthOpenF instance = new FirebaseAuthOpenF();
        String expResult = "";
        String result = instance.getPassword(username);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        //fail("The test case is a prototype.");
    }

    /**
     * Test of setPassword method, of class FirebaseAuthOpenF.
     */
    @Test
    public void testSetPassword() throws Exception {
        System.out.println("setPassword");
        String username = "";
        String password = "";
        FirebaseAuthOpenF instance = new FirebaseAuthOpenF();
        instance.setPassword(username, password);
        // TODO review the generated test code and remove the default call to fail.
        //fail("The test case is a prototype.");
    }

    /**
     * Test of supportsPasswordRetrieval method, of class FirebaseAuthOpenF.
     */
    @Test
    public void testSupportsPasswordRetrieval() {
        System.out.println("supportsPasswordRetrieval");
        FirebaseAuthOpenF instance = new FirebaseAuthOpenF();
        boolean expResult = false;
        boolean result = instance.supportsPasswordRetrieval();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        //fail("The test case is a prototype.");
    }

    /**
     * Test of isScramSupported method, of class FirebaseAuthOpenF.
     */
    @Test
    public void testIsScramSupported() {
        System.out.println("isScramSupported");
        FirebaseAuthOpenF instance = new FirebaseAuthOpenF();
        boolean expResult = false;
        boolean result = instance.isScramSupported();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        //fail("The test case is a prototype.");
    }

    /**
     * Test of getSalt method, of class FirebaseAuthOpenF.
     */
    @Test
    public void testGetSalt() throws Exception {
        System.out.println("getSalt");
        String username = "";
        FirebaseAuthOpenF instance = new FirebaseAuthOpenF();
        String expResult = "";
        String result = instance.getSalt(username);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        //fail("The test case is a prototype.");
    }

    /**
     * Test of getIterations method, of class FirebaseAuthOpenF.
     */
    @Test
    public void testGetIterations() throws Exception {
        System.out.println("getIterations");
        String username = "";
        FirebaseAuthOpenF instance = new FirebaseAuthOpenF();
        int expResult = 0;
        int result = instance.getIterations(username);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        //fail("The test case is a prototype.");
    }

    /**
     * Test of getServerKey method, of class FirebaseAuthOpenF.
     */
    @Test
    public void testGetServerKey() throws Exception {
        System.out.println("getServerKey");
        String username = "";
        FirebaseAuthOpenF instance = new FirebaseAuthOpenF();
        String expResult = "";
        String result = instance.getServerKey(username);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        //fail("The test case is a prototype.");
    }

    /**
     * Test of getStoredKey method, of class FirebaseAuthOpenF.
     */
    @Test
    public void testGetStoredKey() throws Exception {
        System.out.println("getStoredKey");
        String username = "";
        FirebaseAuthOpenF instance = new FirebaseAuthOpenF();
        String expResult = "";
        String result = instance.getStoredKey(username);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        //fail("The test case is a prototype.");
    }
    
}
