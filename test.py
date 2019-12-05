#Application Security
#Andrew Vittetoe
#05OCT2019
#Assignment #2


# importing modules
import os
import unittest
import py.test

# import app from the app.py file
from app import app
app.testing = True


class RoutingTests(unittest.TestCase):
    
    # function to set up testing connection
    def set_up(self):
         app.config["TESTING"] = True
         app.config["DEBUG"] = True
         self.app = app.test_client()
         self.assertEqual(app.debug,False)

    # function to teardown connection after testing
    def tear_down(self):
         pass
    
    # Test register page routes
    def registerpage_route1(self):
        response = self.app.get('/register', follow_redirects = True)
        self.assertEqual(response.status_code, 200)

    # Test home page defaults to register page
    def registerpage_route2(self):
         response = self.app.get('/', follow_redirects = True)
         self.assertEqual(response.status_code, 200)
    
    # Test it us redurected to the login page if not authenticated
    def loginpage_route(self):
         response = self.app.get('/login', follow_redirects = True)
         self.assertEqual(response.status_code, 200)
         
    # Test it us redirected to the login page if not authenticated
    def spell_checkpage_route(self):
         response = self.app.get('/spell_check', follow_redirects = False)
         self.assertEqual(response.status_code, 302)

    # Test that register page does not work when all the info is not provided
    def registerpage1(self):
         response = self.app.post('/register', data=dict(uname='', pword='test', ID_2fa='', password_confirm='test'), follow_redirects = True)
         self.assertEqual(response.status_code, 404)

    # Test that register page registers user when all info is present
    def registerpage2(self):
         response = self.app.post('/register', data=dict(uname='test', pword='test', ID_2fa='test', password_confirm='test'), follow_redirects = True)
         self.assertEqual(response.status_code, 200)
         
    # Test that login page does NOT authenticates with incorrect login (uname) info
    def loginpage1(self):
        response = self.app.post('/login', data=dict(uname='tester', pword='test', ID_2fa='test'), follow_redirects = True)
        self.assertEqual(response.status_code, 404)
        
    # Test that login page does NOT authenticates with incorrect login (password) info
    def loginpage2(self):
        response = self.app.post('/login', data=dict(uname='test', pword='tester', ID_2fa='test'), follow_redirects = True)
        self.assertEqual(response.status_code, 404)

    # Test that login page does NOT authenticates with incorrect login (2fa) info
    def loginpage3(self):
        response = self.app.post('/login', data=dict(uname='test', pword='test', ID_2fa='tester'), follow_redirects = True)
        self.assertEqual(response.status_code, 404)

    # Test that login page authenticates with correct login info
    def loginpage4(self):
        response = self.app.post('/login', data=dict(uname='test', pword='test', ID_2fa='test'), follow_redirects = True)
        self.assertEqual(response.status_code, 200)

    # Test it us redurected to the login page if not authenticated
    def spell_checkpage(self):
         response = self.app.get('/spell_check', data='too many things to throw on the grounddz', follow_redirects = False)
         self.assertEqual(response.status_code, 404)
         
if __name__ == "__main__":
     unittest.main()