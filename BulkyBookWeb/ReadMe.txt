Initial setup:
1. Go to login.gov sandbox and create a test account
	A. Need a dummy gmail account - create one if needed
	B. Link the account to your authenticator app
2. Run the solution in chrome with startup flag of "--disable-web-security" 


Running:
3. Go to Login tab of site, then click the redirect button
4. You will be redirected to Login.gov - login with your test account & authenticator. 
5. Once authentication is complete, you will be sent back to the original /Login/ page, along with a 'code=' and 'session=' in the URL.
6. The application converts the code and session along with other info into a JWT and signs it, then performs HTTP POST. 


How it works:
1. Two main files are ./Controllers/LoginController.cs & ./Views/Login/Index.cshtml.
2. The first redirect upon clicking the button on the Login page is handled via script GET call in Index.cshtml. 
	A. Note that the 'redirect_uri' must match here to the one that was setup in the login.gov sandbox
	B. See https://developers.login.gov/oidc/#authorization for spec guidelines.
3. User is redirected to login.gov if all the parameters in the URI are valid and parsed correctly at their endpoint. 
4. User logs in with username/password, followed by 2FA. 
5. Upon successful login, login.gov send user back to the 'redirect_uri' specified, along with 'code=xxxx&state=xxxxx' appended to the URI. 
6. Application processes the provided code & state within the LoginController.cs file. 
7. Application constructs HTTP POST with 5 parameters to be sent to the login.gov token endpoint.
	A. See https://developers.login.gov/oidc/#token for spec guidelines (Token)
	B. Method LoginController/ExchangeToken has the logic handling creation of the token

Problem:
Step #7 of 'How it works' results in HTTP 400, or HTTP 404 errors. The post is never sent out. 

Resources:
1. https://developers.login.gov/oidc/ - For setting up the Auth, Token, and User parameters exchanges
2. https://github.com/18F/identity-oidc-sinatra/blob/ - Github example repo of implementation
3. https://dashboard.int.identitysandbox.gov/ - Sandbox dashboard - create two accounts: a dummy account (dummy email) & tester account using your @state.gov email
