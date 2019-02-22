#!/usr/bin/env python3

from sanic import Sanic
import sanic
from pprint import pprint
import pydoc

import json
import jwt
import ssl
import sqlite3

context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain("ssl/localhost.crt", keyfile="ssl/localhost.key")

with open('secrets.json') as sec:
	secrets = json.load(sec)

pprint(secrets)

SQLITE_DB="app.db"

class Error(Exception):
	"""Base class for exceptions in this module."""
	pass

class SecurityError(Error):
	"""Exception raised for JTI errors.

	Attributes:
		edupersontargetedid, 
		jti
	"""
	def __init__(self, edupersontargetedid, jti):
		self.edupersontargetedid = edupersontargetedid
		self.jti = jti

with sqlite3.connect(SQLITE_DB) as conn:
	try:
		for row in conn.execute("SELECT count(*) from user"):
			print("Users in db: {}".format(row[0]))
	except:
		# database doesn't exist
		conn.executescript("""
CREATE TABLE user (
	edupersontargetedid text primary key,
	edupersonprincipalname text,
	displayname text,
	surname text,
	mail text,
	givenname text,
	lastlogin timestamp DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE jti (
	edupersontargetedid text REFERENCES user,
	jti text,
	loggedout bool,
	PRIMARY KEY (edupersontargetedid, jti)
);		             
					 """)


	app = Sanic()

	@app.route("/")
	async def test(request):
		return sanic.response.html("""
	<html>
	<body>
	<a href="{}"><img src="https://rapid.test.aaf.edu.au/aaf_service_223x54.png">Login!</a>
	</body>
	</html>
							 """.format(secrets['aaf_url']))


	@app.post(secrets['jwt_endpoint_path'])
	async def jwt_handler(request):
		try:
			output = {}
			output['form'] = request.form
			output['assertion'] = output['form']['assertion'][0]
			output['body'] = request.body
			"""
			4. Validate the signed JWT (JWS) your application has received
			Should any stage of the below validation fail your application MUST discard the token and present the user with a suitable error message.

			Verify that the signature for the signed JWT you have received is valid by using your locally stored secret value
			Ensure that the iss claim has the value https://rapid.aaf.edu.au when in the production environment, or https://rapid.test.aaf.edu.au when in the test environment
			Ensure that the aud claim has the value of your application's primary URL (provided as part of service registration)
			The current time MUST be after or equal to the the time provided in the nbf claim
			The current time MUST be before the time provided in the exp claim
			Ensure that the value of the jti claim does not exist in a local storage mechanism of jti claim values you have accepted. If it doesn't (this SHOULD be the case) add the jti claim value to your local storage mechanism for future protection against replay attacks
			All applications connecting to the AAF must adhere to all relevant AAF rules and policies. Prior to approving the connection of your service to the federation, the AAF may request to review your JWT related code and test your running endpoint to verify that an application's JWT handling conforms to the above requirements.
			"""
			
			pprint(output)
			output['decoded'] = jwt.decode(output['assertion'], 
										   secrets['token'], 
										   audience="https://localhost:8443/",
										   issuer="https://rapid.test.aaf.edu.au") #https://github.com/jpadilla/pyjwt/issues/120 
												# If the `aud` claim on the token is set (on yours it is set to 'some-aud') then decoding MUST specify an expected aud value using the `audience` argument for `decode()` otherwise decoding will fail with an InvalidAudienceError.
			results = conn.execute("SELECT 1, loggedout from jti where edupersontargetedid = ? and jti = ?", [output['decoded']['https://aaf.edu.au/attributes']['edupersontargetedid'], output['decoded']['jti']]).fetchone()
			if not results:
				conn.execute("REPLACE INTO user (edupersontargetedid, edupersonprincipalname, displayname, surname, mail, givenname) VALUES (?, ?, ?, ?, ?, ?)" ,
							[output['decoded']['https://aaf.edu.au/attributes']['edupersontargetedid'], 
							 output['decoded']['https://aaf.edu.au/attributes']['edupersonprincipalname'], 
							 output['decoded']['https://aaf.edu.au/attributes']['displayname'], 
							 output['decoded']['https://aaf.edu.au/attributes']['surname'], 
							 output['decoded']['https://aaf.edu.au/attributes']['mail'], 
							 output['decoded']['https://aaf.edu.au/attributes']['givenname'] ])
				conn.execute("INSERT INTO jti(edupersontargetedid, jti) VALUES (?, ?)", [output['decoded']['https://aaf.edu.au/attributes']['edupersontargetedid'], output['decoded']['jti']])
			else:
				raise SecurityError(output['decoded']['https://aaf.edu.au/attributes']['edupersontargetedid'], output['decoded']['jti'])
			pprint(results)
			return sanic.response.json(output)
		except jwt.exceptions.ExpiredSignatureError:
			return sanic.response.html("503 - Signature has expired. <a href='/'>Try again</a>")
		except jwt.exceptions.InvalidAudienceError:
			return sanic.response.html("Invalid Audience make sure audience= is set to application root given to aaf.")
		except jwt.exceptions.InvalidIssuerError:
			return sanic.response.html("Invalid Issuer make sure issuer= is set to aaf test or prod.")
		except SecurityError:
			return sanic.response.html("You have already logged in with this credential. Please <a href='/'>Try again</a>.")

	@app.route("/test", methods=["GET"])
	async def get_handler(request):

		pprint(request)
		return sanic.response.text("HELLO WORLD {}".format(request.args))

if __name__ == "__main__":	
	app.go_fast(host="0.0.0.0", port=8443, ssl=context, debug=True, auto_reload=True)
#    app.go_fast(host="0.0.0.0", port=8443, debug=True, auto_reload=True)