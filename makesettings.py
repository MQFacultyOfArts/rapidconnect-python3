#!/usr/bin/env python3

import secrets
import json

with open("secrets.json", "w") as sec:
	secret = {'default_institution':"",
			  'base_url': "https://localhost:8443/",
			  'aaf_url': "",
			  'issuer': "https://rapid.test.aaf.edu.au",			  
			  'jwt_endpoint_path': '/auth/jwt'
			  }
	secret['token'] = secrets.token_urlsafe(64)
	print("Secret for registration: {}".format(secret['token']))
	json.dump(secret, sec)