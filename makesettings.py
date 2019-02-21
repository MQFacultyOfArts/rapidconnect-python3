#!/usr/bin/env python3

import secrets
import json

with open("secrets.json", "w") as sec:
	secret = {}
	secret['token'] = secrets.token_urlsafe(64)
	print("Secret for registration: {}".format(secret['token']))
	json.dump(secret, sec)