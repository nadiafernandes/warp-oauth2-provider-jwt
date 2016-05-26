# warp-oauth2-provider-jwt

## Overview
warp-oauth2-provider-jwt is a simple but secure OAuth2 provider for ExpressJS 4 and Redis. Based on jason web tokens. A user can be logged in once per client.

Contains an example implementation, where the model is currently a static file, can be easily replaced with a SequelizeJS model 
(or similar, as long as it is implemented with a getByCredential method for the client and user object).

## Changes
0.0.3 Business logics and middleware separated.
0.0.4 Updated documentation
0.0.5 Updated documentation
...
0.0.11 Refactored, better separation between token logics and middleware.
0.0.14 Implemented check for user.isConfirmed property, make sure you'll have one in your model!
0.0.17 Refresh token functionality via token.update method

## Implementation
The example below is for illustrational purposes only. In real-life applications, store the sessions in Redis (or another session-store).

	var express = require('express'),
	    redis = require('redis'),
	    bodyParser = require('body-parser'),
	    session = require('express-session'),
	    btoa = require('btoa');
	var app = express();
	var oauth2lib = require('../index'),
	    oauth2 = new oauth2lib({
	        client: redis.createClient(),
	        jwt-secret: "TOP secret" 
	        model: {
	            client: require('./models/client.js'),
	            user: require('./models/user.js')
	        },
	        ttl: 600
	    });
	
	app.use(session({
	    secret: 'keyboard cat',
	    resave: false,
	    saveUninitialized: true
	}));
	app.use(bodyParser.urlencoded({ extended: false }));
	app.use(bodyParser.json());
	app.use(oauth2.inject());
	
	app.use('/', express.static('./frontend')); // static routes
	
	app.get('/secure', oauth2.middleware.isAuthorised, function(req, res) {
	    res.json({
	        userId: req.userId
	    });
	});
	
	app.get('/insecure', function(req, res) {
	    res.json(true);
	});
	
	app.post('/oauth/token', oauth2.middleware.createToken);
	
	app.post('/api/session', function(req, res){
	    req.oauth2.token.create(req.oauth2.options, req.body, {
	        authorization: 'Basic ' + btoa('3:secret')
	    }, function(err, data){
	        if (err){
	            res.status(err.status).send(err.body);
	        }
	        req.session.accessToken = data.accessToken;
	        return res.json(data);
	    });
	});
	
	var server = app.listen(3000, function () {
	    var host = server.address().address;
	    var port = server.address().port;
	
	    console.log('Example app listening at http://%s:%s', host, port);
	});

Also, see the /example folder in the module.

## Usage
### Create token
First, make a POST to http://localhost:3000/oauth/token, with the following body:

- grant_type: password
- password: secret
- scope: all
- username: john@doe.com

..and the following headers:

- Content-Type: application/x-www-form-urlencoded; charset=utf-8
- Accept-Language: nl;q=1, en;q=0.9, de;q=0.8
- Authorization: Basic Mzptb29uc2hvdA==
- User-Agent: YourAPP/47 (iPhone; iOS 8.1.1; Scale/2.00)

The Authorization header contains the string "Basic" and a base64-encoded string for "clientId:clientSecret". For instance "3:secret" will become "MzpzZWNyZXQ=".

This will return a JSON object like:

	{
	  "refreshToken" : "a5b0f1433b5ce909698d56e8931008b7da5a58d4d279ee8da7008ee408bb11573d1cc361f7350478fa9a51862341a97ddac73f4f75a13e3e5a9d797224274876",
	  "accessToken" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsImVtYWlsIjoiZW1haWwiLCJyb2xlIjoicm9sZSIsInR0bCI6MjAsImlhdCI6MTQ2NDI1NzU4MiwiZXhwIjoxNDY0MjU3NjAyfQ.SxZKniy83FKxv-VxQLvE8fFRAnBw3ztV5OWKAQc37Vg"
	}

Validate your base64 strings on https://www.base64encode.org/

Now you can access protected endpoints with ?access_token=... or with the token in the Authorization HTTP header.

### Sign in (for web-clients / server-side usage)
In order to allow a simple browser username / password sign-in mechanism, implement a method as follows:

	app.post('/api/session', function(req, res){
	    req.oauth2.token.create(req.oauth2.options, req.body, {
	        authorization: 'Basic ' + btoa('3:secret')
	    }, function(err, data){
	        if (err){
	            res.status(err.status).send(err.body);
	        }
	        req.session.accessToken = data.accessToken;
	        return res.json(data);
	    });
	});

You'll manually pass the options, body and headers to the OAuth createToken method.
If you pass the option jwt-secret the json token wll be used, and encoded with this secret.
The callback method allows you to store the accessToken in a session or cookie and to return want you want to your client.

## Limitations
Currently only supports username / password authentication.