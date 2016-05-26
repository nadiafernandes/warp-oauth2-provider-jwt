var async = require('async'),
    crypto = require('crypto'),
    jwt = require('jsonwebtoken');

module.exports = {
    create: function (options, body, headers, next) {
        var model = options.model;
        var clientId = null;
        var clientSecret = null;
        var client = null;
        var user = null;
        var key = null;
        var value = {};
        var jwt_secret = options['jwt-secret'] ? options['jwt-secret'] : null;

        async.series([
            function (callback) {
                // basic validation
                if (!headers || !headers.authorization) {
                    return next({status: 403, body: 'No authorization header passed'});
                }
                var pieces = headers.authorization.split(' ', 2);
                if (!pieces || pieces.length !== 2) {
                    return next({status: 403, body: 'Authorization header is corrupted'});
                }
                if (pieces[0] !== 'Basic') {
                    return next({status: 403, body: 'Unsupported authorization method: ' + pieces[0]});
                }
                pieces = new Buffer(pieces[1], 'base64').toString('ascii').split(':', 2);
                if (!pieces || pieces.length !== 2) {
                    return next({status: 403, body: 'Authorization header has corrupted data'});
                }
                clientId = pieces[0];
                clientSecret = pieces[1];
                callback();
            },
            function (callback) {
                // client
                model.client.getByCredentials(clientId, clientSecret, function (result) {
                    if (!result) {
                        return next({status: 403, body: 'Invalid client credentials'});
                    }
                    client = result;
                    callback();
                })
            },
            function (callback) {
                // user
                model.user.getByCredentials(body.username, body.password, function (result) {
                    if (!result) {
                        return next({status: 403, body: 'Invalid user credentials'});
                    }
                    user = result;
                    if (!user.isConfirmed) {
                        return next({status: 403, body: 'User account is not confirmed'});
                    }
                    callback();
                });
            },
            function (callback) {
                // create key and value (session:userId:clientId)
                key = 'session:' + user.id + ':' + client.id;
                var jsonAccessToken = null;

                if (jwt_secret) {
                    jsonAccessToken = jwt.sign({
                        userId: user.id,
                        email: user.email,
                        role: user.role,
                        ttl: options.ttl
                    }, jwt_secret, {expiresIn: options.ttl});
                }

                value = {
                    accessToken: jwt_secret ? jsonAccessToken : crypto.randomBytes(32).toString('hex'),
                    refreshToken: crypto.randomBytes(64).toString('hex')
                };
                callback();
            },
            function (callback) {
                // find by key to check if there are other sessions active for the same user/client
                // take access token out and destroy accesstokenhistory item for this session to prevent other logged in user using refresh token
                options.client.get(key, function (err, data) {
                    if (!data) {
                        return callback();
                    }
                    var json = JSON.parse(data);
                    options.client.del('accesstokenhistory:' + json.accessToken, callback);
                });
            },
            function (callback) {
                options.client.del(key, function (err) {
                    return callback();
                });
            },
            function (callback) {
                // create redis record for key -> value
                options.client.setex(key, options.ttl, JSON.stringify(value), callback);
            },
            function (callback) {
                // create redis record for accessToken -> key
                options.client.setex('accesstoken:' + value.accessToken, options.ttl, JSON.stringify({
                    key: key,
                    userId: user.id
                }), callback);
            },
            function (callback) {
                // these records never expire, allows to distinguish expired access tokens from invalid
                options.client.set('accesstokenhistory:' + value.accessToken, JSON.stringify({
                    refreshToken: value.refreshToken,
                    key: key,
                    userId: user.id
                }), callback);
            },
            function () {
                value.userId = user.id;
                return next(null, value);
            }
        ]);
    },
    delete: function (req, next) {
        var options = req.oauth2.options;
        var client = options.client;
        var accessToken = req.query.access_token;
        var key = null;
        var userId = null;

        if (!accessToken) {
            accessToken = req.session.accessToken;
        } // get from session - allow should be an option

        if (req.headers.authorization && req.headers.authorization.toLowerCase().split('bearer ').length === 2) {
            accessToken = req.headers.authorization.toLowerCase().split('bearer ')[1];
        } // support for accessToken provided by header

        // delete key from redis
        async.series([
            function (callback) {
                var json;
                options.client.get('accesstoken:' + accessToken, function (err, data) {
                    if (data) {
                        json = JSON.parse(data);
                        key = json.key;
                    }
                    return callback();
                });
            },
            function (callback) {
                options.client.del(key, function (err) {
                    return callback();
                });
            },
            function (callback) {
                options.client.del('accesstoken:' + accessToken, function (err) {
                    return callback();
                });
            },
            function () {
                options.client.del('accesstokenhistory:' + accessToken, function (err) {
                    return next();
                });
            }
        ]);

    },
    update: function (req, next) {
        var options = req.oauth2.options;
        var client = options.client;
        var accessToken = req.body.accessToken;
        var refreshToken = req.body.refreshToken;
        var key = null;
        var userId = null;
        var jsonAccessToken = null;

        if (options['jwt_secret']) {
            jsonAccessToken = jwt.sign({
                userId: user.id,
                email: user.email,
                role: user.role,
                ttl: options.ttl
            }, options['jwt_secret'], {expiresInMinutes: options.ttl});
        }

        var newAccessToken = jsonAccessToken ? jsonAccessToken : crypto.randomBytes(32).toString('hex');
        async.series([
            function (callback) {
                // validate if accessToken and refreshToken are valid
                client.get('accesstokenhistory:' + accessToken, function (err, data) {
                    // update if exists
                    if (!data) {
                        return next({isAuthorised: false, message: 'invalid accessToken'});
                    }
                    var json = JSON.parse(data);
                    if (refreshToken !== json.refreshToken) {
                        return next({isAuthorised: false, message: 'invalid refreshToken'});
                    }
                    key = json.key;
                    userId = json.userId;
                    callback();
                });
            },
            function (callback) {
                // create redis record for accessToken -> key
                options.client.setex('accesstoken:' + newAccessToken, options.ttl, JSON.stringify({
                    key: key,
                    userId: userId
                }), callback);
            },
            function (callback) {
                // delete old redis record for accessToken -> key
                options.client.del('accesstoken:' + accessToken, callback);
            },
            function (callback) {
                // create redis accesstokenhistory record for new accessToken
                options.client.set('accesstokenhistory:' + newAccessToken, JSON.stringify({
                    refreshToken: refreshToken,
                    key: key,
                    userId: userId
                }), callback);
            },
            function (callback) {
                // delete redis accesstokenhistory record for old accessToken
                options.client.del('accesstokenhistory:' + accessToken, callback);
            },
            function (callback) {
                // overwrite redis record for key -> value
                options.client.setex(key, options.ttl, JSON.stringify({
                    accessToken: newAccessToken,
                    refreshToken: refreshToken
                }), callback);
            },

            function (callback) {
                return next(null, {accessToken: newAccessToken, refreshToken: refreshToken});
            }
        ]);
    },
    isAuthorised: function (req, next) {
        var options = req.oauth2.options;
        var client = options.client;
        var accessToken = req.query.access_token;
        var key = null;
        var userId = null;
        var role = null;
        var email = null;

        if (!accessToken) {
            accessToken = req.session.accessToken;
        } // get from session - allow should be an option

        if (!accessToken) {
            accessToken = req.cookies.token;
        } // get from cookie - allow should be an option

        if (req.headers.authorization && req.headers.authorization.toLowerCase().split('bearer ').length === 2) {
            accessToken = req.headers.authorization.toLowerCase().split('bearer ')[1];
        } // support for accessToken provided by header

        async.series([
            function (callback) {
                client.get('accesstoken:' + accessToken, function (err, data) {
                    if (!data) {
                        client.get('accesstokenhistory:' + accessToken, function (err, data) {
                            if (!data) {
                                return next({isAuthorised: false, message: 'invalid accessToken'});
                            }
                            else {
                                return next({isAuthorised: false, message: 'expired accessToken'});
                            }
                        });

                    }
                    else {
                        if (options['jwt_secret']) {
                            try {
                                var decoded = jwt.verify(data, options['jwt_secret']);
                                userId = decoded.userId
                                email = decoded.email;
                                role = decoded.role;
                            }catch(err){
                                console.log("Error parsing token");
                                return next({isAuthorised: false, message: 'Error parsing token json token'});
                            }
                        }
                        else {
                            var json = JSON.parse(data);
                            key = json.key;
                            userId = json.userId;
                        }
                        return callback();
                    }
                });
            },
            function () {
                client.get(key, function (err, data) {
                    if (!data || JSON.parse(data).accessToken !== accessToken) {
                        return next({isAuthorised: false, message: 'another session active'});
                    }
                    //todo
                    if (options['jwt_secret']) {
                        return next({
                            isAuthorised: true,
                            accessToken: {
                                userId: userId,
                                token: accessToken,
                                email: email,
                                role: role
                            }
                        });
                    } else {
                        return next({
                            isAuthorised: true,
                            accessToken: {
                                userId: userId,
                                token: accessToken
                            }
                        });
                    }

                });
            }
        ]);
    }
};