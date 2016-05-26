var async = require('async');

module.exports = {
    createToken: function (req, res, next) {
        console.log("create");
        req.oauth2.token.create(req.oauth2.options, req.body, req.headers, function (err, data) {
            if (err) {
                return res.status(err.status).send(err.body);
            }
            console.log(data);
            return res.json({
                'refresh_token': data.refreshToken,
                'token_type': 'bearer',
                'access_token': data.accessToken
            });
        });
    },
    isAuthorised: function (req, res, next) {
        req.oauth2.token.isAuthorised(req, function (data) {
            if (!data.isAuthorised) {
                return res.status(403).send(data.message);
            }
            req.userId = data.accessToken.userId; // decode it
            req.oauth2.accessToken = data.accessToken;

            return next();
        });
    }
};