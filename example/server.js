var express = require("express"),
    redis = require("redis"),
    bodyParser = require("body-parser"),
    session = require("express-session"),
    btoa = require("btoa"),
    app = express(),
    config = require("./config.js"),
    oauth2lib = require("../index"),
    oauth2 = new oauth2lib({
        client: redis.createClient(),
        "jwt-secret": config.auth.secret,
        model: {
            client: require("./models/client.js"),
            user: require("./models/user.js")
        },
        ttl: config.auth.ttl
    });

app.use(session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: true
}));
app.use(bodyParser.urlencoded({extended: false}));
app.use(bodyParser.json());
app.use(oauth2.inject());

app.use("/", express.static("./frontend/"));

app.get("/secure", oauth2.middleware.isAuthorised, function (req, res) {
    res.json({
        userId: req.userId
    });
});

app.get("/insecure", function (req, res) {
    res.json(true);
});

app.post("/oauth/token", oauth2.middleware.createToken);

app.post("/api/session", function (req, res) {
    req.oauth2.token.create(req.oauth2.options, req.body, {
        authorization: "Basic " + btoa("3:secret")
    }, function (err, data) {
        if (err) {
            res.status(err.status).send(err.body);
        }
        req.session.accessToken = data.accessToken;
        return res.json(data);
    });
});

app.listen(config.port, function () {
    var host = config.url;
    var port = config.port;

    console.log("Example app listening at http://%s:%s", host, port);
});