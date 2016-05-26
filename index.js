var middleware = require('./middleware');
var token = require('./token');

var oauth2 = function(options) {
    var _self = this;
    this.options = options;
    this.inject = function() {
        return function(req, res, next) {
            req.oauth2 = _self;
            next();
        }
    };
};

oauth2.prototype.middleware = middleware;
oauth2.prototype.token = token;

module.exports = oauth2;