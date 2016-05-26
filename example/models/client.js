// hardcoded sample, your model should contain a definition for a getByCredentials method
exports.getByCredentials = function(id, secret, next){
    if (id==='3'&&secret==='secret'){
        next({
            id: 3,
            name: 'mobile client'
        });
    }
    else {
        next(null);
    }
};