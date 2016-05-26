// hardcoded sample, your model should contain a definition for a getByCredentials method
exports.getByCredentials = function(username, password, next){
    if (username==='john@doe.com'&&password==='secret'){
        next({
            id: 1,
            username: 'john',
            email: 'email',
            role: 'role',
            isConfirmed: true
        });
    }
    else {
        next(null);
    }
};