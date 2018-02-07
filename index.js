var expressJwt = require("express-jwt");
var jwt = require("jsonwebtoken");
var bcrypt = require('bcrypt');


module.exports = function(expressapp,config,UseModel){

    // Basic configs for auth module to work
    var secretcode = config.secret || "this_is_my_secret";
    var path_to_get_token = config.loginpath || "/login";
    var path_to_signup = config.signuppath || "/signup";
    var paths_donot_need_token = config.nonverifypaths || ["/login"];

    // Options to configure the login request
    var loginFormFields = config.login_form || {"username":"username","password":"password"};
    var loginRequestBodyUsernameAlias = loginFormFields.username;
    var loginRequestBodyPasswordAlias = loginFormFields.password;

    // Database table's column config for login purpose
    var auth_db_config = config.auth_db_column || { "username":"username","password":"password"};
    var usernameDBColumn = auth_db_config.username;
    var passwordDBColumn = auth_db_config.password;

    // Configuration for messages:
    var msgConfigs = config.auth_messages || { };
    var msgUsernameMissingInLoginRequest = config.auth_messages.msg_missing_username ||  {"success":false,"message":"username required"};
    var msgPasswordMissingInLoginRequest = config.auth_messages.msg_missing_password ||  {"success":false,"message":"username required"};
    var msgUserNotFoundInDatabase = config.auth_messages.msg_user_notfound ||  {"success":false,"message":"Username does not exist"};
    var msgPasswordIncorrect = config.auth_messages.msg_password_incorrect || {"success":false,"message":"Password is incorrect"};
    var msgInternalError = config.auth_messages.msg_internal_error || {"success":false,"message":"password required"};
    var msgUnauthorizedError = config.auth_messages.msg_unauth_error || {"success":false,"message":"invalid token"};


    expressapp.use(expressJwt({secret: secretcode}).unless({path: paths_donot_need_token}));

    expressapp.post(path_to_get_token, function(req, res) {
        var username = req.body[loginRequestBodyUsernameAlias];
        var password = req.body[loginRequestBodyPasswordAlias];

        if (!username) {
            return res.status(400).send(msgUsernameMissingInLoginRequest);
        }
        if (!password) {
            return res.status(400).send(msgPasswordMissingInLoginRequest);
        }

        var searchCondition = {};
        searchCondition[usernameDBColumn] = username;

        UseModel.findOne({ where: searchCondition }).then(function(userdata){
            if(!userdata){
                return res.status(401).send(msgUserNotFoundInDatabase);
            } else {
                const pwdMatchFlag =bcrypt.compareSync(password, userdata.dataValues[passwordDBColumn]);
                if(pwdMatchFlag){
                    var authToken = jwt.sign({username: username}, "secret");
                    res.status(200).json({token: authToken});
                } else {
                    return res.status(401).send(msgPasswordIncorrect);
                }
            }

        }).catch(function(err){
            return res.status(500).send(msgInternalError);
        });

    });

    expressapp.use(function (err, req, res, next) {
        if (err.name === "UnauthorizedError") {
            res.status(401).send(msgUnauthorizedError);
        }
    });

};