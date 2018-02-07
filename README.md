# OCSP Auth module
This node module is used to provide jwt from /login route and user can destroy
the jwt from /logout route.

When use this module, user need define a Sequelize user module for login/logout serivce

Example:

var auth = require('<this module>');
var userModel = require('./UserModel')(sequelize,Sequelize);

var config = {
    "secretcode":"this_is_demo_secret",
    "path_to_get_token":"/login",
    "paths_donot_need_token":["/login"],
    "auth_db_column":{
        "username":"email",
        "password":"password"
    },
    "login_form":{
        "username":"username",
        "password":"password"
    },
    "auth_messages":{
        "msg_missing_username":{"success":false,"message":"username required"},
        "msg_missing_password":{"success":false,"message":"username required"},
        "msg_user_notfound":{"success":false,"message":"Username does not exist"},
        "msg_password_incorrect":{"success":false,"message":"Password is incorrect"},
        "msg_internal_error":{"success":false,"message":"password required"},
        "msg_unauth_error":{"success":false,"message":"invalid token"}
    }
};
auth(app,config,userModel);