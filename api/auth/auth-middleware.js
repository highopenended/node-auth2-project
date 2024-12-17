const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require("../users/users-model");
const jwt = require("jsonwebtoken");

const restricted = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
        return next({ status: 401, message: "Token Required" });
    }
    jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
        if (err) {
            next({ status: 401, message: "Token Invalid" });
        } else {
            req.decodedToken = decodedToken;
            next();
        }
    });
};

const only = (role_name) => (req, res, next) => {
    const token = req.headers.authorization;
    jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
        if (err || role_name !== decodedToken.role_name) {
            next({ status: 403, message: "This is not for you" });
        } else {
            next();
        }
    });
};

const checkUsernameExists = async (req, res, next) => {
    const { username } = req.body;
    const user = await Users.findBy({ username: username });
    if (!user[0]) {
        next({ status: 401, message: "Invalid credentials" });
    } else {
        req.user = user[0];
        next();
    }
};

const validateRoleName = (req, res, next) => {
    let role_name = req.body.role_name;
    if (role_name) {
        role_name = role_name.trim();
    }
    if (!role_name) {
        req.role_name = "student";
        next();
    } else if (role_name === "admin") {
        next({ status: 422, message: "Role name can not be admin" });
    } else if (role_name.length > 32) {
        next({ status: 422, message: "Role name can not be longer than 32 chars" });
    } else {
        req.role_name = role_name;
        next();
    }
};

module.exports = {
    restricted,
    checkUsernameExists,
    validateRoleName,
    only,
};
