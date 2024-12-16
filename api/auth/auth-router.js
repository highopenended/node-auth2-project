const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require("bcryptjs");
const User = require("../users/users-model");

router.post("/register", validateRoleName, (req, res, next) => {
  const { username, password } = req.body;
  const { role_name } = req;


  console.log(username, ' | ', role_name, ' | ', password, ' | ')

  const hash = bcrypt.hashSync(password, 8);



  User.add({ username, password: hash, role_name })
      .then(noidea => {
          res.status(201).json(noidea);
      })
      .catch(next);
});


router.post("/login", checkUsernameExists, (req, res, next) => {
    /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
    res.json({ message: "Logging In..." });
});

module.exports = router;
