const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require("../users/users-model");


const restricted = (req, res, next) => {
  console.log('Checking Restricted...')

  
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
  next()
}

const only = role_name => (req, res, next) => {
  console.log("Checking Only...")
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
  next()
}


const checkUsernameExists = async (req, res, next) => {
  const {username} =req.body
  const user=await Users.findBy({username:username})
  if(!user[0]){
    next({status: 401, message:'Invalid credentials'})
  }else{
    req.user=user[0]
    next()
  }
}


const validateRoleName = (req, res, next) => {
  const role_name = req.body.role_name.trim()
  if(!role_name){
    req.role_name = 'student'
    next()
  }else if(role_name.trim()==='admin'){
    next({status: 422, message:'Role name can not be admin'})
  }else if(role_name.trim().length>32){
    next({status: 422, message:'Role name can not be longer than 32 characters'})
  } else {
    req.role_name = role_name
    next()
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
