const {login,register,googleLogin,logout,resetPasword}=require('../auth/auth.controller')
const authMiddleware = require('../../middlewares/authmiddleware');
const router=require('express').Router()


router.post('/register',register)
router.post('/login',login)
router.post('/google-login',authMiddleware,googleLogin)
router.post('/logout',authMiddleware,logout)

router.post('/forgot-password',resetPasword)



module.exports=router;


