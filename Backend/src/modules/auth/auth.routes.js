const {
  login,
  register,
  googleLogin,
  logout,
  resetPasword,
  resetPasswordWithToken // ⬅️ Ajoutez ceci
} = require('../auth/auth.controller');

const authMiddleware = require('../../middlewares/authmiddleware');
const router = require('express').Router();

router.post('/register', register);
router.post('/login', login);
router.post('/google-login', authMiddleware, googleLogin);
router.post('/logout', authMiddleware, logout);

// Route pour demander la réinitialisation (envoie l'email)
router.post('/forgot-password', resetPasword);

// ⬇️ NOUVELLE ROUTE - Pour réinitialiser effectivement le mot de passe
router.post('/reset-password/:token', resetPasswordWithToken);

module.exports = router;