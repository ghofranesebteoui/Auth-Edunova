const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../user/user.schema');
const sendEmail = require("../../utils/email");
const { OAuth2Client } = require("google-auth-library");
const { pool } = require('../../config/db');

const client = new OAuth2Client(
  "785002827947-3sbm9969qin3j49motsmn8jl1rh2reui.apps.googleusercontent.com"
);
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

const register = async (req, res) => {
  const { email, password, first_name, last_name, role } = req.body;

  if (!email || !password) {
    return res.status(400).json({ 
      success: false,
      message: 'Email and password are required' 
    });
  }

  const emailExists = await User.emailExists(email);

  if (emailExists) {
    return res.status(409).json({ 
      success: false,
      message: 'Email already exists' 
    });
  }

  const user = await User.create({
    email,
    role,
    password,
    first_name,
    last_name
  });

  const token = jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );

  res.status(201).json({
    success: true,
    message: 'User registered successfully',
    data: {
      user: user.toJSON(),
      token
    }
  });
};

const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ 
      success: false,
      message: 'Email and password are required' 
    });
  }

  const user = await User.findByEmail(email);

  if (!user) {
    return res.status(401).json({ 
      success: false,
      message: 'Invalid credentials' 
    });
  }

  if (!user.is_active) {
    return res.status(403).json({ 
      success: false,
      message: 'Account is deactivated' 
    });
  }

  const isMatch = await user.comparePassword(password);

  if (!isMatch) {
    return res.status(401).json({ 
      success: false,
      message: 'Invalid credentials' 
    });
  }

  await user.updateLastLogin();

  const token = jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );

  res.json({
    success: true,
    message: 'Login successful',
    data: {
      user: user.toJSON(),
      token
    }
  });
};

const googleLogin = async (req, res) => {
  const { token } = req.body;
  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: "785002827947-3sbm9969qin3j49motsmn8jl1rh2reui.apps.googleusercontent.com",
    });
    const payload = ticket.getPayload();
    res.json(payload);
  } catch (error) {
    res.status(400).json({ error: "Invalid token" });
  }
};

const logout = async (req, res) => {
  try {
    await pool.execute("DELETE FROM sessions WHERE user_id = ?", [req.user.id]);
    res.json({ message: "Déconnexion réussie." });
  } catch (err) { 
    res.status(500).json({ error: "Erreur déconnexion." });
  }
};

const resetPasword = async (req, res) => {
  const { email } = req.body;

  // Check if user exists
  const [users] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);
  const user = users[0];
  
  if (!user) {
    return res.status(404).json({ error: "Aucun compte avec cet email" });
  }

  // Generate JWT token
  const token = jwt.sign(
    { userId: user.id, email }, 
    process.env.JWT_SECRET, 
    { expiresIn: "1h" }
  );

  // Save token and expiration
  await pool.query(
    "UPDATE users SET reset_password_token = ?, reset_password_expires = ? WHERE id = ?",
    [token, new Date(Date.now() + 3600000), user.id]
  );

  // Reset URL (token dans le chemin, pas en query param)
  const resetUrl = `http://localhost:3000/reset-password/${token}`;

  // Send email
  await sendEmail({
    email: user.email,
    subject: "Réinitialisation de mot de passe - EduNova",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #4F46E5;">Bonjour ${user.first_name}</h2>
        <p>Vous avez demandé une réinitialisation de mot de passe pour votre compte EduNova.</p>
        <p>Cliquez sur le bouton ci-dessous pour définir un nouveau mot de passe (valable 1 heure) :</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${resetUrl}" 
             style="background-color: #4F46E5; 
                    color: white; 
                    padding: 12px 30px; 
                    text-decoration: none; 
                    border-radius: 5px;
                    display: inline-block;">
            Réinitialiser mon mot de passe
          </a>
        </div>
        <p style="color: #666; font-size: 14px;">
          Si le bouton ne fonctionne pas, copiez-collez ce lien dans votre navigateur :
        </p>
        <p style="color: #4F46E5; word-break: break-all;">${resetUrl}</p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="color: #999; font-size: 12px;">
          Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.
        </p>
      </div>
    `,
  });

  res.json({ message: "Email de réinitialisation envoyé" });
};

// ⬇️ NOUVELLE FONCTION - Réinitialisation avec token
const resetPasswordWithToken = async (req, res) => {
  try {
    const { token } = req.params;
    const { newPassword } = req.body;

    // Validation du mot de passe
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ 
        error: "Le mot de passe doit contenir au moins 6 caractères" 
      });
    }

    // Vérifier et décoder le token JWT
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET); // Utiliser la constante JWT_SECRET
    } catch (err) {
      return res.status(400).json({ error: "Token invalide ou expiré" });
    }

    // Récupérer l'utilisateur correspondant au token
    const [users] = await pool.query(
      "SELECT * FROM users WHERE id = ? AND reset_password_token = ? AND reset_password_expires > ?",
      [decoded.userId, token, new Date()]
    );

    const user = users[0];
    if (!user) {
      return res.status(400).json({ error: "Token invalide ou expiré" });
    }

    // Hasher le nouveau mot de passe
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Mettre à jour le mot de passe et supprimer le token
    await pool.query(
      "UPDATE users SET password_hash = ?, reset_password_token = NULL, reset_password_expires = NULL WHERE id = ?",
      [hashedPassword, user.id]
    );

    res.json({ success: true, message: "Mot de passe réinitialisé avec succès" });

  } catch (error) {
    console.error("Reset Password Error:", error);
    res.status(500).json({ error: "Erreur interne du serveur lors de la réinitialisation" });
  }
};
module.exports = {
  register,
  login,
  googleLogin,
  logout,
  resetPasword,
  resetPasswordWithToken // ⬅️ Ajoutez cette export
};