

const jwt = require('jsonwebtoken');
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
   
        const { email, password, first_name, last_name,role } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({ 
                success: false,
                message: 'Email,  and password are required' 
            });
        }

        // Check if user already exists
        const emailExists = await User.emailExists(email);

        if (emailExists ) {
            return res.status(409).json({ 
                success: false,
                message : 'Email already exists' 
            });

           
        }

        // Create user
        const user = await User.create({
            email,
            role,
           
            password,
            first_name,
            last_name
        });

        // Generate JWT token
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

        // Validate input
        if (!email || !password) {
            return res.status(400).json({ 
                success: false,
                message: 'Email and password are required' 
            });
        }

        // Find user by email
        const user = await User.findByEmail(email);
   
        

        if (!user) {
            return res.status(401).json({ 
                success: false,
                message: 'Invalid credentials' 
            });
        }

        // Check if account is active
        if (!user.is_active) {
            return res.status(403).json({ 
                success: false,
                message: 'Account is deactivated' 
            });
        }
        console.log(user);
        

        // Verify password
        const isMatch = await user.comparePassword(password);

        if (!isMatch) {
            return res.status(401).json({ 
                success: false,
                message: 'Invalid credentials' 
            });
        }

        // Update last login
        await user.updateLastLogin();

        // Generate JWT token
        const token = jwt.sign(
            { id: user.id, email: user.email,  },
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
      audience:
        "785002827947-3sbm9969qin3j49motsmn8jl1rh2reui.apps.googleusercontent.com",
    });
    const payload = ticket.getPayload();
    res.json(payload);
  } catch (error) {
    res.status(400).json({ error: "Invalid token" });
  }
}
const logout = async (req, res) => {

    try {
    await db.execute("DELETE FROM sessions WHERE user_id = ?", [req.user.id]);
    res.json({ message: "Déconnexion réussie." });
  } catch (err) { 
    res.status(500).json({ error: "Erreur déconnexion." });
  }
};

const resetPasword = async (req, res) => {

    const { email } = req.body;
    console.log(email);
    

 
    // Check if user exists
    const [users] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
    const user = users[0];
    if (!user) {
      return res.status(404).json({ error: "Aucun compte avec cet email" });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user.id, email }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    // Save token and expiration
    await pool.query(
      "UPDATE users SET reset_password_token = ?, reset_password_expires = ? WHERE id = ?",
      [token, new Date(Date.now() + 3600000), user.id] // 1 hour expiration
    );

    // Reset URL
    const resetUrl = `http://localhost:3000/reset-password?token=${token}`;

    // Send email
    await sendEmail({
      email: user.email,
      subject: "Réinitialisation de mot de passe - EduNova",
      html: `
        <h2>Bonjour ${user.first_name}</h2>
        <p>Vous avez demandé une réinitialisation de mot de passe.</p>
        <p>Cliquez sur le lien ci-dessous (valable 1 heure) :</p>
        <a href="${resetUrl}">${resetUrl}</a>
        <p>Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.</p>
      `,
    });

    // For testing with Ethereal

    res.json({ message: "Email de réinitialisation envoyé" });

}
module.exports={register,login,googleLogin,logout,resetPasword}