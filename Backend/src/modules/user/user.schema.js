const bcrypt = require('bcryptjs');
const db = require('../../config/db');
const pool = db.pool;


class User {
    constructor(data) {
        this.id = data.id;
        this.email = data.email;
        
        this.password_hash = data.password_hash;
        this.first_name = data.first_name;
        this.last_name = data.last_name;
        this.is_verified = data.is_verified || false;
        this.is_active = data.is_active !== undefined ? data.is_active : true;
        this.created_at = data.created_at;
        this.updated_at = data.updated_at;
        this.last_login = data.last_login;
        this.role = data.role;
    }

    // Create new user
    static async create(userData) {
        const { email,  password, first_name, last_name,role } = userData;
        
        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const [result] = await pool.query(
            `INSERT INTO users (email, password_hash, first_name, last_name,role) 
             VALUES (?, ?, ?,  ?,?);`,
            [email, hashedPassword, first_name || null, last_name || null,role || "etudiant"]
        );

        return await User.findById(result.insertId);
    }

    // Find user by ID
    static async findById(id) {
        const [rows] = await pool.query(
            'SELECT * FROM users WHERE id = ?',
            [id]
        );

        return rows.length > 0 ? new User(rows[0]) : null;
    }

    // Find user by email
    static async findByEmail(email) {
        const [rows] = await pool.query(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );

        return rows.length > 0 ? new User(rows[0]) : null;
    }

 

    // Check if email exists
    static async emailExists(email) {
        const [rows] = await pool.query(
            'SELECT id FROM users WHERE email = ?',
            [email]
        );

        return rows.length > 0;
    }

   
    // Update user
    async update(updates) {
        const fields = [];
        const values = [];

        // Build dynamic update query
        Object.keys(updates).forEach(key => {
            if (updates[key] !== undefined && key !== 'id' && key !== 'password') {
                fields.push(`${key} = ?`);
                values.push(updates[key]);
            }
        });

        if (fields.length === 0) {
            return this;
        }

        values.push(this.id);

        await pool.query(
            `UPDATE users SET ${fields.join(', ')} WHERE id = ?`,
            values
        );

        // Refresh user data
        const updatedUser = await User.findById(this.id);
        Object.assign(this, updatedUser);
        
        return this;
    }

    // Update password
    async updatePassword(newPassword) {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        await pool.query(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            [hashedPassword, this.id]
        );

        this.password = hashedPassword;
        return this;
    }

    // Compare password
    async comparePassword(candidatePassword) {
        console.log(this.password);
        console.log(candidatePassword);
        
        return await bcrypt.compare(candidatePassword, this.password_hash);
    }

    // Update last login
    async updateLastLogin() {
        await pool.query(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
            [this.id]
        );

        this.last_login = new Date();
        return this;
    }

    // Soft delete (deactivate)
    async deactivate() {
        await pool.query(
            'UPDATE users SET is_active = FALSE WHERE id = ?',
            [this.id]
        );

        this.is_active = false;
        return this;
    }

    // Reactivate account
    async activate() {
        await pool.query(
            'UPDATE users SET is_active = TRUE WHERE id = ?',
            [this.id]
        );

        this.is_active = true;
        return this;
    }

    // Verify email
    async verify() {
        await pool.query(
            'UPDATE users SET is_verified = TRUE WHERE id = ?',
            [this.id]
        );

        this.is_verified = true;
        return this;
    }

    // Hard delete
    async delete() {
        await pool.query('DELETE FROM users WHERE id = ?', [this.id]);
        return true;
    }

    // Get public profile (without sensitive data)
    toJSON() {
        return {
            id: this.id,
            email: this.email,
           
            role: this.role,
            
            first_name: this.first_name,
            last_name: this.last_name,
            is_verified: this.is_verified,
            is_active: this.is_active,
            created_at: this.created_at,
            last_login: this.last_login
        };
    }

    // Get full name
    get fullName() {
        return `${this.first_name || ''} ${this.last_name || ''}`.trim();
    }
}

module.exports = User;