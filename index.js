// package.json faylini yaratish uchun: npm init -y
// Kerakli modullarni o'rnatish: npm install express mongoose bcryptjs jsonwebtoken cors dotenv

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// MongoDB connection
mongoose
  .connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/auth_db', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('MongoDB ga muvaffaqiyatli ulanildi'))
  .catch((err) => console.error('MongoDB ulanishida xatolik:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 20,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    match: [
      /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
      "Email formati noto'g'ri",
    ],
  },
  password: {
    type: String,
    required: true,
    minlength: 6,
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user',
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  isVerified: {
    type: Boolean,
    default: false,
  },
});

// Parolni hash qilish (middleware)
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Parolni tekshirish uchun method
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// JWT token yaratish funksiyasi
const generateToken = (userId) => {
  return jwt.sign(
    { userId: userId },
    process.env.JWT_SECRET || 'your-secret-key',
    { expiresIn: '7d' }
  );
};

// Token tekshirish middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Token topilmadi',
      });
    }

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || 'your-secret-key'
    );
    const user = await User.findById(decoded.userId).select('-password');

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Foydalanuvchi topilmadi',
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({
      success: false,
      message: 'Token yaroqsiz',
    });
  }
};

// Validation functions
const validateRegistration = (userData) => {
  const errors = [];

  if (!userData.username || userData.username.length < 3) {
    errors.push("Username kamida 3 ta belgidan iborat bo'lishi kerak");
  }

  if (
    !userData.email ||
    !/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/.test(userData.email)
  ) {
    errors.push("Email formati noto'g'ri");
  }

  if (!userData.password || userData.password.length < 6) {
    errors.push("Parol kamida 6 ta belgidan iborat bo'lishi kerak");
  }

  return errors;
};

// ROUTES

// 1. REGISTRATION ENDPOINT
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;

    // Validation
    const validationErrors = validateRegistration({
      username,
      email,
      password,
    });
    if (validationErrors.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Validation xatoliklari',
        errors: validationErrors,
      });
    }

    // Parollarni tekshirish
    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Parollar mos kelmaydi',
      });
    }

    // Mavjud foydalanuvchini tekshirish
    const existingUser = await User.findOne({
      $or: [{ email: email }, { username: username }],
    });

    if (existingUser) {
      const field = existingUser.email === email ? 'Email' : 'Username';
      return res.status(409).json({
        success: false,
        message: `${field} allaqachon ro'yxatdan o'tgan`,
      });
    }

    // Yangi foydalanuvchi yaratish
    const newUser = new User({
      username,
      email,
      password,
    });

    await newUser.save();

    // Token yaratish
    const token = generateToken(newUser._id);

    res.status(201).json({
      success: true,
      message: "Ro'yxatdan o'tish muvaffaqiyatli",
      data: {
        user: {
          id: newUser._id,
          username: newUser.username,
          email: newUser.email,
          role: newUser.role,
          createdAt: newUser.createdAt,
        },
        token: token,
      },
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Server xatoligi',
      error: error.message,
    });
  }
});

// 2. LOGIN ENDPOINT
app.post('/api/auth/login', async (req, res) => {
  try {
    const { identifier, password } = req.body; // identifier - email yoki username

    // Bo'sh maydonlarni tekshirish
    if (!identifier || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email/Username va parol kiritilishi kerak',
      });
    }

    // Foydalanuvchini topish (email yoki username orqali)
    const user = await User.findOne({
      $or: [{ email: identifier.toLowerCase() }, { username: identifier }],
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Noto'g'ri login ma'lumotlari",
      });
    }

    // Parolni tekshirish
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: "Noto'g'ri login ma'lumotlari",
      });
    }

    // Token yaratish
    const token = generateToken(user._id);

    res.status(200).json({
      success: true,
      message: 'Muvaffaqiyatli kirish',
      data: {
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          role: user.role,
          createdAt: user.createdAt,
        },
        token: token,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Server xatoligi',
      error: error.message,
    });
  }
});

// 3. GET USER PROFILE (Protected route)
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      message: "Profil ma'lumotlari",
      data: {
        user: req.user,
      },
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Server xatoligi',
      error: error.message,
    });
  }
});

// 4. LOGOUT ENDPOINT (Token-based logout)
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    // Token-based logout (frontendda token o'chiriladi)
    res.status(200).json({
      success: true,
      message: 'Muvaffaqiyatli chiqish',
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Server xatoligi',
      error: error.message,
    });
  }
});

// 5. PASSWORD CHANGE ENDPOINT
app.put('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmNewPassword } = req.body;

    // Validation
    if (!currentPassword || !newPassword || !confirmNewPassword) {
      return res.status(400).json({
        success: false,
        message: "Barcha maydonlar to'ldirilishi kerak",
      });
    }

    if (newPassword !== confirmNewPassword) {
      return res.status(400).json({
        success: false,
        message: 'Yangi parollar mos kelmaydi',
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Yangi parol kamida 6 ta belgidan iborat bo'lishi kerak",
      });
    }

    // Joriy parolni tekshirish
    const user = await User.findById(req.user.id);
    const isCurrentPasswordValid = await user.comparePassword(currentPassword);

    if (!isCurrentPasswordValid) {
      return res.status(401).json({
        success: false,
        message: "Joriy parol noto'g'ri",
      });
    }

    // Yangi parolni saqlash
    user.password = newPassword;
    await user.save();

    res.status(200).json({
      success: true,
      message: "Parol muvaffaqiyatli o'zgartirildi",
    });
  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({
      success: false,
      message: 'Server xatoligi',
      error: error.message,
    });
  }
});

// 6. GET ALL USERS (Admin only)
app.get('/api/admin/users', authenticateToken, async (req, res) => {
  try {
    // Admin huquqini tekshirish
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Ruxsat berilmagan',
      });
    }

    const users = await User.find().select('-password');

    res.status(200).json({
      success: true,
      message: "Foydalanuvchilar ro'yxati",
      data: {
        users: users,
        count: users.length,
      },
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      message: 'Server xatoligi',
      error: error.message,
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Kutilmagan server xatoligi',
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint topilmadi',
  });
});

// Server ishga tushirish
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server ${PORT} portda ishlamoqda`);
});
