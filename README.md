# Full Stack Let'sChat App

\
*A real-time chat application built with React Native and Node.js.*

## 📌 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [API Endpoints](#api-endpoints)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

---

## 🚀 Overview

**Let'sChat** is a full-stack real-time chat application that allows users to send messages, media, and track online statuses. It is divided into a **React Native frontend** and a **Node.js backend**, providing a seamless user experience across devices.

The backend is live at: **[Let'sChat Backend](https://letschat-app-backend.onrender.com)**

Download the app: [Google Drive Link](https://drive.google.com/file/d/1U8DK3MQZErlsI83o1pCu4Xq5Sm7W0MXC/view?usp=sharing)

---

## 🌟 Features

✅ Real-time messaging with WebSockets (Socket.IO)\
✅ User authentication (JWT-based) with **ZeroBounce API for email validation**\
✅ Forgot password implementation with **OTP verification**\
✅ Friend requests: **Send, Accept, Delete, Unfollow, and Remove from Friend List**\
✅ **Cloudinary API for profile updates**\
✅ Secure data storage with MongoDB\
✅ Global state management using **Zustand & Context API**\
✅ API endpoints to **delete the current account permanently**\
✅ Responsive & interactive UI

---

## 🛠 Tech Stack

### **Frontend (Client - React Native)**

- React Native
- React Native CLI
- Zustand & Context API for state management
- Socket.IO Client for real-time communication
- React Navigation for seamless user experience

### **Backend (Server - Node.js & Express)**

- Node.js
- Express.js
- MongoDB with Mongoose
- Socket.IO Server
- JWT Authentication
- ZeroBounce API for email validation
- Cloudinary API for media storage
- Nodemailer for OTP-based password recovery

---

## ⚙️ Installation

### Prerequisites

Ensure you have the following installed:

- [Node.js](https://nodejs.org/)
- [MongoDB](https://www.mongodb.com/)
- [Git](https://git-scm.com/)
- [React Native CLI](https://reactnative.dev/docs/environment-setup)

### Clone the Repository

```sh
git clone --recurse-submodules https://github.com/Aravindhan-Senthilkumar/Full_Stack_Let-sChat_App.git
cd Full_Stack_Let-sChat_App
```

### Setting Up the Server

```sh
cd Server
npm install
npm start
```

### Setting Up the Client

```sh
cd ../Client
npm install
npx react-native run-android  # For Android
npx react-native run-ios      # For iOS
```

---

## 🎯 Usage

1. **Run the backend** to start the WebSocket & API server.
2. **Launch the mobile app** to start chatting.
3. **Sign up / Log in** (email validation with ZeroBounce).
4. **Reset password** using OTP verification.
5. **Send friend requests, accept, remove, or unfollow users.**
6. **Chat in real-time, update your profile, and more!**

---

## 📂 Project Structure

```
Full_Stack_Let-sChat_App/
│-- Client/              # React Native frontend
│-- Server/              # Node.js backend
│-- README.md            # Project documentation
```

### **Client (React Native) Folder Structure**

```
Client/
│-- src/
│   │-- components/       # Reusable UI components
│   │-- screens/          # App screens (Chat, Login, etc.)
│   │-- store/            # Zustand & Context API for global state
│   │-- utils/            # Helper functions
│   │-- services/         # API calls & Socket.IO handling
│-- App.js
```

### **Server (Node.js) Folder Structure**

```
Server/
│-- models/              # Database models (User, Message)
│-- routes/              # API routes
│-- controllers/         # Business logic
│-- config/              # Database & environment configs
│-- server.js            # Entry point
```

---

## 🔥 API Endpoints

### Authentication
- **POST /register** - Register a new user
- **POST /login** - Login an existing user
- **POST /forgotpassword** - Send OTP for password reset
- **POST /verifyotp** - Verify OTP for password reset
- **POST /resetpassword** - Reset password

### User Management
- **PUT /update-profile** - Update profile picture
- **GET /users/:userId** - Get all users except friends
- **GET /user/:userId** - Get all friends of a user
- **DELETE /deleteuser** - Remove a friend
- **DELETE /deleteownaccount** - Delete user account

### Friend Requests
- **POST /sendrequest** - Send a friend request
- **GET /getrequests/:userId** - Get pending friend requests
- **POST /acceptrequest** - Accept a friend request
- **DELETE /deleterequest** - Reject a friend request

### Messaging
- **POST /sendmessage** - Send a message
- **GET /message** - Get chat messages

---

## 🤝 Contributing

We welcome contributions! Follow these steps:

1. **Fork** the repository.
2. **Create a new branch** (`git checkout -b feature/new-feature`).
3. **Commit changes** (`git commit -m "Add new feature"`).
4. **Push to GitHub** (`git push origin feature/new-feature`).
5. **Open a Pull Request**.

---

## 📜 License

This project is licensed under the **MIT License**.

---

## 📧 Contact

For any questions, feel free to reach out:

- **GitHub:** [Aravindhan Senthilkumar](https://github.com/Aravindhan-Senthilkumar)

---





