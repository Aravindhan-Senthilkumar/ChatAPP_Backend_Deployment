const dotenv = require('dotenv');
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
dotenv.config();
const app = express();
const port = process.env.PORT
const URI = process.env.MONGO_URI
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const streamifier = require('streamifier');
//Socket io server creating
const http = require('http').createServer(app);
const io = require('socket.io')(http)

//Multer middleware for handling image upload
const storage = multer.memoryStorage();
const upload = multer({ storage }).single('profileImage')

//configuring cloudinary
const cloudinary = require('cloudinary').v2;
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
  });


app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended:false}))
app.use(helmet());
app.disable('x-powered-by');

//Models Importing
const User = require('./models/User');
const Message = require('./models/MessageModel')

app.get('/',(req,res) => {
    res.status(200).json({ message: "Welcome to Chat App Backend" })
})

mongoose.connect(URI).then(() => {
    console.log("Connected to MongoDB Successfully")
}).catch((error) => {
    console.log("Error connecting to MongoDB",error);
});

app.listen(port,(req,res) => {
    console.log(`Listening to port ${port}`)
})


//endpoint to register new user
app.post('/register',async (req,res) => {
    //Getting name,email,password from frontEnd
    const { email,password,fullName } = req.body;
    try{
        if(!email || !password){
            return res.status(404).json({ message:"Please fill up user credentials" })
        }

        //Password must be atleast 8 characters long
        if(password.length < 8){
           return res.status(400).json({ message: "Password must be at least 8 characters long."  })
        }
        //checking for existing user 
        const existingUser = await User.findOne({ email:email });

        if(existingUser){
            return res.status(404).json({ message:"User already exists" })
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password,salt);
        const newUser = new User({ email,fullName,password:hashedPassword })

        //Creating new user credentials
        if(newUser){
            //generate jwt token
            const token = jwt.sign({ userId:newUser._id },process.env.JWT_SECRET_KEY,{ expiresIn: '7d' })
             //saving in db
            await newUser.save();
            return res.status(200).json({ message:"User successfully registered",token,userId:newUser._id})
        }else{
            return res.status(404).json({ message:"Error registering" })
        }
    }catch(error){
        return res.status(404).json({ message:"Error Registering" })
    }
})


//endpoint to login existing user
app.post('/login',async (req,res) => {
   const { email,password } = req.body;

   if(!email || !password){
    return res.status(500).json({ message: "Please fill up user credentials" })
   }

   const user = await User.findOne({ email })
   if(!user){
    return res.status(500).json({ message: "You must be new user" })
   }

   const isMatch = await bcrypt.compare(password,user.password)
   if(!isMatch){
    return res.status(404).json({ message: "Mismatch Password" })
   }
   try{
    const token = jwt.sign({ userId:user._id },process.env.JWT_SECRET_KEY,{ expiresIn:'7d' })

    res.status(200).json({ message: "Login success",token,fullName:user.fullName,email,userId:user._id,profilePhoto:user.profilePhoto })
   }catch(error){
    return res.status(404).json({ message: "Error login" })
   }
 })

//endpoint to update profilepicture
app.put('/update-profile', upload, async (req, res) => {
    try {
      const userId = req.body.userId;
      const file = req.file;
  
      if (!file) {
        return res.status(400).json({ message: "Profile picture is required" });
      }
      //converting buffer into uploadable form
      const stream = streamifier.createReadStream(file.buffer)
      
      const uploadResponse = await cloudinary.uploader.upload_stream({resource_type:'auto'}, async (error,result) => {
        if(error){
            return res.status(500).json({ message: "Error occurred while uploading to Cloudinary" });
        }

        const updatedUser = await User.findByIdAndUpdate(userId, { profilePhoto: result.secure_url }, { new: true });

        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found' });
          }
        
          res.status(200).json(updatedUser);
      })
      // Pipe the stream to Cloudinary
    stream.pipe(uploadResponse);
      
    } catch (error) {
      console.error(error);  // Log the error for debugging
      res.status(500).json({ message: "Error occurred in internal server while uploading profile picture" });
    }
  });


//endpoint to get all the users to find friends screen
app.get('/users/:userId',async(req,res) => {
    try{
        const userId = req.params.userId;
        //friends list of arrays
        const userWithFriends = await User.findById(userId).populate("friends")

        //mapping through friendsIds
        const friendIds = userWithFriends.friends.map((item) => item._id)

        const users = await User.find({_id: {$nin:[userId,...friendIds]}}).select("-password")
        if(!users){
            return res.status(404).json({ message: "Users not found" })
        }
        res.status(200).json(users)
    }catch(error){
        res.status(500).json({ message:"Error in internal server while fetching users" })
    }
})


//endpoint to send request to the users
app.post('/sendrequest',async (req,res) => {
    try{
        const {senderId,receiverId,message} = req.body;
    //Check for receiver Id
    const receiver = await User.findById(receiverId);
    if(!receiver){
        return res.status(404).json({ message:"Receiver not found" })
    }
    //Check for avoiding duplication of requests
    const requestExists = await receiver.requests.some((request) => request.from.toString() === senderId)
    if(requestExists){
      return res.status(400).json({ message: "Request already sent to this user" });
    }
    receiver.requests.push({ from:senderId,message });
    await receiver.save();

    res.status(200).json({ message:"Request sent successfully" })
    }catch(error){
        return res.status(500).json({ message:"Error occurred in internal server" })
    }
})

//endpoint to getrequest from senderId
app.get('/getrequests/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;

        // Populate requests and friends list
        const user = await User.findById(userId)
            .populate("requests.from", "fullName email profilePhoto")
            .populate("friends", "_id"); // Populate only IDs of friends

        if (!user) {
            return res.status(404).json({ message: "Error finding user" });
        }

        // Convert friends array to a Set for faster lookup
        const friendIds = new Set(user.friends.map(friend => friend._id.toString()));

        // Filter out requests where request.from._id exists in friends
        const filteredRequests = user.requests.filter(request => 
            !friendIds.has(request.from._id.toString()) // Remove if in friends
        );

        res.status(200).json(filteredRequests);
    } catch (error) {
        console.error("Error fetching requests:", error);
        return res.status(500).json({ message: "Error occurred in internal server" });
    }
});

//endpoint to accept request
app.post('/acceptrequest',async (req,res) => {
    try{
        const {userId,requestId} = req.body;
        const user = await User.findById(userId);

        if(!user){
            return res.status(404).json({ message:"Error finding user" })
        }
        const isFriendExists = await user.friends.some((friend) => friend.toString() === requestId )

        if(isFriendExists){
            return res.status(404).json({ message:"Friend already exists" })
        }
        const updatedUser = await User.findByIdAndUpdate(userId,{ $pull: {requests: {from: requestId}}},{new:true} )

        if(!updatedUser){
            return res.status(404).json({ message:"Error handling user requests" })
        }

        await User.findByIdAndUpdate(userId,{ $push: {friends:requestId} });
        const friendUser = await User.findByIdAndUpdate(requestId,{ $push: { friends:userId } });
        if(!friendUser){
            return res.status(404).json({ message:"Friends not found" })
        }
        res.status(200).json({ message:"Request accepted successfully" })
    }catch(error){
        return res.status(500).json({ message:"Error occurred in internal server" })
    }
});

//endpoint to delete request 
app.delete('/deleterequest',async (req,res) => {
    try{
        const {userId,requestId} = req.body;
        const user = await User.findById(userId);

        if(!user){
            return res.status(404).json({ message:"Error finding user" })
        }

        const updatedUser = await User.findByIdAndUpdate(userId,{ $pull: {requests: {from: requestId}}},{new:true} )

        if(!updatedUser){
            return res.status(404).json({ message:"Error updating user requests"})
        }

        res.status(200).json({ message:"Request rejected successfully",updatedUser })
    }catch(error){
        return res.status(500).json({ message:"Error occurred in internal server" })
    }
});

//endpoint to get all the friends in homescreen/chatscreen
app.get('/user/:userId', async (req, res) => {
    try {
      const { userId } = req.params;
  
      const users = await User.findById(userId).populate("friends", "fullName email profilePhoto");
  
      const uniqueFriends = Array.from(new Set(users.friends.map(friend => friend._id)))
        .map(id => {
          return users.friends.find(friend => friend._id.toString() === id.toString());
        });
  
      res.status(200).json(uniqueFriends);
    } catch (error) {
        return res.status(500).json({ message: "Error occurred in internal server" });
    }
  });



// { "userId" : "socketId" }
const userSocketMap = {};

io.on('connection', socket => {
    console.log("A user is connected",socket.id);

    const userId = socket.handshake.query.userId;

    console.log("userId",userId);

    if(userId !== "undefined"){
        userSocketMap[userId] = socket.id;
    }

    console.log("user socket data",userSocketMap);

    socket.on("disconnect", () => {
        console.log("user disconnected",socket.id);

        delete userSocketMap[userId];
    })

    socket.on('sendMessage', ({ senderId, receiverId, message }) => {
        try {
          const receiverSocketId = userSocketMap[receiverId];
          if (receiverSocketId) {
            io.to(receiverSocketId).emit("receivingMessage", { senderId, message });
          }
        } catch (error) {
          console.error('Socket error:', error);
        }
      });
})

http.listen(process.env.SOCKET_PORT,() =>{
    console.log(`Socket.io is running on 4000`)
})

//endpoint to post messages to backend db
app.post('/sendmessage',async (req,res) => {
    try{
        const {senderId,receiverId,message} = req.body;

        const newMessage = new Message({
            senderId,
            receiverId,
            message
        })

        await newMessage.save()

        const receiverSocketId = userSocketMap[receiverId];

        if(receiverSocketId){
            console.log("Emitting receive Message Event to the receiver",receiverSocketId)
            io.to(receiverSocketId).emit("newMessage",newMessage)
        }else{
            console.log("Receiver socket ID isn't found")
        }

        res.status(200).json(newMessage)
    }catch(error){
        res.status(500).json({ message:"Error occurred in internal server" })
    }
})

//endpoint to get all messages from backend
app.get('/message',async (req,res) => {
    try{
        const { senderId,receiverId } = req.query;

        const messages = await Message.find({
            $or:[
                {senderId:senderId,receiverId:receiverId},
                {senderId:receiverId,receiverId:senderId}
            ]
        }).populate("senderId","_id name");

        res.status(200).json(messages)
    }catch(error){
        return res.status(500).json({ message:"Error occurred in internal server" })
    }
})

const crypto = require('crypto');
const nodemailer = require('nodemailer');



//endpoint to implement send OTP to user for verifying
const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

app.post('/forgotpassword', async (req, res) => {
    try {
        const { email } = req.body;

        // Validate email with regex
        if (!email || !emailRegex.test(email)) {
            return res.status(400).json({ message: "Invalid Email format" });
        }

        const user = await User.findOne({ email });

        // Checking if the user exists
        if (!user) {
            return res.status(404).json({ message: "Error finding user with this email" });
        }

        // Generating OTP using crypto
        const otp = crypto.randomInt(100000, 999999).toString();
        const hashedOTP = await bcrypt.hash(otp, 10);

        // Saving OTP temporarily in user model
        user.resetpasswordOTP = hashedOTP;
        user.resetPasswordExpires = Date.now() + 10 * 60 * 1000;

        await user.save();

        // Creating nodemailer for mail sending
        const transporter = nodemailer.createTransport({
            service: "Gmail",
            auth: {
                user: process.env.NODE_MAIL,
                pass: process.env.NODE_MAIL_PASS
            }
        });

        await transporter.sendMail({
            from: process.env.NODE_MAIL,
            to: email,
            subject: "Your Password Reset OTP",
            text: `Your OTP for password reset is ${otp}. It is valid for 10 minutes.`,
        });

        res.status(200).json({ message: "OTP sent successfully" });
    } catch (error) {
        console.error("Error:", error);
        return res.status(500).json({ message: "Error occurred in internal server" });
    }
});


//endpoint to verify the otp and proceed changing password
app.post('/verifyotp',async (req,res) => {
    const { otp,email } = req.body
    try{
        const user = await User.findOne({ email });

        //Check if the user is valid or not
        if(!user){
            return res.status(404).json({ message: "User not found" });
        }

        //Check if OTP is expired
        if(Date.now() > user.resetPasswordExpires) {
            return res.status(400).json({ message: "OTP has expired" });
        }

        //Check if the otp is valid or not
        const isValid = await bcrypt.compare(otp,user.resetpasswordOTP)
        if(!isValid) {
            return res.status(400).json({ message: "Invalid OTP" });
        }

        res.status(200).json({ message: "OTP verified successfully" });
    }catch(error){
        res.status(500).json({ message: "Error occurred in internal server" });
    }
})

//endpoint to reset password after successful verifying of OTP
app.post('/resetpassword',async (req,res) => {
    try{
        const { password,email } = req.body;
        if(!password){
            return res.status(400).json({ message: "Please provide password" })
        }

        if(password.length < 8){
            return res.status(400).json({ message: "Password must be at least 8 characters long."  })
        }
        //Check if the user exists
        const user = await User.findOne({ email });
        if(!user){
            return res.status(404).json({ message: "User not found" });
        }

        //change password after successful otp verification
        const salt = await bcrypt.genSalt(10);
        const hashedNewPassword = await bcrypt.hash(password,salt);

        user.password = hashedNewPassword

        //clear otp fields
        user.resetpasswordOTP = undefined;
        user.resetPasswordExpires = undefined;

        //Saving user
        await user.save();

        res.status(200).json({ message: "Password reset successfully" });
    }catch(error){
        return res.status(500).json({ message: "Error occurred in internal server" });
    }
})

//endpoint to delete user from friend list
app.delete('/deleteuser',async (req,res) => {
    try{
        const { userId,friendId } = req.body

        const user = await User.findById(userId)
        if(!user){
            return res.status(404).json({ message: "User not found" });
        }

        const updatedUser = await User.findByIdAndUpdate(userId,{ $pull: {friends : friendId}},{ new:true })

        const updatedFriendUser = await User.findByIdAndUpdate(friendId,{$pull: {friends : userId}},{new:true})
        if(!updatedUser || !updatedFriendUser){
            return res.status(404).json({ message:"Error deleting user"})
        }

        res.status(200).json({ message:"User deleted successfully",updatedUser,updatedFriendUser })
    }catch(error){
        return res.status(500).json({ message:"Error occurred in internal server" })
    }
})

//endpoint to delete user account
app.delete('/deleteownaccount', async(req,res) => {
    try{
        const { userId } = req.body;

        //remove friends
        const result =  await User.updateMany({friends: userId},{$pull: {friends: userId}});

        const result2 = await User.updateMany({ 'requests.from' : userId},{$pull: { requests: {from : userId}}})

        if (result.modifiedCount > 0 || result2.modifiedCount > 0) {
            console.log("Deleted user from all friends and requests fields.");
        } else {
            console.log("No users had this user in their friends or requests fields.");
        }
        //find user
        const deleteduser = await User.findByIdAndDelete(userId)

        if(!deleteduser){
            return res.status(404).json({ message: 'User not found' });
        }
        res.status(200).json({ message: 'User deleted successfully' });
    }catch(error){
        return res.status(500).json({ message: 'Server error' });
    }
})