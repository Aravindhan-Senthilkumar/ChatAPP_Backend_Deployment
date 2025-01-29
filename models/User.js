const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    email: {
        type:String,
        required:true,
        unique:true
    },
    password: {
        type:String,
        required:true,
    },
    fullName:{
        type:String,
        required:true
    },
    profilePhoto:{
        type:String,
        default:null,
    },
    requests:[{
        from:{
            type:mongoose.Schema.Types.ObjectId,
            ref:"User",
            required:true
        },
        message:{
            type:String,
            required:true
        },
        status:{
            type:String,
            enum:["pending","accepted","rejected"]
        }
    }],
    friends:[{
        type:mongoose.Schema.Types.ObjectId,
        ref:"User"
    }],
    resetpasswordOTP: { type : String },
    resetPasswordExpires : { type: Date }
})

module.exports = mongoose.model('User',UserSchema);



