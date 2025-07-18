import mongoose from "mongoose";

const PasswordSchema=new mongoose.Schema({
    email:String,
    id:String,
    site:String,
    username:String,
    password:String,
})

export const Password=mongoose.model('Password',PasswordSchema)
