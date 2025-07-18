import mongoose from "mongoose";

const ResetTokenSchema=new mongoose.Schema({
    token:String,
    email:String,
    expiry:Date,
})

export const ResetToken=mongoose.model('ResetToken',ResetTokenSchema)
