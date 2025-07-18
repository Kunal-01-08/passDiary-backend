import mongoose from "mongoose";

const UnverifiedUserSchema=new mongoose.Schema({
    email:String,
    password:String,
    createdat:Date
})

export const UnverifiedUser=mongoose.model('UnverifiedUser',UnverifiedUserSchema)
