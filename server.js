import express from "express";
import mongoose from "mongoose";
import { Password } from "./models/Password.js";
import { User } from "./models/User.js";
import jwt from "jsonwebtoken";
import bcrypt, { hash } from "bcrypt";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import { ResetToken} from "./models/ResetToken.js";
import nodemailer from "nodemailer";
import { UnverifiedUser } from "./models/UnverifiedUsers.js";
import validator from "validator"

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());

const sk = process.env.JWT_SECRET;

let con = await mongoose.connect("mongodb://localhost:27017/passDiaryDB");
const port = 3000;

app.post("/Signup", async (req, res) => {
  let n_email = req.body.email;
  let n_password = req.body.password;
  let isValid=validator.isEmail(n_email)
  if(!isValid){
    return res.json({message:"Invalid email format"})
  }

  let unverifiedUserExists = await UnverifiedUser.findOne({ email: n_email });
  if(unverifiedUserExists){
    res.json({ error: "Unverified user already present, please check your inbox for the verification link", status: "Signup failed" });
    return 
  }


  let userExists = await User.find({ email: n_email });
  // console.log(userExists)

  if (userExists.length !== 0) {
    console.log("User already exists");
    return res.json({ error: "User already exists", status: "Signup failed" });
  } else {
    let hashedPassword = await bcrypt.hash(n_password, 10);
    // console.log(hashedPassword)
    let newUser = new UnverifiedUser({ email: n_email, password: hashedPassword, createdat:Date.now()});
    await newUser.save();
    console.log("User added");
    res.json({ message: "New user added , click on the verification link sent on the email, link is active for 10 minutes", status: "Signup successful" });

     const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.MY_EMAIL,
        pass: process.env.APP_PASSWORD,
      },
    });


    const mailOptions = {
  from: process.env.MY_EMAIL,
  to: n_email,
  subject: 'Email verification link',
  text: `Click here to verify your email: http://localhost:5173/EmailVerification?email=${n_email}`
};

 transporter.sendMail(mailOptions, (err, info) => {
  if (err) {
    console.error('Error sending email:', err);
  } else {
    console.log('Email sent:', info.response);
  }
});



  }
});

app.post("/EmailVerification", async (req, res) => {
  let email = req.body.email;
  let user=await UnverifiedUser.findOne({email:email})
  // console.log(email)
  if(!user){
    return res.json({message:"User not found"})
  }
 
    
    let verifiedUser=new User({email:email, password:user.password})
    await verifiedUser.save()
    let dlt=await UnverifiedUser.deleteOne({email:email})
    return res.json({message:"User Verified successfully"})

  
});

app.post("/Login", async (req, res) => {
  let n_email = req.body.email2;
  let n_password = req.body.password2;
  let userExist = await User.find({ email: n_email });
  console.log(userExist[0]);
  if (userExist.length === 1) {
    let cmp = await bcrypt.compare(n_password, userExist[0].password);
    if (cmp) {
      const payload = { email: userExist[0].email };
      const token = jwt.sign(payload, sk, { expiresIn: "1h" });

      res.json({
        message: "User found",
        status: "Login Successful",
        token: token,
      });
    } else {
      res.json({ error: "Password incorrect", status: "Login failed" });
    }
  } else {
    res.json({ error: "No user found", status: "Login failed" });
  }
});

app.get("/", async (req, res) => {
  try {
    let token = req.headers.authorization.split(" ")[1];
    let decoded = jwt.verify(token, sk);
    const passwords = await Password.find({ email: decoded.email });
    res.json(passwords);
  } catch (err) {
    res.json({ error: "Token expired" });
  }
});

app.post("/", (req, res) => {
  try {
    let token = req.headers.authorization.split(" ")[1];
    let decoded = jwt.verify(token, sk);
    const data = req.body;

    const entry = new Password({
      email: decoded.email,
      id: data.id,
      site: data.site,
      username: data.username,
      password: data.password,
    });
    entry.save();
    console.log(entry);

    res.json({ data: "received", response: "sent" });
  } catch (err) {
    res.json({ error: "Token expired" });
  }
});
app.delete("/:slug", async (req, res) => {
  try {
    let token = req.headers.authorization.split(" ")[1];
    let decoded = jwt.verify(token, sk);
    const id = req.params.slug;
    const deletedDoc = await Password.findByIdAndDelete(id);
    res.json({ data: "deleted", response: "sent" });
  } catch (err) {
    res.json({ error: "Token expired" });
  }
});

app.post("/ForgotPassword", async (req, res) => {
  let email = req.body.email;
  let user = await User.findOne({ email: email });

  if (user) {
    let token = crypto.randomBytes(32).toString("hex");
    let RToken = new ResetToken({
      token: token,
      email: email,
      expiry: Date.now() + 10 * 60 * 1000,
    });
    await RToken.save();
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.MY_EMAIL,
        pass: process.env.APP_PASSWORD,
      },
    });


    const mailOptions = {
  from: process.env.MY_EMAIL,
  to: email,
  subject: 'Password Reset',
  text: `Click here to reset your password: http://localhost:5173/ResetPassword?token=${token}`
};

 transporter.sendMail(mailOptions, (err, info) => {
  if (err) {
    console.error('Error sending email:', err);
  } else {
    console.log('Email sent:', info.response);
  }
});

    res.json({
      message: "Reset-Password link sent to your email",
      status: "Process initiated",
    });
  }
  else {
    res.json({
      message: "User does not exist",
      status: "Process terminated",
    });
  }
});

app.post("/ResetPassword", async (req, res) => {
   let {token , newPassword}=req.body
   let tokenInDb=await ResetToken.findOne({token:token})
   console.log(token)
   
   
   if(!tokenInDb){
       return res.json({message:"Invalid token",status:"Password reset failed"})
   }
   else if(tokenInDb.expiry<Date.now()){
      return res.json({message:"Token expired",status:"Password reset failed"})
   }
   else{
      let user=await User.findOne({email:tokenInDb.email})
      if(user){  
            let hashedPassword=await bcrypt.hash(newPassword,10)
            const result = await User.findOneAndUpdate(
               { email: user.email },  // filter
               { password: hashedPassword },  // update
               { new: true }  // return the updated document
            );           
            return res.json({message:"User found",status:"Password reset successful"})           
            let dlt=await ResetToken.deleteOne({token:tokenInDb.token})
      }else{
         return res.json({message:"User not found",status:"Password reset failed"})
      }
      
   }


})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
