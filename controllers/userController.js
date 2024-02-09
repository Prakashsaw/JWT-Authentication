import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import validator from "validator";
import UserModel from "../models/userModel.js";
import transporter from "../config/emailConfig.js";
import dotenv from "dotenv";
dotenv.config();

class userController {
  // Code for generating jwt token
  static createToken = (_id) => {
    const jwtSecreteKey = process.env.JWT_SECRETE_KEY;

    return jwt.sign({ _id }, jwtSecreteKey, { expiresIn: "3d" });
  };

  static userRegistration = async (req, res) => {
    // These are fields which will come from frontend
    const { username, email, password, confirmpassword, tc } = req.body;
    try {
      let user = await UserModel.findOne({ email: email });
      if (user) {
        return res
          .status(400)
          .json({ status: "failed", message: "User already exists..." });
      }

      if (!username || !email || !password || !confirmpassword || !tc) {
        return res
          .status(400)
          .json({ Status: "failed", message: "All fields are required..." });
      }

      if (!validator.isEmail(email)) {
        return res.status(400).json({
          Status: "failed",
          message: "Email must be a valid email...",
        });
      }

      if (!validator.isStrongPassword(password)) {
        return res.status(400).json({
          Status: "failed",
          message: "Password must be a strong password...",
        });
      }

      if (password !== confirmpassword) {
        return res.status(400).json({
          Status: "failed",
          message: "password and confirmpassword mismatched!",
        });
      }

      // Creating a hashCode for password and keep this hashcode in database
      // instead of actual password
      const salt = await bcrypt.genSalt(10);
      const passwordHashingCode = await bcrypt.hash(password, salt);

      user = new UserModel({
        username: username,
        email: email,
        password: passwordHashingCode,
        termsConditions: tc,
      });
      await user.save();

      // Now start the JWT process here
      const jwt_token = this.createToken(user._id);

      res.status(200).json({
        Status: "Success",
        message: "Successfully Registered...!",
        _id: user._id,
        username,
        email,
        jwt_token,
      });
    } catch (error) {
      console.log(error);
      res
        .status(400)
        .json({ status: "failed", message: "Unable to register...!" });
    }
  };

  static userLogin = async (req, res) => {
    const { email, password } = req.body;
    try {
      const user = await UserModel.findOne({ email: email });

      if (!user) {
        return res
          .status(400)
          .json({ Status: "failed", message: "Invalid email or password...!" });
      }

      // Validate user password
      const validatePassword = await bcrypt.compare(password, user.password);
      if (user.email !== email || !validatePassword) {
        return res.status(400).json({
          Status: "failed",
          message: "Incorrect email or Password...!",
        });
      }

      // Now start the JWT process here
      const jwt_token = this.createToken(user._id);

      res.status(200).json({
        Status: "Success",
        message: "Successfully Loggedin...!",
        _id: user._id,
        username: user.username,
        email,
        jwt_token,
      });
    } catch (error) {
      console.log(error);
      res
        .status(400)
        .json({ status: "failed", message: "Unable to login...!" });
    }
  };

  static changeUserPassword = async (req, res) => {
    // Now we want validated user and for that we use middleware
    const { password, confirmpassword } = req.body;
    try {
      if (!password || !confirmpassword) {
        return res
          .status(400)
          .json({ Status: "failed", message: "All fields are required...!" });
      }

      if (password !== confirmpassword) {
        return res.status(400).json({
          Status: "failed",
          message: "new password and new confirm password mismatched!",
        });
      }

      const salt = await bcrypt.genSalt(10);
      const newHashPassword = await bcrypt.hash(password, salt);
      // console.log(req.user);

      await UserModel.findByIdAndUpdate(req.user._id, {
        $set: { password: newHashPassword },
      });

      res.status(200).json({
        Status: "Success",
        message: "Successfully Changed Password...!",
      });
    } catch (error) {
      console.log(error);
      res.status(400).json({
        status: "failed",
        message: "Unable to change the password...!",
      });
    }
  };

  static loggedUser = async (req, res) => {
    res.send({ user: req.user });
  };

  static sendUserPasswordResetEmail = async (req, res) => {
    const { email } = req.body;

    try {
      if (!email) {
        return res
          .status(400)
          .json({ status: "failed", message: "Email is required...!" });
      }

      const user = await UserModel.findOne({ email: email });

      if (!user) {
        return res
          .status(400)
          .json({ status: "failed", message: "Email doesn't exists...!" });
      }

      const secrete = user._id + process.env.JWT_SECRETE_KEY;
      const token = jwt.sign({ _id: user._id }, secrete, { expiresIn: "30m" });

      const link = `http://127.0.0.1:3000/api/v1/user/reset/${user._id}/${token}`;
      // Like- /api/v1/reset/:id/:token in frontend
      // console.log(link); // link generated and sent via email, now reset password and enter new password

      console.log(user.username);

      // Now Send Email
      const info = await transporter.sendMail({
        from: process.env.EMAIL_FROM,
        to: user.email,
        subject:
          "You Requested for password reset so this email is regarding password reset.",
        html: `
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta http-equiv="X-UA-Compatible" content="IE=edge">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Document</title>
                    <style>
                        *{
                            box-sizing: border-box;
                        }
                        table{
                            border: transparent;
                            background-color: rgb(220, 216, 216);
                            border: none;
                            border-spacing: 0px;
                            border-radius: 0.25rem; 
                            /* box-shadow: 2px 3px 10px;  */
                        
                        }
                        body{
                            /* background-color: rgb(248, 225, 217); */
                            display: flex;
                            flex-direction: column-reverse;
                            justify-content: center;
                            align-items: center;
                            font-size: 16px;
                        }
                        .title{
                            margin-bottom: 1rem;
                            overflow: hidden;
                            color: rgb(4, 55, 150);
                            font-size: 2em;
                            font-weight: bolder;
                        
                            font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                            padding-top: 1rem;
                            padding-bottom: 1rem;
                        }
                        tr{
                            text-align: center;
                        }
                        
                        .top{
                            background-color: rgb(4, 55, 150);
                            color: white;
                            padding-bottom: 1rem;
                        }
                        .msg{
                            font-size: large;
                            margin-top: 1.5rem;
                            margin-bottom: 1.5rem;
                        }
                
                        
                        .code{
                            border-radius: 4px;
                            color: white;
                            font-size: 2em;
                            display: initial;
                            padding-left: 1rem;
                            padding-right: 1rem;
                            font-family:'Gill Sans', 'Gill Sans MT', Calibri, 'Trebuchet MS', sans-serif ;
                
                        }
                
                        .contactus{
                            margin-top: 1rem;
                            padding-top: 1rem;
                            /* line-height: 30px; */
                            font-size: 1.5rem;
                            padding-bottom: 1rem;
                        
                        }
                        .copywrite{
                            background-color: rgb(4, 55, 150);
                            color: white;
                            width: 100%;
                            padding-left: 0px;
                            padding-right: 0px;
                            height: 1.75rem;
                            text-align: center;
                            padding-top: 5px;
                            border-bottom-left-radius: 0.25rem; 
                            border-bottom-right-radius: 0.25rem;
                        }
                    
                    </style>
                </head>
                <body>
                    <table  style="background-color: rgb(237, 242, 243);;">
                        <th class="title"> Prakash<img src="https://drive.google.com/uc?export=view&id=1SM_3kWz9cckg7bCiQDwje3X76BKySSzr" alt="logo">Company</th>
                        <tbody>
                            <tr class="top">
                                <td>
                                    <img src="https://drive.google.com/uc?export=view&id=1GhR10Ud4KMVY5dHahmrCQMzGRATkZGtk" alt="" width="150">
                                    <p>Welcome To Prakash and Company!<br><br>
                                        <span style="font-size: 2rem;">Reset Your Password</span>
                                    </p>
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <div class="msg">Hi, ${user.username}<br>Please Click Below Link to Reset Your Password! This will redirect to reset form where you will have to give new password.</div>
                                    <div class="code"><a href=${link}>Click here</a></div>
                                    <div><br></div>
                                </td>
                            </tr>
                        <tr>
                        
                        </tr>
                            <tr class="footer">
                                <td style=" background-color: rgb(217, 223, 228);">
                                    <div class="contactus"><span style="color: rgb(4, 55, 150);  font-weight: bold;">Get in touch</span><br>Phone: +91-8873323323<br>Email: ${process.env.EMAIL_FROM}</div>
                                    <div class="copywrite">Copyrights © Prakash $ Company All Rights Reserved</div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </body>
                </html>`, // Html Body Ending Here
      });

      // console.log(info);

      res.status(200).json({
        status: "success",
        message: "Password Reset Email Sent. Please Check Your Email...!",
        "Sent Email Info": info,
      });
    } catch (error) {
      console.log(error);
      res.status(400).json({
        status: "failed",
        message: "Unable to send the email to reset the password...!",
      });
    }
  };

  static userPasswordReset = async (req, res) => {
    const { password, confirmpassword } = req.body;
    const { id, token } = req.params; // by params we get things which is in links
    console.log(id);
    console.log(token);

    try {
      if (!password || !confirmpassword) {
        return res
          .status(400)
          .json({ status: "failed", message: "All fields are required...!" });
      }

      if (password !== confirmpassword) {
        return res.status(400).json({
          status: "failed",
          message: "New Password and New Confirm Password doesn't match...!",
        });
      }

      const user = await UserModel.findById(id);
      const new_secrete = user._id + process.env.JWT_SECRETE_KEY;
      const userID = jwt.verify(token, new_secrete);
      console.log(userID);

      // Now hash password and update into database
      const salt = await bcrypt.genSalt(10);
      const newHashPassword = await bcrypt.hash(password, salt);
      await UserModel.findByIdAndUpdate(user._id, {
        $set: { password: newHashPassword },
      });

      res.status(200).json({
        Status: "Success",
        message: "Password Reset Successfully...!",
      });
    } catch (error) {
      console.log(error);
      res.status(400).json({
        status: "failed",
        message: "Unable to Reset the password...! May be Invalid Token...",
      });
    }
  };
}

export default userController;
