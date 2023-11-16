import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import validator from 'validator';
import UserModel from '../models/userModel.js';

class userController {
    // Code for generating jwt token
    static createToken = (_id) => {
        const jwtSecreteKey = process.env.JWT_SECRETE_KEY;

        return jwt.sign({ _id }, jwtSecreteKey, { expiresIn: "3d" });
    }

    static userRegistration = async (req, res) => {
        // These are fields which will come from frontend 
        const { username, email, password, confirmpassword, tc } = req.body;
        try {
            let user = await UserModel.findOne({ email: email });
            if (user) {
                return res.status(400).json({ "status": "failed", "message": "User already exists..." });
            }


            if (!username || !email || !password || !confirmpassword || !tc) {
                return res.status(400).json({ "Status": "failed", "message": "All fields are required..." });
            }

            if (!validator.isEmail(email)) {
                return res.status(400).json({ "Status": "failed", "message": "Email must be a valid email..." });
            }

            if (!validator.isStrongPassword(password)) {
                return res.status(400).json({ "Status": "failed", "message": "Password must be a strong password..." });
            }

            if (password !== confirmpassword) {
                return res.status(400).json({ "Status": "failed", "message": "password and confirmpassword mismatched!" });
            }

            // Creating a hashCode for password and keep this hashcode in database 
            // instead of actual password 
            const salt = await bcrypt.genSalt(20);
            const passwordHashingCode = await bcrypt.hash(password, salt);

            user = new UserModel({ username: username, email: email, password: passwordHashingCode, termsConditions: tc });
            await user.save();

            // Now start the JWT process here
            const jwt_token = this.createToken(user._id);

            res.status(200).json({ "Status": "Success", "message": "Successfully Registered...!", _id: user._id, username, email, jwt_token });

        } catch (error) {
            console.log(error);
            res.status(400).json({ "status": "failed", "message": "Unable to register...!" });
        }

    }

    static userLogin = async (req, res) => {
        const { email, password } = req.body;
        try {
            const user = await UserModel.findOne({ email: email });

            if (!user) {
                return res.status(400).json({ "Status": "failed", "message": "Invalid email or password...!" });
            }

            // Validate user password
            const validatePassword = await bcrypt.compare(password, user.password);
            if ((user.email !== email) || !validatePassword) {
                return res.status(400).json({ "Status": "failed", "message": "Incorrect email or Password...!" });
            }

            // Now start the JWT process here
            const jwt_token = this.createToken(user._id);

            res.status(200).json({ "Status": "Success", "message": "Successfully Loggedin...!", _id: user._id, username: user.username, email, jwt_token });

        } catch (error) {
            console.log(error);
            res.status(400).json({ "status": "failed", "message": "Unable to login...!" });
        }

    }

}

export default userController;

