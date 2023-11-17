import jwt from "jsonwebtoken";
import UserModel from "../models/userModel.js";
import { connect } from "mongoose";

const checkUserAuth = async (req, res, next) => {
    let token;
    const { authorization } = req.headers;

    try {
        if (authorization && authorization.startsWith('Bearer')) {
            // Get token from header
            token = authorization.split(' ')[1];
            // console.log("Token : ", token);
            // console.log("Authorization : ", authorization);

            // Verify Token
            const { _id } = jwt.verify(token, process.env.JWT_SECRETE_KEY);
            // console.log(_id);


            // Get user from token
            // Selecting all userDetailes except password so thats why we do "-password"
            req.user = await UserModel.findById(_id).select('-password');
            next();
        } else {
            res.status(401).send({ "status": "failed", "message": "Unauthorized User, No token...!" });
        }
    } catch (error) {
        console.log(error);
        res.status(401).send({ "status": "failed", "message": "Unauthorized User...!" });
    }

    // if (!token) {
    //     res.status(401).send({ "status": "failed", "message": "Unauthorized User, No token...!" });
    // }
}

export default checkUserAuth;