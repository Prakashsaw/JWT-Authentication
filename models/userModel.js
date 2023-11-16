import mongoose from "mongoose";

// Defining Schema
const userSchema = new mongoose.Schema(
    {
        username: {
            type: String,
            required: true,
            trim: true,
        },
        email: {
            type: String,
            required: true,
            trim: true,
        },
        password: {
            type: String,
            required: true,
            trim: true,
        },
        termsConditions: {
            type: Boolean,
            required: true
        }
    },
    {
        timestamps: true
    }
)

// Creating Model
const UserModel = mongoose.model("User", userSchema);
export default UserModel;