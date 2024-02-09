import mongoose from "mongoose";

// const MONGO_URL = process.env.MONGO_URL;

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URL);
    console.log("MongoDB Connection Established...");
  } catch (error) {
    console.log(error);
  }
};

export default connectDB;
