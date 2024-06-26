import { asyncHandler } from "../utils/asyncHandler.js"
import { APIError } from "../utils/APIError.js"
import jwt from "jsonwebtoken"
import { User } from "../models/user.models.js"

export const auth = asyncHandler(async(req, _, next) => {
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "")
        console.log(token);
        if(!token){
            throw new APIError(401, "Unathorized rqeuest")
        }
    
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
    
        const user = await User.findById(decodedToken?._id).select(
            "-password -refreshToken"
        )
        if(!user){
            throw new APIError(401, "Invalid  Access Token")
        }
    
        req.user = user;
        next();
    } catch (error) {
        throw new APIError(401, error?.message || "Invalid access token")
    }
})