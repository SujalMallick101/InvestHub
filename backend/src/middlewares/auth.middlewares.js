import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";

export const verifyJWT = asyncHandler(async (req, res, next) => {
    try {
        const token =
            req.cookies?.accessToken ||
            req.header('authorization')?.replace('Bearer ', '');

        if (!token) {
            throw new ApiError(401, "Unauthorized Access")
        }
        const decodedToken = jwt.verify(token.trim(), process.env.ACCESS_TOKEN_SECRET);

        const user = await User.findById(decodedToken?._id).select(
            '-password -refreshToken'
        );

        if (!user) {
            throw new ApiError(401, "Unauthorized Access")
        }
        req.user = user;
        next();
    } catch (error) {
        throw new ApiError(401, "Unauthorized Access")
    }
})