import { User } from '../models/user.model.js';
import { ApiError } from '../utils/ApiError.js';
import { ApiResponse } from '../utils/ApiResponse.js';
import asyncHandler from "../utils/asyncHandler.js";
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const generateAccessAndRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });

        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(500, 'Token generation failed');
    }
}

const registerUser = asyncHandler(async (req, res) => {
    //get user data
    //validate
    //check if user exists
    //craete new user
    //remove password from response
    //send response

    const { userName, email, password, referralCode } = req.body;

    if (!userName || !email || !password) {
        throw new ApiError(400, "All fields are required");
    }

    const existedUser = await User.findOne({
        $or: [{ userName }, { email }]
    })

    if (existedUser) {
        throw new ApiError(409, "User already exists");
    }

    let referredBy = null;

    if (referralCode) {
        const refUser = await User.findOne({ referralCode });
        if (!refUser) {
            throw new ApiError(400, "Invalid referral code");
        }
        referredBy = refUser._id;
    }

    const user = await User.create({
        userName,
        email,
        password,
        referralCode: crypto.randomBytes(4).toString('hex'),
        referredBy
    })

    const createdUser = await User.findById(user._id).select(
        '-password -refreshToken'
    )

    return res
        .status(201)
        .json(
            new ApiResponse(201, createdUser, 'User registered successfully')
        )
})

const loginUser = asyncHandler(async (req, res) => {
    //get user data
    //validate
    //find user
    //check password
    //generate tokens
    //send cookies
    //send response

    const { email, password, userName } = req.body;

    if (!email && !userName) {
        throw new ApiError(400, "Email or Username are required");
    }

    if (!password) {
        throw new ApiError(400, "Password is required");
    }

    const user = await User.findOne({
        $or: [{ email }, { userName }]
    }).select('+password');

    if (!user) {
        throw new ApiError(404, "User not found");
    }

    if (!user.isActive) {
        throw new ApiError(403, "User account is deactivated");
    }

    const isPasswordCorrect = await user.isPasswordCorrect(password);

    if (!isPasswordCorrect) {
        throw new ApiError(401, "Invalid password");
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id);

    const loggedInUser = await User.findById(user._id).select(
        '-password -refreshToken'
    )

    const options = {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
    }

    return res
        .status(200)
        .cookie('accessToken', accessToken, options)
        .cookie('refreshToken', refreshToken, options)
        .json(
            new ApiResponse(
                200,
                {
                    user: loggedInUser,
                    accessToken,
                    refreshToken,
                },
                'User logged in successfully'
            )
        )
})

const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true,
        sameSite: 'strict'
    }

    return res
        .status(200)
        .clearCookie('accessToken', options)
        .clearCookie('refreshToken', options)
        .json(
            new ApiResponse(
                200,
                null,
                'User logged out successfully'
            )
        )
})

const changeCurrentUserPassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
        throw new ApiError(400, "Old password and new password are required");
    }

    const user = await User.findById(req.user._id).select('+password');

    if (!user) {
        throw new ApiError(404, "User not found");
    }

    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

    if (!isPasswordCorrect) {
        throw new ApiError(401, "Old password is incorrect");
    }

    user.password = newPassword;
    await user.save({ validateBeforeSave: true });

    return res
        .status(200)
        .json(
            new ApiResponse(
                200,
                {},
                "Password changed successfully"
            )
        )
})

const getCurrentUser = asyncHandler(async (req, res) => {
    return res
        .status(200)
        .json(
            new ApiResponse(200, req.user, "Current user fetched successfully")
        )
})

const updateAccountDetails = asyncHandler(async (req, res) => {
    const { userName, email } = req.body;

    if (!userName && !email) {
        throw new ApiError(400, "At least one field is required");
    }

    // Check duplicates
    if (userName) {
        const existingUserName = await User.findOne({
            userName,
            _id: { $ne: req.user._id }
        });
        if (existingUserName) {
            throw new ApiError(409, "Username already in use");
        }
    }

    if (email) {
        const existingEmail = await User.findOne({
            email,
            _id: { $ne: req.user._id }
        });
        if (existingEmail) {
            throw new ApiError(409, "Email already in use");
        }
    }

    const updatedUser = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                ...(userName && { userName }),
                ...(email && { email }),
            },
        },
        {
            new: true,
            runValidators: true,
        }
    ).select("-password");

    if (!updatedUser) {
        throw new ApiError(404, "User not found");
    }

    return res.status(200).json(
        new ApiResponse(
            200,
            updatedUser,
            "Account details updated successfully"
        )
    );
})

export {
    generateAccessAndRefreshToken,
    registerUser,
    loginUser,
    logoutUser,
    changeCurrentUserPassword,
    getCurrentUser,
    updateAccountDetails
}