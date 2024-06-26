import { asyncHandler } from "../utils/asyncHandler.js"
import { APIError } from "../utils/APIError.js";
import { User } from "../models/user.models.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { APIResponse } from "../utils/APIResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshToken = async(userId) => {
    try {
        const user = await User.findById(userId);
        const refreshToken = await user.generateRefreshToken()
        const accessToken = await user.generateAccessToken()
        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });
        return { refreshToken, accessToken }
    } catch (error) {
        throw new APIError(500, "Something went wrong while generating refresh and access token")
    }
}

const registerUser = asyncHandler(async (req, res) => {
    const {username, email, fullname, password} = req.body

    if (
        [username, email, fullname, password].some((field) =>
            field?.trim() === ""
        )
    ) {
        throw new APIError(400, "All fields are required")
    }

    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    })
    if(existedUser){
        throw new APIError(409, "User with email or username already exist");
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length>0){
        coverImageLocalPath = req.files.coverImage[0].path
    }

    if (!avatarLocalPath) {
        throw new APIError(400, "Avatar file is required");
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath);

    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if(!avatar){
        throw new APIError(400, "Avatar file is required");
    }

    const user = await User.create({
        username: username.toLowerCase(),
        email,
        fullname,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        password
    });

    const createdUser = await User.findById(user._id).select( // delete password and refreshToken while returning user to frontend
        "-password -refreshToken"
    )

    if(!createdUser){
        throw new APIError(500, "Internal server error")
    }

    return res.status(201).json(
        new APIResponse(200, createdUser, "User registered successfully")
    )
});

const loginUser = asyncHandler(async(req, res) => {
    const { email, username, password } = req.body

    if(!username && !email){
        throw new APIError(400, "username and email is required")
    }

    const user = await User.findOne({
        $or: [
            {username}, {email}
        ]
    })
    if(!user){
        throw new APIError(404, "user does not exist")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)
    if(!isPasswordValid){
        throw new APIError(401, "Password is incorrect")
    }

    const { refreshToken, accessToken } = await generateAccessAndRefreshToken(user._id);
    
    const loggedInUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )
    
    const options = {
        httpOnly: true,
        secure: true,
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new APIResponse(
            200, 
            {
                user: loggedInUser, 
                accessToken: accessToken, 
                refreshToken: refreshToken
            },
            "User logged In Successfully"
        )
    )

})

const logoutUser = asyncHandler(async(req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: ""
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(
            new APIResponse(200, {}, "User logged out")
        )
})

const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
    if(!incomingRefreshToken){
        throw new APIError(401, "Unauthorized request")
    }

    try {
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)
        
        const user = await User.findById(decodedToken?._id)
        if(!user){
            throw new APIError(401, "Invalid refresh token");
        }
    
        if(incomingRefreshToken !== user?.refreshToken){
            throw new APIError(401, "Refresh token is expired or used");
        }
    
        const { refreshToken, accessToken } = await generateAccessAndRefreshToken(user._id)
        
        const options = {
            httpOnly: true,
            secure: true
        }
    
        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options)
            .json(
                new APIResponse(
                    200,
                    {
                        accessToken, refreshToken 
                    },
                    "New access token is generated successfully"
                )
            )
    } catch (error) {
        throw new APIError(
            401, error?.message || "Invalid refresh token"
        )
    }
})

const changeCurrentPassword = asyncHandler(async ( req, res) => {
    const {oldPassword, newPassword} = req.body
    
    const user = await User.findById(req.user?._id)

    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)
    if(!isPasswordCorrect){
        throw new APIError(400, "Invalid ")
    }

    user.password = newPassword
    await user.save({validateBeforeSave: false})

    return res
            .status(200)
            .json(
                new APIResponse(200, {}, "Password has been changed successfullly")
            )
})

const getCurrentUser = asyncHandler(async(req, res) => {
    return res
            .status(200)
            .json(200, req.user, "Current user fetched successfully")
})

const updateAccountDetails = asyncHandler(async(req, res) => {
    const {fullname, email} = req.body

    if(!fullname || !email){
        throw new APIError(400, "all fields are required")
    }

    const user = User.findByIdAndUpdate(req.user?._id, {
        $set: {
            fullname, email
        }
    }, {new: true}).select("-password")

    return res
            .status(200)
            .json(
                new APIResponse(200, user, "Account details updated successfully")
            )
})

const updateAvatar = asyncHandler(async(req, res) => {
    const avatarLocalPath = req.file?.path

    if(!avatarLocalPath){
        throw new APIError(400, "Avatar file is missing")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar.url){
        throw new APIError(400, "Error while uploading on cloudinary")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                avatar: avatar.url
            }
        }
    ).select("-password")

    return res
            .status(200)
            .json(
                new APIResponse(200, user, "Avatar updated successfully")
            )
})

const updateCoverImage = asyncHandler(async(req, res) => {
    const coverImageLocalPath = req.file?.path

    if(!coverImageLocalPath){
        throw new APIError(400, "Cover image file is missing")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!coverImage.url){
        throw new APIError(400, "Error while uploading on cloudinary")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                coverImage: coverImage.url
            }
        }
    ).select("-password")

    return res
            .status(200)
            .json(
                new APIResponse(200, user, "Avatar updated successfully")
            )
})

const getUserChannelProfile = asyncHandler(async(req, res) => {
    const {username} = req.params

    if(!username?.trim()){
        throw new APIError(400, "Username is missing")
    }

    const channel = await User.aggregate([
        {
            $match: {
                username: username?.toLowerCase()
            }
        },
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "channel",
                as: "subscribers"
            }
        },
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "subscriber",
                as: "subscribedTo"
            }
        },
        {
            $addFields: {
                subscriberCount: {
                    $size: "$subscribers"
                },
                subscribedToCount: {
                    $size: "$subscribedTo"
                },
                isSubscribed: {
                    $cond: {
                        if: {$in: [req.user?._id, "$subscribers.subscriber"]},
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project: {
                fullname: 1,
                username: 1,
                subscriberCount: 1,
                subscribedToCount: 1,
                isSubscribed: 1, 
                avatar: 1,
                email: 1,
                coverImage: 1
            }   
        }
    ])

    console.log(channel)

    if(!channel?.length){
        throw new APIError(404, "Channel does not exist")
    }

    return res
            .status(200)
            .json(
                new APIResponse(
                    200, channel[0], "User channel fetched successfully"
                )
            )
})

const getWatchHistory = asyncHandler(async(req, res) => {
    const user = await User.aggregate([
        {
            $match: {
                _id: new mongoose.Types.ObjectId(req.user._id)
            }
        },
        {
            $lookup: {
                from: "videos",
                localField: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",
                pipeline: [
                    {
                        $lookup: {
                            from: "users",
                            localField: "owner",
                            foreignField: "_id",
                            as: "owner",
                            pipeline: [
                                {
                                    $project: {
                                        username: 1,
                                        avatar: 1,
                                        fullname: 1
                                    }
                                }
                            ]
                        }
                    },
                    {
                        $addFields: {
                            owner: {
                                $first: "$owner"
                            }
                        }
                    }
                ]
            }
        },
    ])  
    
    return res
            .status(200)
            .json(
                new APIResponse(200, user[0].watchHistory, "Watch history fetched successfully")
            )
})

export { 
    registerUser,
    loginUser, 
    logoutUser, 
    refreshAccessToken, 
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateAvatar,
    updateCoverImage,
    getUserChannelProfile,
    getWatchHistory
}