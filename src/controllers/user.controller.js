import { asyncHandler } from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js";
import {User} from "../models/user.models.js";
import {uploadOnCloudinary} from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken"

const generateAccessAndRefreshTokens = async(userId) => {
    try{
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({validateBeforeSave : false})

        return {accessToken, refreshToken}

    }
    catch(error){
        throw new ApiError(500, "something went wrong while generating tokens!!")
    }
}

const registerUser = asyncHandler( async (req,res) => {
//    res.status(200).json({
//         message: "ok"
//     })
 
    //get user details from frontend
    //validation - not empty
    //check if user already exists: username, email
    //check for images, check for avatar
    //upload them to cloudinary, avatar
    //create user object- create entry in db
    //remove password and refresh token field from reposnse
    //check for user creation
    //if created then respond...otherwise error

    const {fullName, email, username, password} = req.body
    console.log("email: ", email);

    if(
        [fullName, email, username, password].some((field) => 
        field?.trim() === "")
    ){
        throw new ApiError(400, "all fields are required")
    }

    const existedUser = await User.findOne({
        $or: [{username},{email}]
    })

    if(existedUser){
        throw new ApiError(409, "User with email or Username already exists!!")
    }

    const avatarLocalPath =  req.files?.avatar[0]?.path;
    //const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage)
    && req.files.coverImage.length > 0){
        coverImageLocalPath = req.files.coverImage[0].path
    }



    if(!avatarLocalPath){
        throw new ApiError(400, "Avaratr file is required!!")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!avatar){
        throw new ApiError(400, "Avaratr file is required in cloudinary!!")
    }

    const user = await User.create({
        fullName, 
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if(!createdUser){
        throw new ApiError(500, "Somethinf went wrong while registering the user")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User Registered successfully")
    )
})

const loginUser = asyncHandler(async(req,res) => {
    //req bidy se data le ao
    //username email h ya nhi
    //find user
    //pass check
    //access and refresh token
    //send tokens in cookies 

    const {email, username, password} = req.body

    if(!(username || email)){
        throw new ApiError(400, "username or email is required")
    }

    //findOne returns first entry
    const user = await User.findOne({
        $or: [{username}, {email}]
    })

    if(!user){
        throw new ApiError(400, "user or email is required")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)

    if(!isPasswordValid){
        throw new ApiError(401, "Invalid user credentials")
    }

    const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user._id)

    const loggedInUser = await User.findById(user._id)
    .select("-password -refreshToken")

    //for cookies
    const options = {
        httpOnly: true,
        secure: true
    }

    return res.status(200)
    .cookie("accessToken",accessToken, options)
    .cookie("refreshToken",refreshToken, options)
    .json(
        new ApiResponse(200, {
            user: loggedInUser, accessToken, refreshToken
        }, "User loggedin Successfully")
    )

})


const logoutUser = asyncHandler(async(req, res) => {
    await User.findByIdAndUpdate(
        req.user._id, {
            $set: {refreshToken: undefined}
        }, 
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true 
    }

    return res.status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200,{}, "Usr logged out!!"))
})

const refreshAccessToken = asyncHandler(async(req, res)=> {
   const incomingRefreshToken =  req.cookies.refreshToken || req.body.refreshToken

   if(!incomingRefreshToken){
    throw new ApiError(401, "unauthorized requesd!! token shi nhi h")
   }

   try {
    const decodedToken = jwt.verify(
     incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET
    )
 
    const user = await User.findById(decodedToken?._id)
 
    if(!user){
     throw new ApiError(401, "invalid refresh token")
    }
 
    if(incomingRefreshToken !== user?.refreshToken){
     throw new ApiError(401, "refresh token is expired or used")
    }
 
    const options = {
     httpOnly: true,
     secure: true
    }
 
    const {accessToken, newRefreshToken} = await generateAccessAndRefreshTokens(user._id)
 
    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", newRefreshToken, options)
    .json(
     new ApiResponse(
         200,
         {accessToken, refreshToken: newRefreshToken},
         "access token refreshed!!"
     )
    )
   } catch (error) {
    throw new ApiError(401, error?.message || "invalid refresh token")
   }
})

const changeCurrentPassword = asyncHandler(async(req, res) => {
    const {oldPassword, newPassword} = req.body

    const user = await User.findById(req.user?._id)
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if(!isPasswordCorrect){
        throw new ApiError(400, "Invalid old password")
    }

    user.password = newPassword
    await user.save({validateBeforeSave: false})

    return res.status(200)
    .json(new ApiResponse(200, {}, "password changed!!"))
})

const getCurrentUser = asyncHandler(async(req, res) => {
    return res
    .status(200)
    .json(200, req.user, "current user fetched successfully")
})

const updateAccountDetails = asyncHandler(async(req, res) => {
    const {fullName, email} = req.body

    if(!fullName || !email){
        throw new ApiError(400, "all fields are required")
    }

    const user = User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                //noth below lines can be used
                fullName,
                email: email 
            }
        },
        {new : true}
    ).select("-password")

    return res.status(200)
    .json(throw new ApiResponse(200, user, "account details updates successfully!1"))
})

const updateUserAvatar = asyncHandler(async(req, res) => {
    const avatarLocalPath = req.file?.path

    if(!avatarLocalPath){
        throw new ApiError(400, "avatar file is missing")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar.url){
        throw new ApiError(400, "error while uploading avatar")
    }

    const user =  await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                avatar : avatar.url 
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200,user, "avatar image updated successfully")
    )
})

const updateUserCoverImage = asyncHandler(async(req, res) => {
    const coverImageLocalPath = req.file?.path

    if(!coverImageLocalPath){
        throw new ApiError(400, "cover image file is missing")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!coverImage.url){
        throw new ApiError(400, "error while uploading cover image")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                coverImage : coverImage.url 
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200,user, "cover image updated successfully")
    )
})

export {registerUser, loginUser, 
    logoutUser, refreshAccessToken,
    getCurrentUser, changeCurrentPassword, 
    updateUserAvatar, updateUserCoverImage}