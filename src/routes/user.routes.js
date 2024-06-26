import { Router } from "express";
import { changeCurrentPassword, getCurrentUser, getUserChannelProfile, getWatchHistory, loginUser, logoutUser, refreshAccessToken, registerUser, updateAccountDetails, updateAvatar, updateCoverImage } from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middleware.js";
import { auth } from "../middlewares/auth.middleware.js";

const router = Router();

router.route("/register").post(
    upload.fields([
        {
            name: "avatar",
            maxCount: 1
        },
        {
            name: "coverImage",
            maxCount: 1
        }
    ]),
    registerUser
)

router.route("/login").post(loginUser)

router.route("/logout").post(auth, logoutUser)

router.route("/refresh-access-token").post(refreshAccessToken)

router.route("/change-password").post(auth, changeCurrentPassword)

router.route("/current-user").get(auth, getCurrentUser)

router.route("/update-account-details").patch(auth, updateAccountDetails)

router.route("/update-avatar").patch(
    auth, 
    upload.single("avatar"),
    updateAvatar
)

router.route("/update-cover-image").patch(
    auth, 
    upload.single("coverImage"),
    updateCoverImage
)

router.route("/channel/:username").get(auth, getUserChannelProfile)

router.route("/watch-history").get(auth, getWatchHistory)

export default router;