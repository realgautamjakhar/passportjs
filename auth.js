const User = require("../models/userSchema");
var validator = require("validator");
const passport = require("passport");
const bcrypt = require("bcrypt");
const cloudinary = require("../middlewares/cloudinary");

exports.login = async (req, res, next) => {
  console.log(req);
  try {
    const validationError = [];
    if (!validator.isEmail(req.body.email)) {
      validationError.push({
        msg: "Enter valid Email",
      });
    }
    if (validator.isEmpty(req.body.password)) {
      validationError.push({
        msg: "Enter valid Password",
      });
    }
    if (validationError.length > 0) {
      return res.redirect("/auth");
    }
    req.body.email = validator.normalizeEmail(req.body.email, {
      gmail_remove_dots: true,
    });

    //If everything goes fine in passport middleware you will get user or info containing error
    passport.authenticate("local", (err, user, info) => {
      if (err) {
        return next(err);
      }
      if (!user) {
        return res.status(404).json({
          success: false,
          error: info.error,
        });
      }
      req.login(user, (err) => {
        if (err) {
          return next(err);
        }
        return res.status(200).json({
          user,
          success: true,
          message: "Logged In",
        });
      });
    })(req, res, next);
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};

exports.signup = async (req, res, next) => {
  try {
    const validationError = [];
    //Validation
    if (!validator.isEmail(req.body.email)) {
      validationError.push({
        msg: "Enter valid Email",
      });
    }
    if (validator.isEmpty(req.body.password)) {
      validationError.push({
        msg: "Enter valid Password",
      });
    }
    if (validationError.length > 0) {
      return res.redirect("/auth");
    }

    req.body.email = validator.normalizeEmail(req.body.email, {
      gmail_remove_dots: true,
    });
    //New User (another way to create user in mongodb)
    const user = new User({
      name: req?.body?.name,
      email: req.body.email,
      password: await bcrypt.hash(req.body.password, 5),
      provider: "local",
    });

    User.findOne({ email: req.body.email }, (err, existingUser) => {
      if (err) {
        return next(err);
      }
      if (existingUser) {
        return res.status(401).json({
          success: false,
          error: "Already Exist",
        });
      }
      //Saving user
      user.save((err) => {
        if (err) {
          return next(err);
        }
        req.logIn(user, (err) => {
          if (err) {
            return next(err);
          }
          res.status(200).json({
            success: true,
            user,
            message: "Account Created",
          });
        });
      });
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      msg: "Internal Server Error",
    });
  }
};

exports.loginSuccess = async (req, res) => {
  try {
    if (req.user) {
      return res.status(200).json({
        success: true,
        message: `Welcome ${req?.user?.name}`,
        user: req.user,
      });
    }
    return res.status(401).json({
      success: false,
      error: "Please Login Again",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      error: "Something Went Wrong",
    });
  }
};

exports.loginFailed = async (req, res) => {
  return res.status(401).json({
    success: false,
    error: "Please Login Again",
  });
};

exports.logout = async (req, res) => {
  req.session.destroy((err) => {
    if (err)
      console.log("Error : Failed to destroy the session during logout.", err);
    res.clearCookie("connect.sid");
    req.user = null;

    req.logout(() => {
      return res.status(200).json({
        success: true,
        msg: "Logout out",
      });
    });
  });
};

exports.getUser = async (req, res) => {
  try {
    const userId = req.user._id;
    const user = await User.findById(userId).populate("address");
    if (!user) {
      return res.status(404).json({
        success: false,
        error: "Unable to find user",
      });
    }
    return res.status(200).json({
      success: false,
      success: "User",
      user,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      error: "Something Went Wrong",
    });
  }
};

exports.updateProfile = async (req, res) => {
  try {
    const { name, email } = req.body;

    let image;
    const files = req.files;
    if (files[0]) {
      image = await cloudinary.uploader.upload(files[0].path);
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(400).json({
        success: false,
        error: "Unable to find user",
      });
    }

    const updatedUser = await User.findByIdAndUpdate(req.user._id, {
      name,
      email,
      profileImage: image?.secure_url,
    });

    return res.status(200).json({
      success: true,
      message: "Updated SuccessFully",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      error: "Something Went Wrong",
    });
  }
};
