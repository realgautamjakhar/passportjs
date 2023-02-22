const passport = require("passport");
const User = require("../models/userSchema");
var GitHubStrategy = require("passport-github2").Strategy;
var GoogleStrategy = require("passport-google-oauth20").Strategy;
var LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");

passport.use(
  new LocalStrategy({ usernameField: "email" }, (email, password, done) => {
    User.findOne({ email: email.toLowerCase() }, async (err, user) => {
      if (err) {
        return done(err);
      }
      if (!user) {
        return done(null, false, { error: `Email ${email} not found.` });
      }
      if (!user.password) {
        return done(null, false, {
          error:
            "Your account was registered using a sign-in provider. To enable password login, sign in using a provider, and then set a password under your user profile.",
        });
      }
      const comparePassword = await bcrypt.compare(password, user.password);
      if (!comparePassword) {
        return done(null, false, { error: `Incorrect Credentials` });
      }
      if (comparePassword) {
        return done(null, user);
      }
    });
  })
);

passport.use(
  new GoogleStrategy(
    {
      clientID:
        "380126918524-u8kjiuj0rivpp5nu0c2nn4mfuipqn1j7.apps.googleusercontent.com",
      clientSecret: "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",
      callbackURL: "http://localhost:1338/api/v1/auth/google/callback",
    },
    async function (accessToken, refreshToken, profile, done) {
      if (profile) {
        const existingUser = await User.findOne({
          googleId: profile.id,
        });
        if (existingUser) {
          return done(null, existingUser);
        }
        if (!existingUser) {
          const user = {
            googleId: profile.id,
            name: profile.displayName,
            email: profile.emails[0]?.value,
            emailVerified: profile.emails[0]?.verified,
            profileImage: profile?.photos[0]?.value,
            provider: profile.provider,
          };
          const newCreatedUser = await User.create(user);
          return done(null, newCreatedUser);
        }
      }
      return done(null, profile);
    }
  )
);

passport.use(
  new GitHubStrategy(
    {
      clientID: "18e79f4031134e2cce08",
      clientSecret: "7d3070209b472dec8d7e6f176c2a89881b6341e7",
      callbackURL: "http://localhost:1338/api/v1/auth/github/callback",
    },
    async function (accessToken, refreshToken, profile, done) {
      if (profile) {
        const existingUser = await User.findOne({
          githubUsername: profile.username,
        });
        if (existingUser) {
          return done(null, existingUser);
        }
        if (!existingUser) {
          const user = {
            githubUsername: profile.username,
            name: profile.displayName,
            email: profile.emails[0]?.value,
            profileImage: profile?.photos[0]?.value,
            provider: profile.provider,
          };
          const newCreatedUser = await User.create(user);
          return done(null, newCreatedUser);
        }
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((user, done) => {
  done(null, user);
});
