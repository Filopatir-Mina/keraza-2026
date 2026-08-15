const express = require("express");
const cors = require("cors");
const axios = require("axios");
const QRCode = require("qrcode");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const admin = require("firebase-admin");
const CryptoJS = require("crypto-js");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const cloudinary = require("cloudinary").v2;
const serviceAccount = require("./firebase/serviceAccountKey.json");
const websiteHost = "https://keraza-2026.pages.dev";

require("dotenv").config();
const app = express();
app.set("trust proxy", 1);
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "50mb" }));
app.use(express.json());
app.use(passport.initialize());
app.use(cookieParser());
app.use(
  cors({
    origin: websiteHost,
    credentials: true,
  }),
);

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
});

app.get("/", (req, res) => {
  res.send("Server is online 🔥");
});

app.get("/server-state", (req, res) => {
  res.send({ state: false });
});

//================== Sign In ==================//
//------------ Google ------------//
app.get("/auth/google", (req, res, next) => {
  passport.authenticate("google", {
    scope: ["profile", "email"],
    state: req.query.state,
  })(req, res, next);
});

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    session: false,
  }),
  async (req, res) => {
    try {
      if (!req.user || !req.user.uid) {
        return res.status(401).send("Google login failed: No user");
      }

      res.cookie("session", req.user.uid, {
        httpOnly: true,
        secure: false,
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      await admin.firestore().collection("users").doc(req.user.uid).set({
        email: req.user.email,
        signedInWith: "google",
        createdAt: Date.now(),
      });

      const redirectTo = req.query.state || "/";
      res.redirect(`${websiteHost}${redirectTo}`);
    } catch (err) {
      console.error("❌ Google callback error:", err);
      res.status(500).send("Auth failed");
    }
  },
);

//------------ Email ------------//
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;

  try {
    const userRecord = await admin.auth().createUser({ email, password });

    res.cookie("session", userRecord.uid, {
      httpOnly: true,
      secure: false,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    await admin.firestore().collection("users").doc(userRecord.uid).set({
      email,
      signedInWith: "email",
      createdAt: Date.now(),
    });

    res.send({ success: true, message: "User created and signed in" });
  } catch (err) {
    console.error("Sign up error:", err);
    res.status(500).send({ err });
  }
});

//------------ Login ------------//
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const response = await axios.post(
      `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_API_KEY}`,
      {
        email,
        password,
        returnSecureToken: true,
      },
    );

    const { localId } = response.data;

    // Set secure HTTP-only cookie
    res.cookie("session", localId, {
      httpOnly: true,
      secure: false, // set to true if using HTTPS
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.send({ success: true, uid: localId });
  } catch (err) {
    console.error("Login error:", err);
    const firebaseErrorCode = err.response?.data?.error?.message || "UNKNOWN";
    res.status(500).send({
      err: {
        code: `auth/${firebaseErrorCode.toLowerCase().replace(/_/g, "-")}`,
        errors: err.response?.data?.error?.errors,
        message: err.response?.data?.error?.message,
      },
    });
  }
});

app.post("/logout", (req, res) => {
  res.clearCookie("session");
  res.send({ success: true });
});

//------------ Check ------------//
app.get("/signedIn", async (req, res) => {
  const sessionUID = req.cookies.session;

  if (!sessionUID) {
    return res.status(401).send({ loggedIn: false });
  }

  try {
    const user = await admin.auth().getUser(sessionUID);
    res.send({ loggedIn: true, email: user.email, uid: user.uid });
  } catch (err) {
    // console.error("Failed to get user:", err);
    res.status(401).send({ loggedIn: false, err: { code: "Invalid session" } });
  }
});

app.get("/hasProfile", async (req, res) => {
  const sessionUID = req.cookies.session;

  if (!sessionUID) {
    return res.status(401).send({ loggedIn: false });
  }

  try {
    const Userdoc = await admin
      .firestore()
      .collection("usersData")
      .doc(sessionUID)
      .get();
    const Userdata = Userdoc.data()?.profile;

    if (Userdata) {
      res.send({ loggedIn: true, profile: true });
    } else {
      res.send({ loggedIn: true, profile: false });
    }
  } catch (err) {
    console.error("Failed to get user:", err);
    res.status(401).send({ loggedIn: false, err: { code: "Invalid session" } });
  }
});

//================== Profile ==================//
app.post("/creatProfile", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  var pfp;
  const data = req.body;
  const usernamesListDOC = await admin
    .firestore()
    .collection("usersData")
    .doc("username")
    .get();
  const usernamesList = usernamesListDOC.data();
  try {
    if (data.pfp !== "/pic/profile_pic_unknown.png" && data.pfp !== null) {
      const result = await cloudinary.uploader.upload(data.pfp, {
        folder: "pfp",
      });
      pfp = result.secure_url;
    } else {
      pfp = null;
    }

    const encrypted = encrypt(sessionUID);
    const qrData = await QRCode.toDataURL(encrypted);
    const result = await cloudinary.uploader.upload(qrData, {
      folder: "qr",
    });
    qrURL = result.secure_url;
    console.log(data.status);
    const profileData = {
      pfp: pfp || null,
      qr: qrURL,
      status: data.status || "0",
      username: data.username,
      firstname: data.firstname,
      lastname: data.lastname,
      birthday: data.birthday,
      gender: data.gender,
    };
    const EmptyFields = validateFields({
      username: data.username,
      firstname: data.firstname,
      lastname: data.lastname,
      birthday: data.birthday,
      gender: data.gender,
    });

    if (EmptyFields.valid) {
      if (!(data.username in usernamesList)) {
        await admin.firestore().collection("usersData").doc(sessionUID).set(
          {
            profile: profileData,
            LastUpdated: Date.now(),
          },
          { merge: true },
        );

        await admin
          .firestore()
          .collection("usersData")
          .doc("username")
          .set({ [data.username]: sessionUID }, { merge: true });

        await admin
          .firestore()
          .collection("notifications")
          .doc(sessionUID)
          .set({
            notifications: {},
            unread: false,
          });

        await admin.firestore().collection("calendar").doc(sessionUID).set({});
        await admin
          .firestore()
          .collection("attendance")
          .doc(sessionUID)
          .set({});

        res.send({ success: true, EmptyFields: EmptyFields.errors });
      } else {
        EmptyFields.errors.username = true;
        res.send({
          success: false,
          err: {
            code: "username-already-used",
            EmptyFields: EmptyFields.errors,
          },
        });
      }
    } else {
      res.send({
        success: false,
        err: { code: "empty-fields", EmptyFields: EmptyFields.errors },
      });
    }
  } catch (err) {
    console.log(err);
    res.status(500).send({
      err: {
        code: "failed-to-save-profile",
        EmptyFields: EmptyFields.errors,
      },
    });
  }
});

app.post("/updateProfile", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  var pfp;
  const data = req.body;
  const Userdoc = await admin
    .firestore()
    .collection("usersData")
    .doc(sessionUID)
    .get();
  const Userdata = Userdoc.data()?.profile;

  if (!Userdata)
    return res.status(404).send({ err: { code: "no-profile-found" } });

  if (
    data.pfp !== "/pic/profile_pic_unknown.png" &&
    data.pfp !== Userdata.pfp
  ) {
    const result = await cloudinary.uploader.upload(data.pfp, {
      folder: "pfp",
    });
    pfp = result.secure_url;
  } else if (data.pfp === Userdata.pfp) {
    pfp = Userdata.pfp;
  } else {
    pfp = null;
  }

  const profileData = {
    pfp: pfp || null,
    qr: Userdata.qr,
    status: Userdata.status,
    username: Userdata.username,
    firstname: data.firstname,
    lastname: data.lastname,
    birthday: data.birthday,
    gender: data.gender,
  };

  const EmptyFields = validateFields({
    firstname: data.firstname,
    lastname: data.lastname,
    birthday: data.birthday,
    gender: data.gender,
  });

  if (EmptyFields.valid) {
    try {
      await admin.firestore().collection("usersData").doc(sessionUID).update(
        {
          profile: profileData,
          LastUpdated: Date.now(),
        },
        { merge: true },
      );

      res.send({
        success: true,
        data: profileData,
        EmptyFields: EmptyFields.errors,
      });
    } catch (err) {
      console.log(err);
      res.status(500).send({
        err: {
          code: "failed-to-save-profile",
          EmptyFields: EmptyFields.errors,
        },
      });
    }
  } else {
    res.send({
      success: false,
      err: { code: "empty-fields", EmptyFields: EmptyFields.errors },
    });
  }
});

app.get("/getProfile", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  try {
    const Userdoc = await admin
      .firestore()
      .collection("usersData")
      .doc(sessionUID)
      .get();
    const Userdata = Userdoc.data()?.profile;

    if (!Userdata)
      return res.status(404).send({ err: { code: "no-profile-found" } });

    const data = {
      pfp:
        Userdata.pfp === null ? "/pic/profile_pic_unknown.png" : Userdata.pfp,
      firstname: Userdata.firstname,
      lastname: Userdata.lastname,
      username: Userdata.username,
      birthday: Userdata.birthday,
      gender: Userdata.gender,
      qr: Userdata.qr,
      Ispfp: Userdata.pfp === null ? false : true,
    };

    res.send({ success: true, profile: data });
  } catch (err) {
    res.status(500).send({ err: { code: "failed-to-fetch-profile" } });
  }
});

app.get("/getProfile/:username", async (req, res) => {
  const { username } = req.params;

  const Usernames = await admin
    .firestore()
    .collection("usersData")
    .doc("username")
    .get();
  const sessionUID = Usernames.data()?.[username];

  if (!sessionUID)
    return res.status(404).send({ err: { code: "no-username-found" } });

  try {
    const Userdoc = await admin
      .firestore()
      .collection("usersData")
      .doc(sessionUID)
      .get();
    const Userdata = Userdoc.data()?.profile;
    if (!Userdata)
      return res.status(404).send({ err: { code: "no-profile-found" } });

    const data = {
      pfp:
        Userdata.pfp === null ? "/pic/profile_pic_unknown.png" : Userdata.pfp,
      firstname: Userdata.firstname,
      lastname: Userdata.lastname,
      username: Userdata.username,
      birthday: Userdata.birthday,
      gender: Userdata.gender,
      Ispfp: Userdata.pfp === null ? false : true,
    };

    res.send({ success: true, profile: data });
  } catch (err) {
    res.status(500).send({ err: { code: "failed-to-fetch-profile" } });
  }
});

app.get("/getProfileAccount", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  try {
    const UserDatadoc = await admin
      .firestore()
      .collection("usersData")
      .doc(sessionUID)
      .get();
    const Userdoc = await admin
      .firestore()
      .collection("users")
      .doc(sessionUID)
      .get();
    const UserBrowserNotifications = UserDatadoc.data()?.browserNotifications;
    const UserEmailNotifications = UserDatadoc.data()?.emailNotifications;
    const UserWhatsappNotifications = UserDatadoc.data()?.whatsappNotifications;
    const UserDataDetails = UserDatadoc.data()?.profile;
    const Userdata = Userdoc.data();
    const signedInWith = Userdata.signedInWith;

    res.send({
      success: true,
      username: UserDataDetails.username,
      phoneNum: UserDatadoc.data()?.phoneNum || "",
      email: Userdata.email,
      signedInWith,
      browserNotifications: UserBrowserNotifications || false,
      emailNotifications: UserEmailNotifications || false,
      whatsappNotifications: UserWhatsappNotifications || false,
    });
  } catch (err) {
    console.log(err);
    res.status(500).send({ err: { code: "failed-to-fetch-profile" } });
  }
});

app.get("/getProfileHeader", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  try {
    const Userdoc = await admin
      .firestore()
      .collection("usersData")
      .doc(sessionUID)
      .get();
    const Userdata = Userdoc.data()?.profile;

    if (!Userdata)
      return res.status(404).send({ err: { code: "no-profile-found" } });

    const data = {
      pfp:
        Userdata.pfp === null ? "/pic/profile_pic_unknown.png" : Userdata.pfp,
      firstname: Userdata.firstname,
      Ispfp: Userdata.pfp === null ? false : true,
    };

    res.send({ success: true, profile: data });
  } catch (err) {
    res.status(500).send({ error: "Failed to fetch profile" });
  }
});

app.get("/getStatus", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  try {
    const Userdoc = await admin
      .firestore()
      .collection("usersData")
      .doc(sessionUID)
      .get();
    const Userdata = Userdoc.data()?.profile;

    if (!Userdata)
      return res.status(404).send({ err: { code: "no-profile-found" } });

    res.send({ success: true, status: Userdata.status });
  } catch (err) {
    res.status(500).send({ err: { code: "failed-to-fetch-profile" } });
  }
});

app.get("/getUsername", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  try {
    const Userdoc = await admin
      .firestore()
      .collection("usersData")
      .doc(sessionUID)
      .get();
    const Userdata = Userdoc.data()?.profile;

    if (!Userdata)
      return res.status(404).send({ err: { code: "no-profile-found" } });

    res.send({ success: true, username: Userdata.username });
  } catch (err) {
    res.status(500).send({ err: { code: "failed-to-fetch-profile" } });
  }
});

app.post("/updateUsername", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  const data = req.body;
  const Userdoc = await admin
    .firestore()
    .collection("usersData")
    .doc(sessionUID)
    .get();
  const Userdata = Userdoc.data()?.profile;
  const OldUsername = Userdata.username;

  const UserDatadoc = await admin
    .firestore()
    .collection("users")
    .doc(sessionUID)
    .get();

  if (!Userdata)
    return res.status(404).send({ err: { code: "no-profile-found" } });
  const usernamesListDOC = await admin
    .firestore()
    .collection("usersData")
    .doc("username")
    .get();
  const usernamesList = usernamesListDOC.data();
  const signedInWith = UserDatadoc.data().signedInWith;

  const profileData = {
    pfp: Userdata.pfp,
    username: data.username,
    firstname: Userdata.firstname,
    lastname: Userdata.lastname,
    birthday: Userdata.birthday,
    gender: Userdata.gender,
  };

  const EmptyFields = validateFields({
    username: data.username,
    passwordUsername: signedInWith === "google" ? "none" : data.password,
  });

  const email = UserDatadoc.data().email;
  const password = data.password;

  if (EmptyFields.valid) {
    try {
      const response =
        signedInWith === "google"
          ? { data: { localId: sessionUID } }
          : await axios.post(
              `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_API_KEY}`,
              {
                email,
                password,
                returnSecureToken: true,
              },
            );

      const { localId } = response.data;

      if (localId === sessionUID) {
        if (data.username !== OldUsername) {
          if (!(data.username in usernamesList)) {
            try {
              await admin
                .firestore()
                .collection("usersData")
                .doc(sessionUID)
                .update(
                  {
                    profile: profileData,
                    LastUpdated: Date.now(),
                  },
                  { merge: true },
                );
              await admin
                .firestore()
                .collection("usersData")
                .doc("username")
                .update(
                  {
                    [data.username]: sessionUID,
                    [OldUsername]: admin.firestore.FieldValue.delete(),
                  },
                  { merge: true },
                );
              res.send({
                success: true,
                data: profileData,
                EmptyFields: EmptyFields.errors,
              });
            } catch (err) {
              const firebaseErrorCode =
                err.response?.data?.error?.message || "UNKNOWN";
              res.status(500).send({
                err: {
                  code: `${firebaseErrorCode.toLowerCase().replace(/_/g, "-")}`,
                  errors: err.response?.data?.error?.errors,
                  message: err.response?.data?.error?.message,
                  EmptyFields: EmptyFields.errors,
                },
              });
            }
          } else {
            EmptyFields.errors.username = true;
            res.send({
              success: false,
              err: {
                code: "username-already-used",
                EmptyFields: EmptyFields.errors,
              },
            });
          }
        } else {
          EmptyFields.errors.username = true;
          res.send({
            success: false,
            err: {
              code: "same-as-current-username",
              EmptyFields: EmptyFields.errors,
            },
          });
        }
      } else {
        res.send({
          success: false,
          err: { code: "unknown", EmptyFields: EmptyFields.errors },
        });
      }
    } catch (err) {
      const firebaseErrorCode = err.response?.data?.error?.message || "UNKNOWN";
      EmptyFields.errors.passwordUsername = true;
      res.status(500).send({
        err: {
          code: `${firebaseErrorCode.toLowerCase().replace(/_/g, "-")}`,
          errors: err.response?.data?.error?.errors,
          message: err.response?.data?.error?.message,
          EmptyFields: EmptyFields.errors,
        },
      });
    }
  } else {
    res.send({
      success: false,
      err: { code: "empty-fields", EmptyFields: EmptyFields.errors },
    });
  }
});

app.post("/updatePhoneNum", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  const { phoneNum } = req.body;

  if (!/^01\d{9}$/.test(phoneNum)) {
    return res.status(400).send({
      success: false,
      err: {
        code: "invalid-phone-num",
      },
    });
  }
  const Userdoc = await admin
    .firestore()
    .collection("usersData")
    .doc(sessionUID)
    .get();
  const OldPhoneNum = Userdoc.data()?.phoneNum || "";

  if (!Userdoc)
    return res.status(404).send({ err: { code: "no-profile-found" } });

  const EmptyFields = validateFields({
    phoneNum,
  });

  if (EmptyFields.valid) {
    if (phoneNum !== OldPhoneNum) {
      try {
        await admin.firestore().collection("usersData").doc(sessionUID).update(
          {
            phoneNum,
            LastUpdated: Date.now(),
          },
          { merge: true },
        );

        res.send({
          success: true,
          phoneNum,
          EmptyFields: EmptyFields.errors,
        });
      } catch (err) {
        const firebaseErrorCode =
          err.response?.data?.error?.message || "UNKNOWN";
        res.status(500).send({
          err: {
            code: `${firebaseErrorCode.toLowerCase().replace(/_/g, "-")}`,
            errors: err.response?.data?.error?.errors,
            message: err.response?.data?.error?.message,
            EmptyFields: EmptyFields.errors,
          },
        });
      }
    } else {
      EmptyFields.errors.phoneNum = true;
      res.send({
        success: false,
        err: {
          code: "same-as-current-phone-num",
          EmptyFields: EmptyFields.errors,
        },
      });
    }
  } else {
    res.send({
      success: false,
      err: { code: "empty-fields", EmptyFields: EmptyFields.errors },
    });
  }
});

app.post("/updateEmail", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  const data = req.body;
  const Userdata = await admin
    .firestore()
    .collection("users")
    .doc(sessionUID)
    .get();

  if (!Userdata)
    return res.status(404).send({ err: { code: "no-profile-found" } });

  const EmptyFields = validateFields({
    email: data.email,
    passwordEmail: data.password,
  });

  const OldEmail = Userdata.data().email;
  const password = data.password;
  const signedInWith = Userdata.data().signedInWith;

  if (EmptyFields.valid && signedInWith !== "google") {
    try {
      const response = await axios.post(
        `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_API_KEY}`,
        {
          email: OldEmail,
          password,
          returnSecureToken: true,
        },
      );

      const { localId } = response.data;

      if (localId === sessionUID) {
        if (data.email !== OldEmail) {
          try {
            await admin.auth().updateUser(sessionUID, { email: data.email });

            await admin
              .firestore()
              .collection("users")
              .doc(sessionUID)
              .update({ email: data.email }, { merge: true });

            res.send({
              success: true,
              email: data.email,
              EmptyFields: EmptyFields.errors,
            });
          } catch (err) {
            const firebaseErrorCode =
              err.response?.data?.error?.message || "UNKNOWN";
            res.status(500).send({
              err: {
                code: `${firebaseErrorCode.toLowerCase().replace(/_/g, "-")}`,
                errors: err.response?.data?.error?.errors,
                message: err.response?.data?.error?.message,
                EmptyFields: EmptyFields.errors,
              },
            });
          }
        } else {
          EmptyFields.errors.email = true;
          res.send({
            success: false,
            err: {
              code: "same-as-current-email",
              EmptyFields: EmptyFields.errors,
            },
          });
        }
      } else {
        res.send({
          success: false,
          err: { code: "unknown", EmptyFields: EmptyFields.errors },
        });
      }
    } catch (err) {
      const firebaseErrorCode = err.response?.data?.error?.message || "UNKNOWN";
      res.status(500).send({
        err: {
          code: `${firebaseErrorCode.toLowerCase().replace(/_/g, "-")}`,
          errors: err.response?.data?.error?.errors,
          message: err.response?.data?.error?.message,
          EmptyFields: EmptyFields.errors,
        },
      });
    }
  } else {
    res.send({
      success: false,
      err: { code: "empty-fields", EmptyFields: EmptyFields.errors },
    });
  }
});

app.post("/updatePassword", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  const data = req.body;
  const Userdata = await admin
    .firestore()
    .collection("users")
    .doc(sessionUID)
    .get();

  if (!Userdata)
    return res.status(404).send({ err: { code: "no-profile-found" } });

  const EmptyFields = validateFields({
    newPassword: data.newPassword,
    password: data.password,
  });

  const email = Userdata.data().email;
  const password = data.password;
  const signedInWith = Userdata.data().signedInWith;

  if (EmptyFields.valid && signedInWith !== "google") {
    try {
      const response = await axios.post(
        `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_API_KEY}`,
        {
          email: email,
          password,
          returnSecureToken: true,
        },
      );

      const { localId } = response.data;

      if (localId === sessionUID) {
        if (data.newPassword !== password) {
          try {
            await admin
              .auth()
              .updateUser(sessionUID, { password: data.newPassword });

            res.send({ success: true, EmptyFields: EmptyFields.errors });
          } catch (err) {
            const firebaseErrorCode =
              err.response?.data?.error?.message || "UNKNOWN";
            res.status(500).send({
              err: {
                code: `${firebaseErrorCode.toLowerCase().replace(/_/g, "-")}`,
                errors: err.response?.data?.error?.errors,
                message: err.response?.data?.error?.message,
                EmptyFields: EmptyFields.errors,
              },
            });
          }
        } else {
          EmptyFields.errors.newPassword = true;
          res.send({
            success: false,
            err: {
              code: "same-as-current-password",
              EmptyFields: EmptyFields.errors,
            },
          });
        }
      } else {
        res.send({
          success: false,
          err: { code: "unknown", EmptyFields: EmptyFields.errors },
        });
      }
    } catch (err) {
      const firebaseErrorCode = err.response?.data?.error?.message || "UNKNOWN";
      res.status(500).send({
        err: {
          code: `${firebaseErrorCode.toLowerCase().replace(/_/g, "-")}`,
          errors: err.response?.data?.error?.errors,
          message: err.response?.data?.error?.message,
          EmptyFields: EmptyFields.errors,
        },
      });
    }
  } else {
    res.send({
      success: false,
      err: { code: "empty-fields", EmptyFields: EmptyFields.errors },
    });
  }
});

// app.post("/resetPassword", async (req, res) => {
//   const sessionUID = req.cookies.session;
//   if (!sessionUID) return res.status(401).send({ err: { code: "not-logged-in"} });

//   const data = req.body;
//   const Userdata = await admin.firestore().collection("users").doc(sessionUID).get();

//   if (!Userdata) return res.status(404).send({ err: { code: "no-profile-found"} });

//   const EmptyFields = validateFields({
//     password: data.password
//   });

//   const signedInWith = Userdata.data().signedInWith;

//   if (EmptyFields.valid && signedInWith !== "google") {
//     try {
//       await admin.auth().updateUser(sessionUID, { password: data.password });

//       res.send({ success: true, EmptyFields: EmptyFields.errors  });
//     } catch (err) {
//       const firebaseErrorCode = err.response?.data?.error?.message || "UNKNOWN";
//       res.status(500).send({
//         err: {
//           code: `${firebaseErrorCode.toLowerCase().replace(/_/g, '-')}`,
//           errors: err.response?.data?.error?.errors,
//           message: err.response?.data?.error?.message,
//           EmptyFields: EmptyFields.errors
//         }
//       });
//     }
//   } else {
//     res.send({ success: false, err: { code: "empty-fields", EmptyFields: EmptyFields.errors} });
//   }
// });

// app.post("/SendResetPassword", async (req, res) => {
//   const sessionUID = req.cookies.session;
//   if (!sessionUID) return res.status(401).send({ err: { code: "not-logged-in"} });

//   const data = req.body;
//   const Userdata = await admin.firestore().collection("users").doc(sessionUID).get();

//   if (!Userdata) return res.status(404).send({ err: { code: "no-profile-found"} });

//   const EmptyFields = validateFields({
//     email: data.email
//   });

//   const signedInWith = Userdata.data().signedInWith;

//   if (EmptyFields.valid) {
//     if (signedInWith !== "google") {
//       try {
//         await admin.auth().generatePasswordResetLink(data.email);

//         res.send({ success: true, EmptyFields: EmptyFields.errors  });
//       } catch (err) {
//         const firebaseErrorCode = err.response?.data?.error?.message || "UNKNOWN";
//         res.status(500).send({
//           err: {
//             code: `${firebaseErrorCode.toLowerCase().replace(/_/g, '-')}`,
//             errors: err.response?.data?.error?.errors,
//             message: err.response?.data?.error?.message,
//             EmptyFields: EmptyFields.errors
//           }
//         });
//       }
//     } else {
//       res.send({ success: false, err: { code: "unkown", EmptyFields: EmptyFields.errors} });
//     }
//   } else {
//     res.send({ success: false, err: { code: "empty-fields", EmptyFields: EmptyFields.errors} });
//   }
// });

app.post("/deleteAccount", async (req, res) => {
  const sessionUID = req.cookies.session;

  if (!sessionUID) {
    return res.status(401).send({
      err: { code: "not-logged-in" },
    });
  }

  try {
    const userRecord = await admin.auth().getUser(sessionUID);

    if (!userRecord) {
      return res.status(404).send({
        err: { code: "user-not-found" },
      });
    }

    await admin.firestore().collection("usersData").doc(sessionUID).delete();

    await admin.auth().deleteUser(sessionUID);
    res.clearCookie("session");

    return res.send({
      success: true,
    });
  } catch (err) {
    console.error("❌ Error deleting account:", err);

    if (err.code === "auth/user-not-found") {
      return res.status(404).send({
        err: { code: "user-not-found" },
      });
    }

    return res.status(500).send({
      err: { code: "internal-error" },
    });
  }
});

//================== Qr Code ==================//
app.post("/QRScanned", async (req, res) => {
  const { code } = req.body;

  const UserID = decrypt(code);

  if (!UserID) return res.status(401).send({ err: { code: "no-user-found" } });

  try {
    const Userdoc = await admin
      .firestore()
      .collection("usersData")
      .doc(UserID)
      .get();
    const Userdata = Userdoc.data()?.profile;

    if (!Userdata)
      return res.status(404).send({ err: { code: "no-profile-found" } });

    const profile = {
      username: Userdata.username,
      fullname: Userdata.firstname + " " + Userdata.lastname + " - ",
    };
    res.send({ success: true, profile });
  } catch (err) {
    res.status(500).send({ err: { code: "failed-to-fetch-profile" } });
  }
});

//================== Notifications ==================//
app.post("/saveFCMToken", async (req, res) => {
  try {
    const { token } = req.body;

    const sessionUID = req.cookies.session;
    if (!sessionUID)
      return res.status(401).send({ err: { code: "not-logged-in" } });

    await admin.firestore().collection("usersData").doc(sessionUID).update({
      fcmToken: token,
    });

    res.json({
      success: true,
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      err: {
        code: "internal-error",
      },
    });
  }
});

app.post("/saveNotifiactionSettings", async (req, res) => {
  try {
    const { browserNotifications, emailNotifications, whatsappNotifications } =
      req.body;

    const sessionUID = req.cookies.session;
    if (!sessionUID)
      return res.status(401).send({ err: { code: "not-logged-in" } });

    if (whatsappNotifications) {
      const UserDatadoc = await admin
        .firestore()
        .collection("usersData")
        .doc(sessionUID)
        .get();
      const phoneNum = UserDatadoc.data()?.phoneNum;
      if (!phoneNum) {
        return res.status(400).json({
          success: false,
          err: {
            code: "no-phone-num",
          },
        });
      }
    }

    await admin.firestore().collection("usersData").doc(sessionUID).update({
      browserNotifications,
      emailNotifications,
      whatsappNotifications,
    });

    res.json({
      success: true,
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      success: false,
      err: {
        code: "internal-error",
      },
    });
  }
});

app.get("/isUnreadNotifications", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  try {
    const Userdoc = await admin
      .firestore()
      .collection("notifications")
      .doc(sessionUID)
      .get();
    const isUnread = Userdoc.data()?.unread;

    if (!Userdoc)
      return res.status(404).send({ err: { code: "no-profile-found" } });

    res.send({ success: true, isUnread });
  } catch (err) {
    res.status(500).send({ err: { code: "failed-to-fetch-notifications" } });
  }
});

app.get("/getNotifications", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  try {
    const Userdoc = await admin
      .firestore()
      .collection("notifications")
      .doc(sessionUID)
      .get();
    const Userdata = Userdoc.data();

    if (!Userdata)
      return res.status(404).send({ err: { code: "no-profile-found" } });

    const data = {
      notifications: Userdata.notifications,
      unread: Userdata.unread,
    };

    res.send({ success: true, notifications: data });
  } catch (err) {
    res.status(500).send({ err: { code: "failed-to-fetch-notifications" } });
  }
});

app.post("/readNotifications", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  try {
    const Userdoc = await admin
      .firestore()
      .collection("notifications")
      .doc(sessionUID)
      .get();
    const UserNotifications = Userdoc.data()?.notifications;

    for (const notification of Object.entries(UserNotifications)) {
      if (notification[1].unread) {
        notification[1].unread = false;
      }
    }

    if (!UserNotifications)
      return res.status(404).send({ err: { code: "no-profile-found" } });

    await admin.firestore().collection("notifications").doc(sessionUID).update({
      notifications: UserNotifications,
      unread: false,
    });

    res.send({ success: true });
  } catch (err) {
    res.status(500).send({ err: { code: "failed-to-fetch-notifications" } });
  }
});

app.get("/sendNotifications", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  const Userdoc = await admin
    .firestore()
    .collection("notifications")
    .doc(sessionUID)
    .get();
  const token = Userdoc.data()?.fcmToken;

  await admin.messaging().send({
    token,
    notification: {
      title: "Test Notification",
      body: "Hello from your backend!",
    },
  });
});

//================== Search ==================//
app.get("/getAllProfiles", async (req, res) => {
  try {
    const UsersCollection = await admin
      .firestore()
      .collection("usersData")
      .get();

    var UsersData = [];
    UsersCollection.forEach((postsdoc) => {
      if (postsdoc.id !== "username") {
        const profile = postsdoc.data().profile;
        const UserProfile = {
          pfp:
            profile.pfp === null ? "/pic/profile_pic_unknown.png" : profile.pfp,
          firstname: profile.firstname,
          lastname: profile.lastname,
          username: profile.username,
        };
        UsersData.push(UserProfile);
      }
    });

    res.send({ success: true, profiles: UsersData });
  } catch (err) {
    res.status(500).send({ err: { code: "failed-to-fetch-profile" } });
  }
});

app.get("/getAllProfiles/Attendance", async (req, res) => {
  if (!(await checkStatus(req))) {
    return res.status(403).send({
      success: false,
      err: {
        code: "no-permission",
      },
    });
  }
  try {
    const UsersCollection = await admin
      .firestore()
      .collection("usersData")
      .get();

    var UsersData = [];
    UsersCollection.forEach((postsdoc) => {
      if (postsdoc.id !== "username") {
        const profile = postsdoc.data().profile;
        if (profile.status === "0") {
          const UserProfile = {
            pfp:
              profile.pfp === null
                ? "/pic/profile_pic_unknown.png"
                : profile.pfp,
            firstname: profile.firstname,
            lastname: profile.lastname,
            username: profile.username,
          };
          UsersData.push(UserProfile);
        }
      }
    });

    res.send({ success: true, profiles: UsersData });
  } catch (err) {
    res.status(500).send({ err: { code: "failed-to-fetch-profile" } });
  }
});

//================== Attendance ==================//
app.get("/getAttendance", async (req, res) => {
  if (!(await checkStatus(req))) {
    return res.status(403).send({
      success: false,
      err: {
        code: "no-permission",
      },
    });
  }
  try {
    const AttendanceCollection = await admin
      .firestore()
      .collection("attendance")
      .get();

    const UsersCollection = await admin
      .firestore()
      .collection("usersData")
      .get();

    var UsersData = {};
    AttendanceCollection.forEach((usersdoc) => {
      const username = UsersCollection.docs
        .find((doc) => doc.id === usersdoc.id)
        ?.data().profile?.username;

      if (username) {
        UsersData[username] = usersdoc.data();
      }
    });

    res.send({ success: true, attendance: UsersData });
  } catch (err) {
    res.status(500).send({ err: { code: "failed-to-fetch-profile" } });
  }
});

app.post("/saveAttendance", async (req, res) => {
  if (!(await checkStatus(req))) {
    return res.status(403).send({
      success: false,
      err: {
        code: "no-permission",
      },
    });
  }
  try {
    const { date, username, checked } = req.body;

    const Userdoc = await admin
      .firestore()
      .collection("usersData")
      .doc("username")
      .get();
    const UserID = Userdoc.data()?.[username];

    if (!UserID)
      return res.status(401).send({ err: { code: "not-logged-in" } });

    await admin
      .firestore()
      .collection("attendance")
      .doc(UserID)
      .update({
        [date]: checked,
      });

    sendNotification(
      UserID,
      checked ? "attendanceMarkedPresent" : "attendanceMarkedAbsent",
      checked ? "${attendanceMarkedPresent}" : "${attendanceMarkedAbsent}",
      "/pic/icons/attendance.png",
      "icon",
      "/notifications",
    );

    res.json({
      success: true,
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      err: {
        code: "internal-error",
      },
    });
  }
});

//============== Calendar - Events ==============//
app.post("/getEvents", async (req, res) => {
  if (!(await checkStatus(req))) {
    return res.status(403).send({
      success: false,
      err: {
        code: "no-permission",
      },
    });
  }
  try {
    const { username } = req.body;

    const UsernamesDoc = await admin
      .firestore()
      .collection("usersData")
      .doc("username")
      .get();
    const UserID = UsernamesDoc.data()?.[username];

    const EventsCollection = await admin
      .firestore()
      .collection("calendar")
      .doc(UserID)
      .get();

    res.send({ success: true, events: EventsCollection.data() });
  } catch (err) {
    res.status(500).send({ err: { code: "failed-to-fetch-profile" } });
  }
});

app.post("/getEvents/me", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  try {
    const EventsCollection = await admin
      .firestore()
      .collection("calendar")
      .doc(sessionUID)
      .get();

    console.log(EventsCollection.data());

    res.send({ success: true, events: EventsCollection.data() });
  } catch (err) {
    res.status(500).send({ err: { code: "failed-to-fetch-profile" } });
  }
});

app.post("/getEvents/public", async (req, res) => {
  if (!(await checkStatus(req))) {
    return res.status(403).send({
      success: false,
      err: {
        code: "no-permission",
      },
    });
  }
  try {
    const EventsCollection = await admin
      .firestore()
      .collection("calendar")
      .doc("public")
      .get();
    res.send({ success: true, events: EventsCollection.data() });
  } catch (err) {
    res.status(500).send({ err: { code: "failed-to-fetch-profile" } });
  }
});

app.post("/addEvent", async (req, res) => {
  if (!(await checkStatus(req))) {
    return res.status(403).send({
      success: false,
      err: {
        code: "no-permission",
      },
    });
  }
  try {
    const { usernames, date, title, description, color } = req.body;

    if (!date || !title || !description || !color) {
      return res.send({
        success: false,
        err: {
          code: "empty-fields",
        },
      });
    }

    if (!usernames || !Array.isArray(usernames) || usernames.length === 0) {
      return res.send({
        success: false,
        err: { code: "no-users-selected" },
      });
    }

    const Userdoc = await admin
      .firestore()
      .collection("usersData")
      .doc("username")
      .get();

    const UserIDs = usernames
      .map((name) => Userdoc.data()?.[name])
      .filter(Boolean);

    for (const UserID of UserIDs) {
      if (!UserID)
        return res.status(401).send({ err: { code: "not-logged-in" } });

      const EventsDoc = await admin
        .firestore()
        .collection("calendar")
        .doc(UserID)
        .get();
      const userEvents = EventsDoc.data() || {};
      const oldEvents = Object.values(EventsDoc).flatMap((events) =>
        Object.keys(events),
      );

      const NewEventID = generateUniqueCode(oldEvents);
      const NewUserEvents = {
        ...userEvents,
        [date]: {
          ...(userEvents[date] || {}),
          [NewEventID]: {
            title,
            description,
            color,
            createdAt: Date.now(),
          },
        },
      };

      await admin
        .firestore()
        .collection("calendar")
        .doc(UserID)
        .update({ ...NewUserEvents });

      sendNotification(
        UserID,
        "eventAdded",
        "${eventAdded}",
        "/pic/icons/calendar.png",
        "icon",
        "/calendar",
      );
    }

    res.json({
      success: true,
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      err: {
        code: "internal-error",
      },
    });
  }
});

app.post("/addEvent/me", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  try {
    const { date, title, description, color } = req.body;

    if (!date || !title || !description || !color) {
      return res.send({
        success: false,
        err: {
          code: "empty-fields",
        },
      });
    }

    const EventsDoc = await admin
      .firestore()
      .collection("calendar")
      .doc(sessionUID)
      .get();

    const userEvents = EventsDoc.data() || {};
    const oldEvents = Object.values(EventsDoc).flatMap((events) =>
      Object.keys(events),
    );

    const NewEventID = generateUniqueCode(oldEvents);
    const NewUserEvents = {
      ...userEvents,
      [date]: {
        ...(userEvents[date] || {}),
        [NewEventID]: {
          title,
          description,
          color,
          createdAt: Date.now(),
        },
      },
    };

    await admin
      .firestore()
      .collection("calendar")
      .doc(sessionUID)
      .update({ ...NewUserEvents });

    res.json({
      success: true,
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      err: {
        code: "internal-error",
      },
    });
  }
});

app.post("/addEvent/public", async (req, res) => {
  if (!(await checkStatus(req))) {
    return res.status(403).send({
      success: false,
      err: {
        code: "no-permission",
      },
    });
  }
  try {
    const { date, title, description, color } = req.body;

    if (!date || !title || !description || !color) {
      return res.send({
        success: false,
        err: {
          code: "empty-fields",
        },
      });
    }

    const EventsDoc = await admin
      .firestore()
      .collection("calendar")
      .doc("public")
      .get();
    const PublicEvents = EventsDoc.data() || {};
    const oldEvents = Object.values(EventsDoc).flatMap((events) =>
      Object.keys(events),
    );

    const NewEventID = generateUniqueCode(oldEvents);
    const NewPublicEvents = {
      ...PublicEvents,
      [date]: {
        ...(PublicEvents[date] || {}),
        [NewEventID]: {
          title,
          description,
          color,
          createdAt: Date.now(),
        },
      },
    };

    await admin
      .firestore()
      .collection("calendar")
      .doc("public")
      .update({ ...NewPublicEvents });

    res.json({
      success: true,
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      err: {
        code: "internal-error",
      },
    });
  }
});

app.post("/deleteEvent", async (req, res) => {
  if (!(await checkStatus(req))) {
    return res.status(403).send({
      success: false,
      err: {
        code: "no-permission",
      },
    });
  }
  try {
    const { username, date, eventID } = req.body;

    const UsernamesDoc = await admin
      .firestore()
      .collection("usersData")
      .doc("username")
      .get();
    const UserID = UsernamesDoc.data()?.[username];

    const EventsDoc = await admin
      .firestore()
      .collection("calendar")
      .doc(UserID)
      .get();
    const UserEvents = EventsDoc.data() || {};

    if (!UserEvents[date]?.[eventID]) {
      return res.send({
        success: false,
        err: {
          code: "event-not-found",
        },
      });
    }

    delete UserEvents[date][eventID];

    await admin
      .firestore()
      .collection("calendar")
      .doc(UserID)
      .update({ ...UserEvents });

    sendNotification(
      UserID,
      "eventDeleted",
      "${eventDeleted}",
      "/pic/icons/calendar.png",
      "icon",
      "/calendar",
    );

    res.json({
      success: true,
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      err: {
        code: "internal-error",
      },
    });
  }
});

app.post("/deleteEvent/me", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  try {
    const { date, eventID } = req.body;

    const EventsDoc = await admin
      .firestore()
      .collection("calendar")
      .doc(sessionUID)
      .get();
    const UserEvents = EventsDoc.data() || {};

    if (!UserEvents[date]?.[eventID]) {
      return res.send({
        success: false,
        err: {
          code: "event-not-found",
        },
      });
    }

    delete UserEvents[date][eventID];

    await admin
      .firestore()
      .collection("calendar")
      .doc(sessionUID)
      .update({ ...UserEvents });

    res.json({
      success: true,
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      err: {
        code: "internal-error",
      },
    });
  }
});

app.post("/deleteEvent/public", async (req, res) => {
  if (!(await checkStatus(req))) {
    return res.status(403).send({
      success: false,
      err: {
        code: "no-permission",
      },
    });
  }
  try {
    const { date, eventID } = req.body;

    const EventsDoc = await admin
      .firestore()
      .collection("calendar")
      .doc("public")
      .get();
    const PublicEvents = EventsDoc.data() || {};
    if (!PublicEvents[date]?.[eventID]) {
      return res.send({
        success: false,
        err: {
          code: "event-not-found",
        },
      });
    }

    delete PublicEvents[date][eventID];

    await admin
      .firestore()
      .collection("calendar")
      .doc("public")
      .update({ ...PublicEvents });

    res.json({
      success: true,
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      err: {
        code: "internal-error",
      },
    });
  }
});

app.get("/getCalendar", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  try {
    const calendar = admin.firestore().collection("calendar");

    const UserDoc = await calendar.doc(sessionUID).get();
    const PublicDoc = await calendar.doc("public").get();

    const UserData = UserDoc.data();
    const PublicData = PublicDoc.data();

    if (!UserData)
      return res.status(404).send({ err: { code: "no-profile-found" } });

    const data = { ...UserData };

    for (const [date, events] of Object.entries(PublicData || {})) {
      data[date] = {
        ...(data[date] || {}),
        ...events,
      };
    }

    res.send({ success: true, calendar: data });
  } catch (err) {
    res.status(500).send({ err: { code: "failed-to-fetch-notifications" } });
  }
});

//================== Posts ==================//
app.post("/newPost", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  try {
    var oldPosts = [];
    const collection = await admin.firestore().collection("posts").get();

    if (collection.size > 0) {
      collection.forEach((postsdoc) => {
        oldPosts.push(postsdoc.data().id.split("-")[1]);
      });
    }

    const NewPostData = req.body;
    var pics = [];
    try {
      for (const pic of NewPostData.pics) {
        const result = await cloudinary.uploader.upload(pic, {
          folder: "posts",
        });
        pics.push(result.secure_url);
      }

      const NewPostId = generateUniqueCode(oldPosts);
      if (NewPostData.pics.length > 0) {
        await admin.firestore().collection("posts").doc(NewPostId).set(
          {
            id: NewPostId,
            userID: sessionUID,
            time: Date.now(),
            caption: NewPostData.caption,
            pics: pics,
          },
          { merge: true },
        );

        await admin.firestore().collection("postsDetails").doc(NewPostId).set(
          {
            like: [],
            comment: [],
          },
          { merge: true },
        );

        res.send({ success: true, newPostId: NewPostId });
      } else {
        res.send({ success: false, err: { code: "missing-picture" } });
      }
    } catch (err) {
      res.status(500).send({ err: { code: "failed-to-fetch-profile" } });
    }
  } catch (err) {
    res.status(500).send({ err: { code: "failed-to-fetch-profile" } });
  }
});

app.get("/loadPosts", async (req, res) => {
  const sessionUID = req.cookies.session;

  try {
    var postsList = [];
    const collection = await admin.firestore().collection("posts").get();
    const postsDetails = await admin
      .firestore()
      .collection("postsDetails")
      .get();
    const UsersCollection = await admin
      .firestore()
      .collection("usersData")
      .get();
    if (collection.size > 0) {
      collection.forEach((postsdoc) => {
        const PostData = postsdoc.data();
        const detailsPost = postsDetails.docs
          .find((doc) => doc.id === PostData.id)
          .data();
        const userDoc = UsersCollection.docs.find(
          (doc) => doc.id === PostData.userID,
        );
        const userPost = userDoc ? userDoc.data().profile : {};
        const isLiked = detailsPost.like.includes(sessionUID) || false;
        var comments = [];
        if (detailsPost.comment.length > 0) {
          detailsPost.comment.forEach((commentDetails) => {
            const userComment =
              UsersCollection.size > 0
                ? UsersCollection.docs
                    .find((doc) => doc.id === commentDetails.userID)
                    .data().profile
                : {};
            const userSame =
              commentDetails.userID === sessionUID ? true : false;
            const CommentDetails = {
              userSame,
              id: commentDetails.id,
              pfp:
                userComment.pfp === null
                  ? "/pic/profile_pic_unknown.png"
                  : userComment.pfp,
              name: userComment.firstname
                ? userComment.firstname +
                  (userComment.lastname ? " " + userComment.lastname : "")
                : "Deleted Account",
              time: commentDetails.time,
              text: commentDetails.text,
              reply: commentDetails.reply,
            };
            comments.push(CommentDetails);
          });
          comments.sort((a, b) => b.time - a.time);
        }
        const userSame = PostData.userID === sessionUID ? true : false;
        const PostDetails = {
          userSame,
          id: PostData.id,
          pfp:
            userPost.pfp === null
              ? "/pic/profile_pic_unknown.png"
              : userPost.pfp,
          name: userPost.firstname
            ? userPost.firstname +
              (userPost.lastname ? " " + userPost.lastname : "")
            : "Deleted Account",
          time: PostData.time,
          caption: PostData.caption || "",
          pics: PostData.pics,
          postID: PostData.postID,
          state: {
            isLiked,
            comments,
          },
        };
        postsList.push(PostDetails);
      });

      postsList.sort((a, b) => a.time - b.time);
      res.send({ success: true, posts: postsList });
    } else {
      res.send({ success: true, posts: null });
    }
  } catch (err) {
    res
      .status(500)
      .send({ err: { code: "failed-to-fetch-profile", posts: null } });
    console.log(err);
  }
});

app.post("/like", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  try {
    const Userdoc = await admin
      .firestore()
      .collection("usersData")
      .doc(sessionUID)
      .get();
    const Userdata = Userdoc.data()?.profile;

    if (!Userdata)
      return res.status(404).send({ err: { code: "no-profile-found" } });

    const PostId = req.body.postId;
    if (!PostId)
      return res.status(400).send({ err: { code: "missing-post-id" } });

    const PostDoc = await admin
      .firestore()
      .collection("posts")
      .doc(PostId)
      .get();
    const UserID = PostDoc.data()?.userID;

    const postRef = admin.firestore().collection("postsDetails").doc(PostId);
    const postDetails = await postRef.get();

    if (!postDetails.exists) {
      await postRef.set({ like: [sessionUID], comment: [] });
      return res.send({ success: true, liked: true });
    }

    const currentLikes = postDetails.data().like || [];

    if (currentLikes.includes(sessionUID)) {
      await postRef.update({
        like: admin.firestore.FieldValue.arrayRemove(sessionUID),
      });
      return res.send({ success: true, liked: false });
    } else {
      await postRef.update({
        like: admin.firestore.FieldValue.arrayUnion(sessionUID),
      });
      if (sessionUID !== UserID) {
        sendNotification(
          UserID,
          "postLiked",
          `${Userdata.firstname} ${Userdata.lastname} ` + "${postLiked}",
          Userdata.pfp === null ? "/pic/profile_pic_unknown.png" : Userdata.pfp,
          "profile",
          `/posts?postID=${PostId}`,
        );
      }
      return res.send({ success: true, liked: true });
    }
  } catch (err) {
    console.error("Error in:", err);
    res.status(500).send({ err: { code: "failed-to-fetch-profile" } });
  }
});

app.post("/newComment", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  try {
    const Userdoc = await admin
      .firestore()
      .collection("usersData")
      .doc(sessionUID)
      .get();
    const Userdata = Userdoc.data()?.profile;

    // if (!Userdata) return res.status(404).send({ err: { code: "no-profile-found"} });

    const PostId = req.body.postId;
    const PostText = req.body.text;
    if (!PostId)
      return res.status(400).send({ err: { code: "missing-post-id" } });
    const PostDoc = await admin
      .firestore()
      .collection("posts")
      .doc(PostId)
      .get();
    const UserID = PostDoc.data()?.userID;

    const postRef = admin.firestore().collection("postsDetails").doc(PostId);
    const postDetails = await postRef.get();

    const NewCommentId = generateUniqueCode(postDetails.data().comment);

    const commentData = {
      id: NewCommentId,
      text: PostText,
      postID: PostId,
      userID: sessionUID,
      time: Date.now(),
      reply: [],
    };

    const userComment = {
      pfp:
        Userdata.pfp === null ? "/pic/profile_pic_unknown.png" : Userdata.pfp,
      name: Userdata.firstname
        ? Userdata.firstname +
          (Userdata.lastname ? " " + Userdata.lastname : "")
        : "Deleted Account",
    };

    if (!postDetails.exists) {
      await postRef.set({ comment: [commentData], like: [] });
      return res.send({ success: true, comment: commentData, userComment });
    }

    await postRef.update({
      comment: admin.firestore.FieldValue.arrayUnion(commentData),
    });

    if (sessionUID !== UserID) {
      sendNotification(
        UserID,
        "postCommented",
        `${Userdata.firstname} ${Userdata.lastname} ` + "${postCommented}",
        Userdata.pfp === null ? "/pic/profile_pic_unknown.png" : Userdata.pfp,
        "profile",
        `/posts?postID=${PostId}`,
      );
    }
    return res.send({ success: true, comment: commentData, userComment });
  } catch (err) {
    console.error("Error in:", err);
    res.status(500).send({ err: { code: "failed-to-fetch-profile" } });
  }
});

app.post("/removePost", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  try {
    const PostId = req.body.postId;
    if (!PostId)
      return res.status(400).send({ err: { code: "missing-post-id" } });

    const postRef = await admin
      .firestore()
      .collection("posts")
      .doc(PostId)
      .get();
    const postDetails = postRef.data();
    if (sessionUID !== postDetails.userID)
      return res.send({ success: false, err: { code: "unknown" } });

    await admin.firestore().collection("posts").doc(PostId).delete();
    await admin.firestore().collection("postsDetails").doc(PostId).delete();

    return res.send({ success: true });
  } catch (err) {
    console.error("Error in:", err);
    res.status(500).send({ err: { code: "failed-to-fetch-profile" } });
  }
});

app.post("/removeComment", async (req, res) => {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  try {
    const PostId = req.body.postId;
    const CommentId = req.body.commentId;
    if (!PostId)
      return res.status(400).send({ err: { code: "missing-post-id" } });

    const postDataRef = await admin
      .firestore()
      .collection("posts")
      .doc(PostId)
      .get();
    const postDataDetails = postDataRef.data();
    const postRef = admin.firestore().collection("postsDetails").doc(PostId);
    const postDetailsdoc = await postRef.get();
    const postDetailsData = postDetailsdoc.data();
    const CommentDetails = postDetailsData.comment.find(
      (c) => c.id === CommentId,
    );
    if (sessionUID !== CommentDetails.userID)
      return res.send({ success: false, err: { code: "unknown" } });

    const commentData = {
      id: CommentId,
      text: CommentDetails.text,
      postID: PostId,
      userID: CommentDetails.userID,
      time: CommentDetails.time,
      reply: CommentDetails.reply,
    };

    const lastComment = postDetailsData.comment.length <= 1 ? true : false;

    await postRef.update({
      comment: admin.firestore.FieldValue.arrayRemove(commentData),
    });
    return res.send({ success: true, PostId, CommentId, lastComment });
  } catch (err) {
    console.error("Error in:", err);
    res.status(500).send({ err: { code: "failed-to-fetch-profile" } });
  }
});

//================== OTHER ==================//

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user;
        try {
          user = await admin.auth().getUserByEmail(profile.emails[0].value);
        } catch (e) {
          user = await admin.auth().createUser({
            email: profile.emails[0].value,
            displayName: profile.displayName,
          });
        }

        done(null, user);
      } catch (err) {
        done(err);
      }
    },
  ),
);

//================== Functions ==================//
function generateUniqueCode(existingCodes) {
  const length = 16;
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let code = "";

  for (let i = 0; i < length; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }

  if (existingCodes.includes(code)) {
    return generateUniqueCode(existingCodes);
  } else {
    return code;
  }
}

function validateFields(fields) {
  const errors = {};
  let allValid = true;

  for (const [key, value] of Object.entries(fields)) {
    if (value === "") {
      errors[key] = true;
      allValid = false;
    } else {
      errors[key] = false;
    }
  }

  return { valid: allValid, errors };
}

async function checkStatus(req) {
  const sessionUID = req.cookies.session;
  if (!sessionUID)
    return res.status(401).send({ err: { code: "not-logged-in" } });

  try {
    const Userdoc = await admin
      .firestore()
      .collection("usersData")
      .doc(sessionUID)
      .get();
    const Userdata = Userdoc.data()?.profile;

    if (!Userdata)
      return res.status(404).send({ err: { code: "no-profile-found" } });

    return Userdata?.status === "2";
  } catch (err) {
    return false;
  }
}

async function sendNotification(UserID, title, message, icon, iconType, url) {
  const Userdoc = await admin
    .firestore()
    .collection("usersData")
    .doc(UserID)
    .get();
  const token = Userdoc.data()?.fcmToken;
  const browserNotifications = Userdoc.data()?.browserNotifications;
  const emailNotifications = Userdoc.data()?.emailNotifications;
  const whatsappNotifications = Userdoc.data()?.whatsappNotifications;

  try {
    if (browserNotifications && token) {
      await admin.messaging().send({
        token,
        data: {
          title,
          body: message,
          icon,
          iconType,
          url: url || "/notifications",
        },
      });
    }
  } catch (err) {
    console.error(err);
    if (err.code === "messaging/registration-token-not-registered") {
      await admin.firestore().collection("usersData").doc(UserID).update({
        fcmToken: admin.firestore.FieldValue.delete(),
      });
    }
  }

  try {
    if (whatsappNotifications) {
      const phoneNum = Userdoc.data()?.phoneNum;
      if (phoneNum) {
        const response = await fetch(
          "https://keraza-2026.pages.dev/lang/en.json",
        );

        if (!response.ok) {
          throw new Error(`Failed to fetch language file: ${response.status}`);
        }

        const langData = await response.json();
        const PageNotifications = langData.notifications;

        const titleWhatsapp = PageNotifications[title]?.title;
        const bodyWhatsapp = message.replace(
          /\$\{([^}]+)\}/g,
          (_, key) => PageNotifications[key.trim()]?.message || "",
        );

        sendWhatsapp("2" + phoneNum, "en", titleWhatsapp, bodyWhatsapp, "");
      }
    }
  } catch (err) {
    console.error(err);
  }

  const oldNotifications = [];
  const Notificationdoc = await admin
    .firestore()
    .collection("notifications")
    .doc(UserID)
    .get();
  const UserNotifications = Notificationdoc.data()?.notifications;
  if (UserNotifications && UserNotifications.size > 0) {
    UserNotifications.forEach((notificationsdoc) => {
      oldNotifications.push(notificationsdoc.data().id.split("-")[1]);
    });
  }

  const NewNotificationCode = generateUniqueCode(oldNotifications);
  const NewNotification = {
    [NewNotificationCode]: {
      title,
      message,
      icon,
      iconType,
      unread: true,
      createdAt: Date.now(),
      data: {
        clickable: true,
        type: "qr-scan",
        scannerUID: "...",
        scannerUsername: "mina",
      },
    },
  };

  const NewUserNotifications = {
    ...UserNotifications,
    ...NewNotification,
  };

  await admin.firestore().collection("notifications").doc(UserID).update({
    notifications: NewUserNotifications,
    unread: true,
  });
}

async function sendWhatsapp(phoneNum, lang, title, message, url) {
  const token = process.env.WHATSAPP_TOKEN;
  const phoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID;

  const targetUrl = url?.trim() || "notifications";

  // const response = await fetch(
  //   `https://graph.facebook.com/v22.0/${phoneNumberId}/messages`,
  //   {
  //     method: "POST",
  //     headers: {
  //       Authorization: `Bearer ${token}`,
  //       "Content-Type": "application/json",
  //     },
  //     body: JSON.stringify({
  //       messaging_product: "whatsapp",
  //       to: phoneNum,
  //       type: "template",

  //       template: {
  //         name: "notification_keraza",
  //         language: {
  //           code: lang,
  //         },

  //         components: [
  //           {
  //             type: "body",
  //             parameters: [
  //               {
  //                 type: "text",
  //                 text: title,
  //               },
  //               {
  //                 type: "text",
  //                 text: message,
  //               },
  //             ],
  //           },
  //           {
  //             type: "button",
  //             sub_type: "url",
  //             index: "0",
  //             parameters: [
  //               {
  //                 type: "text",
  //                 text: "",
  //               },
  //             ],
  //           },
  //         ],
  //       },
  //     }),
  //   },
  // );

  const response = await fetch(
    `https://graph.facebook.com/v22.0/${phoneNumberId}/messages`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        messaging_product: "whatsapp",
        to: phoneNum,
        type: "template",

        template: {
          name: "_notifications_keraza_",
          language: {
            code: lang,
          },

          components: [
            {
              type: "header",
              parameters: [
                {
                  type: "text",
                  text: "New Notification",
                },
              ],
            },

            {
              type: "body",
              parameters: [
                {
                  type: "text",
                  text: title,
                },
                {
                  type: "text",
                  text: message,
                },
              ],
            },

            {
              type: "button",
              sub_type: "url",
              index: "0",
              parameters: [
                {
                  type: "text",
                  text: targetUrl,
                },
              ],
            },
          ],
        },
      }),
    },
  );

  const data = await response.json();

  if (!response.ok) {
    console.error("WhatsApp API error:", data);

    return {
      success: false,
      status: response.status,
      error: data,
    };
  }

  return {
    success: true,
    status: response.status,
    messageId: data.messages?.[0]?.id ?? null,
    data,
  };
}

const SECRET_KEY = process.env.encryptPassword;

function encrypt(text) {
  return CryptoJS.AES.encrypt(text, SECRET_KEY).toString();
}
function decrypt(cipher) {
  const bytes = CryptoJS.AES.decrypt(cipher, SECRET_KEY);
  return bytes.toString(CryptoJS.enc.Utf8);
}

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
