require("dotenv").config();
const express = require("express");
const fs = require("fs");
const verifyToken = require("./src/middleware/auth");
const jwt = require("jsonwebtoken");

const raw = fs.readFileSync("./src/db.json");
const database = JSON.parse(raw);

let users = database.users;
const cors = require("cors");
const bcrypt = require("bcrypt");
const app = express();
const jsonServer = require("json-server");
app.use(express.json());
app.use(cors());

// app.use("/api", (req, res) => {
//   res.send("oke server");
// });
//auth
const generateTokens = (payload) => {
  const { id, name } = payload;
  const accessToken = jwt.sign({ id, name }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "5m",
  });
  const refreshToken = jwt.sign(
    { id, name },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: "48h",
    }
  );

  return { accessToken, refreshToken };
};
function updateRefreshToken(name, refreshToken) {
  console.log("updateRefreshToken ~ name", name);
  users = users.map((user) => {
    if (user.name === name) {
      return {
        ...user,
        refreshToken,
      };
    }
    return user;
  });
  fs.writeFileSync("db.json", JSON.stringify({ ...database, users }));
}
app.get("/me", verifyToken, (req, res) => {
  const user = users.find((user) => {
    return user.id === req.userId;
  });
  if (!user) return res.sendStatus(401);
  res.json(user);
});

app.post("/auth/login", (req, res) => {
  const email = req.body.email;
  const user = users.find((user) => {
    return user.email === email;
  });
  if (!user) return res.sendStatus(401);
  const dbPassword = user.password;
  bcrypt.compare(req.body.password, dbPassword, (err, hash) => {
    if (err || !hash) {
      res.status(403).json({
        statusCode: 403,
        error: {
          message: "Password does not match",
        },
      });
    }
    const tokens = generateTokens(user);

    updateRefreshToken(user.name, tokens.refreshToken);
    res.json(tokens);
  });
});

app.post("/token", (req, res) => {
  const refreshToken = req.body.refreshToken;
  if (!refreshToken) return res.sendStatus(401);
  const user = users.find((user) => {
    return user.refreshToken === refreshToken;
  });
  if (!user) return res.sendStatus(403);
  try {
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const tokens = generateTokens(user);
    updateRefreshToken(user.name, tokens.refreshToken);
    res.json(tokens);
  } catch (err) {
    console.log(err);
    res.sendStatus(403);
  }
});

app.post("/auth/register", (req, res) => {
  const { name, password, email, permissions, avtUser } = req.body;
  const user = users.find((user) => {
    return user.email === email;
  });
  if (user) {
    return res.sendStatus(409).json({ error: "User already exists" });
  }
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      return;
    }
    users.push({
      id: users.length + 1,
      name,
      password: hash,
      email,
      avtUser,
      refreshToken: null,
      permissions,
    });
    fs.writeFileSync("db.json", JSON.stringify({ ...database, users }));
    res.sendStatus(201);
  });
});

app.delete("/logout", verifyToken, (req, res) => {
  const user = users.find((user) => user.id === req.userId);
  updateRefreshToken(user.name, "");
  res.sendStatus(204);
});

//api
//app.use("/api", jsonServer.defaults(), jsonServer.router("db.json"));
app.get("/api/campaigns", verifyToken, (req, res) => {
  res.json(database.campaigns);
});
app.get("/api/data", (req, res) => {
  res.json(database);
});

app.listen(4001, () => console.log("Server started on port 4001"));
