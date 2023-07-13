const cookieParser = require("cookie-parser");
const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();
const secretText = "superSecret";
const refreshSecretText = "supersuperSecret";

// 그다음 inspect, document.cookie 하면 쿠키에 들어있는 application  coolies 에서 정보확인가능
const posts = [
  {
    userName: "kyuhyun",
    title: "Post1",
  },
  {
    userName: "TESTUSERNAME",
    title: "Post2",
  },
];

let refreshTokens = []; // 추후 db에 저장해줘야함

// 미들웨어등록 (미들웨어 등록할 땐 항상 app.use 를 사용한다)
app.use(express.json());
app.use(cookieParser());
app.get("/", (req, res) => {
  res.send("hihihi");
});

app.post("/login", (req, res) => {
  const username = req.body.username;
  const user = {
    name: username,
  };

  // Create Token by JWT payload + secretText
  // 유효기간 추가
  const accessToken = jwt.sign(user, secretText, { expiresIn: "30s" });

  // JWT 를 이용해 refreshToken 도 생성
  const refreshToken = jwt.sign(user, refreshSecretText, { expiresIn: "1d" });
  refreshTokens.push(refreshToken);

  // refreshtoken 을 쿠키에 넣어주기
  res.cookie("jwt", refreshToken, {
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
  });

  res.json({ accessToken: accessToken });
});

// authmiddleware 를 넣어줌으로써 token 확인을 한 경우에만 posts를 받을 수 있음.
app.get("/posts", authMiddleware, (req, res) => {
  res.json(posts);
});

function authMiddleware(req, res, next) {
  // Token 을 Request header 에서 가져온다
  const authHeader = req.headers["authorization"];
  // Bearer kjdsanfkwnefkq.dsfnioawenfjl.adsfnklwnkf
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401); // client error 발생시켜주기

  // Token 이 있으니 유효한지 확인하기
  jwt.verify(token, secretText, (err, user) => {
    if (err) return res.sendStatus(403); //client error

    req.user = user;
    next();
  });
}

// refresh Token 요청 cookie
app.get("/refresh", (req, res) => {
  // body => parsing => req.body
  // cookies => parsing => req.cookies
  // cookies 가져오기 cookie-parser
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(403);

  const refreshToken = cookies.jwt;
  // refreshToken 이 Db에 있는 토큰인지 확인
  if (!refreshToken.includes(refreshToken)) {
    return res.sendStatus(403);
  }

  // token 이 유효한 토큰인지 확인
  jwt.verify(refreshToken, refreshSecretText, (err, user) => {
    if (err) return res.sendStatus(403);
    // accessToken 을 생성하기
    const accessToken = jwt.sign({ name: user.name }, secretText, {
      expiresIn: "30s",
    });
    res.json({ accessToken: accessToken });
  });
});

const port = 4000;
app.listen(port, () => {
  console.log("listening on port " + port);
});
