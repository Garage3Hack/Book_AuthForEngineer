// index.js
require('dotenv').config();
const express = require('express');
const passport = require('passport');
const path = require('path');
const jwt = require('jsonwebtoken');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const jwksClient = require('jwks-rsa');
const { 
  CognitoIdentityProviderClient,
  InitiateAuthCommand
} = require("@aws-sdk/client-cognito-identity-provider");

// Cognito クライアントの作成
const cognitoClient = new CognitoIdentityProviderClient({ 
  region: 'ap-northeast-1'
});

// JWKSクライアントの設定
const client = jwksClient({
  jwksUri: `https://cognito-idp.ap-northeast-1.amazonaws.com/********/.well-known/jwks.json`
});

// JWT認証の設定
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKeyProvider: (request, token, done) => {
    // トークンからキーIDを取得
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || !decoded.header.kid) {
      return done(new Error('Invalid token'));
    }

    // JWKSから公開鍵を取得
    client.getSigningKey(decoded.header.kid, (err, key) => {
      if (err) {
        return done(err);
      }
      const publicKey = key.getPublicKey();
      done(null, publicKey);
    });
  },
  algorithms: ['RS256']
};

passport.use(new JwtStrategy(jwtOptions, async (jwtPayload, done) => {
  try {
    // JWTペイロードからユーザー情報を取得
    const user = {
      username: jwtPayload['cognito:username'],
      name: jwtPayload.name,
      sub: jwtPayload.sub
    };
    return done(null, user);
  } catch (error) {
    return done(error, false);
  }
}));

/**
 * ユーザー認証を行う関数
 * @param {string} username - ユーザー名
 * @param {string} password - パスワード
 * @returns {Promise} - 認証結果
 */
const authenticateUser = async (username, password) => {
  try {
    const params = {
      ClientId: '********',
      AuthFlow: "USER_PASSWORD_AUTH",
      AuthParameters: {
        USERNAME: username,
        PASSWORD: password
      }
    };

    const command = new InitiateAuthCommand(params);
    const response = await cognitoClient.send(command);

    return {
      success: true,
      username: username,
      accessToken: response.AuthenticationResult.AccessToken,
      idToken: response.AuthenticationResult.IdToken,
      refreshToken: response.AuthenticationResult.RefreshToken,
      isAuthenticated: true,
      lastLogin: new Date().toISOString()
    };
  } catch (error) {
    console.error("認証エラー:", error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Expressアプリの初期化
const app = express();

// テンプレートエンジンの設定
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ミドルウェアの設定
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());

// 認証確認ミドルウェア
const authenticateJWT = passport.authenticate('jwt', { session: false });

// ルートの設定
// ログインフォームの表示
app.get('/login', (req, res) => {
  res.render('login');
});

// ログイン処理
app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: 'ユーザー名とパスワードは必須です'
      });
    }

    const result = await authenticateUser(username, password);
    if (result.success) {
      return res.json({
        success: true,
        idToken: result.idToken
      });
    } else {
      return res.status(401).json({
        success: false,
        error: result.error
      });
    }
  } catch (error) {
    console.error('認証エラー:', error);
    return res.status(500).json({
      success: false,
      error: '認証処理中にエラーが発生しました'
    });
  }
});

// ユーザー情報取得API
app.get('/api/user', authenticateJWT, (req, res) => {
  res.json({
    success: true,
    user: req.user
  });
});

// ホームページ
app.get('/', (req, res) => {
  res.render('index');
});

// サーバーの起動
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`サーバーが起動しました: http://localhost:${PORT}`);
});
