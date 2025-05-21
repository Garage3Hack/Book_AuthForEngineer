// index.js
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();

// === セッション管理の設定 ===
// ログイン状態をリクエスト間で維持するためにセッションを使用します
app.use(session({
  secret: 'secret', // セッションの暗号化キー（実際に使用する際は強力なキーを設定してください）
  resave: false, // セッションを強制的に保存しない（最適化のため）
  saveUninitialized: true // 初期化されていないセッションを保存しない
}));
// === ビューエンジンの設定 ===
// EJSテンプレートエンジンを使用して動的なHTMLを生成
app.set('view engine', 'ejs');

// === ミドルウェアの設定 ===
// Google OAuth2.0の設定
app.use(passport.initialize());
app.use(passport.session());


passport.use(new GoogleStrategy({
    clientID: '',
    clientSecret: '',
    callbackURL: 'http://localhost:3000/auth/google/callback'
  },
  (accessToken, refreshToken, profile, done) => {
    // ユーザー処理（データベース保存など）
    return done(null, profile);
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ルーティング
app.get('/', (req, res) => res.render('index', { user: req.user }));

app.get('/auth/google',
  passport.authenticate('google', { 
    scope: ['profile'] 
  })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { 
    failureRedirect: '/login' 
  }),
  (req, res) => res.redirect('/home')
);

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

app.get('/home', (req, res) => {
  res.render('home', { 
    user: req.user,
    debugInfo: JSON.stringify(req.user, null, 2)
  });
});

// === サーバーの起動 ===
// 指定されたポートでサーバーを起動
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
