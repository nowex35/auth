# auth

## 概要

###### このリポジトリはHono.jsによる認証用APIの実装です。  
###### 認証ロジックにおかしな点や脆弱性があれば教えていただけると幸いです
主なAPIは
- メール認証
  - /signup
  - /login
  - /verify
- Oauth2.0認証
  - /oauth/google
  - /oauth/google/callback
- other
  - /refresh
  - /logout
  - /me

- basic認証風
  - /basic/register
  - /basic/access

---
## 主な特徴
#### supabase等のBaaSのAPIを用いない独自のOauth連携認証API
#### フロントエンドの実装によりメール・Oauthの任意の認証方法を選択できる
#### なるべく他サービスの依存を避け、APIの拡張性を確保

 
## 実装詳細(工夫等)
- oauth認証は
  1. frontからのアクセス
  2. /auth/oauth/google(oauthリンクがgoogleから送られる)
  3. google側でユーザ情報取得
  4. /auth/oauth/callback
     - 認可コードを使いaccessトークンを取得
     - accessトークンからユーザ情報取得
     - ユーザ情報取得出来たらgoogle側のトークンは廃棄
     - refreshトークンを作成し,frontにCookieで送る
  5. front側のcallbackで受け取りauth/meにリクエスト
  6. /auth/me(user_idを返す)
  7. frontからログアウトのリクエストがあれば/auth/logoutでトークンを削除
- **prisma**によるスキーマ管理、ORM機能
- **redis**によるセッション機能(/meの実装が終われば完全)
- userモデルはpasswordのnullを許し,providerカラムを追加
  - これによりメール認証とoauth認証を同一テーブルで管理可能
- refreshトークンをdbに保存しつつ,Cookieで配布
- accessトークンも独自に文字列を生成
- **Docker-compose**によるコンテナ管理
- **vitest**によるテスト実行
- **CI/CD**

---

## CI/CD

このリポジトリでは、GitHub Actions を使用して継続的インテグレーション（CI）および継続的デリバリー（CD）を実現しています。

- **対象ブランチ:** main および develop ブランチへのプッシュ時に実行
- **使用サービス:**
  - PostgreSQL
  - Redis

CI/CDプロセスの主なステップは以下の通りです。

1. 依存関係のインストール
2. Prismaクライアントの生成
3. Prismaマイグレーションの実行
4. テストの実行

---

## .github フォルダ

このリポジトリには、以下のテンプレートが含まれています。

- **Issue テンプレート:**
  - バグ報告
  - 機能リクエスト
- **Pull Request テンプレート:**
  - チケット番号
  - 変更内容
  - TODO リスト
  - チェックリスト
  - 備考

---

## パフォーマンス比較
### キャッシュ無し（realは変わらない。user,sysは明らかに速い）

##### npm

real    1m7.627s|1m4.592s|1m6.746s  
user    0m0.032s|0m0.024s|0m0.042s  
sys     0m0.151s|0m0.130s|0m0.116s  

##### bun

real    1m9.227s|1m10.097s|1m16.231s  
user    0m0.001s|0m0.003s|0m0.003s  
sys     0m0.025s|0m0.049s|0m0.036s  

#### AVG(若干npmが速い)
##### npm
real    1m6.3s
##### bun
real    1m11.83s

### キャッシュ時（約２倍速い）
##### npm

real    0m11.145s|0m14.210s|0m15.735s  
user    0m0.013s|0m0.008s|0m0.049s  
sys     0m0.038s|0m0.074s|0m0.033s  

##### bun

real    0m6.031s|0m7.555s|0m7.761s  
user    0m0.004s|0m0.003s|0m0.018s  
sys     0m0.033s|0m0.014s|0m0.004s  

#### AVG

##### npm
real    13.67s
##### bun
real    **7.13s**

**結果:キャッシュ時はbunが2倍速くCI/CDなどにおいても有利**  
そのため、基本はbunでビルドしつつ、相性の悪いprismaの一部をnpmで実行することにした
