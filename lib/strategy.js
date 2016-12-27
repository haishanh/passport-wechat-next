'use strict';

const {Strategy} = require('passport-strategy');
const debug = require('debug')('passport-wechat-next');
const OAuth = require('wechat-oauth');

class WechatStrategy extends Strategy {

  constructor({
    name = 'wechat',
    scope = 'snsapi_userinfo',
    lang = 'en',
    client = 'wechat',
    appID,
    appsecret,
    getToken,
    saveToken,
    state,
    callbackURL,
    passReqToCallback,
    checkUserExistence
  } = {}, verify) {
    super();

    if (!verify) {
      throw new TypeError('verify callback needed');
    }
    if (typeof verify !== 'function') {
      throw new TypeError('verify must be a function');
    }
    if (!appID) {
      throw new TypeError('appID needed');
    }
    if (!appsecret) {
      throw new TypeError('appsecret needed');
    }

    this.name = name;
    this._oauth = new OAuth(appID, appsecret, getToken, saveToken);
    this._state = state;
    this._scope = scope;
    this._client = client; // client is wechat app or desktop browser
    this._callbackURL = callbackURL;
    this._verify = verify;
    this._lang = lang;
    this._passReqToCallback = passReqToCallback;
    this._checkUserExistence = checkUserExistence;
  }

  authenticate(req, opt = {}) {
    if (!req._passport) {
      return this.error(new Error('passport.initialize() ' +
        'middleware not in use'));
    }

    if (req.query) {
      const { state, code } = req.query;
      if (state && !code) {
        return this.fail(401);
      }
      if (code === 'authdeny') {
        return this.fail(401);
      }
    }

    if (req.query && req.query.code) {
      const code = req.query.code;
      // 第二步：通过code换取网页授权access_token
      this._oauth.getAccessToken(code, (err, res) => {
        if (err) {
          return this.error(err);
        }

        const asDone = (err, user, info) => {
          if (err) return this.error(err);
          if (!user) return this.fail(info);
          this.success(user, info);
        };

        const {
          access_token,
          expires_in,
          refresh_token,
          openid,
          scope
        } = res.data;
        if (scope.split(',').indexOf('snsapi_base') != -1) {
          // unable to get user info
          const profile = { openid };
          try {
            if (this._passReqToCallback) {
              this._verify(req, access_token, refresh_token, profile, expires_in, asDone);
            } else {
              this._verify(access_token, refresh_token, profile, expires_in, asDone);
            }
          } catch (err) {
            return this.error(err);
          }
        } else {
          // we already have openid
          if (this._checkUserExistence) {
            const user = this._checkUserExistence(openid);
            if (user) {
              return this.success(user);
            }
          }
          this._oauth.getUser({
            openid,
            lang: this._lang
          }, (err, profile) => {
            if (err) return this.error(err);
            try {
              if (this._passReqToCallback) {
                this._verify(req, access_token, refresh_token, profile, expires_in, asDone);
              } else {
                this._verify(access_token, refresh_token, profile, expires_in, asDone);
              }
            } catch (err) {
              return this.error(err);
            }
          });
        }
      });
    } else {
      // 第一步：用户同意授权，获取code
      const state = opt.state || this._state;
      const scope = opt.scope || this._scope;
      const callbackURL = opt.callbackURL || this._callbackURL
      const method = this._client === 'wechat'
        ? 'getAuthorizeURL'
        : 'getAuthorizeURLForWebsite';
      const url = this._oauth[method](callbackURL, state, scope);
      debug('Wechat Oauth step1 redirect to get code');
      this.redirect(url, 302);
    }
  }
}

module.exports = WechatStrategy;
