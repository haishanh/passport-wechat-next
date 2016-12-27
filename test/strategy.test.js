'use strict';

const Strategy = require('../lib').Strategy; 
const expect = require('expect');
const OAuth = require('wechat-oauth');
const { stub, spy } = require('sinon');

// prevent warning from sinon
Strategy.prototype.fail = () => {};
Strategy.prototype.success = () => {};
Strategy.prototype.error = () => {};
Strategy.prototype.redirect = () => {};

describe('WechatStrategy', () => {

  describe('Basic', () => {
    it('should throw TypeError', () => {
      try {
        const s = new Strategy({
          appID: 'test',
        }, () => {});
      } catch (err) {
        expect(err).toBeA(TypeError);
      }
    });
    
    it('should able to create an instance', () => {
      const s = new Strategy({
        appID: 'test',
        appsecret: 'test'
      }, () => {});
      expect(s.name).toBe('wechat');
    });

    it('should fail with 401 w/o req.query.code', () => {
      const s = new Strategy({
        appID: 'test',
        appsecret: 'test'
      }, () => {});
      const fail = spy(Strategy.prototype, 'fail');
      const req = {
        _passport: true,
        query: {
          state: true,
          code: false
        }
      };
      s.authenticate(req);
      Strategy.prototype.fail.restore();
      expect(fail.calledWith(401)).toBeTruthy();
    });

    it('should fail with 401 if auth deny', () => {
      const s = new Strategy({
        appID: 'test',
        appsecret: 'test'
      }, () => {});
      const fail = spy(Strategy.prototype, 'fail');
      const req = {
        _passport: true,
        query: {
          state: true,
          code: 'authdeny'
        }
      };
      s.authenticate(req);
      Strategy.prototype.fail.restore();
      expect(fail.calledWith(401)).toBeTruthy();
    });
  });

  describe('OAuth step 1 - get code', () => {
    it('should redirect to get code', () => {
      const opt = {
        appID: 'test',
        appsecret: 'test',
        state: 'state',
        scope: 'scope',
        callbackURL: 'callbackURL'
      };
      const s = new Strategy(opt, () => {});
      const getAuthorizeURL = stub(OAuth.prototype, 'getAuthorizeURL', () => 'url');
      const redirect = spy(Strategy.prototype, 'redirect');
      const req = {
        _passport: true,
        query: {}
      };
      s.authenticate(req);
      Strategy.prototype.redirect.restore();
      OAuth.prototype.getAuthorizeURL.restore();
      expect(
        getAuthorizeURL.calledWith(opt.callbackURL, opt.state, opt.scope)
      ).toBeTruthy();
      expect(redirect.calledWith('url', 302)).toBeTruthy();
    });

    it('should redirect to get code with provided options', () => {
      const opt = {
        appID: 'test',
        appsecret: 'test',
        state: 'state',
        scope: 'scope',
        callbackURL: 'callbackURL'
      };
      const opt2 = {
        state: 'state-opt2',
        scope: 'scope-opt2',
        callbackURL: 'callbackURL-opt2'
      };
      const s = new Strategy(opt, () => {});
      const getAuthorizeURL = stub(OAuth.prototype, 'getAuthorizeURL', () => 'url');
      const redirect = spy(Strategy.prototype, 'redirect');
      const req = {
        _passport: true,
        query: {}
      };
      s.authenticate(req, opt2);
      Strategy.prototype.redirect.restore();
      OAuth.prototype.getAuthorizeURL.restore();
      expect(
        getAuthorizeURL.calledWith(opt2.callbackURL, opt2.state, opt2.scope)
      ).toBeTruthy();
      expect(redirect.calledWith('url', 302)).toBeTruthy();
    });
  });

  describe('OAuth step 2 - get access_token', () => {
  });

});
