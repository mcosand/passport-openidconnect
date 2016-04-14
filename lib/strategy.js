/**
 * Module dependencies.
 */
var passport = require('passport')
  , url = require('url')
  , querystring= require('querystring')
  , util = require('util')
  , utils = require('./utils')
  , OAuth2 = require('oauth').OAuth2
  , InternalOAuthError = require('./errors/internaloautherror');


function Strategy(options, verify) {
  options = options || {}
  passport.Strategy.call(this);
  this.name = 'openidconnect';
  this._verify = verify;
  
  if (!options.authorizationURL) throw new Error('OpenIDConnectStrategy requires a authorizationURL option');
  if (!options.tokenURL) throw new Error('OpenIDConnectStrategy requires a tokenURL option');
  if (!options.clientID) throw new Error('OpenIDConnectStrategy requires a clientID option');
  if (!options.clientSecret) throw new Error('OpenIDConnectStrategy requires a clientSecret option');

  // TODO: Implement support for discover and registration.  This means endpoint
  //       URLs and client IDs will need to be dynamically loaded, on a per-provider
  //       basis.  The above checks can be relaxed, once this is complete.

  this._authorizationURL = options.authorizationURL;
  this._tokenURL = options.tokenURL;
  this._userInfoURL = options.userInfoURL;
  
  this._clientID = options.clientID;
  this._clientSecret = options.clientSecret;
  this._callbackURL = options.callbackURL;
  
  this._scope = options.scope;
  this._scopeSeparator = options.scopeSeparator || ' ';
  this._passReqToCallback = options.passReqToCallback;
  this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;

  this._ignoreCertificateErrors = (options.ignoreCertificateErrors === undefined) ? false : options.ignoreCertificateErrors;

  this._buildNonce = function(session) {
    var text = "";
    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for(var i = 0; i < 75; i++) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    session.oidcNonce = text;
    session.oidcNonceTime =  new Date().getTime();
    return text;
  }
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);


Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;
  
  if (req.query && req.query.error) {
    // TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
    //       query parameters, and should be propagated to the application.
    return this.fail();
  }
  
  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req), callbackURL);
    }
  }
  
  
  if (req.body && req.body.code) {
    var code = req.body.code;
    
    var oauth2 = new OAuth2(this._clientID,  this._clientSecret,
                            '', this._authorizationURL, this._tokenURL);
    oauth2.useAuthorizationHeaderforGET(true);
    oauth2.ignoreCertificateError(this._ignoreCertificateErrors);
    
    var accessToken = req.body.access_token;
    var idToken = req.body.id_token;
    var refreshToken = req.body.refresh_token || '';
    
    console.log('TOKEN');
    console.log('AT: ' + accessToken);
    console.log('RT: ' + refreshToken);
    console.log(params);
    console.log('----');
    
    if (!idToken) { return self.error(new Error('ID Token not present in token response')); }
    
    var idTokenSegments = idToken.split('.')
      , jwtClaimsStr
      , jwtClaims;
    
    // TODO: Try catch this to trap JSON parse errors.
    try {
      jwtClaimsStr = new Buffer(idTokenSegments[1], 'base64').toString();
      jwtClaims = JSON.parse(jwtClaimsStr);
    } catch (ex) {
      return self.error(ex);
    }
    
    console.log(jwtClaims);
    
    var iss = jwtClaims.iss;
    var sub = jwtClaims.sub;
    // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
    // "sub" claim was named "user_id".  Many providers still issue the
    // claim under the old field, so fallback to that.
    if (!sub) {
      sub = jwtClaims.user_id;
    }
    
    var nonceTime = new Date().getTime() - req.session.oidcNonceTime;
    if (!jwtClaims.nonce || req.session.oidcNonce != jwtClaims.nonce || nonceTime > 300000)
    {
      return self.error("Invalid nonce or nonce expired");
    }
    // TODO: Ensure claims are validated per:
    //       http://openid.net/specs/openid-connect-basic-1_0.html#id_token
    
    
    self._shouldLoadUserProfile(iss, sub, function(err, load) {
      if (err) { return self.error(err); };
      
      console.log('LOAD: ' + load);
      
      if (load) {
        var parsed = url.parse(self._userInfoURL, true);
        var userInfoURL = url.format(parsed);
        
        console.log('fetch profile: ' + userInfoURL);

        oauth2.get(userInfoURL, accessToken, function (err, body, res) {
          if (err) { console.log(err); return self.error(new InternalOAuthError('failed to fetch user profile', err)); }
        
          
          console.log('PROFILE');
          console.log(body);
          console.log('-------');
          
          var profile = {};
          
          try {
            var json = JSON.parse(body);
            
            profile.id = json.sub;
            // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
            // "sub" key was named "user_id".  Many providers still use the old
            // key, so fallback to that.
            if (!profile.id) {
              profile.id = json.user_id;
            }
            
            profile.displayName = json.name;
            profile.name = { familyName: json.family_name,
                              givenName: json.given_name,
                              middleName: json.middle_name };
            
            profile._raw = body;
            profile._json = json;
            
            onProfileLoaded(profile);
          } catch(e) {
            return self.error(ex);
          }
        });
      } else {
        onProfileLoaded();
      }
      
      function onProfileLoaded(profile) {
        function verified(err, user, info) {
          if (err) { return self.error(err); }
          if (!user) { return self.fail(info); }
          self.success(user, info);
        }
      
        if (self._passReqToCallback) {
          var arity = self._verify.length;
          if (arity == 9) {
            self._verify(req, iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified);
          } else if (arity == 8) {
            self._verify(req, iss, sub, profile, accessToken, refreshToken, params, verified);
          } else if (arity == 7) {
            self._verify(req, iss, sub, profile, accessToken, refreshToken, verified);
          } else if (arity == 5) {
            self._verify(req, iss, sub, profile, verified);
          } else { // arity == 4
            self._verify(req, iss, sub, verified);
          }
        } else {
          var arity = self._verify.length;
          if (arity == 8) {
            self._verify(iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified);
          } else if (arity == 7) {
            self._verify(iss, sub, profile, accessToken, refreshToken, params, verified);
          } else if (arity == 6) {
            self._verify(iss, sub, profile, accessToken, refreshToken, verified);
          } else if (arity == 4) {
            self._verify(iss, sub, profile, verified);
          } else { // arity == 3
            self._verify(iss, sub, verified);
          }
        }
      }
    });
  } else {
    var params = this.authorizationParams(options);
    var params = {};
    params['response_type'] = 'code id_token token';
    params['client_id'] = this._clientID;
    params['redirect_uri'] = callbackURL;
    params['nonce'] = this._buildNonce(req.session);
    params['response_mode'] = 'form_post';
    var scope = options.scope || this._scope;
    if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
    if (scope) {
      params.scope = 'openid' + this._scopeSeparator + scope;
    } else {
      params.scope = 'openid';
    }
    // TODO: Add support for automatically generating a random state for verification.
    var state = options.state;
    if (state) { params.state = state; }
    // TODO: Implement support for standard OpenID Connect params (display, prompt, etc.)
    
    var location = this._authorizationURL + '?' + querystring.stringify(params);
    this.redirect(location);
  }
}

/**
 * Return extra parameters to be included in the authorization request.
 *
 * Some OpenID Connect providers allow additional, non-standard parameters to be
 * included when requesting authorization.  Since these parameters are not
 * standardized by the OpenID Connect specification, OpenID Connect-based
 * authentication strategies can overrride this function in order to populate
 * these parameters as required by the provider.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function(options) {
  return {};
}

/**
 * Check if should load user profile, contingent upon options.
 *
 * @param {String} issuer
 * @param {String} subject
 * @param {Function} done
 * @api private
 */
Strategy.prototype._shouldLoadUserProfile = function(issuer, subject, done) {
  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(issuer, subject, function(err, skip) {
      if (err) { return done(err); }
      if (!skip) { return done(null, true); }
      return done(null, false);
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile(issuer, subject) : this._skipUserProfile;
    if (!skip) { return done(null, true); }
    return done(null, false);
  }
}


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
