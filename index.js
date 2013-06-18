var inspect = require('eyespect').inspector()
var should = require('should')
var assert = require('assert')
module.exports = function(backend, cb) {
  var userData = {
    email: 'foo@example.com',
    password: 'barPassword'
  }
  it('should register new user', function(done) {
    backend.register(userData, function(err, user) {
      if (err) {
        inspect(err, 'error registering user')
      }
      should.not.exist(err)
      should.exist(user)
      user.email.should.eql(userData.email, 'user object has incorrect email')
      should.not.exist(user.password, 'password should never be returned to client')
      assert.ok(!user.confirmed, 'user should not be confirmed after registering')
      should.exist(user.confirmToken, 'confirmToken should be returned in user object after registering')
      done()
    })
  })

  it('should not authenticate unconfirmed user', function(done) {
    backend.register(userData, function(err, user) {
      if (err) {
        inspect(err, 'error registering user')
      }
      should.not.exist(err, 'error registering user')
      should.exist(user)
      user.email.should.eql(userData.email, 'user object has incorrect email')
      backend.authenticate(userData, function(err, authenticatedUser) {
        should.exist(err, 'should get error when trying authenticate unconfirmed user')
        err.reason.should.eql('unconfirmed', 'error reason should be "unconfirmed"')
        done()
      })
    })
  })

  it('should confirm new user', function(done) {
    backend.register(userData, function(err, user) {
      if (err) {
        inspect(err, 'error registering user')
      }
      should.not.exist(err, 'error registering user')
      should.exist(user)
      user.email.should.eql(userData.email, 'user object has incorrect email')
      var confirmData = {
        confirmToken: user.confirmToken
      }
      backend.confirmEmail(confirmData, function(err, confirmedUser) {
        if (err) {
          inspect(err, 'error confirming user')
        }
        should.not.exist(err, 'error confirming user')
        should.exist(confirmedUser, 'user object should be returned when confirmEmail succeeds')
        should.not.exist(confirmedUser.password, 'password should not be returned in user object')
        done()
      })
    })
  })

  it('should authenticate confirmed user', function(done) {
    backend.register(userData, function(err, user) {
      if (err) {
        inspect(err, 'error registering user')
      }
      should.not.exist(err, 'error registering user')
      should.exist(user)
      user.email.should.eql(userData.email, 'user object has incorrect email')
      var confirmData = {
        confirmToken: user.confirmToken
      }
      backend.confirmEmail(confirmData, function(err, confirmedUser) {
        if (err) {
          inspect(err, 'error confirming user')
        }
        should.not.exist(err, 'error confirming user')
        should.exist(confirmedUser, 'user object should be returned when confirmEmail succeeds')
        should.not.exist(confirmedUser.password, 'password should not be returned in user object')
        backend.authenticate(userData, function(err, authenticatedUser) {
          if (err) {
            inspect(err, 'error authenticating user')
          }
          should.not.exist(err, 'authenticate should complete correctly')
          should.exist(authenticatedUser, 'user object should be returned when authenticate succeeds')
          should.not.exist(authenticatedUser.password, 'password should not be returned to client when authenticating user')
          done()
        })
      })
    })
  })

  it('should not confirm email with invalid confirmToken', function(done) {
    backend.register(userData, function(err, user) {
      if (err) {
        inspect(err, 'error registering user')
      }
      should.not.exist(err, 'error registering user')
      should.exist(user)
      user.email.should.eql(userData.email, 'user object has incorrect email')
      var fakeConfirmToken = 'foobar'
      fakeConfirmToken.should.not.eql(user.confirmToken)
      var confirmData = {
        confirmToken: fakeConfirmToken
      }
      backend.confirmEmail(confirmData, function(err, confirmedUser) {
        should.exist(err, 'should get error when confirming user with invalid confirmToken user')
        err.reason.should.eql('token not found')
        should.not.exist(confirmedUser, 'user object should not be returned when confirmEmail fails')
        done()
      })
    })
  })

  it('changeEmail should be functional', function(done) {
    backend.register(userData, function(err, user) {
      if (err) {
        inspect(err, 'error registering user')
      }
      should.not.exist(err, 'error registering user')
      should.exist(user)
      user.email.should.eql(userData.email, 'user object has incorrect email')

      var confirmData = {
        confirmToken: user.confirmToken
      }
      backend.confirmEmail(confirmData, function(err, confirmedUser) {
        if (err) {
          inspect(err, 'error confirming user')
        }
        should.not.exist(err, 'error confirming user')
        should.exist(confirmedUser, 'user object should be returned when confirmEmail succeeds')
        var newEmail = 'newEmail@example.com'
        newEmail.should.not.eql(userData.email)
        var changeData = {
          currentEmail: userData.email,
          newEmail: newEmail
        }
        backend.changeEmail(changeData, function(err, userWithNewEmail) {
          if (err) {
            inspect(err, 'error in changeEmail')
          }
          should.not.exist(err, 'error authenticating user')
          should.exist(userWithNewEmail, 'user object not returned from changeEmail')
          userWithNewEmail.email.should.eql(newEmail, 'user has incorrect email after changeEmail')
          var authData = {
            email: userWithNewEmail.email,
            password: userData.password
          }

          should.not.exist(userWithNewEmail.password, 'password should never be returned to client')
          backend.authenticate(authData, function(err, authenticatedUser) {
            if (err) {
              inspect(err, 'error in authenticate')
            }
            should.not.exist(err, 'error authenticating user with new email')
            should.exist(authenticatedUser, 'user object not returned from authenticate after changing email')
            authenticatedUser.email.should.eql(newEmail, 'user object returned from authenticated has incorrect email')
            done()
          })
        })
      })
    })
  })

  it('changePassword should be functional', function(done) {
    backend.register(userData, function(err, user) {
      if (err) {
        inspect(err, 'error in register')
      }
      should.not.exist(err, 'error registering user')
      should.exist(user)
      user.email.should.eql(userData.email, 'user object has incorrect email')
      var confirmData = {
        confirmToken: user.confirmToken
      }
      backend.confirmEmail(confirmData, function(err, confirmedUser) {
        if (err) {
          inspect(err, 'error confirming user')
        }
        should.not.exist(err, 'error confirming user')
        should.exist(confirmedUser, 'user object should be returned when confirmEmail succeeds')
        var newPassword = 'newPassword@example.com'
        newPassword.should.not.eql(userData.password)
        var changeData = {
          email: userData.email,
          currentPassword: userData.password,
          newPassword: newPassword
        }
        backend.changePassword(changeData, function(err, userWithNewPassword) {
          if (err) {
            inspect(err, 'error in changePassword')
          }
          should.not.exist(err, 'error authenticating user')
          should.exist(userWithNewPassword, 'user object not returned from changePassword')
          should.not.exist(userWithNewPassword.password, 'password should never be returned to client')
          var authData = {
            email: userData.email,
            password: newPassword
          }
          backend.authenticate(authData, function(err, authenticatedUser) {
            if (err) {
              inspect(err, 'error in authenticate')
            }
            should.not.exist(err, 'error authenticating user with new password')
            should.exist(authenticatedUser, 'user object not returned from authenticate after changing password')
            backend.authenticate(userData, function(err, authenticatedUser) {
              should.not.exist(err, 'error trying to authenticate with old password')
              should.not.exist(authenticatedUser, 'user object should not be returned when authenticate called with old password')
              done()
            })
          })
        })
      })
    })
  })
}
