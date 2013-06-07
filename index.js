var inspect = require('eyespect').inspector()
var should = require('should')
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
      user.password.should.not.eql(userData.password, 'user password failed to be hashed')
      done()
    })
  })

  it('should register new user then authenticate them', function(done) {
    backend.register(userData, function(err, user) {
      if (err) {
        inspect(err, 'error registering user')
      }
      should.not.exist(err, 'error registering user')
      should.exist(user)
      user.email.should.eql(userData.email, 'user object has incorrect email')
      backend.authenticate(userData, function(err, authenticatedUser) {
        if (err) {
          inspect(err, 'error authenticating user')
        }
        should.not.exist(err, 'error authenticating user')
        should.exist(authenticatedUser)
        authenticatedUser.password.should.not.eql(userData.password, 'user password failed to be hashed')
        authenticatedUser.email.should.eql(userData.email, 'authenticated user has incorrect email')
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
      var newEmail = 'newEmail@example.com'
      newEmail.should.not.eql(userData.email)
      var changeData = {
        email: userData.email,
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
        userWithNewEmail.password.should.not.eql(userData.password, 'user password failed to be hashed')
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

  it('changePassword should be functional', function(done) {
    backend.register(userData, function(err, user) {
      if (err) {
        inspect(err, 'error in register')
      }
      should.not.exist(err, 'error registering user')
      should.exist(user)
      user.email.should.eql(userData.email, 'user object has incorrect email')
      var newPassword = 'newPassword@example.com'
      newPassword.should.not.eql(userData.password)
      var changeData = {
        email: userData.email,
        password: userData.password,
        newPassword: newPassword
      }
      backend.changePassword(changeData, function(err, userWithNewPassword) {
        if (err) {
          inspect(err, 'error in changePassword')
        }
        should.not.exist(err, 'error authenticating user')
        should.exist(userWithNewPassword, 'user object not returned from changePassword')
        userWithNewPassword.password.should.not.eql(newPassword, 'password failed to be hashed in changePassword')
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
            should.exist(err, 'user should not be able to authenticate with old password')
            should.not.exist(authenticatedUser, 'user object should not be returned when authenticate called with old password')
            done()
          })
        })
      })
    })
  })
}
