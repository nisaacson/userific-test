var testSuite = require('../')
var Userific = require('Userific')
describe('Userific Test Suite', function () {
  var backend = new Userific()

  var password = 'barPassword'
  backend.register = function (userData, cb) {
    userData._id = 'fooUserID'
    return cb(null, userData)
  }

  backend.authenticate = function (userData, cb) {
    userData._id = 'fooUserID'
    return cb(null, userData)
  }
  backend.changePassword = function (userData, cb) {
    userData._id = 'fooUserID'
    return cb(null, userData)
  }
  backend.changeEmail = function (userData, cb) {
    userData.email = userData.newEmail
    return cb(null, userData)
  }
  backend.confirmEmail = function (userData, cb) {
    userData.email = userData.newEmail
    userData.confirmed = true
    return cb(null, userData)
  }
  backend.resetPassword = function (userData, cb) {
    var newPassword = 'fooPassword'
    return cb(null, newPassword)
  }
  testSuite(backend)
})
