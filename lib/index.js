'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = exec;

var _cryptico = require('cryptico');

var _cryptico2 = _interopRequireDefault(_cryptico);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// TODO: remove dep

/**
 * Just a query string parser.
 * @return {object}
 */
function qs(search) {
  if (!search) return {};

  var params = search.replace(/^\?/, '').split(/&/g);

  return params.reduce(function (previous, current) {
    var pair = current.split('=');
    var key = pair[0];
    var val = pair[1];

    previous[key] = val;

    return previous;
  }, {});
}

/**
 * Executes code if a public/private key pair is present.
 * @param {string} search - Should be value of window.location.search
 * @param {string} publicKey
 * @param {function} cb
 * @return {boolean}
 */
function exec(search, publicKey, sessionStorage, success, failure) {
  var params = qs(search);

  if (!params.privateKey) {
    if (failure) failure(params);

    return false;
  }

  var privateKey = function () {
    var item = sessionStorage.getItem('privateKey');

    return item ? item : _cryptico2.default.generateRSAKey(params.privateKey, 1024);
  }();

  var result = _cryptico2.default.encrypt('seed', publicKey);
  var test = _cryptico2.default.decrypt(result.cipher, privateKey);

  if (test.status === 'failure') {
    if (failure) failure(test);

    return false;
  }

  if (success) success(params.message);

  sessionStorage.setItem('privateKey', privateKey);

  return true;
}

// TODO: override(search, url)

// TODO: inject(content)