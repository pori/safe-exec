import cryptico from 'cryptico';

/**
 * Just a query string parser.
 * @return {object}
 */
function qs() {
  let params = window.location.search.split(/&/g);

  return params.reduce((previous, current) => {
    let pair = current.split('=');
    let key = pair[0];
    let val = pair[1];

    previous[key] = val;

    return previous;
  }, {});
}

/**
 * Executes code if a public/private key pair is present.
 * @param {string} publicKey
 * @param {function} cb
 * @return {boolean}
 */
export default function exec(publicKey, cb) {
  let params = qs();
  let privateKey = (function() {
    let item = sessionStorage.getItem('privateKey');

    return (item) ? item : params.privateKey;
  })();
  let cipher = cryptico.encrypt('seed', publicKey);
  let test = cryptico.decrypt(cipher, privateKey);

  if (test.status === 'failure') return false;

  cb(params.message);

  sessionStorage.setItem('privateKey', privateKey);

  return true;
}
