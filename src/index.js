import cryptico from 'cryptico'; // TODO: remove dep

/**
 * Just a query string parser.
 * @return {object}
 */
function qs(search) {
  let params = search.split(/&/g);

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
 * @param {string} search - Should be value of window.location.search
 * @param {string} publicKey
 * @param {function} cb
 * @return {boolean}
 */
export default function exec(search, publicKey, sessionStorage, cb) {
  let params = qs(search);
  let privateKey = (function() {
    let item = sessionStorage.getItem('privateKey');

    return (item) ? item : cryptico.generateRSAKey(params.privateKey, 1024);
  })();
  let result = cryptico.encrypt('seed', publicKey);
  let test = cryptico.decrypt(result.cipher, privateKey);

  if (test.status === 'failure') return false;

  cb(params.message);

  sessionStorage.setItem('privateKey', privateKey);

  return true;
}

// TODO: override(search, url)

// TODO: inject(content)
