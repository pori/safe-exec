function qs() {
  let params = window.location.search.split(/&/g);

  return params.reduce((previous, current) {
    let pair = current.split('=');
    let key = pair[0];
    let val = pair[1];

    previous[key] = val;

    return previous;
  }, {});
}

export default function exec(seed, publicKey, cb) {
  let params = qs();
  let privateKey = (function() {
    let item = sessionStorage.getItem('privateKey');

    return (item) ? item : params.privateKey;
  })();
  let cipher = cryptico.encrypt(seed, publicKey);
  let test = cryptico.decrypt(cipher, privateKey);

  if (test.status === 'failure') return false;

  cb(params.message);

  sessionStorage.setItem('privateKey', privateKey);

  return true;
}
