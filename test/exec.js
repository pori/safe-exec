import assert from 'assert';
import cryptico from 'cryptico';
import sessionStorage from 'sessionstorage';
import exec from '../src';

const publicKey = 'pbJgi9aBK+Ohh6Lq5RvQBQXze/94WZv+m9WMWINboE55PLk1TILLQUJ+d2Bb/+52VlPDHlE1qu9qjZSnY0RMbCwb6KyWai+CbYA3kQspztZ0dJVVojhtwSNmlTuPStpM8KOR2Y49jMuTFvCDTh9vnqwPy/KkXJpiUIoaxbKV1Z8=';
const passPhrase = 'how much could a woodchuk chuk';

test('change a script source', function() {
  let victim = document.querySelector('script[src="foobar.js"]');

  assert.equal('foobar.js', victim.getAttribute('src')); // Sanity check

  let search = `?privateKey=${passPhrase}&message=bundle.js`;

  let result = exec(search, publicKey, sessionStorage, (message) => {
    victim.setAttribute('src', message);
  });

  assert.equal(true, result);
  assert.equal('bundle.js', victim.getAttribute('src'));
  assert(sessionStorage.getItem('privateKey'));
});

test('action runs after session start', function() {
  let privateKey = cryptico.generateRSAKey(passPhrase, 1024);

  sessionStorage.setItem('privateKey', privateKey);

  let search = `?message=bundle.js`;

  exec(search, publicKey, sessionStorage, (message) => {
    assert(message);
  });
});

test('fails unobtrusively', function() {
  let result = exec(null, publicKey, sessionStorage);

  assert.equal(false, result);
});

test('fails with feedback', function() {
  var errored = false;

  let result = exec(null, publicKey, sessionStorage, (message) => {
    assert.equal(null, message, 'This never should have been reached!')
  }, (error) => {
    errored = true;
  });

  assert.equal(true, errored, 'There should have been an error.');
});
