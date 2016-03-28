import assert from 'assert';
import exec from '../src';

test('change a script source', function() {
  let victim = document.querySelector('script[src="foobar.js"]');
  let publicKey = 'pbJgi9aBK+Ohh6Lq5RvQBQXze/94WZv+m9WMWINboE55PLk1TILLQUJ+d2Bb/+52VlPDHlE1qu9qjZSnY0RMbCwb6KyWai+CbYA3kQspztZ0dJVVojhtwSNmlTuPStpM8KOR2Y49jMuTFvCDTh9vnqwPy/KkXJpiUIoaxbKV1Z8=';

  assert.equal('foobar.js', victim.getAttribute('src'));

  exec(publicKey, (message) => {
    victim.setAttribute('src', message);
  });

  assert.equal('bundle.js', victim.getAttribute('src'));
});
