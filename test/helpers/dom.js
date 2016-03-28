import { jsdom } from 'jsdom';
import cryptico from 'cryptico';

const document = jsdom(`
  <!DOCTYPE html>

  <html>
    <head>
    </head>

    <body>

      <script src="foobar.js"></script>
    </body>
  </html>
  `);

const window = document.defaultView;

const privateKey = rsa.generateRSAKey('how much could a woodchuk chuk', 1024);

window.location.search = `privateKey=${privateKey}&value=bundle.js`;

global.document = document;
global.window = window;

const globalize = (window) =>  {
  for (let key in window) {
    if (!window.hasOwnProperty(key)) continue;
    if (key in global) continue;

    global[key] = window[key];
  }
};

globalize(window);
