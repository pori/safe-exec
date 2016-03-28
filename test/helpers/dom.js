'use strict';

const jsdom = require('jsdom').jsdom;

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

var window = document.defaultView;

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
