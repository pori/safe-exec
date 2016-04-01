/******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};

/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {

/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId])
/******/ 			return installedModules[moduleId].exports;

/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			exports: {},
/******/ 			id: moduleId,
/******/ 			loaded: false
/******/ 		};

/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);

/******/ 		// Flag the module as loaded
/******/ 		module.loaded = true;

/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}


/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;

/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;

/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";

/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(0);
/******/ })
/************************************************************************/
/******/ ([
/* 0 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';

	Object.defineProperty(exports, "__esModule", {
	  value: true
	});
	exports.default = exec;

	var _cryptico = __webpack_require__(1);

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

/***/ },
/* 1 */
/***/ function(module, exports, __webpack_require__) {

	// Copyright (c) 2005  Tom Wu
	// All Rights Reserved.
	// See "LICENSE" for details.
	// Basic JavaScript BN library - subset useful for RSA encryption.

	// Bits per digit
	var dbits;

	// (public) Constructor

	function BigInteger(a, b, c) {
	    if (a != null) if ("number" == typeof a) this.fromNumber(a, b, c);
	    else if (b == null && "string" != typeof a) this.fromString(a, 256);
	    else this.fromString(a, b);
	}

	// return new, unset BigInteger

	function nbi() {
	    return new BigInteger(null);
	}

	// am avoids a big mult-and-extract completely.
	// Max digit bits should be <= 30 because we do bitwise ops
	// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)

	function am(i, x, w, j, c, n) {
	    var xl = x & 0x7fff,
	        xh = x >> 15;
	    while (--n >= 0) {
	        var l = this[i] & 0x7fff;
	        var h = this[i++] >> 15;
	        var m = xh * l + h * xl;
	        l = xl * l + ((m & 0x7fff) << 15) + w[j] + (c & 0x3fffffff);
	        c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30);
	        w[j++] = l & 0x3fffffff;
	    }
	    return c;
	}

	BigInteger.prototype.am = am;
	dbits = 30;

	BigInteger.prototype.DB = dbits;
	BigInteger.prototype.DM = ((1 << dbits) - 1);
	BigInteger.prototype.DV = (1 << dbits);

	var BI_FP = 52;
	BigInteger.prototype.FV = Math.pow(2, BI_FP);
	BigInteger.prototype.F1 = BI_FP - dbits;
	BigInteger.prototype.F2 = 2 * dbits - BI_FP;

	// Digit conversions
	var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
	var BI_RC = new Array();
	var rr, vv;
	rr = "0".charCodeAt(0);
	for (vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
	rr = "a".charCodeAt(0);
	for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
	rr = "A".charCodeAt(0);
	for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

	function int2char(n) {
	    return BI_RM.charAt(n);
	}

	function intAt(s, i) {
	    var c = BI_RC[s.charCodeAt(i)];
	    return (c == null) ? -1 : c;
	}

	// (protected) copy this to r

	function bnpCopyTo(r) {
	    for (var i = this.t - 1; i >= 0; --i) r[i] = this[i];
	    r.t = this.t;
	    r.s = this.s;
	}

	// (protected) set from integer value x, -DV <= x < DV

	function bnpFromInt(x) {
	    this.t = 1;
	    this.s = (x < 0) ? -1 : 0;
	    if (x > 0) this[0] = x;
	    else if (x < -1) this[0] = x + DV;
	    else this.t = 0;
	}

	// return bigint initialized to value

	function nbv(i) {
	    var r = nbi();
	    r.fromInt(i);
	    return r;
	}

	// (protected) set from string and radix

	function bnpFromString(s, b) {
	    var k;
	    if (b == 16) k = 4;
	    else if (b == 8) k = 3;
	    else if (b == 256) k = 8; // byte array
	    else if (b == 2) k = 1;
	    else if (b == 32) k = 5;
	    else if (b == 4) k = 2;
	    else {
	        this.fromRadix(s, b);
	        return;
	    }
	    this.t = 0;
	    this.s = 0;
	    var i = s.length,
	        mi = false,
	        sh = 0;
	    while (--i >= 0) {
	        var x = (k == 8) ? s[i] & 0xff : intAt(s, i);
	        if (x < 0) {
	            if (s.charAt(i) == "-") mi = true;
	            continue;
	        }
	        mi = false;
	        if (sh == 0) this[this.t++] = x;
	        else if (sh + k > this.DB) {
	            this[this.t - 1] |= (x & ((1 << (this.DB - sh)) - 1)) << sh;
	            this[this.t++] = (x >> (this.DB - sh));
	        }
	        else this[this.t - 1] |= x << sh;
	        sh += k;
	        if (sh >= this.DB) sh -= this.DB;
	    }
	    if (k == 8 && (s[0] & 0x80) != 0) {
	        this.s = -1;
	        if (sh > 0) this[this.t - 1] |= ((1 << (this.DB - sh)) - 1) << sh;
	    }
	    this.clamp();
	    if (mi) BigInteger.ZERO.subTo(this, this);
	}

	// (protected) clamp off excess high words

	function bnpClamp() {
	    var c = this.s & this.DM;
	    while (this.t > 0 && this[this.t - 1] == c)--this.t;
	}

	// (public) return string representation in given radix

	function bnToString(b) {
	    if (this.s < 0) return "-" + this.negate().toString(b);
	    var k;
	    if (b == 16) k = 4;
	    else if (b == 8) k = 3;
	    else if (b == 2) k = 1;
	    else if (b == 32) k = 5;
	    else if (b == 64) k = 6;
	    else if (b == 4) k = 2;
	    else return this.toRadix(b);
	    var km = (1 << k) - 1,
	        d, m = false,
	        r = "",
	        i = this.t;
	    var p = this.DB - (i * this.DB) % k;
	    if (i-- > 0) {
	        if (p < this.DB && (d = this[i] >> p) > 0) {
	            m = true;
	            r = int2char(d);
	        }
	        while (i >= 0) {
	            if (p < k) {
	                d = (this[i] & ((1 << p) - 1)) << (k - p);
	                d |= this[--i] >> (p += this.DB - k);
	            }
	            else {
	                d = (this[i] >> (p -= k)) & km;
	                if (p <= 0) {
	                    p += this.DB;
	                    --i;
	                }
	            }
	            if (d > 0) m = true;
	            if (m) r += int2char(d);
	        }
	    }
	    return m ? r : "0";
	}

	// (public) -this

	function bnNegate() {
	    var r = nbi();
	    BigInteger.ZERO.subTo(this, r);
	    return r;
	}

	// (public) |this|

	function bnAbs() {
	    return (this.s < 0) ? this.negate() : this;
	}

	// (public) return + if this > a, - if this < a, 0 if equal

	function bnCompareTo(a) {
	    var r = this.s - a.s;
	    if (r != 0) return r;
	    var i = this.t;
	    r = i - a.t;
	    if (r != 0) return r;
	    while (--i >= 0) if ((r = this[i] - a[i]) != 0) return r;
	    return 0;
	}

	// returns bit length of the integer x

	function nbits(x) {
	    var r = 1,
	        t;
	    if ((t = x >>> 16) != 0) {
	        x = t;
	        r += 16;
	    }
	    if ((t = x >> 8) != 0) {
	        x = t;
	        r += 8;
	    }
	    if ((t = x >> 4) != 0) {
	        x = t;
	        r += 4;
	    }
	    if ((t = x >> 2) != 0) {
	        x = t;
	        r += 2;
	    }
	    if ((t = x >> 1) != 0) {
	        x = t;
	        r += 1;
	    }
	    return r;
	}

	// (public) return the number of bits in "this"

	function bnBitLength() {
	    if (this.t <= 0) return 0;
	    return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ (this.s & this.DM));
	}

	// (protected) r = this << n*DB

	function bnpDLShiftTo(n, r) {
	    var i;
	    for (i = this.t - 1; i >= 0; --i) r[i + n] = this[i];
	    for (i = n - 1; i >= 0; --i) r[i] = 0;
	    r.t = this.t + n;
	    r.s = this.s;
	}

	// (protected) r = this >> n*DB

	function bnpDRShiftTo(n, r) {
	    for (var i = n; i < this.t; ++i) r[i - n] = this[i];
	    r.t = Math.max(this.t - n, 0);
	    r.s = this.s;
	}

	// (protected) r = this << n

	function bnpLShiftTo(n, r) {
	    var bs = n % this.DB;
	    var cbs = this.DB - bs;
	    var bm = (1 << cbs) - 1;
	    var ds = Math.floor(n / this.DB),
	        c = (this.s << bs) & this.DM,
	        i;
	    for (i = this.t - 1; i >= 0; --i) {
	        r[i + ds + 1] = (this[i] >> cbs) | c;
	        c = (this[i] & bm) << bs;
	    }
	    for (i = ds - 1; i >= 0; --i) r[i] = 0;
	    r[ds] = c;
	    r.t = this.t + ds + 1;
	    r.s = this.s;
	    r.clamp();
	}

	// (protected) r = this >> n

	function bnpRShiftTo(n, r) {
	    r.s = this.s;
	    var ds = Math.floor(n / this.DB);
	    if (ds >= this.t) {
	        r.t = 0;
	        return;
	    }
	    var bs = n % this.DB;
	    var cbs = this.DB - bs;
	    var bm = (1 << bs) - 1;
	    r[0] = this[ds] >> bs;
	    for (var i = ds + 1; i < this.t; ++i) {
	        r[i - ds - 1] |= (this[i] & bm) << cbs;
	        r[i - ds] = this[i] >> bs;
	    }
	    if (bs > 0) r[this.t - ds - 1] |= (this.s & bm) << cbs;
	    r.t = this.t - ds;
	    r.clamp();
	}

	// (protected) r = this - a

	function bnpSubTo(a, r) {
	    var i = 0,
	        c = 0,
	        m = Math.min(a.t, this.t);
	    while (i < m) {
	        c += this[i] - a[i];
	        r[i++] = c & this.DM;
	        c >>= this.DB;
	    }
	    if (a.t < this.t) {
	        c -= a.s;
	        while (i < this.t) {
	            c += this[i];
	            r[i++] = c & this.DM;
	            c >>= this.DB;
	        }
	        c += this.s;
	    }
	    else {
	        c += this.s;
	        while (i < a.t) {
	            c -= a[i];
	            r[i++] = c & this.DM;
	            c >>= this.DB;
	        }
	        c -= a.s;
	    }
	    r.s = (c < 0) ? -1 : 0;
	    if (c < -1) r[i++] = this.DV + c;
	    else if (c > 0) r[i++] = c;
	    r.t = i;
	    r.clamp();
	}

	// (protected) r = this * a, r != this,a (HAC 14.12)
	// "this" should be the larger one if appropriate.

	function bnpMultiplyTo(a, r) {
	    var x = this.abs(),
	        y = a.abs();
	    var i = x.t;
	    r.t = i + y.t;
	    while (--i >= 0) r[i] = 0;
	    for (i = 0; i < y.t; ++i) r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
	    r.s = 0;
	    r.clamp();
	    if (this.s != a.s) BigInteger.ZERO.subTo(r, r);
	}

	// (protected) r = this^2, r != this (HAC 14.16)

	function bnpSquareTo(r) {
	    var x = this.abs();
	    var i = r.t = 2 * x.t;
	    while (--i >= 0) r[i] = 0;
	    for (i = 0; i < x.t - 1; ++i) {
	        var c = x.am(i, x[i], r, 2 * i, 0, 1);
	        if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
	            r[i + x.t] -= x.DV;
	            r[i + x.t + 1] = 1;
	        }
	    }
	    if (r.t > 0) r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1);
	    r.s = 0;
	    r.clamp();
	}

	// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
	// r != q, this != m.  q or r may be null.

	function bnpDivRemTo(m, q, r) {
	    var pm = m.abs();
	    if (pm.t <= 0) return;
	    var pt = this.abs();
	    if (pt.t < pm.t) {
	        if (q != null) q.fromInt(0);
	        if (r != null) this.copyTo(r);
	        return;
	    }
	    if (r == null) r = nbi();
	    var y = nbi(),
	        ts = this.s,
	        ms = m.s;
	    var nsh = this.DB - nbits(pm[pm.t - 1]); // normalize modulus
	    if (nsh > 0) {
	        pm.lShiftTo(nsh, y);
	        pt.lShiftTo(nsh, r);
	    }
	    else {
	        pm.copyTo(y);
	        pt.copyTo(r);
	    }
	    var ys = y.t;
	    var y0 = y[ys - 1];
	    if (y0 == 0) return;
	    var yt = y0 * (1 << this.F1) + ((ys > 1) ? y[ys - 2] >> this.F2 : 0);
	    var d1 = this.FV / yt,
	        d2 = (1 << this.F1) / yt,
	        e = 1 << this.F2;
	    var i = r.t,
	        j = i - ys,
	        t = (q == null) ? nbi() : q;
	    y.dlShiftTo(j, t);
	    if (r.compareTo(t) >= 0) {
	        r[r.t++] = 1;
	        r.subTo(t, r);
	    }
	    BigInteger.ONE.dlShiftTo(ys, t);
	    t.subTo(y, y); // "negative" y so we can replace sub with am later
	    while (y.t < ys) y[y.t++] = 0;
	    while (--j >= 0) {
	        // Estimate quotient digit
	        var qd = (r[--i] == y0) ? this.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
	        if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) { // Try it out
	            y.dlShiftTo(j, t);
	            r.subTo(t, r);
	            while (r[i] < --qd) r.subTo(t, r);
	        }
	    }
	    if (q != null) {
	        r.drShiftTo(ys, q);
	        if (ts != ms) BigInteger.ZERO.subTo(q, q);
	    }
	    r.t = ys;
	    r.clamp();
	    if (nsh > 0) r.rShiftTo(nsh, r); // Denormalize remainder
	    if (ts < 0) BigInteger.ZERO.subTo(r, r);
	}

	// (public) this mod a

	function bnMod(a) {
	    var r = nbi();
	    this.abs().divRemTo(a, null, r);
	    if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r, r);
	    return r;
	}

	// Modular reduction using "classic" algorithm

	function Classic(m) {
	    this.m = m;
	}

	function cConvert(x) {
	    if (x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
	    else return x;
	}

	function cRevert(x) {
	    return x;
	}

	function cReduce(x) {
	    x.divRemTo(this.m, null, x);
	}

	function cMulTo(x, y, r) {
	    x.multiplyTo(y, r);
	    this.reduce(r);
	}

	function cSqrTo(x, r) {
	    x.squareTo(r);
	    this.reduce(r);
	}

	Classic.prototype.convert = cConvert;
	Classic.prototype.revert = cRevert;
	Classic.prototype.reduce = cReduce;
	Classic.prototype.mulTo = cMulTo;
	Classic.prototype.sqrTo = cSqrTo;

	// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
	// justification:
	//         xy == 1 (mod m)
	//         xy =  1+km
	//   xy(2-xy) = (1+km)(1-km)
	// x[y(2-xy)] = 1-k^2m^2
	// x[y(2-xy)] == 1 (mod m^2)
	// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
	// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
	// JS multiply "overflows" differently from C/C++, so care is needed here.

	function bnpInvDigit() {
	    if (this.t < 1) return 0;
	    var x = this[0];
	    if ((x & 1) == 0) return 0;
	    var y = x & 3; // y == 1/x mod 2^2
	    y = (y * (2 - (x & 0xf) * y)) & 0xf; // y == 1/x mod 2^4
	    y = (y * (2 - (x & 0xff) * y)) & 0xff; // y == 1/x mod 2^8
	    y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff; // y == 1/x mod 2^16
	    // last step - calculate inverse mod DV directly;
	    // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
	    y = (y * (2 - x * y % this.DV)) % this.DV; // y == 1/x mod 2^dbits
	    // we really want the negative inverse, and -DV < y < DV
	    return (y > 0) ? this.DV - y : -y;
	}

	// Montgomery reduction

	function Montgomery(m) {
	    this.m = m;
	    this.mp = m.invDigit();
	    this.mpl = this.mp & 0x7fff;
	    this.mph = this.mp >> 15;
	    this.um = (1 << (m.DB - 15)) - 1;
	    this.mt2 = 2 * m.t;
	}

	// xR mod m

	function montConvert(x) {
	    var r = nbi();
	    x.abs().dlShiftTo(this.m.t, r);
	    r.divRemTo(this.m, null, r);
	    if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r, r);
	    return r;
	}

	// x/R mod m

	function montRevert(x) {
	    var r = nbi();
	    x.copyTo(r);
	    this.reduce(r);
	    return r;
	}

	// x = x/R mod m (HAC 14.32)

	function montReduce(x) {
	    while (x.t <= this.mt2) // pad x so am has enough room later
	    x[x.t++] = 0;
	    for (var i = 0; i < this.m.t; ++i) {
	        // faster way of calculating u0 = x[i]*mp mod DV
	        var j = x[i] & 0x7fff;
	        var u0 = (j * this.mpl + (((j * this.mph + (x[i] >> 15) * this.mpl) & this.um) << 15)) & x.DM;
	        // use am to combine the multiply-shift-add into one call
	        j = i + this.m.t;
	        x[j] += this.m.am(0, u0, x, i, 0, this.m.t);
	        // propagate carry
	        while (x[j] >= x.DV) {
	            x[j] -= x.DV;
	            x[++j]++;
	        }
	    }
	    x.clamp();
	    x.drShiftTo(this.m.t, x);
	    if (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
	}

	// r = "x^2/R mod m"; x != r

	function montSqrTo(x, r) {
	    x.squareTo(r);
	    this.reduce(r);
	}

	// r = "xy/R mod m"; x,y != r

	function montMulTo(x, y, r) {
	    x.multiplyTo(y, r);
	    this.reduce(r);
	}

	Montgomery.prototype.convert = montConvert;
	Montgomery.prototype.revert = montRevert;
	Montgomery.prototype.reduce = montReduce;
	Montgomery.prototype.mulTo = montMulTo;
	Montgomery.prototype.sqrTo = montSqrTo;

	// (protected) true iff this is even

	function bnpIsEven() {
	    return ((this.t > 0) ? (this[0] & 1) : this.s) == 0;
	}

	// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)

	function bnpExp(e, z) {
	    if (e > 0xffffffff || e < 1) return BigInteger.ONE;
	    var r = nbi(),
	        r2 = nbi(),
	        g = z.convert(this),
	        i = nbits(e) - 1;
	    g.copyTo(r);
	    while (--i >= 0) {
	        z.sqrTo(r, r2);
	        if ((e & (1 << i)) > 0) z.mulTo(r2, g, r);
	        else {
	            var t = r;
	            r = r2;
	            r2 = t;
	        }
	    }
	    return z.revert(r);
	}

	// (public) this^e % m, 0 <= e < 2^32

	function bnModPowInt(e, m) {
	    var z;
	    if (e < 256 || m.isEven()) z = new Classic(m);
	    else z = new Montgomery(m);
	    return this.exp(e, z);
	}

	// protected
	BigInteger.prototype.copyTo = bnpCopyTo;
	BigInteger.prototype.fromInt = bnpFromInt;
	BigInteger.prototype.fromString = bnpFromString;
	BigInteger.prototype.clamp = bnpClamp;
	BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
	BigInteger.prototype.drShiftTo = bnpDRShiftTo;
	BigInteger.prototype.lShiftTo = bnpLShiftTo;
	BigInteger.prototype.rShiftTo = bnpRShiftTo;
	BigInteger.prototype.subTo = bnpSubTo;
	BigInteger.prototype.multiplyTo = bnpMultiplyTo;
	BigInteger.prototype.squareTo = bnpSquareTo;
	BigInteger.prototype.divRemTo = bnpDivRemTo;
	BigInteger.prototype.invDigit = bnpInvDigit;
	BigInteger.prototype.isEven = bnpIsEven;
	BigInteger.prototype.exp = bnpExp;

	// public
	BigInteger.prototype.toString = bnToString;
	BigInteger.prototype.negate = bnNegate;
	BigInteger.prototype.abs = bnAbs;
	BigInteger.prototype.compareTo = bnCompareTo;
	BigInteger.prototype.bitLength = bnBitLength;
	BigInteger.prototype.mod = bnMod;
	BigInteger.prototype.modPowInt = bnModPowInt;

	// "constants"
	BigInteger.ZERO = nbv(0);
	BigInteger.ONE = nbv(1);


	function bnClone() {
	    var r = nbi();
	    this.copyTo(r);
	    return r;
	}

	// (public) return value as integer

	function bnIntValue() {
	    if (this.s < 0) {
	        if (this.t == 1) return this[0] - this.DV;
	        else if (this.t == 0) return -1;
	    }
	    else if (this.t == 1) return this[0];
	    else if (this.t == 0) return 0;
	    // assumes 16 < DB < 32
	    return ((this[1] & ((1 << (32 - this.DB)) - 1)) << this.DB) | this[0];
	}

	// (public) return value as byte

	function bnByteValue() {
	    return (this.t == 0) ? this.s : (this[0] << 24) >> 24;
	}

	// (public) return value as short (assumes DB>=16)

	function bnShortValue() {
	    return (this.t == 0) ? this.s : (this[0] << 16) >> 16;
	}

	// (protected) return x s.t. r^x < DV

	function bnpChunkSize(r) {
	    return Math.floor(Math.LN2 * this.DB / Math.log(r));
	}

	// (public) 0 if this == 0, 1 if this > 0

	function bnSigNum() {
	    if (this.s < 0) return -1;
	    else if (this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
	    else return 1;
	}

	// (protected) convert to radix string

	function bnpToRadix(b) {
	    if (b == null) b = 10;
	    if (this.signum() == 0 || b < 2 || b > 36) return "0";
	    var cs = this.chunkSize(b);
	    var a = Math.pow(b, cs);
	    var d = nbv(a),
	        y = nbi(),
	        z = nbi(),
	        r = "";
	    this.divRemTo(d, y, z);
	    while (y.signum() > 0) {
	        r = (a + z.intValue()).toString(b).substr(1) + r;
	        y.divRemTo(d, y, z);
	    }
	    return z.intValue().toString(b) + r;
	}

	// (protected) convert from radix string

	function bnpFromRadix(s, b) {
	    this.fromInt(0);
	    if (b == null) b = 10;
	    var cs = this.chunkSize(b);
	    var d = Math.pow(b, cs),
	        mi = false,
	        j = 0,
	        w = 0;
	    for (var i = 0; i < s.length; ++i) {
	        var x = intAt(s, i);
	        if (x < 0) {
	            if (s.charAt(i) == "-" && this.signum() == 0) mi = true;
	            continue;
	        }
	        w = b * w + x;
	        if (++j >= cs) {
	            this.dMultiply(d);
	            this.dAddOffset(w, 0);
	            j = 0;
	            w = 0;
	        }
	    }
	    if (j > 0) {
	        this.dMultiply(Math.pow(b, j));
	        this.dAddOffset(w, 0);
	    }
	    if (mi) BigInteger.ZERO.subTo(this, this);
	}

	// (protected) alternate constructor

	function bnpFromNumber(a, b, c) {
	    if ("number" == typeof b) {
	        // new BigInteger(int,int,RNG)
	        if (a < 2) this.fromInt(1);
	        else {
	            this.fromNumber(a, c);
	            if (!this.testBit(a - 1)) // force MSB set
	            this.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, this);
	            if (this.isEven()) this.dAddOffset(1, 0); // force odd
	            while (!this.isProbablePrime(b)) {
	                this.dAddOffset(2, 0);
	                if (this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a - 1), this);
	            }
	        }
	    }
	    else {
	        // new BigInteger(int,RNG)
	        var x = new Array(),
	            t = a & 7;
	        x.length = (a >> 3) + 1;
	        b.nextBytes(x);
	        if (t > 0) x[0] &= ((1 << t) - 1);
	        else x[0] = 0;
	        this.fromString(x, 256);
	    }
	}

	// (public) convert to bigendian byte array

	function bnToByteArray() {
	    var i = this.t,
	        r = new Array();
	    r[0] = this.s;
	    var p = this.DB - (i * this.DB) % 8,
	        d, k = 0;
	    if (i-- > 0) {
	        if (p < this.DB && (d = this[i] >> p) != (this.s & this.DM) >> p) r[k++] = d | (this.s << (this.DB - p));
	        while (i >= 0) {
	            if (p < 8) {
	                d = (this[i] & ((1 << p) - 1)) << (8 - p);
	                d |= this[--i] >> (p += this.DB - 8);
	            }
	            else {
	                d = (this[i] >> (p -= 8)) & 0xff;
	                if (p <= 0) {
	                    p += this.DB;
	                    --i;
	                }
	            }
	            if ((d & 0x80) != 0) d |= -256;
	            if (k == 0 && (this.s & 0x80) != (d & 0x80))++k;
	            if (k > 0 || d != this.s) r[k++] = d;
	        }
	    }
	    return r;
	}

	function bnEquals(a) {
	    return (this.compareTo(a) == 0);
	}

	function bnMin(a) {
	    return (this.compareTo(a) < 0) ? this : a;
	}

	function bnMax(a) {
	    return (this.compareTo(a) > 0) ? this : a;
	}

	// (protected) r = this op a (bitwise)

	function bnpBitwiseTo(a, op, r) {
	    var i, f, m = Math.min(a.t, this.t);
	    for (i = 0; i < m; ++i) r[i] = op(this[i], a[i]);
	    if (a.t < this.t) {
	        f = a.s & this.DM;
	        for (i = m; i < this.t; ++i) r[i] = op(this[i], f);
	        r.t = this.t;
	    }
	    else {
	        f = this.s & this.DM;
	        for (i = m; i < a.t; ++i) r[i] = op(f, a[i]);
	        r.t = a.t;
	    }
	    r.s = op(this.s, a.s);
	    r.clamp();
	}

	// (public) this & a

	function op_and(x, y) {
	    return x & y;
	}

	function bnAnd(a) {
	    var r = nbi();
	    this.bitwiseTo(a, op_and, r);
	    return r;
	}

	// (public) this | a

	function op_or(x, y) {
	    return x | y;
	}

	function bnOr(a) {
	    var r = nbi();
	    this.bitwiseTo(a, op_or, r);
	    return r;
	}

	// (public) this ^ a

	function op_xor(x, y) {
	    return x ^ y;
	}

	function bnXor(a) {
	    var r = nbi();
	    this.bitwiseTo(a, op_xor, r);
	    return r;
	}

	// (public) this & ~a

	function op_andnot(x, y) {
	    return x & ~y;
	}

	function bnAndNot(a) {
	    var r = nbi();
	    this.bitwiseTo(a, op_andnot, r);
	    return r;
	}

	// (public) ~this

	function bnNot() {
	    var r = nbi();
	    for (var i = 0; i < this.t; ++i) r[i] = this.DM & ~this[i];
	    r.t = this.t;
	    r.s = ~this.s;
	    return r;
	}

	// (public) this << n

	function bnShiftLeft(n) {
	    var r = nbi();
	    if (n < 0) this.rShiftTo(-n, r);
	    else this.lShiftTo(n, r);
	    return r;
	}

	// (public) this >> n

	function bnShiftRight(n) {
	    var r = nbi();
	    if (n < 0) this.lShiftTo(-n, r);
	    else this.rShiftTo(n, r);
	    return r;
	}

	// return index of lowest 1-bit in x, x < 2^31

	function lbit(x) {
	    if (x == 0) return -1;
	    var r = 0;
	    if ((x & 0xffff) == 0) {
	        x >>= 16;
	        r += 16;
	    }
	    if ((x & 0xff) == 0) {
	        x >>= 8;
	        r += 8;
	    }
	    if ((x & 0xf) == 0) {
	        x >>= 4;
	        r += 4;
	    }
	    if ((x & 3) == 0) {
	        x >>= 2;
	        r += 2;
	    }
	    if ((x & 1) == 0)++r;
	    return r;
	}

	// (public) returns index of lowest 1-bit (or -1 if none)

	function bnGetLowestSetBit() {
	    for (var i = 0; i < this.t; ++i)
	    if (this[i] != 0) return i * this.DB + lbit(this[i]);
	    if (this.s < 0) return this.t * this.DB;
	    return -1;
	}

	// return number of 1 bits in x

	function cbit(x) {
	    var r = 0;
	    while (x != 0) {
	        x &= x - 1;
	        ++r;
	    }
	    return r;
	}

	// (public) return number of set bits

	function bnBitCount() {
	    var r = 0,
	        x = this.s & this.DM;
	    for (var i = 0; i < this.t; ++i) r += cbit(this[i] ^ x);
	    return r;
	}

	// (public) true iff nth bit is set

	function bnTestBit(n) {
	    var j = Math.floor(n / this.DB);
	    if (j >= this.t) return (this.s != 0);
	    return ((this[j] & (1 << (n % this.DB))) != 0);
	}

	// (protected) this op (1<<n)

	function bnpChangeBit(n, op) {
	    var r = BigInteger.ONE.shiftLeft(n);
	    this.bitwiseTo(r, op, r);
	    return r;
	}

	// (public) this | (1<<n)

	function bnSetBit(n) {
	    return this.changeBit(n, op_or);
	}

	// (public) this & ~(1<<n)

	function bnClearBit(n) {
	    return this.changeBit(n, op_andnot);
	}

	// (public) this ^ (1<<n)

	function bnFlipBit(n) {
	    return this.changeBit(n, op_xor);
	}

	// (protected) r = this + a

	function bnpAddTo(a, r) {
	    var i = 0,
	        c = 0,
	        m = Math.min(a.t, this.t);
	    while (i < m) {
	        c += this[i] + a[i];
	        r[i++] = c & this.DM;
	        c >>= this.DB;
	    }
	    if (a.t < this.t) {
	        c += a.s;
	        while (i < this.t) {
	            c += this[i];
	            r[i++] = c & this.DM;
	            c >>= this.DB;
	        }
	        c += this.s;
	    }
	    else {
	        c += this.s;
	        while (i < a.t) {
	            c += a[i];
	            r[i++] = c & this.DM;
	            c >>= this.DB;
	        }
	        c += a.s;
	    }
	    r.s = (c < 0) ? -1 : 0;
	    if (c > 0) r[i++] = c;
	    else if (c < -1) r[i++] = this.DV + c;
	    r.t = i;
	    r.clamp();
	}

	// (public) this + a

	function bnAdd(a) {
	    var r = nbi();
	    this.addTo(a, r);
	    return r;
	}

	// (public) this - a

	function bnSubtract(a) {
	    var r = nbi();
	    this.subTo(a, r);
	    return r;
	}

	// (public) this * a

	function bnMultiply(a) {
	    var r = nbi();
	    this.multiplyTo(a, r);
	    return r;
	}

	// (public) this^2

	function bnSquare() {
	    var r = nbi();
	    this.squareTo(r);
	    return r;
	}

	// (public) this / a

	function bnDivide(a) {
	    var r = nbi();
	    this.divRemTo(a, r, null);
	    return r;
	}

	// (public) this % a

	function bnRemainder(a) {
	    var r = nbi();
	    this.divRemTo(a, null, r);
	    return r;
	}

	// (public) [this/a,this%a]

	function bnDivideAndRemainder(a) {
	    var q = nbi(),
	        r = nbi();
	    this.divRemTo(a, q, r);
	    return new Array(q, r);
	}

	// (protected) this *= n, this >= 0, 1 < n < DV

	function bnpDMultiply(n) {
	    this[this.t] = this.am(0, n - 1, this, 0, 0, this.t);
	    ++this.t;
	    this.clamp();
	}

	// (protected) this += n << w words, this >= 0

	function bnpDAddOffset(n, w) {
	    if (n == 0) return;
	    while (this.t <= w) this[this.t++] = 0;
	    this[w] += n;
	    while (this[w] >= this.DV) {
	        this[w] -= this.DV;
	        if (++w >= this.t) this[this.t++] = 0;
	        ++this[w];
	    }
	}

	// A "null" reducer

	function NullExp() {}

	function nNop(x) {
	    return x;
	}

	function nMulTo(x, y, r) {
	    x.multiplyTo(y, r);
	}

	function nSqrTo(x, r) {
	    x.squareTo(r);
	}

	NullExp.prototype.convert = nNop;
	NullExp.prototype.revert = nNop;
	NullExp.prototype.mulTo = nMulTo;
	NullExp.prototype.sqrTo = nSqrTo;

	// (public) this^e

	function bnPow(e) {
	    return this.exp(e, new NullExp());
	}

	// (protected) r = lower n words of "this * a", a.t <= n
	// "this" should be the larger one if appropriate.

	function bnpMultiplyLowerTo(a, n, r) {
	    var i = Math.min(this.t + a.t, n);
	    r.s = 0; // assumes a,this >= 0
	    r.t = i;
	    while (i > 0) r[--i] = 0;
	    var j;
	    for (j = r.t - this.t; i < j; ++i) r[i + this.t] = this.am(0, a[i], r, i, 0, this.t);
	    for (j = Math.min(a.t, n); i < j; ++i) this.am(0, a[i], r, i, 0, n - i);
	    r.clamp();
	}

	// (protected) r = "this * a" without lower n words, n > 0
	// "this" should be the larger one if appropriate.

	function bnpMultiplyUpperTo(a, n, r) {
	    --n;
	    var i = r.t = this.t + a.t - n;
	    r.s = 0; // assumes a,this >= 0
	    while (--i >= 0) r[i] = 0;
	    for (i = Math.max(n - this.t, 0); i < a.t; ++i)
	    r[this.t + i - n] = this.am(n - i, a[i], r, 0, 0, this.t + i - n);
	    r.clamp();
	    r.drShiftTo(1, r);
	}

	// Barrett modular reduction

	function Barrett(m) {
	    // setup Barrett
	    this.r2 = nbi();
	    this.q3 = nbi();
	    BigInteger.ONE.dlShiftTo(2 * m.t, this.r2);
	    this.mu = this.r2.divide(m);
	    this.m = m;
	}

	function barrettConvert(x) {
	    if (x.s < 0 || x.t > 2 * this.m.t) return x.mod(this.m);
	    else if (x.compareTo(this.m) < 0) return x;
	    else {
	        var r = nbi();
	        x.copyTo(r);
	        this.reduce(r);
	        return r;
	    }
	}

	function barrettRevert(x) {
	    return x;
	}

	// x = x mod m (HAC 14.42)

	function barrettReduce(x) {
	    x.drShiftTo(this.m.t - 1, this.r2);
	    if (x.t > this.m.t + 1) {
	        x.t = this.m.t + 1;
	        x.clamp();
	    }
	    this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
	    this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
	    while (x.compareTo(this.r2) < 0) x.dAddOffset(1, this.m.t + 1);
	    x.subTo(this.r2, x);
	    while (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
	}

	// r = x^2 mod m; x != r

	function barrettSqrTo(x, r) {
	    x.squareTo(r);
	    this.reduce(r);
	}

	// r = x*y mod m; x,y != r

	function barrettMulTo(x, y, r) {
	    x.multiplyTo(y, r);
	    this.reduce(r);
	}

	Barrett.prototype.convert = barrettConvert;
	Barrett.prototype.revert = barrettRevert;
	Barrett.prototype.reduce = barrettReduce;
	Barrett.prototype.mulTo = barrettMulTo;
	Barrett.prototype.sqrTo = barrettSqrTo;

	// (public) this^e % m (HAC 14.85)

	function bnModPow(e, m) {
	    var i = e.bitLength(),
	        k, r = nbv(1),
	        z;
	    if (i <= 0) return r;
	    else if (i < 18) k = 1;
	    else if (i < 48) k = 3;
	    else if (i < 144) k = 4;
	    else if (i < 768) k = 5;
	    else k = 6;
	    if (i < 8) z = new Classic(m);
	    else if (m.isEven()) z = new Barrett(m);
	    else z = new Montgomery(m);

	    // precomputation
	    var g = new Array(),
	        n = 3,
	        k1 = k - 1,
	        km = (1 << k) - 1;
	    g[1] = z.convert(this);
	    if (k > 1) {
	        var g2 = nbi();
	        z.sqrTo(g[1], g2);
	        while (n <= km) {
	            g[n] = nbi();
	            z.mulTo(g2, g[n - 2], g[n]);
	            n += 2;
	        }
	    }

	    var j = e.t - 1,
	        w, is1 = true,
	        r2 = nbi(),
	        t;
	    i = nbits(e[j]) - 1;
	    while (j >= 0) {
	        if (i >= k1) w = (e[j] >> (i - k1)) & km;
	        else {
	            w = (e[j] & ((1 << (i + 1)) - 1)) << (k1 - i);
	            if (j > 0) w |= e[j - 1] >> (this.DB + i - k1);
	        }

	        n = k;
	        while ((w & 1) == 0) {
	            w >>= 1;
	            --n;
	        }
	        if ((i -= n) < 0) {
	            i += this.DB;
	            --j;
	        }
	        if (is1) { // ret == 1, don't bother squaring or multiplying it
	            g[w].copyTo(r);
	            is1 = false;
	        }
	        else {
	            while (n > 1) {
	                z.sqrTo(r, r2);
	                z.sqrTo(r2, r);
	                n -= 2;
	            }
	            if (n > 0) z.sqrTo(r, r2);
	            else {
	                t = r;
	                r = r2;
	                r2 = t;
	            }
	            z.mulTo(r2, g[w], r);
	        }

	        while (j >= 0 && (e[j] & (1 << i)) == 0) {
	            z.sqrTo(r, r2);
	            t = r;
	            r = r2;
	            r2 = t;
	            if (--i < 0) {
	                i = this.DB - 1;
	                --j;
	            }
	        }
	    }
	    return z.revert(r);
	}

	// (public) gcd(this,a) (HAC 14.54)

	function bnGCD(a) {
	    var x = (this.s < 0) ? this.negate() : this.clone();
	    var y = (a.s < 0) ? a.negate() : a.clone();
	    if (x.compareTo(y) < 0) {
	        var t = x;
	        x = y;
	        y = t;
	    }
	    var i = x.getLowestSetBit(),
	        g = y.getLowestSetBit();
	    if (g < 0) return x;
	    if (i < g) g = i;
	    if (g > 0) {
	        x.rShiftTo(g, x);
	        y.rShiftTo(g, y);
	    }
	    while (x.signum() > 0) {
	        if ((i = x.getLowestSetBit()) > 0) x.rShiftTo(i, x);
	        if ((i = y.getLowestSetBit()) > 0) y.rShiftTo(i, y);
	        if (x.compareTo(y) >= 0) {
	            x.subTo(y, x);
	            x.rShiftTo(1, x);
	        }
	        else {
	            y.subTo(x, y);
	            y.rShiftTo(1, y);
	        }
	    }
	    if (g > 0) y.lShiftTo(g, y);
	    return y;
	}

	// (protected) this % n, n < 2^26

	function bnpModInt(n) {
	    if (n <= 0) return 0;
	    var d = this.DV % n,
	        r = (this.s < 0) ? n - 1 : 0;
	    if (this.t > 0) if (d == 0) r = this[0] % n;
	    else for (var i = this.t - 1; i >= 0; --i) r = (d * r + this[i]) % n;
	    return r;
	}

	// (public) 1/this % m (HAC 14.61)

	function bnModInverse(m) {
	    var ac = m.isEven();
	    if ((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
	    var u = m.clone(),
	        v = this.clone();
	    var a = nbv(1),
	        b = nbv(0),
	        c = nbv(0),
	        d = nbv(1);
	    while (u.signum() != 0) {
	        while (u.isEven()) {
	            u.rShiftTo(1, u);
	            if (ac) {
	                if (!a.isEven() || !b.isEven()) {
	                    a.addTo(this, a);
	                    b.subTo(m, b);
	                }
	                a.rShiftTo(1, a);
	            }
	            else if (!b.isEven()) b.subTo(m, b);
	            b.rShiftTo(1, b);
	        }
	        while (v.isEven()) {
	            v.rShiftTo(1, v);
	            if (ac) {
	                if (!c.isEven() || !d.isEven()) {
	                    c.addTo(this, c);
	                    d.subTo(m, d);
	                }
	                c.rShiftTo(1, c);
	            }
	            else if (!d.isEven()) d.subTo(m, d);
	            d.rShiftTo(1, d);
	        }
	        if (u.compareTo(v) >= 0) {
	            u.subTo(v, u);
	            if (ac) a.subTo(c, a);
	            b.subTo(d, b);
	        }
	        else {
	            v.subTo(u, v);
	            if (ac) c.subTo(a, c);
	            d.subTo(b, d);
	        }
	    }
	    if (v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
	    if (d.compareTo(m) >= 0) return d.subtract(m);
	    if (d.signum() < 0) d.addTo(m, d);
	    else return d;
	    if (d.signum() < 0) return d.add(m);
	    else return d;
	}

	var lowprimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997];
	var lplim = (1 << 26) / lowprimes[lowprimes.length - 1];

	// (public) test primality with certainty >= 1-.5^t

	function bnIsProbablePrime(t) {
	    var i, x = this.abs();
	    if (x.t == 1 && x[0] <= lowprimes[lowprimes.length - 1]) {
	        for (i = 0; i < lowprimes.length; ++i)
	        if (x[0] == lowprimes[i]) return true;
	        return false;
	    }
	    if (x.isEven()) return false;
	    i = 1;
	    while (i < lowprimes.length) {
	        var m = lowprimes[i],
	            j = i + 1;
	        while (j < lowprimes.length && m < lplim) m *= lowprimes[j++];
	        m = x.modInt(m);
	        while (i < j) if (m % lowprimes[i++] == 0) return false;
	    }
	    return x.millerRabin(t);
	}

	// (protected) true if probably prime (HAC 4.24, Miller-Rabin)

	function bnpMillerRabin(t) {
	    var n1 = this.subtract(BigInteger.ONE);
	    var k = n1.getLowestSetBit();
	    if (k <= 0) return false;
	    var r = n1.shiftRight(k);
	    t = (t + 1) >> 1;
	    if (t > lowprimes.length) t = lowprimes.length;
	    var a = nbi();
	    for (var i = 0; i < t; ++i) {
	        //Pick bases at random, instead of starting at 2
	        a.fromInt(lowprimes[Math.floor(Math.random() * lowprimes.length)]);
	        var y = a.modPow(r, this);
	        if (y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
	            var j = 1;
	            while (j++ < k && y.compareTo(n1) != 0) {
	                y = y.modPowInt(2, this);
	                if (y.compareTo(BigInteger.ONE) == 0) return false;
	            }
	            if (y.compareTo(n1) != 0) return false;
	        }
	    }
	    return true;
	}

	// protected
	BigInteger.prototype.chunkSize = bnpChunkSize;
	BigInteger.prototype.toRadix = bnpToRadix;
	BigInteger.prototype.fromRadix = bnpFromRadix;
	BigInteger.prototype.fromNumber = bnpFromNumber;
	BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
	BigInteger.prototype.changeBit = bnpChangeBit;
	BigInteger.prototype.addTo = bnpAddTo;
	BigInteger.prototype.dMultiply = bnpDMultiply;
	BigInteger.prototype.dAddOffset = bnpDAddOffset;
	BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
	BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
	BigInteger.prototype.modInt = bnpModInt;
	BigInteger.prototype.millerRabin = bnpMillerRabin;

	// public
	BigInteger.prototype.clone = bnClone;
	BigInteger.prototype.intValue = bnIntValue;
	BigInteger.prototype.byteValue = bnByteValue;
	BigInteger.prototype.shortValue = bnShortValue;
	BigInteger.prototype.signum = bnSigNum;
	BigInteger.prototype.toByteArray = bnToByteArray;
	BigInteger.prototype.equals = bnEquals;
	BigInteger.prototype.min = bnMin;
	BigInteger.prototype.max = bnMax;
	BigInteger.prototype.and = bnAnd;
	BigInteger.prototype.or = bnOr;
	BigInteger.prototype.xor = bnXor;
	BigInteger.prototype.andNot = bnAndNot;
	BigInteger.prototype.not = bnNot;
	BigInteger.prototype.shiftLeft = bnShiftLeft;
	BigInteger.prototype.shiftRight = bnShiftRight;
	BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
	BigInteger.prototype.bitCount = bnBitCount;
	BigInteger.prototype.testBit = bnTestBit;
	BigInteger.prototype.setBit = bnSetBit;
	BigInteger.prototype.clearBit = bnClearBit;
	BigInteger.prototype.flipBit = bnFlipBit;
	BigInteger.prototype.add = bnAdd;
	BigInteger.prototype.subtract = bnSubtract;
	BigInteger.prototype.multiply = bnMultiply;
	BigInteger.prototype.divide = bnDivide;
	BigInteger.prototype.remainder = bnRemainder;
	BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
	BigInteger.prototype.modPow = bnModPow;
	BigInteger.prototype.modInverse = bnModInverse;
	BigInteger.prototype.pow = bnPow;
	BigInteger.prototype.gcd = bnGCD;
	BigInteger.prototype.isProbablePrime = bnIsProbablePrime;

	// JSBN-specific extension
	BigInteger.prototype.square = bnSquare;// seedrandom.js version 2.0.
	// Author: David Bau 4/2/2011
	//
	// Defines a method Math.seedrandom() that, when called, substitutes
	// an explicitly seeded RC4-based algorithm for Math.random().  Also
	// supports automatic seeding from local or network sources of entropy.
	//
	// Usage:
	//
	//   <script src=http://davidbau.com/encode/seedrandom-min.js></script>
	//
	//   Math.seedrandom('yipee'); Sets Math.random to a function that is
	//                             initialized using the given explicit seed.
	//
	//   Math.seedrandom();        Sets Math.random to a function that is
	//                             seeded using the current time, dom state,
	//                             and other accumulated local entropy.
	//                             The generated seed string is returned.
	//
	//   Math.seedrandom('yowza', true);
	//                             Seeds using the given explicit seed mixed
	//                             together with accumulated entropy.
	//
	//   <script src="http://bit.ly/srandom-512"></script>
	//                             Seeds using physical random bits downloaded
	//                             from random.org.
	//
	//   <script src="https://jsonlib.appspot.com/urandom?callback=Math.seedrandom">
	//   </script>                 Seeds using urandom bits from call.jsonlib.com,
	//                             which is faster than random.org.
	//
	// Examples:
	//
	//   Math.seedrandom("hello");            // Use "hello" as the seed.
	//   document.write(Math.random());       // Always 0.5463663768140734
	//   document.write(Math.random());       // Always 0.43973793770592234
	//   var rng1 = Math.random;              // Remember the current prng.
	//
	//   var autoseed = Math.seedrandom();    // New prng with an automatic seed.
	//   document.write(Math.random());       // Pretty much unpredictable.
	//
	//   Math.random = rng1;                  // Continue "hello" prng sequence.
	//   document.write(Math.random());       // Always 0.554769432473455
	//
	//   Math.seedrandom(autoseed);           // Restart at the previous seed.
	//   document.write(Math.random());       // Repeat the 'unpredictable' value.
	//
	// Notes:
	//
	// Each time seedrandom('arg') is called, entropy from the passed seed
	// is accumulated in a pool to help generate future seeds for the
	// zero-argument form of Math.seedrandom, so entropy can be injected over
	// time by calling seedrandom with explicit data repeatedly.
	//
	// On speed - This javascript implementation of Math.random() is about
	// 3-10x slower than the built-in Math.random() because it is not native
	// code, but this is typically fast enough anyway.  Seeding is more expensive,
	// especially if you use auto-seeding.  Some details (timings on Chrome 4):
	//
	// Our Math.random()            - avg less than 0.002 milliseconds per call
	// seedrandom('explicit')       - avg less than 0.5 milliseconds per call
	// seedrandom('explicit', true) - avg less than 2 milliseconds per call
	// seedrandom()                 - avg about 38 milliseconds per call
	//
	// LICENSE (BSD):
	//
	// Copyright 2010 David Bau, all rights reserved.
	//
	// Redistribution and use in source and binary forms, with or without
	// modification, are permitted provided that the following conditions are met:
	// 
	//   1. Redistributions of source code must retain the above copyright
	//      notice, this list of conditions and the following disclaimer.
	//
	//   2. Redistributions in binary form must reproduce the above copyright
	//      notice, this list of conditions and the following disclaimer in the
	//      documentation and/or other materials provided with the distribution.
	// 
	//   3. Neither the name of this module nor the names of its contributors may
	//      be used to endorse or promote products derived from this software
	//      without specific prior written permission.
	// 
	// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
	// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
	// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
	// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
	// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
	// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
	// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
	// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
	// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
	// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
	//
	/**
	 * All code is in an anonymous closure to keep the global namespace clean.
	 *
	 * @param {number=} overflow 
	 * @param {number=} startdenom
	 */
	(function (pool, math, width, chunks, significance, overflow, startdenom)
	{


	    //
	    // seedrandom()
	    // This is the seedrandom function described above.
	    //
	    math['seedrandom'] = function seedrandom(seed, use_entropy)
	    {
	        var key = [];
	        var arc4;

	        // Flatten the seed string or build one from local entropy if needed.
	        seed = mixkey(flatten(
	        use_entropy ? [seed, pool] : arguments.length ? seed : [new Date().getTime(), pool], 3), key);

	        // Use the seed to initialize an ARC4 generator.
	        arc4 = new ARC4(key);

	        // Mix the randomness into accumulated entropy.
	        mixkey(arc4.S, pool);

	        // Override Math.random
	        // This function returns a random double in [0, 1) that contains
	        // randomness in every bit of the mantissa of the IEEE 754 value.
	        math['random'] = function random()
	        { // Closure to return a random double:
	            var n = arc4.g(chunks); // Start with a numerator n < 2 ^ 48
	            var d = startdenom; //   and denominator d = 2 ^ 48.
	            var x = 0; //   and no 'extra last byte'.
	            while (n < significance)
	            { // Fill up all significant digits by
	                n = (n + x) * width; //   shifting numerator and
	                d *= width; //   denominator and generating a
	                x = arc4.g(1); //   new least-significant-byte.
	            }
	            while (n >= overflow)
	            { // To avoid rounding up, before adding
	                n /= 2; //   last byte, shift everything
	                d /= 2; //   right using integer math until
	                x >>>= 1; //   we have exactly the desired bits.
	            }
	            return (n + x) / d; // Form the number within [0, 1).
	        };

	        // Return the seed that was used
	        return seed;
	    };

	    //
	    // ARC4
	    //
	    // An ARC4 implementation.  The constructor takes a key in the form of
	    // an array of at most (width) integers that should be 0 <= x < (width).
	    //
	    // The g(count) method returns a pseudorandom integer that concatenates
	    // the next (count) outputs from ARC4.  Its return value is a number x
	    // that is in the range 0 <= x < (width ^ count).
	    //
	    /** @constructor */

	    function ARC4(key)
	    {
	        var t, u, me = this,
	            keylen = key.length;
	        var i = 0,
	            j = me.i = me.j = me.m = 0;
	        me.S = [];
	        me.c = [];

	        // The empty key [] is treated as [0].
	        if (!keylen)
	        {
	            key = [keylen++];
	        }

	        // Set up S using the standard key scheduling algorithm.
	        while (i < width)
	        {
	            me.S[i] = i++;
	        }
	        for (i = 0; i < width; i++)
	        {
	            t = me.S[i];
	            j = lowbits(j + t + key[i % keylen]);
	            u = me.S[j];
	            me.S[i] = u;
	            me.S[j] = t;
	        }

	        // The "g" method returns the next (count) outputs as one number.
	        me.g = function getnext(count)
	        {
	            var s = me.S;
	            var i = lowbits(me.i + 1);
	            var t = s[i];
	            var j = lowbits(me.j + t);
	            var u = s[j];
	            s[i] = u;
	            s[j] = t;
	            var r = s[lowbits(t + u)];
	            while (--count)
	            {
	                i = lowbits(i + 1);
	                t = s[i];
	                j = lowbits(j + t);
	                u = s[j];
	                s[i] = u;
	                s[j] = t;
	                r = r * width + s[lowbits(t + u)];
	            }
	            me.i = i;
	            me.j = j;
	            return r;
	        };
	        // For robust unpredictability discard an initial batch of values.
	        // See http://www.rsa.com/rsalabs/node.asp?id=2009
	        me.g(width);
	    }

	    //
	    // flatten()
	    // Converts an object tree to nested arrays of strings.
	    //
	    /** @param {Object=} result 
	     * @param {string=} prop
	     * @param {string=} typ */

	    function flatten(obj, depth, result, prop, typ)
	    {
	        result = [];
	        typ = typeof (obj);
	        if (depth && typ == 'object')
	        {
	            for (prop in obj)
	            {
	                if (prop.indexOf('S') < 5)
	                { // Avoid FF3 bug (local/sessionStorage)
	                    try
	                    {
	                        result.push(flatten(obj[prop], depth - 1));
	                    }
	                    catch (e)
	                    {}
	                }
	            }
	        }
	        return (result.length ? result : obj + (typ != 'string' ? '\0' : ''));
	    }

	    //
	    // mixkey()
	    // Mixes a string seed into a key that is an array of integers, and
	    // returns a shortened string seed that is equivalent to the result key.
	    //
	    /** @param {number=} smear 
	     * @param {number=} j */

	    function mixkey(seed, key, smear, j)
	    {
	        seed += ''; // Ensure the seed is a string
	        smear = 0;
	        for (j = 0; j < seed.length; j++)
	        {
	            key[lowbits(j)] = lowbits((smear ^= key[lowbits(j)] * 19) + seed.charCodeAt(j));
	        }
	        seed = '';
	        for (j in key)
	        {
	            seed += String.fromCharCode(key[j]);
	        }
	        return seed;
	    }

	    //
	    // lowbits()
	    // A quick "n mod width" for width a power of 2.
	    //


	    function lowbits(n)
	    {
	        return n & (width - 1);
	    }

	    //
	    // The following constants are related to IEEE 754 limits.
	    //
	    startdenom = math.pow(width, chunks);
	    significance = math.pow(2, significance);
	    overflow = significance * 2;

	    //
	    // When seedrandom.js is loaded, we immediately mix a few bits
	    // from the built-in RNG into the entropy pool.  Because we do
	    // not want to intefere with determinstic PRNG state later,
	    // seedrandom will not call math.random on its own again after
	    // initialization.
	    //
	    mixkey(math.random(), pool);

	    // End anonymous scope, and pass initial values.
	})([], // pool: entropy pool starts empty
	Math, // math: package containing random, pow, and seedrandom
	256, // width: each RC4 output is 0 <= x < 256
	6, // chunks: at least six RC4 outputs for each double
	52 // significance: there are 52 significant digits in a double
	);


	// This is not really a random number generator object, and two SeededRandom
	// objects will conflict with one another, but it's good enough for generating 
	// the rsa key.
	function SeededRandom(){}

	function SRnextBytes(ba)
	{
	    var i;
	    for(i = 0; i < ba.length; i++)
	    {
	        ba[i] = Math.floor(Math.random() * 256);
	    }
	}

	SeededRandom.prototype.nextBytes = SRnextBytes;

	// prng4.js - uses Arcfour as a PRNG

	function Arcfour() {
	  this.i = 0;
	  this.j = 0;
	  this.S = new Array();
	}

	// Initialize arcfour context from key, an array of ints, each from [0..255]
	function ARC4init(key) {
	  var i, j, t;
	  for(i = 0; i < 256; ++i)
	    this.S[i] = i;
	  j = 0;
	  for(i = 0; i < 256; ++i) {
	    j = (j + this.S[i] + key[i % key.length]) & 255;
	    t = this.S[i];
	    this.S[i] = this.S[j];
	    this.S[j] = t;
	  }
	  this.i = 0;
	  this.j = 0;
	}

	function ARC4next() {
	  var t;
	  this.i = (this.i + 1) & 255;
	  this.j = (this.j + this.S[this.i]) & 255;
	  t = this.S[this.i];
	  this.S[this.i] = this.S[this.j];
	  this.S[this.j] = t;
	  return this.S[(t + this.S[this.i]) & 255];
	}

	Arcfour.prototype.init = ARC4init;
	Arcfour.prototype.next = ARC4next;

	// Plug in your RNG constructor here
	function prng_newstate() {
	  return new Arcfour();
	}

	// Pool size must be a multiple of 4 and greater than 32.
	// An array of bytes the size of the pool will be passed to init()
	var rng_psize = 256;

	// Random number generator - requires a PRNG backend, e.g. prng4.js

	// For best results, put code like
	// <body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
	// in your main HTML document.

	var rng_state;
	var rng_pool;
	var rng_pptr;

	// Mix in a 32-bit integer into the pool
	function rng_seed_int(x) {
	  rng_pool[rng_pptr++] ^= x & 255;
	  rng_pool[rng_pptr++] ^= (x >> 8) & 255;
	  rng_pool[rng_pptr++] ^= (x >> 16) & 255;
	  rng_pool[rng_pptr++] ^= (x >> 24) & 255;
	  if(rng_pptr >= rng_psize) rng_pptr -= rng_psize;
	}

	// Mix in the current time (w/milliseconds) into the pool
	function rng_seed_time() {
	  rng_seed_int(new Date().getTime());
	}

	// Initialize the pool with junk if needed.
	if(rng_pool == null) {
	  rng_pool = new Array();
	  rng_pptr = 0;
	  var t;
	  while(rng_pptr < rng_psize) {  // extract some randomness from Math.random()
	    t = Math.floor(65536 * Math.random());
	    rng_pool[rng_pptr++] = t >>> 8;
	    rng_pool[rng_pptr++] = t & 255;
	  }
	  rng_pptr = 0;
	  rng_seed_time();
	  //rng_seed_int(window.screenX);
	  //rng_seed_int(window.screenY);
	}

	function rng_get_byte() {
	  if(rng_state == null) {
	    rng_seed_time();
	    rng_state = prng_newstate();
	    rng_state.init(rng_pool);
	    for(rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
	      rng_pool[rng_pptr] = 0;
	    rng_pptr = 0;
	    //rng_pool = null;
	  }
	  // TODO: allow reseeding after first request
	  return rng_state.next();
	}

	function rng_get_bytes(ba) {
	  var i;
	  for(i = 0; i < ba.length; ++i) ba[i] = rng_get_byte();
	}

	function SecureRandom() {}

	SecureRandom.prototype.nextBytes = rng_get_bytes;/**
	*
	*  Secure Hash Algorithm (SHA256)
	*  http://www.webtoolkit.info/
	*
	*  Original code by Angel Marin, Paul Johnston.
	*
	**/

	var crypto = __webpack_require__(2);
	 
	function SHA256(s){
		return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
	}

	var sha256 = {}
	sha256.hex = function(s)
	{
	    return SHA256(s);
	}

	/**
	*
	*  Secure Hash Algorithm (SHA1)
	*  http://www.webtoolkit.info/
	*
	**/
	 
	function SHA1 (msg) {
		return crypto.createHash('sha1').update(msg, 'utf8').digest('hex'); 
	}

	var sha1 = {}
	sha1.hex = function(s)
	{
	    return SHA1(s);
	}

	/**
	*
	*  MD5 (Message-Digest Algorithm)
	*  http://www.webtoolkit.info/
	*
	**/
	 
	var MD5 = function (string) {
		return crypto.createHash('md5').update(string, 'utf8').digest('hex');
	}// Depends on jsbn.js and rng.js
	// Version 1.1: support utf-8 encoding in pkcs1pad2
	// convert a (hex) string to a bignum object


	function parseBigInt(str, r)
	{
	    return new BigInteger(str, r);
	}

	function linebrk(s, n)
	{
	    var ret = "";
	    var i = 0;
	    while (i + n < s.length)
	    {
	        ret += s.substring(i, i + n) + "\n";
	        i += n;
	    }
	    return ret + s.substring(i, s.length);
	}

	function byte2Hex(b)
	{
	    if (b < 0x10) return "0" + b.toString(16);
	    else return b.toString(16);
	}

	// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint


	function pkcs1pad2(s, n)
	{
	    if (n < s.length + 11)
	    { // TODO: fix for utf-8
	        //alert("Message too long for RSA (n=" + n + ", l=" + s.length + ")");
	        //return null;
	        throw "Message too long for RSA (n=" + n + ", l=" + s.length + ")";
	    }
	    var ba = new Array();
	    var i = s.length - 1;
	    while (i >= 0 && n > 0)
	    {
	        var c = s.charCodeAt(i--);
	        if (c < 128)
	        { // encode using utf-8
	            ba[--n] = c;
	        }
	        else if ((c > 127) && (c < 2048))
	        {
	            ba[--n] = (c & 63) | 128;
	            ba[--n] = (c >> 6) | 192;
	        }
	        else
	        {
	            ba[--n] = (c & 63) | 128;
	            ba[--n] = ((c >> 6) & 63) | 128;
	            ba[--n] = (c >> 12) | 224;
	        }
	    }
	    ba[--n] = 0;
	    var rng = new SecureRandom();
	    var x = new Array();
	    while (n > 2)
	    { // random non-zero pad
	        x[0] = 0;
	        while (x[0] == 0) rng.nextBytes(x);
	        ba[--n] = x[0];
	    }
	    ba[--n] = 2;
	    ba[--n] = 0;
	    return new BigInteger(ba);
	}

	// "empty" RSA key constructor


	function RSAKey()
	{
	    this.n = null;
	    this.e = 0;
	    this.d = null;
	    this.p = null;
	    this.q = null;
	    this.dmp1 = null;
	    this.dmq1 = null;
	    this.coeff = null;
	}
	// Set the public key fields N and e from hex strings


	function RSASetPublic(N, E)
	{
	    if (N != null && E != null && N.length > 0 && E.length > 0)
	    {
	        this.n = parseBigInt(N, 16);
	        this.e = parseInt(E, 16);
	    }
	    else alert("Invalid RSA public key");
	}

	// Perform raw public operation on "x": return x^e (mod n)


	function RSADoPublic(x)
	{
	    return x.modPowInt(this.e, this.n);
	}

	// Return the PKCS#1 RSA encryption of "text" as an even-length hex string


	function RSAEncrypt(text)
	{
	    var m = pkcs1pad2(text, (this.n.bitLength() + 7) >> 3);
	    if (m == null) return null;
	    var c = this.doPublic(m);
	    if (c == null) return null;
	    var h = c.toString(16);
	    if ((h.length & 1) == 0) return h;
	    else return "0" + h;
	}

	function RSAToJSON()
	{
	    return {
	        coeff: this.coeff.toString(16),
	        d: this.d.toString(16),
	        dmp1: this.dmp1.toString(16),
	        dmq1: this.dmq1.toString(16),
	        e: this.e.toString(16),
	        n: this.n.toString(16),
	        p: this.p.toString(16),
	        q: this.q.toString(16),
	    }
	}

	function RSAParse(rsaString) {
	    var json = JSON.parse(rsaString);
	    var rsa = new RSAKey();

	    rsa.setPrivateEx(json.n, json.e, json.d, json.p, json.q, json.dmp1, json.dmq1, json.coeff);

	    return rsa;
	}

	// Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
	//function RSAEncryptB64(text) {
	//  var h = this.encrypt(text);
	//  if(h) return hex2b64(h); else return null;
	//}
	// protected
	RSAKey.prototype.doPublic = RSADoPublic;

	// public
	RSAKey.prototype.setPublic = RSASetPublic;
	RSAKey.prototype.encrypt = RSAEncrypt;
	RSAKey.prototype.toJSON = RSAToJSON;
	RSAKey.parse = RSAParse;

	// Version 1.1: support utf-8 decoding in pkcs1unpad2
	// Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext

	function pkcs1unpad2(d, n)
	{
	    var b = d.toByteArray();
	    var i = 0;
	    while (i < b.length && b[i] == 0)++i;
	    if (b.length - i != n - 1 || b[i] != 2) return null;
	    ++i;
	    while (b[i] != 0)
	    if (++i >= b.length) return null;
	    var ret = "";
	    while (++i < b.length)
	    {
	        var c = b[i] & 255;
	        if (c < 128)
	        { // utf-8 decode
	            ret += String.fromCharCode(c);
	        }
	        else if ((c > 191) && (c < 224))
	        {
	            ret += String.fromCharCode(((c & 31) << 6) | (b[i + 1] & 63));
	            ++i;
	        }
	        else
	        {
	            ret += String.fromCharCode(((c & 15) << 12) | ((b[i + 1] & 63) << 6) | (b[i + 2] & 63));
	            i += 2;
	        }
	    }
	    return ret;
	}

	// Set the private key fields N, e, and d from hex strings
	function RSASetPrivate(N, E, D)
	{
	    if (N != null && E != null && N.length > 0 && E.length > 0)
	    {
	        this.n = parseBigInt(N, 16);
	        this.e = parseInt(E, 16);
	        this.d = parseBigInt(D, 16);
	    }
	    else alert("Invalid RSA private key");
	}

	// Set the private key fields N, e, d and CRT params from hex strings
	function RSASetPrivateEx(N, E, D, P, Q, DP, DQ, C)
	{
	    if (N != null && E != null && N.length > 0 && E.length > 0)
	    {
	        this.n = parseBigInt(N, 16);
	        this.e = parseInt(E, 16);
	        this.d = parseBigInt(D, 16);
	        this.p = parseBigInt(P, 16);
	        this.q = parseBigInt(Q, 16);
	        this.dmp1 = parseBigInt(DP, 16);
	        this.dmq1 = parseBigInt(DQ, 16);
	        this.coeff = parseBigInt(C, 16);
	    }
	    else alert("Invalid RSA private key");
	}

	// Generate a new random private key B bits long, using public expt E
	function RSAGenerate(B, E)
	{
	    var rng = new SeededRandom();
	    var qs = B >> 1;
	    this.e = parseInt(E, 16);
	    var ee = new BigInteger(E, 16);
	    for (;;)
	    {
	        for (;;)
	        {
	            this.p = new BigInteger(B - qs, 1, rng);
	            if (this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.p.isProbablePrime(10)) break;
	        }
	        for (;;)
	        {
	            this.q = new BigInteger(qs, 1, rng);
	            if (this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.q.isProbablePrime(10)) break;
	        }
	        if (this.p.compareTo(this.q) <= 0)
	        {
	            var t = this.p;
	            this.p = this.q;
	            this.q = t;
	        }
	        var p1 = this.p.subtract(BigInteger.ONE);
	        var q1 = this.q.subtract(BigInteger.ONE);
	        var phi = p1.multiply(q1);
	        if (phi.gcd(ee).compareTo(BigInteger.ONE) == 0)
	        {
	            this.n = this.p.multiply(this.q);
	            this.d = ee.modInverse(phi);
	            this.dmp1 = this.d.mod(p1);
	            this.dmq1 = this.d.mod(q1);
	            this.coeff = this.q.modInverse(this.p);
	            break;
	        }
	    }
	}

	// Perform raw private operation on "x": return x^d (mod n)
	function RSADoPrivate(x)
	{
	    if (this.p == null || this.q == null) return x.modPow(this.d, this.n);
	    // TODO: re-calculate any missing CRT params
	    var xp = x.mod(this.p).modPow(this.dmp1, this.p);
	    var xq = x.mod(this.q).modPow(this.dmq1, this.q);
	    while (xp.compareTo(xq) < 0)
	    xp = xp.add(this.p);
	    return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
	}

	// Return the PKCS#1 RSA decryption of "ctext".
	// "ctext" is an even-length hex string and the output is a plain string.
	function RSADecrypt(ctext)
	{
	    var c = parseBigInt(ctext, 16);
	    var m = this.doPrivate(c);
	    if (m == null) return null;
	    return pkcs1unpad2(m, (this.n.bitLength() + 7) >> 3);
	}

	// protected
	RSAKey.prototype.doPrivate = RSADoPrivate;

	// public
	RSAKey.prototype.setPrivate = RSASetPrivate;
	RSAKey.prototype.setPrivateEx = RSASetPrivateEx;
	RSAKey.prototype.generate = RSAGenerate;
	RSAKey.prototype.decrypt = RSADecrypt;


	//
	// rsa-sign.js - adding signing functions to RSAKey class.
	//
	//
	// version: 1.0 (2010-Jun-03)
	//
	// Copyright (c) 2010 Kenji Urushima (kenji.urushima@gmail.com)
	//
	// This software is licensed under the terms of the MIT License.
	// http://www.opensource.org/licenses/mit-license.php
	//
	// The above copyright and license notice shall be 
	// included in all copies or substantial portions of the Software.
	//
	// Depends on:
	//   function sha1.hex(s) of sha1.js
	//   jsbn.js
	//   jsbn2.js
	//   rsa.js
	//   rsa2.js
	//
	// keysize / pmstrlen
	//  512 /  128
	// 1024 /  256
	// 2048 /  512
	// 4096 / 1024
	// As for _RSASGIN_DIHEAD values for each hash algorithm, see PKCS#1 v2.1 spec (p38).
	var _RSASIGN_DIHEAD = [];
	_RSASIGN_DIHEAD['sha1'] = "3021300906052b0e03021a05000414";
	_RSASIGN_DIHEAD['sha256'] = "3031300d060960864801650304020105000420";
	//_RSASIGN_DIHEAD['md2'] = "3020300c06082a864886f70d020205000410";
	//_RSASIGN_DIHEAD['md5'] = "3020300c06082a864886f70d020505000410";
	//_RSASIGN_DIHEAD['sha384'] = "3041300d060960864801650304020205000430";
	//_RSASIGN_DIHEAD['sha512'] = "3051300d060960864801650304020305000440";
	var _RSASIGN_HASHHEXFUNC = [];
	_RSASIGN_HASHHEXFUNC['sha1'] = sha1.hex;
	_RSASIGN_HASHHEXFUNC['sha256'] = sha256.hex;

	// ========================================================================
	// Signature Generation
	// ========================================================================

	function _rsasign_getHexPaddedDigestInfoForString(s, keySize, hashAlg)
	{
	    var pmStrLen = keySize / 4;
	    var hashFunc = _RSASIGN_HASHHEXFUNC[hashAlg];
	    var sHashHex = hashFunc(s);

	    var sHead = "0001";
	    var sTail = "00" + _RSASIGN_DIHEAD[hashAlg] + sHashHex;
	    var sMid = "";
	    var fLen = pmStrLen - sHead.length - sTail.length;
	    for (var i = 0; i < fLen; i += 2)
	    {
	        sMid += "ff";
	    }
	    sPaddedMessageHex = sHead + sMid + sTail;
	    return sPaddedMessageHex;
	}

	function _rsasign_signString(s, hashAlg)
	{
	    var hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), hashAlg);
	    var biPaddedMessage = parseBigInt(hPM, 16);
	    var biSign = this.doPrivate(biPaddedMessage);
	    var hexSign = biSign.toString(16);
	    return hexSign;
	}

	function _rsasign_signStringWithSHA1(s)
	{
	    var hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), 'sha1');
	    var biPaddedMessage = parseBigInt(hPM, 16);
	    var biSign = this.doPrivate(biPaddedMessage);
	    var hexSign = biSign.toString(16);
	    return hexSign;
	}

	function _rsasign_signStringWithSHA256(s)
	{
	    var hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), 'sha256');
	    var biPaddedMessage = parseBigInt(hPM, 16);
	    var biSign = this.doPrivate(biPaddedMessage);
	    var hexSign = biSign.toString(16);
	    return hexSign;
	}

	// ========================================================================
	// Signature Verification
	// ========================================================================

	function _rsasign_getDecryptSignatureBI(biSig, hN, hE)
	{
	    var rsa = new RSAKey();
	    rsa.setPublic(hN, hE);
	    var biDecryptedSig = rsa.doPublic(biSig);
	    return biDecryptedSig;
	}

	function _rsasign_getHexDigestInfoFromSig(biSig, hN, hE)
	{
	    var biDecryptedSig = _rsasign_getDecryptSignatureBI(biSig, hN, hE);
	    var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
	    return hDigestInfo;
	}

	function _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo)
	{
	    for (var algName in _RSASIGN_DIHEAD)
	    {
	        var head = _RSASIGN_DIHEAD[algName];
	        var len = head.length;
	        if (hDigestInfo.substring(0, len) == head)
	        {
	            var a = [algName, hDigestInfo.substring(len)];
	            return a;
	        }
	    }
	    return [];
	}

	function _rsasign_verifySignatureWithArgs(sMsg, biSig, hN, hE)
	{
	    var hDigestInfo = _rsasign_getHexDigestInfoFromSig(biSig, hN, hE);
	    var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
	    if (digestInfoAry.length == 0) return false;
	    var algName = digestInfoAry[0];
	    var diHashValue = digestInfoAry[1];
	    var ff = _RSASIGN_HASHHEXFUNC[algName];
	    var msgHashValue = ff(sMsg);
	    return (diHashValue == msgHashValue);
	}

	function _rsasign_verifyHexSignatureForMessage(hSig, sMsg)
	{
	    var biSig = parseBigInt(hSig, 16);
	    var result = _rsasign_verifySignatureWithArgs(sMsg, biSig, this.n.toString(16), this.e.toString(16));
	    return result;
	}

	function _rsasign_verifyString(sMsg, hSig)
	{
	    hSig = hSig.replace(/[ \n]+/g, "");
	    var biSig = parseBigInt(hSig, 16);
	    var biDecryptedSig = this.doPublic(biSig);
	    var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
	    var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);

	    if (digestInfoAry.length == 0) return false;
	    var algName = digestInfoAry[0];
	    var diHashValue = digestInfoAry[1];
	    var ff = _RSASIGN_HASHHEXFUNC[algName];
	    var msgHashValue = ff(sMsg);
	    return (diHashValue == msgHashValue);
	}

	RSAKey.prototype.signString = _rsasign_signString;
	RSAKey.prototype.signStringWithSHA1 = _rsasign_signStringWithSHA1;
	RSAKey.prototype.signStringWithSHA256 = _rsasign_signStringWithSHA256;

	RSAKey.prototype.verifyString = _rsasign_verifyString;
	RSAKey.prototype.verifyHexSignatureForMessage = _rsasign_verifyHexSignatureForMessage;



























	/*
	 *  jsaes version 0.1  -  Copyright 2006 B. Poettering
	 *
	 *  This program is free software; you can redistribute it and/or
	 *  modify it under the terms of the GNU General Public License as
	 *  published by the Free Software Foundation; either version 2 of the
	 *  License, or (at your option) any later version.
	 *
	 *  This program is distributed in the hope that it will be useful,
	 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
	 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	 *  General Public License for more details.
	 *
	 *  You should have received a copy of the GNU General Public License
	 *  along with this program; if not, write to the Free Software
	 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
	 *  02111-1307 USA
	 */
	 
	 // later modifications by wwwtyro@github
	 
	var aes = (function () {

	    var my = {};

	    my.Sbox = new Array(99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22);

	    my.ShiftRowTab = new Array(0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11);

	    my.Init = function () {
	        my.Sbox_Inv = new Array(256);
	        for (var i = 0; i < 256; i++)
	        my.Sbox_Inv[my.Sbox[i]] = i;

	        my.ShiftRowTab_Inv = new Array(16);
	        for (var i = 0; i < 16; i++)
	        my.ShiftRowTab_Inv[my.ShiftRowTab[i]] = i;

	        my.xtime = new Array(256);
	        for (var i = 0; i < 128; i++) {
	            my.xtime[i] = i << 1;
	            my.xtime[128 + i] = (i << 1) ^ 0x1b;
	        }
	    }

	    my.Done = function () {
	        delete my.Sbox_Inv;
	        delete my.ShiftRowTab_Inv;
	        delete my.xtime;
	    }

	    my.ExpandKey = function (key) {
	        var kl = key.length,
	            ks, Rcon = 1;
	        switch (kl) {
	        case 16:
	            ks = 16 * (10 + 1);
	            break;
	        case 24:
	            ks = 16 * (12 + 1);
	            break;
	        case 32:
	            ks = 16 * (14 + 1);
	            break;
	        default:
	            alert("my.ExpandKey: Only key lengths of 16, 24 or 32 bytes allowed!");
	        }
	        for (var i = kl; i < ks; i += 4) {
	            var temp = key.slice(i - 4, i);
	            if (i % kl == 0) {
	                temp = new Array(my.Sbox[temp[1]] ^ Rcon, my.Sbox[temp[2]], my.Sbox[temp[3]], my.Sbox[temp[0]]);
	                if ((Rcon <<= 1) >= 256) Rcon ^= 0x11b;
	            }
	            else if ((kl > 24) && (i % kl == 16)) temp = new Array(my.Sbox[temp[0]], my.Sbox[temp[1]], my.Sbox[temp[2]], my.Sbox[temp[3]]);
	            for (var j = 0; j < 4; j++)
	            key[i + j] = key[i + j - kl] ^ temp[j];
	        }
	    }

	    my.Encrypt = function (block, key) {
	        var l = key.length;
	        my.AddRoundKey(block, key.slice(0, 16));
	        for (var i = 16; i < l - 16; i += 16) {
	            my.SubBytes(block, my.Sbox);
	            my.ShiftRows(block, my.ShiftRowTab);
	            my.MixColumns(block);
	            my.AddRoundKey(block, key.slice(i, i + 16));
	        }
	        my.SubBytes(block, my.Sbox);
	        my.ShiftRows(block, my.ShiftRowTab);
	        my.AddRoundKey(block, key.slice(i, l));
	    }

	    my.Decrypt = function (block, key) {
	        var l = key.length;
	        my.AddRoundKey(block, key.slice(l - 16, l));
	        my.ShiftRows(block, my.ShiftRowTab_Inv);
	        my.SubBytes(block, my.Sbox_Inv);
	        for (var i = l - 32; i >= 16; i -= 16) {
	            my.AddRoundKey(block, key.slice(i, i + 16));
	            my.MixColumns_Inv(block);
	            my.ShiftRows(block, my.ShiftRowTab_Inv);
	            my.SubBytes(block, my.Sbox_Inv);
	        }
	        my.AddRoundKey(block, key.slice(0, 16));
	    }

	    my.SubBytes = function (state, sbox) {
	        for (var i = 0; i < 16; i++)
	        state[i] = sbox[state[i]];
	    }

	    my.AddRoundKey = function (state, rkey) {
	        for (var i = 0; i < 16; i++)
	        state[i] ^= rkey[i];
	    }

	    my.ShiftRows = function (state, shifttab) {
	        var h = new Array().concat(state);
	        for (var i = 0; i < 16; i++)
	        state[i] = h[shifttab[i]];
	    }

	    my.MixColumns = function (state) {
	        for (var i = 0; i < 16; i += 4) {
	            var s0 = state[i + 0],
	                s1 = state[i + 1];
	            var s2 = state[i + 2],
	                s3 = state[i + 3];
	            var h = s0 ^ s1 ^ s2 ^ s3;
	            state[i + 0] ^= h ^ my.xtime[s0 ^ s1];
	            state[i + 1] ^= h ^ my.xtime[s1 ^ s2];
	            state[i + 2] ^= h ^ my.xtime[s2 ^ s3];
	            state[i + 3] ^= h ^ my.xtime[s3 ^ s0];
	        }
	    }

	    my.MixColumns_Inv = function (state) {
	        for (var i = 0; i < 16; i += 4) {
	            var s0 = state[i + 0],
	                s1 = state[i + 1];
	            var s2 = state[i + 2],
	                s3 = state[i + 3];
	            var h = s0 ^ s1 ^ s2 ^ s3;
	            var xh = my.xtime[h];
	            var h1 = my.xtime[my.xtime[xh ^ s0 ^ s2]] ^ h;
	            var h2 = my.xtime[my.xtime[xh ^ s1 ^ s3]] ^ h;
	            state[i + 0] ^= h1 ^ my.xtime[s0 ^ s1];
	            state[i + 1] ^= h2 ^ my.xtime[s1 ^ s2];
	            state[i + 2] ^= h1 ^ my.xtime[s2 ^ s3];
	            state[i + 3] ^= h2 ^ my.xtime[s3 ^ s0];
	        }
	    }

	    return my;

	}());var cryptico = module.exports = (function() {

	    var my = {};

	    aes.Init();

	    var base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

	    my.b256to64 = function(t) {
	        var a, c, n;
	        var r = '', l = 0, s = 0;
	        var tl = t.length;
	        for (n = 0; n < tl; n++)
	        {
	            c = t.charCodeAt(n);
	            if (s == 0)
	            {
	                r += base64Chars.charAt((c >> 2) & 63);
	                a = (c & 3) << 4;
	            }
	            else if (s == 1)
	            {
	                r += base64Chars.charAt((a | (c >> 4) & 15));
	                a = (c & 15) << 2;
	            }
	            else if (s == 2)
	            {
	                r += base64Chars.charAt(a | ((c >> 6) & 3));
	                l += 1;
	                r += base64Chars.charAt(c & 63);
	            }
	            l += 1;
	            s += 1;
	            if (s == 3) s = 0;
	        }
	        if (s > 0)
	        {
	            r += base64Chars.charAt(a);
	            l += 1;
	            r += '=';
	            l += 1;
	        }
	        if (s == 1)
	        {
	            r += '=';
	        }
	        return r;
	    }

	    my.b64to256 = function(t) 
	    {
	        var c, n;
	        var r = '', s = 0, a = 0;
	        var tl = t.length;
	        for (n = 0; n < tl; n++)
	        {
	            c = base64Chars.indexOf(t.charAt(n));
	            if (c >= 0)
	            {
	                if (s) r += String.fromCharCode(a | (c >> (6 - s)) & 255);
	                s = (s + 2) & 7;
	                a = (c << s) & 255;
	            }
	        }
	        return r;
	    }    

	    my.b16to64 = function(h) {
	        var i;
	        var c;
	        var ret = "";
	        if(h.length % 2 == 1)
	        {
	            h = "0" + h;
	        }
	        for (i = 0; i + 3 <= h.length; i += 3)
	        {
	            c = parseInt(h.substring(i, i + 3), 16);
	            ret += base64Chars.charAt(c >> 6) + base64Chars.charAt(c & 63);
	        }
	        if (i + 1 == h.length)
	        {
	            c = parseInt(h.substring(i, i + 1), 16);
	            ret += base64Chars.charAt(c << 2);
	        }
	        else if (i + 2 == h.length)
	        {
	            c = parseInt(h.substring(i, i + 2), 16);
	            ret += base64Chars.charAt(c >> 2) + base64Chars.charAt((c & 3) << 4);
	        }
	        while ((ret.length & 3) > 0) ret += "=";
	        return ret;
	    }

	    my.b64to16 = function(s) {
	        var ret = "";
	        var i;
	        var k = 0;
	        var slop;
	        for (i = 0; i < s.length; ++i)
	        {
	            if (s.charAt(i) == "=") break;
	            v = base64Chars.indexOf(s.charAt(i));
	            if (v < 0) continue;
	            if (k == 0)
	            {
	                ret += int2char(v >> 2);
	                slop = v & 3;
	                k = 1;
	            }
	            else if (k == 1)
	            {
	                ret += int2char((slop << 2) | (v >> 4));
	                slop = v & 0xf;
	                k = 2;
	            }
	            else if (k == 2)
	            {
	                ret += int2char(slop);
	                ret += int2char(v >> 2);
	                slop = v & 3;
	                k = 3;
	            }
	            else
	            {
	                ret += int2char((slop << 2) | (v >> 4));
	                ret += int2char(v & 0xf);
	                k = 0;
	            }
	        }
	        if (k == 1) ret += int2char(slop << 2);
	        return ret;
	    }
	    
	    // Converts a string to a byte array.
	    my.string2bytes = function(string)
	    {
	        var bytes = new Array();
	        for(var i = 0; i < string.length; i++) 
	        {
	            bytes.push(string.charCodeAt(i));
	        }
	        return bytes;
	    }

	    // Converts a byte array to a string.
	    my.bytes2string = function(bytes)
	    {
	        var string = "";
	        for(var i = 0; i < bytes.length; i++)
	        {
	            string += String.fromCharCode(bytes[i]);
	        }   
	        return string;
	    }
	    
	    // Returns a XOR b, where a and b are 16-byte byte arrays.
	    my.blockXOR = function(a, b)
	    {
	        var xor = new Array(16);
	        for(var i = 0; i < 16; i++)
	        {
	            xor[i] = a[i] ^ b[i];
	        }
	        return xor;
	    }
	    
	    // Returns a 16-byte initialization vector.
	    my.blockIV = function()
	    {
	        var r = new SecureRandom();
	        var IV = new Array(16);
	        r.nextBytes(IV);
	        return IV;
	    }
	    
	    // Returns a copy of bytes with zeros appended to the end
	    // so that the (length of bytes) % 16 == 0.
	    my.pad16 = function(bytes)
	    {
	        var newBytes = bytes.slice(0);
	        var padding = (16 - (bytes.length % 16)) % 16;
	        for(i = bytes.length; i < bytes.length + padding; i++)
	        {
	            newBytes.push(0);
	        }
	        return newBytes;
	    }
	    
	    // Removes trailing zeros from a byte array.
	    my.depad = function(bytes)
	    {
	        var newBytes = bytes.slice(0);
	        while(newBytes[newBytes.length - 1] == 0)
	        {
	            newBytes = newBytes.slice(0, newBytes.length - 1);
	        }
	        return newBytes;
	    }
	    
	    // AES CBC Encryption.
	    my.encryptAESCBC = function(plaintext, key)
	    {
	        var exkey = key.slice(0);
	        aes.ExpandKey(exkey);
	        var blocks = my.string2bytes(plaintext);
	        blocks = my.pad16(blocks);
	        var encryptedBlocks = my.blockIV();
	        for(var i = 0; i < blocks.length/16; i++)
	        {
	            var tempBlock = blocks.slice(i * 16, i * 16 + 16);
	            var prevBlock = encryptedBlocks.slice((i) * 16, (i) * 16 + 16);
	            tempBlock = my.blockXOR(prevBlock, tempBlock);
	            aes.Encrypt(tempBlock, exkey);
	            encryptedBlocks = encryptedBlocks.concat(tempBlock);
	        }
	        var ciphertext = my.bytes2string(encryptedBlocks);
	        return my.b256to64(ciphertext)
	    }

	    // AES CBC Decryption.
	    my.decryptAESCBC = function(encryptedText, key)
	    {
	        var exkey = key.slice(0);
	        aes.ExpandKey(exkey);
	        var encryptedText = my.b64to256(encryptedText);
	        var encryptedBlocks = my.string2bytes(encryptedText);
	        var decryptedBlocks = new Array();
	        for(var i = 1; i < encryptedBlocks.length/16; i++)
	        {
	            var tempBlock = encryptedBlocks.slice(i * 16, i * 16 + 16);
	            var prevBlock = encryptedBlocks.slice((i-1) * 16, (i-1) * 16 + 16);
	            aes.Decrypt(tempBlock, exkey);
	            tempBlock = my.blockXOR(prevBlock, tempBlock);
	            decryptedBlocks = decryptedBlocks.concat(tempBlock);
	        }
	        decryptedBlocks = my.depad(decryptedBlocks);
	        return my.bytes2string(decryptedBlocks);
	    }
	    
	    // Wraps a string to 60 characters.
	    my.wrap60 = function(string) 
	    {
	        var outstr = "";
	        for(var i = 0; i < string.length; i++) {
	            if(i % 60 == 0 && i != 0) outstr += "\n";
	            outstr += string[i]; }
	        return outstr; 
	    }

	    // Generate a random key for the AES-encrypted message.
	    my.generateAESKey = function()
	    {
	        var key = new Array(32);
	        var r = new SecureRandom();
	        r.nextBytes(key);
	        return key;
	    }

	    // Generates an RSA key from a passphrase.
	    my.generateRSAKey = function(passphrase, bitlength)
	    {
	        Math.seedrandom(sha256.hex(passphrase));
	        var rsa = new RSAKey();
	        rsa.generate(bitlength, "03");
	        return rsa;
	    }

	    // Returns the ascii-armored version of the public key.
	    my.publicKeyString = function(rsakey) 
	    {
	        pubkey = my.b16to64(rsakey.n.toString(16));
	        return pubkey; 
	    }
	    
	    // Returns an MD5 sum of a publicKeyString for easier identification.
	    my.publicKeyID = function(publicKeyString)
	    {
	        return MD5(publicKeyString);
	    }
	    
	    my.publicKeyFromString = function(string)
	    {
	        var N = my.b64to16(string.split("|")[0]);
	        var E = "03";
	        var rsa = new RSAKey();
	        rsa.setPublic(N, E);
	        return rsa
	    }
	    
	    my.encrypt = function(plaintext, publickeystring, signingkey)
	    {
	        var cipherblock = "";
	        var aeskey = my.generateAESKey();
	        try
	        {
	            var publickey = my.publicKeyFromString(publickeystring);
	            cipherblock += my.b16to64(publickey.encrypt(my.bytes2string(aeskey))) + "?";
	        }
	        catch(err)
	        {
	            return {status: "Invalid public key"};
	        }
	        if(signingkey)
	        {
	            signString = cryptico.b16to64(signingkey.signString(plaintext, "sha256"));
	            plaintext += "::52cee64bb3a38f6403386519a39ac91c::";
	            plaintext += cryptico.publicKeyString(signingkey);
	            plaintext += "::52cee64bb3a38f6403386519a39ac91c::";
	            plaintext += signString;
	        }
	        cipherblock += my.encryptAESCBC(plaintext, aeskey);    
	        return {status: "success", cipher: cipherblock};
	    }

	    my.decrypt = function(ciphertext, key)
	    {
	        var cipherblock = ciphertext.split("?");
	        var aeskey = key.decrypt(my.b64to16(cipherblock[0]));
	        if(aeskey == null)
	        {
	            return {status: "failure"};
	        }
	        aeskey = my.string2bytes(aeskey);
	        var plaintext = my.decryptAESCBC(cipherblock[1], aeskey).split("::52cee64bb3a38f6403386519a39ac91c::");
	        if(plaintext.length == 3)
	        {
	            var publickey = my.publicKeyFromString(plaintext[1]);
	            var signature = my.b64to16(plaintext[2]);
	            if(publickey.verifyString(plaintext[0], signature))
	            {
	                return {status: "success", 
	                        plaintext: plaintext[0], 
	                        signature: "verified", 
	                        publicKeyString: my.publicKeyString(publickey)};
	            }
	            else
	            {
	                return {status: "success", 
	                        plaintext: plaintext[0], 
	                        signature: "forged", 
	                        publicKeyString: my.publicKeyString(publickey)};
	            }
	        }
	        else
	        {
	            return {status: "success", plaintext: plaintext[0], signature: "unsigned"};
	        }
	    }

	    return my;

	}());

	module.exports.RSAKey = RSAKey;

/***/ },
/* 2 */
/***/ function(module, exports, __webpack_require__) {

	/* WEBPACK VAR INJECTION */(function(Buffer) {var rng = __webpack_require__(7)

	function error () {
	  var m = [].slice.call(arguments).join(' ')
	  throw new Error([
	    m,
	    'we accept pull requests',
	    'http://github.com/dominictarr/crypto-browserify'
	    ].join('\n'))
	}

	exports.createHash = __webpack_require__(9)

	exports.createHmac = __webpack_require__(22)

	exports.randomBytes = function(size, callback) {
	  if (callback && callback.call) {
	    try {
	      callback.call(this, undefined, new Buffer(rng(size)))
	    } catch (err) { callback(err) }
	  } else {
	    return new Buffer(rng(size))
	  }
	}

	function each(a, f) {
	  for(var i in a)
	    f(a[i], i)
	}

	exports.getHashes = function () {
	  return ['sha1', 'sha256', 'sha512', 'md5', 'rmd160']
	}

	var p = __webpack_require__(23)(exports)
	exports.pbkdf2 = p.pbkdf2
	exports.pbkdf2Sync = p.pbkdf2Sync


	// the least I can do is make error messages for the rest of the node.js/crypto api.
	each(['createCredentials'
	, 'createCipher'
	, 'createCipheriv'
	, 'createDecipher'
	, 'createDecipheriv'
	, 'createSign'
	, 'createVerify'
	, 'createDiffieHellman'
	], function (name) {
	  exports[name] = function () {
	    error('sorry,', name, 'is not implemented yet')
	  }
	})

	/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(3).Buffer))

/***/ },
/* 3 */
/***/ function(module, exports, __webpack_require__) {

	/* WEBPACK VAR INJECTION */(function(Buffer, global) {/*!
	 * The buffer module from node.js, for the browser.
	 *
	 * @author   Feross Aboukhadijeh <feross@feross.org> <http://feross.org>
	 * @license  MIT
	 */
	/* eslint-disable no-proto */

	'use strict'

	var base64 = __webpack_require__(4)
	var ieee754 = __webpack_require__(5)
	var isArray = __webpack_require__(6)

	exports.Buffer = Buffer
	exports.SlowBuffer = SlowBuffer
	exports.INSPECT_MAX_BYTES = 50
	Buffer.poolSize = 8192 // not used by this implementation

	var rootParent = {}

	/**
	 * If `Buffer.TYPED_ARRAY_SUPPORT`:
	 *   === true    Use Uint8Array implementation (fastest)
	 *   === false   Use Object implementation (most compatible, even IE6)
	 *
	 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
	 * Opera 11.6+, iOS 4.2+.
	 *
	 * Due to various browser bugs, sometimes the Object implementation will be used even
	 * when the browser supports typed arrays.
	 *
	 * Note:
	 *
	 *   - Firefox 4-29 lacks support for adding new properties to `Uint8Array` instances,
	 *     See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438.
	 *
	 *   - Safari 5-7 lacks support for changing the `Object.prototype.constructor` property
	 *     on objects.
	 *
	 *   - Chrome 9-10 is missing the `TypedArray.prototype.subarray` function.
	 *
	 *   - IE10 has a broken `TypedArray.prototype.subarray` function which returns arrays of
	 *     incorrect length in some situations.

	 * We detect these buggy browsers and set `Buffer.TYPED_ARRAY_SUPPORT` to `false` so they
	 * get the Object implementation, which is slower but behaves correctly.
	 */
	Buffer.TYPED_ARRAY_SUPPORT = global.TYPED_ARRAY_SUPPORT !== undefined
	  ? global.TYPED_ARRAY_SUPPORT
	  : typedArraySupport()

	function typedArraySupport () {
	  function Bar () {}
	  try {
	    var arr = new Uint8Array(1)
	    arr.foo = function () { return 42 }
	    arr.constructor = Bar
	    return arr.foo() === 42 && // typed array instances can be augmented
	        arr.constructor === Bar && // constructor can be set
	        typeof arr.subarray === 'function' && // chrome 9-10 lack `subarray`
	        arr.subarray(1, 1).byteLength === 0 // ie10 has broken `subarray`
	  } catch (e) {
	    return false
	  }
	}

	function kMaxLength () {
	  return Buffer.TYPED_ARRAY_SUPPORT
	    ? 0x7fffffff
	    : 0x3fffffff
	}

	/**
	 * Class: Buffer
	 * =============
	 *
	 * The Buffer constructor returns instances of `Uint8Array` that are augmented
	 * with function properties for all the node `Buffer` API functions. We use
	 * `Uint8Array` so that square bracket notation works as expected -- it returns
	 * a single octet.
	 *
	 * By augmenting the instances, we can avoid modifying the `Uint8Array`
	 * prototype.
	 */
	function Buffer (arg) {
	  if (!(this instanceof Buffer)) {
	    // Avoid going through an ArgumentsAdaptorTrampoline in the common case.
	    if (arguments.length > 1) return new Buffer(arg, arguments[1])
	    return new Buffer(arg)
	  }

	  if (!Buffer.TYPED_ARRAY_SUPPORT) {
	    this.length = 0
	    this.parent = undefined
	  }

	  // Common case.
	  if (typeof arg === 'number') {
	    return fromNumber(this, arg)
	  }

	  // Slightly less common case.
	  if (typeof arg === 'string') {
	    return fromString(this, arg, arguments.length > 1 ? arguments[1] : 'utf8')
	  }

	  // Unusual.
	  return fromObject(this, arg)
	}

	function fromNumber (that, length) {
	  that = allocate(that, length < 0 ? 0 : checked(length) | 0)
	  if (!Buffer.TYPED_ARRAY_SUPPORT) {
	    for (var i = 0; i < length; i++) {
	      that[i] = 0
	    }
	  }
	  return that
	}

	function fromString (that, string, encoding) {
	  if (typeof encoding !== 'string' || encoding === '') encoding = 'utf8'

	  // Assumption: byteLength() return value is always < kMaxLength.
	  var length = byteLength(string, encoding) | 0
	  that = allocate(that, length)

	  that.write(string, encoding)
	  return that
	}

	function fromObject (that, object) {
	  if (Buffer.isBuffer(object)) return fromBuffer(that, object)

	  if (isArray(object)) return fromArray(that, object)

	  if (object == null) {
	    throw new TypeError('must start with number, buffer, array or string')
	  }

	  if (typeof ArrayBuffer !== 'undefined') {
	    if (object.buffer instanceof ArrayBuffer) {
	      return fromTypedArray(that, object)
	    }
	    if (object instanceof ArrayBuffer) {
	      return fromArrayBuffer(that, object)
	    }
	  }

	  if (object.length) return fromArrayLike(that, object)

	  return fromJsonObject(that, object)
	}

	function fromBuffer (that, buffer) {
	  var length = checked(buffer.length) | 0
	  that = allocate(that, length)
	  buffer.copy(that, 0, 0, length)
	  return that
	}

	function fromArray (that, array) {
	  var length = checked(array.length) | 0
	  that = allocate(that, length)
	  for (var i = 0; i < length; i += 1) {
	    that[i] = array[i] & 255
	  }
	  return that
	}

	// Duplicate of fromArray() to keep fromArray() monomorphic.
	function fromTypedArray (that, array) {
	  var length = checked(array.length) | 0
	  that = allocate(that, length)
	  // Truncating the elements is probably not what people expect from typed
	  // arrays with BYTES_PER_ELEMENT > 1 but it's compatible with the behavior
	  // of the old Buffer constructor.
	  for (var i = 0; i < length; i += 1) {
	    that[i] = array[i] & 255
	  }
	  return that
	}

	function fromArrayBuffer (that, array) {
	  if (Buffer.TYPED_ARRAY_SUPPORT) {
	    // Return an augmented `Uint8Array` instance, for best performance
	    array.byteLength
	    that = Buffer._augment(new Uint8Array(array))
	  } else {
	    // Fallback: Return an object instance of the Buffer class
	    that = fromTypedArray(that, new Uint8Array(array))
	  }
	  return that
	}

	function fromArrayLike (that, array) {
	  var length = checked(array.length) | 0
	  that = allocate(that, length)
	  for (var i = 0; i < length; i += 1) {
	    that[i] = array[i] & 255
	  }
	  return that
	}

	// Deserialize { type: 'Buffer', data: [1,2,3,...] } into a Buffer object.
	// Returns a zero-length buffer for inputs that don't conform to the spec.
	function fromJsonObject (that, object) {
	  var array
	  var length = 0

	  if (object.type === 'Buffer' && isArray(object.data)) {
	    array = object.data
	    length = checked(array.length) | 0
	  }
	  that = allocate(that, length)

	  for (var i = 0; i < length; i += 1) {
	    that[i] = array[i] & 255
	  }
	  return that
	}

	if (Buffer.TYPED_ARRAY_SUPPORT) {
	  Buffer.prototype.__proto__ = Uint8Array.prototype
	  Buffer.__proto__ = Uint8Array
	} else {
	  // pre-set for values that may exist in the future
	  Buffer.prototype.length = undefined
	  Buffer.prototype.parent = undefined
	}

	function allocate (that, length) {
	  if (Buffer.TYPED_ARRAY_SUPPORT) {
	    // Return an augmented `Uint8Array` instance, for best performance
	    that = Buffer._augment(new Uint8Array(length))
	    that.__proto__ = Buffer.prototype
	  } else {
	    // Fallback: Return an object instance of the Buffer class
	    that.length = length
	    that._isBuffer = true
	  }

	  var fromPool = length !== 0 && length <= Buffer.poolSize >>> 1
	  if (fromPool) that.parent = rootParent

	  return that
	}

	function checked (length) {
	  // Note: cannot use `length < kMaxLength` here because that fails when
	  // length is NaN (which is otherwise coerced to zero.)
	  if (length >= kMaxLength()) {
	    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
	                         'size: 0x' + kMaxLength().toString(16) + ' bytes')
	  }
	  return length | 0
	}

	function SlowBuffer (subject, encoding) {
	  if (!(this instanceof SlowBuffer)) return new SlowBuffer(subject, encoding)

	  var buf = new Buffer(subject, encoding)
	  delete buf.parent
	  return buf
	}

	Buffer.isBuffer = function isBuffer (b) {
	  return !!(b != null && b._isBuffer)
	}

	Buffer.compare = function compare (a, b) {
	  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
	    throw new TypeError('Arguments must be Buffers')
	  }

	  if (a === b) return 0

	  var x = a.length
	  var y = b.length

	  var i = 0
	  var len = Math.min(x, y)
	  while (i < len) {
	    if (a[i] !== b[i]) break

	    ++i
	  }

	  if (i !== len) {
	    x = a[i]
	    y = b[i]
	  }

	  if (x < y) return -1
	  if (y < x) return 1
	  return 0
	}

	Buffer.isEncoding = function isEncoding (encoding) {
	  switch (String(encoding).toLowerCase()) {
	    case 'hex':
	    case 'utf8':
	    case 'utf-8':
	    case 'ascii':
	    case 'binary':
	    case 'base64':
	    case 'raw':
	    case 'ucs2':
	    case 'ucs-2':
	    case 'utf16le':
	    case 'utf-16le':
	      return true
	    default:
	      return false
	  }
	}

	Buffer.concat = function concat (list, length) {
	  if (!isArray(list)) throw new TypeError('list argument must be an Array of Buffers.')

	  if (list.length === 0) {
	    return new Buffer(0)
	  }

	  var i
	  if (length === undefined) {
	    length = 0
	    for (i = 0; i < list.length; i++) {
	      length += list[i].length
	    }
	  }

	  var buf = new Buffer(length)
	  var pos = 0
	  for (i = 0; i < list.length; i++) {
	    var item = list[i]
	    item.copy(buf, pos)
	    pos += item.length
	  }
	  return buf
	}

	function byteLength (string, encoding) {
	  if (typeof string !== 'string') string = '' + string

	  var len = string.length
	  if (len === 0) return 0

	  // Use a for loop to avoid recursion
	  var loweredCase = false
	  for (;;) {
	    switch (encoding) {
	      case 'ascii':
	      case 'binary':
	      // Deprecated
	      case 'raw':
	      case 'raws':
	        return len
	      case 'utf8':
	      case 'utf-8':
	        return utf8ToBytes(string).length
	      case 'ucs2':
	      case 'ucs-2':
	      case 'utf16le':
	      case 'utf-16le':
	        return len * 2
	      case 'hex':
	        return len >>> 1
	      case 'base64':
	        return base64ToBytes(string).length
	      default:
	        if (loweredCase) return utf8ToBytes(string).length // assume utf8
	        encoding = ('' + encoding).toLowerCase()
	        loweredCase = true
	    }
	  }
	}
	Buffer.byteLength = byteLength

	function slowToString (encoding, start, end) {
	  var loweredCase = false

	  start = start | 0
	  end = end === undefined || end === Infinity ? this.length : end | 0

	  if (!encoding) encoding = 'utf8'
	  if (start < 0) start = 0
	  if (end > this.length) end = this.length
	  if (end <= start) return ''

	  while (true) {
	    switch (encoding) {
	      case 'hex':
	        return hexSlice(this, start, end)

	      case 'utf8':
	      case 'utf-8':
	        return utf8Slice(this, start, end)

	      case 'ascii':
	        return asciiSlice(this, start, end)

	      case 'binary':
	        return binarySlice(this, start, end)

	      case 'base64':
	        return base64Slice(this, start, end)

	      case 'ucs2':
	      case 'ucs-2':
	      case 'utf16le':
	      case 'utf-16le':
	        return utf16leSlice(this, start, end)

	      default:
	        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
	        encoding = (encoding + '').toLowerCase()
	        loweredCase = true
	    }
	  }
	}

	Buffer.prototype.toString = function toString () {
	  var length = this.length | 0
	  if (length === 0) return ''
	  if (arguments.length === 0) return utf8Slice(this, 0, length)
	  return slowToString.apply(this, arguments)
	}

	Buffer.prototype.equals = function equals (b) {
	  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
	  if (this === b) return true
	  return Buffer.compare(this, b) === 0
	}

	Buffer.prototype.inspect = function inspect () {
	  var str = ''
	  var max = exports.INSPECT_MAX_BYTES
	  if (this.length > 0) {
	    str = this.toString('hex', 0, max).match(/.{2}/g).join(' ')
	    if (this.length > max) str += ' ... '
	  }
	  return '<Buffer ' + str + '>'
	}

	Buffer.prototype.compare = function compare (b) {
	  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
	  if (this === b) return 0
	  return Buffer.compare(this, b)
	}

	Buffer.prototype.indexOf = function indexOf (val, byteOffset) {
	  if (byteOffset > 0x7fffffff) byteOffset = 0x7fffffff
	  else if (byteOffset < -0x80000000) byteOffset = -0x80000000
	  byteOffset >>= 0

	  if (this.length === 0) return -1
	  if (byteOffset >= this.length) return -1

	  // Negative offsets start from the end of the buffer
	  if (byteOffset < 0) byteOffset = Math.max(this.length + byteOffset, 0)

	  if (typeof val === 'string') {
	    if (val.length === 0) return -1 // special case: looking for empty string always fails
	    return String.prototype.indexOf.call(this, val, byteOffset)
	  }
	  if (Buffer.isBuffer(val)) {
	    return arrayIndexOf(this, val, byteOffset)
	  }
	  if (typeof val === 'number') {
	    if (Buffer.TYPED_ARRAY_SUPPORT && Uint8Array.prototype.indexOf === 'function') {
	      return Uint8Array.prototype.indexOf.call(this, val, byteOffset)
	    }
	    return arrayIndexOf(this, [ val ], byteOffset)
	  }

	  function arrayIndexOf (arr, val, byteOffset) {
	    var foundIndex = -1
	    for (var i = 0; byteOffset + i < arr.length; i++) {
	      if (arr[byteOffset + i] === val[foundIndex === -1 ? 0 : i - foundIndex]) {
	        if (foundIndex === -1) foundIndex = i
	        if (i - foundIndex + 1 === val.length) return byteOffset + foundIndex
	      } else {
	        foundIndex = -1
	      }
	    }
	    return -1
	  }

	  throw new TypeError('val must be string, number or Buffer')
	}

	// `get` is deprecated
	Buffer.prototype.get = function get (offset) {
	  console.log('.get() is deprecated. Access using array indexes instead.')
	  return this.readUInt8(offset)
	}

	// `set` is deprecated
	Buffer.prototype.set = function set (v, offset) {
	  console.log('.set() is deprecated. Access using array indexes instead.')
	  return this.writeUInt8(v, offset)
	}

	function hexWrite (buf, string, offset, length) {
	  offset = Number(offset) || 0
	  var remaining = buf.length - offset
	  if (!length) {
	    length = remaining
	  } else {
	    length = Number(length)
	    if (length > remaining) {
	      length = remaining
	    }
	  }

	  // must be an even number of digits
	  var strLen = string.length
	  if (strLen % 2 !== 0) throw new Error('Invalid hex string')

	  if (length > strLen / 2) {
	    length = strLen / 2
	  }
	  for (var i = 0; i < length; i++) {
	    var parsed = parseInt(string.substr(i * 2, 2), 16)
	    if (isNaN(parsed)) throw new Error('Invalid hex string')
	    buf[offset + i] = parsed
	  }
	  return i
	}

	function utf8Write (buf, string, offset, length) {
	  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
	}

	function asciiWrite (buf, string, offset, length) {
	  return blitBuffer(asciiToBytes(string), buf, offset, length)
	}

	function binaryWrite (buf, string, offset, length) {
	  return asciiWrite(buf, string, offset, length)
	}

	function base64Write (buf, string, offset, length) {
	  return blitBuffer(base64ToBytes(string), buf, offset, length)
	}

	function ucs2Write (buf, string, offset, length) {
	  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
	}

	Buffer.prototype.write = function write (string, offset, length, encoding) {
	  // Buffer#write(string)
	  if (offset === undefined) {
	    encoding = 'utf8'
	    length = this.length
	    offset = 0
	  // Buffer#write(string, encoding)
	  } else if (length === undefined && typeof offset === 'string') {
	    encoding = offset
	    length = this.length
	    offset = 0
	  // Buffer#write(string, offset[, length][, encoding])
	  } else if (isFinite(offset)) {
	    offset = offset | 0
	    if (isFinite(length)) {
	      length = length | 0
	      if (encoding === undefined) encoding = 'utf8'
	    } else {
	      encoding = length
	      length = undefined
	    }
	  // legacy write(string, encoding, offset, length) - remove in v0.13
	  } else {
	    var swap = encoding
	    encoding = offset
	    offset = length | 0
	    length = swap
	  }

	  var remaining = this.length - offset
	  if (length === undefined || length > remaining) length = remaining

	  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
	    throw new RangeError('attempt to write outside buffer bounds')
	  }

	  if (!encoding) encoding = 'utf8'

	  var loweredCase = false
	  for (;;) {
	    switch (encoding) {
	      case 'hex':
	        return hexWrite(this, string, offset, length)

	      case 'utf8':
	      case 'utf-8':
	        return utf8Write(this, string, offset, length)

	      case 'ascii':
	        return asciiWrite(this, string, offset, length)

	      case 'binary':
	        return binaryWrite(this, string, offset, length)

	      case 'base64':
	        // Warning: maxLength not taken into account in base64Write
	        return base64Write(this, string, offset, length)

	      case 'ucs2':
	      case 'ucs-2':
	      case 'utf16le':
	      case 'utf-16le':
	        return ucs2Write(this, string, offset, length)

	      default:
	        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
	        encoding = ('' + encoding).toLowerCase()
	        loweredCase = true
	    }
	  }
	}

	Buffer.prototype.toJSON = function toJSON () {
	  return {
	    type: 'Buffer',
	    data: Array.prototype.slice.call(this._arr || this, 0)
	  }
	}

	function base64Slice (buf, start, end) {
	  if (start === 0 && end === buf.length) {
	    return base64.fromByteArray(buf)
	  } else {
	    return base64.fromByteArray(buf.slice(start, end))
	  }
	}

	function utf8Slice (buf, start, end) {
	  end = Math.min(buf.length, end)
	  var res = []

	  var i = start
	  while (i < end) {
	    var firstByte = buf[i]
	    var codePoint = null
	    var bytesPerSequence = (firstByte > 0xEF) ? 4
	      : (firstByte > 0xDF) ? 3
	      : (firstByte > 0xBF) ? 2
	      : 1

	    if (i + bytesPerSequence <= end) {
	      var secondByte, thirdByte, fourthByte, tempCodePoint

	      switch (bytesPerSequence) {
	        case 1:
	          if (firstByte < 0x80) {
	            codePoint = firstByte
	          }
	          break
	        case 2:
	          secondByte = buf[i + 1]
	          if ((secondByte & 0xC0) === 0x80) {
	            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
	            if (tempCodePoint > 0x7F) {
	              codePoint = tempCodePoint
	            }
	          }
	          break
	        case 3:
	          secondByte = buf[i + 1]
	          thirdByte = buf[i + 2]
	          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
	            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
	            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
	              codePoint = tempCodePoint
	            }
	          }
	          break
	        case 4:
	          secondByte = buf[i + 1]
	          thirdByte = buf[i + 2]
	          fourthByte = buf[i + 3]
	          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
	            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
	            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
	              codePoint = tempCodePoint
	            }
	          }
	      }
	    }

	    if (codePoint === null) {
	      // we did not generate a valid codePoint so insert a
	      // replacement char (U+FFFD) and advance only 1 byte
	      codePoint = 0xFFFD
	      bytesPerSequence = 1
	    } else if (codePoint > 0xFFFF) {
	      // encode to utf16 (surrogate pair dance)
	      codePoint -= 0x10000
	      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
	      codePoint = 0xDC00 | codePoint & 0x3FF
	    }

	    res.push(codePoint)
	    i += bytesPerSequence
	  }

	  return decodeCodePointsArray(res)
	}

	// Based on http://stackoverflow.com/a/22747272/680742, the browser with
	// the lowest limit is Chrome, with 0x10000 args.
	// We go 1 magnitude less, for safety
	var MAX_ARGUMENTS_LENGTH = 0x1000

	function decodeCodePointsArray (codePoints) {
	  var len = codePoints.length
	  if (len <= MAX_ARGUMENTS_LENGTH) {
	    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
	  }

	  // Decode in chunks to avoid "call stack size exceeded".
	  var res = ''
	  var i = 0
	  while (i < len) {
	    res += String.fromCharCode.apply(
	      String,
	      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
	    )
	  }
	  return res
	}

	function asciiSlice (buf, start, end) {
	  var ret = ''
	  end = Math.min(buf.length, end)

	  for (var i = start; i < end; i++) {
	    ret += String.fromCharCode(buf[i] & 0x7F)
	  }
	  return ret
	}

	function binarySlice (buf, start, end) {
	  var ret = ''
	  end = Math.min(buf.length, end)

	  for (var i = start; i < end; i++) {
	    ret += String.fromCharCode(buf[i])
	  }
	  return ret
	}

	function hexSlice (buf, start, end) {
	  var len = buf.length

	  if (!start || start < 0) start = 0
	  if (!end || end < 0 || end > len) end = len

	  var out = ''
	  for (var i = start; i < end; i++) {
	    out += toHex(buf[i])
	  }
	  return out
	}

	function utf16leSlice (buf, start, end) {
	  var bytes = buf.slice(start, end)
	  var res = ''
	  for (var i = 0; i < bytes.length; i += 2) {
	    res += String.fromCharCode(bytes[i] + bytes[i + 1] * 256)
	  }
	  return res
	}

	Buffer.prototype.slice = function slice (start, end) {
	  var len = this.length
	  start = ~~start
	  end = end === undefined ? len : ~~end

	  if (start < 0) {
	    start += len
	    if (start < 0) start = 0
	  } else if (start > len) {
	    start = len
	  }

	  if (end < 0) {
	    end += len
	    if (end < 0) end = 0
	  } else if (end > len) {
	    end = len
	  }

	  if (end < start) end = start

	  var newBuf
	  if (Buffer.TYPED_ARRAY_SUPPORT) {
	    newBuf = Buffer._augment(this.subarray(start, end))
	  } else {
	    var sliceLen = end - start
	    newBuf = new Buffer(sliceLen, undefined)
	    for (var i = 0; i < sliceLen; i++) {
	      newBuf[i] = this[i + start]
	    }
	  }

	  if (newBuf.length) newBuf.parent = this.parent || this

	  return newBuf
	}

	/*
	 * Need to make sure that buffer isn't trying to write out of bounds.
	 */
	function checkOffset (offset, ext, length) {
	  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
	  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
	}

	Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
	  offset = offset | 0
	  byteLength = byteLength | 0
	  if (!noAssert) checkOffset(offset, byteLength, this.length)

	  var val = this[offset]
	  var mul = 1
	  var i = 0
	  while (++i < byteLength && (mul *= 0x100)) {
	    val += this[offset + i] * mul
	  }

	  return val
	}

	Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
	  offset = offset | 0
	  byteLength = byteLength | 0
	  if (!noAssert) {
	    checkOffset(offset, byteLength, this.length)
	  }

	  var val = this[offset + --byteLength]
	  var mul = 1
	  while (byteLength > 0 && (mul *= 0x100)) {
	    val += this[offset + --byteLength] * mul
	  }

	  return val
	}

	Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
	  if (!noAssert) checkOffset(offset, 1, this.length)
	  return this[offset]
	}

	Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
	  if (!noAssert) checkOffset(offset, 2, this.length)
	  return this[offset] | (this[offset + 1] << 8)
	}

	Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
	  if (!noAssert) checkOffset(offset, 2, this.length)
	  return (this[offset] << 8) | this[offset + 1]
	}

	Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
	  if (!noAssert) checkOffset(offset, 4, this.length)

	  return ((this[offset]) |
	      (this[offset + 1] << 8) |
	      (this[offset + 2] << 16)) +
	      (this[offset + 3] * 0x1000000)
	}

	Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
	  if (!noAssert) checkOffset(offset, 4, this.length)

	  return (this[offset] * 0x1000000) +
	    ((this[offset + 1] << 16) |
	    (this[offset + 2] << 8) |
	    this[offset + 3])
	}

	Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
	  offset = offset | 0
	  byteLength = byteLength | 0
	  if (!noAssert) checkOffset(offset, byteLength, this.length)

	  var val = this[offset]
	  var mul = 1
	  var i = 0
	  while (++i < byteLength && (mul *= 0x100)) {
	    val += this[offset + i] * mul
	  }
	  mul *= 0x80

	  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

	  return val
	}

	Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
	  offset = offset | 0
	  byteLength = byteLength | 0
	  if (!noAssert) checkOffset(offset, byteLength, this.length)

	  var i = byteLength
	  var mul = 1
	  var val = this[offset + --i]
	  while (i > 0 && (mul *= 0x100)) {
	    val += this[offset + --i] * mul
	  }
	  mul *= 0x80

	  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

	  return val
	}

	Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
	  if (!noAssert) checkOffset(offset, 1, this.length)
	  if (!(this[offset] & 0x80)) return (this[offset])
	  return ((0xff - this[offset] + 1) * -1)
	}

	Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
	  if (!noAssert) checkOffset(offset, 2, this.length)
	  var val = this[offset] | (this[offset + 1] << 8)
	  return (val & 0x8000) ? val | 0xFFFF0000 : val
	}

	Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
	  if (!noAssert) checkOffset(offset, 2, this.length)
	  var val = this[offset + 1] | (this[offset] << 8)
	  return (val & 0x8000) ? val | 0xFFFF0000 : val
	}

	Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
	  if (!noAssert) checkOffset(offset, 4, this.length)

	  return (this[offset]) |
	    (this[offset + 1] << 8) |
	    (this[offset + 2] << 16) |
	    (this[offset + 3] << 24)
	}

	Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
	  if (!noAssert) checkOffset(offset, 4, this.length)

	  return (this[offset] << 24) |
	    (this[offset + 1] << 16) |
	    (this[offset + 2] << 8) |
	    (this[offset + 3])
	}

	Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
	  if (!noAssert) checkOffset(offset, 4, this.length)
	  return ieee754.read(this, offset, true, 23, 4)
	}

	Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
	  if (!noAssert) checkOffset(offset, 4, this.length)
	  return ieee754.read(this, offset, false, 23, 4)
	}

	Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
	  if (!noAssert) checkOffset(offset, 8, this.length)
	  return ieee754.read(this, offset, true, 52, 8)
	}

	Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
	  if (!noAssert) checkOffset(offset, 8, this.length)
	  return ieee754.read(this, offset, false, 52, 8)
	}

	function checkInt (buf, value, offset, ext, max, min) {
	  if (!Buffer.isBuffer(buf)) throw new TypeError('buffer must be a Buffer instance')
	  if (value > max || value < min) throw new RangeError('value is out of bounds')
	  if (offset + ext > buf.length) throw new RangeError('index out of range')
	}

	Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
	  value = +value
	  offset = offset | 0
	  byteLength = byteLength | 0
	  if (!noAssert) checkInt(this, value, offset, byteLength, Math.pow(2, 8 * byteLength), 0)

	  var mul = 1
	  var i = 0
	  this[offset] = value & 0xFF
	  while (++i < byteLength && (mul *= 0x100)) {
	    this[offset + i] = (value / mul) & 0xFF
	  }

	  return offset + byteLength
	}

	Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
	  value = +value
	  offset = offset | 0
	  byteLength = byteLength | 0
	  if (!noAssert) checkInt(this, value, offset, byteLength, Math.pow(2, 8 * byteLength), 0)

	  var i = byteLength - 1
	  var mul = 1
	  this[offset + i] = value & 0xFF
	  while (--i >= 0 && (mul *= 0x100)) {
	    this[offset + i] = (value / mul) & 0xFF
	  }

	  return offset + byteLength
	}

	Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
	  value = +value
	  offset = offset | 0
	  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
	  if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value)
	  this[offset] = (value & 0xff)
	  return offset + 1
	}

	function objectWriteUInt16 (buf, value, offset, littleEndian) {
	  if (value < 0) value = 0xffff + value + 1
	  for (var i = 0, j = Math.min(buf.length - offset, 2); i < j; i++) {
	    buf[offset + i] = (value & (0xff << (8 * (littleEndian ? i : 1 - i)))) >>>
	      (littleEndian ? i : 1 - i) * 8
	  }
	}

	Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
	  value = +value
	  offset = offset | 0
	  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
	  if (Buffer.TYPED_ARRAY_SUPPORT) {
	    this[offset] = (value & 0xff)
	    this[offset + 1] = (value >>> 8)
	  } else {
	    objectWriteUInt16(this, value, offset, true)
	  }
	  return offset + 2
	}

	Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
	  value = +value
	  offset = offset | 0
	  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
	  if (Buffer.TYPED_ARRAY_SUPPORT) {
	    this[offset] = (value >>> 8)
	    this[offset + 1] = (value & 0xff)
	  } else {
	    objectWriteUInt16(this, value, offset, false)
	  }
	  return offset + 2
	}

	function objectWriteUInt32 (buf, value, offset, littleEndian) {
	  if (value < 0) value = 0xffffffff + value + 1
	  for (var i = 0, j = Math.min(buf.length - offset, 4); i < j; i++) {
	    buf[offset + i] = (value >>> (littleEndian ? i : 3 - i) * 8) & 0xff
	  }
	}

	Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
	  value = +value
	  offset = offset | 0
	  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
	  if (Buffer.TYPED_ARRAY_SUPPORT) {
	    this[offset + 3] = (value >>> 24)
	    this[offset + 2] = (value >>> 16)
	    this[offset + 1] = (value >>> 8)
	    this[offset] = (value & 0xff)
	  } else {
	    objectWriteUInt32(this, value, offset, true)
	  }
	  return offset + 4
	}

	Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
	  value = +value
	  offset = offset | 0
	  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
	  if (Buffer.TYPED_ARRAY_SUPPORT) {
	    this[offset] = (value >>> 24)
	    this[offset + 1] = (value >>> 16)
	    this[offset + 2] = (value >>> 8)
	    this[offset + 3] = (value & 0xff)
	  } else {
	    objectWriteUInt32(this, value, offset, false)
	  }
	  return offset + 4
	}

	Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
	  value = +value
	  offset = offset | 0
	  if (!noAssert) {
	    var limit = Math.pow(2, 8 * byteLength - 1)

	    checkInt(this, value, offset, byteLength, limit - 1, -limit)
	  }

	  var i = 0
	  var mul = 1
	  var sub = value < 0 ? 1 : 0
	  this[offset] = value & 0xFF
	  while (++i < byteLength && (mul *= 0x100)) {
	    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
	  }

	  return offset + byteLength
	}

	Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
	  value = +value
	  offset = offset | 0
	  if (!noAssert) {
	    var limit = Math.pow(2, 8 * byteLength - 1)

	    checkInt(this, value, offset, byteLength, limit - 1, -limit)
	  }

	  var i = byteLength - 1
	  var mul = 1
	  var sub = value < 0 ? 1 : 0
	  this[offset + i] = value & 0xFF
	  while (--i >= 0 && (mul *= 0x100)) {
	    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
	  }

	  return offset + byteLength
	}

	Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
	  value = +value
	  offset = offset | 0
	  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
	  if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value)
	  if (value < 0) value = 0xff + value + 1
	  this[offset] = (value & 0xff)
	  return offset + 1
	}

	Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
	  value = +value
	  offset = offset | 0
	  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
	  if (Buffer.TYPED_ARRAY_SUPPORT) {
	    this[offset] = (value & 0xff)
	    this[offset + 1] = (value >>> 8)
	  } else {
	    objectWriteUInt16(this, value, offset, true)
	  }
	  return offset + 2
	}

	Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
	  value = +value
	  offset = offset | 0
	  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
	  if (Buffer.TYPED_ARRAY_SUPPORT) {
	    this[offset] = (value >>> 8)
	    this[offset + 1] = (value & 0xff)
	  } else {
	    objectWriteUInt16(this, value, offset, false)
	  }
	  return offset + 2
	}

	Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
	  value = +value
	  offset = offset | 0
	  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
	  if (Buffer.TYPED_ARRAY_SUPPORT) {
	    this[offset] = (value & 0xff)
	    this[offset + 1] = (value >>> 8)
	    this[offset + 2] = (value >>> 16)
	    this[offset + 3] = (value >>> 24)
	  } else {
	    objectWriteUInt32(this, value, offset, true)
	  }
	  return offset + 4
	}

	Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
	  value = +value
	  offset = offset | 0
	  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
	  if (value < 0) value = 0xffffffff + value + 1
	  if (Buffer.TYPED_ARRAY_SUPPORT) {
	    this[offset] = (value >>> 24)
	    this[offset + 1] = (value >>> 16)
	    this[offset + 2] = (value >>> 8)
	    this[offset + 3] = (value & 0xff)
	  } else {
	    objectWriteUInt32(this, value, offset, false)
	  }
	  return offset + 4
	}

	function checkIEEE754 (buf, value, offset, ext, max, min) {
	  if (value > max || value < min) throw new RangeError('value is out of bounds')
	  if (offset + ext > buf.length) throw new RangeError('index out of range')
	  if (offset < 0) throw new RangeError('index out of range')
	}

	function writeFloat (buf, value, offset, littleEndian, noAssert) {
	  if (!noAssert) {
	    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
	  }
	  ieee754.write(buf, value, offset, littleEndian, 23, 4)
	  return offset + 4
	}

	Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
	  return writeFloat(this, value, offset, true, noAssert)
	}

	Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
	  return writeFloat(this, value, offset, false, noAssert)
	}

	function writeDouble (buf, value, offset, littleEndian, noAssert) {
	  if (!noAssert) {
	    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
	  }
	  ieee754.write(buf, value, offset, littleEndian, 52, 8)
	  return offset + 8
	}

	Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
	  return writeDouble(this, value, offset, true, noAssert)
	}

	Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
	  return writeDouble(this, value, offset, false, noAssert)
	}

	// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
	Buffer.prototype.copy = function copy (target, targetStart, start, end) {
	  if (!start) start = 0
	  if (!end && end !== 0) end = this.length
	  if (targetStart >= target.length) targetStart = target.length
	  if (!targetStart) targetStart = 0
	  if (end > 0 && end < start) end = start

	  // Copy 0 bytes; we're done
	  if (end === start) return 0
	  if (target.length === 0 || this.length === 0) return 0

	  // Fatal error conditions
	  if (targetStart < 0) {
	    throw new RangeError('targetStart out of bounds')
	  }
	  if (start < 0 || start >= this.length) throw new RangeError('sourceStart out of bounds')
	  if (end < 0) throw new RangeError('sourceEnd out of bounds')

	  // Are we oob?
	  if (end > this.length) end = this.length
	  if (target.length - targetStart < end - start) {
	    end = target.length - targetStart + start
	  }

	  var len = end - start
	  var i

	  if (this === target && start < targetStart && targetStart < end) {
	    // descending copy from end
	    for (i = len - 1; i >= 0; i--) {
	      target[i + targetStart] = this[i + start]
	    }
	  } else if (len < 1000 || !Buffer.TYPED_ARRAY_SUPPORT) {
	    // ascending copy from start
	    for (i = 0; i < len; i++) {
	      target[i + targetStart] = this[i + start]
	    }
	  } else {
	    target._set(this.subarray(start, start + len), targetStart)
	  }

	  return len
	}

	// fill(value, start=0, end=buffer.length)
	Buffer.prototype.fill = function fill (value, start, end) {
	  if (!value) value = 0
	  if (!start) start = 0
	  if (!end) end = this.length

	  if (end < start) throw new RangeError('end < start')

	  // Fill 0 bytes; we're done
	  if (end === start) return
	  if (this.length === 0) return

	  if (start < 0 || start >= this.length) throw new RangeError('start out of bounds')
	  if (end < 0 || end > this.length) throw new RangeError('end out of bounds')

	  var i
	  if (typeof value === 'number') {
	    for (i = start; i < end; i++) {
	      this[i] = value
	    }
	  } else {
	    var bytes = utf8ToBytes(value.toString())
	    var len = bytes.length
	    for (i = start; i < end; i++) {
	      this[i] = bytes[i % len]
	    }
	  }

	  return this
	}

	/**
	 * Creates a new `ArrayBuffer` with the *copied* memory of the buffer instance.
	 * Added in Node 0.12. Only available in browsers that support ArrayBuffer.
	 */
	Buffer.prototype.toArrayBuffer = function toArrayBuffer () {
	  if (typeof Uint8Array !== 'undefined') {
	    if (Buffer.TYPED_ARRAY_SUPPORT) {
	      return (new Buffer(this)).buffer
	    } else {
	      var buf = new Uint8Array(this.length)
	      for (var i = 0, len = buf.length; i < len; i += 1) {
	        buf[i] = this[i]
	      }
	      return buf.buffer
	    }
	  } else {
	    throw new TypeError('Buffer.toArrayBuffer not supported in this browser')
	  }
	}

	// HELPER FUNCTIONS
	// ================

	var BP = Buffer.prototype

	/**
	 * Augment a Uint8Array *instance* (not the Uint8Array class!) with Buffer methods
	 */
	Buffer._augment = function _augment (arr) {
	  arr.constructor = Buffer
	  arr._isBuffer = true

	  // save reference to original Uint8Array set method before overwriting
	  arr._set = arr.set

	  // deprecated
	  arr.get = BP.get
	  arr.set = BP.set

	  arr.write = BP.write
	  arr.toString = BP.toString
	  arr.toLocaleString = BP.toString
	  arr.toJSON = BP.toJSON
	  arr.equals = BP.equals
	  arr.compare = BP.compare
	  arr.indexOf = BP.indexOf
	  arr.copy = BP.copy
	  arr.slice = BP.slice
	  arr.readUIntLE = BP.readUIntLE
	  arr.readUIntBE = BP.readUIntBE
	  arr.readUInt8 = BP.readUInt8
	  arr.readUInt16LE = BP.readUInt16LE
	  arr.readUInt16BE = BP.readUInt16BE
	  arr.readUInt32LE = BP.readUInt32LE
	  arr.readUInt32BE = BP.readUInt32BE
	  arr.readIntLE = BP.readIntLE
	  arr.readIntBE = BP.readIntBE
	  arr.readInt8 = BP.readInt8
	  arr.readInt16LE = BP.readInt16LE
	  arr.readInt16BE = BP.readInt16BE
	  arr.readInt32LE = BP.readInt32LE
	  arr.readInt32BE = BP.readInt32BE
	  arr.readFloatLE = BP.readFloatLE
	  arr.readFloatBE = BP.readFloatBE
	  arr.readDoubleLE = BP.readDoubleLE
	  arr.readDoubleBE = BP.readDoubleBE
	  arr.writeUInt8 = BP.writeUInt8
	  arr.writeUIntLE = BP.writeUIntLE
	  arr.writeUIntBE = BP.writeUIntBE
	  arr.writeUInt16LE = BP.writeUInt16LE
	  arr.writeUInt16BE = BP.writeUInt16BE
	  arr.writeUInt32LE = BP.writeUInt32LE
	  arr.writeUInt32BE = BP.writeUInt32BE
	  arr.writeIntLE = BP.writeIntLE
	  arr.writeIntBE = BP.writeIntBE
	  arr.writeInt8 = BP.writeInt8
	  arr.writeInt16LE = BP.writeInt16LE
	  arr.writeInt16BE = BP.writeInt16BE
	  arr.writeInt32LE = BP.writeInt32LE
	  arr.writeInt32BE = BP.writeInt32BE
	  arr.writeFloatLE = BP.writeFloatLE
	  arr.writeFloatBE = BP.writeFloatBE
	  arr.writeDoubleLE = BP.writeDoubleLE
	  arr.writeDoubleBE = BP.writeDoubleBE
	  arr.fill = BP.fill
	  arr.inspect = BP.inspect
	  arr.toArrayBuffer = BP.toArrayBuffer

	  return arr
	}

	var INVALID_BASE64_RE = /[^+\/0-9A-Za-z-_]/g

	function base64clean (str) {
	  // Node strips out invalid characters like \n and \t from the string, base64-js does not
	  str = stringtrim(str).replace(INVALID_BASE64_RE, '')
	  // Node converts strings with length < 2 to ''
	  if (str.length < 2) return ''
	  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
	  while (str.length % 4 !== 0) {
	    str = str + '='
	  }
	  return str
	}

	function stringtrim (str) {
	  if (str.trim) return str.trim()
	  return str.replace(/^\s+|\s+$/g, '')
	}

	function toHex (n) {
	  if (n < 16) return '0' + n.toString(16)
	  return n.toString(16)
	}

	function utf8ToBytes (string, units) {
	  units = units || Infinity
	  var codePoint
	  var length = string.length
	  var leadSurrogate = null
	  var bytes = []

	  for (var i = 0; i < length; i++) {
	    codePoint = string.charCodeAt(i)

	    // is surrogate component
	    if (codePoint > 0xD7FF && codePoint < 0xE000) {
	      // last char was a lead
	      if (!leadSurrogate) {
	        // no lead yet
	        if (codePoint > 0xDBFF) {
	          // unexpected trail
	          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
	          continue
	        } else if (i + 1 === length) {
	          // unpaired lead
	          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
	          continue
	        }

	        // valid lead
	        leadSurrogate = codePoint

	        continue
	      }

	      // 2 leads in a row
	      if (codePoint < 0xDC00) {
	        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
	        leadSurrogate = codePoint
	        continue
	      }

	      // valid surrogate pair
	      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
	    } else if (leadSurrogate) {
	      // valid bmp char, but last char was a lead
	      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
	    }

	    leadSurrogate = null

	    // encode utf8
	    if (codePoint < 0x80) {
	      if ((units -= 1) < 0) break
	      bytes.push(codePoint)
	    } else if (codePoint < 0x800) {
	      if ((units -= 2) < 0) break
	      bytes.push(
	        codePoint >> 0x6 | 0xC0,
	        codePoint & 0x3F | 0x80
	      )
	    } else if (codePoint < 0x10000) {
	      if ((units -= 3) < 0) break
	      bytes.push(
	        codePoint >> 0xC | 0xE0,
	        codePoint >> 0x6 & 0x3F | 0x80,
	        codePoint & 0x3F | 0x80
	      )
	    } else if (codePoint < 0x110000) {
	      if ((units -= 4) < 0) break
	      bytes.push(
	        codePoint >> 0x12 | 0xF0,
	        codePoint >> 0xC & 0x3F | 0x80,
	        codePoint >> 0x6 & 0x3F | 0x80,
	        codePoint & 0x3F | 0x80
	      )
	    } else {
	      throw new Error('Invalid code point')
	    }
	  }

	  return bytes
	}

	function asciiToBytes (str) {
	  var byteArray = []
	  for (var i = 0; i < str.length; i++) {
	    // Node's code seems to be doing this and not & 0x7F..
	    byteArray.push(str.charCodeAt(i) & 0xFF)
	  }
	  return byteArray
	}

	function utf16leToBytes (str, units) {
	  var c, hi, lo
	  var byteArray = []
	  for (var i = 0; i < str.length; i++) {
	    if ((units -= 2) < 0) break

	    c = str.charCodeAt(i)
	    hi = c >> 8
	    lo = c % 256
	    byteArray.push(lo)
	    byteArray.push(hi)
	  }

	  return byteArray
	}

	function base64ToBytes (str) {
	  return base64.toByteArray(base64clean(str))
	}

	function blitBuffer (src, dst, offset, length) {
	  for (var i = 0; i < length; i++) {
	    if ((i + offset >= dst.length) || (i >= src.length)) break
	    dst[i + offset] = src[i]
	  }
	  return i
	}

	/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(3).Buffer, (function() { return this; }())))

/***/ },
/* 4 */
/***/ function(module, exports, __webpack_require__) {

	var lookup = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

	;(function (exports) {
		'use strict';

	  var Arr = (typeof Uint8Array !== 'undefined')
	    ? Uint8Array
	    : Array

		var PLUS   = '+'.charCodeAt(0)
		var SLASH  = '/'.charCodeAt(0)
		var NUMBER = '0'.charCodeAt(0)
		var LOWER  = 'a'.charCodeAt(0)
		var UPPER  = 'A'.charCodeAt(0)
		var PLUS_URL_SAFE = '-'.charCodeAt(0)
		var SLASH_URL_SAFE = '_'.charCodeAt(0)

		function decode (elt) {
			var code = elt.charCodeAt(0)
			if (code === PLUS ||
			    code === PLUS_URL_SAFE)
				return 62 // '+'
			if (code === SLASH ||
			    code === SLASH_URL_SAFE)
				return 63 // '/'
			if (code < NUMBER)
				return -1 //no match
			if (code < NUMBER + 10)
				return code - NUMBER + 26 + 26
			if (code < UPPER + 26)
				return code - UPPER
			if (code < LOWER + 26)
				return code - LOWER + 26
		}

		function b64ToByteArray (b64) {
			var i, j, l, tmp, placeHolders, arr

			if (b64.length % 4 > 0) {
				throw new Error('Invalid string. Length must be a multiple of 4')
			}

			// the number of equal signs (place holders)
			// if there are two placeholders, than the two characters before it
			// represent one byte
			// if there is only one, then the three characters before it represent 2 bytes
			// this is just a cheap hack to not do indexOf twice
			var len = b64.length
			placeHolders = '=' === b64.charAt(len - 2) ? 2 : '=' === b64.charAt(len - 1) ? 1 : 0

			// base64 is 4/3 + up to two characters of the original data
			arr = new Arr(b64.length * 3 / 4 - placeHolders)

			// if there are placeholders, only get up to the last complete 4 chars
			l = placeHolders > 0 ? b64.length - 4 : b64.length

			var L = 0

			function push (v) {
				arr[L++] = v
			}

			for (i = 0, j = 0; i < l; i += 4, j += 3) {
				tmp = (decode(b64.charAt(i)) << 18) | (decode(b64.charAt(i + 1)) << 12) | (decode(b64.charAt(i + 2)) << 6) | decode(b64.charAt(i + 3))
				push((tmp & 0xFF0000) >> 16)
				push((tmp & 0xFF00) >> 8)
				push(tmp & 0xFF)
			}

			if (placeHolders === 2) {
				tmp = (decode(b64.charAt(i)) << 2) | (decode(b64.charAt(i + 1)) >> 4)
				push(tmp & 0xFF)
			} else if (placeHolders === 1) {
				tmp = (decode(b64.charAt(i)) << 10) | (decode(b64.charAt(i + 1)) << 4) | (decode(b64.charAt(i + 2)) >> 2)
				push((tmp >> 8) & 0xFF)
				push(tmp & 0xFF)
			}

			return arr
		}

		function uint8ToBase64 (uint8) {
			var i,
				extraBytes = uint8.length % 3, // if we have 1 byte left, pad 2 bytes
				output = "",
				temp, length

			function encode (num) {
				return lookup.charAt(num)
			}

			function tripletToBase64 (num) {
				return encode(num >> 18 & 0x3F) + encode(num >> 12 & 0x3F) + encode(num >> 6 & 0x3F) + encode(num & 0x3F)
			}

			// go through the array every three bytes, we'll deal with trailing stuff later
			for (i = 0, length = uint8.length - extraBytes; i < length; i += 3) {
				temp = (uint8[i] << 16) + (uint8[i + 1] << 8) + (uint8[i + 2])
				output += tripletToBase64(temp)
			}

			// pad the end with zeros, but make sure to not forget the extra bytes
			switch (extraBytes) {
				case 1:
					temp = uint8[uint8.length - 1]
					output += encode(temp >> 2)
					output += encode((temp << 4) & 0x3F)
					output += '=='
					break
				case 2:
					temp = (uint8[uint8.length - 2] << 8) + (uint8[uint8.length - 1])
					output += encode(temp >> 10)
					output += encode((temp >> 4) & 0x3F)
					output += encode((temp << 2) & 0x3F)
					output += '='
					break
			}

			return output
		}

		exports.toByteArray = b64ToByteArray
		exports.fromByteArray = uint8ToBase64
	}( false ? (this.base64js = {}) : exports))


/***/ },
/* 5 */
/***/ function(module, exports) {

	exports.read = function (buffer, offset, isLE, mLen, nBytes) {
	  var e, m
	  var eLen = nBytes * 8 - mLen - 1
	  var eMax = (1 << eLen) - 1
	  var eBias = eMax >> 1
	  var nBits = -7
	  var i = isLE ? (nBytes - 1) : 0
	  var d = isLE ? -1 : 1
	  var s = buffer[offset + i]

	  i += d

	  e = s & ((1 << (-nBits)) - 1)
	  s >>= (-nBits)
	  nBits += eLen
	  for (; nBits > 0; e = e * 256 + buffer[offset + i], i += d, nBits -= 8) {}

	  m = e & ((1 << (-nBits)) - 1)
	  e >>= (-nBits)
	  nBits += mLen
	  for (; nBits > 0; m = m * 256 + buffer[offset + i], i += d, nBits -= 8) {}

	  if (e === 0) {
	    e = 1 - eBias
	  } else if (e === eMax) {
	    return m ? NaN : ((s ? -1 : 1) * Infinity)
	  } else {
	    m = m + Math.pow(2, mLen)
	    e = e - eBias
	  }
	  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
	}

	exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
	  var e, m, c
	  var eLen = nBytes * 8 - mLen - 1
	  var eMax = (1 << eLen) - 1
	  var eBias = eMax >> 1
	  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
	  var i = isLE ? 0 : (nBytes - 1)
	  var d = isLE ? 1 : -1
	  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

	  value = Math.abs(value)

	  if (isNaN(value) || value === Infinity) {
	    m = isNaN(value) ? 1 : 0
	    e = eMax
	  } else {
	    e = Math.floor(Math.log(value) / Math.LN2)
	    if (value * (c = Math.pow(2, -e)) < 1) {
	      e--
	      c *= 2
	    }
	    if (e + eBias >= 1) {
	      value += rt / c
	    } else {
	      value += rt * Math.pow(2, 1 - eBias)
	    }
	    if (value * c >= 2) {
	      e++
	      c /= 2
	    }

	    if (e + eBias >= eMax) {
	      m = 0
	      e = eMax
	    } else if (e + eBias >= 1) {
	      m = (value * c - 1) * Math.pow(2, mLen)
	      e = e + eBias
	    } else {
	      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
	      e = 0
	    }
	  }

	  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

	  e = (e << mLen) | m
	  eLen += mLen
	  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

	  buffer[offset + i - d] |= s * 128
	}


/***/ },
/* 6 */
/***/ function(module, exports) {

	var toString = {}.toString;

	module.exports = Array.isArray || function (arr) {
	  return toString.call(arr) == '[object Array]';
	};


/***/ },
/* 7 */
/***/ function(module, exports, __webpack_require__) {

	/* WEBPACK VAR INJECTION */(function(global, Buffer) {(function() {
	  var g = ('undefined' === typeof window ? global : window) || {}
	  _crypto = (
	    g.crypto || g.msCrypto || __webpack_require__(8)
	  )
	  module.exports = function(size) {
	    // Modern Browsers
	    if(_crypto.getRandomValues) {
	      var bytes = new Buffer(size); //in browserify, this is an extended Uint8Array
	      /* This will not work in older browsers.
	       * See https://developer.mozilla.org/en-US/docs/Web/API/window.crypto.getRandomValues
	       */
	    
	      _crypto.getRandomValues(bytes);
	      return bytes;
	    }
	    else if (_crypto.randomBytes) {
	      return _crypto.randomBytes(size)
	    }
	    else
	      throw new Error(
	        'secure random number generation not supported by this browser\n'+
	        'use chrome, FireFox or Internet Explorer 11'
	      )
	  }
	}())

	/* WEBPACK VAR INJECTION */}.call(exports, (function() { return this; }()), __webpack_require__(3).Buffer))

/***/ },
/* 8 */
/***/ function(module, exports) {

	/* (ignored) */

/***/ },
/* 9 */
/***/ function(module, exports, __webpack_require__) {

	/* WEBPACK VAR INJECTION */(function(Buffer) {var createHash = __webpack_require__(10)

	var md5 = toConstructor(__webpack_require__(19))
	var rmd160 = toConstructor(__webpack_require__(21))

	function toConstructor (fn) {
	  return function () {
	    var buffers = []
	    var m= {
	      update: function (data, enc) {
	        if(!Buffer.isBuffer(data)) data = new Buffer(data, enc)
	        buffers.push(data)
	        return this
	      },
	      digest: function (enc) {
	        var buf = Buffer.concat(buffers)
	        var r = fn(buf)
	        buffers = null
	        return enc ? r.toString(enc) : r
	      }
	    }
	    return m
	  }
	}

	module.exports = function (alg) {
	  if('md5' === alg) return new md5()
	  if('rmd160' === alg) return new rmd160()
	  return createHash(alg)
	}

	/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(3).Buffer))

/***/ },
/* 10 */
/***/ function(module, exports, __webpack_require__) {

	var exports = module.exports = function (alg) {
	  var Alg = exports[alg]
	  if(!Alg) throw new Error(alg + ' is not supported (we accept pull requests)')
	  return new Alg()
	}

	var Buffer = __webpack_require__(3).Buffer
	var Hash   = __webpack_require__(11)(Buffer)

	exports.sha1 = __webpack_require__(12)(Buffer, Hash)
	exports.sha256 = __webpack_require__(17)(Buffer, Hash)
	exports.sha512 = __webpack_require__(18)(Buffer, Hash)


/***/ },
/* 11 */
/***/ function(module, exports) {

	module.exports = function (Buffer) {

	  //prototype class for hash functions
	  function Hash (blockSize, finalSize) {
	    this._block = new Buffer(blockSize) //new Uint32Array(blockSize/4)
	    this._finalSize = finalSize
	    this._blockSize = blockSize
	    this._len = 0
	    this._s = 0
	  }

	  Hash.prototype.init = function () {
	    this._s = 0
	    this._len = 0
	  }

	  Hash.prototype.update = function (data, enc) {
	    if ("string" === typeof data) {
	      enc = enc || "utf8"
	      data = new Buffer(data, enc)
	    }

	    var l = this._len += data.length
	    var s = this._s = (this._s || 0)
	    var f = 0
	    var buffer = this._block

	    while (s < l) {
	      var t = Math.min(data.length, f + this._blockSize - (s % this._blockSize))
	      var ch = (t - f)

	      for (var i = 0; i < ch; i++) {
	        buffer[(s % this._blockSize) + i] = data[i + f]
	      }

	      s += ch
	      f += ch

	      if ((s % this._blockSize) === 0) {
	        this._update(buffer)
	      }
	    }
	    this._s = s

	    return this
	  }

	  Hash.prototype.digest = function (enc) {
	    // Suppose the length of the message M, in bits, is l
	    var l = this._len * 8

	    // Append the bit 1 to the end of the message
	    this._block[this._len % this._blockSize] = 0x80

	    // and then k zero bits, where k is the smallest non-negative solution to the equation (l + 1 + k) === finalSize mod blockSize
	    this._block.fill(0, this._len % this._blockSize + 1)

	    if (l % (this._blockSize * 8) >= this._finalSize * 8) {
	      this._update(this._block)
	      this._block.fill(0)
	    }

	    // to this append the block which is equal to the number l written in binary
	    // TODO: handle case where l is > Math.pow(2, 29)
	    this._block.writeInt32BE(l, this._blockSize - 4)

	    var hash = this._update(this._block) || this._hash()

	    return enc ? hash.toString(enc) : hash
	  }

	  Hash.prototype._update = function () {
	    throw new Error('_update must be implemented by subclass')
	  }

	  return Hash
	}


/***/ },
/* 12 */
/***/ function(module, exports, __webpack_require__) {

	/*
	 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
	 * in FIPS PUB 180-1
	 * Version 2.1a Copyright Paul Johnston 2000 - 2002.
	 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
	 * Distributed under the BSD License
	 * See http://pajhome.org.uk/crypt/md5 for details.
	 */

	var inherits = __webpack_require__(13).inherits

	module.exports = function (Buffer, Hash) {

	  var A = 0|0
	  var B = 4|0
	  var C = 8|0
	  var D = 12|0
	  var E = 16|0

	  var W = new (typeof Int32Array === 'undefined' ? Array : Int32Array)(80)

	  var POOL = []

	  function Sha1 () {
	    if(POOL.length)
	      return POOL.pop().init()

	    if(!(this instanceof Sha1)) return new Sha1()
	    this._w = W
	    Hash.call(this, 16*4, 14*4)

	    this._h = null
	    this.init()
	  }

	  inherits(Sha1, Hash)

	  Sha1.prototype.init = function () {
	    this._a = 0x67452301
	    this._b = 0xefcdab89
	    this._c = 0x98badcfe
	    this._d = 0x10325476
	    this._e = 0xc3d2e1f0

	    Hash.prototype.init.call(this)
	    return this
	  }

	  Sha1.prototype._POOL = POOL
	  Sha1.prototype._update = function (X) {

	    var a, b, c, d, e, _a, _b, _c, _d, _e

	    a = _a = this._a
	    b = _b = this._b
	    c = _c = this._c
	    d = _d = this._d
	    e = _e = this._e

	    var w = this._w

	    for(var j = 0; j < 80; j++) {
	      var W = w[j] = j < 16 ? X.readInt32BE(j*4)
	        : rol(w[j - 3] ^ w[j -  8] ^ w[j - 14] ^ w[j - 16], 1)

	      var t = add(
	        add(rol(a, 5), sha1_ft(j, b, c, d)),
	        add(add(e, W), sha1_kt(j))
	      )

	      e = d
	      d = c
	      c = rol(b, 30)
	      b = a
	      a = t
	    }

	    this._a = add(a, _a)
	    this._b = add(b, _b)
	    this._c = add(c, _c)
	    this._d = add(d, _d)
	    this._e = add(e, _e)
	  }

	  Sha1.prototype._hash = function () {
	    if(POOL.length < 100) POOL.push(this)
	    var H = new Buffer(20)
	    //console.log(this._a|0, this._b|0, this._c|0, this._d|0, this._e|0)
	    H.writeInt32BE(this._a|0, A)
	    H.writeInt32BE(this._b|0, B)
	    H.writeInt32BE(this._c|0, C)
	    H.writeInt32BE(this._d|0, D)
	    H.writeInt32BE(this._e|0, E)
	    return H
	  }

	  /*
	   * Perform the appropriate triplet combination function for the current
	   * iteration
	   */
	  function sha1_ft(t, b, c, d) {
	    if(t < 20) return (b & c) | ((~b) & d);
	    if(t < 40) return b ^ c ^ d;
	    if(t < 60) return (b & c) | (b & d) | (c & d);
	    return b ^ c ^ d;
	  }

	  /*
	   * Determine the appropriate additive constant for the current iteration
	   */
	  function sha1_kt(t) {
	    return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
	           (t < 60) ? -1894007588 : -899497514;
	  }

	  /*
	   * Add integers, wrapping at 2^32. This uses 16-bit operations internally
	   * to work around bugs in some JS interpreters.
	   * //dominictarr: this is 10 years old, so maybe this can be dropped?)
	   *
	   */
	  function add(x, y) {
	    return (x + y ) | 0
	  //lets see how this goes on testling.
	  //  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
	  //  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
	  //  return (msw << 16) | (lsw & 0xFFFF);
	  }

	  /*
	   * Bitwise rotate a 32-bit number to the left.
	   */
	  function rol(num, cnt) {
	    return (num << cnt) | (num >>> (32 - cnt));
	  }

	  return Sha1
	}


/***/ },
/* 13 */
/***/ function(module, exports, __webpack_require__) {

	/* WEBPACK VAR INJECTION */(function(global, process) {// Copyright Joyent, Inc. and other Node contributors.
	//
	// Permission is hereby granted, free of charge, to any person obtaining a
	// copy of this software and associated documentation files (the
	// "Software"), to deal in the Software without restriction, including
	// without limitation the rights to use, copy, modify, merge, publish,
	// distribute, sublicense, and/or sell copies of the Software, and to permit
	// persons to whom the Software is furnished to do so, subject to the
	// following conditions:
	//
	// The above copyright notice and this permission notice shall be included
	// in all copies or substantial portions of the Software.
	//
	// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
	// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
	// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
	// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
	// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
	// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
	// USE OR OTHER DEALINGS IN THE SOFTWARE.

	var formatRegExp = /%[sdj%]/g;
	exports.format = function(f) {
	  if (!isString(f)) {
	    var objects = [];
	    for (var i = 0; i < arguments.length; i++) {
	      objects.push(inspect(arguments[i]));
	    }
	    return objects.join(' ');
	  }

	  var i = 1;
	  var args = arguments;
	  var len = args.length;
	  var str = String(f).replace(formatRegExp, function(x) {
	    if (x === '%%') return '%';
	    if (i >= len) return x;
	    switch (x) {
	      case '%s': return String(args[i++]);
	      case '%d': return Number(args[i++]);
	      case '%j':
	        try {
	          return JSON.stringify(args[i++]);
	        } catch (_) {
	          return '[Circular]';
	        }
	      default:
	        return x;
	    }
	  });
	  for (var x = args[i]; i < len; x = args[++i]) {
	    if (isNull(x) || !isObject(x)) {
	      str += ' ' + x;
	    } else {
	      str += ' ' + inspect(x);
	    }
	  }
	  return str;
	};


	// Mark that a method should not be used.
	// Returns a modified function which warns once by default.
	// If --no-deprecation is set, then it is a no-op.
	exports.deprecate = function(fn, msg) {
	  // Allow for deprecating things in the process of starting up.
	  if (isUndefined(global.process)) {
	    return function() {
	      return exports.deprecate(fn, msg).apply(this, arguments);
	    };
	  }

	  if (process.noDeprecation === true) {
	    return fn;
	  }

	  var warned = false;
	  function deprecated() {
	    if (!warned) {
	      if (process.throwDeprecation) {
	        throw new Error(msg);
	      } else if (process.traceDeprecation) {
	        console.trace(msg);
	      } else {
	        console.error(msg);
	      }
	      warned = true;
	    }
	    return fn.apply(this, arguments);
	  }

	  return deprecated;
	};


	var debugs = {};
	var debugEnviron;
	exports.debuglog = function(set) {
	  if (isUndefined(debugEnviron))
	    debugEnviron = process.env.NODE_DEBUG || '';
	  set = set.toUpperCase();
	  if (!debugs[set]) {
	    if (new RegExp('\\b' + set + '\\b', 'i').test(debugEnviron)) {
	      var pid = process.pid;
	      debugs[set] = function() {
	        var msg = exports.format.apply(exports, arguments);
	        console.error('%s %d: %s', set, pid, msg);
	      };
	    } else {
	      debugs[set] = function() {};
	    }
	  }
	  return debugs[set];
	};


	/**
	 * Echos the value of a value. Trys to print the value out
	 * in the best way possible given the different types.
	 *
	 * @param {Object} obj The object to print out.
	 * @param {Object} opts Optional options object that alters the output.
	 */
	/* legacy: obj, showHidden, depth, colors*/
	function inspect(obj, opts) {
	  // default options
	  var ctx = {
	    seen: [],
	    stylize: stylizeNoColor
	  };
	  // legacy...
	  if (arguments.length >= 3) ctx.depth = arguments[2];
	  if (arguments.length >= 4) ctx.colors = arguments[3];
	  if (isBoolean(opts)) {
	    // legacy...
	    ctx.showHidden = opts;
	  } else if (opts) {
	    // got an "options" object
	    exports._extend(ctx, opts);
	  }
	  // set default options
	  if (isUndefined(ctx.showHidden)) ctx.showHidden = false;
	  if (isUndefined(ctx.depth)) ctx.depth = 2;
	  if (isUndefined(ctx.colors)) ctx.colors = false;
	  if (isUndefined(ctx.customInspect)) ctx.customInspect = true;
	  if (ctx.colors) ctx.stylize = stylizeWithColor;
	  return formatValue(ctx, obj, ctx.depth);
	}
	exports.inspect = inspect;


	// http://en.wikipedia.org/wiki/ANSI_escape_code#graphics
	inspect.colors = {
	  'bold' : [1, 22],
	  'italic' : [3, 23],
	  'underline' : [4, 24],
	  'inverse' : [7, 27],
	  'white' : [37, 39],
	  'grey' : [90, 39],
	  'black' : [30, 39],
	  'blue' : [34, 39],
	  'cyan' : [36, 39],
	  'green' : [32, 39],
	  'magenta' : [35, 39],
	  'red' : [31, 39],
	  'yellow' : [33, 39]
	};

	// Don't use 'blue' not visible on cmd.exe
	inspect.styles = {
	  'special': 'cyan',
	  'number': 'yellow',
	  'boolean': 'yellow',
	  'undefined': 'grey',
	  'null': 'bold',
	  'string': 'green',
	  'date': 'magenta',
	  // "name": intentionally not styling
	  'regexp': 'red'
	};


	function stylizeWithColor(str, styleType) {
	  var style = inspect.styles[styleType];

	  if (style) {
	    return '\u001b[' + inspect.colors[style][0] + 'm' + str +
	           '\u001b[' + inspect.colors[style][1] + 'm';
	  } else {
	    return str;
	  }
	}


	function stylizeNoColor(str, styleType) {
	  return str;
	}


	function arrayToHash(array) {
	  var hash = {};

	  array.forEach(function(val, idx) {
	    hash[val] = true;
	  });

	  return hash;
	}


	function formatValue(ctx, value, recurseTimes) {
	  // Provide a hook for user-specified inspect functions.
	  // Check that value is an object with an inspect function on it
	  if (ctx.customInspect &&
	      value &&
	      isFunction(value.inspect) &&
	      // Filter out the util module, it's inspect function is special
	      value.inspect !== exports.inspect &&
	      // Also filter out any prototype objects using the circular check.
	      !(value.constructor && value.constructor.prototype === value)) {
	    var ret = value.inspect(recurseTimes, ctx);
	    if (!isString(ret)) {
	      ret = formatValue(ctx, ret, recurseTimes);
	    }
	    return ret;
	  }

	  // Primitive types cannot have properties
	  var primitive = formatPrimitive(ctx, value);
	  if (primitive) {
	    return primitive;
	  }

	  // Look up the keys of the object.
	  var keys = Object.keys(value);
	  var visibleKeys = arrayToHash(keys);

	  if (ctx.showHidden) {
	    keys = Object.getOwnPropertyNames(value);
	  }

	  // IE doesn't make error fields non-enumerable
	  // http://msdn.microsoft.com/en-us/library/ie/dww52sbt(v=vs.94).aspx
	  if (isError(value)
	      && (keys.indexOf('message') >= 0 || keys.indexOf('description') >= 0)) {
	    return formatError(value);
	  }

	  // Some type of object without properties can be shortcutted.
	  if (keys.length === 0) {
	    if (isFunction(value)) {
	      var name = value.name ? ': ' + value.name : '';
	      return ctx.stylize('[Function' + name + ']', 'special');
	    }
	    if (isRegExp(value)) {
	      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
	    }
	    if (isDate(value)) {
	      return ctx.stylize(Date.prototype.toString.call(value), 'date');
	    }
	    if (isError(value)) {
	      return formatError(value);
	    }
	  }

	  var base = '', array = false, braces = ['{', '}'];

	  // Make Array say that they are Array
	  if (isArray(value)) {
	    array = true;
	    braces = ['[', ']'];
	  }

	  // Make functions say that they are functions
	  if (isFunction(value)) {
	    var n = value.name ? ': ' + value.name : '';
	    base = ' [Function' + n + ']';
	  }

	  // Make RegExps say that they are RegExps
	  if (isRegExp(value)) {
	    base = ' ' + RegExp.prototype.toString.call(value);
	  }

	  // Make dates with properties first say the date
	  if (isDate(value)) {
	    base = ' ' + Date.prototype.toUTCString.call(value);
	  }

	  // Make error with message first say the error
	  if (isError(value)) {
	    base = ' ' + formatError(value);
	  }

	  if (keys.length === 0 && (!array || value.length == 0)) {
	    return braces[0] + base + braces[1];
	  }

	  if (recurseTimes < 0) {
	    if (isRegExp(value)) {
	      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
	    } else {
	      return ctx.stylize('[Object]', 'special');
	    }
	  }

	  ctx.seen.push(value);

	  var output;
	  if (array) {
	    output = formatArray(ctx, value, recurseTimes, visibleKeys, keys);
	  } else {
	    output = keys.map(function(key) {
	      return formatProperty(ctx, value, recurseTimes, visibleKeys, key, array);
	    });
	  }

	  ctx.seen.pop();

	  return reduceToSingleString(output, base, braces);
	}


	function formatPrimitive(ctx, value) {
	  if (isUndefined(value))
	    return ctx.stylize('undefined', 'undefined');
	  if (isString(value)) {
	    var simple = '\'' + JSON.stringify(value).replace(/^"|"$/g, '')
	                                             .replace(/'/g, "\\'")
	                                             .replace(/\\"/g, '"') + '\'';
	    return ctx.stylize(simple, 'string');
	  }
	  if (isNumber(value))
	    return ctx.stylize('' + value, 'number');
	  if (isBoolean(value))
	    return ctx.stylize('' + value, 'boolean');
	  // For some reason typeof null is "object", so special case here.
	  if (isNull(value))
	    return ctx.stylize('null', 'null');
	}


	function formatError(value) {
	  return '[' + Error.prototype.toString.call(value) + ']';
	}


	function formatArray(ctx, value, recurseTimes, visibleKeys, keys) {
	  var output = [];
	  for (var i = 0, l = value.length; i < l; ++i) {
	    if (hasOwnProperty(value, String(i))) {
	      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
	          String(i), true));
	    } else {
	      output.push('');
	    }
	  }
	  keys.forEach(function(key) {
	    if (!key.match(/^\d+$/)) {
	      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
	          key, true));
	    }
	  });
	  return output;
	}


	function formatProperty(ctx, value, recurseTimes, visibleKeys, key, array) {
	  var name, str, desc;
	  desc = Object.getOwnPropertyDescriptor(value, key) || { value: value[key] };
	  if (desc.get) {
	    if (desc.set) {
	      str = ctx.stylize('[Getter/Setter]', 'special');
	    } else {
	      str = ctx.stylize('[Getter]', 'special');
	    }
	  } else {
	    if (desc.set) {
	      str = ctx.stylize('[Setter]', 'special');
	    }
	  }
	  if (!hasOwnProperty(visibleKeys, key)) {
	    name = '[' + key + ']';
	  }
	  if (!str) {
	    if (ctx.seen.indexOf(desc.value) < 0) {
	      if (isNull(recurseTimes)) {
	        str = formatValue(ctx, desc.value, null);
	      } else {
	        str = formatValue(ctx, desc.value, recurseTimes - 1);
	      }
	      if (str.indexOf('\n') > -1) {
	        if (array) {
	          str = str.split('\n').map(function(line) {
	            return '  ' + line;
	          }).join('\n').substr(2);
	        } else {
	          str = '\n' + str.split('\n').map(function(line) {
	            return '   ' + line;
	          }).join('\n');
	        }
	      }
	    } else {
	      str = ctx.stylize('[Circular]', 'special');
	    }
	  }
	  if (isUndefined(name)) {
	    if (array && key.match(/^\d+$/)) {
	      return str;
	    }
	    name = JSON.stringify('' + key);
	    if (name.match(/^"([a-zA-Z_][a-zA-Z_0-9]*)"$/)) {
	      name = name.substr(1, name.length - 2);
	      name = ctx.stylize(name, 'name');
	    } else {
	      name = name.replace(/'/g, "\\'")
	                 .replace(/\\"/g, '"')
	                 .replace(/(^"|"$)/g, "'");
	      name = ctx.stylize(name, 'string');
	    }
	  }

	  return name + ': ' + str;
	}


	function reduceToSingleString(output, base, braces) {
	  var numLinesEst = 0;
	  var length = output.reduce(function(prev, cur) {
	    numLinesEst++;
	    if (cur.indexOf('\n') >= 0) numLinesEst++;
	    return prev + cur.replace(/\u001b\[\d\d?m/g, '').length + 1;
	  }, 0);

	  if (length > 60) {
	    return braces[0] +
	           (base === '' ? '' : base + '\n ') +
	           ' ' +
	           output.join(',\n  ') +
	           ' ' +
	           braces[1];
	  }

	  return braces[0] + base + ' ' + output.join(', ') + ' ' + braces[1];
	}


	// NOTE: These type checking functions intentionally don't use `instanceof`
	// because it is fragile and can be easily faked with `Object.create()`.
	function isArray(ar) {
	  return Array.isArray(ar);
	}
	exports.isArray = isArray;

	function isBoolean(arg) {
	  return typeof arg === 'boolean';
	}
	exports.isBoolean = isBoolean;

	function isNull(arg) {
	  return arg === null;
	}
	exports.isNull = isNull;

	function isNullOrUndefined(arg) {
	  return arg == null;
	}
	exports.isNullOrUndefined = isNullOrUndefined;

	function isNumber(arg) {
	  return typeof arg === 'number';
	}
	exports.isNumber = isNumber;

	function isString(arg) {
	  return typeof arg === 'string';
	}
	exports.isString = isString;

	function isSymbol(arg) {
	  return typeof arg === 'symbol';
	}
	exports.isSymbol = isSymbol;

	function isUndefined(arg) {
	  return arg === void 0;
	}
	exports.isUndefined = isUndefined;

	function isRegExp(re) {
	  return isObject(re) && objectToString(re) === '[object RegExp]';
	}
	exports.isRegExp = isRegExp;

	function isObject(arg) {
	  return typeof arg === 'object' && arg !== null;
	}
	exports.isObject = isObject;

	function isDate(d) {
	  return isObject(d) && objectToString(d) === '[object Date]';
	}
	exports.isDate = isDate;

	function isError(e) {
	  return isObject(e) &&
	      (objectToString(e) === '[object Error]' || e instanceof Error);
	}
	exports.isError = isError;

	function isFunction(arg) {
	  return typeof arg === 'function';
	}
	exports.isFunction = isFunction;

	function isPrimitive(arg) {
	  return arg === null ||
	         typeof arg === 'boolean' ||
	         typeof arg === 'number' ||
	         typeof arg === 'string' ||
	         typeof arg === 'symbol' ||  // ES6 symbol
	         typeof arg === 'undefined';
	}
	exports.isPrimitive = isPrimitive;

	exports.isBuffer = __webpack_require__(15);

	function objectToString(o) {
	  return Object.prototype.toString.call(o);
	}


	function pad(n) {
	  return n < 10 ? '0' + n.toString(10) : n.toString(10);
	}


	var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
	              'Oct', 'Nov', 'Dec'];

	// 26 Feb 16:19:34
	function timestamp() {
	  var d = new Date();
	  var time = [pad(d.getHours()),
	              pad(d.getMinutes()),
	              pad(d.getSeconds())].join(':');
	  return [d.getDate(), months[d.getMonth()], time].join(' ');
	}


	// log is just a thin wrapper to console.log that prepends a timestamp
	exports.log = function() {
	  console.log('%s - %s', timestamp(), exports.format.apply(exports, arguments));
	};


	/**
	 * Inherit the prototype methods from one constructor into another.
	 *
	 * The Function.prototype.inherits from lang.js rewritten as a standalone
	 * function (not on Function.prototype). NOTE: If this file is to be loaded
	 * during bootstrapping this function needs to be rewritten using some native
	 * functions as prototype setup using normal JavaScript does not work as
	 * expected during bootstrapping (see mirror.js in r114903).
	 *
	 * @param {function} ctor Constructor function which needs to inherit the
	 *     prototype.
	 * @param {function} superCtor Constructor function to inherit prototype from.
	 */
	exports.inherits = __webpack_require__(16);

	exports._extend = function(origin, add) {
	  // Don't do anything if add isn't an object
	  if (!add || !isObject(add)) return origin;

	  var keys = Object.keys(add);
	  var i = keys.length;
	  while (i--) {
	    origin[keys[i]] = add[keys[i]];
	  }
	  return origin;
	};

	function hasOwnProperty(obj, prop) {
	  return Object.prototype.hasOwnProperty.call(obj, prop);
	}

	/* WEBPACK VAR INJECTION */}.call(exports, (function() { return this; }()), __webpack_require__(14)))

/***/ },
/* 14 */
/***/ function(module, exports) {

	// shim for using process in browser

	var process = module.exports = {};
	var queue = [];
	var draining = false;
	var currentQueue;
	var queueIndex = -1;

	function cleanUpNextTick() {
	    draining = false;
	    if (currentQueue.length) {
	        queue = currentQueue.concat(queue);
	    } else {
	        queueIndex = -1;
	    }
	    if (queue.length) {
	        drainQueue();
	    }
	}

	function drainQueue() {
	    if (draining) {
	        return;
	    }
	    var timeout = setTimeout(cleanUpNextTick);
	    draining = true;

	    var len = queue.length;
	    while(len) {
	        currentQueue = queue;
	        queue = [];
	        while (++queueIndex < len) {
	            if (currentQueue) {
	                currentQueue[queueIndex].run();
	            }
	        }
	        queueIndex = -1;
	        len = queue.length;
	    }
	    currentQueue = null;
	    draining = false;
	    clearTimeout(timeout);
	}

	process.nextTick = function (fun) {
	    var args = new Array(arguments.length - 1);
	    if (arguments.length > 1) {
	        for (var i = 1; i < arguments.length; i++) {
	            args[i - 1] = arguments[i];
	        }
	    }
	    queue.push(new Item(fun, args));
	    if (queue.length === 1 && !draining) {
	        setTimeout(drainQueue, 0);
	    }
	};

	// v8 likes predictible objects
	function Item(fun, array) {
	    this.fun = fun;
	    this.array = array;
	}
	Item.prototype.run = function () {
	    this.fun.apply(null, this.array);
	};
	process.title = 'browser';
	process.browser = true;
	process.env = {};
	process.argv = [];
	process.version = ''; // empty string to avoid regexp issues
	process.versions = {};

	function noop() {}

	process.on = noop;
	process.addListener = noop;
	process.once = noop;
	process.off = noop;
	process.removeListener = noop;
	process.removeAllListeners = noop;
	process.emit = noop;

	process.binding = function (name) {
	    throw new Error('process.binding is not supported');
	};

	process.cwd = function () { return '/' };
	process.chdir = function (dir) {
	    throw new Error('process.chdir is not supported');
	};
	process.umask = function() { return 0; };


/***/ },
/* 15 */
/***/ function(module, exports) {

	module.exports = function isBuffer(arg) {
	  return arg && typeof arg === 'object'
	    && typeof arg.copy === 'function'
	    && typeof arg.fill === 'function'
	    && typeof arg.readUInt8 === 'function';
	}

/***/ },
/* 16 */
/***/ function(module, exports) {

	if (typeof Object.create === 'function') {
	  // implementation from standard node.js 'util' module
	  module.exports = function inherits(ctor, superCtor) {
	    ctor.super_ = superCtor
	    ctor.prototype = Object.create(superCtor.prototype, {
	      constructor: {
	        value: ctor,
	        enumerable: false,
	        writable: true,
	        configurable: true
	      }
	    });
	  };
	} else {
	  // old school shim for old browsers
	  module.exports = function inherits(ctor, superCtor) {
	    ctor.super_ = superCtor
	    var TempCtor = function () {}
	    TempCtor.prototype = superCtor.prototype
	    ctor.prototype = new TempCtor()
	    ctor.prototype.constructor = ctor
	  }
	}


/***/ },
/* 17 */
/***/ function(module, exports, __webpack_require__) {

	
	/**
	 * A JavaScript implementation of the Secure Hash Algorithm, SHA-256, as defined
	 * in FIPS 180-2
	 * Version 2.2-beta Copyright Angel Marin, Paul Johnston 2000 - 2009.
	 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
	 *
	 */

	var inherits = __webpack_require__(13).inherits

	module.exports = function (Buffer, Hash) {

	  var K = [
	      0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
	      0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	      0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	      0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	      0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
	      0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	      0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
	      0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	      0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	      0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	      0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
	      0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	      0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
	      0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	      0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	      0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
	    ]

	  var W = new Array(64)

	  function Sha256() {
	    this.init()

	    this._w = W //new Array(64)

	    Hash.call(this, 16*4, 14*4)
	  }

	  inherits(Sha256, Hash)

	  Sha256.prototype.init = function () {

	    this._a = 0x6a09e667|0
	    this._b = 0xbb67ae85|0
	    this._c = 0x3c6ef372|0
	    this._d = 0xa54ff53a|0
	    this._e = 0x510e527f|0
	    this._f = 0x9b05688c|0
	    this._g = 0x1f83d9ab|0
	    this._h = 0x5be0cd19|0

	    this._len = this._s = 0

	    return this
	  }

	  function S (X, n) {
	    return (X >>> n) | (X << (32 - n));
	  }

	  function R (X, n) {
	    return (X >>> n);
	  }

	  function Ch (x, y, z) {
	    return ((x & y) ^ ((~x) & z));
	  }

	  function Maj (x, y, z) {
	    return ((x & y) ^ (x & z) ^ (y & z));
	  }

	  function Sigma0256 (x) {
	    return (S(x, 2) ^ S(x, 13) ^ S(x, 22));
	  }

	  function Sigma1256 (x) {
	    return (S(x, 6) ^ S(x, 11) ^ S(x, 25));
	  }

	  function Gamma0256 (x) {
	    return (S(x, 7) ^ S(x, 18) ^ R(x, 3));
	  }

	  function Gamma1256 (x) {
	    return (S(x, 17) ^ S(x, 19) ^ R(x, 10));
	  }

	  Sha256.prototype._update = function(M) {

	    var W = this._w
	    var a, b, c, d, e, f, g, h
	    var T1, T2

	    a = this._a | 0
	    b = this._b | 0
	    c = this._c | 0
	    d = this._d | 0
	    e = this._e | 0
	    f = this._f | 0
	    g = this._g | 0
	    h = this._h | 0

	    for (var j = 0; j < 64; j++) {
	      var w = W[j] = j < 16
	        ? M.readInt32BE(j * 4)
	        : Gamma1256(W[j - 2]) + W[j - 7] + Gamma0256(W[j - 15]) + W[j - 16]

	      T1 = h + Sigma1256(e) + Ch(e, f, g) + K[j] + w

	      T2 = Sigma0256(a) + Maj(a, b, c);
	      h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
	    }

	    this._a = (a + this._a) | 0
	    this._b = (b + this._b) | 0
	    this._c = (c + this._c) | 0
	    this._d = (d + this._d) | 0
	    this._e = (e + this._e) | 0
	    this._f = (f + this._f) | 0
	    this._g = (g + this._g) | 0
	    this._h = (h + this._h) | 0

	  };

	  Sha256.prototype._hash = function () {
	    var H = new Buffer(32)

	    H.writeInt32BE(this._a,  0)
	    H.writeInt32BE(this._b,  4)
	    H.writeInt32BE(this._c,  8)
	    H.writeInt32BE(this._d, 12)
	    H.writeInt32BE(this._e, 16)
	    H.writeInt32BE(this._f, 20)
	    H.writeInt32BE(this._g, 24)
	    H.writeInt32BE(this._h, 28)

	    return H
	  }

	  return Sha256

	}


/***/ },
/* 18 */
/***/ function(module, exports, __webpack_require__) {

	var inherits = __webpack_require__(13).inherits

	module.exports = function (Buffer, Hash) {
	  var K = [
	    0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd,
	    0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
	    0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
	    0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
	    0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe,
	    0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
	    0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1,
	    0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
	    0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
	    0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
	    0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483,
	    0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
	    0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210,
	    0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
	    0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
	    0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
	    0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926,
	    0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
	    0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8,
	    0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
	    0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
	    0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
	    0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910,
	    0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
	    0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53,
	    0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
	    0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
	    0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
	    0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60,
	    0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
	    0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9,
	    0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
	    0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
	    0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
	    0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6,
	    0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
	    0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493,
	    0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
	    0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
	    0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
	  ]

	  var W = new Array(160)

	  function Sha512() {
	    this.init()
	    this._w = W

	    Hash.call(this, 128, 112)
	  }

	  inherits(Sha512, Hash)

	  Sha512.prototype.init = function () {

	    this._a = 0x6a09e667|0
	    this._b = 0xbb67ae85|0
	    this._c = 0x3c6ef372|0
	    this._d = 0xa54ff53a|0
	    this._e = 0x510e527f|0
	    this._f = 0x9b05688c|0
	    this._g = 0x1f83d9ab|0
	    this._h = 0x5be0cd19|0

	    this._al = 0xf3bcc908|0
	    this._bl = 0x84caa73b|0
	    this._cl = 0xfe94f82b|0
	    this._dl = 0x5f1d36f1|0
	    this._el = 0xade682d1|0
	    this._fl = 0x2b3e6c1f|0
	    this._gl = 0xfb41bd6b|0
	    this._hl = 0x137e2179|0

	    this._len = this._s = 0

	    return this
	  }

	  function S (X, Xl, n) {
	    return (X >>> n) | (Xl << (32 - n))
	  }

	  function Ch (x, y, z) {
	    return ((x & y) ^ ((~x) & z));
	  }

	  function Maj (x, y, z) {
	    return ((x & y) ^ (x & z) ^ (y & z));
	  }

	  Sha512.prototype._update = function(M) {

	    var W = this._w
	    var a, b, c, d, e, f, g, h
	    var al, bl, cl, dl, el, fl, gl, hl

	    a = this._a | 0
	    b = this._b | 0
	    c = this._c | 0
	    d = this._d | 0
	    e = this._e | 0
	    f = this._f | 0
	    g = this._g | 0
	    h = this._h | 0

	    al = this._al | 0
	    bl = this._bl | 0
	    cl = this._cl | 0
	    dl = this._dl | 0
	    el = this._el | 0
	    fl = this._fl | 0
	    gl = this._gl | 0
	    hl = this._hl | 0

	    for (var i = 0; i < 80; i++) {
	      var j = i * 2

	      var Wi, Wil

	      if (i < 16) {
	        Wi = W[j] = M.readInt32BE(j * 4)
	        Wil = W[j + 1] = M.readInt32BE(j * 4 + 4)

	      } else {
	        var x  = W[j - 15*2]
	        var xl = W[j - 15*2 + 1]
	        var gamma0  = S(x, xl, 1) ^ S(x, xl, 8) ^ (x >>> 7)
	        var gamma0l = S(xl, x, 1) ^ S(xl, x, 8) ^ S(xl, x, 7)

	        x  = W[j - 2*2]
	        xl = W[j - 2*2 + 1]
	        var gamma1  = S(x, xl, 19) ^ S(xl, x, 29) ^ (x >>> 6)
	        var gamma1l = S(xl, x, 19) ^ S(x, xl, 29) ^ S(xl, x, 6)

	        // W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16]
	        var Wi7  = W[j - 7*2]
	        var Wi7l = W[j - 7*2 + 1]

	        var Wi16  = W[j - 16*2]
	        var Wi16l = W[j - 16*2 + 1]

	        Wil = gamma0l + Wi7l
	        Wi  = gamma0  + Wi7 + ((Wil >>> 0) < (gamma0l >>> 0) ? 1 : 0)
	        Wil = Wil + gamma1l
	        Wi  = Wi  + gamma1  + ((Wil >>> 0) < (gamma1l >>> 0) ? 1 : 0)
	        Wil = Wil + Wi16l
	        Wi  = Wi  + Wi16 + ((Wil >>> 0) < (Wi16l >>> 0) ? 1 : 0)

	        W[j] = Wi
	        W[j + 1] = Wil
	      }

	      var maj = Maj(a, b, c)
	      var majl = Maj(al, bl, cl)

	      var sigma0h = S(a, al, 28) ^ S(al, a, 2) ^ S(al, a, 7)
	      var sigma0l = S(al, a, 28) ^ S(a, al, 2) ^ S(a, al, 7)
	      var sigma1h = S(e, el, 14) ^ S(e, el, 18) ^ S(el, e, 9)
	      var sigma1l = S(el, e, 14) ^ S(el, e, 18) ^ S(e, el, 9)

	      // t1 = h + sigma1 + ch + K[i] + W[i]
	      var Ki = K[j]
	      var Kil = K[j + 1]

	      var ch = Ch(e, f, g)
	      var chl = Ch(el, fl, gl)

	      var t1l = hl + sigma1l
	      var t1 = h + sigma1h + ((t1l >>> 0) < (hl >>> 0) ? 1 : 0)
	      t1l = t1l + chl
	      t1 = t1 + ch + ((t1l >>> 0) < (chl >>> 0) ? 1 : 0)
	      t1l = t1l + Kil
	      t1 = t1 + Ki + ((t1l >>> 0) < (Kil >>> 0) ? 1 : 0)
	      t1l = t1l + Wil
	      t1 = t1 + Wi + ((t1l >>> 0) < (Wil >>> 0) ? 1 : 0)

	      // t2 = sigma0 + maj
	      var t2l = sigma0l + majl
	      var t2 = sigma0h + maj + ((t2l >>> 0) < (sigma0l >>> 0) ? 1 : 0)

	      h  = g
	      hl = gl
	      g  = f
	      gl = fl
	      f  = e
	      fl = el
	      el = (dl + t1l) | 0
	      e  = (d + t1 + ((el >>> 0) < (dl >>> 0) ? 1 : 0)) | 0
	      d  = c
	      dl = cl
	      c  = b
	      cl = bl
	      b  = a
	      bl = al
	      al = (t1l + t2l) | 0
	      a  = (t1 + t2 + ((al >>> 0) < (t1l >>> 0) ? 1 : 0)) | 0
	    }

	    this._al = (this._al + al) | 0
	    this._bl = (this._bl + bl) | 0
	    this._cl = (this._cl + cl) | 0
	    this._dl = (this._dl + dl) | 0
	    this._el = (this._el + el) | 0
	    this._fl = (this._fl + fl) | 0
	    this._gl = (this._gl + gl) | 0
	    this._hl = (this._hl + hl) | 0

	    this._a = (this._a + a + ((this._al >>> 0) < (al >>> 0) ? 1 : 0)) | 0
	    this._b = (this._b + b + ((this._bl >>> 0) < (bl >>> 0) ? 1 : 0)) | 0
	    this._c = (this._c + c + ((this._cl >>> 0) < (cl >>> 0) ? 1 : 0)) | 0
	    this._d = (this._d + d + ((this._dl >>> 0) < (dl >>> 0) ? 1 : 0)) | 0
	    this._e = (this._e + e + ((this._el >>> 0) < (el >>> 0) ? 1 : 0)) | 0
	    this._f = (this._f + f + ((this._fl >>> 0) < (fl >>> 0) ? 1 : 0)) | 0
	    this._g = (this._g + g + ((this._gl >>> 0) < (gl >>> 0) ? 1 : 0)) | 0
	    this._h = (this._h + h + ((this._hl >>> 0) < (hl >>> 0) ? 1 : 0)) | 0
	  }

	  Sha512.prototype._hash = function () {
	    var H = new Buffer(64)

	    function writeInt64BE(h, l, offset) {
	      H.writeInt32BE(h, offset)
	      H.writeInt32BE(l, offset + 4)
	    }

	    writeInt64BE(this._a, this._al, 0)
	    writeInt64BE(this._b, this._bl, 8)
	    writeInt64BE(this._c, this._cl, 16)
	    writeInt64BE(this._d, this._dl, 24)
	    writeInt64BE(this._e, this._el, 32)
	    writeInt64BE(this._f, this._fl, 40)
	    writeInt64BE(this._g, this._gl, 48)
	    writeInt64BE(this._h, this._hl, 56)

	    return H
	  }

	  return Sha512

	}


/***/ },
/* 19 */
/***/ function(module, exports, __webpack_require__) {

	/*
	 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
	 * Digest Algorithm, as defined in RFC 1321.
	 * Version 2.1 Copyright (C) Paul Johnston 1999 - 2002.
	 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
	 * Distributed under the BSD License
	 * See http://pajhome.org.uk/crypt/md5 for more info.
	 */

	var helpers = __webpack_require__(20);

	/*
	 * Calculate the MD5 of an array of little-endian words, and a bit length
	 */
	function core_md5(x, len)
	{
	  /* append padding */
	  x[len >> 5] |= 0x80 << ((len) % 32);
	  x[(((len + 64) >>> 9) << 4) + 14] = len;

	  var a =  1732584193;
	  var b = -271733879;
	  var c = -1732584194;
	  var d =  271733878;

	  for(var i = 0; i < x.length; i += 16)
	  {
	    var olda = a;
	    var oldb = b;
	    var oldc = c;
	    var oldd = d;

	    a = md5_ff(a, b, c, d, x[i+ 0], 7 , -680876936);
	    d = md5_ff(d, a, b, c, x[i+ 1], 12, -389564586);
	    c = md5_ff(c, d, a, b, x[i+ 2], 17,  606105819);
	    b = md5_ff(b, c, d, a, x[i+ 3], 22, -1044525330);
	    a = md5_ff(a, b, c, d, x[i+ 4], 7 , -176418897);
	    d = md5_ff(d, a, b, c, x[i+ 5], 12,  1200080426);
	    c = md5_ff(c, d, a, b, x[i+ 6], 17, -1473231341);
	    b = md5_ff(b, c, d, a, x[i+ 7], 22, -45705983);
	    a = md5_ff(a, b, c, d, x[i+ 8], 7 ,  1770035416);
	    d = md5_ff(d, a, b, c, x[i+ 9], 12, -1958414417);
	    c = md5_ff(c, d, a, b, x[i+10], 17, -42063);
	    b = md5_ff(b, c, d, a, x[i+11], 22, -1990404162);
	    a = md5_ff(a, b, c, d, x[i+12], 7 ,  1804603682);
	    d = md5_ff(d, a, b, c, x[i+13], 12, -40341101);
	    c = md5_ff(c, d, a, b, x[i+14], 17, -1502002290);
	    b = md5_ff(b, c, d, a, x[i+15], 22,  1236535329);

	    a = md5_gg(a, b, c, d, x[i+ 1], 5 , -165796510);
	    d = md5_gg(d, a, b, c, x[i+ 6], 9 , -1069501632);
	    c = md5_gg(c, d, a, b, x[i+11], 14,  643717713);
	    b = md5_gg(b, c, d, a, x[i+ 0], 20, -373897302);
	    a = md5_gg(a, b, c, d, x[i+ 5], 5 , -701558691);
	    d = md5_gg(d, a, b, c, x[i+10], 9 ,  38016083);
	    c = md5_gg(c, d, a, b, x[i+15], 14, -660478335);
	    b = md5_gg(b, c, d, a, x[i+ 4], 20, -405537848);
	    a = md5_gg(a, b, c, d, x[i+ 9], 5 ,  568446438);
	    d = md5_gg(d, a, b, c, x[i+14], 9 , -1019803690);
	    c = md5_gg(c, d, a, b, x[i+ 3], 14, -187363961);
	    b = md5_gg(b, c, d, a, x[i+ 8], 20,  1163531501);
	    a = md5_gg(a, b, c, d, x[i+13], 5 , -1444681467);
	    d = md5_gg(d, a, b, c, x[i+ 2], 9 , -51403784);
	    c = md5_gg(c, d, a, b, x[i+ 7], 14,  1735328473);
	    b = md5_gg(b, c, d, a, x[i+12], 20, -1926607734);

	    a = md5_hh(a, b, c, d, x[i+ 5], 4 , -378558);
	    d = md5_hh(d, a, b, c, x[i+ 8], 11, -2022574463);
	    c = md5_hh(c, d, a, b, x[i+11], 16,  1839030562);
	    b = md5_hh(b, c, d, a, x[i+14], 23, -35309556);
	    a = md5_hh(a, b, c, d, x[i+ 1], 4 , -1530992060);
	    d = md5_hh(d, a, b, c, x[i+ 4], 11,  1272893353);
	    c = md5_hh(c, d, a, b, x[i+ 7], 16, -155497632);
	    b = md5_hh(b, c, d, a, x[i+10], 23, -1094730640);
	    a = md5_hh(a, b, c, d, x[i+13], 4 ,  681279174);
	    d = md5_hh(d, a, b, c, x[i+ 0], 11, -358537222);
	    c = md5_hh(c, d, a, b, x[i+ 3], 16, -722521979);
	    b = md5_hh(b, c, d, a, x[i+ 6], 23,  76029189);
	    a = md5_hh(a, b, c, d, x[i+ 9], 4 , -640364487);
	    d = md5_hh(d, a, b, c, x[i+12], 11, -421815835);
	    c = md5_hh(c, d, a, b, x[i+15], 16,  530742520);
	    b = md5_hh(b, c, d, a, x[i+ 2], 23, -995338651);

	    a = md5_ii(a, b, c, d, x[i+ 0], 6 , -198630844);
	    d = md5_ii(d, a, b, c, x[i+ 7], 10,  1126891415);
	    c = md5_ii(c, d, a, b, x[i+14], 15, -1416354905);
	    b = md5_ii(b, c, d, a, x[i+ 5], 21, -57434055);
	    a = md5_ii(a, b, c, d, x[i+12], 6 ,  1700485571);
	    d = md5_ii(d, a, b, c, x[i+ 3], 10, -1894986606);
	    c = md5_ii(c, d, a, b, x[i+10], 15, -1051523);
	    b = md5_ii(b, c, d, a, x[i+ 1], 21, -2054922799);
	    a = md5_ii(a, b, c, d, x[i+ 8], 6 ,  1873313359);
	    d = md5_ii(d, a, b, c, x[i+15], 10, -30611744);
	    c = md5_ii(c, d, a, b, x[i+ 6], 15, -1560198380);
	    b = md5_ii(b, c, d, a, x[i+13], 21,  1309151649);
	    a = md5_ii(a, b, c, d, x[i+ 4], 6 , -145523070);
	    d = md5_ii(d, a, b, c, x[i+11], 10, -1120210379);
	    c = md5_ii(c, d, a, b, x[i+ 2], 15,  718787259);
	    b = md5_ii(b, c, d, a, x[i+ 9], 21, -343485551);

	    a = safe_add(a, olda);
	    b = safe_add(b, oldb);
	    c = safe_add(c, oldc);
	    d = safe_add(d, oldd);
	  }
	  return Array(a, b, c, d);

	}

	/*
	 * These functions implement the four basic operations the algorithm uses.
	 */
	function md5_cmn(q, a, b, x, s, t)
	{
	  return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s),b);
	}
	function md5_ff(a, b, c, d, x, s, t)
	{
	  return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
	}
	function md5_gg(a, b, c, d, x, s, t)
	{
	  return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
	}
	function md5_hh(a, b, c, d, x, s, t)
	{
	  return md5_cmn(b ^ c ^ d, a, b, x, s, t);
	}
	function md5_ii(a, b, c, d, x, s, t)
	{
	  return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
	}

	/*
	 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
	 * to work around bugs in some JS interpreters.
	 */
	function safe_add(x, y)
	{
	  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
	  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
	  return (msw << 16) | (lsw & 0xFFFF);
	}

	/*
	 * Bitwise rotate a 32-bit number to the left.
	 */
	function bit_rol(num, cnt)
	{
	  return (num << cnt) | (num >>> (32 - cnt));
	}

	module.exports = function md5(buf) {
	  return helpers.hash(buf, core_md5, 16);
	};


/***/ },
/* 20 */
/***/ function(module, exports, __webpack_require__) {

	/* WEBPACK VAR INJECTION */(function(Buffer) {var intSize = 4;
	var zeroBuffer = new Buffer(intSize); zeroBuffer.fill(0);
	var chrsz = 8;

	function toArray(buf, bigEndian) {
	  if ((buf.length % intSize) !== 0) {
	    var len = buf.length + (intSize - (buf.length % intSize));
	    buf = Buffer.concat([buf, zeroBuffer], len);
	  }

	  var arr = [];
	  var fn = bigEndian ? buf.readInt32BE : buf.readInt32LE;
	  for (var i = 0; i < buf.length; i += intSize) {
	    arr.push(fn.call(buf, i));
	  }
	  return arr;
	}

	function toBuffer(arr, size, bigEndian) {
	  var buf = new Buffer(size);
	  var fn = bigEndian ? buf.writeInt32BE : buf.writeInt32LE;
	  for (var i = 0; i < arr.length; i++) {
	    fn.call(buf, arr[i], i * 4, true);
	  }
	  return buf;
	}

	function hash(buf, fn, hashSize, bigEndian) {
	  if (!Buffer.isBuffer(buf)) buf = new Buffer(buf);
	  var arr = fn(toArray(buf, bigEndian), buf.length * chrsz);
	  return toBuffer(arr, hashSize, bigEndian);
	}

	module.exports = { hash: hash };

	/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(3).Buffer))

/***/ },
/* 21 */
/***/ function(module, exports, __webpack_require__) {

	/* WEBPACK VAR INJECTION */(function(Buffer) {
	module.exports = ripemd160



	/*
	CryptoJS v3.1.2
	code.google.com/p/crypto-js
	(c) 2009-2013 by Jeff Mott. All rights reserved.
	code.google.com/p/crypto-js/wiki/License
	*/
	/** @preserve
	(c) 2012 by Cédric Mesnil. All rights reserved.

	Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

	    - Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
	    - Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
	*/

	// Constants table
	var zl = [
	    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
	    7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
	    3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
	    1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
	    4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13];
	var zr = [
	    5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
	    6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
	    15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
	    8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
	    12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11];
	var sl = [
	     11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
	    7, 6,   8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
	    11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
	      11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
	    9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6 ];
	var sr = [
	    8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
	    9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
	    9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
	    15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
	    8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11 ];

	var hl =  [ 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E];
	var hr =  [ 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000];

	var bytesToWords = function (bytes) {
	  var words = [];
	  for (var i = 0, b = 0; i < bytes.length; i++, b += 8) {
	    words[b >>> 5] |= bytes[i] << (24 - b % 32);
	  }
	  return words;
	};

	var wordsToBytes = function (words) {
	  var bytes = [];
	  for (var b = 0; b < words.length * 32; b += 8) {
	    bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
	  }
	  return bytes;
	};

	var processBlock = function (H, M, offset) {

	  // Swap endian
	  for (var i = 0; i < 16; i++) {
	    var offset_i = offset + i;
	    var M_offset_i = M[offset_i];

	    // Swap
	    M[offset_i] = (
	        (((M_offset_i << 8)  | (M_offset_i >>> 24)) & 0x00ff00ff) |
	        (((M_offset_i << 24) | (M_offset_i >>> 8))  & 0xff00ff00)
	    );
	  }

	  // Working variables
	  var al, bl, cl, dl, el;
	  var ar, br, cr, dr, er;

	  ar = al = H[0];
	  br = bl = H[1];
	  cr = cl = H[2];
	  dr = dl = H[3];
	  er = el = H[4];
	  // Computation
	  var t;
	  for (var i = 0; i < 80; i += 1) {
	    t = (al +  M[offset+zl[i]])|0;
	    if (i<16){
	        t +=  f1(bl,cl,dl) + hl[0];
	    } else if (i<32) {
	        t +=  f2(bl,cl,dl) + hl[1];
	    } else if (i<48) {
	        t +=  f3(bl,cl,dl) + hl[2];
	    } else if (i<64) {
	        t +=  f4(bl,cl,dl) + hl[3];
	    } else {// if (i<80) {
	        t +=  f5(bl,cl,dl) + hl[4];
	    }
	    t = t|0;
	    t =  rotl(t,sl[i]);
	    t = (t+el)|0;
	    al = el;
	    el = dl;
	    dl = rotl(cl, 10);
	    cl = bl;
	    bl = t;

	    t = (ar + M[offset+zr[i]])|0;
	    if (i<16){
	        t +=  f5(br,cr,dr) + hr[0];
	    } else if (i<32) {
	        t +=  f4(br,cr,dr) + hr[1];
	    } else if (i<48) {
	        t +=  f3(br,cr,dr) + hr[2];
	    } else if (i<64) {
	        t +=  f2(br,cr,dr) + hr[3];
	    } else {// if (i<80) {
	        t +=  f1(br,cr,dr) + hr[4];
	    }
	    t = t|0;
	    t =  rotl(t,sr[i]) ;
	    t = (t+er)|0;
	    ar = er;
	    er = dr;
	    dr = rotl(cr, 10);
	    cr = br;
	    br = t;
	  }
	  // Intermediate hash value
	  t    = (H[1] + cl + dr)|0;
	  H[1] = (H[2] + dl + er)|0;
	  H[2] = (H[3] + el + ar)|0;
	  H[3] = (H[4] + al + br)|0;
	  H[4] = (H[0] + bl + cr)|0;
	  H[0] =  t;
	};

	function f1(x, y, z) {
	  return ((x) ^ (y) ^ (z));
	}

	function f2(x, y, z) {
	  return (((x)&(y)) | ((~x)&(z)));
	}

	function f3(x, y, z) {
	  return (((x) | (~(y))) ^ (z));
	}

	function f4(x, y, z) {
	  return (((x) & (z)) | ((y)&(~(z))));
	}

	function f5(x, y, z) {
	  return ((x) ^ ((y) |(~(z))));
	}

	function rotl(x,n) {
	  return (x<<n) | (x>>>(32-n));
	}

	function ripemd160(message) {
	  var H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

	  if (typeof message == 'string')
	    message = new Buffer(message, 'utf8');

	  var m = bytesToWords(message);

	  var nBitsLeft = message.length * 8;
	  var nBitsTotal = message.length * 8;

	  // Add padding
	  m[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
	  m[(((nBitsLeft + 64) >>> 9) << 4) + 14] = (
	      (((nBitsTotal << 8)  | (nBitsTotal >>> 24)) & 0x00ff00ff) |
	      (((nBitsTotal << 24) | (nBitsTotal >>> 8))  & 0xff00ff00)
	  );

	  for (var i=0 ; i<m.length; i += 16) {
	    processBlock(H, m, i);
	  }

	  // Swap endian
	  for (var i = 0; i < 5; i++) {
	      // Shortcut
	    var H_i = H[i];

	    // Swap
	    H[i] = (((H_i << 8)  | (H_i >>> 24)) & 0x00ff00ff) |
	          (((H_i << 24) | (H_i >>> 8))  & 0xff00ff00);
	  }

	  var digestbytes = wordsToBytes(H);
	  return new Buffer(digestbytes);
	}



	/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(3).Buffer))

/***/ },
/* 22 */
/***/ function(module, exports, __webpack_require__) {

	/* WEBPACK VAR INJECTION */(function(Buffer) {var createHash = __webpack_require__(9)

	var zeroBuffer = new Buffer(128)
	zeroBuffer.fill(0)

	module.exports = Hmac

	function Hmac (alg, key) {
	  if(!(this instanceof Hmac)) return new Hmac(alg, key)
	  this._opad = opad
	  this._alg = alg

	  var blocksize = (alg === 'sha512') ? 128 : 64

	  key = this._key = !Buffer.isBuffer(key) ? new Buffer(key) : key

	  if(key.length > blocksize) {
	    key = createHash(alg).update(key).digest()
	  } else if(key.length < blocksize) {
	    key = Buffer.concat([key, zeroBuffer], blocksize)
	  }

	  var ipad = this._ipad = new Buffer(blocksize)
	  var opad = this._opad = new Buffer(blocksize)

	  for(var i = 0; i < blocksize; i++) {
	    ipad[i] = key[i] ^ 0x36
	    opad[i] = key[i] ^ 0x5C
	  }

	  this._hash = createHash(alg).update(ipad)
	}

	Hmac.prototype.update = function (data, enc) {
	  this._hash.update(data, enc)
	  return this
	}

	Hmac.prototype.digest = function (enc) {
	  var h = this._hash.digest()
	  return createHash(this._alg).update(this._opad).update(h).digest(enc)
	}


	/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(3).Buffer))

/***/ },
/* 23 */
/***/ function(module, exports, __webpack_require__) {

	var pbkdf2Export = __webpack_require__(24)

	module.exports = function (crypto, exports) {
	  exports = exports || {}

	  var exported = pbkdf2Export(crypto)

	  exports.pbkdf2 = exported.pbkdf2
	  exports.pbkdf2Sync = exported.pbkdf2Sync

	  return exports
	}


/***/ },
/* 24 */
/***/ function(module, exports, __webpack_require__) {

	/* WEBPACK VAR INJECTION */(function(Buffer) {module.exports = function(crypto) {
	  function pbkdf2(password, salt, iterations, keylen, digest, callback) {
	    if ('function' === typeof digest) {
	      callback = digest
	      digest = undefined
	    }

	    if ('function' !== typeof callback)
	      throw new Error('No callback provided to pbkdf2')

	    setTimeout(function() {
	      var result

	      try {
	        result = pbkdf2Sync(password, salt, iterations, keylen, digest)
	      } catch (e) {
	        return callback(e)
	      }

	      callback(undefined, result)
	    })
	  }

	  function pbkdf2Sync(password, salt, iterations, keylen, digest) {
	    if ('number' !== typeof iterations)
	      throw new TypeError('Iterations not a number')

	    if (iterations < 0)
	      throw new TypeError('Bad iterations')

	    if ('number' !== typeof keylen)
	      throw new TypeError('Key length not a number')

	    if (keylen < 0)
	      throw new TypeError('Bad key length')

	    digest = digest || 'sha1'

	    if (!Buffer.isBuffer(password)) password = new Buffer(password)
	    if (!Buffer.isBuffer(salt)) salt = new Buffer(salt)

	    var hLen, l = 1, r, T
	    var DK = new Buffer(keylen)
	    var block1 = new Buffer(salt.length + 4)
	    salt.copy(block1, 0, 0, salt.length)

	    for (var i = 1; i <= l; i++) {
	      block1.writeUInt32BE(i, salt.length)

	      var U = crypto.createHmac(digest, password).update(block1).digest()

	      if (!hLen) {
	        hLen = U.length
	        T = new Buffer(hLen)
	        l = Math.ceil(keylen / hLen)
	        r = keylen - (l - 1) * hLen

	        if (keylen > (Math.pow(2, 32) - 1) * hLen)
	          throw new TypeError('keylen exceeds maximum length')
	      }

	      U.copy(T, 0, 0, hLen)

	      for (var j = 1; j < iterations; j++) {
	        U = crypto.createHmac(digest, password).update(U).digest()

	        for (var k = 0; k < hLen; k++) {
	          T[k] ^= U[k]
	        }
	      }

	      var destPos = (i - 1) * hLen
	      var len = (i == l ? r : hLen)
	      T.copy(DK, destPos, 0, len)
	    }

	    return DK
	  }

	  return {
	    pbkdf2: pbkdf2,
	    pbkdf2Sync: pbkdf2Sync
	  }
	}

	/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(3).Buffer))

/***/ }
/******/ ]);