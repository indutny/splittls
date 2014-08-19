var fs = require('fs');
var http = require('http');
var util = require('util');
var binding = require('bindings')('splittls-binding');
var Buffer = require('buffer').Buffer;

function Backend(options) {
  http.Server.call(this);

  this.options = util._extend({
    prefix: '/stls/'
  }, options);
  this.binding = new binding.Engine(fs.readFileSync(this.options.key));

  var self = this;
  this.on('request', function(req, res) {
    self._handleReq(req, res);
  });
}
util.inherits(Backend, http.Server);
exports.Backend = Backend;

exports.createBackend = function createBackend(options) {
  return new Backend(options);
};

Backend.prototype._handleReq = function _handleReq(req, res) {
  if (req.url.indexOf(this.options.prefix) !== 0) {
    res.writeHead(404);
    res.end();
    return;
  }

  var self = this;

  var url = req.url.replace(this.options.prefix, '');
  while (url[0] === '/')
    url = req.url.slice(1);

  var chunks = '';
  req.on('data', function(chunk) {
    chunks += chunk;
  });
  req.on('end', function() {
    try {
      chunks = JSON.parse(chunks);
    } catch (e) {
      done(e);
      return;
    }

    if (url === 'decrypt') {
      self._doDecrypt(chunks, done);
    } else {
      res.writeHead(404);
      res.end();
    }
  });

  function done(err, data) {
    if (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err && err.stack || err }));
      return;
    }

    var body = JSON.stringify({ response: data });
    res.writeHead(200, {
      'Content-Length': Buffer.byteLength(body),
      'Content-Type': 'application/json'
    });
    res.end(body);
  }
};

Backend.prototype._doDecrypt = function _doDecrypt(data, cb) {
  try {
    var dec = this.binding.modExp(new Buffer(data.data, 'hex')).toString('hex');
  } catch (e) {
    cb(e);
    return;
  }
  cb(null, dec);
};
