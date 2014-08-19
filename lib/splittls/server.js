var stls = require('../splittls');
var Parser = stls.Parser;
var Framer = stls.Framer;

var tls = require('tls.js');
var net = require('net');
var http = require('http');
var util = require('util');
var url = require('url');

function Server(options) {
  net.Server.call(this);

  this.options = util._extend({}, options);
  this.target = util._extend({
    host: '127.0.0.1',
    port: 4443
  }, this.options.target);
  this.backend = util._extend({
    host: '127.0.0.1',
    hostname: '127.0.0.1',
    port: 8000,
    prefix: '/stls/',
    maxSockets: 1024
  }, this.options.backend);
  this.backendAgent = new http.Agent(this.backend);

  this.prefetchCache = {};

  var self = this;
  this.channel = new net.Server(function(c) {
    self._handleChannel(c);
  }).listen(this.options.path || '/tmp/stls.sock');

  this.on('connection', function(c) {
    self._handleConnection(c);
  });
}
util.inherits(Server, net.Server);

exports.Server = Server;

exports.createServer = function createServer(options) {
  return new Server(options);
};

Server.prototype._backendReq = function _backendReq(method, path, body, cb) {
  var once = false;
  function done(err, data) {
    if (once)
      return;
    once = true;
    cb(err, data);
  }

  var uri = url.parse(url.resolve(this.backend.prefix, path));
  uri.agent = this.backendAgent;
  uri.method = method;
  uri.headers = {
    host: this.backend.hostname,
  };
  uri.host = this.backend.host;
  uri.port = this.backend.port;

  if (body) {
    body = '{"data":"' + body.toString('hex') + '"}';

    uri.headers['Content-Type'] = 'application/json';
    uri.headers['Content-Length'] = body.length;
  }

  var req = http.request(uri, function(res) {
    var chunks = '';
    if (res.statusCode < 200 || res.statusCode >= 400) {
      req.abort();
      return done(new Error('Bad backend status code: ' + res.statusCode));
    }

    res.on('data', function(chunk) {
      chunks += chunk;
    });
    res.on('end', function() {
      try {
        var reply = JSON.parse(chunks);
      } catch (e) {
        done(e);
        return;
      }
      done(null, reply);
    });
  })
  req.on('error', done);

  req.end(body);
};

Server.prototype._decrypt = function _decrypt(data, cb) {
  this._backendReq('POST', 'decrypt', data, cb);
};

Server.prototype._handleChannel = function _handleChannel(c) {
  var conn = new Channel(this, c);
};

function Channel(server, socket) {
  this.server = server;
  this.socket = socket;

  this.parser = new Parser();
  this.framer = new Framer();

  this.socket.on('error', function() {
    this.destroy();
  });

  this.socket.pipe(this.parser);
  this.framer.pipe(this.socket);

  var self = this;
  this.parser.on('data', function(frame) {
    self.handleFrame(frame);
  });
}

Channel.prototype.handleFrame = function handleFrame(frame) {
  // Version mismatch
  if (frame.version !== stls.constants.version)
    return this.socket.destroy();

  if (frame.type === 'modExp') {
    var key = frame.body.toString('hex');
    var entry = this.server.prefetchCache[key];
    if (!entry)
      return this.socket.destroy(new Error('No prefetched data'));
    if (--entry.ref === 0)
      delete this.server.prefetchCache[key];

    var res = entry.client.prefetchCache[key];
    if (!res)
      return this.socket.destroy(new Error('No prefetched data'));
    delete entry.client.prefetchCache[key];

    this.framer.frame('modExpReply', res);
  }
};

Server.prototype._handleConnection = function _handleConnection(c) {
  var conn = new Connection(this, c);
};

function Connection(server, socket) {
  this.server = server;
  this.socket = socket;
  this.target = net.connect(this.server.target);

  this.state = new ConnectionState();
  this.parser = tls.parser.create(this.state);

  this.prefetchCache = {};

  this.socket.pipe(this.parser);
  this.target.pipe(this.socket);

  // TODO: figure it out from supported ciphers and clienthello
  this.cipher = 'rsa';
  this.buffer = null;

  var self = this;
  function onerror(err) {
    self.destroy();
  }
  this.socket.on('error', onerror);
  this.target.on('error', onerror);
  this.parser.on('error', onerror);
  this.socket.on('close', onerror);
  this.target.on('close', onerror);

  // Handle records
  this.parser.on('data', function(rec) {
    self._handleRecord(rec);
  });
  this.parser.on('end', function() {
    self.target.end();
  });
}

Connection.prototype.destroy = function destroy() {
  this.socket.destroySoon();
  this.target.destroySoon();

  Object.keys(this.prefetchCache).forEach(function(key) {
    var entry = this.server.prefetchCache[key];
    if (entry && --entry.ref === 0)
      delete this.server.prefetchCache[key];
  }, this);
};

Connection.prototype._handleRecord = function _handleRecord(rec) {
  if (this.buffer) {
    this.buffer = this.buffer.concat(rec.buffers);
    return;
  }

  if (rec.type === 'handshake' && rec.handshakeType === 'client_key_exchange') {
    var self = this;

    this.buffer = rec.buffers;
    self.socket.unpipe(self.parser);

    this.prefetch(rec.content, function(err) {
      if (err)
        return self.parser.emit('error', err);

      // Unqueue data
      var buf = self.buffer;
      self.buffer = null;

      // Bypass parser
      if (!self.target._writableState.ending) {
        for (var i = 0; i < buf.length; i++)
          self.target.write(buf[i]);

        self.target.write(self.parser.getPending());
        self.socket.pipe(self.target);
      }
    });
    return;
  }

  for (var i = 0; i < rec.buffers.length; i++)
    this.target.write(rec.buffers[i]);
};

Connection.prototype.prefetch = function prefetch(content, cb) {
  if (this.cipher === 'rsa') {
    if (content.length < 2)
      return this.parser.emit('error', new Error('client_key_exchange OOB'));

    var len = content.readUInt16BE(0, true);
    if (content.length < 2 + len)
      return this.parser.emit('error', new Error('client_key_exchange OOB'));

    var secret = content.slice(2, 2 + len);
    this.decrypt(secret, cb);
  } else {
    cb(new Error('Unsupported cipher: ' + this.cipher));
  }
};

Connection.prototype.decrypt = function decrypt(data, cb) {
  var self = this;

  this.server._decrypt(data, function(err, dec) {
    if (err)
      return cb(err);

    var key = data.toString('hex').replace(/^(?:00)+/, '');
    if (self.server.prefetchCache[key]) {
      self.server.prefetchCache[key].ref++;
      return cb(null);
    }

    self.server.prefetchCache[key] = { ref: 1, client: self };
    self.prefetchCache[key] = new Buffer(dec.response, 'hex');

    cb(null);
  });
};

function ConnectionState() {
  this.encrypted = false;
}

ConnectionState.prototype.switchToPending = function switchToPending() {
  this.encrypted = true;
};

ConnectionState.prototype.decrypt = function decrypt(body, cb) {
  if (this.encrypted)
    return null;
  else
    return cb(body);
};
