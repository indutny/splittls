var stls = require('../splittls');
var Parser = stls.Parser;
var Framer = stls.Framer;

var tls = require('tls.js');
var net = require('net');
var util = require('util');

// XXX Just for testing
var bn = require('bn.js');
var asn1 = require('asn1.js');

var RSAPrivateKey = asn1.define('RSAPrivateKey', function() {
  this.seq().obj(
    this.key('version').int(),
    this.key('modulus').int(),
    this.key('publicExponent').int(),
    this.key('privateExponent').int(),
    this.key('prime1').int(),
    this.key('prime2').int(),
    this.key('exponent1').int(),
    this.key('exponent2').int(),
    this.key('coefficient').int()
  );
});

function Server(options) {
  net.Server.call(this);

  this.options = options;
  this.target = this.options.target;

  // XXX Just for testing
  if (/-----BEGIN RSA PRIVATE KEY-----/.test(options.key.toString())) {
    this.key = new Buffer(
        options.key.toString()
                   .replace(/-----BEGIN RSA PRIVATE KEY-----/g, '')
                   .replace(/-----END RSA PRIVATE KEY-----/g, '')
                   .replace(/[^\w\d\/\+=]+/g, ''),
        'base64');
  } else {
    this.key = options.key;
  }
  this.key = RSAPrivateKey.decode(this.key, 'der');
  this.red = bn.mont(this.key.modulus);

  this.prefetchCache = {};

  var self = this;
  this.channel = new net.Server(function(c) {
    self._handleChannel(c);
  }).listen(options.path);

  this.on('connection', function(c) {
    self._handleConnection(c);
  });
}
util.inherits(Server, net.Server);

exports.Server = Server;

exports.createServer = function createServer(options) {
  return new Server(options);
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
    var client = this.server.prefetchCache[key];
    if (!client)
      return this.socket.destroy();
    delete this.server.prefetchCache[key];

    var res = client.prefetchCache[key];
    if (!res)
      return this.socket.destroy();
    delete client.prefetchCache[key];

    this.framer.frame('modExpReply', res);
  }
};

Server.prototype._handleConnection = function _handleConnection(c) {
  var conn = new Connection(this, c);
};

function Connection(server, socket) {
  this.server = server;
  this.socket = socket;
  this.target = net.connect(server.target.port, server.target.host);

  this.state = new ConnectionState();
  this.parser = tls.parser.create(this.state);

  this.prefetchCache = {};

  this.socket.pipe(this.parser);
  this.target.pipe(this.socket);

  // TODO: figure it out from supported ciphers and clienthello
  this.cipher = 'rsa';
  this.buffer = null;

  var self = this;
  function onerror() {
    self.destroy();
  }
  this.socket.on('error', onerror);
  this.target.on('error', onerror);
  this.parser.on('error', onerror);
  this.socket.on('close', onerror);
  this.target.on('close', onerror);

  this.parser.on('data', function(rec) {
    self._handleRecord(rec);
  });
  this.parser.on('end', function() {
    self.target.end();
  });
}

Connection.prototype.destroy = function destroy() {
  this.socket.destroy();
  this.target.destroy();

  Object.keys(this.prefetchCache).forEach(function(key) {
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
    this.prefetch(rec.content, function(err) {
      if (err)
        return self.parser.emit('error', err);

      // Unqueue data
      var buf = self.buffer;
      self.buffer = null;
      for (var i = 0; i < buf.length; i++)
        self.target.write(buf[i]);
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
  var server = this.server;

  setTimeout(function() {
    var dec = new Buffer(new bn(data).toRed(server.red)
                                     .redPow(new bn(server.key.privateExponent))
                                     .fromRed()
                                     .toArray());

    var key = data.toString('hex');
    if (server.prefetchCache[key])
      return cb(null);

    self.prefetchCache[key] = dec;
    server.prefetchCache[key] = self;

    cb(null);
  }, 500);
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
