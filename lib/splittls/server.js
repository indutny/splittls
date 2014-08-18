var stls = require('../splittls');
var Parser = stls.Parser;
var Framer = stls.Framer;

var tls = require('tls.js');
var net = require('net');
var util = require('util');

function Server(options) {
  net.Server.call(this);

  this.options = options;
  this.target = this.options.target;

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
    this.framer.frame('modExpReply', new Buffer(64));
  }
};

Server.prototype._handleConnection = function _handleConnection(c) {
  var conn = new Connection(this, c);
};

function Connection(server, socket) {
  this.server = server;
  this.socket = socket;
  this.target = net.connect(server.target.port, server.target.host);

  var provider = tls.provider.node.create();
  var context = tls.context.create({ provider: provider });

  this.parser = tls.parser.create({ context: context });

  this.socket.pipe(this.parser);

  var self = this;
  this.socket.on('error', function() {
    self.destroy();
  });
  this.target.on('error', function() {
    self.destroy();
  });
  this.parser.on('data', function(rec) {
    self._handleRecord(rec);
  });
}

Connection.prototype.destroy = function destroy() {
  this.socket.destroy();
  this.target.destroy();
};

Connection.prototype._handleRecord = function _handleRecord(rec) {
  console.log(rec);
};
