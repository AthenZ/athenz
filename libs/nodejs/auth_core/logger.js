const winston = require('winston');
const config = require('./config/config');
const console = new winston.transports.Console({ level: config.logLevel });

winston.add(console);

module.exports = winston;
