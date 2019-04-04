'use strict';
const helmet = require('helmet');
const bodyParser = require('body-parser');
const os = require('os');
const winstonSNS = require('winston-sns');
const winstonNewRelic = require('winston-newrelic-update');

function checkSNSUsage(options) {
  const { alwaysUseSNS = false, useSNSLog = true, } = options;
  const env = this.settings.application.environment;

  if (alwaysUseSNS) {
    return true;
  } else {
    return useSNSLog && env !== 'development';
  }
}

function configureProductionLogger(options) {
  try {
    const { permittedCSP, cspConfig, useCORSDevOverride = true, useCORSOverride, useCSP = true, useHelmet = true, aws_key, aws_secret, subscriber, topic_arn, region,  useNewrelicLog = true, SNSLogLevel='info', } = options;
    const env = this.settings.application.environment;
   
    if (useHelmet) {
      const ninetyDaysInMilliseconds = 7776000000;
      this.app.use(helmet.frameguard({ action: 'sameorigin', }));
      this.app.use(helmet.hidePoweredBy());
      this.app.use(helmet.ieNoOpen());
      this.app.use(helmet.noSniff());
      this.app.use(helmet.xssFilter());
      this.app.use(helmet.hsts({
        maxAge: ninetyDaysInMilliseconds,     // Must be at least 18 weeks to be approved by Google
        includeSubDomains: true, // Must be enabled to be approved by Google
        preload: true,
      }));
    }
    if (useCSP) {
      const cspOptions = Object.assign({
        directives: {
          defaultSrc: permittedCSP,
          reportUri: '/report-violation',
          //objectSrc: [] // An empty array allows nothing through
        },
        // Set to true if you only want browsers to report errors, not block them
        reportOnly: true,
        // Set to true if you want to blindly set all headers: Content-Security-Policy,
        // X-WebKit-CSP, and X-Content-Security-Policy.
        setAllHeaders: false,
        // Set to true if you want to disable CSP on Android where it can be buggy.
        disableAndroid: true,
        // Set to false if you want to completely disable any user-agent sniffing.
        // This may make the headers less compatible but it will be much faster.
        // This defaults to `true`.
        browserSniff: true,
      }, cspConfig);
      const helmetCSP = helmet.contentSecurityPolicy(cspOptions);
      this.app.use(helmetCSP);
      this.app.post('/report-violation',
        bodyParser.json({
          type: ['json', 'application/csp-report',],
        }), (req, res) => {
          let userdata = {};
          if (req && req.user && req.user.email) {
            userdata = {
              email: req.user.email,
              username: req.user.username,
              firstname: req.user.firstname,
              lastname: req.user.lastname,
            };
          }
          if (req.body) {
            this.logger.warn('CSP Violation: ', {
              reqBody: req.body,
              ipinfo: {
                date: new Date(),
                'x-forwarded-for': req.headers[ 'x-forwarded-for' ],
                remoteAddress: req.connection.remoteAddress,
                originalUrl: req.originalUrl,
                headerHost: req.headers.host,
                userAgent: req.headers[ 'user-agent' ],
                referer: req.headers.referer,
                user: userdata,
                osHostname: os.hostname(),
              },
            });
          } else {
            this.logger.error('CSP Violation: No data received!');
          }
          res.status(204).end();
        });
    }
    if (checkSNSUsage.call(this, options)) {
      this.logger.add(winstonSNS, {
        aws_key,
        aws_secret,
        subscriber, // Subscriber number - found in your SNS AWS Console, after clicking on a topic. Same as AWS Account ID. [required]
        topic_arn, // Also found in SNS AWS Console - listed under a topic as Topic ARN. [required]
        region, //AWS Region to use. Can be one of: us-east-1,us-west-1,eu-west-1,ap-southeast-1,ap-northeast-1,us-gov-west-1,sa-east-1. (default: us-east-1)
        subject: this.settings.name + ' Server Log (%l) [' + env + ' - ' + os.hostname() + ']', // Subject for notifications. Uses placeholders for level (%l), error message (%e), and metadata (%m). (default: 'Winston Error Report')
        //message: Message of notifications. Uses placeholders for level (%l), error message (%e), and metadata (%m). (default: 'Level '%l' Error:\n%e\n\nMetadata:\n%m')
        message: 'Level \'%l\'\r\n Message:\r\n%e\r\n \r\nMetadata:\r\n%m',
        level: SNSLogLevel, //lowest level this transport will log. (default: info)
        json: true, // use json instead of a prettier (human friendly) string for meta information in the notification. (default: false)
        handleExceptions: true, // set to true to have this transport handle exceptions. (default: false)
      });
    }
    if (useNewrelicLog) {
      this.logger.add(winstonNewRelic, {});
    }
    this.logger.exitOnError = false;
    if (useCORSOverride || (useCORSDevOverride && env === 'development')) {
      this.app.all('*', function (req, res, next) {
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET,HEAD,OPTIONS,POST,DELETE,DEL,PUT');
        res.setHeader('Access-Control-Allow-Headers', 'Access-Control-Allow-Headers, Origin,Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers, entitytype, clientid, username, password, x-access-token, X-Access-Token');
        // console.log({ req })
        if (req.method === 'OPTIONS') {
          res.sendStatus(200);
          // next();
        } else {
          next();
        }
      });
    }
  } catch (e) {
    this.logger.error(e);
  }  
}

module.exports = {
  configureProductionLogger,
};