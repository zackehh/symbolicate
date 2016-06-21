const _ = require('lodash');
const fs = require('fs');
const path = require('path');
const cliff = require('cliff');
const express = require('express');
const bodyParser = require('body-parser');

const sym = require('../');

var app = express();

// IMPORTANT: Change this path to reflect the correct dSYM file.
var dSYMPath = '../sample/crash.dsym';

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

app.post('/crashreports', function(req, res, next) {
    var dir = './tmp';

    if (!fs.existsSync(dir)){
        fs.mkdirSync(dir);
    }

    var fname = `${Date.now()}.json`;
    var input = `tmp/input_${fname}`;
    var output = `tmp/output_${fname}`;

    console.log(`Received crash report saved at ${input}`);

    fs.writeFile(input, JSON.stringify(req.body, null, 2) , function (err) {
      if (err) {
        console.error(err);
        return next(err);
      }

      // Take the expected part of JSON from input and send to symbolication.
      sym.symbolicateCrashReport(dSYMPath, req.body.stack, function(err, report) {
        if (err) {
          console.error(err);
          return next(err);
        }

        prettyPrintReport(report);

        fs.writeFile(output, JSON.stringify(report, null, 2) , function (err) {
          if (err) {
            console.error(err);
            return next(err);
          }

          console.log(`Symbolicated report saved at ${output}`);

          var pretty_threads = _.each(report.crash.threads, function (thread) {
            console.log(`\nThread ${thread.index}`);
            console.log(cliff.stringifyObjectRows(thread.backtrace.contents, [
              'object_name',
              'instruction_addr',
              'symbol_name'
            ], [
              'yellow',
              'yellow',
              'yellow'
            ]));
          });

          res.send(`Reason: ${error.reason}${pretty_threads}`);
        });
      });
    });
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
});

app.listen(3000, function() {
  console.log(`Using dSYM file: ${dSYMPath}`);
  console.log(`Crash your app and POST to http://localhost:${3000}/crashreports`);
});

module.exports = app;

