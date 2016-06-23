/*******************************************************************
The symbolication engine.
*******************************************************************/

var strict = false;

const _ = require('lodash');
const fs = require('fs');
const path = require('path');
const async = require('async');
const cliff = require('cliff');
const spawn = require('child_process').spawn;

const IS_MAC = process.platform === 'darwin';

/*
  Exported functions
 */

exports.pretty = pretty;
exports.symbolicate = symbolicateCrashReport;
exports.symbolicateCrashReport = symbolicateCrashReport;
exports.strict = strict;

/**
 * Prettifies a JSON crash report.
 *
 * @param report the JSON crash report.
 */
function pretty(report) {
  var o = `Reason: ${report.crash.error.reason}\n`;

  _.each(report.crash.threads, function (thread) {
    o += '\n';
    o += `Thread ${thread.index}`;
    o += '\n';
    o += cliff.stringifyObjectRows(thread.backtrace.contents, [
      'object_name',
      'instruction_addr',
      'symbol_name'
    ], [
      'yellow',
      'yellow',
      'yellow'
    ]);
    o += '\n';
  });

  return o;
}

/**
 * Symbolicates a JSON crash report.
 *
 * @param dSYMPath The dSYM file path.
 * @param report The JSON crash report content in KSCrash format. This is not file path.
 * @param cb callback(err, symbolicatedReport)
 */
function symbolicateCrashReport(dSYMPath, report, cb) {
	var metaInfo = {
     'dSYMPath': dSYMPath,
     'process_name': report.system.process_name,
     'cpu_arch': report.system.cpu_arch,
     'os_version': report.system.os_version,
     'system_version': report.system.system_version
  };

  /*
  We go through each thread and create a dictionary of image name and all occurences of instruction symbols.

  {
    "CoreFoundation": {
       "symbols": {
         572056299: <name1>,
         52205789: <name1>,
         ...
       },
       "object_addr": 571052032,
       "symbol_addr": 572056172,
       "object_name": "CoreFoundation"
     },
    "UIKit": {...},
    ...
    }
  }
  */
  var images = {};

  _.each(report.crash.threads).forEach(function (thread) {
    _.each(thread.backtrace.contents, function (element) {
      var obj_name = element['object_name'];
      var entry = images[obj_name];

      if (_.isEmpty(entry)) {
        entry = _.extend({ 'symbols': { } }, _.omit(element, 'instruction_addr', 'symbol_name'));
      }

      entry.symbols[element.instruction_addr] = element.symbol_name;
      images[obj_name] = entry;
    });
  });

  symbolicateImages(metaInfo, images, function(err, names) {
    if (err) {
      return cb(err);
    }
    cb(null, updateNames(report, names));
  });
}

/*
 Private functions
 */

function symbolicateImages(metaInfo, images, cb) {
  async.eachSeries(images, symbolicateEntry.bind(null, metaInfo), function (err, results) {
    if (err) {
      return cb(err);
    }

    var names = { };

    _.each(results, function (item) {
      _.extend(names, item.symbols);
    });

    cb(null, names);
  });
}

function updateNames(report, names) {
  return _.merge(report, {
    crash: {
      threads: _.map(report.crash.threads, function (thread) {
        return _.merge(thread, {
          backtrace: {
            contents: _.map(thread.backtrace.contents, function (entry) {
              var hex_addr = toHex(entry.instruction_addr);

              return _.merge(entry, {
                instruction_addr: hex_addr,
                object_addr: toHex(entry.object_addr),
                symbol_addr: toHex(entry.symbol_addr),
                symbol_name: names[hex_addr]
              });
            })
          }
        })
      })
    }
  })
}

/*
Structure of entry is

{
 "symbols": {
   572056299: <name1>,
   52205789: <name1>,
   ...
 },
 "object_addr": 571052032,
 "symbol_addr": 572056172,
 "object_name": "CoreFoundation"
}

Result is that every symbol is symbolicated and the corresponding name is replaced.
*/
function symbolicateEntry(metaInfo, entry, cb) {
  var hexSymbols = {};
  var object_name = entry.object_name;

  if (_.isEmpty(object_name)) {
    return cb(null, entry);
  }

  var symbols = [];

  _.each(entry.symbols, function(name, decimalAddr) {
    var hex = toHex(decimalAddr);
    hexSymbols[hex] = name;
    symbols.push(hex);
  });

  // TODO: If symbol name exists then skip from symbolication.
  entry.symbols = hexSymbols;
  entry.object_addr = toHex(entry.object_addr);
  entry.symbol_addr = toHex(entry.symbol_addr);

  var sym_files;

  if (object_name === metaInfo.process_name) {
    sym_files = [metaInfo.dSYMPath];
  } else {
    // Ex: ~/Library/Developer/Xcode/iOS\ DeviceSupport/9.2.1\ \(13D15\)
    // If we are using single version of system symbol files point that path here.
    var version_tag = `${metaInfo.system_version} \\(${metaInfo.os_version}\\)`;
    var dev_sup_path = IS_MAC ? '~/Library/Developer/Xcode/iOS DeviceSupport' : '/opt/xcode';
    var joined_path = path.join(dev_sup_path, version_tag);
    var symbol_file = joined_path.replace(/ /g, '\\ ');

    if (object_name.endsWith('dylib')) {
      sym_files = [
        path.join(symbol_file, '/Symbols/usr/lib/system/', object_name),
        path.join(symbol_file, '/Symbols/usr/lib/', object_name)
      ];
    } else {
      sym_files = [
        path.join(symbol_file, '/Symbols/System/Library/Frameworks', `${object_name}.framework`, object_name),
        path.join(symbol_file, '/Symbols/System/Library/PrivateFrameworks', `${object_name}.framework`, object_name)
      ];
    }
  }

  var args = [
    '-o',
    null,
    `${IS_MAC ? '' : '-'}-arch`,
    metaInfo.cpu_arch === 'armv7' ? 'armv7s' : metaInfo.cpu_arch,
    '-l',
    entry.object_addr,
    symbols.join(' ')
  ];

  async.reduce(sym_files, entry, symbolicationReducer(args, symbols), function (err, result) {
    if (strict && err) {
      return cb(err);
    }
    cb(null, result);
  });
}

function symbolicationReducer(args, symbols) {
  var atos_tool = `atos${IS_MAC ? '' : 'l'}`;
  var inner_args = args.concat();

  return function (entry, sym_file, next) {
    inner_args[1] = sym_file;

    var atos = spawn(atos_tool, inner_args);

    var stdout = '';
    var stderr = '';

    atos.stdout.on('data', function (data) {
      stdout += data.toString();
    });

    atos.stderr.on('data', function (data) {
      stderr += data.toString();
    });

    atos.on('close', function (code) {
      var cmd = [atos_tool]
        .concat(inner_args)
        .join(' ');

      if (code !== 0) {
        if (strict) {
          console.error(stderr);
          next(new Error(`Error when using ${cmd}`));
        } else {
          next(null, entry);
        }

        return;
      }

      if (_.isEmpty(stdout)) {
        if (strict) {
          next(new Error(`Empty result from ${cmd}`));
        } else {
          next(null, entry);
        }
        return;
      }

      var names = stdout
        .trim()
        .replace(/\r\n/g, '\n')
        .split('\n');

      entry.symbols = _.zipObject(symbols, names);

      next(null, entry);
    });
  };
}

function toHex(n) {
  return Number(n).toString(16).toUpperCase();
}
