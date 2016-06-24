/*******************************************************************
The symbolication engine.
*******************************************************************/

const options = {
  base_path: undefined,
  strict: false
};

const _ = require('lodash');
const fs = require('fs');
const kc = require('kscrash-converter');
const path = require('path');
const async = require('async');
const cliff = require('cliff');
const spawn = require('child_process').spawn;

const DEFAULT_SYM_PATH = '~/Library/Developer/Xcode/iOS DeviceSupport';
const IS_MAC = process.platform === 'darwin';

/*
  Exported functions
 */

var Symbolicator = {

  /**
   * Retrieves a global option.
   *
   * @param opt the option name.
   * @param def the default value.
   * @returns {*} an option result.
   */
  getOpt: function getOpt(opt, def) {
    var val = options[opt];
    if (val === undefined) {
      return typeof def === 'function'
        ? def() : def;
    }
    return val;
  },

  /**
   * Sets a global option.
   *
   * @param opt the option name.
   * @param val the value to set.
   */
  setOpt: function setOpt(opt, val) {
    options[opt] = val;
  },

  /**
   * Symbolicates a JSON crash report.
   *
   * @param report The JSON crash report content in KSCrash format. This is not file path.
   * @param dSYMPath The dSYM file path.
   * @param options Any options for this pass.
   * @param cb callback(err, symbolicatedReport)
   */
  symbolicate: function symbolicate(report, dSYMPath, options, cb) {
    if (cb === undefined) {
      if (typeof options !== 'function') {
        return;
      }
      cb = options;
      options = {};
    }

    if (!options.base_path) {
      options.base_path = Symbolicator.getOpt('base_path', DEFAULT_SYM_PATH);
    }

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
      }
    */
    var images = {};

    _.each(report.crash.threads, function (thread) {
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

    async.mapSeries(images, symbolicateEntry.bind(null, metaInfo, options), function (err, results) {
      if (err) {
        return cb(err);
      }

      var names = { };

      _.each(results, function (item) {
        _.extend(names, item.symbols);
      });

      cb(null, updateNames(report, names));
    });
  }

};

/*
  Export everything as a module.
 */

module.exports = Symbolicator;
module.exports.pretty = kc.convert_json;
module.exports.symbolicateCrashReport = Symbolicator.symbolicate;

/*
 Private functions
 */

/**
 * Updates all symbol names with the parsed names.
 *
 * @param report the JSON crash report.
 * @param names the names to replace with.
 */
function updateNames(report, names) {
  return _.merge(report, {
    crash: {
      threads: _.map(report.crash.threads, function (thread) {
        return _.merge(thread, {
          backtrace: {
            contents: _.map(thread.backtrace.contents, function (entry) {
              return _.merge(entry, {
                instruction_addr: entry.instruction_addr,
                object_addr: entry.object_addr,
                symbol_addr: entry.symbol_addr,
                symbol_name: names[toHex(entry.instruction_addr)]
              });
            })
          }
        })
      })
    }
  });
}

/**
 * Symbolicates an entry, and the result has the corresponding
 * symbol name replaced.
 *
 * An entry exists in the following form:
 *
 *  {
 *    "symbols": {
 *      572056299: <name1>,
 *      522057899: <name2>,
 *      ...
 *    }
 *    "object_addr": 571052032,
 *    "symbol_addr": 572056172,
 *    "object_name": "CoreFoundation"
 *  }
 *
 * @param metaInfo
 * @param entry
 * @param options
 * @param cb
 * @returns {*}
 */
function symbolicateEntry(metaInfo, options, entry, cb) {
  var hexSymbols = {};
  var object_name = entry['object_name'];

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

  var sym_files;

  if (object_name === metaInfo.process_name) {
    sym_files = [metaInfo.dSYMPath];
  } else {
    // Ex: ~/Library/Developer/Xcode/iOS\ DeviceSupport/9.2.1\ \(13D15\)
    // If we are using single version of system symbol files point that path here.
    var version_tag = `${metaInfo.system_version} (${metaInfo.os_version})`;
    var joined_path = path.join(options.base_path, version_tag);

    if (object_name.endsWith('dylib')) {
      sym_files = [
        path.join(joined_path, '/Symbols/usr/lib/system/', object_name),
        path.join(joined_path, '/Symbols/usr/lib/', object_name)
      ];
    } else {
      sym_files = [
        path.join(joined_path, '/Symbols/System/Library/Frameworks', `${object_name}.framework`, object_name),
        path.join(joined_path, '/Symbols/System/Library/PrivateFrameworks', `${object_name}.framework`, object_name)
      ];
    }
  }

  var args = [
    '-o',
    null,
    `${IS_MAC ? '' : '-'}-arch`,
    metaInfo.cpu_arch === 'armv7' ? 'armv7s' : metaInfo.cpu_arch,
    '-l',
    toHex(entry.object_addr),
    symbols.join(' ')
  ];

  var atos_tool = `atos${IS_MAC ? '' : 'l'}`;

  async.reduce(sym_files, entry, function (entry, sym_file, next) {
    if (IS_MAC) {
      args[1] = sym_file.replace(/( |\(|\))/g, '\\$1');
    } else {
      args[1] = sym_file;
    }

    var atos = spawn(atos_tool, args);

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
        .concat(args)
        .join(' ');

      if (code !== 0) {
        if (Symbolicator.getOpt('strict', false)) {
          console.error(stderr);
          next(new Error(`Error when using ${cmd}`));
        } else {
          next(null, entry);
        }

        return;
      }

      if (_.isEmpty(stdout)) {
        if (Symbolicator.getOpt('strict', false)) {
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
  }, function (err, result) {
    if (Symbolicator.getOpt('strict', false) && err) {
      return cb(err);
    }
    cb(null, result);
  });
}

/**
 * Converts an input number to a hex string.
 *
 * @param n the input number.
 * @returns {string} a hex string.
 */
function toHex(n) {
  return Number(n).toString(16).toUpperCase();
}
