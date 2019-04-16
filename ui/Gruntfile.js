/*jshint camelcase: false*/
'use strict';

var config = require('./config/config.js')();

module.exports = function(grunt) {
  require('load-grunt-tasks')(grunt);
  var path = require('path'),
    pretty = require('prettysize'),
    https = require('https'),
    url = require('url');

  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    copy: {
      css: {
        files: [
          {
            expand: true,
            flatten: true,
            src: [
              'node_modules/vis/dist/*.css',
              'node_modules/select2/dist/css/*.css',
              'node_modules/jquery-ui/themes/base/minified/jquery-ui.min.css'
            ],
            dest: 'build/<%= pkg.version %>/css/'
          }
        ]
      }
    },
    clean: ['build/', 'artifacts/'],
    browserify: {
      js: {
        options: {
          browserifyOptions: {
            debug: true
          },
          plugin: [
            ['minifyify', {
              output: 'build/<%= pkg.version %>/js/bundle.map'
            }]
          ]
        },
        src: ['public/js/' + 'index.js'],
        dest: 'build/<%= pkg.version %>/js/bundle.js'
      },
      jsDev: {
        options: {
          browserifyOptions: {
            debug: true
          }
        },
        src: ['public/js/' + 'index.js'],
        dest: 'build/<%= pkg.version %>/js/bundle.js'
      }
    },
    eslint: {
      options: {
        cache: true,
        cacheFile: '.eslintcodecache',
        configFile: 'eslint.json'
      },
      target: ['public/js/' + '**/*.js', 'src/**/*.js', './*.js', 'test/**/*.js']
    },
    filesize: {
      base: {
        files: [{
          expand: true,
          cwd: 'build/<%= pkg.version %>/',
          src: ['css/' + '*.css', 'js/' + '*']
        }],
        options: {
          stdout: true
        }
      }
    },
    jshint: {
      options: {
        globalstrict: true,
        expr: true,
        esversion: 6,
        globals: {
          "expect": true,
          "assert": false,
          "it": false,
          "require": false,
          "describe": false,
          "beforeEach": false,
          "afterEach": false,
          "before": false,
          "after": false,
          "$": false,
          "$$": false,
          "browser": false,
          "Buffer": false,
          "module": false,
          "global": false,
          "exports": false,
          "process": false,
          "console": false,
          "__dirname": false,
          "Intl": false,
        }
      },
      files: ['Gruntfile.js', 'src/**/*.js', './*.js',  'test/**/*.js'],
    },
    postcss: {
      options: {
        failOnError: true,
        processors: [
          require('postcss-import'),
          require('postcss-mixins')(),
          require('postcss-nested')(),
          require('postcss-simple-vars')({
            variables: require('./src/utils/colors')
          }),
          require('postcss-extend')()
        ]
      },
      dist: {
        dest: 'build/<%= pkg.version %>/css/app.css',
        src: ['public/css/app.css']
      }
    },
    watch: {
      css: {
        files: ['public/css/**/*.css'],
        tasks: ['postcss', 'csslint']
      },
      bundle: {
        files: ['public/**/*.js'],
        tasks: ['browserify:jsDev', 'eslint']
      },
      js: {
        files: ['src/**/*.js', './*.js', 'test/**/*.js'],
        tasks: ['eslint', 'test']
      }
    },
    exec: {
      webdriver: path.resolve('node_modules/protractor/bin/webdriver-manager') + ' update --standalone',
      functest: path.resolve('node_modules/protractor/bin/protractor') + ' ./test/config/protractor.conf.js',
      rdlapi: './node_modules/.bin/rdl-rest-docs ./config/zms.json ./rdl-api.md'
    },
    protractor_webdriver: {
      options: {
        keepAlive: true
      },
      default: {
      }
    }
  });

  grunt.registerTask('rdl', ['rdl-fetch', 'exec:rdlapi']);

  grunt.registerTask('rdlapi', ['exec:rdlapi']);

  grunt.registerTask('rdl-fetch', function(){
    var done = this.async(),
      options, req, apiHost;

    apiHost = config.zms;

    options = url.parse(apiHost + 'schema'),

    grunt.log.ok('Fetching RDL Spec from ' + apiHost);
    options.rejectUnauthorized = false;
    req = https.get(options, function(res) {
      var data = '';
      res.on('data', function(chunk) {
        data += chunk;
      });
      res.on('end', function() {
        var json = JSON.parse(data);
        grunt.file.write('config/zms.json', JSON.stringify(json, null, 4) + '\n');
        grunt.log.ok('RDL JSON saved (' + pretty(data.length) + ')');
        done();
      });
    });
    req.on('error', function(err) {
      grunt.log.error(err);
      done();
    });
  });

  grunt.registerTask('move-xunit', function(){
    if (grunt.file.exists('xunit.xml')) {
      grunt.log.ok('Moving functional xunit.xml');
      grunt.file.copy('xunit.xml', 'artifacts/test/functional.xml');
      grunt.file.delete('xunit.xml');
    }
  });

  grunt.registerTask('functional-sd', 'Run Functional Tests', function(){
    grunt.log.ok('Running functional tests with node@' + process.version);
    grunt.task.run(['exec:functest', 'move-xunit']);
  });

  grunt.registerTask('functional', 'Run Functional Tests', function(){
    grunt.log.ok('Running functional tests with node@' + process.version);
    grunt.task.run(['exec:webdriver', 'protractor_webdriver', 'exec:functest', 'move-xunit']);
  });

  grunt.registerTask('test', 'Run tests', function(){
    grunt.log.ok('Running unit tests with node@' + process.version);
    var done = this.async();
    grunt.util.spawn({
      cmd: path.join(__dirname, 'node_modules/nyc/bin/nyc.js'),
      args: ['node_modules/.bin/jenkins-mocha', '--require', 'test/config/mock.js', 'test/unit/**/*.js'],
      opts: { stdio: 'inherit' }
    }, done);
  });

  grunt.registerTask('csslint', 'Lint css', function(){
    var done = this.async();
    var files = grunt.template.process('build/<%= pkg.version %>/css/app.css');
    grunt.util.spawn({
      cmd: path.join(__dirname, 'node_modules/.bin/csslint'),
      args: ['--ignore=adjoining-classes,order-alphabetical,unqualified-attributes,regex-selectors,important,unique-headings,qualified-headings,box-model,outline-none,box-sizing,bulletproof-font-face,duplicate-background-images,font-sizes', files],
      opts: { stdio: 'inherit' }
    }, done);
  });

  grunt.registerTask('lint', function() {
    grunt.task.run(['jshint', 'eslint']);
  });

  grunt.registerTask('build-css', function() {
    grunt.task.run(['postcss', 'copy:css', 'csslint']);
  });

  grunt.registerTask('build', function() {
    grunt.task.run(['clean', 'build-css', 'browserify:js', 'filesize:base']);
  });

  grunt.registerTask('build-dev', function() {
    grunt.task.run(['clean', 'build-css', 'browserify:jsDev', 'filesize:base']);
  });

  grunt.registerTask('default', ['lint', 'build', 'test']);

  grunt.registerTask('local', ['build-dev', 'watch']);
};
