/*jshint camelcase: false*/
'use strict';

//var config = require('./config/config.js')();

module.exports = function(grunt) {
  require('load-grunt-tasks')(grunt);
  var path = require('path'),
    pretty = require('prettysize');

  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    copy: {},
    clean: ['build/', 'artifacts/'],
    browserify: {},
    eslint: {
      options: {
        cache: true,
        cacheFile: '.eslintcodecache',
        configFile: 'eslint.json'
      },
      target: ['src/**/*.js', './*.js', 'test/**/*.js']
    },
    filesize: {},
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
    }
  });

  grunt.registerTask('test', 'Run tests', function(){
    grunt.log.ok('Running unit tests with node@' + process.version);
    var done = this.async();
    grunt.util.spawn({
      cmd: path.join(__dirname, 'node_modules/.bin/jenkins-mocha'),
      args: ['--require', 'test/config/mock.js', 'test/unit/**/*.js'],
      opts: { stdio: 'inherit' }
    }, function(){
      grunt.util.spawn({
        cmd: path.join(__dirname, 'node_modules/.bin/istanbul'),
        args: ['check-coverage'],
        opts: { stdio: 'inherit' }
      }, done);
    });
  });

  grunt.registerTask('lint', function() {
    grunt.task.run(['jshint', 'eslint']);
  });

  grunt.registerTask('build', function() {
    grunt.task.run(['clean']);
  });

  grunt.registerTask('build-dev', function() {
    grunt.task.run(['clean']);
  });

  grunt.registerTask('default', ['lint', 'build', 'test']);

  grunt.registerTask('local', ['build-dev']);
};
