'use strict';

window.jQuery = require('jquery');
require('./addDomain.js');
require('./athenzPost.js');
require('./manageDomain.js');
require('./manageRole.js');
require('./manageService.js');
require('select2')(window.jQuery);
require('./managePolicy.js');

window.athenzScriptsLoaded = true;
