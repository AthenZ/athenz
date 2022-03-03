module.exports = {
    chrome: {
        name: 'Chrome',
        browserName: 'chrome',
        platform: 'Windows 10',
        version: 'latest',
        'goog:chromeOptions': {
            perfLoggingPrefs: {
                enableNetwork: true,
                enablePage: false,
            },
        },
        'goog:loggingPrefs': {
            performance: 'ALL',
            browser: 'ALL',
        },
    },
    edge: {
        name: 'Edge',
        browserName: 'MicrosoftEdge',
        platform: 'Windows 10',
        version: 'latest',
    },
    firefox: {
        name: 'Firefox',
        browserName: 'firefox',
        platform: 'Windows 10',
        version: 'latest',
    },
    safari: {
        name: 'Safari',
        browserName: 'safari',
        browserVersion: 'latest',
        platform: 'macOS 10.14',
        'sauce:options': {
            screenResolution: '1280x960',
        },
    },
};
