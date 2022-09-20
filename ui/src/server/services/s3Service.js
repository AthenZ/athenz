const debug = require('debug')('AthenzUI:server:services:aws-s3');
const S3 = require('aws-sdk/clients/s3');
const defaultS3 = new S3();

module.exports = {
    getS3ObjectMetaData: function (bucket, key, cb, s3 = defaultS3) {
        return s3.headObject(
            { Bucket: bucket, Key: key },
            function (err, data) {
                if (err) {
                    debug(
                        `Unable to fetch Bucket head: ${bucket}, Key: ${key}, error: %o`,
                        err.stack
                    );
                    cb(err, null);
                } else {
                    cb(null, data);
                }
            }
        );
    },
    getContent: function (bucket, key, cb, s3 = defaultS3) {
        return s3.getObject({ Bucket: bucket, Key: key }, function (err, data) {
            if (err) {
                debug(
                    `Unable to fetch Bucket: ${bucket}, Key: ${key}, error: %o`,
                    err.stack
                );
                cb(err);
            } else {
                cb(null, data.Body.toString());
            }
        });
    },
};
