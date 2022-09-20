'use strict';
let s3Service = require('./s3Service');

function checkUsersUpdate(directory, fileName, extServiceClient) {
    return new Promise((resolve, reject) => {
        s3Service.getS3ObjectMetaData(
            directory,
            fileName,
            (err, metadata) => {
                if (err) {
                    reject(err);
                }
                resolve(metadata);
            },
            extServiceClient
        );
    });
}
function loadUpdatedFile(directory, fileName, extServiceClient) {
    return new Promise((resolve, reject) => {
        s3Service.getContent(
            directory,
            fileName,
            (err, data) => {
                if (err) {
                    reject(err);
                }
                resolve(data);
            },
            extServiceClient
        );
    });
}
module.exports.checkUsersUpdate = checkUsersUpdate;
module.exports.fetchUpdatedUsers = loadUpdatedFile;
