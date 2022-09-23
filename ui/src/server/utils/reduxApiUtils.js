module.exports.extractAssertionId = (
    data,
    domainName,
    roleName,
    action,
    effect,
    resource
) => {
    for (let i = 0; i < data.assertions.length; i++) {
        let assertion = data.assertions[i];
        if (
            assertion.role === domainName + ':role.' + roleName &&
            assertion.resource === domainName + ':' + resource &&
            assertion.action === action &&
            assertion.effect === effect
        ) {
            return assertion.id;
        }
    }
    return -1;
};

module.exports.getMicrosegmentationActionRegex = () => {
    return new RegExp(
        '^(TCP|UDP)-(IN|OUT):(\\d{1,5}-\\d{1,5}|\\d{1,5}):((?:\\d{1,5}|\\d{1,5}-\\d{1,5})(?:,\\d{1,5}|\\d{1,5}-\\d{1,5})*)$'
    );
};

module.exports.omitUndefined = (obj) => {
    try {
        return JSON.parse(JSON.stringify(obj));
    } catch (err) {
        return obj === undefined ? null : obj;
    }
};
