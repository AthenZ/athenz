import { getFullName } from '../../utils';
import { groupDelimiter, roleDelimiter } from '../../config';

export const getFullCollectionName = (domainName, collectionName, category) => {
    if (category === 'group') {
        return getFullName(domainName, groupDelimiter, collectionName);
    } else if (category === 'role') {
        return getFullName(domainName, roleDelimiter, collectionName);
    }
    return collectionName;
};
