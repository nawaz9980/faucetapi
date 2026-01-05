/**
 * Normalizes an IP address by stripping IPv6 prefixes like ::ffff:
 * @param {string} ip - The IP address to normalize
 * @returns {string} - The cleaned IPv4 or IPv6 address
 */
const normalizeIp = (ip) => {
    if (!ip) return '0.0.0.0';
    if (ip.startsWith('::ffff:')) {
        return ip.substring(7);
    }
    if (ip === '::1') {
        return '127.0.0.1';
    }
    return ip;
};

module.exports = {
    normalizeIp
};
