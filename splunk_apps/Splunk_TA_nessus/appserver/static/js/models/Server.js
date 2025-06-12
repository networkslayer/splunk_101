/*global define*/
define([
    'underscore',
    'app/models/Base.Model',
    'app/config/ContextMap',
    'app/models/TenableUtils.js'
], function (
    _,
    BaseModel,
    ContextMap,
    Utils
) {
    return BaseModel.extend({
        url: [
            ContextMap.restRoot,
            ContextMap.server
        ].join('/'),

        initialize: function (attributes, options) {
            options = options || {};
            this.collection = options.collection;
            BaseModel.prototype.initialize.call(this, attributes, options);
            this.addValidation('url', this.validServerURL);
            this.addValidation('username', this.nonEmptyString);
            this.addValidation('password', this.nonEmptyString);
        },
        validServerURL: function (attr) {
            var url = this.entry.content.get(attr);
            product = "Security Center";
            return Utils.validateURL(url, product);
        }
    });
});
