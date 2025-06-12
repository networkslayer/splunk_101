/*global define*/
define([
    'underscore',
    'jquery',
    'app/util/Util',
    'views/shared/PopTart',
    'app/views/Component/EntityDialog',
    'app/views/Component/Error',
    'app/collections/Servers',
    'app/models/appData'
], function (
    _,
    $,
    Util,
    PopTartView,
    EntityDialog,
    ErrorDialog,
    Servers,
    appData
) {
    return PopTartView.extend({
        className: 'dropdown-menu',
        initialize: function (options) {
            _.bindAll(this, 'create');
            PopTartView.prototype.initialize.apply(this, arguments);
            this.collection = options.collection;
            this.dispatcher = options.dispatcher;
            this.services = options.services;
            this.servers = new Servers([], {
                appData: {app: appData.get("app"), owner: appData.get("owner")},
                targetApp: Util.getAddonName(),
                targetOwner: "nobody"
            });
        },

        events: {
            'click a': 'create'
        },

        render: function () {
            var html = '<ul class="first-group">',
                service;
            for (service in this.services) {
                if (this.services.hasOwnProperty(service)) {
                    html += '<li><a href="#" class="' + service + '">' + this.services[service].title + '</a></li>';
                }
            }
            html += '</ul>';

            this.el.innerHTML = PopTartView.prototype.template_menu;
            this.$el.append(html);

            this.$el.addClass('dropdown-menu-narrow');
            return this;
        },

        create: function (e) {
            var dlg, errorDialog;
            this.service_type = $(e.target).attr('class');
            // Check the dependency for Security Center input
            if (this.service_type === 'input') {
                this.checkDependency().done(function () {
                    if (this.servers.models.length === 0) {
                        errorDialog = new ErrorDialog({
                            el: $('.dialog-placeholder'),
                            msg: 'Please add a Security Center Server first under configuration page.'
                        });
                        errorDialog.render().modal();
                    } else {
                        dlg = new EntityDialog({
                            el: $(".dialog-placeholder"),
                            collection: this.collection,
                            component: this.services[this.service_type],
                            isInput: true
                        }).render();
                        dlg.modal();
                    }
                }.bind(this));
            } else {
                dlg = new EntityDialog({
                    el: $(".dialog-placeholder"),
                    collection: this.collection,
                    component: this.services[this.service_type],
                    isInput: true
                }).render();
                dlg.modal();
            }
            this.hide();
        },

        checkDependency: function () {
            return $.when(this.servers.fetch());
        }
    });
});
