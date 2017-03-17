var nmeta = {

    views: {},

    models: {},

    loadTemplates: function(views, callback) {
        // Load template html files from template directory
        var deferreds = [];
        $.each(views, function(index, view) {
            console.log('loadTemplates index=' + index + ' view=' + view);
            if (nmeta[view]) {
                deferreds.push($.get('templates/' + view + '.html', function(data) {
                    nmeta[view].prototype.template = _.template(data);
                }, 'html'));
            } else {
                alert(view + " not found");
            }
        });
        console.log('deferreds=' + deferreds)
        $.when.apply(null, deferreds).done(callback);
    }

};

nmeta.Router = Backbone.Router.extend({

    routes: {
        "":               "home",
        "who":            "who",
        "what":           "what",
        "kit":            "kit",
        "policy":         "policy",
        "flowDetails/:flow_hash":    "flowDetails",
        "switch/:dpid":   "switch"
    },

    // Display nav bar and set up rest of page
    initialize: function () {

        // Instantiate Flows Collection:
        console.log('instantiating flows_collection');
        this.flows_collection = new nmeta.FlowsCollection();

        // Instantiate model to hold UI states for Flows View:
        this.flowsState = new Backbone.Model();

        // Instantiate Flow Details Collection:
        console.log('instantiating flowDetailsCollection');
        this.flowDetailsCollection = new nmeta.FlowDetailsCollection();

        // Instantiate Bars View to show top and bottom bars and provide
        // anchor ids for content from other views:
        nmeta.barsView = new nmeta.BarsView();
        $('body').html(nmeta.barsView.render().el);
        // Close the search dropdown on click anywhere in the UI
        $('body').click(function () {
            $('.dropdown').removeClass("open");
        });
        // Variables linking to HTML content ids
        this.$content = $("#content");
        this.$content2 = $("#content2");

    },

    // Display 'home' page
    home: function () {
        // Since the home view never changes, we instantiate it and render it only once
        if (!nmeta.homelView) {
            nmeta.homelView = new nmeta.HomeView();
            nmeta.homelView.render();
        } else {
            console.log('reusing home view');
            nmeta.homelView.delegateEvents(); // delegate events when the view is recycled
        }
        this.$content.html(nmeta.homelView.el);
        // Empty unused content2:
        this.$content2.empty();
        // Update top menu bar:
        nmeta.barsView.selectMenuItem('home-menu');
    },

    // Display 'who' page about identities on the network:
    who: function () {
        // Instantiate Identities Collection:
        var identities_collection = new nmeta.IdentitiesCollection();
        var self = this;
        // Retrieve identities information via REST API:
        identities_collection.fetch({
            success: function (data) {
                console.log('identities_collection data=' + data);
                self.$content.html(new nmeta.IdentitiesView({model: data}).render().el);
            }
        });
        // Empty unused content2:
        this.$content2.empty();
        // Update top menu bar:
        nmeta.barsView.selectMenuItem('who-menu');
    },

    // Display 'what' page about flows on the network:
    what: function () {
        // Instantiate flows view if not already existing:
        if (!nmeta.flowsView) {
            // Instantiate flowsView:
            console.log('app instantiating flowsView');
            nmeta.flowsView = new nmeta.FlowsView({model: this.flows_collection,
                                                   flowsState: this.flowsState});
        } else {
            // Rebind events:
            console.log('app rebinding flowsView events');
            nmeta.flowsView.delegateEvents()
        }

        // Fetch flows_collection as reset event (note: invokes render):
        console.log('app calling flows_collection fetch({reset: true})');
        this.flows_collection.fetch({reset: true})

        // Publish result into DOM against id="content":
        this.$content.html(nmeta.flowsView.el);

        // Empty unused id="content2" in DOM:
        this.$content2.empty();

        // Update top menu bar:
        nmeta.barsView.selectMenuItem('what-menu');
    },

    kit: function (id) {
        // Retrieve Controller Summary View via REST API:
        var controller_summary_model = new nmeta.ControllerSummaryModel();
        var self = this;
        controller_summary_model.fetch({
            success: function (data) {
                // Render against id='content':
                self.$content.html(new nmeta.ControllerSummaryView({model: data}).render().el);
            }
        });

        // Instantiate Switches Collection:
        var switches_collection = new nmeta.SwitchesCollection();
        var self = this;
        // Retrieve switches information via REST API:
        switches_collection.fetch({
            success: function (data) {
                // Render against id='content2':
                self.$content2.html(new nmeta.SwitchesView({model: data}).render().el);
            }
        });
        // Update top menu bar:
        nmeta.barsView.selectMenuItem('kit-menu');
    },

    // Display 'policy' page
    policy: function () {
        if (!nmeta.policyView) {
            console.log('creating policy view');
            nmeta.policyView = new nmeta.PolicyView();
            nmeta.policyView.render();
        }
        this.$content.html(nmeta.policyView.el);
        // Empty unused content2:
        this.$content2.empty();
        // Update top menu bar:
        nmeta.barsView.selectMenuItem('policy-menu');
    },

    flowDetails: function (flow_hash) {
        console.log('in router flowDetails flow_hash=' + flow_hash);
        // Instantiate flow details view if not already existing:
        if (!nmeta.flowDetailsView) {
            // Instantiate flowDetailsView:
            console.log('app instantiating flowDetailsView');
            nmeta.flowDetailsView = new nmeta.FlowDetailsView({model: this.flowDetailsCollection});
        } else {
            // Rebind events:
            console.log('app rebinding flowDetailsView events');
            nmeta.flowDetailsView.delegateEvents()
        }

        // Fetch flow_details_model as reset event (note: invokes render):
        console.log('app calling flowDetailsCollection fetch({reset: true})');
        var where_query = '{\"flow_hash\":\"' + flow_hash + '\"}'
        console.log('where_query=' + where_query);
        this.flowDetailsCollection.fetch({reset: true, data: $.param({ where: where_query})})

        // Publish result into DOM against id="content":
        this.$content.html(nmeta.flowDetailsView.el);

        // Empty unused id="content2" in DOM:
        this.$content2.empty();

        // Update top menu bar:
        nmeta.barsView.selectMenuItem('what-menu');
    },

});

$(document).on("ready", function () {
    nmeta.loadTemplates(["HomeView", "IdentitiesView", "IdentityView", "FlowsView", "FlowView", "FlowDetailsView", "FlowDetailView", "PolicyView", "BarsView", "ControllerSummaryView", "SwitchesView", "SwitchView"],
        function () {
            nmeta.router = new nmeta.Router();
            Backbone.history.start();
        });
});
