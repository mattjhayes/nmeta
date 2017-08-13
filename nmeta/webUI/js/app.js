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

// TEST CLEAN-UP:
Backbone.View.prototype.close = function() {
    console.log('running Backbone.View.prototype.close');
    if (this.onClose) {
        console.log('... calling onClose');
        this.onClose();
    }
    console.log('... calling remove');
    this.remove();
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

    //=========================================================================
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

        // Instantiate Flow Mods Collection:
        console.log('instantiating flowModsCollection');
        this.flowModsCollection = new nmeta.FlowModsCollection();

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
        this.$content3 = $("#content3");

        // Array for storing current views for later clean-up:
        this.currentViews = [];
    },

    //=========================================================================
    // Display 'home' page
    home: function () {
        // Pane 1: Clean-up then create View:
        this.cleanUpViews();
        nmeta.homelView = new nmeta.HomeView();
        this.registerView(nmeta.homelView);
        
        // Pane 1: Render View:
        nmeta.homelView.render();
        this.$content.html(nmeta.homelView.el);

        // Pane 2: Create switch count Model
        this.switch_count_model = new nmeta.SwitchCountModel();

        // Pane 2: Create switch count View:
        nmeta.switchCountView = new nmeta.SwitchCountView({model: this.switch_count_model});
        this.registerView(nmeta.switchCountView);

        // Pane 2: Fetch switch_count_model as reset event (note: invokes render):
        console.log('app calling switch_count_model fetch({reset: true})');
        this.switch_count_model.fetch({reset: true})

        // Pane 2: Publish result into DOM against id="content2":
        this.$content2.html(nmeta.switchCountView.el);

        // Pane 3: Empty unused content3 in the DOM:
        this.$content3.empty();

        // Update top menu bar:
        nmeta.barsView.selectMenuItem('home-menu');
    },

    //=========================================================================
    // Display 'who' page about identities on the network:
    who: function () {
        // Pane 1: Clean-up + TBD:
        this.cleanUpViews();
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
        // Empty unused content2 and content3 in the DOM:
        this.$content2.empty();
        this.$content3.empty();
        // Update top menu bar:
        nmeta.barsView.selectMenuItem('who-menu');
    },

    //=========================================================================
    // Display 'what' page about flows on the network:
    what: function () {
        this.cleanUpViews();
        // Instantiate flows view if not already existing:
        //if (!nmeta.flowsView) {
            // Instantiate flowsView:
        //    console.log('app instantiating flowsView');
        //    nmeta.flowsView = new nmeta.FlowsView({model: this.flows_collection,
        //                                           flowsState: this.flowsState});
        //} else {
            // Rebind events:
        //    console.log('app rebinding flowsView events');
        //    nmeta.flowsView.delegateEvents()
        //}
        
        nmeta.flowsView = new nmeta.FlowsView({model: this.flows_collection,
                                                 flowsState: this.flowsState});
        this.registerView(nmeta.flowsView);

        // Fetch flows_collection as reset event (note: invokes render):
        console.log('app calling flows_collection fetch({reset: true})');
        this.flows_collection.fetch({reset: true})

        // Publish result into DOM against id="content":
        this.$content.html(nmeta.flowsView.el);

        // Empty unused content2 and content3 in the DOM:
        this.$content2.empty();
        this.$content3.empty()

        // Update top menu bar:
        nmeta.barsView.selectMenuItem('what-menu');
    },

    //=========================================================================
    // Display 'kit' page about networking equipment:
    kit: function (id) {
        this.cleanUpViews();
        // Retrieve Controller Summary View via REST API:
        var controller_summary_model = new nmeta.ControllerSummaryModel();
        var self = this;
        controller_summary_model.fetch({
            success: function (data) {
                // Render against id='content':
                self.$content.html(new nmeta.ControllerSummaryView({model: data}).render().el);
            }
        });

        // Retrieve connected switch count via REST API:
        var switch_count_model = new nmeta.SwitchCountModel();
        var self = this;
        switch_count_model.fetch({
            success: function (data) {
                // Render against id='content2':
                self.$content2.html(new nmeta.SwitchCountView({model: data}).render().el);
            }
        });

        // Instantiate Switches Collection:
        var switches_collection = new nmeta.SwitchesCollection();
        var self = this;
        // Retrieve switches information via REST API:
        switches_collection.fetch({
            success: function (data) {
                // Render against id='content3':
                self.$content3.html(new nmeta.SwitchesView({model: data}).render().el);
            }
        });

        // Update top menu bar:
        nmeta.barsView.selectMenuItem('kit-menu');
    },

    //=========================================================================
    // Display 'policy' page
    policy: function () {
        this.cleanUpViews();
        if (!nmeta.policyView) {
            console.log('creating policy view');
            nmeta.policyView = new nmeta.PolicyView();
            nmeta.policyView.render();
        }
        this.$content.html(nmeta.policyView.el);
        // Empty unused content2 and content3 in the DOM:
        this.$content2.empty();
        this.$content3.empty()
        // Update top menu bar:
        nmeta.barsView.selectMenuItem('policy-menu');
    },

    //=========================================================================
    // Display the FlowDetails View:
    flowDetails: function (flow_hash) {
        this.cleanUpViews();
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

        //---------------------------------------------------------------------
        // Instantiate flow mods view if not already existing:
        if (!nmeta.flowModsView) {
            // Instantiate flowModsView:
            console.log('app instantiating flowModsView');
            nmeta.flowModsView = new nmeta.FlowModsView({model: this.flowModsCollection});
        } else {
            // Rebind events:
            console.log('app rebinding flowModsView events');
            nmeta.flowModsView.delegateEvents()
        }

        // Fetch flow_mods_model as reset event (note: invokes render):
        console.log('app calling flowModsCollection fetch({reset: true})');
        var where_query = '{\"flow_hash\":\"' + flow_hash + '\"}'
        console.log('where_query=' + where_query);
        this.flowModsCollection.fetch({reset: true, data: $.param({ where: where_query})})

        // Publish result into DOM against id="content2":
        this.$content2.html(nmeta.flowModsView.el);

        // Empty unused content3 in the DOM:
        this.$content3.empty()

        //---------------------------------------------------------------------
        // Update top menu bar:
        nmeta.barsView.selectMenuItem('what-menu');
    },

    //=========================================================================
    // Register a View as active so we can later clean it up:
    registerView: function (view) {
        // Holds array of current views:
        console.log('running registerView');
        this.currentViews.push(view)
        console.log('...array length is now ' + this.currentViews.length);
    },

    //=========================================================================
    // Clean up all current views:
    cleanUpViews: function () {
        console.log('running cleanUpViews number=' + this.currentViews.length);
        this.currentViews.forEach(function (view){
            if (view) {
                console.log('...closing view');
                view.close();
            }
            else {
                console.log('...ERROR: could not find view to close');
            }
        });
        this.currentViews = [];
    },

});

//=============================================================================
// HTML template names to load (it appends .html to load file from templates
// directory)
// Note: ensure the view name in the *_view.js file is identical i.e.:
//   "SwitchCountView" requires nmeta.SwitchCountView in switch_count_view.js
$(document).on("ready", function () {
    nmeta.loadTemplates(["HomeView", "SwitchCountView", "IdentitiesView",
                "IdentityView", "FlowsView", "FlowView", "FlowDetailsView",
                "FlowDetailView", "FlowModsView", "FlowModView", "PolicyView",
                "BarsView", "ControllerSummaryView", "SwitchesView",
                "SwitchView"],
        function () {
            nmeta.router = new nmeta.Router();
            Backbone.history.start();
        });
});
