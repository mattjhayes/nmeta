//=============================================================================
// nmeta holds the context for the app:
var nmeta = {

    views: {},

    models: {},

    // Loads HTML templates and binds them to Views:
    loadTemplates: function(views, callback) {
        var deferreds = [];
        $.each(views, function(index, view) {
            console.log('loadTemplates index=' + index + ' view=' + view);
            if (nmeta[view]) {
                // Load template html files from template directory:
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

//=============================================================================
// Extend Backbone.View to have a function for clean-up called 'close':
Backbone.View.prototype.close = function() {
    if (this.onClose) {
        // Run the View's onClose function (where it exists):
        this.onClose();
    }
    // Remove the View, including unbinding events:
    this.remove();
};

//=============================================================================
// Router controls navigation around the main areas of the app by URL:
nmeta.Router = Backbone.Router.extend({

    routes: {
        "":                        "home",
        "who":                     "who",
        "what":                    "what",
        "kit":                     "kit",
        "kit/controller":          "controllerDetails",
        "policy":                  "policy",
        "flowDetails/:flow_hash":  "flowDetails",
        "switch/:dpid":            "switch",
        "top-talkers":             "flowsRemoved"
    },

    //=========================================================================
    // Display nav bar and set up rest of page
    initialize: function () {
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
        this.$content1a = $("#content1a");
        this.$content1b = $("#content1b");
        this.$content1c = $("#content1c");
        this.$content2a = $("#content2a");
        this.$content2b = $("#content2b");
        this.$content2c = $("#content2c");
        this.$content3a = $("#content3a");
        this.$content3b = $("#content3b");
        this.$content3c = $("#content3c");
        this.$content4a = $("#content4a");
        this.$content4b = $("#content4b");
        this.$content4c = $("#content4c");
        this.$content5a = $("#content5a");
        this.$content5b = $("#content5b");
        this.$content5c = $("#content5c");

        // Array for storing current views for later clean-up:
        this.currentViews = [];
    },

    //=========================================================================
    // Display 'home' page
    home: function () {
        // Pane 1a: Clean-up then create View:
        this.cleanUpViews();
        nmeta.homelView = new nmeta.HomeView();
        this.registerView(nmeta.homelView);
        
        // Pane 1a: Render View:
        nmeta.homelView.render();
        this.$content1a.html(nmeta.homelView.el);

        // Pane 2a: Instantiate switch count Model
        this.switch_count_model = new nmeta.SwitchCountModel();

        // Pane 2a: Instantiate switch count View:
        nmeta.switchCountView = new nmeta.SwitchCountView({model: this.switch_count_model});
        this.registerView(nmeta.switchCountView);

        // Pane 2a: Fetch switch_count_model as reset event (note: invokes render):
        console.log('Fetching switch_count_model');
        this.switch_count_model.fetch({reset: true})

        // Pane 2a: Publish result into DOM against id="content2a":
        this.$content2a.html(nmeta.switchCountView.el);

        // Update top menu bar:
        nmeta.barsView.selectMenuItem('home-menu');
    },

    //=========================================================================
    // Display 'who' page about identities on the network:
    who: function () {
        // Clean-up previous Views:
        this.cleanUpViews();

        // Backgrid Filter, Grid and Paginator of Flows:

        // Pane 1a: Instantiate Identities BackGrid Collection:
        this.identities_pageable_collection = new nmeta.IdentitiesPageableCollection();

        // Pane 1a: Create Identities Filter View:
        nmeta.identitiesFilterView = new nmeta.IdentitiesFilterView({model: this.identities_pageable_collection});
        this.registerView(nmeta.identitiesFilterView);

        // Pane 2a: Create BackGrid View:
        nmeta.identitiesBackgridView = new nmeta.IdentitiesBackGridView({model: this.identities_pageable_collection});
        this.registerView(nmeta.identitiesBackgridView);

        // Pane 1a: Render filter view:
        nmeta.identitiesFilterView.render();

        // Pane 1a & 2a: Fetch data causing a render:
        this.identities_pageable_collection.fetch({reset: true});

        // Pane 1a: Publish result into DOM against id="content1a":
        this.$content1a.html(nmeta.identitiesFilterView.el);
        
        // Pane 2a: Publish result into DOM against id="content2a":
        this.$content2a.html(nmeta.identitiesBackgridView.el);

        // Pane 3a: Create BackGrid Paginator View:
        nmeta.identitiesPaginatorView = new nmeta.IdentitiesPaginatorView({model: this.identities_pageable_collection});
        this.registerView(nmeta.identitiesPaginatorView);

        // Pane 3a: Render paginator view:
        nmeta.identitiesPaginatorView.render();
        
        // Pane 3a: Publish result into DOM against id="content3a":
        this.$content3a.html(nmeta.identitiesPaginatorView.el);

        // Update top menu bar:
        nmeta.barsView.selectMenuItem('who-menu');
    },

    //=========================================================================
    // Display 'what' page about flows on the network:
    what: function () {
        // Clean-up previous Views:
        this.cleanUpViews();

        // Backgrid Filter, Grid and Paginator of Flows:

        // Pane 1a: Instantiate Flows BackGrid Collection:
        this.flows_pageable_collection = new nmeta.FlowsPageableCollection();

        // Pane 1a: Create Flows Filter View:
        nmeta.flowsFilterView = new nmeta.FlowsFilterView({model: this.flows_pageable_collection});
        this.registerView(nmeta.flowsFilterView);

        // Pane 2a: Create BackGrid View:
        nmeta.flowsBackgridView = new nmeta.FlowsBackGridView({model: this.flows_pageable_collection});
        this.registerView(nmeta.flowsBackgridView);

        // Pane 1a: Render filter view:
        nmeta.flowsFilterView.render();

        // Pane 1a & 2a: Fetch data causing a render:
        this.flows_pageable_collection.fetch({reset: true});

        // Pane 1a: Publish result into DOM against id="content1a":
        this.$content1a.html(nmeta.flowsFilterView.el);
        
        // Pane 2a: Publish result into DOM against id="content2a":
        this.$content2a.html(nmeta.flowsBackgridView.el);

        // Pane 3a: Create BackGrid Paginator View:
        nmeta.flowsPaginatorView = new nmeta.FlowsPaginatorView({model: this.flows_pageable_collection});
        this.registerView(nmeta.flowsPaginatorView);

        // Pane 3a: Render paginator view:
        nmeta.flowsPaginatorView.render();
        
        // Pane 3a: Publish result into DOM against id="content3a":
        this.$content3a.html(nmeta.flowsPaginatorView.el);

        // Update top menu bar:
        nmeta.barsView.selectMenuItem('what-menu');
    },

    //=========================================================================
    // Display 'kit' page about networking equipment:
    kit: function (id) {
        // Clean-up previous Views:
        this.cleanUpViews();

        // Pane 1a: Instantiate Controller Summary Model:
        this.controller_summary_model = new nmeta.ControllerSummaryModel();

        // Pane 1a: Instantiate Controller Summary View:
        nmeta.controllerSummaryView = new nmeta.ControllerSummaryView({model: this.controller_summary_model});
        this.registerView(nmeta.controllerSummaryView);

        // Pane 1a: Fetch controller_summary_model as reset event (note: invokes render):
        console.log('Fetching controller_summary_model');
        this.controller_summary_model.fetch({reset: true});

        // Pane 1a: Publish result into DOM against id="content1a":
        this.$content1a.html(nmeta.controllerSummaryView.el);

        // Pane 2a: Instantiate switch count Model
        this.switch_count_model = new nmeta.SwitchCountModel();

        // Pane 2a: Instantiate switch count View:
        nmeta.switchCountView = new nmeta.SwitchCountView({model: this.switch_count_model});
        this.registerView(nmeta.switchCountView);

        // Pane 2a: Fetch switch_count_model as reset event (note: invokes render):
        console.log('Fetching switch_count_model');
        this.switch_count_model.fetch({reset: true})

        // Pane 2a: Publish result into DOM against id="content2a":
        this.$content2a.html(nmeta.switchCountView.el);

        // Pane 3a: Instantiate Switches Collection:
        this.switches_collection = new nmeta.SwitchesCollection();

        // Pane 3a: Create Switches View:
        nmeta.switchesView = new nmeta.SwitchesView({model: this.switches_collection});
        this.registerView(nmeta.switchesView);

        // Pane 3a: Fetch switches_collection as reset event (note: invokes render):
        console.log('Fetching switches_collection');
        this.switches_collection.fetch({reset: true})

        // Pane 3a: Publish result into DOM against id="content3a":
        this.$content3a.html(nmeta.switchesView.el);

        // Update top menu bar:
        nmeta.barsView.selectMenuItem('kit-menu');
    },

    //=========================================================================
    // Display 'kit' Controller Details page:
    controllerDetails: function (id) {
        // Clean-up previous Views:
        this.cleanUpViews();

        // Pane 4a: Instantiate Controller Packet-In Time Chart Model:
        this.controller_pitime_chart_model = new nmeta.ControllerPITimeChartModel();

        // Pane 4a: Instantiate View:
        nmeta.controllerPITimeChartView = new nmeta.ControllerPITimeChartView({model: this.controller_pitime_chart_model});
        this.registerView(nmeta.controllerPITimeChartView);

        // Pane 4a: Fetch model as reset event (note: invokes render):
        this.controller_pitime_chart_model.fetch({reset: true});

        // Pane 4a: Publish result into DOM against id="content4a":
        this.$content4a.html(nmeta.controllerPITimeChartView.el);

        // Pane 5a: Instantiate Controller Packet-In Rate Chart Model:
        this.controller_pirate_chart_model = new nmeta.ControllerPIRateChartModel();

        // Pane 5a: Instantiate View:
        nmeta.controllerPIRateChartView = new nmeta.ControllerPIRateChartView({model: this.controller_pirate_chart_model});
        this.registerView(nmeta.controllerPIRateChartView);

        // Pane 5a: Fetch model as reset event (note: invokes render):
        this.controller_pirate_chart_model.fetch({reset: true});

        // Pane 5a: Publish result into DOM against id="content5a":
        this.$content5a.html(nmeta.controllerPIRateChartView.el);

        // Update top menu bar:
        nmeta.barsView.selectMenuItem('kit-menu');
    },

    //=========================================================================
    // Display 'policy' page
    policy: function () {
        // Clean-up previous Views:
        this.cleanUpViews();

        if (!nmeta.policyView) {
            console.log('creating policy view');
            nmeta.policyView = new nmeta.PolicyView();
            nmeta.policyView.render();
        }
        this.$content1a.html(nmeta.policyView.el);

        // Update top menu bar:
        nmeta.barsView.selectMenuItem('policy-menu');
    },

    //=========================================================================
    // Display the FlowDetails View:
    flowDetails: function (flow_hash) {
        this.cleanUpViews();
        console.log('in router flowDetails flow_hash=' + flow_hash);

        // Pane 1a: Instantiate flowDetailsView:
        console.log('app instantiating flowDetailsView');
        nmeta.flowDetailsView = new nmeta.FlowDetailsView({model: this.flowDetailsCollection});
        this.registerView(nmeta.flowDetailsView);

        // Pane 1a: Fetch flow_details_model as reset event (note: invokes render):
        console.log('app calling flowDetailsCollection fetch({reset: true})');
        var where_query = '{\"flow_hash\":\"' + flow_hash + '\"}'
        console.log('where_query=' + where_query);
        this.flowDetailsCollection.fetch({reset: true, data: $.param({ where: where_query})})

        // Pane 1a: Publish result into DOM against id="content1a":
        this.$content1a.html(nmeta.flowDetailsView.el);

        // Pane 2a: Instantiate flowModsView:
        console.log('app instantiating flowModsView');
        nmeta.flowModsView = new nmeta.FlowModsView({model: this.flowModsCollection});
        this.registerView(nmeta.flowModsView);

        // Pane 2a: Fetch flow_mods_model as reset event (note: invokes render):
        console.log('app calling flowModsCollection fetch({reset: true})');
        var where_query = '{\"flow_hash\":\"' + flow_hash + '\"}'
        console.log('where_query=' + where_query);
        this.flowModsCollection.fetch({reset: true, data: $.param({ where: where_query})})

        // Pane 2a: Publish result into DOM against id="content2a":
        this.$content2a.html(nmeta.flowModsView.el);

        //---------------------------------------------------------------------
        // Update top menu bar:
        nmeta.barsView.selectMenuItem('what-menu');
    },

    //=========================================================================
    // Display the FlowsRemoved View (experimental):
    flowsRemoved: function () {
        this.cleanUpViews();
        console.log('in router flowsRemoved');

        // Pane 1a: Instantiate Flows Removed Bytes Src Sent Chart Model:
        this.flowsRemovedBytesSrcSentChartModel = new nmeta.FlowsRemovedBytesSrcSentChartModel();

        // Pane 1a: Instantiate flowsRemovedBytesSrcSentChartView:
        console.log('app instantiating flowsRemovedBytesSrcSentChartView');
        nmeta.flowsRemovedBytesSrcSentChartView = new nmeta.FlowsRemovedBytesSrcSentChartView({model: this.flowsRemovedBytesSrcSentChartModel});
        this.registerView(nmeta.flowsRemovedBytesSrcSentChartView);

        // Pane 1a: Fetch flowsRemovedBytesSrcSentChartModel as reset event (note: invokes render):
        console.log('app calling flowsRemovedBytesSrcSentChartModel fetch({reset: true})');
        this.flowsRemovedBytesSrcSentChartModel.fetch({reset: true})

        // Pane 1a: Publish result into DOM against id="content1a":
        this.$content1a.html(nmeta.flowsRemovedBytesSrcSentChartView.el);

        //---------------------------------------------------------------------
        // Pane 1b: Instantiate Flows Removed Bytes Src Received Chart Model:
        this.flowsRemovedBytesSrcReceivedChartModel = new nmeta.FlowsRemovedBytesSrcReceivedChartModel();

        // Pane 1b: Instantiate flowsRemovedBytesSrcReceivedChartView:
        console.log('app instantiating flowsRemovedBytesSrcReceivedChartView');
        nmeta.flowsRemovedBytesSrcReceivedChartView = new nmeta.FlowsRemovedBytesSrcReceivedChartView({model: this.flowsRemovedBytesSrcReceivedChartModel});
        this.registerView(nmeta.flowsRemovedBytesSrcReceivedChartView);

        // Pane 1b: Fetch flowsRemovedBytesSrcReceivedChartModel as reset event (note: invokes render):
        console.log('app calling flowsRemovedBytesSrcReceivedChartModel fetch({reset: true})');
        this.flowsRemovedBytesSrcReceivedChartModel.fetch({reset: true})

        // Pane 1b: Publish result into DOM against id="content1b":
        this.$content1b.html(nmeta.flowsRemovedBytesSrcReceivedChartView.el);

        //---------------------------------------------------------------------
        // Pane 2a: Instantiate Flows Removed Bytes Dst Sent Chart Model:
        this.flowsRemovedBytesDstSentChartModel = new nmeta.FlowsRemovedBytesDstSentChartModel();

        // Pane 2a: Instantiate flowsRemovedBytesDstSentChartView:
        console.log('app instantiating flowsRemovedBytesDstSentChartView');
        nmeta.flowsRemovedBytesDstSentChartView = new nmeta.FlowsRemovedBytesDstSentChartView({model: this.flowsRemovedBytesDstSentChartModel});
        this.registerView(nmeta.flowsRemovedBytesDstSentChartView);

        // Pane 2a: Fetch flowsRemovedBytesDstSentChartModel as reset event (note: invokes render):
        console.log('app calling flowsRemovedBytesDstSentChartModel fetch({reset: true})');
        this.flowsRemovedBytesDstSentChartModel.fetch({reset: true})

        // Pane 2a: Publish result into DOM against id="content2a":
        this.$content2a.html(nmeta.flowsRemovedBytesDstSentChartView.el);

        //---------------------------------------------------------------------
        // Pane 2b: Instantiate Flows Removed Bytes Dst Received Chart Model:
        this.flowsRemovedBytesDstReceivedChartModel = new nmeta.FlowsRemovedBytesDstReceivedChartModel();

        // Pane 2b: Instantiate flowsRemovedBytesDstReceivedChartView:
        console.log('app instantiating flowsRemovedBytesDstReceivedChartView');
        nmeta.flowsRemovedBytesDstReceivedChartView = new nmeta.FlowsRemovedBytesDstReceivedChartView({model: this.flowsRemovedBytesDstReceivedChartModel});
        this.registerView(nmeta.flowsRemovedBytesDstReceivedChartView);

        // Pane 2b: Fetch flowsRemovedBytesDstReceivedChartModel as reset event (note: invokes render):
        console.log('app calling flowsRemovedBytesDstReceivedChartModel fetch({reset: true})');
        this.flowsRemovedBytesDstReceivedChartModel.fetch({reset: true})

        // Pane 2b: Publish result into DOM against id="content2b":
        this.$content2b.html(nmeta.flowsRemovedBytesDstReceivedChartView.el);
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
    nmeta.loadTemplates(["HomeView", "SwitchCountView", "IdentitiesFilterView",
                "FlowsFilterView", "FlowDetailsView",
                "FlowDetailView", "FlowModsView", "FlowModView", 
                "FlowsRemovedBytesSrcSentChartView",
                "FlowsRemovedBytesSrcReceivedChartView",
                "FlowsRemovedBytesDstSentChartView",
                "FlowsRemovedBytesDstReceivedChartView",
                "PolicyView",
                "BarsView", "ControllerSummaryView",
                "ControllerPITimeChartView", "ControllerPIRateChartView",
                "SwitchesView", "SwitchView"],
        function () {
            nmeta.router = new nmeta.Router();
            Backbone.history.start();
        });
});
