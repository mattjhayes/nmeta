nmeta.FlowsView = Backbone.View.extend({

    initialize:function (options) {

        // Get options passed to us:
        this.options = options || {};

        // We're passed a model to hold UI states in for random stuff:
        this.flowsState = this.options.flowsState;
        this.flowsState.set('searchString', '');

        // Bind 'reset' event to run render function on this collection:
        this.model.on("reset", this.render, this);

        // Bind flow 'add' event to create new instance of FlowView
        // and render it against id='flow' (table row):
        this.model.on("add", function (flow) {
          console.log('FlowsView add called');
            $('#flow', this.el).append(new nmeta.FlowView({model:flow}).render().el);
        });

    },

    events: {
        // Bind searchFlowSrc to function:
        'keyup #searchFlowSrc' : 'searchProcessKey',

        // Bind refreshFlows click to function:
        'click .refreshFlows': 'refreshFlows',

        // Bind refreshFlows click to function:
        'click .clearFlowsSearch': 'clearFlowsSearch'

    },

    clearFlowsSearch:function () {
        // TBD:
        console.log('in clearFlowsSearch, clearing ', this.flowsState.get('searchString'));
        this.flowsState.set('searchString', '');
        $("#searchFlowSrc").val('');
        // Retrieve fresh data without searchString:
        this.model.fetch({reset: true,
                            data: $.param({ searchString: '' })})

    },

    refreshFlows:function () {
        // Fetch flows_collection, sending as reset event:
        console.log('FlowsView refreshFlows calling fetch() as reset and search=', this.flowsState.get('searchString'));
        this.model.fetch({reset: true,
                            data: $.param({ searchString: this.flowsState.get('searchString')})})
    },

    render:function () {
        console.log('FlowsView render function');

        // Start with empty el:
        this.$el.empty();

        // Apply FlowsView.html template:
        this.$el.html(this.template());

        // Render flow models:
        var self = this;
        // Iterate through models in collection:
        _.each(this.model.models, function (flow) {
            // Instantiate flow view for model:
            var flowView = new nmeta.FlowView({ model : flow });
            // Append rendered flow view to el id="flow":
            $('#flow', this.el).append(flowView.render().el);
        });

        // Re-add value to user text input:
        $('#searchFlowSrc').val(this.flowsState.get('searchString'));

        return this;
    },

    searchProcessKey: function(e) {
        // Only perform flow search if form is submitted:
        if(e.which === 13) // enter key
        this.search();
    },

    search : function(e){
        console.log('FlowsView search function');

        // Get search term:
        var searchTerm = $("#searchFlowSrc").val();
        console.log('FlowsView search function, searchTerm=', searchTerm);

        // Store search term:
        this.flowsState.set('searchString', searchTerm);

        this.model.fetch({reset: true,
                            data: $.param({ searchString: this.flowsState.get('searchString')})})

    }

});
