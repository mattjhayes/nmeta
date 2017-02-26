nmeta.FlowsView = Backbone.View.extend({

    initialize:function () {

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
        console.log('in clearFlowsSearch');

    },

    refreshFlows:function () {
        // Fetch flows_collection, sending as reset event:
        console.log('FlowsView refreshFlows calling fetch() as reset');
        this.model.fetch({reset: true})
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

        // Create a filtered version of collection:
        var filtered = this.model.search(searchTerm);
        console.log('FlowsView search returned ', JSON.stringify(filtered));

        // Empty flows table:
        console.log('FlowsView search function emptying flows from table');
        $('#flow', this.el).empty();

        // Render filtered collection back into table:
        filtered.each(function(item){
            console.log('FlowsView search function adding flow row');
            $('#flow', this.el).append(new nmeta.FlowView({model:item}).render().el);
        });
    }

});
