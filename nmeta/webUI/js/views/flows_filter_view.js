nmeta.FlowsFilterView = Backbone.View.extend({

    initialize:function (options) {
        // Initialise a client-side filter to filter on the client
        // mode pageable collection's cache:
        this.filter = new Backgrid.Extension.ClientSideFilter({
            collection: this.model,
            // Names of columns that are searched for filtering:
            fields: ['src_location_logical', 'src', 'dst'],
            // Display grey text in the filter bar to encourage use:
            placeholder: "Filter the flows"
        });
    },

    events: {
        // Bind refreshFlows click to function:
        'click .refreshFlows': 'refreshFlows'
    },

    render:function () {
        console.log('FlowsFilterView render function');
        // Apply FlowsFilterView.html template:
        this.$el.html(this.template());
        
        // Append rendered filter view to el id="filter":
        $('#filter', this.el).append(this.filter.render().el);
        return this;
    },

    refreshFlows:function () {
        // Fetch flows_collection, sending as reset event:
        console.log('FlowsFilterView refreshFlows calling fetch() as reset');
        this.model.fetch({reset: true})
    },

});
