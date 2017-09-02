nmeta.IdentitiesFilterView = Backbone.View.extend({

    initialize:function (options) {
        // Initialise a client-side filter to filter on the client
        // mode pageable collection's cache:
        this.filter = new Backgrid.Extension.ClientSideFilter({
            collection: this.model,
            // Names of columns that are searched for filtering:
            fields: ['harvest_type', 'host_name', 'service_name', 
                        'mac_address', 'ip_address'],

            // Display grey text in the filter bar to encourage use:
            placeholder: "Filter the identities"
        });
        
        // Event to reapply search filter after collection refresh:
        this.model.on("sync", this.reSearch, this);
    },

    events: {
        // Bind refreshIdentities click to function:
        'click .refreshIdentities': 'refreshIdentities'
    },

    render:function () {
        console.log('IdentitiesFilterView render function');
        // Apply IdentitiesFilterView.html template:
        this.$el.html(this.template());
        
        // Append rendered filter view to el id="filter":
        $('#filter', this.el).append(this.filter.render().el);
        return this;
    },

    refreshIdentities:function () {
        // Fetch identities_collection, sending as reset event:
        this.model.fetch({reset: true});
    },

    reSearch:function () {
        // Reapply the search filter to the collection after a fetch:
        this.filter.search();
    },

});
